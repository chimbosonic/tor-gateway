/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	record "k8s.io/client-go/tools/record"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

const (
	testGwUID            = "abc-123"
	testMasterSecretName = "ob-master"
	testMasterSecretNS   = "secrets-ns"
)

// testSchemeWithGrants returns a scheme that also includes the Gateway API
// v1beta1 types (ReferenceGrant) in addition to the base testScheme types.
func testSchemeWithGrants(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := testScheme(t)
	utilruntime.Must(gwv1beta1.Install(s))
	return s
}

// testRESTMapper returns a REST mapper that knows the correct plural resource
// names for Gateway API types.  The default fake-client mapper uses
// UnsafeGuessKindToResource which pluralises "gateway" as "gatewaies" (ends in
// 'y'), so we register the correct plural explicitly.
func testRESTMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper(nil)
	gwGV := schema.GroupVersion{Group: gwv1.GroupName, Version: "v1"}
	m.Add(gwGV.WithKind("Gateway"), meta.RESTScopeNamespace)
	m.Add(gwGV.WithKind("GatewayClass"), meta.RESTScopeRoot)
	return m
}

// validMasterSecretData generates a fresh ed25519 key-pair and returns the
// data map suitable for a master-key Secret.
func validMasterSecretData(t *testing.T) map[string][]byte {
	t.Helper()
	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		tor.FileSecretKeyName: kp.SecretKeyFile(),
		tor.FilePublicKeyName: kp.PublicKeyFile(),
	}
}

func TestEnsureModeB_RejectsCrossNSWithoutReferenceGrant(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(3)
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testMasterSecretName, Namespace: testMasterSecretNS},
		Data:       validMasterSecretData(t),
	}
	// No ReferenceGrant present.
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).
		WithRESTMapper(testRESTMapper()).
		WithObjects(gw, obp, masterSecret).
		Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}
	err := r.ensureModeB(ctx, gw, obp)
	if err == nil {
		t.Fatal("expected ReferenceGrant-missing error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "referencegrant") {
		t.Errorf("error = %q, want substring 'referencegrant'", err)
	}
}

func TestEnsureModeB_CreatesCrossNSRoleBinding(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(3)
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testMasterSecretName, Namespace: testMasterSecretNS},
		Data:       validMasterSecretData(t),
	}
	rg := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-blog", Namespace: testMasterSecretNS},
		Spec: gwv1beta1.ReferenceGrantSpec{
			From: []gwv1beta1.ReferenceGrantFrom{{
				Group:     "policy.torgateway.io",
				Kind:      "OnionBalancePolicy",
				Namespace: gwv1beta1.Namespace(gw.Namespace),
			}},
			To: []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Secret"}},
		},
	}
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).
		WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).
		WithObjects(gw, obp, masterSecret, rg).
		Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}
	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}
	var rb rbacv1.RoleBinding
	if err := cl.Get(ctx, types.NamespacedName{Namespace: testMasterSecretNS, Name: CrossNSMasterRoleName(gw)}, &rb); err != nil {
		t.Fatalf("cross-NS RoleBinding not created: %v", err)
	}
	var role rbacv1.Role
	if err := cl.Get(ctx, types.NamespacedName{Namespace: testMasterSecretNS, Name: CrossNSMasterRoleName(gw)}, &role); err != nil {
		t.Fatalf("cross-NS Role not created: %v", err)
	}
}

// TestEnsureModeB_CrossNSMasterOnionPublishedInStatus covers the assertion
// relocated from the e2e cross-NS spec: with a ReferenceGrant in place, the
// master .onion derived from a Secret in ANOTHER namespace ends up in
// Gateway.status.addresses. (RBAC enforcement of the frontend pod's cross-NS
// GET is live-only and deliberately not covered here — see the 2026-06-12
// e2e-pregen-retry design spec, "accepted gap".)
func TestEnsureModeB_CrossNSMasterOnionPublishedInStatus(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(1)
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName

	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testMasterSecretName, Namespace: testMasterSecretNS},
		Data: map[string][]byte{
			tor.FileSecretKeyName: kp.SecretKeyFile(),
			tor.FilePublicKeyName: kp.PublicKeyFile(),
		},
	}
	rg := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-blog", Namespace: testMasterSecretNS},
		Spec: gwv1beta1.ReferenceGrantSpec{
			From: []gwv1beta1.ReferenceGrantFrom{{
				Group:     "policy.torgateway.io",
				Kind:      "OnionBalancePolicy",
				Namespace: gwv1beta1.Namespace(gw.Namespace),
			}},
			To: []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Secret"}},
		},
	}
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).
		WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).
		WithObjects(gw, obp, masterSecret, rg).
		Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}
	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}

	var got gwv1.Gateway
	if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	want := kp.OnionAddress().String()
	for _, a := range got.Status.Addresses {
		if a.Value == want {
			return
		}
	}
	t.Errorf("status.addresses = %v, want to contain %s (onion derived from the cross-NS master Secret)",
		got.Status.Addresses, want)
}

func TestCleanupModeBResources_DeletesOnionbalanceConfigMap(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	orphan := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OnionbalanceConfigMapName(gw),
			Namespace: gw.Namespace,
		},
	}
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw, orphan).Build()
	r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
	if err := r.cleanupModeBResources(ctx, gw); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: OnionbalanceConfigMapName(gw)}, &corev1.ConfigMap{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestEnsureModeB_GCsStaleCrossNSPairs(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	gw.UID = testGwUID
	obp := samplePolicy(3)
	obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns-new"
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName

	staleRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: "secrets-ns-old",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				"torgateway.io/owner-uid":      testGwUID,
			},
		},
	}
	staleRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: "secrets-ns-old",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				"torgateway.io/owner-uid":      testGwUID,
			},
		},
	}
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testMasterSecretName, Namespace: "secrets-ns-new"},
		Data:       validMasterSecretData(t),
	}
	rg := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-new", Namespace: "secrets-ns-new"},
		Spec: gwv1beta1.ReferenceGrantSpec{
			From: []gwv1beta1.ReferenceGrantFrom{{
				Group:     "policy.torgateway.io",
				Kind:      "OnionBalancePolicy",
				Namespace: gwv1beta1.Namespace(gw.Namespace),
			}},
			To: []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Secret"}},
		},
	}

	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).
		WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).
		WithObjects(gw, obp, masterSecret, rg, staleRole, staleRB).
		Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}
	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}

	// Old namespace pair gone.
	err := cl.Get(ctx, types.NamespacedName{Namespace: "secrets-ns-old", Name: CrossNSMasterRoleName(gw)}, &rbacv1.Role{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("stale Role in secrets-ns-old should be deleted; got %v", err)
	}
	err = cl.Get(ctx, types.NamespacedName{Namespace: "secrets-ns-old", Name: CrossNSMasterRoleName(gw)}, &rbacv1.RoleBinding{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("stale RoleBinding in secrets-ns-old should be deleted; got %v", err)
	}

	// New namespace pair exists.
	err = cl.Get(ctx, types.NamespacedName{Namespace: "secrets-ns-new", Name: CrossNSMasterRoleName(gw)}, &rbacv1.Role{})
	if err != nil {
		t.Fatalf("new Role in secrets-ns-new should exist; got %v", err)
	}
}

func TestCleanupModeBResources_GCsAllCrossNSPairs(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	gw.UID = testGwUID
	crossNSRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: testMasterSecretNS,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				"torgateway.io/owner-uid":      testGwUID,
			},
		},
	}
	crossNSRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: testMasterSecretNS,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				"torgateway.io/owner-uid":      testGwUID,
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw, crossNSRole, crossNSRB).Build()
	r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
	if err := r.cleanupModeBResources(ctx, gw); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	err := cl.Get(ctx, types.NamespacedName{Namespace: testMasterSecretNS, Name: CrossNSMasterRoleName(gw)}, &rbacv1.Role{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("cross-NS Role should be deleted; got %v", err)
	}
	err = cl.Get(ctx, types.NamespacedName{Namespace: testMasterSecretNS, Name: CrossNSMasterRoleName(gw)}, &rbacv1.RoleBinding{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("cross-NS RoleBinding should be deleted; got %v", err)
	}
}

// TestEnsureModeB_ScaleDownShrinksBeforeGC verifies that when the StatefulSet
// has not yet scaled down (Status.Replicas > Spec.Replicas), orphan backend
// Secrets are preserved so in-flight pod init containers can still fetch them.
func TestEnsureModeB_ScaleDownShrinksBeforeGC(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(2)
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "master-keys", Namespace: gw.Namespace},
		Data:       validMasterSecretData(t),
	}
	// StatefulSet at 4 replicas, Status also at 4 — simulates the moment just
	// after the reconcile patches Spec down to 2 but pods have not gone yet.
	oldReplicas := int32(4)
	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: BackendStatefulSetName(gw), Namespace: gw.Namespace},
		Spec:       appsv1.StatefulSetSpec{Replicas: &oldReplicas},
		Status:     appsv1.StatefulSetStatus{Replicas: 4, ReadyReplicas: 4},
	}
	seeds := make([]client.Object, 0, 8)
	seeds = append(seeds, ss, gw, obp, masterSecret)
	for i := range 4 {
		seeds = append(seeds, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      BackendKeySecretName(gw, i),
				Namespace: gw.Namespace,
				Labels: map[string]string{
					"torgateway.io/gateway": gw.Name,
					"torgateway.io/role":    "backend",
				},
			},
		})
	}
	sc := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(sc).WithStatusSubresource(gw).WithObjects(seeds...).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}

	// StatefulSet spec should have been patched to 2.
	var got appsv1.StatefulSet
	if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: BackendStatefulSetName(gw)}, &got); err != nil {
		t.Fatalf("get StatefulSet: %v", err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 2 {
		t.Errorf("StatefulSet spec replicas = %v, want 2", got.Spec.Replicas)
	}

	// Secrets at indices 2 and 3 must NOT be deleted yet — pods are still running.
	for i := 2; i < 4; i++ {
		var s corev1.Secret
		if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: BackendKeySecretName(gw, i)}, &s); err != nil {
			t.Errorf("Secret backend-%d unexpectedly gone (GC should wait for pods to terminate): %v", i, err)
		}
	}
}

// TestEnsureModeB_ScaleDownGCsOnceReplicasMatch verifies that once the
// StatefulSet status reflects the new replica count (all excess pods gone),
// orphan backend Secrets are deleted on the next reconcile.
func TestEnsureModeB_ScaleDownGCsOnceReplicasMatch(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(2)
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "master-keys", Namespace: gw.Namespace},
		Data:       validMasterSecretData(t),
	}
	// StatefulSet already at desired spec; Status.Replicas == Spec.Replicas == 2,
	// meaning all excess pods have terminated and GC is safe.
	matchedReplicas := int32(2)
	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: BackendStatefulSetName(gw), Namespace: gw.Namespace},
		Spec:       appsv1.StatefulSetSpec{Replicas: &matchedReplicas},
		Status:     appsv1.StatefulSetStatus{Replicas: 2, ReadyReplicas: 2},
	}
	seeds := make([]client.Object, 0, 8)
	seeds = append(seeds, ss, gw, obp, masterSecret)
	// Seed 4 backend Secrets (indices 0-3); 2 and 3 are orphans.
	for i := range 4 {
		seeds = append(seeds, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      BackendKeySecretName(gw, i),
				Namespace: gw.Namespace,
				Labels: map[string]string{
					"torgateway.io/gateway": gw.Name,
					"torgateway.io/role":    "backend",
				},
			},
		})
	}
	sc := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(sc).WithStatusSubresource(gw).WithObjects(seeds...).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}

	// Secrets 0 and 1 must still exist.
	for i := range 2 {
		var s corev1.Secret
		if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: BackendKeySecretName(gw, i)}, &s); err != nil {
			t.Errorf("Secret backend-%d should still exist: %v", i, err)
		}
	}
	// Secrets 2 and 3 must be deleted — status matched, GC should have run.
	for i := 2; i < 4; i++ {
		err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: BackendKeySecretName(gw, i)}, &corev1.Secret{})
		if !apierrors.IsNotFound(err) {
			t.Errorf("orphan Secret backend-%d should be deleted after GC; got %v", i, err)
		}
	}
}

// --- findEffectiveOnionBalance helpers ---

// sampleGatewayName returns a Gateway like sampleGateway() but with a custom name.
func sampleGatewayName(name string) *gwv1.Gateway {
	gw := sampleGateway()
	gw.Name = name
	return gw
}

// obpTargeting returns an OBP that targets a single Gateway by name.
func obpTargeting(gw *gwv1.Gateway, obpName string) *policyv1alpha1.OnionBalancePolicy {
	return &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: obpName, Namespace: gw.Namespace},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			TargetRefs: []gwv1.LocalPolicyTargetReference{{
				Group: GatewayAPIGroup,
				Kind:  GatewayKind,
				Name:  gwv1.ObjectName(gw.Name),
			}},
			Replicas:           1,
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "master"},
		},
	}
}

// obpTargetingMany returns an OBP that targets multiple Gateways by name.
func obpTargetingMany(obpName string, gwNames ...string) *policyv1alpha1.OnionBalancePolicy {
	refs := make([]gwv1.LocalPolicyTargetReference, 0, len(gwNames))
	for _, n := range gwNames {
		refs = append(refs, gwv1.LocalPolicyTargetReference{
			Group: GatewayAPIGroup,
			Kind:  GatewayKind,
			Name:  gwv1.ObjectName(n),
		})
	}
	return &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: obpName, Namespace: testGwNamespace},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			TargetRefs:         refs,
			Replicas:           1,
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "master"},
		},
	}
}

// makeAcceptedFor returns a status with a single Accepted=True ancestor for gw.
func makeAcceptedFor(gw *gwv1.Gateway) policyv1alpha1.OnionBalancePolicyStatus {
	ns := gwv1.Namespace(gw.Namespace)
	kind := gwv1.Kind(GatewayKind)
	group := gwv1.Group(GatewayAPIGroup)
	return policyv1alpha1.OnionBalancePolicyStatus{
		Ancestors: []gwv1.PolicyAncestorStatus{{
			AncestorRef: gwv1.ParentReference{
				Group:     &group,
				Kind:      &kind,
				Name:      gwv1.ObjectName(gw.Name),
				Namespace: &ns,
			},
			ControllerName: ControllerName,
			Conditions: []metav1.Condition{{
				Type:   string(gwv1.PolicyConditionAccepted),
				Status: metav1.ConditionTrue,
				Reason: ReasonOBPAccepted,
			}},
		}},
	}
}

// --- cleanupModeBResources annotation gate tests ---

func TestCleanupModeBResources_NoUpdateWhenAnnotationsAbsent(t *testing.T) {
	gw := sampleGateway()
	gw.Annotations = map[string]string{"unrelated": "value"}
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw).Build()
	// Read the stored object to get the RV the fake client assigned.
	var stored gwv1.Gateway
	if err := cl.Get(context.Background(), types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &stored); err != nil {
		t.Fatalf("pre-get: %v", err)
	}
	rv := stored.ResourceVersion
	r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
	if err := r.cleanupModeBResources(context.Background(), &stored); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	var got gwv1.Gateway
	if err := cl.Get(context.Background(), types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ResourceVersion != rv {
		t.Errorf("ResourceVersion changed (%s -> %s); cleanup should not Update when no HA annotations present", rv, got.ResourceVersion)
	}
}

func TestCleanupModeBResources_UpdatesWhenHAAnnotationsPresent(t *testing.T) {
	gw := sampleGateway()
	gw.Annotations = map[string]string{
		annLastReplicas: "3",
	}
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw).Build()
	// Read the stored object to get the RV the fake client assigned.
	var stored gwv1.Gateway
	if err := cl.Get(context.Background(), types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &stored); err != nil {
		t.Fatalf("pre-get: %v", err)
	}
	rv := stored.ResourceVersion
	r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
	if err := r.cleanupModeBResources(context.Background(), &stored); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	var got gwv1.Gateway
	if err := cl.Get(context.Background(), types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ResourceVersion == rv {
		t.Error("ResourceVersion unchanged; cleanup should Update when HA annotations are present")
	}
	if _, ok := got.Annotations[annLastReplicas]; ok {
		t.Errorf("%s annotation should have been removed", annLastReplicas)
	}
}

// --- findEffectiveOnionBalance tests ---

func TestFindEffectiveOnionBalance_LexicalTiebreak(t *testing.T) {
	gw := sampleGateway()
	obpZ := obpTargeting(gw, "obp-zebra")
	obpA := obpTargeting(gw, "obp-alpha")
	obpA.Status = makeAcceptedFor(gw)
	obpZ.Status = makeAcceptedFor(gw)
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw, obpA, obpZ).Build()
	r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
	got, _, err := r.findEffectiveOnionBalance(context.Background(), gw)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if got == nil || got.Name != "obp-alpha" {
		t.Errorf("got %v, want obp-alpha", got)
	}
}

func TestFindEffectiveOnionBalance_PerAncestorAccepted(t *testing.T) {
	gwA := sampleGatewayName("gw-a")
	gwB := sampleGatewayName("gw-b")
	obp := obpTargetingMany("obp", "gw-a", "gw-b")
	obp.Status = makeAcceptedFor(gwA) // gw-b NOT accepted
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gwA, gwB, obp).Build()
	r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
	_, accepted, _ := r.findEffectiveOnionBalance(context.Background(), gwB)
	if accepted {
		t.Error("gw-b should NOT see Accepted=true; OBP only accepted for gw-a")
	}
	_, accepted, _ = r.findEffectiveOnionBalance(context.Background(), gwA)
	if !accepted {
		t.Error("gw-a should see Accepted=true")
	}
}

// --- retryProbeClient — simulates 409 Conflict on first Update / Status().Update ---

// retryProbeStatusWriter wraps a SubResourceWriter and injects a 409 Conflict on
// the first call to Update, delegating all subsequent calls to the real writer.
type retryProbeStatusWriter struct {
	inner  client.SubResourceWriter
	parent *retryProbeClient
}

func (s *retryProbeStatusWriter) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	return s.inner.Create(ctx, obj, subResource, opts...)
}

func (s *retryProbeStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	s.parent.statusUpdateAttempts++
	if s.parent.statusUpdateAttempts == 1 {
		return apierrors.NewConflict(
			schema.GroupResource{Group: gwv1.GroupName, Resource: "gateways"},
			obj.GetName(),
			errors.New("simulated conflict"),
		)
	}
	return s.inner.Update(ctx, obj, opts...)
}

func (s *retryProbeStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	return s.inner.Patch(ctx, obj, patch, opts...)
}

func (s *retryProbeStatusWriter) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	return s.inner.Apply(ctx, obj, opts...)
}

// retryProbeClient wraps a client.Client and injects 409 Conflict errors on
// the first call to Update and the first call to Status().Update.
type retryProbeClient struct {
	client.Client
	updateAttempts       int
	statusUpdateAttempts int
}

func (c *retryProbeClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updateAttempts++
	if c.updateAttempts == 1 {
		return apierrors.NewConflict(
			schema.GroupResource{Group: gwv1.GroupName, Resource: "gateways"},
			obj.GetName(),
			errors.New("simulated conflict"),
		)
	}
	return c.Client.Update(ctx, obj, opts...)
}

func (c *retryProbeClient) Status() client.SubResourceWriter {
	return &retryProbeStatusWriter{inner: c.Client.Status(), parent: c}
}

// TestUpdateStatusModeB_PreservesExistingAddressesOfOtherTypes verifies that
// updateStatusModeB keeps non-onion addresses already present in Status.Addresses
// while still adding (or updating) the master .onion entry.
func TestUpdateStatusModeB_PreservesExistingAddressesOfOtherTypes(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	hostnameType := gwv1.HostnameAddressType
	gw.Status.Addresses = []gwv1.GatewayStatusAddress{
		{Type: &hostnameType, Value: "external.example"},
	}

	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := kp.OnionAddress()

	sc := testScheme(t)
	inner := fake.NewClientBuilder().
		WithScheme(sc).
		WithStatusSubresource(gw).
		WithObjects(gw).
		Build()
	// Prime the status subresource with the pre-existing address.
	if err := inner.Status().Update(ctx, gw); err != nil {
		t.Fatalf("pre-seed status: %v", err)
	}
	r := &GatewayReconciler{Client: inner, Scheme: sc, Images: sampleImages()}

	if err := r.updateStatusModeB(ctx, gw, master, samplePolicy(2)); err != nil {
		t.Fatalf("updateStatusModeB: %v", err)
	}

	var got gwv1.Gateway
	if err := inner.Get(ctx, client.ObjectKeyFromObject(gw), &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	var sawHostname, sawOnion bool
	for _, a := range got.Status.Addresses {
		if a.Value == "external.example" {
			sawHostname = true
		}
		if strings.HasSuffix(a.Value, ".onion") {
			sawOnion = true
		}
	}
	if !sawHostname {
		t.Error("expected pre-existing hostname address to be preserved")
	}
	if !sawOnion {
		t.Error("expected master .onion address to be added")
	}
}

// TestUpdateStatusModeB_RetriesOnConflict verifies that updateStatusModeB uses
// RetryOnConflict for both the annotation Update and the Status().Update calls.
// The retryProbeClient returns a 409 on the first attempt of each; the test
// asserts the function returns nil and that two attempts were made for each.
func TestUpdateStatusModeB_RetriesOnConflict(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	// Set a replica annotation that differs from the policy so that the
	// annotation-update branch (r.Update) is exercised.
	gw.Annotations = map[string]string{annLastReplicas: "0"}

	pol := samplePolicy(3)

	// A ready frontend Deployment + backend Secret so modeBHealth reports
	// healthy and Programmed stays True; this test is about retry, not health.
	frontend := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: FrontendName(gw), Namespace: gw.Namespace},
		Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{
			{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue}}},
	}
	backend := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: BackendKeySecretName(gw, 0), Namespace: gw.Namespace,
			Labels: map[string]string{
				"torgateway.io/gateway":   gw.Name,
				"torgateway.io/role":      "backend",
				"torgateway.io/owner-uid": string(gw.UID),
			}},
		Data: map[string][]byte{"hostname": []byte("backend0example.onion")},
	}

	sc := testScheme(t)
	inner := fake.NewClientBuilder().
		WithScheme(sc).
		WithStatusSubresource(gw).
		WithObjects(gw, pol, frontend, backend).
		Build()
	probe := &retryProbeClient{Client: inner}
	r := &GatewayReconciler{Client: probe, Scheme: sc, Images: sampleImages()}

	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := kp.OnionAddress()

	if err := r.updateStatusModeB(ctx, gw, master, pol); err != nil {
		t.Fatalf("updateStatusModeB returned error: %v", err)
	}

	// Each write should have been attempted twice (first=conflict, second=success).
	if probe.updateAttempts != 2 {
		t.Errorf("Update attempts = %d, want 2", probe.updateAttempts)
	}
	if probe.statusUpdateAttempts != 2 {
		t.Errorf("Status().Update attempts = %d, want 2", probe.statusUpdateAttempts)
	}

	// Verify all mutations were actually persisted to the stored object.
	// This confirms the re-fetched object inside the retry closures received
	// the correct mutations before each Update call.
	var got gwv1.Gateway
	if err := inner.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	// Annotation mutation: annLastReplicas must reflect the policy's replica count.
	if got.Annotations[annLastReplicas] != "3" {
		t.Errorf("annotation %s = %q, want %q", annLastReplicas, got.Annotations[annLastReplicas], "3")
	}
	// Status mutation: address must be the master onion.
	if len(got.Status.Addresses) == 0 || got.Status.Addresses[0].Value != master.String() {
		t.Errorf("status.addresses = %v, want [%s]", got.Status.Addresses, master.String())
	}
	// Status mutation: Accepted condition must be True.
	acceptedCond := meta.FindStatusCondition(got.Status.Conditions, string(gwv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("Accepted condition = %v, want True", acceptedCond)
	}
	// Status mutation: Programmed condition must be True.
	programmedCond := meta.FindStatusCondition(got.Status.Conditions, string(gwv1.GatewayConditionProgrammed))
	if programmedCond == nil || programmedCond.Status != metav1.ConditionTrue {
		t.Errorf("Programmed condition = %v, want True", programmedCond)
	}
}

// TestEnsureModeB_ReconcilesNetworkPolicy verifies that ensureModeB creates a
// NetworkPolicy for the Gateway when TorPodNetworkPolicyEnabled is true.
func TestEnsureModeB_ReconcilesNetworkPolicy(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(2)
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "master-keys", Namespace: gw.Namespace},
		Data:       validMasterSecretData(t),
	}
	sc := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(sc).WithStatusSubresource(gw).WithObjects(gw, obp, masterSecret).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages(), TorPodNetworkPolicyEnabled: true}
	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}
	var np netv1.NetworkPolicy
	if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: NetworkPolicyName(gw.Name)}, &np); err != nil {
		t.Fatalf("NetworkPolicy not created: %v", err)
	}
}

// TestEnsureModeB_NoNetworkPolicyWhenDisabled verifies that ensureModeB does
// NOT create a NetworkPolicy when TorPodNetworkPolicyEnabled is false.
func TestEnsureModeB_NoNetworkPolicyWhenDisabled(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(2)
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "master-keys", Namespace: gw.Namespace},
		Data:       validMasterSecretData(t),
	}
	sc := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(sc).WithStatusSubresource(gw).WithObjects(gw, obp, masterSecret).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages(), TorPodNetworkPolicyEnabled: false}
	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}
	err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: NetworkPolicyName(gw.Name)}, &netv1.NetworkPolicy{})
	if err == nil {
		t.Fatal("NetworkPolicy should not exist when TorPodNetworkPolicyEnabled=false")
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error checking for NetworkPolicy: %v", err)
	}
}

// TestModeBReconcile_PreservesSharedRouterRBAC runs the exact sequence the
// controller executes every reconcile when an accepted OnionBalancePolicy
// targets the Gateway (cleanupModeAResources then ensureModeB) against router
// SA/Role/RoleBinding left by a prior reconcile. Mode B backend pods run as
// the router ServiceAccount, so the trio must survive in place: a
// delete+recreate cycle would invalidate the pods' projected SA tokens and
// tor-init's per-pod key fetch would get 401s. The marker annotation
// distinguishes "kept" from "deleted and recreated" — CreateOrUpdate
// preserves annotations it does not manage, deletion does not.
func TestModeBReconcile_PreservesSharedRouterRBAC(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(2)
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "master-keys", Namespace: gw.Namespace},
		Data:       validMasterSecretData(t),
	}
	const marker = "torgateway.io/test-prior-reconcile"
	prior := metav1.ObjectMeta{
		Name:        RouterRBACName(gw.Name),
		Namespace:   gw.Namespace,
		Annotations: map[string]string{marker: "true"},
	}
	routerSA := &corev1.ServiceAccount{ObjectMeta: *prior.DeepCopy()}
	routerRole := &rbacv1.Role{ObjectMeta: *prior.DeepCopy()}
	routerRB := &rbacv1.RoleBinding{ObjectMeta: *prior.DeepCopy()}

	sc := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(sc).WithStatusSubresource(gw).
		WithObjects(gw, obp, masterSecret, routerSA, routerRole, routerRB).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	if err := r.cleanupModeAResources(ctx, gw); err != nil {
		t.Fatalf("cleanupModeAResources: %v", err)
	}
	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}

	nn := types.NamespacedName{Namespace: gw.Namespace, Name: RouterRBACName(gw.Name)}
	for name, obj := range map[string]client.Object{
		"ServiceAccount": &corev1.ServiceAccount{},
		"Role":           &rbacv1.Role{},
		"RoleBinding":    &rbacv1.RoleBinding{},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cl.Get(ctx, nn, obj); err != nil {
				t.Fatalf("router %s missing after Mode B reconcile: %v", name, err)
			}
			if obj.GetAnnotations()[marker] != "true" {
				t.Fatalf("router %s was deleted and recreated during Mode B reconcile (marker annotation lost)", name)
			}
		})
	}
}

// TestReconcile_FinalizerCleansCrossNSOnDelete verifies the finalizer runs
// cleanupModeBResources (GC'ing the cross-NS Role/RoleBinding that cannot carry
// an owner ref) and then removes itself so the Gateway can be reaped.
func TestReconcile_FinalizerCleansCrossNSOnDelete(t *testing.T) {
	ctx := context.Background()
	gc := &gwv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway"}, // matches sampleGateway().Spec.GatewayClassName
		Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
	}
	gw := sampleGateway()
	gw.Finalizers = []string{FinalizerName}
	crossLabels := map[string]string{
		"app.kubernetes.io/managed-by": "tor-gateway",
		"torgateway.io/owner-uid":      string(gw.UID),
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
		Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS, Labels: crossLabels}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
		Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS, Labels: crossLabels}}

	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).WithObjects(gc, gw, role, rb).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	if err := cl.Delete(ctx, gw); err != nil {
		t.Fatalf("delete gateway: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if err := cl.Get(ctx, types.NamespacedName{Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS},
		&rbacv1.Role{}); !apierrors.IsNotFound(err) {
		t.Errorf("cross-NS Role should be GC'd; got %v", err)
	}
	if err := cl.Get(ctx, types.NamespacedName{Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS},
		&rbacv1.RoleBinding{}); !apierrors.IsNotFound(err) {
		t.Errorf("cross-NS RoleBinding should be GC'd; got %v", err)
	}
	if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace},
		&gwv1.Gateway{}); !apierrors.IsNotFound(err) {
		t.Errorf("Gateway should be gone after finalizer removal; got %v", err)
	}
}

// TestReconcile_AddsFinalizerToManagedGateway verifies a live managed Gateway
// gets the finalizer on first reconcile.
func TestReconcile_AddsFinalizerToManagedGateway(t *testing.T) {
	ctx := context.Background()
	gc := &gwv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway"},
		Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
	}
	gw := sampleGateway()
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).WithObjects(gc, gw).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got gwv1.Gateway
	if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&got, FinalizerName) {
		t.Errorf("expected finalizer %q; finalizers=%v", FinalizerName, got.Finalizers)
	}
}

// TestEnsureModeB_MasterSecretNotFoundSurfaces verifies a missing master Secret
// sets Programmed=False/MasterSecretNotFound and does NOT return an error (which
// would hot-loop the reconcile).
func TestEnsureModeB_MasterSecretNotFoundSurfaces(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(1) // same-namespace master Secret ref, but Secret absent
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).WithObjects(gw, obp).Build()
	rec := record.NewFakeRecorder(10)
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages(), Recorder: rec}

	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB should not return an error for a missing master Secret; got %v", err)
	}
	var got gwv1.Gateway
	if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatal(err)
	}
	prog := meta.FindStatusCondition(got.Status.Conditions, string(gwv1.GatewayConditionProgrammed))
	if prog == nil || prog.Status != metav1.ConditionFalse || prog.Reason != ReasonMasterSecretNotFound {
		t.Errorf("Programmed = %v, want False/%s", prog, ReasonMasterSecretNotFound)
	}
	select {
	case ev := <-rec.Events:
		if !strings.Contains(ev, "Warning") || !strings.Contains(ev, ReasonMasterSecretNotFound) {
			t.Errorf("event = %q, want Warning/%s", ev, ReasonMasterSecretNotFound)
		}
	default:
		t.Error("expected a Warning event for the missing master Secret")
	}
}

// TestUpdateStatusModeB_ProgrammedReflectsReadiness verifies Programmed is True
// only when the frontend Deployment is Available AND at least one backend is
// ready; otherwise False with a specific reason. The master .onion is always
// published.
func TestUpdateStatusModeB_ProgrammedReflectsReadiness(t *testing.T) {
	ctx := context.Background()
	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := kp.OnionAddress()

	frontend := func(available bool) *appsv1.Deployment {
		gw := sampleGateway()
		st := corev1.ConditionFalse
		if available {
			st = corev1.ConditionTrue
		}
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: FrontendName(gw), Namespace: gw.Namespace},
			Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: st}}},
		}
	}
	readyBackend := func() *corev1.Secret {
		gw := sampleGateway()
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: BackendKeySecretName(gw, 0), Namespace: gw.Namespace,
				Labels: map[string]string{
					"torgateway.io/gateway":   gw.Name,
					"torgateway.io/role":      "backend",
					"torgateway.io/owner-uid": string(gw.UID),
				}},
			Data: map[string][]byte{"hostname": []byte(master.String())},
		}
	}

	tests := []struct {
		name       string
		extra      []client.Object
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{"healthy", []client.Object{frontend(true), readyBackend()}, metav1.ConditionTrue, string(gwv1.GatewayReasonProgrammed)},
		{"frontend not ready", []client.Object{frontend(false), readyBackend()}, metav1.ConditionFalse, ReasonFrontendNotReady},
		{"backends not ready", []client.Object{frontend(true)}, metav1.ConditionFalse, ReasonBackendsNotReady},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := sampleGateway()
			pol := samplePolicy(1)
			sc := testScheme(t)
			objs := append([]client.Object{gw, pol}, tc.extra...)
			cl := fake.NewClientBuilder().WithScheme(sc).WithStatusSubresource(gw).WithObjects(objs...).Build()
			r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}
			if err := r.updateStatusModeB(ctx, gw, master, pol); err != nil {
				t.Fatalf("updateStatusModeB: %v", err)
			}
			var got gwv1.Gateway
			if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
				t.Fatal(err)
			}
			prog := meta.FindStatusCondition(got.Status.Conditions, string(gwv1.GatewayConditionProgrammed))
			if prog == nil || prog.Status != tc.wantStatus || prog.Reason != tc.wantReason {
				t.Errorf("Programmed = %v, want %s/%s", prog, tc.wantStatus, tc.wantReason)
			}
			if len(got.Status.Addresses) == 0 || got.Status.Addresses[0].Value != master.String() {
				t.Errorf("master .onion must be published regardless of readiness; got %v", got.Status.Addresses)
			}
		})
	}
}
