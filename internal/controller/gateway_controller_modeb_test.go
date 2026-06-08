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
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

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

func TestCleanupModeAResources_DeletesAllChildren(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	ns := gw.Namespace

	// Seed one object of every Mode A child type.
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: DeploymentName(gw.Name), Namespace: ns}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName(gw.Name), Namespace: ns}}
	keys := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: KeySecretName(gw.Name), Namespace: ns}}
	torrc := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: TorrcConfigMapName(gw.Name), Namespace: ns}}
	np := &netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: NetworkPolicyName(gw.Name), Namespace: ns}}
	routerSA := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: ns}}
	routerRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: ns}}
	routerRB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: ns}}
	vanitySA := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: VanityRBACName(gw.Name), Namespace: ns}}
	vanityRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: VanityRBACName(gw.Name), Namespace: ns}}
	vanityRB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: VanityRBACName(gw.Name), Namespace: ns}}
	vanityOut := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: VanityOutSecretName(gw.Name), Namespace: ns}}
	vanityJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: VanityRBACName(gw.Name), Namespace: ns}}

	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(
		gw, deploy, svc, keys, torrc, np,
		routerSA, routerRole, routerRB,
		vanitySA, vanityRole, vanityRB, vanityOut, vanityJob,
	).Build()
	r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}

	if err := r.cleanupModeAResources(ctx, gw); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	assertGone := func(t *testing.T, name string, nn types.NamespacedName, obj client.Object) {
		t.Helper()
		err := cl.Get(ctx, nn, obj)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("%s: expected NotFound after cleanup, got %v", name, err)
		}
	}

	t.Run("Deployment", func(t *testing.T) {
		assertGone(t, "Deployment", types.NamespacedName{Namespace: ns, Name: DeploymentName(gw.Name)}, &appsv1.Deployment{})
	})
	t.Run("Service", func(t *testing.T) {
		assertGone(t, "Service", types.NamespacedName{Namespace: ns, Name: ServiceName(gw.Name)}, &corev1.Service{})
	})
	t.Run("KeySecret", func(t *testing.T) {
		assertGone(t, "KeySecret", types.NamespacedName{Namespace: ns, Name: KeySecretName(gw.Name)}, &corev1.Secret{})
	})
	t.Run("TorrcConfigMap", func(t *testing.T) {
		assertGone(t, "TorrcConfigMap", types.NamespacedName{Namespace: ns, Name: TorrcConfigMapName(gw.Name)}, &corev1.ConfigMap{})
	})
	t.Run("NetworkPolicy", func(t *testing.T) {
		assertGone(t, "NetworkPolicy", types.NamespacedName{Namespace: ns, Name: NetworkPolicyName(gw.Name)}, &netv1.NetworkPolicy{})
	})
	t.Run("RouterServiceAccount", func(t *testing.T) {
		assertGone(t, "RouterServiceAccount", types.NamespacedName{Namespace: ns, Name: RouterRBACName(gw.Name)}, &corev1.ServiceAccount{})
	})
	t.Run("RouterRole", func(t *testing.T) {
		assertGone(t, "RouterRole", types.NamespacedName{Namespace: ns, Name: RouterRBACName(gw.Name)}, &rbacv1.Role{})
	})
	t.Run("RouterRoleBinding", func(t *testing.T) {
		assertGone(t, "RouterRoleBinding", types.NamespacedName{Namespace: ns, Name: RouterRBACName(gw.Name)}, &rbacv1.RoleBinding{})
	})
	t.Run("VanityServiceAccount", func(t *testing.T) {
		assertGone(t, "VanityServiceAccount", types.NamespacedName{Namespace: ns, Name: VanityRBACName(gw.Name)}, &corev1.ServiceAccount{})
	})
	t.Run("VanityRole", func(t *testing.T) {
		assertGone(t, "VanityRole", types.NamespacedName{Namespace: ns, Name: VanityRBACName(gw.Name)}, &rbacv1.Role{})
	})
	t.Run("VanityRoleBinding", func(t *testing.T) {
		assertGone(t, "VanityRoleBinding", types.NamespacedName{Namespace: ns, Name: VanityRBACName(gw.Name)}, &rbacv1.RoleBinding{})
	})
	t.Run("VanityOutSecret", func(t *testing.T) {
		assertGone(t, "VanityOutSecret", types.NamespacedName{Namespace: ns, Name: VanityOutSecretName(gw.Name)}, &corev1.Secret{})
	})
	t.Run("VanityJob", func(t *testing.T) {
		assertGone(t, "VanityJob", types.NamespacedName{Namespace: ns, Name: VanityRBACName(gw.Name)}, &batchv1.Job{})
	})
}
