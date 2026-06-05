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

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/chimbosonic/tor-gateway/internal/tor"
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
	obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns"
	obp.Spec.MasterKeySecretRef.Name = "ob-master"
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ob-master", Namespace: "secrets-ns"},
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
	obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns"
	obp.Spec.MasterKeySecretRef.Name = "ob-master"
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ob-master", Namespace: "secrets-ns"},
		Data:       validMasterSecretData(t),
	}
	rg := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-blog", Namespace: "secrets-ns"},
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
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "secrets-ns", Name: CrossNSMasterRoleName(gw)}, &rb); err != nil {
		t.Fatalf("cross-NS RoleBinding not created: %v", err)
	}
	var role rbacv1.Role
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "secrets-ns", Name: CrossNSMasterRoleName(gw)}, &role); err != nil {
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
	gw.UID = "abc-123"
	obp := samplePolicy(3)
	obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns-new"
	obp.Spec.MasterKeySecretRef.Name = "ob-master"

	staleRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: "secrets-ns-old",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				"torgateway.io/owner-uid":      "abc-123",
			},
		},
	}
	staleRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: "secrets-ns-old",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				"torgateway.io/owner-uid":      "abc-123",
			},
		},
	}
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ob-master", Namespace: "secrets-ns-new"},
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
	gw.UID = "abc-123"
	crossNSRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: "secrets-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				"torgateway.io/owner-uid":      "abc-123",
			},
		},
	}
	crossNSRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: "secrets-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				"torgateway.io/owner-uid":      "abc-123",
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw, crossNSRole, crossNSRB).Build()
	r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
	if err := r.cleanupModeBResources(ctx, gw); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	err := cl.Get(ctx, types.NamespacedName{Namespace: "secrets-ns", Name: CrossNSMasterRoleName(gw)}, &rbacv1.Role{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("cross-NS Role should be deleted; got %v", err)
	}
	err = cl.Get(ctx, types.NamespacedName{Namespace: "secrets-ns", Name: CrossNSMasterRoleName(gw)}, &rbacv1.RoleBinding{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("cross-NS RoleBinding should be deleted; got %v", err)
	}
}
