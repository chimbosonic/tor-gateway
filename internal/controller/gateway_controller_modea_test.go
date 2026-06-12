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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestCleanupModeAResources_DeletesAllChildren verifies that the Mode A→B
// transition GCs every Mode-A-only child, while keeping the router
// SA/Role/RoleBinding: those are shared with Mode B (backend pods run as the
// router SA) and Gateway deletion GCs them via their controller
// ownerReference (asserted in the Build* tests in gateway_resources_test.go).
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
	assertKept := func(t *testing.T, name string, nn types.NamespacedName, obj client.Object) {
		t.Helper()
		if err := cl.Get(ctx, nn, obj); err != nil {
			t.Fatalf("%s: shared router RBAC must survive cleanup, got %v", name, err)
		}
	}

	t.Run("RouterServiceAccountKept", func(t *testing.T) {
		assertKept(t, "RouterServiceAccount", types.NamespacedName{Namespace: ns, Name: RouterRBACName(gw.Name)}, &corev1.ServiceAccount{})
	})
	t.Run("RouterRoleKept", func(t *testing.T) {
		assertKept(t, "RouterRole", types.NamespacedName{Namespace: ns, Name: RouterRBACName(gw.Name)}, &rbacv1.Role{})
	})
	t.Run("RouterRoleBindingKept", func(t *testing.T) {
		assertKept(t, "RouterRoleBinding", types.NamespacedName{Namespace: ns, Name: RouterRBACName(gw.Name)}, &rbacv1.RoleBinding{})
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
