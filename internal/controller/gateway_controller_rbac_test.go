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
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	rbacVerbGet    = "get"
	rbacResSecrets = "secrets"
)

func TestEnsureRouterRBAC_ModeBAddsBackendSecretGet(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	gw := sampleGateway()
	obp := samplePolicy(3)
	obp.Spec.TargetRefs = []gwv1.LocalPolicyTargetReference{{
		Group: GatewayAPIGroup,
		Kind:  GatewayKind,
		Name:  gwv1.ObjectName(gw.Name),
	}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, obp).Build()
	r := &GatewayReconciler{Client: cl, Scheme: scheme}

	if err := r.ensureRouterRBAC(ctx, gw, obp); err != nil {
		t.Fatalf("ensureRouterRBAC: %v", err)
	}

	var role rbacv1.Role
	if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: RouterRBACName(gw.Name)}, &role); err != nil {
		t.Fatalf("get Role: %v", err)
	}

	var sawSecretGet bool
	for _, rule := range role.Rules {
		if len(rule.Resources) == 1 && rule.Resources[0] == rbacResSecrets && slices.Contains(rule.Verbs, rbacVerbGet) {
			sawSecretGet = true
			for i := range 3 {
				want := BackendKeySecretName(gw, i)
				if !slices.Contains(rule.ResourceNames, want) {
					t.Errorf("missing resourceName %q", want)
				}
			}
		}
	}
	if !sawSecretGet {
		t.Fatal("expected a secrets-get rule in the router Role when Mode B is active")
	}
}

func TestEnsureRouterRBAC_ModeANoSecretGet(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	gw := sampleGateway()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()
	r := &GatewayReconciler{Client: cl, Scheme: scheme}

	if err := r.ensureRouterRBAC(ctx, gw, nil); err != nil {
		t.Fatalf("ensureRouterRBAC: %v", err)
	}

	var role rbacv1.Role
	if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: RouterRBACName(gw.Name)}, &role); err != nil {
		t.Fatalf("get Role: %v", err)
	}

	for _, rule := range role.Rules {
		if len(rule.Resources) == 1 && rule.Resources[0] == rbacResSecrets {
			t.Fatalf("Mode A router Role must NOT have a secrets rule; got %+v", rule)
		}
	}
}
