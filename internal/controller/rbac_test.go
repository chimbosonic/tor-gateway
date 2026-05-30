/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// TestGeneratedRole_HasEventsRule asserts that the controller-gen-generated
// ClusterRole grants events: create;patch. Without this, EventRecorder calls
// on the operator (vanity progress, policy validation) silently fail on a
// cluster with default-deny RBAC.
func TestGeneratedRole_HasEventsRule(t *testing.T) {
	p := filepath.Join("..", "..", "config", "rbac", "role.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var role rbacv1.ClusterRole
	if err := yaml.Unmarshal(b, &role); err != nil {
		t.Fatalf("parse role: %v", err)
	}
	for _, r := range role.Rules {
		if !slices.Contains(r.APIGroups, "") {
			continue
		}
		if !slices.Contains(r.Resources, "events") {
			continue
		}
		if slices.Contains(r.Verbs, "create") && slices.Contains(r.Verbs, "patch") {
			return
		}
	}
	t.Fatalf("role.yaml is missing an events rule with create;patch verbs")
}

// TestGeneratedRole_HasNetworkPoliciesRule asserts the generated
// ClusterRole grants the verbs the operator needs to manage per-Gateway
// NetworkPolicy children.
func TestGeneratedRole_HasNetworkPoliciesRule(t *testing.T) {
	p := filepath.Join("..", "..", "config", "rbac", "role.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var role rbacv1.ClusterRole
	if err := yaml.Unmarshal(b, &role); err != nil {
		t.Fatalf("parse role: %v", err)
	}
	wantVerbs := []string{"get", "list", "watch", "create", "update", "patch", "delete"}
	for _, r := range role.Rules {
		if !slices.Contains(r.APIGroups, "networking.k8s.io") {
			continue
		}
		if !slices.Contains(r.Resources, "networkpolicies") {
			continue
		}
		ok := true
		for _, v := range wantVerbs {
			if !slices.Contains(r.Verbs, v) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("role.yaml is missing a networking.k8s.io/networkpolicies rule with verbs %v", wantVerbs)
}
