/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"slices"
	"testing"
)

func TestBuildVanityRoleScopedToOutSecret(t *testing.T) {
	gw := sampleGateway()
	role, err := BuildVanityRole(gw, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(role.Rules))
	}
	rule := role.Rules[0]
	if !slices.Equal(rule.Resources, []string{"secrets"}) {
		t.Errorf("resources = %v, want [secrets]", rule.Resources)
	}
	if !slices.Equal(rule.ResourceNames, []string{VanityOutSecretName(gw.Name)}) {
		t.Errorf("resourceNames = %v, want [%s]", rule.ResourceNames, VanityOutSecretName(gw.Name))
	}
	for _, v := range rule.Verbs {
		if v == "create" || v == "list" || v == "delete" {
			t.Errorf("vanity Role must not grant %q (resourceNames cannot scope it)", v)
		}
	}
	if !slices.Contains(rule.Verbs, "update") || !slices.Contains(rule.Verbs, "get") {
		t.Errorf("verbs = %v, want at least get+update", rule.Verbs)
	}
}

func TestBuildVanityOutSecretIsEmptyAndOwned(t *testing.T) {
	gw := sampleGateway()
	s, err := BuildVanityOutSecret(gw, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != VanityOutSecretName(gw.Name) {
		t.Errorf("name = %s, want %s", s.Name, VanityOutSecretName(gw.Name))
	}
	if len(s.Data) != 0 {
		t.Errorf("Data should be empty, got %v", s.Data)
	}
	if len(s.OwnerReferences) != 1 {
		t.Fatalf("want 1 ownerRef, got %d", len(s.OwnerReferences))
	}
}

func TestBuildVanityServiceAccountAndBindingNames(t *testing.T) {
	gw := sampleGateway()
	sa, err := BuildVanityServiceAccount(gw, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if sa.Name != VanityRBACName(gw.Name) {
		t.Errorf("SA name = %s, want %s", sa.Name, VanityRBACName(gw.Name))
	}
	rb, err := BuildVanityRoleBinding(gw, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if rb.RoleRef.Name != VanityRBACName(gw.Name) || rb.Subjects[0].Name != VanityRBACName(gw.Name) {
		t.Errorf("binding does not wire the vanity SA to the vanity Role")
	}
}
