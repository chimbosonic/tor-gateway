/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func gwForNPTest() *gwv1.Gateway {
	return &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "g1", Namespace: "ns"}}
}

func TestBuildNetworkPolicy_HasDNSRule(t *testing.T) {
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	if got := findEgressByNSLabel(np, "kube-system"); got == nil {
		t.Fatalf("missing kube-system egress rule (DNS); rules=%+v", np.Spec.Egress)
	} else {
		if !hasPort(got, "UDP", 53) || !hasPort(got, "TCP", 53) {
			t.Errorf("DNS rule missing UDP/TCP 53; ports=%+v", got.Ports)
		}
	}
}

// findEgressByNSLabel returns the first egress rule whose first `to` entry
// is a namespaceSelector matching `kubernetes.io/metadata.name=<name>`.
func findEgressByNSLabel(np *netv1.NetworkPolicy, name string) *netv1.NetworkPolicyEgressRule {
	for i := range np.Spec.Egress {
		r := &np.Spec.Egress[i]
		for _, to := range r.To {
			if to.NamespaceSelector == nil {
				continue
			}
			if to.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == name {
				return r
			}
		}
	}
	return nil
}

func hasPort(r *netv1.NetworkPolicyEgressRule, protocol string, port int) bool {
	for _, p := range r.Ports {
		if p.Protocol != nil && string(*p.Protocol) == protocol &&
			p.Port != nil && p.Port.IntValue() == port {
			return true
		}
	}
	return false
}

func TestBuildNetworkPolicy_HasAPIServerRule(t *testing.T) {
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	// The apiserver rule is the SECOND egress rule whose `to` matches
	// kube-system (DNS is the first), and it must have ports 6443+443 TCP.
	var apiserver *netv1.NetworkPolicyEgressRule
	hits := 0
	for i := range np.Spec.Egress {
		r := &np.Spec.Egress[i]
		for _, to := range r.To {
			if to.NamespaceSelector != nil &&
				to.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "kube-system" {
				hits++
				if hits == 2 {
					apiserver = r
				}
			}
		}
	}
	if apiserver == nil {
		t.Fatalf("missing second kube-system egress rule (apiserver); rules=%+v", np.Spec.Egress)
	}
	if !hasPort(apiserver, "TCP", 6443) || !hasPort(apiserver, "TCP", 443) {
		t.Errorf("apiserver rule missing TCP 6443/443; ports=%+v", apiserver.Ports)
	}
}

func TestBuildNetworkPolicy_PublicEgress_NoExceptWhenCIDRsEmpty(t *testing.T) {
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	rule := lastEgress(np)
	if len(rule.To) != 1 || rule.To[0].IPBlock == nil {
		t.Fatalf("last rule is not an IPBlock; got %+v", rule)
	}
	if rule.To[0].IPBlock.CIDR != "0.0.0.0/0" {
		t.Errorf("CIDR want 0.0.0.0/0, got %q", rule.To[0].IPBlock.CIDR)
	}
	if len(rule.To[0].IPBlock.Except) != 0 {
		t.Errorf("Except should be empty when no clusterPodCIDRs; got %v", rule.To[0].IPBlock.Except)
	}
}

func TestBuildNetworkPolicy_PublicEgress_ExceptPopulatedWhenCIDRsSet(t *testing.T) {
	cidrs := []string{"10.244.0.0/16", "fd00::/64"}
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, cidrs, testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	rule := lastEgress(np)
	if len(rule.To) != 1 || rule.To[0].IPBlock == nil {
		t.Fatalf("last rule is not an IPBlock; got %+v", rule)
	}
	if !slicesEqual(rule.To[0].IPBlock.Except, cidrs) {
		t.Errorf("Except mismatch: got %v want %v", rule.To[0].IPBlock.Except, cidrs)
	}
}

func lastEgress(np *netv1.NetworkPolicy) netv1.NetworkPolicyEgressRule {
	return np.Spec.Egress[len(np.Spec.Egress)-1]
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBuildNetworkPolicy_PerBackendRules(t *testing.T) {
	backends := []ResolvedBackend{
		{
			Namespace:   "appns",
			PodSelector: map[string]string{"app": "app1"},
			TargetPort:  intstr.FromInt(5678),
			Protocol:    corev1.ProtocolTCP,
		},
		{
			Namespace:   "otherns",
			PodSelector: map[string]string{"app": "app2"},
			TargetPort:  intstr.FromString("http"),
			Protocol:    corev1.ProtocolTCP,
		},
	}
	np, err := BuildNetworkPolicy(gwForNPTest(), backends, nil, testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	// Egress order: DNS, apiserver, backend(appns), backend(otherns), public.
	if got, want := len(np.Spec.Egress), 5; got != want {
		t.Fatalf("egress rules count: got %d want %d (%+v)", got, want, np.Spec.Egress)
	}
	for i, want := range []struct{ ns, port string }{
		{"appns", "5678"},
		{"otherns", "http"},
	} {
		rule := np.Spec.Egress[2+i]
		if len(rule.To) != 1 || rule.To[0].NamespaceSelector == nil || rule.To[0].PodSelector == nil {
			t.Fatalf("backend rule %d shape wrong: %+v", i, rule)
		}
		if got := rule.To[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]; got != want.ns {
			t.Errorf("backend %d ns: got %q want %q", i, got, want.ns)
		}
		if len(rule.Ports) != 1 || rule.Ports[0].Port.String() != want.port {
			t.Errorf("backend %d port: got %+v want %s", i, rule.Ports, want.port)
		}
	}
}

func TestBuildNetworkPolicy_PerBackendRules_SortedDeterministically(t *testing.T) {
	// Same selector, multiple namespaces fed out of order — output is sorted
	// by (namespace, port, podSelector-first-label).
	backends := []ResolvedBackend{
		{Namespace: "z", PodSelector: map[string]string{"a": "1"}, TargetPort: intstr.FromInt(80), Protocol: corev1.ProtocolTCP},
		{Namespace: "a", PodSelector: map[string]string{"a": "1"}, TargetPort: intstr.FromInt(80), Protocol: corev1.ProtocolTCP},
	}
	np, err := BuildNetworkPolicy(gwForNPTest(), backends, nil, testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	first := np.Spec.Egress[2].To[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]
	second := np.Spec.Egress[3].To[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]
	if first != "a" || second != "z" {
		t.Errorf("sort order wrong: got %q then %q", first, second)
	}
}

func TestBuildNetworkPolicy_RejectsEmptyPodSelector(t *testing.T) {
	bad := []ResolvedBackend{{Namespace: "x", PodSelector: nil, TargetPort: intstr.FromInt(80), Protocol: corev1.ProtocolTCP}}
	_, err := BuildNetworkPolicy(gwForNPTest(), bad, nil, testScheme(t))
	if err == nil {
		t.Fatal("expected error for empty PodSelector")
	}
}
