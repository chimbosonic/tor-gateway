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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/chimbosonic/tor-gateway/internal/tor"
)

func gwForNPTest() *gwv1.Gateway {
	return &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "g1", Namespace: "ns"}}
}

func TestBuildNetworkPolicy_HasDNSRule(t *testing.T) {
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, "", testScheme(t))
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
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, "", testScheme(t))
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
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, "", testScheme(t))
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
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, cidrs, "", testScheme(t))
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

func TestBuildNetworkPolicy_TestingNetworkEgress(t *testing.T) {
	cidrs := []string{"10.244.0.0/16"}
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, cidrs, "tor-gateway-chutney", testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	if got := findEgressByNSLabel(np, "tor-gateway-chutney"); got == nil {
		t.Fatalf("missing chutney-namespace egress rule; rules=%+v", np.Spec.Egress)
	}
	// In testing mode the public-internet egress rule must be absent —
	// the Tor pods should reach only chutney (the private Tor network).
	for _, r := range np.Spec.Egress {
		for _, peer := range r.To {
			if peer.IPBlock != nil {
				t.Errorf("public-internet egress must be absent in testing mode; got rule %+v", r)
			}
		}
	}
}

// TestBuildNetworkPolicy_TestingMode_PublicEgressAbsent verifies that when
// testing mode is active the public-internet IPBlock rule is not emitted,
// regardless of clusterPodCIDRs.
func TestBuildNetworkPolicy_TestingMode_PublicEgressAbsent(t *testing.T) {
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, "tor-gateway-chutney", testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	for _, r := range np.Spec.Egress {
		for _, peer := range r.To {
			if peer.IPBlock != nil {
				t.Errorf("public-internet egress must be absent in testing mode; got rule %+v", r)
			}
		}
	}
}

// TestTestingModeEgress_IsScopedToChutneyPodsAndPorts verifies the
// testing-mode egress rule targets only chutney pods (by PodSelector) and
// the known chutney port ranges (OR: 5000-5002, DirAuth: 7000-7002), not an
// unrestricted namespace-wide allow.
func TestTestingModeEgress_IsScopedToChutneyPodsAndPorts(t *testing.T) {
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, "tor-gateway-chutney", testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	var sawChutney bool
	for i := range np.Spec.Egress {
		e := &np.Spec.Egress[i]
		for _, peer := range e.To {
			if peer.NamespaceSelector == nil {
				continue
			}
			if peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "tor-gateway-chutney" {
				continue
			}
			sawChutney = true
			if peer.PodSelector == nil || len(peer.PodSelector.MatchLabels) == 0 {
				t.Error("chutney egress peer must restrict by PodSelector, not bare namespace")
			} else if peer.PodSelector.MatchLabels["app"] != "chutney" {
				t.Errorf("chutney PodSelector must have app=chutney; got %v", peer.PodSelector.MatchLabels)
			}
			if len(e.Ports) == 0 {
				t.Error("chutney egress must enumerate ports")
			}
		}
	}
	if !sawChutney {
		t.Fatal("expected a chutney egress rule")
	}
}

func TestBuildNetworkPolicy_TestingNetworkOmittedByDefault(t *testing.T) {
	np, err := BuildNetworkPolicy(gwForNPTest(), nil, nil, "", testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	for _, r := range np.Spec.Egress {
		for _, to := range r.To {
			if to.NamespaceSelector != nil &&
				to.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "tor-gateway-chutney" {
				t.Fatalf("unexpected chutney egress rule in production mode: %+v", r)
			}
		}
	}
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
	np, err := BuildNetworkPolicy(gwForNPTest(), backends, nil, "", testScheme(t))
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
	np, err := BuildNetworkPolicy(gwForNPTest(), backends, nil, "", testScheme(t))
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
	_, err := BuildNetworkPolicy(gwForNPTest(), bad, nil, "", testScheme(t))
	if err == nil {
		t.Fatal("expected error for empty PodSelector")
	}
}

func TestNetworkPolicySelectsBothModeBPodSets(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	np, err := BuildNetworkPolicy(gw, nil, nil, "", testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	sel := np.Spec.PodSelector.MatchLabels
	if sel["torgateway.io/gateway"] != "blog" {
		t.Errorf("expected gateway label; got %v", sel)
	}
	if _, ok := sel["torgateway.io/role"]; ok {
		t.Errorf("podSelector must NOT pin role; got %v (frontend + backend pods both need to be covered)", sel)
	}
}

func TestNetworkPolicySelectorMatchesModeBPodLabels(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	np, err := BuildNetworkPolicy(gw, nil, nil, "", testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		t.Fatalf("LabelSelectorAsSelector: %v", err)
	}
	for _, role := range []string{haRoleBackend, haRoleFrontend} {
		podLabels := HALabels(gw, role)
		if !sel.Matches(labels.Set(podLabels)) {
			t.Errorf("Mode B %s pod labels %v not matched by NP selector %v", role, podLabels, sel)
		}
	}
}

// TestNetworkPolicyMatchesRenderedModeBPods verifies the NP selector matches
// the pod template labels produced by the actual builder functions, catching
// any label drift between HALabels and the workload builders.
func TestNetworkPolicyMatchesRenderedModeBPods(t *testing.T) {
	gw := sampleGateway()
	obp := samplePolicy(2)
	np, err := BuildNetworkPolicy(gw, nil, nil, "", testScheme(t))
	if err != nil {
		t.Fatalf("BuildNetworkPolicy: %v", err)
	}
	sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		t.Fatalf("LabelSelectorAsSelector: %v", err)
	}

	backend, err := BuildBackendStatefulSet(gw, obp, tor.OnionAddress{}, sampleImages(), testScheme(t))
	if err != nil {
		t.Fatalf("BuildBackendStatefulSet: %v", err)
	}
	frontend, err := BuildFrontendDeployment(gw, obp, tor.OnionAddress{}, sampleImages(), false, testScheme(t))
	if err != nil {
		t.Fatalf("BuildFrontendDeployment: %v", err)
	}

	if !sel.Matches(labels.Set(backend.Spec.Template.Labels)) {
		t.Errorf("NP selector does not match backend pod template labels %v", backend.Spec.Template.Labels)
	}
	if !sel.Matches(labels.Set(frontend.Spec.Template.Labels)) {
		t.Errorf("NP selector does not match frontend pod template labels %v", frontend.Spec.Template.Labels)
	}
}
