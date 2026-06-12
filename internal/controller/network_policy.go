/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ResolvedBackend is one entry in the egress allow-list: a backend Service
// the reconciler successfully resolved AND that passes the ReferenceGrant
// gate when cross-namespace.
type ResolvedBackend struct {
	Namespace   string
	PodSelector map[string]string
	TargetPort  intstr.IntOrString
	Protocol    corev1.Protocol
}

// BuildNetworkPolicy emits the per-Gateway, egress-only NetworkPolicy.
// See docs/superpowers/specs/2026-05-30-tor-pod-networkpolicy-design.md.
func BuildNetworkPolicy(
	gw *gwv1.Gateway,
	backends []ResolvedBackend,
	clusterPodCIDRs []string,
	testingNetworkNamespace string,
	scheme *runtime.Scheme,
) (*netv1.NetworkPolicy, error) {
	for _, b := range backends {
		if len(b.PodSelector) == 0 {
			return nil, fmt.Errorf("BuildNetworkPolicy: backend in ns %q has empty PodSelector", b.Namespace)
		}
	}

	egress := []netv1.NetworkPolicyEgressRule{
		dnsEgress(),
		apiserverEgress(),
	}
	sorted := append([]ResolvedBackend(nil), backends...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Namespace != sorted[j].Namespace {
			return sorted[i].Namespace < sorted[j].Namespace
		}
		if sorted[i].TargetPort.String() != sorted[j].TargetPort.String() {
			return sorted[i].TargetPort.String() < sorted[j].TargetPort.String()
		}
		return firstLabelKey(sorted[i].PodSelector) < firstLabelKey(sorted[j].PodSelector)
	})
	for _, b := range sorted {
		egress = append(egress, backendEgress(b))
	}
	if testingNetworkNamespace != "" {
		// Testing mode: reach only the chutney pod (directory authorities +
		// OR relays). Public internet egress is intentionally omitted —
		// chutney IS the Tor network in this mode.
		egress = append(egress, testingNetworkEgress(testingNetworkNamespace))
	} else {
		egress = append(egress, publicInternetEgress(clusterPodCIDRs))
	}

	np := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      NetworkPolicyName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: ChildLabels(gw.Name)},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			Egress:      egress,
		},
	}

	if err := controllerutil.SetControllerReference(gw, np, scheme); err != nil {
		return nil, err
	}
	return np, nil
}

func dnsEgress() netv1.NetworkPolicyEgressRule {
	udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
	dnsPort := intstr.FromInt(53)
	return netv1.NetworkPolicyEgressRule{
		To: []netv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": "kube-system",
			}},
		}},
		Ports: []netv1.NetworkPolicyPort{
			{Protocol: &udp, Port: &dnsPort},
			{Protocol: &tcp, Port: &dnsPort},
		},
	}
}

func apiserverEgress() netv1.NetworkPolicyEgressRule {
	tcp := corev1.ProtocolTCP
	p6443 := intstr.FromInt(6443)
	p443 := intstr.FromInt(443)
	return netv1.NetworkPolicyEgressRule{
		To: []netv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": "kube-system",
			}},
		}},
		Ports: []netv1.NetworkPolicyPort{
			{Protocol: &tcp, Port: &p6443},
			{Protocol: &tcp, Port: &p443},
		},
	}
}

func publicInternetEgress(clusterPodCIDRs []string) netv1.NetworkPolicyEgressRule {
	block := &netv1.IPBlock{CIDR: "0.0.0.0/0"}
	if len(clusterPodCIDRs) > 0 {
		block.Except = append([]string(nil), clusterPodCIDRs...)
	}
	return netv1.NetworkPolicyEgressRule{
		To: []netv1.NetworkPolicyPeer{{IPBlock: block}},
	}
}

// chutneyPodLabel is the label carried by the chutney Pod in every e2e
// cluster (see hack/chutney/chutney.yaml).
const chutneyPodLabel = "chutney"

// Chutney k8s-mini port ranges used by the three directory authorities and
// three relays (idx 0-5).
// OR ports: 5000-5005 (circuit-building)
// DirAuth ports: 7000-7005 (consensus / directory fetch)
const (
	chutneyORPortFirst  = int32(5000)
	chutneyORPortLast   = int32(5005)
	chutneyDirPortFirst = int32(7000)
	chutneyDirPortLast  = int32(7005)
)

// testingNetworkEgress restricts egress to the chutney pod (by PodSelector)
// on the known OR and DirAuth port ranges. Production never enables this.
func testingNetworkEgress(namespace string) netv1.NetworkPolicyEgressRule {
	tcp := corev1.ProtocolTCP
	orFirst := intstr.FromInt(int(chutneyORPortFirst))
	dirFirst := intstr.FromInt(int(chutneyDirPortFirst))
	orLast, dirLast := chutneyORPortLast, chutneyDirPortLast
	return netv1.NetworkPolicyEgressRule{
		To: []netv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": namespace,
			}},
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"app": chutneyPodLabel,
			}},
		}},
		Ports: []netv1.NetworkPolicyPort{
			{Protocol: &tcp, Port: &orFirst, EndPort: &orLast},
			{Protocol: &tcp, Port: &dirFirst, EndPort: &dirLast},
		},
	}
}

func backendEgress(b ResolvedBackend) netv1.NetworkPolicyEgressRule {
	proto := b.Protocol
	port := b.TargetPort
	return netv1.NetworkPolicyEgressRule{
		To: []netv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": b.Namespace,
			}},
			PodSelector: &metav1.LabelSelector{MatchLabels: b.PodSelector},
		}},
		Ports: []netv1.NetworkPolicyPort{{Protocol: &proto, Port: &port}},
	}
}

func firstLabelKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}
