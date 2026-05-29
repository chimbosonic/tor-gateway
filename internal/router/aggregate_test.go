/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ghostBackend is the fixture backend Service name used across the router
// tests; the stub backends also echo it as their response body.
const ghostBackend = "ghost"

// routeFor builds a minimal HTTPRoute in namespace ns with a single
// parentRef naming parentGW and one backendRef to backend.
func routeFor(ns, name, parentGW, backend string) gwv1.HTTPRoute {
	port := gwv1.PortNumber(80)
	return gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: gwv1.HTTPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{
				ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(parentGW)}},
			},
			Rules: []gwv1.HTTPRouteRule{{
				BackendRefs: []gwv1.HTTPBackendRef{{
					BackendRef: gwv1.BackendRef{
						BackendObjectReference: gwv1.BackendObjectReference{
							Name: gwv1.ObjectName(backend),
							Port: &port,
						},
					},
				}},
			}},
		},
	}
}

func TestRulesForGateway_SelectsRoutesTargetingGateway(t *testing.T) {
	gw := types.NamespacedName{Namespace: "prod", Name: "blog-gw"}

	mine := routeFor("prod", "blog", "blog-gw", ghostBackend)
	other := routeFor("prod", "other", "different-gw", "nope")

	rules := rulesForGateway([]gwv1.HTTPRoute{mine, other}, gw)
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1 (only the route targeting blog-gw)", len(rules))
	}
	if len(rules[0].Backends) != 1 || rules[0].Backends[0].Name != ghostBackend {
		t.Fatalf("backend = %+v, want ghost", rules[0].Backends)
	}
}

func TestRulesForGateway_ParentRefNamespaceDefaultsToRouteNamespace(t *testing.T) {
	gw := types.NamespacedName{Namespace: "prod", Name: "blog-gw"}

	// Same Gateway name, but the route lives in another namespace and gives
	// no explicit parentRef namespace, so the ref defaults to "staging" and
	// must not attach to the "prod" Gateway.
	elsewhere := routeFor("staging", "blog", "blog-gw", ghostBackend)

	if rules := rulesForGateway([]gwv1.HTTPRoute{elsewhere}, gw); len(rules) != 0 {
		t.Fatalf("got %d rules, want 0 (parentRef namespace defaults to the route's, staging != prod)", len(rules))
	}
}

func TestRulesForGateway_IgnoresNonGatewayParentRefs(t *testing.T) {
	gw := types.NamespacedName{Namespace: "prod", Name: "blog-gw"}

	// A parentRef with the same name but Kind=Service (mesh attachment) must
	// not bind to our Gateway.
	svcKind := gwv1.Kind("Service")
	route := routeFor("prod", "blog", "blog-gw", ghostBackend)
	route.Spec.ParentRefs[0].Kind = &svcKind

	if rules := rulesForGateway([]gwv1.HTTPRoute{route}, gw); len(rules) != 0 {
		t.Fatalf("got %d rules, want 0 (parentRef Kind=Service is not a Gateway)", len(rules))
	}
}

func TestRulesForGateway_IgnoresForeignGroupParentRefs(t *testing.T) {
	gw := types.NamespacedName{Namespace: "prod", Name: "blog-gw"}

	// Same name and (default) Kind=Gateway, but in a different API group.
	otherGroup := gwv1.Group("example.com")
	route := routeFor("prod", "blog", "blog-gw", ghostBackend)
	route.Spec.ParentRefs[0].Group = &otherGroup

	if rules := rulesForGateway([]gwv1.HTTPRoute{route}, gw); len(rules) != 0 {
		t.Fatalf("got %d rules, want 0 (parentRef Group=example.com is not the Gateway API group)", len(rules))
	}
}

const localBackend = "local"

// resolvedRoute builds an HTTPRoute with one same-ns backend ("local") and one
// cross-ns backend ("remote" in namespace "other"), optionally with a
// ResolvedRefs status condition for the named gateway parent.
func resolvedRoute(status metav1.ConditionStatus, withCond bool) gwv1.HTTPRoute {
	const gwName = "gw"
	r := gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "gwns"},
		Spec: gwv1.HTTPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(gwName)}}},
			Rules: []gwv1.HTTPRouteRule{{BackendRefs: []gwv1.HTTPBackendRef{
				{BackendRef: gwv1.BackendRef{BackendObjectReference: gwv1.BackendObjectReference{Name: localBackend, Port: ptr.To(gwv1.PortNumber(80))}}},
				{BackendRef: gwv1.BackendRef{BackendObjectReference: gwv1.BackendObjectReference{Name: "remote", Namespace: ptr.To(gwv1.Namespace("other")), Port: ptr.To(gwv1.PortNumber(80))}}},
			}}},
		},
	}
	if withCond {
		r.Status.Parents = []gwv1.RouteParentStatus{{
			ParentRef:  gwv1.ParentReference{Name: gwv1.ObjectName(gwName)},
			Conditions: []metav1.Condition{{Type: string(gwv1.RouteConditionResolvedRefs), Status: status}},
		}}
	}
	return r
}

func backendNames(rules []Rule) []string {
	var out []string
	for _, r := range rules {
		for _, b := range r.Backends {
			out = append(out, b.Name)
		}
	}
	return out
}

func TestRulesForGatewayDropsUnresolvedCrossNS(t *testing.T) {
	gw := types.NamespacedName{Namespace: "gwns", Name: "gw"}

	ok := resolvedRoute(metav1.ConditionTrue, true)
	if got := backendNames(rulesForGateway([]gwv1.HTTPRoute{ok}, gw)); len(got) != 2 {
		t.Errorf("resolved: backends = %v, want both", got)
	}

	bad := resolvedRoute(metav1.ConditionFalse, true)
	got := backendNames(rulesForGateway([]gwv1.HTTPRoute{bad}, gw))
	if len(got) != 1 || got[0] != localBackend {
		t.Errorf("unresolved: backends = %v, want [local]", got)
	}

	unknown := resolvedRoute(metav1.ConditionUnknown, true)
	got = backendNames(rulesForGateway([]gwv1.HTTPRoute{unknown}, gw))
	if len(got) != 1 || got[0] != localBackend {
		t.Errorf("unknown condition: backends = %v, want [local]", got)
	}

	// Status value is irrelevant here: no ResolvedRefs condition is present at all.
	none := resolvedRoute(metav1.ConditionTrue, false)
	got = backendNames(rulesForGateway([]gwv1.HTTPRoute{none}, gw))
	if len(got) != 1 || got[0] != localBackend {
		t.Errorf("missing condition: backends = %v, want [local]", got)
	}
}
