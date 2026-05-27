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
