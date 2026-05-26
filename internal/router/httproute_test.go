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
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestRulesFromHTTPRoute_PathAndBackend(t *testing.T) {
	prefix := gwv1.PathMatchPathPrefix
	pathVal := "/api"
	port := gwv1.PortNumber(8080)
	route := gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod"},
		Spec: gwv1.HTTPRouteSpec{
			Rules: []gwv1.HTTPRouteRule{{
				Matches: []gwv1.HTTPRouteMatch{{
					Path: &gwv1.HTTPPathMatch{Type: &prefix, Value: &pathVal},
				}},
				BackendRefs: []gwv1.HTTPBackendRef{{
					BackendRef: gwv1.BackendRef{
						BackendObjectReference: gwv1.BackendObjectReference{
							Name: "api-svc",
							Port: &port,
						},
					},
				}},
			}},
		},
	}

	rules := RulesFromHTTPRoute(route)
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if len(r.Matches) != 1 || r.Matches[0].Path.Type != PathPrefix || r.Matches[0].Path.Value != "/api" {
		t.Fatalf("match = %+v, want PathPrefix /api", r.Matches)
	}
	if len(r.Backends) != 1 {
		t.Fatalf("got %d backends, want 1", len(r.Backends))
	}
	b := r.Backends[0]
	if b.Name != "api-svc" || b.Port != 8080 || b.Namespace != "prod" {
		t.Fatalf("backend = %+v, want api-svc:8080 in prod", b)
	}
}

func TestRulesFromHTTPRoute_DefaultsAndExplicitNamespace(t *testing.T) {
	backendNS := gwv1.Namespace("shared")
	route := gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod"},
		Spec: gwv1.HTTPRouteSpec{
			Rules: []gwv1.HTTPRouteRule{{
				// No matches => implicit "/" prefix (Gateway API default).
				BackendRefs: []gwv1.HTTPBackendRef{{
					BackendRef: gwv1.BackendRef{
						BackendObjectReference: gwv1.BackendObjectReference{
							Name:      "other-svc",
							Namespace: &backendNS,
							// No port.
						},
					},
				}},
			}},
		},
	}

	rules := RulesFromHTTPRoute(route)
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if len(rules[0].Matches) != 1 || rules[0].Matches[0].Path != (PathMatch{Type: PathPrefix, Value: "/"}) {
		t.Fatalf("missing matches should default to PathPrefix /, got %+v", rules[0].Matches)
	}
	b := rules[0].Backends[0]
	if b.Namespace != "shared" {
		t.Fatalf("explicit backendRef namespace = %q, want shared", b.Namespace)
	}
	if b.Port != 0 {
		t.Fatalf("absent port should be 0, got %d", b.Port)
	}
}
