/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"net/http/httptest"
	"testing"
)

func TestRouteTable_ExactPathMatch(t *testing.T) {
	rt := NewRouteTable([]Rule{{
		Matches:  []Match{{Path: PathMatch{Type: PathExact, Value: "/foo"}}},
		Backends: []Backend{{Namespace: "default", Name: "svc", Port: 8080}},
	}})

	got, ok := rt.Match(httptest.NewRequest("GET", "/foo", nil))
	if !ok {
		t.Fatal("expected a match for /foo")
	}
	if got.Name != "svc" || got.Port != 8080 {
		t.Fatalf("got %+v, want svc:8080", got)
	}
}

func TestRouteTable_NoMatch(t *testing.T) {
	rt := NewRouteTable([]Rule{{
		Matches:  []Match{{Path: PathMatch{Type: PathExact, Value: "/foo"}}},
		Backends: []Backend{{Name: "svc", Port: 8080}},
	}})
	if _, ok := rt.Match(httptest.NewRequest("GET", "/bar", nil)); ok {
		t.Fatal("expected no match for /bar")
	}
}

func TestRouteTable_PathPrefixMatch(t *testing.T) {
	rt := NewRouteTable([]Rule{{
		Matches:  []Match{{Path: PathMatch{Type: PathPrefix, Value: "/api"}}},
		Backends: []Backend{{Name: "api", Port: 80}},
	}})

	cases := []struct {
		path string
		want bool
	}{
		{"/api", true},       // prefix matches the segment itself
		{"/api/", true},      // trailing slash
		{"/api/users", true}, // sub-path
		{"/apiv2", false},    // not a path-segment boundary
		{"/", false},         // unrelated
	}
	for _, tc := range cases {
		_, ok := rt.Match(httptest.NewRequest("GET", tc.path, nil))
		if ok != tc.want {
			t.Errorf("path %q: matched=%v, want %v", tc.path, ok, tc.want)
		}
	}
}

func TestRouteTable_Precedence(t *testing.T) {
	// Rules listed prefix-first to prove ordering doesn't decide the winner.
	rt := NewRouteTable([]Rule{
		{
			Matches:  []Match{{Path: PathMatch{Type: PathPrefix, Value: "/"}}},
			Backends: []Backend{{Name: "catchall", Port: 80}},
		},
		{
			Matches:  []Match{{Path: PathMatch{Type: PathPrefix, Value: "/api"}}},
			Backends: []Backend{{Name: "api", Port: 80}},
		},
		{
			Matches:  []Match{{Path: PathMatch{Type: PathExact, Value: "/api/health"}}},
			Backends: []Backend{{Name: "health", Port: 80}},
		},
	})

	cases := []struct {
		path string
		want string
	}{
		{"/api/health", "health"}, // exact beats both prefixes
		{"/api/users", "api"},     // longer prefix beats "/"
		{"/other", "catchall"},    // only "/" matches
	}
	for _, tc := range cases {
		got, ok := rt.Match(httptest.NewRequest("GET", tc.path, nil))
		if !ok {
			t.Errorf("path %q: expected a match", tc.path)
			continue
		}
		if got.Name != tc.want {
			t.Errorf("path %q: routed to %q, want %q", tc.path, got.Name, tc.want)
		}
	}
}
