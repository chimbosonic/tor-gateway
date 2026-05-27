/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func gwScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := gwv1.Install(s); err != nil {
		t.Fatalf("install gateway-api scheme: %v", err)
	}
	return s
}

func TestRouteSync_PopulatesTableFromCluster(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(ghostBackend))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	route := routeFor("prod", "blog", "blog-gw", ghostBackend)
	c := fake.NewClientBuilder().WithScheme(gwScheme(t)).WithObjects(&route).Build()

	// Inject a resolver pointing at the test backend so we exercise the full
	// match->proxy path without real cluster DNS.
	proxy := NewProxy(func(Backend) (*url.URL, bool) { return backendURL, true })
	s := &routeSync{
		reader: c,
		gw:     types.NamespacedName{Namespace: "prod", Name: "blog-gw"},
		proxy:  proxy,
	}

	if err := s.sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (route synced from cluster and proxied)", rec.Code)
	}
	if got := rec.Body.String(); got != ghostBackend {
		t.Fatalf("body = %q, want %q", got, ghostBackend)
	}
}

func TestRouteSync_RebuildsFreshOnReSync(t *testing.T) {
	route := routeFor("prod", "blog", "blog-gw", ghostBackend)
	c := fake.NewClientBuilder().WithScheme(gwScheme(t)).WithObjects(&route).Build()

	backendURL, _ := url.Parse("http://unused.example")
	proxy := NewProxy(func(Backend) (*url.URL, bool) { return backendURL, true })
	s := &routeSync{
		reader: c,
		gw:     types.NamespacedName{Namespace: "prod", Name: "blog-gw"},
		proxy:  proxy,
	}

	if err := s.sync(context.Background()); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	// Delete the route and re-sync: the table must reflect the now-empty
	// cluster, not retain the old route.
	if err := c.Delete(context.Background(), &route); err != nil {
		t.Fatalf("delete route: %v", err)
	}
	if err := s.sync(context.Background()); err != nil {
		t.Fatalf("re-sync: %v", err)
	}

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (deleted route should no longer match)", rec.Code)
	}
}
