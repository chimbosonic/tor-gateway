/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProxy_RoutesToMatchedBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello from backend " + r.URL.Path))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	p := NewProxy(func(Backend) (*url.URL, bool) { return backendURL, true })
	p.SetTable(NewRouteTable([]Rule{{
		Matches:  []Match{{Path: PathMatch{Type: PathPrefix, Value: "/"}}},
		Backends: []Backend{{Name: "svc", Port: 80}},
	}}))

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/foo", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "hello from backend /foo") {
		t.Fatalf("body = %q, want backend response", rec.Body.String())
	}
}

func TestProxy_NoMatchReturns404(t *testing.T) {
	p := NewProxy(func(Backend) (*url.URL, bool) { return nil, false })
	p.SetTable(NewRouteTable(nil))

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestProxy_UnresolvableBackendReturns502(t *testing.T) {
	p := NewProxy(func(Backend) (*url.URL, bool) { return nil, false })
	p.SetTable(NewRouteTable([]Rule{{
		Matches:  []Match{{Path: PathMatch{Type: PathPrefix, Value: "/"}}},
		Backends: []Backend{{Name: "svc", Port: 80}},
	}}))

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/foo", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}
