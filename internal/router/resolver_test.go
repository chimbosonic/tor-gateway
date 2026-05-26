/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import "testing"

func TestClusterResolver_BuildsServiceDNS(t *testing.T) {
	u, ok := ClusterResolver()(Backend{Namespace: "prod", Name: "api", Port: 8080})
	if !ok {
		t.Fatal("expected resolvable backend")
	}
	if got := u.String(); got != "http://api.prod.svc:8080" {
		t.Fatalf("url = %q, want http://api.prod.svc:8080", got)
	}
}

func TestClusterResolver_RejectsIncompleteBackend(t *testing.T) {
	cases := []Backend{
		{Namespace: "prod", Port: 8080},  // no name
		{Name: "api", Port: 8080},        // no namespace
		{Namespace: "prod", Name: "api"}, // no port
	}
	for _, b := range cases {
		if _, ok := ClusterResolver()(b); ok {
			t.Errorf("backend %+v should not resolve", b)
		}
	}
}
