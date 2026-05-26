//go:build conformance

/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package conformance runs the upstream Gateway API conformance suite
// against a live cluster (typically kind in CI) that has tor-gateway
// installed.
//
// Build with the `conformance` tag; the suite reads its kubeconfig and
// command-line flags from the runner (the Makefile target test-conformance
// supplies them). Sample invocation:
//
//	go test -tags=conformance -timeout 30m ./test/conformance \
//	  -args \
//	    -gateway-class=tor-gateway \
//	    -supported-features=Gateway \
//	    -conformance-profiles=GATEWAY-HTTP \
//	    -implementation-name=tor-gateway \
//	    -implementation-organization=chimbosonic
//
// Features we currently claim are intentionally minimal; we will widen
// the claim as we implement BackendRefs routing, BackendTLSPolicy, etc.
package conformance

import (
	"testing"

	"sigs.k8s.io/gateway-api/conformance"
)

func TestConformance(t *testing.T) {
	conformance.RunConformance(t)
}
