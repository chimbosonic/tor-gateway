//go:build conformance

/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package conformance verifies that a deployed tor-gateway operator
// satisfies the Gateway API *status contract* for the resources it manages.
//
// We deliberately do NOT run the upstream sigs.k8s.io/gateway-api
// conformance suite: that suite's GATEWAY-HTTP profile creates a dozen
// standard HTTP Gateways and drives real L7 traffic to IP-reachable
// addresses. A Tor hidden-service gateway publishes `.onion` addresses
// reachable only over Tor, so the upstream traffic tests cannot pass by
// construction, and provisioning a Tor pod per conformance Gateway
// overwhelms a single-node Kind cluster.
//
// Instead this test asserts the slice of the Gateway API contract we DO
// implement against the real, deployed operator (not envtest's manual
// Reconcile calls):
//
//   - GatewayClass is Accepted.
//   - A Gateway of our class becomes Accepted and Programmed.
//   - The Gateway publishes a v3 .onion address as a Hostname-typed
//     status address.
//   - Per-listener status is reported.
//
// Build with the `conformance` tag; the Makefile test-conformance target
// stands up Kind, deploys the operator, applies the GatewayClass, then
// runs this.
package conformance

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

const (
	gatewayClassName = "tor-gateway"
	testNamespace    = "tor-gateway-conformance"
	gatewayName      = "shape"
	hiddenSvcProto   = gwv1.ProtocolType("torgateway.io/HiddenService")
	pollTimeout      = 90 * time.Second
	pollInterval     = 2 * time.Second
)

var onionRE = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

func newClient(t *testing.T) client.Client {
	t.Helper()
	cfg, err := ctrlconfig.GetConfig()
	if err != nil {
		t.Fatalf("load kubeconfig: %v", err)
	}
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gwv1.Install(scheme))
	utilruntime.Must(gwv1beta1.Install(scheme))
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	return c
}

func TestGatewayClassAccepted(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	waitCondition(t, func() (string, bool) {
		gc := &gwv1.GatewayClass{}
		if err := c.Get(ctx, client.ObjectKey{Name: gatewayClassName}, gc); err != nil {
			return "GatewayClass not found yet: " + err.Error(), false
		}
		return conditionStatus(gc.Status.Conditions, string(gwv1.GatewayClassConditionStatusAccepted))
	}, "GatewayClass %q should be Accepted=True", gatewayClassName)
}

func TestGatewayStatusContract(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	// Namespace + Gateway, cleaned up at the end.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := c.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: testNamespace},
		Spec: gwv1.GatewaySpec{
			GatewayClassName: gatewayClassName,
			Listeners: []gwv1.Listener{{
				Name:     "onion",
				Port:     80,
				Protocol: hiddenSvcProto,
			}},
		},
	}
	if err := c.Create(ctx, gw); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create Gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Delete(ctx, gw)
		_ = c.Delete(ctx, ns)
	})

	// Poll for the full status contract in one place so a failure reports
	// the last-observed state.
	waitCondition(t, func() (string, bool) {
		got := &gwv1.Gateway{}
		if err := c.Get(ctx, client.ObjectKey{Name: gatewayName, Namespace: testNamespace}, got); err != nil {
			return "get Gateway: " + err.Error(), false
		}
		if msg, ok := conditionStatus(got.Status.Conditions, string(gwv1.GatewayConditionAccepted)); !ok {
			return "Accepted: " + msg, false
		}
		if msg, ok := conditionStatus(got.Status.Conditions, string(gwv1.GatewayConditionProgrammed)); !ok {
			return "Programmed: " + msg, false
		}
		if len(got.Status.Addresses) == 0 {
			return "no status.addresses yet", false
		}
		addr := got.Status.Addresses[0]
		if addr.Type == nil || *addr.Type != gwv1.HostnameAddressType {
			return "address type is not Hostname", false
		}
		if !onionRE.MatchString(addr.Value) {
			return "address %q is not a v3 .onion: " + addr.Value, false
		}
		if len(got.Status.Listeners) == 0 {
			return "no per-listener status yet", false
		}
		return "", true
	}, "Gateway %q should satisfy the Gateway API status contract", gatewayName)
}

// waitCondition polls fn until it returns ok, or fails the test with the
// last status message after pollTimeout.
func waitCondition(t *testing.T, fn func() (msg string, ok bool), format string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	var last string
	for time.Now().Before(deadline) {
		msg, ok := fn()
		if ok {
			return
		}
		last = msg
		time.Sleep(pollInterval)
	}
	t.Fatalf(format+"\n  last observed: %s", append(args, last)...)
}

// conditionStatus returns (message, true) when the named condition is
// present with Status=True, otherwise (reason, false).
func conditionStatus(conds []metav1.Condition, condType string) (string, bool) {
	for _, c := range conds {
		if c.Type != condType {
			continue
		}
		if c.Status == metav1.ConditionTrue {
			return "", true
		}
		return strings.TrimSpace(string(c.Status) + " " + c.Reason), false
	}
	return "condition absent", false
}

// routeParentReason returns (reason, true) when the named condition on the
// route's parent (matched by our ControllerName) has Status=True, else
// (reason, false). Returns ("absent", false) when the condition is missing.
func routeParentReason(route *gwv1.HTTPRoute, condType string) (string, bool) {
	const controllerName = gwv1.GatewayController("torgateway.io/gateway-controller")
	for _, p := range route.Status.Parents {
		if p.ControllerName != controllerName {
			continue
		}
		for _, c := range p.Conditions {
			if c.Type == condType {
				return c.Reason, c.Status == metav1.ConditionTrue
			}
		}
	}
	return "absent", false
}

func TestRouteResolvedRefsContract(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	const (
		routeNS   = "tor-gateway-conformance-rg"
		backendNS = "tor-gateway-conformance-rg-backend"
		routeName = "rg-route"
	)
	for _, name := range []string{routeNS, backendNS} {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := c.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create namespace %s: %v", name, err)
		}
	}

	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "rg-gw", Namespace: routeNS},
		Spec: gwv1.GatewaySpec{
			GatewayClassName: gatewayClassName,
			Listeners:        []gwv1.Listener{{Name: "onion", Port: 80, Protocol: hiddenSvcProto}},
		},
	}
	if err := c.Create(ctx, gw); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create Gateway: %v", err)
	}

	port := gwv1.PortNumber(80)
	bns := gwv1.Namespace(backendNS)
	route := &gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: routeName, Namespace: routeNS},
		Spec: gwv1.HTTPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{ParentRefs: []gwv1.ParentReference{{Name: "rg-gw"}}},
			Rules: []gwv1.HTTPRouteRule{{
				BackendRefs: []gwv1.HTTPBackendRef{{BackendRef: gwv1.BackendRef{
					BackendObjectReference: gwv1.BackendObjectReference{Name: "app", Namespace: &bns, Port: &port},
				}}},
			}},
		},
	}
	if err := c.Create(ctx, route); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create HTTPRoute: %v", err)
	}

	waitCondition(t, func() (string, bool) {
		got := &gwv1.HTTPRoute{}
		if err := c.Get(ctx, client.ObjectKey{Name: routeName, Namespace: routeNS}, got); err != nil {
			return "get route: " + err.Error(), false
		}
		reason, ok := routeParentReason(got, string(gwv1.RouteConditionResolvedRefs))
		if ok || reason != "RefNotPermitted" {
			return "want ResolvedRefs=False/RefNotPermitted, got reason=" + reason, false
		}
		return "", true
	}, "ungated cross-ns backendRef should be RefNotPermitted")

	grant := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-routes", Namespace: backendNS},
		Spec: gwv1beta1.ReferenceGrantSpec{
			From: []gwv1beta1.ReferenceGrantFrom{{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: gwv1beta1.Namespace(routeNS)}},
			To:   []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Service"}},
		},
	}
	if err := c.Create(ctx, grant); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create ReferenceGrant: %v", err)
	}

	waitCondition(t, func() (string, bool) {
		got := &gwv1.HTTPRoute{}
		if err := c.Get(ctx, client.ObjectKey{Name: routeName, Namespace: routeNS}, got); err != nil {
			return "get route: " + err.Error(), false
		}
		reason, ok := routeParentReason(got, string(gwv1.RouteConditionResolvedRefs))
		if !ok || reason != "ResolvedRefs" {
			return "want ResolvedRefs=True, got reason=" + reason, false
		}
		return "", true
	}, "granted cross-ns backendRef should be ResolvedRefs")
}
