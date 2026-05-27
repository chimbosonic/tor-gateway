/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// rulesForGateway selects the HTTPRoutes whose parentRefs target gw and
// aggregates their compiled rules into a single slice. Pure: no cluster
// access. The informer calls this on every HTTPRoute change to rebuild the
// RouteTable.
func rulesForGateway(routes []gwv1.HTTPRoute, gw types.NamespacedName) []Rule {
	var rules []Rule
	for _, route := range routes {
		if routeTargetsGateway(route, gw) {
			rules = append(rules, RulesFromHTTPRoute(route)...)
		}
	}
	return rules
}

// routeTargetsGateway reports whether route has a parentRef naming gw. A
// parentRef without an explicit namespace defaults to the route's own
// namespace, per the Gateway API.
func routeTargetsGateway(route gwv1.HTTPRoute, gw types.NamespacedName) bool {
	for _, ref := range route.Spec.ParentRefs {
		if string(ref.Name) != gw.Name {
			continue
		}
		// Kind/Group default to Gateway / gateway.networking.k8s.io; anything
		// else (e.g. a Service mesh parentRef) is not our Gateway.
		if ref.Kind != nil && *ref.Kind != "Gateway" {
			continue
		}
		if ref.Group != nil && *ref.Group != gwv1.GroupName {
			continue
		}
		ns := route.Namespace
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		if ns == gw.Namespace {
			return true
		}
	}
	return false
}
