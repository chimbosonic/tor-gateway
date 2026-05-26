/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import gwv1 "sigs.k8s.io/gateway-api/apis/v1"

// RulesFromHTTPRoute converts a Gateway API HTTPRoute into the router's
// internal []Rule. Pure: no cluster access. A backendRef without an
// explicit namespace inherits the route's namespace.
func RulesFromHTTPRoute(route gwv1.HTTPRoute) []Rule {
	rules := make([]Rule, 0, len(route.Spec.Rules))
	for _, hr := range route.Spec.Rules {
		rules = append(rules, Rule{
			Matches:  convertMatches(hr.Matches),
			Backends: convertBackends(hr.BackendRefs, route.Namespace),
		})
	}
	return rules
}

func convertMatches(matches []gwv1.HTTPRouteMatch) []Match {
	// An HTTPRouteRule with no matches defaults to a PathPrefix "/" match.
	if len(matches) == 0 {
		return []Match{{Path: PathMatch{Type: PathPrefix, Value: "/"}}}
	}
	out := make([]Match, 0, len(matches))
	for _, m := range matches {
		out = append(out, Match{Path: convertPath(m.Path)})
	}
	return out
}

// convertPath maps an HTTPPathMatch to our PathMatch, applying the Gateway
// API defaults (PathPrefix "/" when fields are unset).
func convertPath(p *gwv1.HTTPPathMatch) PathMatch {
	out := PathMatch{Type: PathPrefix, Value: "/"}
	if p == nil {
		return out
	}
	if p.Type != nil {
		switch *p.Type {
		case gwv1.PathMatchExact:
			out.Type = PathExact
		case gwv1.PathMatchPathPrefix:
			out.Type = PathPrefix
		}
	}
	if p.Value != nil {
		out.Value = *p.Value
	}
	return out
}

func convertBackends(refs []gwv1.HTTPBackendRef, routeNS string) []Backend {
	out := make([]Backend, 0, len(refs))
	for _, ref := range refs {
		b := Backend{
			Name:      string(ref.Name),
			Namespace: routeNS,
		}
		if ref.Namespace != nil {
			b.Namespace = string(*ref.Namespace)
		}
		if ref.Port != nil {
			b.Port = *ref.Port
		}
		out = append(out, b)
	}
	return out
}
