/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

// FromRef identifies the referrer (group/kind/namespace) in a cross-namespace
// reference being authorized.
type FromRef struct{ Group, Kind, Namespace string }

// ToRef identifies the referent (group/kind/name). Core API group is "".
type ToRef struct{ Group, Kind, Name string }

// Allows reports whether any ReferenceGrant permits the from→to reference. A
// grant permits it when it has a matching `from` entry AND a matching `to`
// entry (a `to` with empty Name matches any object of that group/kind). The
// caller must pass grants from the referent's (to) namespace.
func Allows(grants []gwv1beta1.ReferenceGrant, from FromRef, to ToRef) bool {
	for i := range grants {
		g := &grants[i]
		if grantMatchesFrom(g, from) && grantMatchesTo(g, to) {
			return true
		}
	}
	return false
}

func grantMatchesFrom(g *gwv1beta1.ReferenceGrant, from FromRef) bool {
	for _, f := range g.Spec.From {
		if string(f.Group) == from.Group && string(f.Kind) == from.Kind && string(f.Namespace) == from.Namespace {
			return true
		}
	}
	return false
}

func grantMatchesTo(g *gwv1beta1.ReferenceGrant, to ToRef) bool {
	for _, t := range g.Spec.To {
		if string(t.Group) != to.Group || string(t.Kind) != to.Kind {
			continue
		}
		if t.Name == nil || string(*t.Name) == "" || string(*t.Name) == to.Name {
			return true
		}
	}
	return false
}
