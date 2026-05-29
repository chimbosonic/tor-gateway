/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func grant(ns string, from gwv1beta1.ReferenceGrantFrom, to gwv1beta1.ReferenceGrantTo) gwv1beta1.ReferenceGrant {
	return gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: ns},
		Spec:       gwv1beta1.ReferenceGrantSpec{From: []gwv1beta1.ReferenceGrantFrom{from}, To: []gwv1beta1.ReferenceGrantTo{to}},
	}
}

func TestAllows(t *testing.T) {
	httpRouteFrom := gwv1beta1.ReferenceGrantFrom{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: "team-a"}
	serviceToAny := gwv1beta1.ReferenceGrantTo{Group: "", Kind: "Service"}
	serviceToEmpty := gwv1beta1.ReferenceGrantTo{Group: "", Kind: "Service", Name: ptr.To(gwv1.ObjectName(""))}
	serviceToNamed := gwv1beta1.ReferenceGrantTo{Group: "", Kind: "Service", Name: ptr.To(gwv1.ObjectName("app"))}

	from := FromRef{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: "team-a"}
	to := ToRef{Group: "", Kind: "Service", Name: "app"}

	tests := []struct {
		name   string
		grants []gwv1beta1.ReferenceGrant
		from   FromRef
		to     ToRef
		want   bool
	}{
		{"any-name grant permits", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToAny)}, from, to, true},
		{"explicit empty-name grant permits", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToEmpty)}, from, to, true},
		{"named grant permits matching name", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToNamed)}, from, to, true},
		{"named grant denies other name", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToNamed)}, from, ToRef{Group: "", Kind: "Service", Name: "other"}, false},
		{"wrong from namespace denies", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToAny)}, FromRef{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: "team-x"}, to, false},
		{"wrong to kind denies", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, gwv1beta1.ReferenceGrantTo{Group: "", Kind: "Secret"})}, from, to, false},
		{"no grants denies", nil, from, to, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Allows(tc.grants, tc.from, tc.to); got != tc.want {
				t.Errorf("Allows = %v, want %v", got, tc.want)
			}
		})
	}
}
