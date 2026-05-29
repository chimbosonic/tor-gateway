/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
)

func TestEffectivePolicyFromUsesGivenReader(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	tsp := &policyv1alpha1.TorServicePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: gw.Namespace},
		Spec: policyv1alpha1.TorServicePolicySpec{
			TargetRefs: []gwv1.LocalPolicyTargetReference{{
				Group: GatewayAPIGroup, Kind: GatewayKind, Name: gwv1.ObjectName(gw.Name),
			}},
			VanityPrefix: "abc",
		},
	}
	withPolicy := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tsp).Build()
	empty := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := &GatewayReconciler{}

	got, err := r.effectivePolicyFrom(context.Background(), withPolicy, gw)
	if err != nil {
		t.Fatal(err)
	}
	if got.VanityPrefix != "abc" {
		t.Errorf("with policy reader: VanityPrefix = %q, want abc", got.VanityPrefix)
	}

	got2, err := r.effectivePolicyFrom(context.Background(), empty, gw)
	if err != nil {
		t.Fatal(err)
	}
	if got2.VanityPrefix != "" {
		t.Errorf("with empty reader: VanityPrefix = %q, want empty", got2.VanityPrefix)
	}
}
