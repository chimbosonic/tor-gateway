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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var _ = Describe("GatewayClass reconciler", func() {
	ctx := context.Background()

	reconcileAndGet := func(name string) *gwv1.GatewayClass {
		GinkgoHelper()
		r := &GatewayClassReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
		Expect(err).NotTo(HaveOccurred())
		out := &gwv1.GatewayClass{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, out)).To(Succeed())
		return out
	}

	It("marks a matching GatewayClass Accepted", func() {
		gc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
		}
		Expect(k8sClient.Create(ctx, gc)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gc) })

		got := reconcileAndGet("tor-gateway")
		var accepted *metav1.Condition
		for i := range got.Status.Conditions {
			c := &got.Status.Conditions[i]
			if c.Type == string(gwv1.GatewayClassConditionStatusAccepted) {
				accepted = c
				break
			}
		}
		Expect(accepted).NotTo(BeNil())
		Expect(accepted.Status).To(Equal(metav1.ConditionTrue))
		Expect(accepted.Reason).To(Equal(string(gwv1.GatewayClassReasonAccepted)))
	})

	It("ignores GatewayClasses owned by other controllers", func() {
		gc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "other-gateway"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: "example.com/other"},
		}
		Expect(k8sClient.Create(ctx, gc)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gc) })

		// The apiserver default-populates a Pending/Unknown Accepted
		// condition on creation per the Gateway API spec. Our reconciler
		// must NOT replace it with our own Accepted=True for a foreign
		// controllerName.
		got := reconcileAndGet("other-gateway")
		var accepted *metav1.Condition
		for i := range got.Status.Conditions {
			c := &got.Status.Conditions[i]
			if c.Type == string(gwv1.GatewayClassConditionStatusAccepted) {
				accepted = c
				break
			}
		}
		Expect(accepted).NotTo(BeNil(), "spec-defaulted Accepted condition should still be present")
		Expect(accepted.Status).To(Equal(metav1.ConditionUnknown))
		Expect(accepted.Reason).To(Equal("Pending"),
			"foreign GatewayClass should keep its Pending status, not flip to our Accepted reason")
	})

	It("does not error when the GatewayClass is missing", func() {
		r := &GatewayClassReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "absent"}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("is idempotent: re-running doesn't bump LastTransitionTime", func() {
		gc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway-idem"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
		}
		Expect(k8sClient.Create(ctx, gc)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gc) })

		first := reconcileAndGet("tor-gateway-idem")
		firstTime := first.Status.Conditions[0].LastTransitionTime
		second := reconcileAndGet("tor-gateway-idem")
		secondTime := second.Status.Conditions[0].LastTransitionTime
		Expect(secondTime.Equal(&firstTime)).To(BeTrue(),
			"LastTransitionTime moved despite no status change")
	})
})
