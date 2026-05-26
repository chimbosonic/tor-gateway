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

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
)

var _ = Describe("TorClientAuthPolicy status", func() {
	ctx := context.Background()

	reconcileTCAP := func(name, ns string) *policyv1alpha1.TorClientAuthPolicy {
		GinkgoHelper()
		r := &TorClientAuthPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: ns},
		})
		Expect(err).NotTo(HaveOccurred())
		out := &policyv1alpha1.TorClientAuthPolicy{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, out)).To(Succeed())
		return out
	}

	makeTCAP := func(name, gwName string) *policyv1alpha1.TorClientAuthPolicy {
		tcap := &policyv1alpha1.TorClientAuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: policyv1alpha1.TorClientAuthPolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  gwv1.ObjectName(gwName),
				}},
				ClientsSecretRef: policyv1alpha1.ClientsSecretRef{Name: "client-keys"},
			},
		}
		Expect(k8sClient.Create(ctx, tcap)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, tcap) })
		return tcap
	}

	BeforeEach(func() {
		gc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway-test"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
		}
		if err := k8sClient.Create(ctx, gc); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}
	})

	It("reports Accepted=True when target Gateway is managed by us", func() {
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "tcap-accept-gw", Namespace: "default"},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "tor-gateway-test",
				Listeners: []gwv1.Listener{{
					Name: "onion", Port: 80, Protocol: HiddenServiceProtocol,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gw) })

		tcap := makeTCAP("tcap-accept", gw.Name)
		got := reconcileTCAP(tcap.Name, tcap.Namespace)
		assertTcapAccepted(got, metav1.ConditionTrue, string(gwv1.PolicyReasonAccepted))
	})

	It("reports TargetNotFound when the Gateway does not exist", func() {
		tcap := makeTCAP("tcap-missing", "no-such-gateway")
		got := reconcileTCAP(tcap.Name, tcap.Namespace)
		assertTcapAccepted(got, metav1.ConditionFalse, "TargetNotFound")
	})

	It("reports TargetNotManaged when the Gateway has a foreign class", func() {
		fc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "foreign-tcap"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: "example.com/other"},
		}
		if err := k8sClient.Create(ctx, fc); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, fc) })

		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "tcap-foreign-gw", Namespace: "default"},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "foreign-tcap",
				Listeners: []gwv1.Listener{{
					Name: "x", Port: 80, Protocol: "HTTP",
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gw) })

		tcap := makeTCAP("tcap-foreign", gw.Name)
		got := reconcileTCAP(tcap.Name, tcap.Namespace)
		assertTcapAccepted(got, metav1.ConditionFalse, "TargetNotManaged")
	})
})

func assertTcapAccepted(tcap *policyv1alpha1.TorClientAuthPolicy, status metav1.ConditionStatus, reason string) {
	GinkgoHelper()
	Expect(tcap.Status.Ancestors).NotTo(BeEmpty())
	for _, c := range tcap.Status.Ancestors[0].Conditions {
		if c.Type == string(gwv1.PolicyConditionAccepted) {
			Expect(c.Status).To(Equal(status))
			Expect(c.Reason).To(Equal(reason))
			return
		}
	}
	Fail("client-auth policy ancestor missing Accepted condition")
}
