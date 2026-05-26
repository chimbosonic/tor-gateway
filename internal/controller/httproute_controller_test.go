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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var _ = Describe("HTTPRoute reconciler", func() {
	ctx := context.Background()

	reconcileRoute := func(name, ns string) *gwv1.HTTPRoute {
		GinkgoHelper()
		r := &HTTPRouteReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: ns},
		})
		Expect(err).NotTo(HaveOccurred())
		out := &gwv1.HTTPRoute{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, out)).To(Succeed())
		return out
	}

	makeRoute := func(name, ns, parentGW string, sectionName *gwv1.SectionName) *gwv1.HTTPRoute {
		route := &gwv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: gwv1.HTTPRouteSpec{
				CommonRouteSpec: gwv1.CommonRouteSpec{
					ParentRefs: []gwv1.ParentReference{{
						Name:        gwv1.ObjectName(parentGW),
						SectionName: sectionName,
					}},
				},
				Rules: []gwv1.HTTPRouteRule{{
					BackendRefs: []gwv1.HTTPBackendRef{{
						BackendRef: gwv1.BackendRef{
							BackendObjectReference: gwv1.BackendObjectReference{
								Name: "test-backend",
								Port: ptr.To[gwv1.PortNumber](80),
							},
						},
					}},
				}},
			},
		}
		Expect(k8sClient.Create(ctx, route)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, route) })
		return route
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

	It("accepts a route attached to a managed Gateway", func() {
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "rt-gw", Namespace: "default"},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "tor-gateway-test",
				Listeners: []gwv1.Listener{{
					Name: "onion", Port: 80, Protocol: HiddenServiceProtocol,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gw) })

		route := makeRoute("rt-accept", "default", gw.Name, nil)
		got := reconcileRoute(route.Name, route.Namespace)

		Expect(got.Status.Parents).To(HaveLen(1))
		Expect(got.Status.Parents[0].ControllerName).To(Equal(ControllerName))
		assertRouteAccepted(got, metav1.ConditionTrue, string(gwv1.RouteReasonAccepted))
	})

	It("ignores a route attached to a foreign Gateway", func() {
		fc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "foreign-route-class"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: "example.com/other"},
		}
		if err := k8sClient.Create(ctx, fc); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, fc) })

		fgw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "rt-foreign-gw", Namespace: "default"},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "foreign-route-class",
				Listeners: []gwv1.Listener{{
					Name: "x", Port: 80, Protocol: "HTTP",
				}},
			},
		}
		Expect(k8sClient.Create(ctx, fgw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, fgw) })

		route := makeRoute("rt-ignore", "default", fgw.Name, nil)
		got := reconcileRoute(route.Name, route.Namespace)

		for _, p := range got.Status.Parents {
			Expect(p.ControllerName).NotTo(Equal(ControllerName),
				"foreign route should not have our controller name in status")
		}
	})

	It("reports NoMatchingParent when SectionName does not exist", func() {
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "rt-section-gw", Namespace: "default"},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "tor-gateway-test",
				Listeners: []gwv1.Listener{{
					Name: "real-listener", Port: 80, Protocol: HiddenServiceProtocol,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gw) })

		section := gwv1.SectionName("nonexistent")
		route := makeRoute("rt-bad-section", "default", gw.Name, &section)
		got := reconcileRoute(route.Name, route.Namespace)

		Expect(got.Status.Parents).To(HaveLen(1))
		assertRouteAccepted(got, metav1.ConditionFalse, string(gwv1.RouteReasonNoMatchingParent))
	})

	It("updates Gateway listener AttachedRoutes counter", func() {
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "rt-count-gw", Namespace: "default"},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "tor-gateway-test",
				Listeners: []gwv1.Listener{{
					Name: "onion", Port: 80, Protocol: HiddenServiceProtocol,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gw) })

		// Bootstrap Gateway status so listener entries exist before we touch them.
		gr := &GatewayReconciler{
			Client: k8sClient, Scheme: k8sClient.Scheme(),
			Images: RuntimeImages{Tor: "t", Router: "r", TorInit: "i", Operator: "m"},
		}
		_, err := gr.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace},
		})
		Expect(err).NotTo(HaveOccurred())

		_ = makeRoute("rt-count-a", "default", gw.Name, nil)
		_ = makeRoute("rt-count-b", "default", gw.Name, nil)
		reconcileRoute("rt-count-a", "default")
		reconcileRoute("rt-count-b", "default")

		got := &gwv1.Gateway{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, got)).To(Succeed())
		Expect(got.Status.Listeners).To(HaveLen(1))
		Expect(got.Status.Listeners[0].AttachedRoutes).To(BeNumerically("==", 2))
	})
})

func assertRouteAccepted(route *gwv1.HTTPRoute, status metav1.ConditionStatus, reason string) {
	GinkgoHelper()
	Expect(route.Status.Parents).NotTo(BeEmpty())
	conds := route.Status.Parents[0].Conditions
	for _, c := range conds {
		if c.Type == string(gwv1.RouteConditionAccepted) {
			Expect(c.Status).To(Equal(status))
			Expect(c.Reason).To(Equal(reason))
			return
		}
	}
	Fail("route parent missing Accepted condition")
}
