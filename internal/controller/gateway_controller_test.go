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
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

var _ = Describe("Gateway reconciler", func() {
	ctx := context.Background()

	makeReconciler := func() *GatewayReconciler {
		return &GatewayReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
			Images: RuntimeImages{
				Tor:      "tor:test",
				Router:   "router:test",
				TorInit:  "init:test",
				Operator: "manager:test",
			},
		}
	}

	reconcileGW := func(name, ns string) {
		GinkgoHelper()
		_, err := makeReconciler().Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: ns},
		})
		Expect(err).NotTo(HaveOccurred())
	}

	BeforeEach(func() {
		gc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway-test"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
		}
		// Idempotent: ignore AlreadyExists errors from earlier tests.
		if err := k8sClient.Create(ctx, gc); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}
	})

	makeGateway := func(name, ns, className string) *gwv1.Gateway {
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: gwv1.ObjectName(className),
				Listeners: []gwv1.Listener{{
					Name:     "onion",
					Port:     80,
					Protocol: HiddenServiceProtocol,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gw) })
		return gw
	}

	It("provisions a Secret, ConfigMap, Deployment, and Service for a managed Gateway", func() {
		gw := makeGateway("blog", "default", "tor-gateway-test")
		reconcileGW(gw.Name, gw.Namespace)

		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: KeySecretName(gw.Name), Namespace: gw.Namespace,
		}, secret)).To(Succeed())
		Expect(secret.Data).To(HaveKey(tor.FileSecretKeyName))
		Expect(secret.Data).To(HaveKey(tor.FilePublicKeyName))
		Expect(secret.Data).To(HaveKey(tor.FileHostnameName))
		Expect(secret.OwnerReferences).To(HaveLen(1))

		cm := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: TorrcConfigMapName(gw.Name), Namespace: gw.Namespace,
		}, cm)).To(Succeed())
		Expect(cm.Data["torrc"]).To(ContainSubstring("HiddenServicePort 80 127.0.0.1:9080"))

		dep := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: DeploymentName(gw.Name), Namespace: gw.Namespace,
		}, dep)).To(Succeed())
		Expect(dep.OwnerReferences).To(HaveLen(1))

		svc := &corev1.Service{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: ServiceName(gw.Name), Namespace: gw.Namespace,
		}, svc)).To(Succeed())

		// Status: .onion in addresses; Accepted+Programmed True.
		out := &gwv1.Gateway{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, out)).To(Succeed())
		Expect(out.Status.Addresses).To(HaveLen(1))
		Expect(strings.HasSuffix(out.Status.Addresses[0].Value, ".onion")).To(BeTrue(),
			"address %q should end with .onion", out.Status.Addresses[0].Value)
		Expect(*out.Status.Addresses[0].Type).To(Equal(gwv1.HostnameAddressType))
		assertGwConditionTrue(out, gwv1.GatewayConditionAccepted)
		assertGwConditionTrue(out, gwv1.GatewayConditionProgrammed)
	})

	It("ignores Gateways with a foreign GatewayClass", func() {
		fc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "foreign-class"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: "example.com/other"},
		}
		Expect(k8sClient.Create(ctx, fc)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, fc) })

		gw := makeGateway("foreign", "default", "foreign-class")
		reconcileGW(gw.Name, gw.Namespace)

		// No children should exist.
		err := k8sClient.Get(ctx, types.NamespacedName{
			Name: KeySecretName(gw.Name), Namespace: gw.Namespace,
		}, &corev1.Secret{})
		Expect(err).To(HaveOccurred(), "no Secret should be created for foreign Gateway")
	})

	It("is key-stable across re-reconcile", func() {
		gw := makeGateway("blog-stable", "default", "tor-gateway-test")
		reconcileGW(gw.Name, gw.Namespace)
		first := &gwv1.Gateway{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, first)).To(Succeed())
		firstOnion := first.Status.Addresses[0].Value

		reconcileGW(gw.Name, gw.Namespace)
		second := &gwv1.Gateway{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, second)).To(Succeed())
		Expect(second.Status.Addresses[0].Value).To(Equal(firstOnion), "key Secret should not be regenerated")
	})

	It("propagates a matching TorServicePolicy into the rendered torrc", func() {
		gw := makeGateway("policied", "default", "tor-gateway-test")

		disabled := false
		tsp := &policyv1alpha1.TorServicePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policied-tsp", Namespace: "default"},
			Spec: policyv1alpha1.TorServicePolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  gwv1.ObjectName(gw.Name),
				}},
				LogLevel:           "debug",
				PoWDefensesEnabled: &disabled,
			},
		}
		Expect(k8sClient.Create(ctx, tsp)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, tsp) })

		reconcileGW(gw.Name, gw.Namespace)
		cm := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: TorrcConfigMapName(gw.Name), Namespace: gw.Namespace,
		}, cm)).To(Succeed())
		Expect(cm.Data["torrc"]).To(ContainSubstring("Log debug stdout"))
		Expect(cm.Data["torrc"]).NotTo(ContainSubstring("HiddenServicePoWDefensesEnabled 1"))
	})

	It("mounts the clients Secret when a Strict TorClientAuthPolicy targets the Gateway", func() {
		gw := makeGateway("strict-auth", "default", "tor-gateway-test")

		tcap := &policyv1alpha1.TorClientAuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "strict-auth-tcap", Namespace: "default"},
			Spec: policyv1alpha1.TorClientAuthPolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  gwv1.ObjectName(gw.Name),
				}},
				ClientsSecretRef: policyv1alpha1.ClientsSecretRef{Name: "strict-auth-clients"},
				Mode:             policyv1alpha1.ClientAuthModeStrict,
			},
		}
		Expect(k8sClient.Create(ctx, tcap)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, tcap) })

		reconcileGW(gw.Name, gw.Namespace)

		dep := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: DeploymentName(gw.Name), Namespace: gw.Namespace,
		}, dep)).To(Succeed())

		hasClientAuthVol := false
		for _, v := range dep.Spec.Template.Spec.Volumes {
			if v.Name == clientAuthVolumeName {
				hasClientAuthVol = true
				Expect(v.Secret).NotTo(BeNil())
				Expect(v.Secret.SecretName).To(Equal("strict-auth-clients"))
			}
		}
		Expect(hasClientAuthVol).To(BeTrue(), "client-auth volume should be added when policy is Strict")
		Expect(dep.Spec.Template.Spec.InitContainers[0].Args).To(
			ContainElement("--client-auth-src"))
	})

	It("does NOT mount the clients Secret when the policy is in Audit mode", func() {
		gw := makeGateway("audit-auth", "default", "tor-gateway-test")

		tcap := &policyv1alpha1.TorClientAuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "audit-auth-tcap", Namespace: "default"},
			Spec: policyv1alpha1.TorClientAuthPolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  gwv1.ObjectName(gw.Name),
				}},
				ClientsSecretRef: policyv1alpha1.ClientsSecretRef{Name: "audit-auth-clients"},
				Mode:             policyv1alpha1.ClientAuthModeAudit,
			},
		}
		Expect(k8sClient.Create(ctx, tcap)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, tcap) })

		reconcileGW(gw.Name, gw.Namespace)

		dep := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: DeploymentName(gw.Name), Namespace: gw.Namespace,
		}, dep)).To(Succeed())
		for _, v := range dep.Spec.Template.Spec.Volumes {
			Expect(v.Name).NotTo(Equal(clientAuthVolumeName),
				"Audit mode must not add the client-auth volume")
		}
	})

	It("re-enqueues Gateway reconciliation when an OnionBalancePolicy targeting it is created", func() {
		gw := makeGateway("obp-watch", "default", "tor-gateway-test")
		reconcileGW(gw.Name, gw.Namespace)

		r := makeReconciler()
		obp := &policyv1alpha1.OnionBalancePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-watch-policy", Namespace: "default"},
			Spec: policyv1alpha1.OnionBalancePolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  gwv1.ObjectName(gw.Name),
				}},
				Replicas:           1,
				MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "obp-watch-master"},
			},
		}
		Expect(k8sClient.Create(ctx, obp)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, obp) })

		reqs := r.gatewaysForOnionBalancePolicy(ctx, obp)
		Expect(reqs).To(HaveLen(1))
		Expect(reqs[0].NamespacedName).To(Equal(types.NamespacedName{
			Namespace: gw.Namespace,
			Name:      gw.Name,
		}))
	})
})

// assertGwConditionTrue asserts the Gateway has the given condition with
// Status=True. Uses Ginkgo helper semantics so the failure points at the
// caller.
func assertGwConditionTrue(gw *gwv1.Gateway, t gwv1.GatewayConditionType) {
	GinkgoHelper()
	for _, c := range gw.Status.Conditions {
		if c.Type == string(t) {
			Expect(c.Status).To(Equal(metav1.ConditionTrue), "condition %s should be True", t)
			return
		}
	}
	Fail("missing condition: " + string(t))
}

// client_IgnoreAlreadyExists wraps client.IgnoreAlreadyExists for callers that
// don't want to import the package directly in this file. Avoids a circular
// import gotcha during test refactors.
func client_IgnoreAlreadyExists(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

var _ = Describe("Gateway NetworkPolicy", func() {
	ctx := context.Background()

	const (
		ns      = "np-test"
		gwClass = "tor-gateway-test"
		svcName = "np-app"
	)

	// gatewayReconciler is shared across specs so the "disable flag" case can
	// toggle TorPodNetworkPolicyEnabled and observe the NP deletion path on
	// the next manual Reconcile.
	var gatewayReconciler *GatewayReconciler

	makeGateway := func(name, namespace, className string) *gwv1.Gateway {
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: gwv1.ObjectName(className),
				Listeners: []gwv1.Listener{{
					Name:     "onion",
					Port:     80,
					Protocol: HiddenServiceProtocol,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gw) })
		return gw
	}

	BeforeEach(func() {
		gc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: gwClass},
			Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
		}
		if err := k8sClient.Create(ctx, gc); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}

		nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
		if err := k8sClient.Create(ctx, nsObj); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}

		// The default reconciler enables the feature.
		gatewayReconciler = &GatewayReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
			Images: RuntimeImages{
				Tor:      "tor:test",
				Router:   "router:test",
				TorInit:  "init:test",
				Operator: "manager:test",
			},
			TorPodNetworkPolicyEnabled: true,
		}
	})

	It("creates the NetworkPolicy with DNS + apiserver + public when there are no routes", func() {
		gw := makeGateway("np-gw", ns, gwClass)
		_, err := gatewayReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
		Expect(err).NotTo(HaveOccurred())

		np := &netv1.NetworkPolicy{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: NetworkPolicyName(gw.Name)}, np)).To(Succeed())
		Expect(np.Spec.PolicyTypes).To(ConsistOf(netv1.PolicyTypeEgress))
		Expect(np.Spec.Egress).To(HaveLen(3)) // DNS, apiserver, public
	})

	It("adds a per-backend rule when an HTTPRoute targets the Gateway", func() {
		gw := makeGateway("np-gw-route", ns, gwClass)

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: ns},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "np-app"},
				Ports:    []corev1.ServicePort{{Port: 5678, TargetPort: intstr.FromInt(5678), Protocol: corev1.ProtocolTCP}},
			},
		}
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, svc) })

		port := gwv1.PortNumber(5678)
		route := &gwv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "np-route", Namespace: ns},
			Spec: gwv1.HTTPRouteSpec{
				CommonRouteSpec: gwv1.CommonRouteSpec{ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(gw.Name)}}},
				Rules: []gwv1.HTTPRouteRule{{
					BackendRefs: []gwv1.HTTPBackendRef{{BackendRef: gwv1.BackendRef{
						BackendObjectReference: gwv1.BackendObjectReference{Name: gwv1.ObjectName(svcName), Port: &port},
					}}},
				}},
			},
		}
		Expect(k8sClient.Create(ctx, route)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, route) })

		_, err := gatewayReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
		Expect(err).NotTo(HaveOccurred())

		np := &netv1.NetworkPolicy{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: NetworkPolicyName(gw.Name)}, np)).To(Succeed())
		Expect(np.Spec.Egress).To(HaveLen(4)) // DNS, apiserver, backend, public

		// Backend rule is index 2.
		backendRule := np.Spec.Egress[2]
		Expect(backendRule.To).To(HaveLen(1))
		Expect(backendRule.To[0].NamespaceSelector.MatchLabels).To(HaveKeyWithValue("kubernetes.io/metadata.name", ns))
		Expect(backendRule.To[0].PodSelector.MatchLabels).To(HaveKeyWithValue("app", "np-app"))
	})

	It("skips a cross-ns backendRef when no ReferenceGrant permits it, then adds the rule when granted", func() {
		const backendNS = "np-test-backend"
		backendNsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: backendNS}}
		if err := k8sClient.Create(ctx, backendNsObj); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}

		gw := makeGateway("gw-crossns", ns, gwClass)

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "remote", Namespace: backendNS},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "remote"},
				Ports:    []corev1.ServicePort{{Port: 5678, TargetPort: intstr.FromInt(5678), Protocol: corev1.ProtocolTCP}},
			},
		}
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, svc) })

		bns := gwv1.Namespace(backendNS)
		port := gwv1.PortNumber(5678)
		route := &gwv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "crossns", Namespace: ns},
			Spec: gwv1.HTTPRouteSpec{
				CommonRouteSpec: gwv1.CommonRouteSpec{ParentRefs: []gwv1.ParentReference{{Name: "gw-crossns"}}},
				Rules: []gwv1.HTTPRouteRule{{
					BackendRefs: []gwv1.HTTPBackendRef{{BackendRef: gwv1.BackendRef{
						BackendObjectReference: gwv1.BackendObjectReference{Name: "remote", Namespace: &bns, Port: &port},
					}}},
				}},
			},
		}
		Expect(k8sClient.Create(ctx, route)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, route) })

		_, err := gatewayReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
		Expect(err).NotTo(HaveOccurred())

		np := &netv1.NetworkPolicy{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: NetworkPolicyName("gw-crossns")}, np)).To(Succeed())
		Expect(np.Spec.Egress).To(HaveLen(3)) // DNS, apiserver, public — no per-backend rule yet

		grant := &gwv1beta1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-np", Namespace: backendNS},
			Spec: gwv1beta1.ReferenceGrantSpec{
				From: []gwv1beta1.ReferenceGrantFrom{{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: gwv1beta1.Namespace(ns)}},
				To:   []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Service"}},
			},
		}
		Expect(k8sClient.Create(ctx, grant)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, grant) })

		_, err = gatewayReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: NetworkPolicyName("gw-crossns")}, np)).To(Succeed())
		Expect(np.Spec.Egress).To(HaveLen(4)) // DNS, apiserver, granted backend, public
		Expect(np.Spec.Egress[2].To[0].NamespaceSelector.MatchLabels).To(HaveKeyWithValue("kubernetes.io/metadata.name", backendNS))
	})

	It("deletes the NetworkPolicy when the feature flag is disabled", func() {
		gw := makeGateway("gw-disabled", ns, gwClass)
		_, err := gatewayReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
		Expect(err).NotTo(HaveOccurred())

		np := &netv1.NetworkPolicy{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: NetworkPolicyName(gw.Name)}, np)).To(Succeed())

		// Disable, reconcile, NP gone.
		gatewayReconciler.TorPodNetworkPolicyEnabled = false
		_, err = gatewayReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
		Expect(err).NotTo(HaveOccurred())

		err = k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: NetworkPolicyName(gw.Name)}, np)
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "NetworkPolicy should be deleted; got err=%v", err)
	})
})
