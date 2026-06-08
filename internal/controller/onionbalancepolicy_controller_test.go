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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

var _ = Describe("OnionBalancePolicy status", func() {
	ctx := context.Background()

	reconcileOBP := func(name, ns string) *policyv1alpha1.OnionBalancePolicy {
		GinkgoHelper()
		r := &OnionBalancePolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: ns},
		})
		Expect(err).NotTo(HaveOccurred())
		out := &policyv1alpha1.OnionBalancePolicy{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, out)).To(Succeed())
		return out
	}

	makeOBP := func(name, gwName, secretName string) *policyv1alpha1.OnionBalancePolicy {
		GinkgoHelper()
		pol := &policyv1alpha1.OnionBalancePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: policyv1alpha1.OnionBalancePolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  gwv1.ObjectName(gwName),
				}},
				Replicas: 3,
				MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{
					Name: secretName,
				},
			},
		}
		Expect(k8sClient.Create(ctx, pol)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pol) })
		return pol
	}

	makeGateway := func(name string) *gwv1.Gateway {
		GinkgoHelper()
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "tor-gateway-test",
				Listeners: []gwv1.Listener{{
					Name: "onion", Port: 80, Protocol: HiddenServiceProtocol,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, gw) })
		return gw
	}

	makeValidSecret := func(name string) *corev1.Secret {
		GinkgoHelper()
		kp, err := tor.GenerateKeyPair(nil)
		Expect(err).NotTo(HaveOccurred())
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Data: map[string][]byte{
				"hs_ed25519_secret_key": kp.SecretKeyFile(),
				"hs_ed25519_public_key": kp.PublicKeyFile(),
			},
		}
		Expect(k8sClient.Create(ctx, sec)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, sec) })
		return sec
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

	It("reports Accepted=True when Gateway exists and master Secret is valid", func() {
		makeGateway("obp-accept-gw")
		makeValidSecret("obp-accept-secret")
		pol := makeOBP("obp-accept", "obp-accept-gw", "obp-accept-secret")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionTrue, ReasonOBPAccepted)
	})

	It("reports Accepted=False / GatewayMissing when no Gateway exists", func() {
		makeValidSecret("obp-gw-missing-secret")
		pol := makeOBP("obp-gw-missing", "no-such-gateway", "obp-gw-missing-secret")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionFalse, ReasonOBPGatewayMissing)
	})

	It("reports Accepted=False / MasterKeyMissing when the Secret does not exist", func() {
		makeGateway("obp-nosec-gw")
		pol := makeOBP("obp-nosec", "obp-nosec-gw", "no-such-secret")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionFalse, ReasonOBPMasterKeyMissing)
	})

	It("reports Accepted=False / MasterKeyMissing when hs_ed25519_secret_key is absent", func() {
		makeGateway("obp-noskey-gw")
		kp, err := tor.GenerateKeyPair(nil)
		Expect(err).NotTo(HaveOccurred())
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-noskey-secret", Namespace: "default"},
			Data: map[string][]byte{
				"hs_ed25519_public_key": kp.PublicKeyFile(),
			},
		}
		Expect(k8sClient.Create(ctx, sec)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, sec) })

		pol := makeOBP("obp-noskey", "obp-noskey-gw", "obp-noskey-secret")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionFalse, ReasonOBPMasterKeyMissing)
	})

	It("reports Accepted=False / MasterKeyMissing when hs_ed25519_public_key is absent", func() {
		makeGateway("obp-nopkey-gw")
		kp, err := tor.GenerateKeyPair(nil)
		Expect(err).NotTo(HaveOccurred())
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-nopkey-secret", Namespace: "default"},
			Data: map[string][]byte{
				"hs_ed25519_secret_key": kp.SecretKeyFile(),
			},
		}
		Expect(k8sClient.Create(ctx, sec)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, sec) })

		pol := makeOBP("obp-nopkey", "obp-nopkey-gw", "obp-nopkey-secret")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionFalse, ReasonOBPMasterKeyMissing)
	})

	It("reports Accepted=False / MasterKeyInvalid when keys do not form a pair", func() {
		makeGateway("obp-mismatch-gw")
		kp1, err := tor.GenerateKeyPair(nil)
		Expect(err).NotTo(HaveOccurred())
		kp2, err := tor.GenerateKeyPair(nil)
		Expect(err).NotTo(HaveOccurred())
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-mismatch-secret", Namespace: "default"},
			Data: map[string][]byte{
				"hs_ed25519_secret_key": kp1.SecretKeyFile(),
				"hs_ed25519_public_key": kp2.PublicKeyFile(), // wrong pair
			},
		}
		Expect(k8sClient.Create(ctx, sec)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, sec) })

		pol := makeOBP("obp-mismatch", "obp-mismatch-gw", "obp-mismatch-secret")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionFalse, ReasonOBPMasterKeyInvalid)
	})

	It("reports Accepted=False / MasterKeyInvalid when secret bytes are garbage", func() {
		makeGateway("obp-garbage-gw")
		kp, err := tor.GenerateKeyPair(nil)
		Expect(err).NotTo(HaveOccurred())
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-garbage-secret", Namespace: "default"},
			Data: map[string][]byte{
				"hs_ed25519_secret_key": []byte("not a real key at all"),
				"hs_ed25519_public_key": kp.PublicKeyFile(),
			},
		}
		Expect(k8sClient.Create(ctx, sec)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, sec) })

		pol := makeOBP("obp-garbage", "obp-garbage-gw", "obp-garbage-secret")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionFalse, ReasonOBPMasterKeyInvalid)
	})

	It("readyBackends counts only backend Secrets with non-empty hostname", func() {
		gw := makeGateway("obp-rb-gw")
		makeValidSecret("obp-rb-master")

		backendReady := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obp-rb-backend-ready",
				Namespace: "default",
				Labels: map[string]string{
					gatewayLabelKey:      gw.Name,
					"torgateway.io/role": "backend",
				},
			},
			Data: map[string][]byte{"hostname": []byte("abc123.onion")},
		}
		Expect(k8sClient.Create(ctx, backendReady)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, backendReady) })

		backendNotReady := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obp-rb-backend-notready",
				Namespace: "default",
				Labels: map[string]string{
					gatewayLabelKey:      gw.Name,
					"torgateway.io/role": "backend",
				},
			},
			Data: map[string][]byte{"hostname": []byte("")},
		}
		Expect(k8sClient.Create(ctx, backendNotReady)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, backendNotReady) })

		pol := makeOBP("obp-rb", gw.Name, "obp-rb-master")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionTrue, ReasonOBPAccepted)
		Expect(got.Status.ReadyBackends).To(Equal(int32(1)))
	})

	It("cross-namespace master key: Accepted=True when ReferenceGrant allows it", func() {
		// Create a second namespace for the master secret.
		otherNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "obp-xns-target"}}
		if err := k8sClient.Create(ctx, otherNS); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}

		makeGateway("obp-xns-gw")

		kp, err := tor.GenerateKeyPair(nil)
		Expect(err).NotTo(HaveOccurred())
		crossSec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-xns-master", Namespace: "obp-xns-target"},
			Data: map[string][]byte{
				"hs_ed25519_secret_key": kp.SecretKeyFile(),
				"hs_ed25519_public_key": kp.PublicKeyFile(),
			},
		}
		Expect(k8sClient.Create(ctx, crossSec)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, crossSec) })

		grant := &gwv1beta1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-xns-grant", Namespace: "obp-xns-target"},
			Spec: gwv1beta1.ReferenceGrantSpec{
				From: []gwv1beta1.ReferenceGrantFrom{{
					Group:     "policy.torgateway.io",
					Kind:      "OnionBalancePolicy",
					Namespace: gwv1.Namespace("default"),
				}},
				To: []gwv1beta1.ReferenceGrantTo{{
					Group: "",
					Kind:  "Secret",
					Name:  ptr.To(gwv1.ObjectName("obp-xns-master")),
				}},
			},
		}
		Expect(k8sClient.Create(ctx, grant)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, grant) })

		pol := &policyv1alpha1.OnionBalancePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-xns", Namespace: "default"},
			Spec: policyv1alpha1.OnionBalancePolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  "obp-xns-gw",
				}},
				Replicas: 3,
				MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{
					Name:      "obp-xns-master",
					Namespace: "obp-xns-target",
				},
			},
		}
		Expect(k8sClient.Create(ctx, pol)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pol) })

		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionTrue, ReasonOBPAccepted)
	})

	It("cross-namespace master key: Accepted=False / MasterKeyCrossNamespaceDenied without ReferenceGrant", func() {
		otherNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "obp-xns-deny-target"}}
		if err := k8sClient.Create(ctx, otherNS); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}

		makeGateway("obp-xns-deny-gw")

		kp, err := tor.GenerateKeyPair(nil)
		Expect(err).NotTo(HaveOccurred())
		crossSec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-xns-deny-master", Namespace: "obp-xns-deny-target"},
			Data: map[string][]byte{
				"hs_ed25519_secret_key": kp.SecretKeyFile(),
				"hs_ed25519_public_key": kp.PublicKeyFile(),
			},
		}
		Expect(k8sClient.Create(ctx, crossSec)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, crossSec) })

		pol := &policyv1alpha1.OnionBalancePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-xns-deny", Namespace: "default"},
			Spec: policyv1alpha1.OnionBalancePolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  "obp-xns-deny-gw",
				}},
				Replicas: 3,
				MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{
					Name:      "obp-xns-deny-master",
					Namespace: "obp-xns-deny-target",
				},
			},
		}
		Expect(k8sClient.Create(ctx, pol)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pol) })

		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionFalse, ReasonOBPMasterKeyCrossNSDenied)
	})

	It("PoW override: Accepted=True message notes onionbalance#13 when TSP has PoW enabled", func() {
		makeGateway("obp-pow-gw")
		makeValidSecret("obp-pow-master")

		pow := true
		tsp := &policyv1alpha1.TorServicePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-pow-tsp", Namespace: "default"},
			Spec: policyv1alpha1.TorServicePolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  "obp-pow-gw",
				}},
				PoWDefensesEnabled: &pow,
			},
		}
		Expect(k8sClient.Create(ctx, tsp)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, tsp) })

		pol := makeOBP("obp-pow", "obp-pow-gw", "obp-pow-master")
		got := reconcileOBP(pol.Name, pol.Namespace)
		assertOBPAccepted(got, metav1.ConditionTrue, ReasonOBPAccepted)

		var msg string
		for _, c := range got.Status.Ancestors[0].Conditions {
			if c.Type == string(gwv1.PolicyConditionAccepted) {
				msg = c.Message
				break
			}
		}
		Expect(msg).To(ContainSubstring("onionbalance#13"))
	})

	It("multi-target: both ancestors Accepted=True and readyBackends is sum (0+0) not silently dropped", func() {
		makeGateway("obp-multi-gw1")
		makeGateway("obp-multi-gw2")
		makeValidSecret("obp-multi-secret")

		pol := &policyv1alpha1.OnionBalancePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "obp-multi", Namespace: "default"},
			Spec: policyv1alpha1.OnionBalancePolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{
					{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "obp-multi-gw1"},
					{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "obp-multi-gw2"},
				},
				Replicas:           3,
				MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "obp-multi-secret"},
			},
		}
		Expect(k8sClient.Create(ctx, pol)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pol) })

		got := reconcileOBP(pol.Name, pol.Namespace)

		Expect(got.Status.Ancestors).To(HaveLen(2))
		for _, anc := range got.Status.Ancestors {
			var found bool
			for _, c := range anc.Conditions {
				if c.Type == string(gwv1.PolicyConditionAccepted) {
					Expect(c.Status).To(Equal(metav1.ConditionTrue), "ancestor %s should be Accepted", anc.AncestorRef.Name)
					Expect(c.Reason).To(Equal(ReasonOBPAccepted))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "ancestor %s missing Accepted condition", anc.AncestorRef.Name)
		}
		// countReadyBackends is a stub returning 0; the accumulation fix
		// ensures 0+0=0, not a silent drop of one iteration.
		Expect(got.Status.ReadyBackends).To(Equal(int32(0)))
	})
})

func assertOBPAccepted(pol *policyv1alpha1.OnionBalancePolicy, status metav1.ConditionStatus, reason string) {
	GinkgoHelper()
	Expect(pol.Status.Ancestors).NotTo(BeEmpty())
	for _, c := range pol.Status.Ancestors[0].Conditions {
		if c.Type == string(gwv1.PolicyConditionAccepted) {
			Expect(c.Status).To(Equal(status))
			Expect(c.Reason).To(Equal(reason))
			return
		}
	}
	Fail("onionbalance policy ancestor missing Accepted condition")
}

const testOBPName = "blog-obp"

func TestOnionBalancePolicyReconciler_WatchSecretRequeuesOBP(t *testing.T) {
	obp := &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testOBPName, Namespace: "default"},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "ob-master"},
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
			Replicas: 3,
		},
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ob-master", Namespace: "default"}}

	r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(obp, secret).Build()}
	reqs := r.obpsForSecret(context.Background(), secret)
	if len(reqs) != 1 || reqs[0].Name != testOBPName {
		t.Fatalf("expected 1 request for blog-obp, got %+v", reqs)
	}
}

func TestOnionBalancePolicyReconciler_WatchSecretNoMatchRequeuesNothing(t *testing.T) {
	obp := &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testOBPName, Namespace: "default"},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "ob-master"},
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
			Replicas: 3,
		},
	}
	otherSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "other-secret", Namespace: "default"}}

	r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(obp).Build()}
	reqs := r.obpsForSecret(context.Background(), otherSecret)
	if len(reqs) != 0 {
		t.Fatalf("expected 0 requests, got %+v", reqs)
	}
}

func TestOnionBalancePolicyReconciler_WatchGatewayRequeuesOBP(t *testing.T) {
	obp := &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testOBPName, Namespace: "default"},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "ob-master"},
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
			Replicas: 3,
		},
	}
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "default"}}

	r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(obp).Build()}
	reqs := r.obpsForGateway(context.Background(), gw)
	if len(reqs) != 1 || reqs[0].Name != testOBPName {
		t.Fatalf("expected 1 request for blog-obp, got %+v", reqs)
	}
}

func TestOnionBalancePolicyReconciler_WatchGatewayNoMatchRequeuesNothing(t *testing.T) {
	obp := &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testOBPName, Namespace: "default"},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "ob-master"},
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
			Replicas: 3,
		},
	}
	otherGw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "other-gateway", Namespace: "default"}}

	r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(obp).Build()}
	reqs := r.obpsForGateway(context.Background(), otherGw)
	if len(reqs) != 0 {
		t.Fatalf("expected 0 requests, got %+v", reqs)
	}
}

func TestOnionBalancePolicyReconciler_WatchReferenceGrantRequeuesOBP(t *testing.T) {
	obp := &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testOBPName, Namespace: "default"},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{
				Name:      "ob-master",
				Namespace: "secrets-ns",
			},
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
			Replicas: 3,
		},
	}
	rg := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-obp", Namespace: "secrets-ns"},
		Spec: gwv1beta1.ReferenceGrantSpec{
			From: []gwv1beta1.ReferenceGrantFrom{{
				Group:     gwv1.Group(policyv1alpha1.GroupVersion.Group),
				Kind:      "OnionBalancePolicy",
				Namespace: "default",
			}},
			To: []gwv1beta1.ReferenceGrantTo{{
				Group: "",
				Kind:  "Secret",
			}},
		},
	}

	r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testSchemeWithGrants(t)).WithObjects(obp).Build()}
	reqs := r.obpsForReferenceGrant(context.Background(), rg)
	if len(reqs) != 1 || reqs[0].Name != testOBPName {
		t.Fatalf("expected 1 request for blog-obp, got %+v", reqs)
	}
}

func TestOnionBalancePolicyReconciler_WatchReferenceGrantNoMatchRequeuesNothing(t *testing.T) {
	obp := &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testOBPName, Namespace: "default"},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{
				Name:      "ob-master",
				Namespace: "secrets-ns",
			},
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
			Replicas: 3,
		},
	}
	// ReferenceGrant in a different namespace — should not match
	rg := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-obp", Namespace: "other-ns"},
		Spec: gwv1beta1.ReferenceGrantSpec{
			From: []gwv1beta1.ReferenceGrantFrom{{
				Group:     gwv1.Group(policyv1alpha1.GroupVersion.Group),
				Kind:      "OnionBalancePolicy",
				Namespace: "default",
			}},
		},
	}

	r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testSchemeWithGrants(t)).WithObjects(obp).Build()}
	reqs := r.obpsForReferenceGrant(context.Background(), rg)
	if len(reqs) != 0 {
		t.Fatalf("expected 0 requests, got %+v", reqs)
	}
}

func TestOnionBalancePolicyReconciler_WatchTorServicePolicyRequeuesOBP(t *testing.T) {
	obp := &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testOBPName, Namespace: "default"},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "ob-master"},
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
			Replicas: 3,
		},
	}
	tsp := &policyv1alpha1.TorServicePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "blog-tsp", Namespace: "default"},
		Spec: policyv1alpha1.TorServicePolicySpec{
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
		},
	}

	r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(obp).Build()}
	reqs := r.obpsForTorServicePolicy(context.Background(), tsp)
	if len(reqs) != 1 || reqs[0].Name != testOBPName {
		t.Fatalf("expected 1 request for blog-obp, got %+v", reqs)
	}
}

func TestOnionBalancePolicyReconciler_WatchTorServicePolicyNoMatchRequeuesNothing(t *testing.T) {
	obp := &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testOBPName, Namespace: "default"},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "ob-master"},
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"},
			},
			Replicas: 3,
		},
	}
	// TSP targets a different gateway — should not match
	tsp := &policyv1alpha1.TorServicePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "other-tsp", Namespace: "default"},
		Spec: policyv1alpha1.TorServicePolicySpec{
			TargetRefs: []gwv1.LocalPolicyTargetReference{
				{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "other-gateway"},
			},
		},
	}

	r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(obp).Build()}
	reqs := r.obpsForTorServicePolicy(context.Background(), tsp)
	if len(reqs) != 0 {
		t.Fatalf("expected 0 requests, got %+v", reqs)
	}
}
