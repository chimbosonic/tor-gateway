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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

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
