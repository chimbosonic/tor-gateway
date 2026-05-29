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
	"crypto/rand"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

var _ = Describe("Gateway vanity harvest", func() {
	ctx := context.Background()
	const ns = "default"

	makeReconciler := func() (*GatewayReconciler, *record.FakeRecorder) {
		rec := record.NewFakeRecorder(20)
		return &GatewayReconciler{
			Client:         k8sClient,
			Scheme:         k8sClient.Scheme(),
			Images:         RuntimeImages{Tor: "tor:t", Router: "r:t", TorInit: "i:t", Mkp224o: "mkp:t", VanityFinalize: "vf:t"},
			Recorder:       rec,
			VanityDeadline: time.Hour,
			APIReader:      k8sClient,
		}, rec
	}

	reconcileGw := func(r *GatewayReconciler, name string) error {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
		return err
	}

	BeforeEach(func() {
		// Use a dedicated class name (not "tor-gateway", which the GatewayClass
		// reconciler spec strict-creates) to avoid cross-spec collisions under
		// randomized ordering.
		gc := &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway-test"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
		}
		if err := k8sClient.Create(ctx, gc); err != nil {
			Expect(client_IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		}
	})

	newGateway := func(name string) *gwv1.Gateway {
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "tor-gateway-test",
				Listeners: []gwv1.Listener{{
					Name:     "onion",
					Port:     80,
					Protocol: HiddenServiceProtocol,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, gw)).To(Succeed())
		return gw
	}

	newVanityPolicy := func(name, target, prefix string) {
		tsp := &policyv1alpha1.TorServicePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: policyv1alpha1.TorServicePolicySpec{
				TargetRefs: []gwv1.LocalPolicyTargetReference{{
					Group: GatewayAPIGroup, Kind: GatewayKind, Name: gwv1.ObjectName(target),
				}},
				VanityPrefix: prefix,
			},
		}
		Expect(k8sClient.Create(ctx, tsp)).To(Succeed())
	}

	It("launches a harvest Job and reports Programmed=False/InProgress", func() {
		newGateway("van-a")
		newVanityPolicy("tsp-van-a", "van-a", "abc")
		r, _ := makeReconciler()
		Expect(reconcileGw(r, "van-a")).To(Succeed())

		By("creating the vanity RBAC, out-Secret, and Job")
		job := &batchv1.Job{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityRBACName("van-a")}, job)).To(Succeed())
		Expect(job.Labels[vanityPrefixLabel]).To(Equal("abc"))
		sa := &corev1.ServiceAccount{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityRBACName("van-a")}, sa)).To(Succeed())
		role := &rbacv1.Role{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityRBACName("van-a")}, role)).To(Succeed())
		out := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityOutSecretName("van-a")}, out)).To(Succeed())

		By("not creating the canonical key Secret yet")
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: KeySecretName("van-a")}, &corev1.Secret{})).To(HaveOccurred())

		By("setting Programmed=False/VanityHarvestInProgress")
		fresh := &gwv1.Gateway{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "van-a"}, fresh)).To(Succeed())
		Expect(conditionReason(fresh, string(gwv1.GatewayConditionProgrammed))).To(Equal(ReasonVanityHarvestInProgress))
	})

	It("promotes the harvested key once the out-Secret is populated", func() {
		_ = newGateway("van-b")
		newVanityPolicy("tsp-van-b", "van-b", "abc")
		r, _ := makeReconciler()
		Expect(reconcileGw(r, "van-b")).To(Succeed())

		By("simulating the finalize step populating the out-Secret")
		kp, err := tor.GenerateKeyPair(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		out := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityOutSecretName("van-b")}, out)).To(Succeed())
		out.Data = map[string][]byte{
			tor.FileSecretKeyName: kp.SecretKeyFile(),
			tor.FilePublicKeyName: kp.PublicKeyFile(),
			tor.FileHostnameName:  kp.Hostname(),
		}
		Expect(k8sClient.Update(ctx, out)).To(Succeed())

		Expect(reconcileGw(r, "van-b")).To(Succeed())

		By("creating <gw>-keys and deleting the throwaway Secret + Job")
		key := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: KeySecretName("van-b")}, key)).To(Succeed())
		Expect(key.Data).To(HaveKey(tor.FileSecretKeyName))
		Eventually(func() bool {
			e := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityOutSecretName("van-b")}, &corev1.Secret{})
			return e != nil
		}).Should(BeTrue())
	})

	It("fails and does not relaunch when the Job exceeds its deadline", func() {
		_ = newGateway("van-c")
		newVanityPolicy("tsp-van-c", "van-c", "abc")
		r, rec := makeReconciler()
		Expect(reconcileGw(r, "van-c")).To(Succeed())

		By("marking the Job failed (DeadlineExceeded)")
		job := &batchv1.Job{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityRBACName("van-c")}, job)).To(Succeed())
		// The API server rejects a finished Job status that sets Failed=True
		// without a startTime and a preceding FailureTarget=True condition.
		startTime := metav1.Now()
		job.Status.StartTime = &startTime
		job.Status.Conditions = []batchv1.JobCondition{
			{Type: batchv1.JobFailureTarget, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"},
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"},
		}
		Expect(k8sClient.Status().Update(ctx, job)).To(Succeed())

		Expect(reconcileGw(r, "van-c")).To(Succeed())
		fresh := &gwv1.Gateway{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "van-c"}, fresh)).To(Succeed())
		Expect(conditionReason(fresh, string(gwv1.GatewayConditionProgrammed))).To(Equal(ReasonVanityHarvestFailed))
		Expect(fresh.Annotations[vanityFailedAnnotation]).To(Equal("abc"))
		// The flow emits VanityHarvestStarted (reconcile 1) then
		// VanityHarvestFailed (reconcile 2); assert the failure event appears
		// among the buffered events rather than assuming channel position.
		Expect(drainEvents(rec)).To(ContainElement(ContainSubstring("VanityHarvestFailed")))
	})

	It("waits without a key when await-vanity is set and no policy exists yet", func() {
		gw := newGateway("van-await")
		gw.Annotations = map[string]string{awaitVanityAnnotation: "true"}
		Expect(k8sClient.Update(ctx, gw)).To(Succeed())
		r, _ := makeReconciler()
		Expect(reconcileGw(r, "van-await")).To(Succeed())

		By("not creating a key Secret")
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: KeySecretName("van-await")}, &corev1.Secret{})).To(HaveOccurred())

		By("reporting Programmed=False/AwaitingVanityPolicy")
		fresh := &gwv1.Gateway{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "van-await"}, fresh)).To(Succeed())
		Expect(conditionReason(fresh, string(gwv1.GatewayConditionProgrammed))).To(Equal(ReasonAwaitingVanityPolicy))

		By("harvesting once the matching policy is created")
		newVanityPolicy("tsp-van-await", "van-await", "abc")
		Expect(reconcileGw(r, "van-await")).To(Succeed())
		job := &batchv1.Job{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityRBACName("van-await")}, job)).To(Succeed())
		Expect(job.Labels[vanityPrefixLabel]).To(Equal("abc"))
	})

	It("still generates a random key for a plain keyless Gateway (no policy, no annotation)", func() {
		newGateway("van-plain")
		r, _ := makeReconciler()
		Expect(reconcileGw(r, "van-plain")).To(Succeed())
		key := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: KeySecretName("van-plain")}, key)).To(Succeed())
		Expect(key.Data).To(HaveKey(tor.FileSecretKeyName))
	})

	It("ignores a vanity prefix when a key already exists", func() {
		gw := newGateway("van-d")
		// Pre-create a non-vanity key.
		kp, err := tor.GenerateKeyPair(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		key, err := BuildKeySecret(gw, kp, k8sClient.Scheme())
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Create(ctx, key)).To(Succeed())
		newVanityPolicy("tsp-van-d", "van-d", "zzz")

		r, rec := makeReconciler()
		Expect(reconcileGw(r, "van-d")).To(Succeed())

		By("not creating a harvest Job")
		err = k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityRBACName("van-d")}, &batchv1.Job{})
		Expect(err).To(HaveOccurred())
		Expect(rec.Events).To(Receive(ContainSubstring("VanityPrefixIgnored")))
	})
})

// conditionReason returns the Reason of the named Gateway condition, or "".
func conditionReason(gw *gwv1.Gateway, condType string) string {
	for _, c := range gw.Status.Conditions {
		if c.Type == condType {
			return c.Reason
		}
	}
	return ""
}

// drainEvents non-blockingly reads all events currently buffered on the fake
// recorder, so assertions can search them regardless of emission order.
func drainEvents(rec *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case e := <-rec.Events:
			events = append(events, e)
		default:
			return events
		}
	}
}
