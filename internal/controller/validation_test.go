/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
)

// These tests exercise the OpenAPI / CEL validation declared on each Policy
// CRD. They run against envtest's real apiserver via the suite_test.go
// bootstrap, so they verify the YAML the operator ships to users actually
// rejects the inputs we expect it to reject.
//
// Conventions:
//   - Each policy has one "valid baseline" object that the test mutates.
//   - Each subtest applies one mutation, attempts a Create, and asserts
//     either Succeed() or an error matching a substring.

// validGatewayTarget returns a fresh slice so tests can mutate it freely
// without leaking changes between Specs.
func validGatewayTarget() []gwv1.LocalPolicyTargetReference {
	return []gwv1.LocalPolicyTargetReference{{
		Group: "gateway.networking.k8s.io",
		Kind:  "Gateway",
		Name:  "test-gateway",
	}}
}

func mustFail(obj client.Object, want string) {
	err := k8sClient.Create(ctx, obj)
	Expect(err).To(HaveOccurred())
	Expect(strings.ToLower(err.Error())).To(ContainSubstring(strings.ToLower(want)))
}

func cleanup(obj client.Object) {
	if obj.GetName() == "" {
		return
	}
	_ = k8sClient.Delete(ctx, obj)
}

var _ = Describe("CRD validation", func() {

	// --- TorServicePolicy ---

	Describe("TorServicePolicy", func() {
		base := func(name string) *policyv1alpha1.TorServicePolicy {
			return &policyv1alpha1.TorServicePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
				Spec: policyv1alpha1.TorServicePolicySpec{
					TargetRefs: validGatewayTarget(),
				},
			}
		}

		It("accepts a minimal valid policy", func() {
			obj := base("tsp-valid")
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(cleanup, obj)
		})

		It("rejects missing targetRefs", func() {
			obj := base("tsp-no-target")
			obj.Spec.TargetRefs = nil
			mustFail(obj, "targetRefs")
		})

		It("rejects targetRef with wrong Group", func() {
			obj := base("tsp-wrong-group")
			obj.Spec.TargetRefs[0].Group = "networking.k8s.io"
			mustFail(obj, "must reference gateway.networking.k8s.io/Gateway")
		})

		It("rejects targetRef with wrong Kind", func() {
			obj := base("tsp-wrong-kind")
			obj.Spec.TargetRefs[0].Kind = "HTTPRoute"
			mustFail(obj, "must reference gateway.networking.k8s.io/Gateway")
		})

		It("rejects an invalid vanityPrefix character", func() {
			obj := base("tsp-bad-vanity")
			obj.Spec.VanityPrefix = "BadChars" // uppercase + "8/9" not in base32
			mustFail(obj, "should match")
		})

		It("rejects vanityPrefix longer than 8 chars", func() {
			obj := base("tsp-long-vanity")
			obj.Spec.VanityPrefix = "abcdefghi"
			mustFail(obj, "too long")
		})

		It("rejects vanityPrefix over 6 chars without acknowledgement", func() {
			obj := base("tsp-vanity-noack")
			obj.Spec.VanityPrefix = "abcdefg" // 7 chars, no ack
			mustFail(obj, "vanityAcknowledgeLongRunning")
		})

		It("accepts vanityPrefix over 6 chars with acknowledgement", func() {
			obj := base("tsp-vanity-ack")
			obj.Spec.VanityPrefix = "abcdefg"
			obj.Spec.VanityAcknowledgeLongRunning = true
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		})

		It("accepts a short vanityPrefix without acknowledgement", func() {
			obj := base("tsp-vanity-short")
			obj.Spec.VanityPrefix = "abc" // 3 chars
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		})

		It("rejects an unknown logLevel", func() {
			obj := base("tsp-bad-level")
			obj.Spec.LogLevel = "verbose"
			mustFail(obj, "supported values")
		})
	})

	// --- TorClientAuthPolicy ---

	Describe("TorClientAuthPolicy", func() {
		base := func(name string) *policyv1alpha1.TorClientAuthPolicy {
			return &policyv1alpha1.TorClientAuthPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
				Spec: policyv1alpha1.TorClientAuthPolicySpec{
					TargetRefs: validGatewayTarget(),
					ClientsSecretRef: policyv1alpha1.ClientsSecretRef{
						Name: "client-keys",
					},
				},
			}
		}

		It("accepts a minimal valid policy", func() {
			obj := base("tcap-valid")
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(cleanup, obj)
		})

		It("rejects missing clientsSecretRef.name", func() {
			obj := base("tcap-empty-secret")
			obj.Spec.ClientsSecretRef.Name = ""
			mustFail(obj, "clientsSecretRef.name")
		})

		It("rejects unknown mode", func() {
			obj := base("tcap-bad-mode")
			obj.Spec.Mode = "Lenient"
			mustFail(obj, "supported values")
		})

		It("accepts mode=Audit", func() {
			obj := base("tcap-audit")
			obj.Spec.Mode = policyv1alpha1.ClientAuthModeAudit
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(cleanup, obj)
		})
	})

	// --- OnionBalancePolicy ---

	Describe("OnionBalancePolicy", func() {
		base := func(name string) *policyv1alpha1.OnionBalancePolicy {
			return &policyv1alpha1.OnionBalancePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
				Spec: policyv1alpha1.OnionBalancePolicySpec{
					TargetRefs: validGatewayTarget(),
					Replicas:   3,
					MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{
						Name: "master-key",
					},
				},
			}
		}

		It("accepts a minimal valid policy", func() {
			obj := base("obp-valid")
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(cleanup, obj)
		})

		It("rejects replicas=0", func() {
			obj := base("obp-zero")
			obj.Spec.Replicas = 0
			mustFail(obj, "should be greater than or equal to 1")
		})

		It("rejects replicas=13 (above the cap of 12)", func() {
			obj := base("obp-too-many")
			obj.Spec.Replicas = 13
			mustFail(obj, "should be less than or equal to 12")
		})

		It("rejects missing masterKeySecretRef.name", func() {
			obj := base("obp-no-master")
			obj.Spec.MasterKeySecretRef.Name = ""
			mustFail(obj, "masterKeySecretRef.name")
		})
	})
})
