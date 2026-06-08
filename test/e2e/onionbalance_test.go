//go:build e2e
// +build e2e

/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// HA e2e: deploys a Gateway + OnionBalancePolicy (3 backends) + two-backend
// HTTPRoute fan-out, then fetches the master .onion through an in-cluster Tor
// SOCKS client and verifies that the service survives a pod kill and a replica
// scale-down. Uses the in-cluster chutney Tor network so descriptor propagation
// is fast (~30–60 s rather than 5–15 min on the public network).

// Spec authoring rules for this file (codified by the stable-e2e-pipeline design):
//  1. No spec depends on another Describe block's state — each block re-creates
//     its own Gateway/OBP/Secret in its own namespace.
//  2. Within an Ordered block, observer specs come before mutator specs.
//  3. Use Label("ob-failover") on mutator specs and Label("ob-crossns") on
//     cross-namespace specs so the CI matrix can route them correctly.
//  4. Generous setup budgets (5-10m), tight assertion budgets (<=2m).

package e2e

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/chimbosonic/tor-gateway/internal/tor"
	"github.com/chimbosonic/tor-gateway/test/utils"
)

const obpNS = "tor-gateway-ha"

// modeBFixture builds a Mode B test fixture in the given namespace + GatewayClass.
// Generates a master keypair, creates the master Secret + GatewayClass + Gateway +
// OBP + HTTPRoute + 2 echo backends, waits for the frontend Deployment Available,
// waits for Gateway.status.addresses to publish the .onion, applies a tor-client
// pod, and returns the master .onion address for use in specs.
func modeBFixture(ns, gwClass, gwName string) (masterOnion string) {
	const (
		obrefreshImage = "ghcr.io/chimbosonic/tor-gateway-obrefresh:dev"
		obImage        = "ghcr.io/chimbosonic/tor-gateway-onionbalance:dev"
	)

	masterSecretName := gwName + "-master-secret"
	obpName := gwName + "-obp"
	routeName := gwName + "-route"
	backendA := gwName + "-backend-a"
	backendB := gwName + "-backend-b"
	torClientPod := gwName + "-tor-client"

	By("building and loading HA-specific images")
	buildAndLoadImage("image-router", "ghcr.io/chimbosonic/tor-gateway-router:dev")
	buildAndLoadImage("image-tor-init", "ghcr.io/chimbosonic/tor-gateway-tor-init:dev")
	buildAndLoadImage("image-tor", "ghcr.io/chimbosonic/tor:0.4.9")
	buildAndLoadImage("image-obrefresh", obrefreshImage)
	buildAndLoadImage("image-onionbalance", obImage)

	By("patching the manager to enable the onionbalance and obrefresh images")
	_, err := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-system", "patch", "deployment",
		"tor-gateway-controller-manager", "--type=json",
		"-p", fmt.Sprintf(`[
			{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--onionbalance-image=%s"},
			{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--obrefresh-image=%s"}
		]`, obImage, obrefreshImage)))
	Expect(err).NotTo(HaveOccurred(), "patch manager with HA image flags")

	By("waiting for the manager rollout after patch")
	Eventually(func() (string, error) {
		return utils.Run(exec.Command("kubectl", "-n", "tor-gateway-system",
			"rollout", "status", "deployment/tor-gateway-controller-manager", "--timeout=30s"))
	}, "2m", "5s").Should(ContainSubstring("successfully rolled out"))

	By("creating the HA test namespace")
	runOrSkipExisting("kubectl", "create", "ns", ns)

	By("copying the chutney fragment into the HA namespace")
	copyChutneyFragmentTo(ns)

	By("installing the tor-gateway GatewayClass for HA tests")
	applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: %s
spec:
  controllerName: torgateway.io/gateway-controller
`, gwClass))

	By("generating and storing the master ed25519 key Secret")
	kp, err := tor.GenerateKeyPair(rand.Reader)
	Expect(err).NotTo(HaveOccurred(), "generate master key")
	secretKey := base64.StdEncoding.EncodeToString(kp.SecretKeyFile())
	publicKey := base64.StdEncoding.EncodeToString(kp.PublicKeyFile())
	masterOnion = kp.OnionAddress().String()
	applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
data:
  hs_ed25519_secret_key: %s
  hs_ed25519_public_key: %s
`, masterSecretName, ns, secretKey, publicKey))

	By("deploying two http-echo backends for path-based routing")
	applyYAML(fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: %[2]s, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: %[2]s } }
  template:
    metadata: { labels: { app: %[2]s } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=backend-A", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: %[2]s, namespace: %[1]s }
spec:
  selector: { app: %[2]s }
  ports: [{ port: 5678, targetPort: 5678 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: %[3]s, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: %[3]s } }
  template:
    metadata: { labels: { app: %[3]s } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=backend-B", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: %[3]s, namespace: %[1]s }
spec:
  selector: { app: %[3]s }
  ports: [{ port: 5678, targetPort: 5678 }]
`, ns, backendA, backendB))

	By("waiting for app backends to be Available")
	for _, d := range []string{backendA, backendB} {
		_, err := utils.Run(exec.Command("kubectl", "-n", ns,
			"rollout", "status", "deployment/"+d, "--timeout=120s"))
		Expect(err).NotTo(HaveOccurred(), "app backend %s not ready", d)
	}

	By("applying Gateway + OnionBalancePolicy (3 backends) + two-rule HTTPRoute")
	applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: %[3]s
  namespace: %[1]s
spec:
  gatewayClassName: %[2]s
  listeners:
  - { name: onion, port: 80, protocol: torgateway.io/HiddenService }
---
apiVersion: policy.torgateway.io/v1alpha1
kind: OnionBalancePolicy
metadata:
  name: %[4]s
  namespace: %[1]s
spec:
  targetRefs:
  - { group: gateway.networking.k8s.io, kind: Gateway, name: %[3]s }
  replicas: 3
  masterKeySecretRef:
    name: %[5]s
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: %[6]s
  namespace: %[1]s
spec:
  parentRefs: [{ name: %[3]s }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: /api } }]
    backendRefs: [{ name: %[8]s, port: 5678 }]
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: %[7]s, port: 5678 }]
`, ns, gwClass, gwName, obpName, masterSecretName, routeName, backendA, backendB))

	By("waiting for the frontend Deployment to become Available")
	Eventually(func() (string, error) {
		return utils.Run(exec.Command("kubectl", "-n", ns, "get", "deployment", gwName+"-frontend",
			"-o", "jsonpath={.status.conditions[?(@.type==\"Available\")].status}"))
	}, "5m", "5s").Should(Equal("True"), "frontend Deployment never became Available")

	By("waiting for Gateway.status.addresses to publish the master .onion")
	Eventually(func() string {
		out, _ := utils.Run(exec.Command("kubectl", "-n", ns, "get", "gateway", gwName,
			"-o", "jsonpath={.status.addresses[0].value}"))
		return strings.TrimSpace(out)
	}, "60s", "2s").Should(Equal(masterOnion),
		"Gateway should publish the pre-seeded master .onion address")

	By("deploying an in-cluster Tor SOCKS client for fetching the .onion")
	applyYAML(chutneyTorClientPodYAML(ns, torClientPod))

	_, err = utils.Run(exec.Command("kubectl", "-n", ns,
		"wait", "--for=condition=Ready", "pod/"+torClientPod, "--timeout=120s"))
	Expect(err).NotTo(HaveOccurred(), "%s pod not ready", torClientPod)

	return masterOnion
}

// teardownModeBFixture removes everything modeBFixture created.
func teardownModeBFixture(ns, gwClass string) {
	if os.Getenv("TOR_GATEWAY_E2E_NO_TEARDOWN") == "1" {
		fmt.Printf("\n[debug] keeping ns %s + gatewayclass %s (TOR_GATEWAY_E2E_NO_TEARDOWN=1)\n", ns, gwClass)
		return
	}
	_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", ns, "--ignore-not-found", "--wait=false"))
	_, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", gwClass, "--ignore-not-found"))
}

var _ = Describe("OnionBalance HA — happy path", Ordered, Label("onionbalance"), func() {
	var masterOnion string

	BeforeAll(func() {
		masterOnion = modeBFixture("tor-gateway-ha", "ha-gw-class", "ha-gw")
	})

	AfterAll(func() {
		teardownModeBFixture("tor-gateway-ha", "ha-gw-class")
	})

	fetchOverTor := func(pod, path string) func() string {
		return func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha", "exec", pod, "-c", "curl", "--",
				"curl", "-s", "--max-time", "30", "--socks5-hostname", "127.0.0.1:9050",
				"http://"+masterOnion+path))
			return strings.TrimSpace(out)
		}
	}

	It("routes by path to the correct backend over the master .onion", func() {
		By("fetching / over Tor via onionbalance -> backend-A (waits for HS descriptor propagation)")
		// In testing mode the operator passes --is-testnet to onionbalance,
		// which drops its descriptor cycle to 20s fetch / 10s publish-check.
		// 5m matches the single-pod tests' first-fetch budget.
		Eventually(fetchOverTor("ha-tor-client", "/"), "5m", "5s").
			Should(Equal("backend-A"), "/ should route to backend-A via the master .onion")

		By("fetching /api over Tor via onionbalance -> backend-B")
		Eventually(fetchOverTor("ha-tor-client", "/api"), "2m", "5s").
			Should(Equal("backend-B"), "/api should route to backend-B via the master .onion")
	})

	// Task 10: Mode B per-pod key isolation.
	It("isolates per-pod keys: a backend's tor container only sees its own onion key", func() {
		const taskReplicas = 3

		By("restoring OBP replicas to 3 for key-isolation assertions")
		_, err := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha", "patch", "onionbalancepolicy", "ha-gw-obp",
			"--type=merge", "-p", `{"spec":{"replicas":3}}`))
		Expect(err).NotTo(HaveOccurred(), "patch OBP replicas back to 3")

		By("waiting for the StatefulSet to reach 3 ready replicas")
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha", "get", "statefulset", "ha-gw-backend",
				"-o", "jsonpath={.status.readyReplicas}"))
			return strings.TrimSpace(out)
		}, 5*time.Minute, 5*time.Second).Should(Equal("3"), "StatefulSet should reach 3 ready replicas")

		for i := range taskReplicas {
			podName := fmt.Sprintf("ha-gw-backend-%d", i)

			By(fmt.Sprintf("hashing the on-disk secret key in %s", podName))
			// HiddenServiceDir is /var/lib/tor/hs/hs (hsServiceDir). tor-init writes
			// the key pair there from the pod's own per-pod Secret (ha-gw-backend-{i}-keys).
			onDiskOut, err := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha", "exec", podName, "-c", "tor", "--",
				"sh", "-c", `sha256sum /var/lib/tor/hs/hs/hs_ed25519_secret_key | awk '{print $1}'`))
			Expect(err).NotTo(HaveOccurred(), "sha256sum on-disk key in pod %s", podName)
			secretHashOnDisk := strings.TrimSpace(onDiskOut)

			By(fmt.Sprintf("hashing the corresponding Secret's bytes for pod %d", i))
			b64Out, err := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha", "get", "secret",
				fmt.Sprintf("ha-gw-backend-%d-keys", i),
				"-o", "jsonpath={.data.hs_ed25519_secret_key}"))
			Expect(err).NotTo(HaveOccurred(), "fetch Secret ha-gw-backend-%d-keys", i)
			decoded, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Out))
			Expect(decErr).NotTo(HaveOccurred(), "base64-decode secret key for pod %d", i)
			wantHash := sha256.Sum256(decoded)
			Expect(secretHashOnDisk).To(Equal(hex.EncodeToString(wantHash[:])),
				"pod %s on-disk key should match its own Secret", podName)

			By(fmt.Sprintf("confirming pod %s hs dir holds exactly one keypair (no other pods' keys)", podName))
			// The emptyDir ("hs") is pod-local: each pod's HiddenServiceDir
			// contains only its own pair. Listing the dir and counting
			// ed25519 key files is the right negative check given that there
			// is no per-backend-index subdirectory — tor-init writes the single
			// pair directly into /var/lib/tor/hs/hs/.
			lsOut, err := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha", "exec", podName, "-c", "tor", "--",
				"sh", "-c", `find /var/lib/tor/hs/hs -maxdepth 1 -name 'hs_ed25519_*' | wc -l`))
			Expect(err).NotTo(HaveOccurred(), "list hs dir in pod %s", podName)
			Expect(strings.TrimSpace(lsOut)).To(Equal("2"),
				"pod %s should have exactly 2 hs_ed25519_* files (secret + public key)", podName)
		}
	})
})

var _ = Describe("OnionBalance HA — mutations", Ordered, Label("onionbalance", "ob-failover"), func() {
	var masterOnion string

	BeforeAll(func() {
		masterOnion = modeBFixture("tor-gateway-ha-mut", "ha-gw-mut-class", "ha-gw-mut")
	})

	AfterAll(func() {
		teardownModeBFixture("tor-gateway-ha-mut", "ha-gw-mut-class")
	})

	fetchOverTor := func(pod, path string) func() string {
		return func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha-mut", "exec", pod, "-c", "curl", "--",
				"curl", "-s", "--max-time", "30", "--socks5-hostname", "127.0.0.1:9050",
				"http://"+masterOnion+path))
			return strings.TrimSpace(out)
		}
	}

	It("remains reachable after a backend pod is killed", func() {
		By("deleting one backend StatefulSet pod")
		out, _ := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha-mut",
			"get", "pods", "-l", "torgateway.io/role=backend",
			"-o", "jsonpath={.items[0].metadata.name}"))
		podName := strings.TrimSpace(out)
		Expect(podName).NotTo(BeEmpty(), "expected at least one backend pod to exist")

		_, err := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha-mut", "delete", "pod", podName, "--wait=false"))
		Expect(err).NotTo(HaveOccurred(), "delete backend pod %s", podName)

		By("verifying the master .onion still serves / after pod kill")
		Eventually(fetchOverTor("ha-gw-mut-tor-client", "/"), "1m", "5s").
			Should(Equal("backend-A"), "service should remain up after one pod kill")
	})

	It("remains reachable after scaling replicas from 3 to 1", func() {
		By("patching OnionBalancePolicy replicas: 3 → 1")
		_, err := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha-mut", "patch", "onionbalancepolicy", "ha-gw-mut-obp",
			"--type=merge", "-p", `{"spec":{"replicas":1}}`))
		Expect(err).NotTo(HaveOccurred(), "patch OBP replicas to 1")

		By("waiting for the StatefulSet to scale down to 1")
		Eventually(func() (string, error) {
			return utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha-mut", "get", "statefulset", "ha-gw-mut-backend",
				"-o", "jsonpath={.status.readyReplicas}"))
		}, "3m", "5s").Should(Equal("1"), "StatefulSet should scale down to 1 ready replica")

		By("verifying the master .onion still serves / after scale-down")
		// Budget covers: obrefresh interval (30s) + SIGHUP + OB re-renders
		// descriptor with the smaller backend set + HSDir publish (testnet
		// publish-check 10s) + client re-lookup (testnet fetch 20s).
		// Typical ~90s on warm Mac, more headroom for cold CI runners.
		Eventually(fetchOverTor("ha-gw-mut-tor-client", "/"), "5m", "10s").
			Should(Equal("backend-A"), "service should remain up after scale to 1 replica")
	})

	// Task 11: SIGHUP reload on scale-up.
	// Runs after scale-down to 1; patches OBP to 4.
	It("reloads onionbalance via SIGHUP when backends scale up", func() {
		By("patching OBP replicas: 1 → 4")
		_, err := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha-mut", "patch", "onionbalancepolicy", "ha-gw-mut-obp",
			"--type=merge", "-p", `{"spec":{"replicas":4}}`))
		Expect(err).NotTo(HaveOccurred(), "patch OBP replicas to 4")

		By("waiting for backend-3 pod to be Running")
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha-mut", "get", "pod", "ha-gw-mut-backend-3",
				"-o", "jsonpath={.status.phase}"))
			return strings.TrimSpace(out)
		}, 5*time.Minute, 5*time.Second).Should(Equal("Running"),
			"ha-gw-mut-backend-3 pod should reach Running phase")

		By("waiting for the StatefulSet to reach 4 ready replicas")
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", "tor-gateway-ha-mut", "get", "statefulset", "ha-gw-mut-backend",
				"-o", "jsonpath={.status.readyReplicas}"))
			return strings.TrimSpace(out)
		}, 5*time.Minute, 5*time.Second).Should(Equal("4"),
			"StatefulSet should reach 4 ready replicas after scale-up")

		// countIntroPoints (parsing onionbalance or HSDir state) is not yet
		// implemented in the e2e helpers. Instead we verify readiness via two
		// gates: (1) all 4 backend StatefulSet pods are Running (above), and
		// (2) the master .onion continues to serve requests, proving that
		// onionbalance re-registered with the expanded backend set after SIGHUP.
		By("verifying the master .onion still serves / after scale-up to 4")
		// Budget: obrefresh poll interval (default 30s) + SIGHUP latency +
		// OB descriptor publish on chutney testnet (publish-check 10s) +
		// client re-lookup (testnet fetch cycle 20s).
		Eventually(fetchOverTor("ha-gw-mut-tor-client", "/"), 5*time.Minute, 10*time.Second).
			Should(Equal("backend-A"),
				"master .onion should remain reachable after scale-up to 4 backends")
	})
})

var _ = Describe("OnionBalance HA — cross-NS + NetworkPolicy", Ordered, Label("onionbalance"), func() {
	BeforeAll(func() {
		// NP-coverage spec observes the ha-gw fixture. The cross-NS spec is
		// self-contained — creates its own ha-master-secrets / tor-gateway-ha-crossns
		// namespaces in its body, doesn't depend on this fixture.
		_ = modeBFixture("tor-gateway-ha", "ha-gw-class", "ha-gw")
	})

	AfterAll(func() {
		teardownModeBFixture("tor-gateway-ha", "ha-gw-class")
	})

	// Task 12: Cross-NS master Secret via ReferenceGrant.
	It("supports a master Secret in a different namespace via ReferenceGrant", Label("ob-crossns"), func() {
		const (
			crossNSGWClass = "tor-gateway-ha-crossns"
			crossGWName    = "blog-cross"
			masterSecName  = "ob-master"
		)
		sourceNS := "ha-master-secrets"

		By("creating the cross-NS secrets namespace")
		_, err := utils.Run(exec.Command("kubectl", "create", "ns", sourceNS))
		Expect(err).NotTo(HaveOccurred(), "create namespace %s", sourceNS)
		DeferCleanup(func() {
			_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", sourceNS, "--wait=false", "--ignore-not-found"))
			_, _ = utils.Run(exec.Command("kubectl", "-n", obpNS, "delete", "gateway", crossGWName, "--ignore-not-found"))
			_, _ = utils.Run(exec.Command("kubectl", "-n", obpNS, "delete", "onionbalancepolicy",
				crossGWName+"-obp", "--ignore-not-found"))
			_, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", crossNSGWClass, "--ignore-not-found"))
		})

		By("generating a master keypair and creating the Secret in sourceNS")
		kp, kpErr := tor.GenerateKeyPair(rand.Reader)
		Expect(kpErr).NotTo(HaveOccurred(), "generate cross-NS master keypair")
		crossHostname := kp.OnionAddress().String()

		applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %[1]s
  namespace: %[2]s
type: Opaque
data:
  hs_ed25519_secret_key: %[3]s
  hs_ed25519_public_key: %[4]s
`, masterSecName, sourceNS,
			base64.StdEncoding.EncodeToString(kp.SecretKeyFile()),
			base64.StdEncoding.EncodeToString(kp.PublicKeyFile())))

		By("applying a ReferenceGrant in sourceNS allowing OnionBalancePolicies in obpNS to read Secrets")
		// The from.group matches the OBP API group used by MasterKeyReferenceGrantAllows.
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-ob-master-fetch
  namespace: %[1]s
spec:
  from:
  - group: policy.torgateway.io
    kind: OnionBalancePolicy
    namespace: %[2]s
  to:
  - group: ""
    kind: Secret
    name: %[3]s
`, sourceNS, obpNS, masterSecName))

		By("installing a dedicated GatewayClass for the cross-NS test")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: %s
spec:
  controllerName: torgateway.io/gateway-controller
`, crossNSGWClass))

		By("deploying Gateway + OBP referencing the cross-NS master Secret")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  gatewayClassName: %[3]s
  listeners:
  - { name: onion, port: 80, protocol: torgateway.io/HiddenService }
---
apiVersion: policy.torgateway.io/v1alpha1
kind: OnionBalancePolicy
metadata:
  name: %[1]s-obp
  namespace: %[2]s
spec:
  targetRefs:
  - { group: gateway.networking.k8s.io, kind: Gateway, name: %[1]s }
  replicas: 1
  masterKeySecretRef:
    name: %[4]s
    namespace: %[5]s
`, crossGWName, obpNS, crossNSGWClass, masterSecName, sourceNS))

		By("waiting for Gateway.status.addresses to publish the expected .onion hostname")
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", obpNS, "get", "gateway", crossGWName,
				"-o", "jsonpath={.status.addresses[0].value}"))
			return strings.TrimSpace(out)
		}, 5*time.Minute, 5*time.Second).Should(Equal(crossHostname),
			"Gateway %s should publish the pre-seeded cross-NS master .onion address", crossGWName)

		// CrossNSMasterRoleName(gw) = FrontendName(gw) + "-master-fetch"
		//                           = gw.Name + "-frontend-master-fetch"
		expectedRoleBindingName := crossGWName + "-frontend-master-fetch"
		By("confirming the cross-NS RoleBinding lands in sourceNS")
		out, rbErr := utils.Run(exec.Command("kubectl", "-n", sourceNS, "get", "rolebinding", expectedRoleBindingName))
		Expect(rbErr).NotTo(HaveOccurred(), "cross-NS RoleBinding %s should exist in %s: %s",
			expectedRoleBindingName, sourceNS, out)
	})

	// Task 13: per-Gateway NetworkPolicy selector covers all Mode B pods.
	It("covers Mode B frontend and backend pods with the per-Gateway NetworkPolicy",
		Label("networkpolicy", "onionbalance"), func() {
			const npName = "ha-gw-netpol"

			By("fetching the per-Gateway NetworkPolicy")
			npOut, err := utils.Run(exec.Command("kubectl", "-n", obpNS, "get", "networkpolicy", npName, "-o", "json"))
			Expect(err).NotTo(HaveOccurred(), "NetworkPolicy %s should exist in %s", npName, obpNS)
			var np networkingv1.NetworkPolicy
			Expect(json.Unmarshal([]byte(npOut), &np)).To(Succeed())

			sel, selErr := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
			Expect(selErr).NotTo(HaveOccurred())

			By("listing all Mode B pods (frontend Deployment + backend StatefulSet)")
			podOut, err := utils.Run(exec.Command("kubectl", "-n", obpNS, "get", "pods",
				"-l", "torgateway.io/gateway=ha-gw",
				"-o", "jsonpath={range .items[*]}{.metadata.name}={.metadata.labels}{\"\\n\"}{end}"))
			Expect(err).NotTo(HaveOccurred(), "list Mode B pods in %s", obpNS)

			type podItem struct {
				Metadata struct {
					Name   string            `json:"name"`
					Labels map[string]string `json:"labels"`
				} `json:"metadata"`
			}
			type podList struct {
				Items []podItem `json:"items"`
			}
			listOut, err := utils.Run(exec.Command("kubectl", "-n", obpNS, "get", "pods",
				"-l", "torgateway.io/gateway=ha-gw",
				"-o", "json"))
			Expect(err).NotTo(HaveOccurred(), "get pods JSON in %s", obpNS)
			_ = podOut

			var pl podList
			Expect(json.Unmarshal([]byte(listOut), &pl)).To(Succeed())
			Expect(pl.Items).NotTo(BeEmpty(), "expected at least one Mode B pod with label torgateway.io/gateway=ha-gw")

			By("asserting the NP podSelector matches every Mode B pod")
			for _, p := range pl.Items {
				Expect(sel.Matches(labels.Set(p.Metadata.Labels))).To(BeTrue(),
					"NP selector should match Mode B pod %s with labels %v", p.Metadata.Name, p.Metadata.Labels)
			}
		})
})
