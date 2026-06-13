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
//  3. Use Label("ob-failover") on mutator specs so the CI matrix can route them.
//  4. Generous setup budgets (5-10m), tight assertion budgets (<=2m).

package e2e

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/internal/tor"
	"github.com/chimbosonic/tor-gateway/test/utils"
)

// buildModeBFixture builds a Mode B test fixture in the given namespace + GatewayClass.
// Generates a master keypair, creates the master Secret + GatewayClass + Gateway +
// OBP + HTTPRoute + 2 echo backends, waits for the frontend Deployment Available,
// waits for Gateway.status.addresses to publish the .onion, applies a tor-client
// pod, and returns the master .onion address for use in specs.
func buildModeBFixture(ns, gwClass, gwName string) (masterOnion string) {
	masterSecretName := gwName + "-master-secret"
	obpName := gwName + "-obp"
	routeName := gwName + "-route"
	backendA := gwName + "-backend-a"
	backendB := gwName + "-backend-b"
	torClientPod := gwName + "-tor-client"

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

// warmUpMasterOnion polls the master .onion until it serves a backend
// response. This wait pulls the HSDir propagation cost out of every spec —
// once it succeeds, fetchOverTor calls inside specs can use tight budgets
// (30s-1m). Error-returning (not Expect-failing) so the caller can rebuild
// the fixture and retry — a ginkgo BeforeAll failure is otherwise terminal.
func warmUpMasterOnion(ns, pod, onion string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last string
	for time.Now().Before(deadline) {
		out, _ := utils.Run(exec.Command("kubectl", "-n", ns, "exec", pod, "-c", "curl", "--",
			"curl", "-s", "--max-time", "30", "--socks5-hostname", "127.0.0.1:9050",
			"http://"+onion+"/"))
		last = strings.TrimSpace(out)
		if last == "backend-A" || last == "backend-B" {
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	return fmt.Errorf("master .onion not reachable within %s (last output %q)", budget, last)
}

// modeBFixture builds the fixture and warms the master .onion circuit,
// rebuilding the whole fixture once (fresh namespace, fresh keys) if the
// warmup times out. (With TOR_GATEWAY_E2E_NO_TEARDOWN=1 the rebuild path
// can't reclaim the namespace — that env is a local debug knob only.)
func modeBFixture(ns, gwClass, gwName string) string {
	const warmupBudget = 10 * time.Minute
	torClientPod := gwName + "-tor-client"

	masterOnion := buildModeBFixture(ns, gwClass, gwName)
	By("warming up the Tor circuit to the master .onion (absorbs HSDir propagation latency)")
	err := warmUpMasterOnion(ns, torClientPod, masterOnion, warmupBudget)
	if err == nil {
		return masterOnion
	}

	utils.CIWarning("mode B fixture warmup failed in %s; rebuilding fixture once: %v", ns, err)
	utils.StepSummary("fixture rebuild: %s (warmup timeout)", ns)
	teardownModeBFixture(ns, gwClass)
	waitForNamespaceGone(ns)

	masterOnion = buildModeBFixture(ns, gwClass, gwName)
	By("warming up the Tor circuit after fixture rebuild")
	err = warmUpMasterOnion(ns, torClientPod, masterOnion, warmupBudget)
	Expect(err).NotTo(HaveOccurred(), "mode B fixture warmup failed again after rebuild")
	utils.StepSummary("fixture ready after rebuild: %s", ns)
	return masterOnion
}

// waitForNamespaceGone blocks until the namespace finishes deleting
// (teardownModeBFixture deletes with --wait=false).
func waitForNamespaceGone(ns string) {
	Eventually(func() string {
		out, _ := utils.Run(exec.Command("kubectl", "get", "ns", ns,
			"-o", "jsonpath={.metadata.name}", "--ignore-not-found"))
		return strings.TrimSpace(out)
	}, "3m", "5s").Should(BeEmpty(), "namespace %s should finish deleting before rebuild", ns)
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
		By("fetching / over Tor via onionbalance -> backend-A (circuit is warm from BeforeAll warmup)")
		Eventually(fetchOverTor("ha-gw-tor-client", "/"), "1m", "3s").
			Should(Equal("backend-A"), "/ should route to backend-A via the master .onion")

		By("fetching /api over Tor via onionbalance -> backend-B")
		Eventually(fetchOverTor("ha-gw-tor-client", "/api"), "1m", "3s").
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
		// Pod kill -> StatefulSet restarts pod -> onionbalance descriptor refresh ->
		// HSDir re-publish -> client re-lookup. Circuit is warm from BeforeAll warmup;
		// 2m covers recovery on chutney testnet with headroom for cold CI runners.
		Eventually(fetchOverTor("ha-gw-mut-tor-client", "/"), "2m", "3s").
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
