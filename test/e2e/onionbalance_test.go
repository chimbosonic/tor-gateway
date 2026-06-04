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

package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/internal/tor"
	"github.com/chimbosonic/tor-gateway/test/utils"
)

const obpNS = "tor-gateway-ha"

var _ = Describe("OnionBalance HA (Mode B)", Ordered, Label("onionbalance"), func() {
	const (
		obpGwClass     = "tor-gateway-ha"
		masterSecret   = "ha-master-key"
		obrefreshImage = "ghcr.io/chimbosonic/tor-gateway-obrefresh:dev"
		obImage        = "ghcr.io/chimbosonic/tor-gateway-onionbalance:dev"
	)

	var masterOnion string

	fetchOverTor := func(pod, path string) func() string {
		return func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", obpNS, "exec", pod, "-c", "curl", "--",
				"curl", "-s", "--max-time", "30", "--socks5-hostname", "127.0.0.1:9050",
				"http://"+masterOnion+path))
			return strings.TrimSpace(out)
		}
	}

	BeforeAll(func() {
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
		runOrSkipExisting("kubectl", "create", "ns", obpNS)

		By("copying the chutney fragment into the HA namespace")
		copyChutneyFragmentTo(obpNS)

		By("installing the tor-gateway GatewayClass for HA tests")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: %s
spec:
  controllerName: torgateway.io/gateway-controller
`, obpGwClass))

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
`, masterSecret, obpNS, secretKey, publicKey))

		By("deploying two http-echo backends for path-based routing")
		applyYAML(fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: ha-backend-a, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: ha-backend-a } }
  template:
    metadata: { labels: { app: ha-backend-a } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=backend-A", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: ha-backend-a, namespace: %[1]s }
spec:
  selector: { app: ha-backend-a }
  ports: [{ port: 5678, targetPort: 5678 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: ha-backend-b, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: ha-backend-b } }
  template:
    metadata: { labels: { app: ha-backend-b } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=backend-B", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: ha-backend-b, namespace: %[1]s }
spec:
  selector: { app: ha-backend-b }
  ports: [{ port: 5678, targetPort: 5678 }]
`, obpNS))

		By("waiting for app backends to be Available")
		for _, d := range []string{"ha-backend-a", "ha-backend-b"} {
			_, err := utils.Run(exec.Command("kubectl", "-n", obpNS,
				"rollout", "status", "deployment/"+d, "--timeout=120s"))
			Expect(err).NotTo(HaveOccurred(), "app backend %s not ready", d)
		}

		By("applying Gateway + OnionBalancePolicy (3 backends) + two-rule HTTPRoute")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ha-gw
  namespace: %[1]s
spec:
  gatewayClassName: %[2]s
  listeners:
  - { name: onion, port: 80, protocol: torgateway.io/HiddenService }
---
apiVersion: policy.torgateway.io/v1alpha1
kind: OnionBalancePolicy
metadata:
  name: ha-obp
  namespace: %[1]s
spec:
  targetRefs:
  - { group: gateway.networking.k8s.io, kind: Gateway, name: ha-gw }
  replicas: 3
  masterKeySecretRef:
    name: %[3]s
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ha-route
  namespace: %[1]s
spec:
  parentRefs: [{ name: ha-gw }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: /api } }]
    backendRefs: [{ name: ha-backend-b, port: 5678 }]
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: ha-backend-a, port: 5678 }]
`, obpNS, obpGwClass, masterSecret))

		By("waiting for the frontend Deployment to become Available")
		Eventually(func() (string, error) {
			return utils.Run(exec.Command("kubectl", "-n", obpNS, "get", "deployment", "ha-gw-frontend",
				"-o", "jsonpath={.status.conditions[?(@.type==\"Available\")].status}"))
		}, "5m", "5s").Should(Equal("True"), "frontend Deployment never became Available")

		By("waiting for Gateway.status.addresses to publish the master .onion")
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", obpNS, "get", "gateway", "ha-gw",
				"-o", "jsonpath={.status.addresses[0].value}"))
			return strings.TrimSpace(out)
		}, "60s", "2s").Should(Equal(masterOnion),
			"Gateway should publish the pre-seeded master .onion address")

		By("deploying an in-cluster Tor SOCKS client for fetching the .onion")
		applyYAML(chutneyTorClientPodYAML(obpNS, "ha-tor-client"))

		_, err = utils.Run(exec.Command("kubectl", "-n", obpNS,
			"wait", "--for=condition=Ready", "pod/ha-tor-client", "--timeout=120s"))
		Expect(err).NotTo(HaveOccurred(), "ha-tor-client pod not ready")
	})

	AfterAll(func() {
		if os.Getenv("TOR_GATEWAY_E2E_NO_TEARDOWN") == "1" {
			fmt.Printf("\n[debug] keeping ns %s + gatewayclass %s (TOR_GATEWAY_E2E_NO_TEARDOWN=1)\n", obpNS, obpGwClass)
			return
		}
		By("removing HA test namespace and GatewayClass")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", obpNS, "--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", obpGwClass, "--ignore-not-found"))
	})

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

	It("remains reachable after a backend pod is killed", func() {
		By("deleting one backend StatefulSet pod")
		out, _ := utils.Run(exec.Command("kubectl", "-n", obpNS,
			"get", "pods", "-l", "torgateway.io/role=backend",
			"-o", "jsonpath={.items[0].metadata.name}"))
		podName := strings.TrimSpace(out)
		Expect(podName).NotTo(BeEmpty(), "expected at least one backend pod to exist")

		_, err := utils.Run(exec.Command("kubectl", "-n", obpNS, "delete", "pod", podName, "--wait=false"))
		Expect(err).NotTo(HaveOccurred(), "delete backend pod %s", podName)

		By("verifying the master .onion still serves / after pod kill")
		Eventually(fetchOverTor("ha-tor-client", "/"), "1m", "5s").
			Should(Equal("backend-A"), "service should remain up after one pod kill")
	})

	It("remains reachable after scaling replicas from 3 to 1", func() {
		By("patching OnionBalancePolicy replicas: 3 → 1")
		_, err := utils.Run(exec.Command("kubectl", "-n", obpNS, "patch", "onionbalancepolicy", "ha-obp",
			"--type=merge", "-p", `{"spec":{"replicas":1}}`))
		Expect(err).NotTo(HaveOccurred(), "patch OBP replicas to 1")

		By("waiting for the StatefulSet to scale down to 1")
		Eventually(func() (string, error) {
			return utils.Run(exec.Command("kubectl", "-n", obpNS, "get", "statefulset", "ha-gw-backend",
				"-o", "jsonpath={.status.readyReplicas}"))
		}, "3m", "5s").Should(Equal("1"), "StatefulSet should scale down to 1 ready replica")

		By("verifying the master .onion still serves / after scale-down")
		// Budget covers: obrefresh interval (30s) + SIGHUP + OB re-renders
		// descriptor with the smaller backend set + HSDir publish (testnet
		// publish-check 10s) + client re-lookup (testnet fetch 20s).
		// Typical ~90s on warm Mac, more headroom for cold CI runners.
		Eventually(fetchOverTor("ha-tor-client", "/"), "5m", "10s").
			Should(Equal("backend-A"), "service should remain up after scale to 1 replica")
	})
})
