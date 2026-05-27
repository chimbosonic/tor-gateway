//go:build e2e
// +build e2e

/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Real-Tor data-plane e2e: deploys a Gateway + two-backend HTTPRoute, then
// fetches the published .onion over the public Tor network through an
// in-cluster Tor SOCKS client and asserts path-based routing. Tor bootstrap
// and hidden-service descriptor publish/lookup are slow and occasionally
// flaky against the public network; on failure, re-run.

package e2e

import (
	"fmt"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/test/utils"
)

const dataplaneNS = "tor-gateway-dataplane"

// buildAndLoadImage builds a project image via its make target and loads the
// resulting tag into the kind cluster so PullIfNotPresent uses it.
func buildAndLoadImage(makeTarget, imageRef string) {
	GinkgoHelper()
	_, err := utils.Run(exec.Command("make", makeTarget))
	Expect(err).NotTo(HaveOccurred(), "make %s", makeTarget)
	Expect(utils.LoadImageToKindClusterWithName(imageRef)).To(Succeed(), "kind load %s", imageRef)
}

var _ = Describe("Tor data plane", Ordered, Label("dataplane"), func() {
	BeforeAll(func() {
		By("building and loading the per-Gateway pod images")
		// Tags must match the operator's --router-image / --tor-init-image /
		// --tor-image defaults (cmd/manager/main.go) so the pods use the
		// kind-loaded images.
		buildAndLoadImage("image-router", "ghcr.io/chimbosonic/tor-gateway-router:dev")
		buildAndLoadImage("image-tor-init", "ghcr.io/chimbosonic/tor-gateway-tor-init:dev")
		buildAndLoadImage("image-tor", "ghcr.io/chimbosonic/tor:0.4.8-latest")

		By("creating the data-plane namespace")
		runOrSkipExisting("kubectl", "create", "ns", dataplaneNS)

		By("installing the tor-gateway GatewayClass")
		applyYAML(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: tor-gateway
spec:
  controllerName: torgateway.io/gateway-controller
`)

		By("deploying two http-echo backends with distinct bodies")
		applyYAML(fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: backend-a, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: backend-a } }
  template:
    metadata: { labels: { app: backend-a } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=backend-A", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: backend-a, namespace: %[1]s }
spec:
  selector: { app: backend-a }
  ports: [{ port: 5678, targetPort: 5678 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: backend-b, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: backend-b } }
  template:
    metadata: { labels: { app: backend-b } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=backend-B", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: backend-b, namespace: %[1]s }
spec:
  selector: { app: backend-b }
  ports: [{ port: 5678, targetPort: 5678 }]
`, dataplaneNS))

		By("waiting for the backends to be Available")
		for _, d := range []string{"backend-a", "backend-b"} {
			_, err := utils.Run(exec.Command("kubectl", "-n", dataplaneNS,
				"rollout", "status", "deployment/"+d, "--timeout=120s"))
			Expect(err).NotTo(HaveOccurred(), "backend %s not ready", d)
		}
	})

	AfterAll(func() {
		By("removing data-plane namespace and GatewayClass")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", dataplaneNS, "--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", "tor-gateway", "--ignore-not-found"))
	})

	It("routes by path to the right backend over the published .onion", func() {
		By("creating the Gateway and a two-rule HTTPRoute")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: blog, namespace: %[1]s }
spec:
  gatewayClassName: tor-gateway
  listeners:
  - { name: onion, port: 80, protocol: torgateway.io/HiddenService }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: blog, namespace: %[1]s }
spec:
  parentRefs: [{ name: blog }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: /api } }]
    backendRefs: [{ name: backend-b, port: 5678 }]
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: backend-a, port: 5678 }]
`, dataplaneNS))

		By("waiting for the Tor Deployment to become Available (real images now run)")
		Eventually(func() (string, error) {
			return utils.Run(exec.Command("kubectl", "-n", dataplaneNS, "get", "deployment", "blog",
				"-o", "jsonpath={.status.conditions[?(@.type==\"Available\")].status}"))
		}, "3m", "5s").Should(Equal("True"), "Tor pod never became Available")

		By("reading the published .onion from Gateway status")
		var onion string
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", dataplaneNS, "get", "gateway", "blog",
				"-o", "jsonpath={.status.addresses[0].value}"))
			onion = strings.TrimSpace(out)
			return onion
		}, "60s", "2s").Should(MatchRegexp(`^[a-z2-7]{56}\.onion$`))

		By("deploying an in-cluster Tor SOCKS client + curl sidecar")
		applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata: { name: tor-client, namespace: %[1]s }
spec:
  restartPolicy: Never
  securityContext: { fsGroup: 65532 }
  containers:
  - name: tor
    image: ghcr.io/chimbosonic/tor:0.4.8-latest
    imagePullPolicy: IfNotPresent
    args: ["--SocksPort", "127.0.0.1:9050", "--DataDirectory", "/var/lib/tor/data/data", "--Log", "notice stdout"]
    securityContext: { runAsUser: 65532, runAsGroup: 65532 }
    volumeMounts: [{ name: data, mountPath: /var/lib/tor/data }]
  - name: curl
    image: curlimages/curl:8.11.1
    command: ["sleep", "infinity"]
  volumes:
  - { name: data, emptyDir: {} }
`, dataplaneNS))
		// Ready here only means the tor process started, not that it has
		// bootstrapped onto the Tor network; the Eventually below tolerates
		// the bootstrap + descriptor-lookup time.
		_, err := utils.Run(exec.Command("kubectl", "-n", dataplaneNS,
			"wait", "--for=condition=Ready", "pod/tor-client", "--timeout=120s"))
		Expect(err).NotTo(HaveOccurred(), "tor-client pod not ready")

		// fetchOverTor curls the .onion through the client's SOCKS proxy.
		fetchOverTor := func(path string) func() string {
			return func() string {
				out, _ := utils.Run(exec.Command("kubectl", "-n", dataplaneNS, "exec", "tor-client", "-c", "curl", "--",
					"curl", "-s", "--max-time", "30", "--socks5-hostname", "127.0.0.1:9050",
					"http://"+onion+path))
				return strings.TrimSpace(out)
			}
		}

		By("fetching / over Tor -> backend-A (allows time for HS descriptor publish+lookup)")
		Eventually(fetchOverTor("/"), "8m", "15s").Should(Equal("backend-A"))

		By("fetching /api over Tor -> backend-B")
		Eventually(fetchOverTor("/api"), "2m", "10s").Should(Equal("backend-B"))
	})
})
