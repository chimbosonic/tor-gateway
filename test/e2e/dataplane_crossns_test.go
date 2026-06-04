//go:build e2e

/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e

import (
	"fmt"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/test/utils"
)

var _ = Describe("Tor data plane cross-namespace", Ordered, Label("dataplane-crossns"), func() {
	const (
		gwNS      = "crossns-e2e"
		backendNS = "crossns-e2e-backend"
		gwClass   = "tor-gateway-crossns-e2e"
	)
	var onion string

	echoDeploy := func(name, ns, body string) string {
		return fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: %[1]s, namespace: %[2]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: %[1]s } }
  template:
    metadata: { labels: { app: %[1]s } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=%[3]s", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: %[1]s, namespace: %[2]s }
spec:
  selector: { app: %[1]s }
  ports: [{ port: 5678, targetPort: 5678 }]
`, name, ns, body)
	}

	fetchOverTor := func(path string) func() string {
		return func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", gwNS, "exec", "tor-client", "-c", "curl", "--",
				"curl", "-s", "--max-time", "30", "--socks5-hostname", "127.0.0.1:9050", "http://"+onion+path))
			return strings.TrimSpace(out)
		}
	}

	BeforeAll(func() {
		buildAndLoadImage("image-router", "ghcr.io/chimbosonic/tor-gateway-router:dev")
		buildAndLoadImage("image-tor-init", "ghcr.io/chimbosonic/tor-gateway-tor-init:dev")
		buildAndLoadImage("image-tor", "ghcr.io/chimbosonic/tor:0.4.9")
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", gwNS))
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", backendNS))

		By("copying the chutney fragment into the gateway namespace")
		copyChutneyFragmentTo(gwNS)

		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: %s }
spec: { controllerName: torgateway.io/gateway-controller }
`, gwClass))
		applyYAML(echoDeploy("local", gwNS, "local"))
		applyYAML(echoDeploy("remote", backendNS, "remote"))
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: blog, namespace: %[1]s }
spec:
  gatewayClassName: %[2]s
  listeners: [{ name: onion, port: 80, protocol: torgateway.io/HiddenService }]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: blog, namespace: %[1]s }
spec:
  parentRefs: [{ name: blog }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: /local } }]
    backendRefs: [{ name: local, port: 5678 }]
  - matches: [{ path: { type: PathPrefix, value: /remote } }]
    backendRefs: [{ name: remote, namespace: %[3]s, port: 5678 }]
`, gwNS, gwClass, backendNS))
	})

	AfterAll(func() {
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", gwNS, "--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", backendNS, "--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", gwClass, "--ignore-not-found"))
	})

	It("routes the control path but withholds the ungated cross-ns path, then routes it after a grant", func() {
		By("reading the published .onion")
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", gwNS, "get", "gateway", "blog",
				"-o", "jsonpath={.status.addresses[0].value}"))
			onion = strings.TrimSpace(out)
			return onion
		}, "60s", "2s").Should(MatchRegexp(`^[a-z2-7]{56}\.onion$`))

		By("deploying the in-cluster Tor SOCKS client")
		applyYAML(chutneyTorClientPodYAML(gwNS, "tor-client"))

		By("waiting for the Tor client pod to be Ready")
		_, _ = utils.Run(exec.Command("kubectl", "-n", gwNS, "wait", "--for=condition=Ready",
			"pod/tor-client", "--timeout=120s"))

		By("control path /local routes (proves the circuit is live)")
		Eventually(fetchOverTor("/local"), "2m", "5s").Should(Equal("local"))

		By("ungated /remote does NOT route (cross-ns denied)")
		Consistently(fetchOverTor("/remote"), "30s", "10s").ShouldNot(Equal("remote"))

		By("adding a ReferenceGrant in the backend namespace")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata: { name: allow-crossns, namespace: %[1]s }
spec:
  from: [{ group: gateway.networking.k8s.io, kind: HTTPRoute, namespace: %[2]s }]
  to: [{ group: "", kind: Service }]
`, backendNS, gwNS))

		By("/remote now routes")
		Eventually(fetchOverTor("/remote"), "2m", "5s").Should(Equal("remote"))
	})
})
