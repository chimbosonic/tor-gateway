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

var _ = Describe("Tor-pod NetworkPolicy", Ordered, Label("networkpolicy"), func() {
	const (
		ns      = "np-e2e"
		gwClass = "tor-gateway-np-e2e"
	)

	BeforeAll(func() {
		buildAndLoadImage("image-router", "ghcr.io/chimbosonic/tor-gateway-router:dev")
		buildAndLoadImage("image-tor-init", "ghcr.io/chimbosonic/tor-gateway-tor-init:dev")
		buildAndLoadImage("image-tor", "ghcr.io/chimbosonic/tor:0.4.9")
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", ns))
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: %s }
spec: { controllerName: torgateway.io/gateway-controller }
`, gwClass))
	})

	AfterAll(func() {
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", ns, "--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", gwClass, "--ignore-not-found"))
	})

	It("lets the Tor pod reach the backend and blocks a non-backend in the same namespace", func() {
		By("deploying a backend Service + a victim pod with a different label, both in the Gateway ns")
		applyYAML(fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: backend, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: backend } }
  template:
    metadata: { labels: { app: backend } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=backend", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: backend, namespace: %[1]s }
spec: { selector: { app: backend }, ports: [{ port: 5678, targetPort: 5678 }] }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: victim, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: victim } }
  template:
    metadata: { labels: { app: victim } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=victim", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: victim, namespace: %[1]s }
spec: { selector: { app: victim }, ports: [{ port: 5678, targetPort: 5678 }] }
---
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
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: backend, port: 5678 }]
`, ns, gwClass))

		By("waiting for the Tor pod to be Ready (Gateway Programmed=True)")
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", ns, "get", "gateway", "blog",
				"-o", "jsonpath={.status.conditions[?(@.type==\"Programmed\")].status}"))
			return strings.TrimSpace(out)
		}, "5m", "5s").Should(Equal("True"))

		By("deploying a labelled prober pod (same labels as the Tor pod -> covered by the same NetworkPolicy)")
		// The router container is distroless (no shell), so we can't kubectl
		// exec into the actual Tor pod. Instead we deploy a busybox pod with
		// the same ChildLabels so the per-Gateway NetworkPolicy applies to
		// it too; the rule matrix is identical.
		applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: prober
  namespace: %[1]s
  labels:
    app.kubernetes.io/managed-by: tor-gateway
    torgateway.io/gateway: blog
spec:
  restartPolicy: Never
  containers:
  - name: probe
    image: busybox:1.36
    command: ["sleep", "infinity"]
`, ns))
		_, _ = utils.Run(exec.Command("kubectl", "-n", ns, "wait", "--for=condition=Ready",
			"pod/prober", "--timeout=60s"))

		curlFromProber := func(target string) func() string {
			return func() string {
				out, _ := utils.Run(exec.Command("kubectl", "-n", ns, "exec", "prober", "-c", "probe", "--",
					"sh", "-c", "wget -qO- --timeout=5 "+target+" 2>&1"))
				return strings.TrimSpace(out)
			}
		}

		By("backend is reachable from the prober (per-backend rule allows)")
		Eventually(curlFromProber("http://backend."+ns+".svc:5678/"), "60s", "5s").Should(ContainSubstring("backend"))

		By("victim is NOT reachable (no rule allows)")
		Consistently(curlFromProber("http://victim."+ns+".svc:5678/"), "20s", "5s").ShouldNot(ContainSubstring("victim"))
	})
})
