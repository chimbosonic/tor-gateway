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

var _ = Describe("Vanity harvest", Ordered, Label("vanity"), func() {
	const (
		ns      = "vanity-e2e"
		gwClass = "tor-gateway-vanity-e2e"
	)

	jpath := func(ref, path string) func() string {
		return func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", ns, "get", ref, "-o", "jsonpath="+path))
			return strings.TrimSpace(out)
		}
	}

	BeforeAll(func() {
		buildAndLoadImage("image-mkp224o", "ghcr.io/chimbosonic/mkp224o:dev")
		buildAndLoadImage("image-vanity-finalize", "ghcr.io/chimbosonic/tor-gateway-vanity-finalize:dev")
		// The promoted Gateway also provisions a Tor Deployment; load its images
		// so the pod runs and Programmed=True is reached (not just published).
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

	It("harvests via the real mkp224o Job and publishes a vanity .onion with the requested prefix", func() {
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: van
  namespace: %[1]s
  annotations: { torgateway.io/await-vanity: "true" }
spec:
  gatewayClassName: %[2]s
  listeners: [{ name: onion, port: 80, protocol: torgateway.io/HiddenService }]
---
apiVersion: policy.torgateway.io/v1alpha1
kind: TorServicePolicy
metadata: { name: van, namespace: %[1]s }
spec:
  targetRefs: [{ group: gateway.networking.k8s.io, kind: Gateway, name: van }]
  vanityPrefix: "abc"
`, ns, gwClass))

		// The harvest Job is transient (the operator deletes it right after
		// promoting the key), so we don't assert on it. The published address
		// carrying the 3-char prefix is the end-to-end proof the real mkp224o
		// Job ran and its key was promoted; a broken/SIGILL image would never
		// publish, and a random key matching "abc" is ~1/32768.
		By("the published .onion starts with the requested prefix")
		Eventually(jpath("gateway/van", "{.status.addresses[0].value}"), "3m", "5s").
			Should(MatchRegexp(`^abc[a-z2-7]{53}\.onion$`))

		By("Gateway Programmed=True")
		Eventually(jpath("gateway/van", `{.status.conditions[?(@.type=="Programmed")].status}`), "60s", "3s").
			Should(Equal("True"))
	})
})
