/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/test/utils"
)

var _ = Describe("ReferenceGrant cross-namespace backendRef", Ordered, Label("referencegrant"), func() {
	const (
		gwNS      = "rg-e2e"
		backendNS = "rg-e2e-backend"
		gwClass   = "tor-gateway-rg-e2e"
	)

	// jpath reads a jsonpath off a resource in gwNS.
	jpath := func(ref, path string) func() string {
		return func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", gwNS, "get", ref, "-o", "jsonpath="+path))
			return strings.TrimSpace(out)
		}
	}

	BeforeAll(func() {
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", gwNS))
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", backendNS))
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: %s }
spec: { controllerName: torgateway.io/gateway-controller }
`, gwClass))
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: rg-gw, namespace: %s }
spec:
  gatewayClassName: %s
  listeners:
  - { name: onion, port: 80, protocol: torgateway.io/HiddenService }
`, gwNS, gwClass))
	})

	AfterAll(func() {
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", gwNS, "--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", backendNS, "--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", gwClass, "--ignore-not-found"))
	})

	const resolvedRefsReason = `{.status.parents[?(@.controllerName=="torgateway.io/gateway-controller")].conditions[?(@.type=="ResolvedRefs")].reason}`

	It("reports RefNotPermitted for an ungated cross-namespace backendRef", func() {
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: rg-route, namespace: %[1]s }
spec:
  parentRefs: [{ name: rg-gw }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: app, namespace: %[2]s, port: 80 }]
`, gwNS, backendNS))

		Eventually(jpath("httproute/rg-route", resolvedRefsReason), "30s", "2s").
			Should(Equal("RefNotPermitted"))
	})

	It("flips to ResolvedRefs once a ReferenceGrant is added", func() {
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata: { name: allow-rg-e2e, namespace: %[2]s }
spec:
  from: [{ group: gateway.networking.k8s.io, kind: HTTPRoute, namespace: %[1]s }]
  to: [{ group: "", kind: Service }]
`, gwNS, backendNS))

		Eventually(jpath("httproute/rg-route", resolvedRefsReason), "30s", "2s").
			Should(Equal("ResolvedRefs"))
	})
})
