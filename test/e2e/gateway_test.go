//go:build e2e
// +build e2e

/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Operator-side e2e assertions for tor-gateway. The Tor and router
// containers in the per-Gateway pod use placeholder image references that
// will not become Ready in the test cluster; we exercise *the operator*
// (reconciler resource generation, status writes, OwnerReferences-driven
// cleanup), not the data plane. A separate suite (deferred to v2) will
// run a real Tor image and assert .onion connectivity.

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/test/utils"
)

const (
	testNamespace = "tor-gateway-e2e"
	testGwClass   = "tor-gateway"
)

var _ = Describe("Gateway lifecycle", Ordered, Label("gateway"), func() {

	// The operator + CRDs are deployed once at suite level
	// (deployOperator in e2e_suite_test.go), so this container only needs
	// its own namespace and GatewayClass.
	BeforeAll(func() {
		By("creating an isolated test namespace")
		runOrSkipExisting("kubectl", "create", "ns", testNamespace)

		By("installing the tor-gateway GatewayClass")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: %s
spec:
  controllerName: torgateway.io/gateway-controller
`, testGwClass))
	})

	AfterAll(func() {
		By("removing test namespace and GatewayClass")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", testGwClass, "--ignore-not-found"))
	})

	It("provisions a Secret, ConfigMap, Deployment, Service and publishes an .onion", func() {
		By("creating a Gateway")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: blog
  namespace: %s
spec:
  gatewayClassName: %s
  listeners:
  - name: onion
    port: 80
    protocol: torgateway.io/HiddenService
`, testNamespace, testGwClass))

		By("waiting for the key Secret to appear")
		Eventually(getJSONPath("secret/blog-keys", "{.data.hostname}"), "60s", "2s").
			ShouldNot(BeEmpty(), "key Secret should be created with a hostname")

		By("waiting for the torrc ConfigMap to appear")
		Eventually(getJSONPath("configmap/blog-torrc", "{.data.torrc}"), "30s", "2s").
			Should(ContainSubstring("HiddenServiceVersion 3"))

		By("waiting for the Deployment to appear")
		Eventually(getJSONPath("deployment/blog", "{.metadata.name}"), "30s", "2s").
			Should(Equal("blog"))

		By("waiting for the headless Service to appear")
		Eventually(getJSONPath("service/blog", "{.spec.clusterIP}"), "30s", "2s").
			Should(Equal("None"))

		By("checking OwnerReferences on each child")
		// Each child has its own deterministic name (the Secret is
		// <gw>-keys, the ConfigMap <gw>-torrc, the Deployment/Service
		// just <gw>); assert every one carries a Gateway ownerReference.
		children := map[string]string{
			"secret":     "blog-keys",
			"configmap":  "blog-torrc",
			"service":    "blog",
			"deployment": "blog",
		}
		for kind, name := range children {
			out, err := utils.Run(exec.Command("kubectl", "-n", testNamespace,
				"get", kind, name, "-o", "jsonpath={.metadata.ownerReferences[0].kind}"))
			Expect(err).NotTo(HaveOccurred(), "getting %s/%s", kind, name)
			Expect(strings.TrimSpace(string(out))).To(Equal("Gateway"),
				"%s/%s should be owned by Gateway", kind, name)
		}

		By("waiting for Gateway.status.addresses to publish a .onion")
		Eventually(getJSONPath("gateway/blog", "{.status.addresses[0].value}"), "30s", "2s").
			Should(MatchRegexp(`^[a-z2-7]{56}\.onion$`),
				"status.addresses[0].value should be a v3 .onion")

		By("Gateway.status conditions Accepted+Programmed should be True")
		Eventually(getJSONPath("gateway/blog",
			`{.status.conditions[?(@.type=="Accepted")].status}`), "30s", "2s").
			Should(Equal("True"))
		Eventually(getJSONPath("gateway/blog",
			`{.status.conditions[?(@.type=="Programmed")].status}`), "30s", "2s").
			Should(Equal("True"))
	})

	It("propagates TorServicePolicy into the rendered torrc", func() {
		By("applying a TorServicePolicy targeting the blog Gateway")
		applyYAML(fmt.Sprintf(`
apiVersion: policy.torgateway.io/v1alpha1
kind: TorServicePolicy
metadata:
  name: blog-tsp
  namespace: %s
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: blog
  logLevel: debug
  poWDefensesEnabled: false
`, testNamespace))

		By("torrc ConfigMap should reflect debug log level")
		Eventually(getJSONPath("configmap/blog-torrc", "{.data.torrc}"), "60s", "2s").
			Should(ContainSubstring("Log debug stdout"))

		By("TorServicePolicy status should report Accepted=True for the target")
		Eventually(getJSONPath("torservicepolicy/blog-tsp",
			`{.status.ancestors[0].conditions[?(@.type=="Accepted")].status}`), "30s", "2s").
			Should(Equal("True"))
	})

	It("attaches HTTPRoute and bumps the listener AttachedRoutes counter", func() {
		By("creating an HTTPRoute attached to the blog Gateway")
		applyYAML(fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: blog-route
  namespace: %s
spec:
  parentRefs:
  - name: blog
  rules:
  - matches:
    - path:
        value: /
    backendRefs:
    - name: nonexistent-backend
      port: 80
`, testNamespace))

		By("HTTPRoute status should show Accepted=True from our controller")
		Eventually(getJSONPath("httproute/blog-route",
			`{.status.parents[?(@.controllerName=="torgateway.io/gateway-controller")].conditions[?(@.type=="Accepted")].status}`),
			"30s", "2s").Should(Equal("True"))

		By("Gateway.status.listeners[onion].attachedRoutes should be 1")
		Eventually(getJSONPath("gateway/blog",
			`{.status.listeners[?(@.name=="onion")].attachedRoutes}`), "30s", "2s").
			Should(Equal("1"))
	})

	It("cascade-deletes children when the Gateway is deleted", func() {
		By("deleting the Gateway")
		_, err := utils.Run(exec.Command("kubectl", "-n", testNamespace, "delete", "gateway", "blog"))
		Expect(err).NotTo(HaveOccurred())

		By("children should disappear via OwnerReferences cascade")
		Eventually(func() bool {
			for _, ref := range []string{"secret/blog-keys", "configmap/blog-torrc", "deployment/blog", "service/blog"} {
				out, _ := utils.Run(exec.Command("kubectl", "-n", testNamespace, "get", ref, "--ignore-not-found"))
				if strings.TrimSpace(string(out)) != "" {
					return false
				}
			}
			return true
		}, 90*time.Second, 3*time.Second).Should(BeTrue(),
			"all owned children should be garbage-collected when the Gateway is deleted")
	})
})

// applyYAML pipes a YAML document into `kubectl apply -f -`.
func applyYAML(yaml string) {
	GinkgoHelper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	out, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "kubectl apply failed: %s", string(out))
}

// runOrSkipExisting runs a command and ignores AlreadyExists-style errors so
// tests are idempotent against a partially-set-up cluster.
func runOrSkipExisting(name string, args ...string) {
	GinkgoHelper()
	cmd := exec.Command(name, args...)
	out, err := utils.Run(cmd)
	if err != nil && !strings.Contains(string(out), "already exists") {
		Fail(fmt.Sprintf("%s %v failed: %v\n%s", name, args, err, string(out)))
	}
}

// getJSONPath returns a func() string suitable for Eventually that issues
// `kubectl get -n testNamespace <ref> -o jsonpath=<path>`.
func getJSONPath(ref, path string) func() string {
	return func() string {
		out, _ := utils.Run(exec.Command(
			"kubectl", "-n", testNamespace, "get", ref, "-o",
			"jsonpath="+path,
		))
		return strings.TrimSpace(string(out))
	}
}
