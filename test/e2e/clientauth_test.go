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
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/test/utils"
)

// x25519Pair returns (pubB32, privB32): RFC4648-base32, no padding (52 chars
// each), matching the operator's authorized-client validator and Tor's
// ClientOnionAuthDir private-key format.
func x25519Pair() (string, string) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	return b32.EncodeToString(priv.PublicKey().Bytes()), b32.EncodeToString(priv.Bytes())
}

var _ = Describe("Client auth (Strict) over Tor", Ordered, Label("clientauth"), func() {
	const (
		ns      = "clientauth-e2e"
		gwClass = "tor-gateway-clientauth-e2e"
	)
	var onion string

	fetchFrom := func(pod, path string) func() string {
		return func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", ns, "exec", pod, "-c", "curl", "--",
				"curl", "-s", "--max-time", "30", "--socks5-hostname", "127.0.0.1:9050", "http://"+onion+path))
			return strings.TrimSpace(out)
		}
	}

	// torClientPod renders a Tor SOCKS client. When authPrivate is non-empty the
	// pod is "authorized": an init container (running as 65532) writes the
	// .auth_private into an emptyDir subdir it owns, and tor points
	// ClientOnionAuthDir at it. This emptyDir-owned-by-65532 dance is required
	// because Tor refuses a ClientOnionAuthDir not owned by the tor uid, and
	// Secret/ConfigMap volume dirs are owned by root (fsGroup only sets group).
	torClientPod := func(name, authPrivate string) string {
		torArgs := `"--SocksPort", "127.0.0.1:9050", "--DataDirectory", "/var/lib/tor/data/data", "--Log", "notice stdout"`
		initSection, authMount, authVolume := "", "", ""
		if authPrivate != "" {
			torArgs += `, "--ClientOnionAuthDir", "/authdir/keys"`
			initSection = fmt.Sprintf(`  initContainers:
  - name: authinit
    image: busybox:1.36
    command: ["sh", "-c", "mkdir -p /authdir/keys && printf '%%s' '%s' > /authdir/keys/alice.auth_private && chmod 700 /authdir/keys && chmod 600 /authdir/keys/alice.auth_private"]
    securityContext: { runAsUser: 65532, runAsGroup: 65532 }
    volumeMounts: [{ name: authdir, mountPath: /authdir }]
`, authPrivate)
			authMount = `    - { name: authdir, mountPath: /authdir }`
			authVolume = `  - { name: authdir, emptyDir: {} }`
		}
		return fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata: { name: %[1]s, namespace: %[2]s }
spec:
  restartPolicy: Never
  securityContext: { fsGroup: 65532 }
%[3]s  containers:
  - name: tor
    image: ghcr.io/chimbosonic/tor:0.4.9
    imagePullPolicy: IfNotPresent
    args: [%[4]s]
    securityContext: { runAsUser: 65532, runAsGroup: 65532 }
    volumeMounts:
    - { name: data, mountPath: /var/lib/tor/data }
%[5]s
  - name: curl
    image: curlimages/curl:8.11.1
    command: ["sleep", "infinity"]
  volumes:
  - { name: data, emptyDir: {} }
%[6]s
`, name, ns, initSection, torArgs, authMount, authVolume)
	}

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

	It("admits the authorized client and refuses the unauthorized one", func() {
		pub, priv := x25519Pair()

		By("deploying backend + client-auth Secret + Strict policy + Gateway/HTTPRoute")
		applyYAML(fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata: { name: app, namespace: %[1]s }
spec:
  replicas: 1
  selector: { matchLabels: { app: app } }
  template:
    metadata: { labels: { app: app } }
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=hello", "-listen=:5678"]
        ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: app, namespace: %[1]s }
spec: { selector: { app: app }, ports: [{ port: 5678, targetPort: 5678 }] }
---
apiVersion: v1
kind: Secret
metadata: { name: clients, namespace: %[1]s }
stringData: { alice: "%[3]s" }
---
apiVersion: policy.torgateway.io/v1alpha1
kind: TorClientAuthPolicy
metadata: { name: auth, namespace: %[1]s }
spec:
  targetRefs: [{ group: gateway.networking.k8s.io, kind: Gateway, name: blog }]
  mode: Strict
  clientsSecretRef: { name: clients }
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
    backendRefs: [{ name: app, port: 5678 }]
`, ns, gwClass, pub))

		By("reading the published .onion")
		Eventually(func() string {
			out, _ := utils.Run(exec.Command("kubectl", "-n", ns, "get", "gateway", "blog",
				"-o", "jsonpath={.status.addresses[0].value}"))
			onion = strings.TrimSpace(out)
			return onion
		}, "60s", "2s").Should(MatchRegexp(`^[a-z2-7]{56}\.onion$`))

		By("deploying the authorized Tor client (init writes its key) and the unauthorized client")
		addr := strings.TrimSuffix(onion, ".onion")
		authPrivate := fmt.Sprintf("%s:descriptor:x25519:%s", addr, priv)
		applyYAML(torClientPod("tor-auth", authPrivate))
		applyYAML(torClientPod("tor-noauth", ""))

		By("waiting for both Tor client pods to be Ready")
		for _, pod := range []string{"tor-auth", "tor-noauth"} {
			_, _ = utils.Run(exec.Command("kubectl", "-n", ns, "wait", "--for=condition=Ready",
				"pod/"+pod, "--timeout=120s"))
		}

		By("authorized client reaches the service (proves circuit live AND auth passes)")
		Eventually(fetchFrom("tor-auth", "/"), "2m", "5s").Should(Equal("hello"))

		By("unauthorized client is refused (Strict enforced)")
		Consistently(fetchFrom("tor-noauth", "/"), "30s", "10s").ShouldNot(Equal("hello"))
	})
})
