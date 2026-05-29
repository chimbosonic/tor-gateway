# Feature E2E / Conformance Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add five real-cluster tests covering features that today have only unit/envtest coverage (where Jobs and Tor are faked): cross-namespace ReferenceGrant gating (status + data-plane), mkp224o vanity harvest, and v3 client auth.

**Architecture:** Test-only additions to the existing kind harnesses. e2e specs (`//go:build e2e`) shell out via `kubectl` (`applyYAML`, plus per-file namespace-scoped jsonpath closures) and fetch over a real circuit via an in-cluster Tor SOCKS client; the conformance test (`//go:build conformance`) uses the controller-runtime client. No production code changes (one test-helper scheme tweak).

**Tech Stack:** Go 1.26, Ginkgo (e2e), plain `testing` (conformance), kind, Gateway API v1.5.1 (ReferenceGrant served `v1beta1`), `crypto/ecdh` X25519 + RFC4648 base32 for client-auth keys.

**Verification reality:** These run only on kind (`make test-e2e`, `make test-conformance`), NOT in unit `make test`. `#3` and `#5` use a real Tor circuit and are slow (~8–10 min each). They verify already-shipped behavior, so the expected result is PASS, not red→green. Per-task steps compile-check with `go vet` (fast); the full kind run is the gate in Task 6.

**Conventions:** Apache header on new files (copy from `internal/controller/names.go`). Commit unsigned: `git -c commit.gpgsign=false commit`. No `Co-Authored-By` trailer. Reuse `buildAndLoadImage(makeTarget, imageRef)` and `applyYAML(yaml)` (both package-level in `test/e2e`). Each new e2e file uses its own namespace(s) + dedicated GatewayClass (created idempotently) and its own small jsonpath/fetch closures (`getJSONPath` is hardcoded to a different namespace; `fetchOverTor` is a local closure in `dataplane_test.go`).

---

## File Structure

**New:**
- `test/e2e/referencegrant_test.go` — #1, RG `ResolvedRefs` deny→allow (no Tor).
- `test/e2e/dataplane_crossns_test.go` — #3, cross-ns routing over real Tor (control + gated).
- `test/e2e/vanity_test.go` — #4, real vanity harvest → published `.onion` (no Tor).
- `test/e2e/clientauth_test.go` — #5, Strict client auth over real Tor (two clients).

**Modified:**
- `test/conformance/conformance_test.go` — #2, add `gwv1beta1` to `newClient`'s scheme + `TestRouteResolvedRefsContract` + a route-parent condition reader.

---

### Task 1: #1 — ReferenceGrant `ResolvedRefs` operator e2e (no Tor)

**Files:**
- Create: `test/e2e/referencegrant_test.go`

- [ ] **Step 1: Write the test**

Create `test/e2e/referencegrant_test.go` (Apache header, then):

```go
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
```

Why this is meaningful: before the ReferenceGrant feature, the route had no `ResolvedRefs` condition at all, so the first assertion would never see `RefNotPermitted`.

- [ ] **Step 2: Compile-check**

Run: `go vet -tags=e2e ./test/e2e/`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add test/e2e/referencegrant_test.go
git -c commit.gpgsign=false commit -m "test(e2e): ReferenceGrant ResolvedRefs deny->allow for cross-ns backendRef"
```

---

### Task 2: #2 — Conformance `ResolvedRefs` contract

**Files:**
- Modify: `test/conformance/conformance_test.go`

- [ ] **Step 1: Register `gwv1beta1` in the conformance client**

In `test/conformance/conformance_test.go`, add the import `gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"`. In `newClient`, after the existing `utilruntime.Must(gwv1.Install(scheme))`, add:

```go
	utilruntime.Must(gwv1beta1.Install(scheme))
```

- [ ] **Step 2: Add a route-parent condition reader + the test**

Append to `test/conformance/conformance_test.go`:

```go
// routeParentReason returns (reason, true) when the named condition on the
// route's parent (matched by our ControllerName) has Status=True, else
// (reason, false). Returns ("absent", false) when the condition is missing.
func routeParentReason(route *gwv1.HTTPRoute, condType string) (string, bool) {
	const controllerName = gwv1.GatewayController("torgateway.io/gateway-controller")
	for _, p := range route.Status.Parents {
		if p.ControllerName != controllerName {
			continue
		}
		for _, c := range p.Conditions {
			if c.Type == condType {
				return c.Reason, c.Status == metav1.ConditionTrue
			}
		}
	}
	return "absent", false
}

func TestRouteResolvedRefsContract(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	const (
		routeNS   = "tor-gateway-conformance-rg"
		backendNS = "tor-gateway-conformance-rg-backend"
		routeName = "rg-route"
	)
	for _, name := range []string{routeNS, backendNS} {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := c.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create namespace %s: %v", name, err)
		}
	}

	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "rg-gw", Namespace: routeNS},
		Spec: gwv1.GatewaySpec{
			GatewayClassName: gatewayClassName,
			Listeners:        []gwv1.Listener{{Name: "onion", Port: 80, Protocol: hiddenSvcProto}},
		},
	}
	if err := c.Create(ctx, gw); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create Gateway: %v", err)
	}

	port := gwv1.PortNumber(80)
	bns := gwv1.Namespace(backendNS)
	route := &gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: routeName, Namespace: routeNS},
		Spec: gwv1.HTTPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{ParentRefs: []gwv1.ParentReference{{Name: "rg-gw"}}},
			Rules: []gwv1.HTTPRouteRule{{
				BackendRefs: []gwv1.HTTPBackendRef{{BackendRef: gwv1.BackendRef{
					BackendObjectReference: gwv1.BackendObjectReference{Name: "app", Namespace: &bns, Port: &port},
				}}},
			}},
		},
	}
	if err := c.Create(ctx, route); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create HTTPRoute: %v", err)
	}

	waitCondition(t, func() (string, bool) {
		got := &gwv1.HTTPRoute{}
		if err := c.Get(ctx, client.ObjectKey{Name: routeName, Namespace: routeNS}, got); err != nil {
			return "get route: " + err.Error(), false
		}
		reason, ok := routeParentReason(got, string(gwv1.RouteConditionResolvedRefs))
		if ok || reason != "RefNotPermitted" {
			return "want ResolvedRefs=False/RefNotPermitted, got reason=" + reason, false
		}
		return "", true
	}, "ungated cross-ns backendRef should be RefNotPermitted")

	grant := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-routes", Namespace: backendNS},
		Spec: gwv1beta1.ReferenceGrantSpec{
			From: []gwv1beta1.ReferenceGrantFrom{{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: routeNS}},
			To:   []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Service"}},
		},
	}
	if err := c.Create(ctx, grant); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create ReferenceGrant: %v", err)
	}

	waitCondition(t, func() (string, bool) {
		got := &gwv1.HTTPRoute{}
		if err := c.Get(ctx, client.ObjectKey{Name: routeName, Namespace: routeNS}, got); err != nil {
			return "get route: " + err.Error(), false
		}
		reason, ok := routeParentReason(got, string(gwv1.RouteConditionResolvedRefs))
		if !ok || reason != "ResolvedRefs" {
			return "want ResolvedRefs=True, got reason=" + reason, false
		}
		return "", true
	}, "granted cross-ns backendRef should be ResolvedRefs")
}
```

If the file does not already import `apierrors "k8s.io/apimachinery/pkg/api/errors"`, `corev1 "k8s.io/api/core/v1"`, `"context"`, `metav1`, `client`, add them (the existing `TestGatewayStatusContract` uses all of these, so they should already be present).

- [ ] **Step 2b: Compile-check**

Run: `go vet -tags=conformance ./test/conformance/`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add test/conformance/conformance_test.go
git -c commit.gpgsign=false commit -m "test(conformance): assert ResolvedRefs contract for cross-ns backendRefs"
```

---

### Task 3: #3 — Cross-namespace routing over real Tor (control + gated)

**Files:**
- Create: `test/e2e/dataplane_crossns_test.go`

- [ ] **Step 1: Write the test**

Create `test/e2e/dataplane_crossns_test.go` (Apache header, then):

```go
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
		applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata: { name: tor-client, namespace: %[1]s }
spec:
  restartPolicy: Never
  securityContext: { fsGroup: 65532 }
  containers:
  - name: tor
    image: ghcr.io/chimbosonic/tor:0.4.9
    imagePullPolicy: IfNotPresent
    args: ["--SocksPort", "127.0.0.1:9050", "--DataDirectory", "/var/lib/tor/data/data", "--Log", "notice stdout"]
    securityContext: { runAsUser: 65532, runAsGroup: 65532 }
    volumeMounts: [{ name: data, mountPath: /var/lib/tor/data }]
  - name: curl
    image: curlimages/curl:8.11.1
    command: ["sleep", "infinity"]
  volumes: [{ name: data, emptyDir: {} }]
`, gwNS))

		By("control path /local routes (proves the circuit is live)")
		Eventually(fetchOverTor("/local"), "8m", "15s").Should(Equal("local"))

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
		Eventually(fetchOverTor("/remote"), "2m", "10s").Should(Equal("remote"))
	})
})
```

- [ ] **Step 2: Compile-check**

Run: `go vet -tags=e2e ./test/e2e/`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add test/e2e/dataplane_crossns_test.go
git -c commit.gpgsign=false commit -m "test(e2e): cross-ns routing over Tor gated by ReferenceGrant"
```

---

### Task 4: #4 — Vanity harvest e2e (real Job, no Tor)

**Files:**
- Create: `test/e2e/vanity_test.go`

- [ ] **Step 1: Write the test**

Create `test/e2e/vanity_test.go` (Apache header, then):

```go
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

	It("runs the mkp224o Job and publishes a vanity .onion with the requested prefix", func() {
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
  vanityPrefix: "a"
`, ns, gwClass))

		By("the per-Gateway vanity Job is created")
		Eventually(jpath("job/van-vanity", "{.metadata.name}"), "60s", "3s").Should(Equal("van-vanity"))

		By("the published .onion starts with the requested prefix")
		Eventually(jpath("gateway/van", "{.status.addresses[0].value}"), "3m", "5s").
			Should(MatchRegexp(`^a[a-z2-7]{55}\.onion$`))

		By("Gateway Programmed=True")
		Eventually(jpath("gateway/van", `{.status.conditions[?(@.type=="Programmed")].status}`), "60s", "3s").
			Should(Equal("True"))
	})
})
```

Why meaningful: a broken/SIGILL mkp224o image makes the Job crashloop, so the `.onion` never publishes and the second assertion times out — the regression guard we lacked at v0.2.0.

- [ ] **Step 2: Compile-check**

Run: `go vet -tags=e2e ./test/e2e/`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add test/e2e/vanity_test.go
git -c commit.gpgsign=false commit -m "test(e2e): vanity harvest runs the real Job and publishes a prefixed .onion"
```

---

### Task 5: #5 — Client auth over real Tor (two clients)

**Files:**
- Create: `test/e2e/clientauth_test.go`

- [ ] **Step 1: Write the test**

Create `test/e2e/clientauth_test.go` (Apache header, then):

```go
//go:build e2e

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

	torClientPod := func(name, extraTorArgs, authVolume, authMount string) string {
		return fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata: { name: %[1]s, namespace: %[2]s }
spec:
  restartPolicy: Never
  securityContext: { fsGroup: 65532 }
  containers:
  - name: tor
    image: ghcr.io/chimbosonic/tor:0.4.9
    imagePullPolicy: IfNotPresent
    args: ["--SocksPort", "127.0.0.1:9050", "--DataDirectory", "/var/lib/tor/data/data", "--Log", "notice stdout"%[3]s]
    securityContext: { runAsUser: 65532, runAsGroup: 65532 }
    volumeMounts:
    - { name: data, mountPath: /var/lib/tor/data }
%[4]s
  - name: curl
    image: curlimages/curl:8.11.1
    command: ["sleep", "infinity"]
  volumes:
  - { name: data, emptyDir: {} }
%[5]s
`, name, ns, extraTorArgs, authVolume, authMount)
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

		By("creating the client-auth private key ConfigMap (mode 0600) for the authorized client")
		addr := strings.TrimSuffix(onion, ".onion")
		applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata: { name: client-key, namespace: %[1]s }
data:
  alice.auth_private: "%[2]s:descriptor:x25519:%[3]s"
`, ns, addr, priv))

		By("deploying the authorized Tor client (ClientOnionAuthDir mounted) and the unauthorized client")
		authMount := `    - { name: authkeys, mountPath: /etc/tor-auth, readOnly: true }`
		authVolume := fmt.Sprintf(`  - name: authkeys
    configMap: { name: client-key, defaultMode: 0600 }`)
		applyYAML(torClientPod("tor-auth", `, "--ClientOnionAuthDir", "/etc/tor-auth"`, authMount, authVolume))
		applyYAML(torClientPod("tor-noauth", ``, ``, ``))

		By("authorized client reaches the service (proves circuit live AND auth passes)")
		Eventually(fetchFrom("tor-auth", "/"), "8m", "15s").Should(Equal("hello"))

		By("unauthorized client is refused (Strict enforced)")
		Consistently(fetchFrom("tor-noauth", "/"), "30s", "10s").ShouldNot(Equal("hello"))
	})
})
```

Notes for the implementer (real-Tor + client-auth finicky bits — tune during the kind run in Task 6, do not change the assertions):
- Tor refuses `ClientOnionAuthDir` files that are group/world readable; the ConfigMap volume uses `defaultMode: 0600` and the pod sets `fsGroup: 65532`/`runAsUser: 65532`. If Tor logs a permissions complaint, adjust the volume mode/ownership (not the test's assertions).
- The `.auth_private` filename must end in `.auth_private` (Tor requirement) — `alice.auth_private` satisfies this.
- The `TorClientAuthPolicy` field names (`mode`, `clientsSecretRef.name`) and the Secret entry shape (`<label>: <52-char base32 pubkey>`) come from `api/v1alpha1/torclientauthpolicy_types.go` and `internal/tor/clientauth.go`. Verify them while writing; adapt the YAML if the json tags differ.

- [ ] **Step 2: Compile-check**

Run: `go vet -tags=e2e ./test/e2e/`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add test/e2e/clientauth_test.go
git -c commit.gpgsign=false commit -m "test(e2e): Strict client auth over Tor (authorized admitted, unauthorized refused)"
```

---

### Task 6: Verification gate

**Files:** none (verification only)

- [ ] **Step 1: Unit gate unaffected**

Run: `make test && make lint`
Expected: PASS / `0 issues` (these additions are e2e/conformance-tagged + a conformance test-helper tweak; the default unit build excludes them).

- [ ] **Step 2: Compile all tagged builds**

Run: `go vet -tags=e2e ./test/e2e/ && go vet -tags=conformance ./test/conformance/`
Expected: no errors.

- [ ] **Step 3: Conformance run on kind**

Run: `make test-conformance`
Expected: PASS, including `TestRouteResolvedRefsContract`.

- [ ] **Step 4: e2e run on kind (slow — includes two real-Tor specs)**

Run: `make test-e2e`
Expected: PASS, including the four new specs (`referencegrant`, `dataplane-crossns`, `vanity`, `clientauth`). The Tor specs (`dataplane-crossns`, `clientauth`) each take several minutes for HS descriptor publish/lookup. If a real-Tor spec fails on timing or client-auth file permissions, tune the timeouts / volume mode (NOT the assertions) and re-run; if the controller/router behavior itself is wrong, escalate (it shouldn't be — the feature is already shipped).

- [ ] **Step 5: Final commit (only if anything changed)**

```bash
git add -A
git -c commit.gpgsign=false commit -m "test: tune e2e timings for ReferenceGrant/vanity/client-auth coverage" || echo "nothing to commit"
```

---

## Notes for the implementer

- **No production code changes** beyond the conformance `newClient` scheme registration (test helper). If a test reveals a real product bug, stop and escalate rather than editing production code under a test plan.
- **Isolation:** every spec uses its own namespace(s) and a dedicated GatewayClass (created idempotently, deleted in AfterAll) — do not reuse `tor-gateway-e2e`/`testGwClass` from `gateway_test.go`.
- **Helper reuse:** `applyYAML` and `buildAndLoadImage` are package-level in `test/e2e`; reuse them directly. Do NOT reuse `getJSONPath` (hardcoded to `gateway_test.go`'s namespace) — each new file has its own `jpath`/`fetchOverTor` closure.
- **Real-Tor cost:** `#3` and `#5` dominate runtime. They use the in-cluster Tor SOCKS client pattern from `dataplane_test.go`; the 8-minute Eventually for the first fetch matches the existing data-plane spec's descriptor-publish budget.
```
