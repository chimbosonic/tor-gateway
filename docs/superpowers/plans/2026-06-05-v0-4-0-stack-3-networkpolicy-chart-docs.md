# v0.4.0 — Stack 3: NetworkPolicy + chart + docs + e2e

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close out the v0.4.0 release by fixing NetworkPolicy coverage for Mode B, correcting the chart's image references, narrowing the chutney testing-mode egress, refreshing SECURITY.md / README / PLAN.md to match the new architecture, and adding end-to-end test coverage for the Stack 1 + Stack 2 invariants.

**Architecture:** Independent commits on a single feature branch. Depends on Stack 1 + Stack 2 being merged (the docs describe Stack 1's behavior; the e2e tests exercise both stacks). Each task is TDD where applicable — for non-code changes (chart, docs) the verification is by-inspection or by `helm template` rendering.

**Tech Stack:** Go, controller-runtime, Helm, kubebuilder, Ginkgo+Gomega e2e, kind, chutney.

**Tickets covered:** B1, B2, M7, M8, L6, L10, plus SECURITY.md realignment for H2 (PoW silent disable signal in Mode B default case) and the HALabels managed-by fix that underpins B2. Also adds H10-adjacent E2E coverage for the master-fetch + per-pod isolation introduced in Stack 1.

**Spec:** `docs/superpowers/specs/2026-06-05-v0-4-0-release-fixes-design.md` (Stack 3 section).

**Branching:** create `feat/v0.4.0-stack-3-network-chart-docs` off `main` (which already has Stack 1 + Stack 2 merged).

---

### Task 0: Branch setup

- [ ] **Step 1: Create branch**

```bash
git -C /Volumes/source-code/Personal/torGateway checkout main
git -C /Volumes/source-code/Personal/torGateway pull --ff-only origin main 2>&1 || true
git -C /Volumes/source-code/Personal/torGateway checkout -b feat/v0.4.0-stack-3-network-chart-docs
```

---

### Task 1: HALabels add `managed-by` (so NP selector matches Mode B pods)

**Why:** The per-Gateway NetworkPolicy's PodSelector is built from `ChildLabels(gw.Name)` which requires `app.kubernetes.io/managed-by: tor-gateway`. `HALabels` omits that label, so Mode B pods never match the NP even when the NP exists.

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`HALabels` ~line 43)
- Test: `internal/controller/gateway_resources_ha_test.go`, `internal/controller/network_policy_test.go`

- [ ] **Step 1: Failing test**

```go
func TestHALabels_IncludesManagedBy(t *testing.T) {
    gw := sampleGateway()
    got := HALabels(gw, "backend")
    if got["app.kubernetes.io/managed-by"] != "tor-gateway" {
        t.Errorf("HALabels missing app.kubernetes.io/managed-by=tor-gateway; got %v", got)
    }
}

func TestNetworkPolicySelectorMatchesModeBPodLabels(t *testing.T) {
    gw := sampleGateway()
    np := BuildNetworkPolicy(gw, ...) // adapt to actual signature
    sel, _ := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
    backendLabels := HALabels(gw, "backend")
    if !sel.Matches(labels.Set(backendLabels)) {
        t.Errorf("Mode B backend pod labels %v not matched by NP selector %v", backendLabels, sel)
    }
    frontendLabels := HALabels(gw, "frontend")
    if !sel.Matches(labels.Set(frontendLabels)) {
        t.Errorf("Mode B frontend pod labels %v not matched by NP selector %v", frontendLabels, sel)
    }
}
```

- [ ] **Step 2-3: Implement**

```go
func HALabels(gw *gwv1.Gateway, role string) map[string]string {
    return map[string]string{
        "app.kubernetes.io/managed-by": "tor-gateway",
        "app.kubernetes.io/name":       "tor-gateway",
        "app.kubernetes.io/instance":   gw.Name,
        gatewayLabelKey:                gw.Name,
        haRoleKey:                      role,
    }
}
```

- [ ] **Step 4: Commit**

```bash
git add internal/controller/gateway_resources_ha.go internal/controller/gateway_resources_ha_test.go internal/controller/network_policy_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): HALabels carries app.kubernetes.io/managed-by"
```

---

### Task 2: B2 — `ensureModeB` reconciles a NetworkPolicy

**Why:** `ensureModeB` never calls `ensureNetworkPolicy`. A Gateway born straight into Mode B (OBP applied first) gets no NP at all.

**Files:**
- Modify: `internal/controller/gateway_controller.go` (`ensureModeB`)
- Test: `internal/controller/gateway_controller_modeb_test.go`

- [ ] **Step 1: Failing test**

```go
func TestEnsureModeB_ReconcilesNetworkPolicy(t *testing.T) {
    ctx := context.Background()
    gw := sampleGateway()
    obp := samplePolicy(2)
    cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw, obp).Build()
    r := &GatewayReconciler{Client: cl, Scheme: testScheme(t), TorRuntime: testRuntimeImages(), TorPodNetworkPolicyEnabled: true}
    _ = r.ensureModeB(ctx, gw, obp)
    var np networkingv1.NetworkPolicy
    if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: NetworkPolicyName(gw.Name)}, &np); err != nil {
        t.Fatalf("NetworkPolicy not created: %v", err)
    }
}
```

- [ ] **Step 2-3: Implement**

Add a call to `r.ensureNetworkPolicy(ctx, gw)` (or the equivalent existing entry point) in `ensureModeB`, after the HA resources are reconciled. Gate it on `r.TorPodNetworkPolicyEnabled` to match the Mode A behavior.

- [ ] **Step 4: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): ensureModeB reconciles a NetworkPolicy"
```

---

### Task 3: M8 — Narrow testing-mode egress to specific chutney pods + ports

**Why:** The chutney-mode egress rule today allows any pod in the chutney namespace on any port. Should target chutney's directory authorities (and OR ports) via PodSelector + Ports.

**Files:**
- Modify: `internal/controller/network_policy.go` (testing-mode egress branch)
- Test: `internal/controller/network_policy_test.go`

- [ ] **Step 1: Identify chutney pod labels + ports**

Read `test/e2e/chutney_test.go` setup and `images/chutney/`. The chutney pod has `app: chutney` (or similar) and exposes ports 5000-5010 for DirAuth + OR.

- [ ] **Step 2: Failing test**

```go
func TestTestingModeEgress_IsScopedToChutneyPodsAndPorts(t *testing.T) {
    r := &Reconciler{TestingNetworkPodNamespace: "tor-gateway-chutney"}
    np := r.buildNetworkPolicy(sampleGateway(), httpRouteBackends())
    var sawChutney bool
    for _, e := range np.Spec.Egress {
        for _, peer := range e.To {
            if peer.NamespaceSelector != nil && peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "tor-gateway-chutney" {
                sawChutney = true
                if peer.PodSelector == nil || len(peer.PodSelector.MatchLabels) == 0 {
                    t.Error("chutney egress peer must restrict by PodSelector, not bare namespace")
                }
                if len(e.Ports) == 0 {
                    t.Error("chutney egress must enumerate ports")
                }
            }
        }
    }
    if !sawChutney {
        t.Fatal("expected a chutney egress rule")
    }
}
```

- [ ] **Step 3-4: Implement**

```go
{
    To: []networkingv1.NetworkPolicyPeer{{
        NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": r.TestingNetworkPodNamespace}},
        PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "chutney"}},
    }},
    Ports: []networkingv1.NetworkPolicyPort{
        {Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt(5000))},
        // ... 5001..5010 or whatever chutney exposes
    },
},
```

(Read the chutney Pod spec to enumerate ports correctly; if there's a known range, use a single rule with `Port`/`EndPort` instead of N rules.)

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): narrow testing-mode egress to chutney pods + ports"
```

---

### Task 4: Strengthen NP selector test (build a real Mode B pod template)

**Files:**
- Modify: `internal/controller/network_policy_test.go`

- [ ] **Step 1: Refactor `TestNetworkPolicySelectsBothModeBPodSets`**

Instead of asserting just label keys on the selector, BUILD a real Mode B pod template via the builders and run the NP's PodSelector against the rendered labels:

```go
func TestNetworkPolicyMatchesRenderedModeBPods(t *testing.T) {
    gw := sampleGateway()
    obp := samplePolicy(2)
    np := r.buildNetworkPolicy(gw, nil)
    sel, _ := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)

    backend, _ := BuildBackendStatefulSet(gw, obp, ...)
    frontend, _ := BuildFrontendDeployment(gw, obp, ...)
    if !sel.Matches(labels.Set(backend.Spec.Template.Labels)) {
        t.Errorf("NP selector does not match backend pod labels")
    }
    if !sel.Matches(labels.Set(frontend.Spec.Template.Labels)) {
        t.Errorf("NP selector does not match frontend pod labels")
    }
}
```

- [ ] **Step 2: Verify the test passes (it should, given Task 1's HALabels fix)** then commit.

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "test(controller): NP selector test exercises rendered Mode B pod labels"
```

---

### Task 5: B1 — Chart `onionbalanceImage` repo + tag fix

**Why:** `charts/tor-gateway/values.yaml:83` points `onionbalanceImage.repository` at `ghcr.io/chimbosonic/onionbalance` but the release workflow pushes `ghcr.io/chimbosonic/tor-gateway-onionbalance`. The `tag: "0.2-latest"` is a floating tag that contradicts the chart's "pinned by appVersion" pattern.

**Files:**
- Modify: `charts/tor-gateway/values.yaml`
- Test: by `helm template` and by reading

- [ ] **Step 1: Fix the values**

```yaml
onionbalanceImage:
  repository: ghcr.io/chimbosonic/tor-gateway-onionbalance
  tag: ""
  pullPolicy: IfNotPresent
```

- [ ] **Step 2: Render**

```bash
helm template charts/tor-gateway --set onionbalanceImage.tag=test > /tmp/r.yaml
grep -n 'image:.*onionbalance' /tmp/r.yaml
```

Confirm the rendered image string is `ghcr.io/chimbosonic/tor-gateway-onionbalance:<chart appVersion>` when `tag` is empty, and overridable.

- [ ] **Step 3: Commit**

```bash
git add charts/tor-gateway/values.yaml
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(chart): onionbalanceImage repo + tag align with release workflow"
```

---

### Task 6: M7 — Chart cross-check `testingTorNetwork.enabled` requires `podNamespace`

**Files:**
- Modify: `charts/tor-gateway/templates/deployment.yaml`

- [ ] **Step 1: Add Helm `required`**

In the manager Deployment's args block:

```yaml
{{- if .Values.testingTorNetwork.enabled }}
{{- $ns := required "testingTorNetwork.podNamespace is required when testingTorNetwork.enabled=true" .Values.testingTorNetwork.podNamespace }}
{{- $cm := required "testingTorNetwork.configMapName is required when testingTorNetwork.enabled=true" .Values.testingTorNetwork.configMapName }}
- --testing-tor-network-file=/etc/tor-gateway/testing-network/fragment
- --testing-tor-network-namespace={{ $ns }}
{{- end }}
```

- [ ] **Step 2: Render in both modes**

```bash
helm template charts/tor-gateway > /tmp/off.yaml  # off by default — should render fine
helm template charts/tor-gateway --set testingTorNetwork.enabled=true 2>&1 | grep -i required
# expect: error: execution error at ...: testingTorNetwork.podNamespace is required
helm template charts/tor-gateway --set testingTorNetwork.enabled=true --set testingTorNetwork.podNamespace=foo --set testingTorNetwork.configMapName=cm 2>&1 | grep -c testing-tor-network-namespace
# expect: 1
```

- [ ] **Step 3: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(chart): testingTorNetwork.enabled requires podNamespace + configMapName"
```

---

### Task 7: L6 — Pin base images by digest

**Files:**
- Modify: `images/onionbalance/Dockerfile`, `images/chutney/Dockerfile`
- Optionally: SECURITY.md note on pin discipline

- [ ] **Step 1: Find current digests**

```bash
docker pull python:3.12-slim
docker inspect python:3.12-slim --format='{{index .RepoDigests 0}}'
docker pull debian:bookworm-slim
docker inspect debian:bookworm-slim --format='{{index .RepoDigests 0}}'
```

Capture the `@sha256:...` strings.

- [ ] **Step 2: Update Dockerfiles**

```Dockerfile
FROM python:3.12-slim@sha256:<digest> AS base
```

- [ ] **Step 3: Build both images locally to confirm pull-by-digest still works**

```bash
make image-onionbalance
make image-chutney
```

- [ ] **Step 4: Commit**

```bash
git add images/
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "build(images): pin onionbalance + chutney base images by sha256"
```

---

### Task 8: SECURITY.md realignment for v0.4.0 Mode B

**Files:**
- Modify: `SECURITY.md`

- [ ] **Step 1: Rewrite the Mode B section**

Sections to cover:

1. **Backend-key isolation:**
   - Each backend pod's runtime tor container has NO Secret mount; its onion key arrives via an init-container API GET into an emptyDir.
   - The init container's SA has `secrets:get` scoped to `resourceNames` enumerating ALL backend Secret names for the Gateway (RBAC limitation: per-replica resourceName scoping requires per-replica SAs, which StatefulSet doesn't template). So a compromised init container can fetch any of THIS Gateway's backend keys via the Kubernetes API — but cannot reach other Gateways' keys or the master key.
   - A node-local attacker sees only the in-pod emptyDir contents (its own pod's keys).

2. **Frontend SA scope:**
   - `secrets:get` is `resourceNames`-scoped to the master Secret + the N backend Secrets.
   - `secrets:list/watch` stays namespace-wide (RBAC limitation), narrowed in code by an informer LabelSelector that requires `torgateway.io/owner-uid=<gw.UID>`. Tenant-planted Secrets that don't carry the operator-set owner UID label are skipped.
   - **Recommended deployment shape:** one Gateway per namespace for the strongest isolation. (RBAC `list/watch` cannot be label-scoped at the apiserver level.)

3. **Cross-namespace `MasterKeySecretRef`:**
   - Works as advertised. `ReferenceGrant` is the authoritative gate, re-validated on every reconcile. The operator emits a per-Gateway `Role` + `RoleBinding` in the source namespace that grants the frontend SA `get` on EXACTLY the named master Secret. Old bindings are GC'd on namespace change.

4. **PoW in Mode B:**
   - Onionbalance instances cannot run PoW themselves (Tor protocol limitation: the protocol layer for PoW lives at the backend Tor, not the directory-publishing layer).
   - When PoW would otherwise be enabled (default-policy OR explicit TorServicePolicy with `powDefenses.enabled=true`), the operator emits a `PoWForcedOffInHA` Event and annotates the Gateway with `torgateway.io/pow-override-emitted`. **The OBP Accepted condition's message includes a `PoW forced off` warning so the user has CLI-visible signal.** (This is H2 — the default-policy path was previously silent.)

5. **Testing mode (chutney):**
   - The `--testing-tor-network-file` flag is operator-level only and never exposed to API tenants.
   - When set, Tor pods load a chutney directory authority fragment and route exclusively over the in-cluster private network. The per-Gateway NetworkPolicy's egress is narrowed to chutney pods + DirAuth/OR ports — no broader namespace egress.
   - `testingTorNetwork.enabled` in the chart is off by default and `helm template` errors at render-time if it's flipped on without also providing `podNamespace` + `configMapName`. This prevents accidental production enablement.

- [ ] **Step 2: Commit**

```bash
git add SECURITY.md
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "docs(security): realign SECURITY.md with v0.4.0 Mode B architecture"
```

---

### Task 9: README.md + PLAN.md updates

**Files:**
- Modify: `README.md`
- Modify: `docs/PLAN.md`

- [ ] **Step 1: README**

Update the Mode B section: stays experimental in v0.4.0, requires chart appVersion ≥ 0.4.0 because earlier installs reference the wrong onionbalance image repo.

Update the current-release line if you want — note that per CLAUDE.md the user does the post-tag README/PLAN.md bumps themselves, so just confirm the format matches the recent pattern (commits `e1213be`, `4baedce`, `97c750a`).

- [ ] **Step 2: PLAN.md**

Append a paragraph: "v0.4.0 (in progress): pre-release review fixes covering Mode B correctness, NetworkPolicy coverage, RBAC narrowing, chart configuration. Mode B remains experimental; graduation targeted for v0.5."

- [ ] **Step 3: Commit**

```bash
git add README.md docs/PLAN.md
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "docs: README + PLAN.md updates for v0.4.0"
```

---

### Task 10: E2E — Mode B per-pod key isolation

**Files:**
- Modify: `test/e2e/onionbalance_test.go`

- [ ] **Step 1: New spec**

```go
It("isolates per-pod keys: a backend's tor container only sees its own onion key", Label("onionbalance"), func() {
    // Apply the Mode B fixture (already standing for this Ordered suite).
    // For each backend pod 0..N-1, exec into the tor container and assert
    // /var/lib/tor/hs/hs/hs_ed25519_secret_key matches THAT pod's Secret,
    // and that no other pod's key is reachable.
    for i := 0; i < replicas; i++ {
        podName := fmt.Sprintf("ha-gw-backend-%d", i)
        out, _, err := utils.Run("kubectl", "-n", ns, "exec", podName, "-c", "tor", "--", "sh", "-c",
            `sha256sum /var/lib/tor/hs/hs/hs_ed25519_secret_key | awk '{print $1}'`)
        Expect(err).NotTo(HaveOccurred())
        secretHashOnDisk := strings.TrimSpace(out)

        // Fetch the corresponding Secret's bytes and hash them.
        b64, _, err := utils.Run("kubectl", "-n", ns, "get", "secret", fmt.Sprintf("ha-gw-backend-%d-keys", i),
            "-o", "jsonpath={.data.hs_ed25519_secret_key}")
        Expect(err).NotTo(HaveOccurred())
        decoded, err := base64.StdEncoding.DecodeString(b64)
        Expect(err).NotTo(HaveOccurred())
        wantHash := sha256.Sum256(decoded)
        Expect(secretHashOnDisk).To(Equal(hex.EncodeToString(wantHash[:])))

        // Negative: the OTHER pods' keys must not be reachable inside this pod.
        for j := 0; j < replicas; j++ {
            if j == i {
                continue
            }
            // The init container's emptyDir is shared with tor; assert there's
            // only one keypair on disk (no /var/lib/tor-keys/* enumeration).
            _, _, err := utils.Run("kubectl", "-n", ns, "exec", podName, "-c", "tor", "--", "test", "!", "-e",
                fmt.Sprintf("/var/lib/tor-keys/%d", j))
            Expect(err).To(HaveOccurred(), "pod %s should not have access to backend-%d's keys", podName, j)
        }
    }
})
```

- [ ] **Step 2: Commit**

```bash
git add test/e2e/onionbalance_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "test(e2e): assert Mode B per-pod backend-key isolation"
```

---

### Task 11: E2E — Mode B SIGHUP reload on scale-up

**Files:**
- Modify: `test/e2e/onionbalance_test.go`

- [ ] **Step 1: New spec**

```go
It("reloads onionbalance via SIGHUP when backends scale up", Label("onionbalance"), func() {
    // Start at replicas=3 (current Ordered suite default), then patch OBP to 4.
    Expect(utils.Run("kubectl", "-n", ns, "patch", "onionbalancepolicy", "ha-obp", "--type=merge",
        "-p", `{"spec":{"replicas":4}}`)).Error().NotTo(HaveOccurred())

    // Wait for backend-3 to be Running (defensive: it's the StatefulSet's job).
    Eventually(func() string {
        out, _, _ := utils.Run("kubectl", "-n", ns, "get", "pod", "ha-gw-backend-3", "-o", "jsonpath={.status.phase}")
        return out
    }, 5*time.Minute, 5*time.Second).Should(Equal("Running"))

    // Within 2× RefreshInterval, onionbalance should log a SIGHUP reload.
    // The simplest assertion: the published superdescriptor lists 4 intro
    // points for the master onion. Cleanest: query via the tor-client pod.
    Eventually(func() int {
        // hit the master .onion and count intro points (use the helper from
        // test/e2e/tor_client_test.go's tor-client pod).
        return countIntroPoints(ctx, masterOnion)
    }, 5*time.Minute, 10*time.Second).Should(Equal(4))
})
```

- [ ] **Step 2: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "test(e2e): assert SIGHUP-driven reload picks up scaled-up backends"
```

---

### Task 12: E2E — Cross-NS master Secret

**Files:**
- Modify: `test/e2e/onionbalance_test.go`

- [ ] **Step 1: New spec**

```go
It("supports a master Secret in a different namespace via ReferenceGrant", Label("onionbalance", "crossns"), func() {
    sourceNS := "ha-master-secrets"
    Expect(utils.Run("kubectl", "create", "ns", sourceNS)).Error().NotTo(HaveOccurred())
    defer utils.Run("kubectl", "delete", "ns", sourceNS, "--wait=false")

    // Generate a master keypair, create Secret in sourceNS.
    sk, pk, hostname := generateMasterKeypair()
    applyMasterSecret(sourceNS, "ob-master", sk, pk)

    // Create a ReferenceGrant in sourceNS that allows OBPs in our Gateway namespace to read Secrets.
    applyReferenceGrant(sourceNS, gwNS, "Secret")

    // Create the Gateway + OBP referencing ob-master in sourceNS.
    applyCrossNSGateway(gwNS, "blog-cross", "ob-master", sourceNS)

    // Assert: the frontend Deployment becomes Available, status.addresses
    // includes the expected hostname.
    Eventually(func() string {
        out, _, _ := utils.Run("kubectl", "-n", gwNS, "get", "gateway", "blog-cross", "-o", "jsonpath={.status.addresses[0].value}")
        return out
    }, 5*time.Minute, 5*time.Second).Should(Equal(hostname))

    // Confirm the cross-NS RoleBinding exists in sourceNS.
    out, _, err := utils.Run("kubectl", "-n", sourceNS, "get", "rolebinding", "blog-cross-frontend-master-fetch")
    Expect(err).NotTo(HaveOccurred(), out)
})
```

- [ ] **Step 2: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "test(e2e): cross-NS MasterKeySecretRef with ReferenceGrant"
```

---

### Task 13: E2E — Mode B pods are covered by per-Gateway NetworkPolicy

**Files:**
- Modify: `test/e2e/networkpolicy_test.go`

- [ ] **Step 1: New spec**

```go
It("covers Mode B frontend and backend pods with the per-Gateway NetworkPolicy", Label("networkpolicy", "onionbalance"), func() {
    // Use the OB fixture from onionbalance_test.go (Ordered).
    // After Mode B is up:
    np := getNetworkPolicy(gwNS, "ha-gw-tor-egress")
    sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
    Expect(err).NotTo(HaveOccurred())

    // List all Mode B pods (frontend Deployment + backend StatefulSet) and assert each matches.
    pods := listPods(gwNS, map[string]string{"torgateway.io/gateway": "ha-gw"})
    Expect(pods).NotTo(BeEmpty())
    for _, p := range pods {
        Expect(sel.Matches(labels.Set(p.Labels))).To(BeTrue(),
            "NP selector should match Mode B pod %s with labels %v", p.Name, p.Labels)
    }
})
```

- [ ] **Step 2: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "test(e2e): per-Gateway NP selector covers Mode B pods"
```

---

### Task 14: L10 — Chutney pod restartPolicy + liveness

**Why:** The chutney pod uses `restartPolicy: Never`. If chutney's tor processes crash mid-suite (OOM under kind memory pressure, etc.), the pod is stuck and every subsequent spec hangs waiting on Ready until its budget expires.

**Files:**
- Modify: `test/e2e/chutney_test.go` (the Pod spec applied in `DeployChutney`)

- [ ] **Step 1: Change restartPolicy + add liveness**

```yaml
spec:
  restartPolicy: OnFailure
  containers:
  - name: chutney
    # ...
    livenessProbe:
      exec:
        command: ["sh", "-c", "./chutney status > /tmp/last-check 2>&1 && grep -q 'Done' /tmp/last-check"]
      initialDelaySeconds: 60
      periodSeconds: 60
      failureThreshold: 5
```

(Verify the chutney command syntax; adapt as needed.)

- [ ] **Step 2: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "test(e2e): chutney pod restartPolicy=OnFailure + liveness probe"
```

---

### Task 15: Final integration sanity (full e2e)

- [ ] **Step 1: Run `make test`** to confirm all unit tests pass.

- [ ] **Step 2: Run `make test-e2e`** (chutney mode). All specs should pass, including the new Mode B isolation/SIGHUP/cross-NS/NP coverage tests.

If the vanity test flakes (as noted in Stack 1 validation), retry once. If it consistently fails on this machine, note it and move on — it's pre-existing and not in Stack 3's scope.

- [ ] **Step 3: Verify `make generate && make manifests && make chart-sync` produce no diff**

- [ ] **Step 4: Branch summary**

`git log --oneline main..HEAD` — roughly 13-14 commits.

- [ ] **Step 5: Report**

```
Stack 3 complete on branch feat/v0.4.0-stack-3-network-chart-docs.

Tickets: B1, B2, M7, M8, L6, L10 + HALabels managed-by + SECURITY.md realign + 4 new e2e specs.
Stack 2 + Stack 3 + Stack 1 = v0.4.0 fix scope COMPLETE.

Ready for git rebase --signoff origin/main + push + PR + tag v0.4.0.
```

---

## Self-review notes

**Spec coverage (Stack 3 portion):**
- B1 chart image repo + tag → Task 5 ✓
- B2 ensureModeB NetworkPolicy → Task 2 ✓
- HALabels managed-by → Task 1 ✓ (gates Task 2 and Task 4)
- M7 testingTorNetwork required cross-check → Task 6 ✓
- M8 testing-mode egress narrowing → Task 3 ✓
- L6 base image digest pinning → Task 7 ✓
- L10 chutney pod restartPolicy → Task 14 ✓
- SECURITY.md realign → Task 8 ✓ (also addresses H2's documentation gap)
- README.md + PLAN.md → Task 9 ✓
- E2E coverage for Stack 1 invariants → Tasks 10, 11, 12, 13 ✓

**Cross-stack dependencies:**
- Task 1 (HALabels) must land BEFORE Task 2 (ensureModeB NP) and Task 4 (selector test), because they assert against the labeled pods.
- Task 8 (SECURITY.md) describes Stack 1's API-fetch behavior; safe to land after Stack 1.
- Task 11's "SIGHUP reload" test exercises Stack 2's `shareProcessNamespace` fix (B3) — depends on Stack 2 being merged.
- Task 14 (chutney liveness) is independent.

**Test discipline:** every controller/chart change has a unit-or-integration test. The four new e2e specs assert end-to-end behaviors that unit tests can't reach (kubelet mounts, kernel NetworkPolicy enforcement, actual SIGHUP delivery).

**Acknowledged compromises:**
- Task 3's port enumeration assumes chutney's port layout; implementer must read `images/chutney/networks/k8s-mini/network` to confirm exact ports.
- Task 11's `countIntroPoints` helper isn't shown in detail — it lives in `test/e2e/tor_client_test.go` already (used by other onionbalance specs).
- Task 14's liveness probe command (`./chutney status`) may need adjustment per chutney's actual CLI.
