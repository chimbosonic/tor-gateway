# Stable E2E Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop Mode B chutney flakes from cascade-skipping unrelated Mode A specs and turn "E2E Tests failed" into precise per-suite failures with first-class diagnostic artifacts.

**Architecture:** (1) Replace the single `test-e2e.yml` job with a 3-row `strategy.matrix` that fans out to independent kind clusters, each scoped by a ginkgo `--label-filter`. (2) Split the 7-spec `OnionBalance HA (Mode B)` `Describe(..., Ordered, ...)` block in `test/e2e/onionbalance_test.go` into 3 sibling `Describe` blocks, each with its own `BeforeAll`/`AfterAll`, so a flake in one block cannot cascade-skip the others. (3) Add a `make test-e2e-suite` target driven by `$E2E_LABEL_FILTER`. (4) Upload per-suite diagnostic artifacts on failure + emit a ginkgo step summary on every run.

**Tech Stack:** GitHub Actions matrix, Ginkgo v2 labels/Ordered specs, Go test, kind, chutney, Makefile.

**Spec:** `docs/superpowers/specs/2026-06-08-stable-e2e-pipeline-design.md`

**Branching:** create `feat/stable-e2e-pipeline` off `main`. Each task is its own commit. Land via PR or local merge after `git rebase --signoff origin/main`.

---

### Task 0: Branch setup

- [ ] **Step 1: Create branch**

```bash
git -C /Volumes/source-code/Personal/torGateway checkout main
git -C /Volumes/source-code/Personal/torGateway pull --ff-only origin main 2>&1 || true
git -C /Volumes/source-code/Personal/torGateway checkout -b feat/stable-e2e-pipeline
```

---

### Task 1: Add `ob-failover` and `ob-crossns` labels to mutator + cross-NS Mode B specs

**Why:** The matrix label filter in Task 4 keys on these labels to route Mode B specs into the right matrix row. Today the 3 mutator specs (pod kill, scale-down, scale-up SIGHUP) only carry the generic `onionbalance` label, and the cross-NS spec carries `crossns` (which collides with the existing `dataplane-crossns` label). We need precise, namespaced labels.

**Files:**
- Modify: `test/e2e/onionbalance_test.go`

- [ ] **Step 1: Find the spec headers**

Run:

```bash
grep -nE "It\(.*backend pod is killed|It\(.*scaling replicas from 3 to 1|It\(.*reloads onionbalance|It\(.*master Secret in a different namespace" test/e2e/onionbalance_test.go
```

Expected: four matches. Note the line numbers.

- [ ] **Step 2: Add `ob-failover` to the three mutator specs**

Each currently looks like `It("...", Label("onionbalance"), func() { ... })` (or no `Label` at all — they inherit from the surrounding `Describe`). Change each to:

```go
It("remains reachable after a backend pod is killed", Label("onionbalance", "ob-failover"), func() {
    // ... existing body ...
})

It("remains reachable after scaling replicas from 3 to 1", Label("onionbalance", "ob-failover"), func() {
    // ... existing body ...
})

It("reloads onionbalance via SIGHUP when backends scale up", Label("onionbalance", "ob-failover"), func() {
    // ... existing body ...
})
```

(If a spec already has `Label("onionbalance")`, replace the call with `Label("onionbalance", "ob-failover")`. If it has no `Label`, add `Label("onionbalance", "ob-failover")` between the description string and the `func()` argument.)

- [ ] **Step 3: Add `ob-crossns` to the cross-NS spec**

The cross-NS spec currently has `Label("onionbalance", "crossns")`. Replace with:

```go
It("supports a master Secret in a different namespace via ReferenceGrant", Label("onionbalance", "ob-crossns"), func() {
    // ... existing body ...
})
```

Drop the bare `crossns` label — `ob-crossns` is the namespaced replacement; nothing else in the codebase references the bare label. Confirm with:

```bash
grep -rn '"crossns"' test/ Makefile .github/ 2>/dev/null
```

If the only result is the line you just changed, you're clean. If something else references it, leave the bare `crossns` label as well: `Label("onionbalance", "crossns", "ob-crossns")`.

- [ ] **Step 4: Verify compile + dry-run lists the right specs**

Run:

```bash
go vet ./test/e2e/...
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v -ginkgo.label-filter='ob-failover' 2>&1 | grep -E 'It|backend pod|scaling|SIGHUP'
```

Expected: lists the 3 mutator specs. The `ob-crossns` filter should list only the cross-NS spec:

```bash
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v -ginkgo.label-filter='ob-crossns' 2>&1 | grep -E 'It|master Secret'
```

- [ ] **Step 5: Commit**

```bash
git add test/e2e/onionbalance_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "test(e2e): label Mode B mutator + cross-NS specs for matrix routing"
```

---

### Task 2: Decompose `onionbalance_test.go` into 3 sibling Describe blocks

**Why:** The current single `Describe(..., Ordered, ...)` shares one `BeforeAll`, so any spec failure cascade-skips every following spec in the block (the recent "13 passed, 1 failed, 7 skipped" pattern). Splitting into three `Ordered` siblings isolates failures.

**Files:**
- Modify: `test/e2e/onionbalance_test.go`

Read the file first to understand current structure:

```bash
sed -n '47,80p' test/e2e/onionbalance_test.go    # Describe + BeforeAll opening
sed -n '195,235p' test/e2e/onionbalance_test.go  # rest of BeforeAll
sed -n '236,270p' test/e2e/onionbalance_test.go  # AfterAll
```

Map of specs to blocks (from spec § Change 2):

| Block | Specs | Namespace | GatewayClass |
|---|---|---|---|
| A — happy path | routes by path, isolates per-pod keys | `tor-gateway-ha` | `ha-gw-class` |
| B — mutations | pod kill, scale-down, scale-up SIGHUP | `tor-gateway-ha-mut` | `ha-gw-mut-class` |
| C — cross-NS + NP | cross-NS master Secret, NP coverage | `tor-gateway-ha` (NP only); cross-NS spec self-contained | `ha-gw-class` |

- [ ] **Step 1: Extract a fixture-builder helper**

Each block needs to create a Gateway + OBP + master Secret + tor-client + 2 echo backends + HTTPRoute. Today all of that lives inline inside the single `BeforeAll`. Extract into a helper at the bottom of `onionbalance_test.go`:

```go
// modeBFixture builds a Mode B test fixture in the given namespace + GatewayClass.
// It generates a master keypair, creates the master Secret + Gateway + OBP +
// HTTPRoute + 2 echo backends, waits for the frontend Deployment Available,
// waits for Gateway.status.addresses to publish the .onion, applies a
// tor-client pod, and returns the master .onion address for use in specs.
func modeBFixture(ns, gwClass, gwName string) (masterOnion string) {
    // ... move the body of the current BeforeAll here, parameterized by ns/gwClass/gwName ...
    // The existing BeforeAll uses const obpNS / obpGwClass / a hardcoded "ha-gw" — replace
    // those references inside this helper with the function's parameters.
    // Keep the same Eventually budgets (5m frontend, 60s gateway address, 120s tor-client).
    return strings.TrimSpace(masterOnion)
}

// teardownModeBFixture removes everything modeBFixture created. Best-effort.
func teardownModeBFixture(ns, gwClass string) {
    if os.Getenv("TOR_GATEWAY_E2E_NO_TEARDOWN") == "1" {
        fmt.Printf("\n[debug] keeping ns %s + gatewayclass %s (TOR_GATEWAY_E2E_NO_TEARDOWN=1)\n", ns, gwClass)
        return
    }
    _, _ = utils.Run(exec.Command("kubectl", "delete", "ns", ns, "--ignore-not-found", "--wait=false"))
    _, _ = utils.Run(exec.Command("kubectl", "delete", "gatewayclass", gwClass, "--ignore-not-found"))
}
```

**Important:** the existing fixture references things like `obpNS`, `obpGwClass`, the hardcoded `"ha-gw"` Gateway name, `ha-backend-a` / `ha-backend-b` service names, the `ha-tor-client` Pod name, the `ha-obp` OBP name, the `ha-route` HTTPRoute name, and the master Secret name. All of these are used by the existing specs. Pick a clear convention:
- The helper takes `gwName` as a parameter; Gateway, OBP (`<gwName>-obp`), HTTPRoute (`<gwName>-route`), backends (`<gwName>-backend-a/b`), and tor-client (`<gwName>-tor-client`) all derive from it.
- Block A uses `gwName="ha-gw"` (unchanged).
- Block B uses `gwName="ha-gw-mut"` (new isolated fixture).
- Block C's NP-coverage spec uses Block A's `gwName="ha-gw"` (NP coverage is observer-only). Block C also runs the cross-NS spec which builds its own self-contained fixture inline (it already does today — leave that path alone).

- [ ] **Step 2: Write Block A (happy path)**

Replace the current single `Describe` with this as the first of three siblings:

```go
var _ = Describe("OnionBalance HA — happy path", Ordered, Label("onionbalance"), func() {
    var masterOnion string

    BeforeAll(func() {
        masterOnion = modeBFixture("tor-gateway-ha", "ha-gw-class", "ha-gw")
    })

    AfterAll(func() {
        teardownModeBFixture("tor-gateway-ha", "ha-gw-class")
    })

    It("routes by path to the correct backend over the master .onion", func() {
        // existing body — uses fetchOverTor("ha-tor-client", ...) and Equal("backend-A")/("backend-B")
    })

    It("isolates per-pod keys: a backend's tor container only sees its own onion key", Label("onionbalance"), func() {
        // existing body — uses ha-gw-backend-0/1/2-keys Secret names
    })
})
```

- [ ] **Step 3: Write Block B (mutations)**

Below Block A:

```go
var _ = Describe("OnionBalance HA — mutations", Ordered, Label("onionbalance", "ob-failover"), func() {
    var masterOnion string

    BeforeAll(func() {
        masterOnion = modeBFixture("tor-gateway-ha-mut", "ha-gw-mut-class", "ha-gw-mut")
    })

    AfterAll(func() {
        teardownModeBFixture("tor-gateway-ha-mut", "ha-gw-mut-class")
    })

    It("remains reachable after a backend pod is killed", func() {
        // existing body — but adapt: replace obpNS with "tor-gateway-ha-mut",
        // replace "ha-gw-backend-..." references with "ha-gw-mut-backend-...",
        // replace "ha-tor-client" with "ha-gw-mut-tor-client".
    })

    It("remains reachable after scaling replicas from 3 to 1", func() {
        // existing body, same renames as above. Also patches OBP "ha-obp" -> "ha-gw-mut-obp".
    })

    It("reloads onionbalance via SIGHUP when backends scale up", func() {
        // existing body, same renames.
    })
})
```

(The `Label("ob-failover")` from Task 1 is now at the `Describe` level. Per-`It` labels can be dropped from these three specs since they inherit from the parent — but Ginkgo allows duplicates, so leaving them is fine if it's less invasive.)

- [ ] **Step 4: Write Block C (cross-NS + NP coverage)**

Below Block B:

```go
var _ = Describe("OnionBalance HA — cross-NS + NetworkPolicy", Ordered, Label("onionbalance"), func() {
    var masterOnion string

    BeforeAll(func() {
        // NP-coverage spec needs a Mode B fixture to observe. Cross-NS spec
        // is fully self-contained (creates its own NS + GatewayClass + cleans up).
        masterOnion = modeBFixture("tor-gateway-ha", "ha-gw-class", "ha-gw")
    })

    AfterAll(func() {
        teardownModeBFixture("tor-gateway-ha", "ha-gw-class")
    })

    It("supports a master Secret in a different namespace via ReferenceGrant", Label("ob-crossns"), func() {
        // existing body — unchanged; this spec already self-contains its
        // ha-master-secrets / tor-gateway-ha-crossns / tor-gateway-ha-crossns-class
        // setup + DeferCleanup. It does NOT depend on the masterOnion built above.
    })

    It("covers Mode B frontend and backend pods with the per-Gateway NetworkPolicy",
        Label("networkpolicy", "onionbalance"), func() {
        // existing body — observes the ha-gw fixture's pods.
    })
})
```

- [ ] **Step 5: Delete the old single Describe block**

The pre-existing single `Describe("OnionBalance HA (Mode B)", Ordered, Label("onionbalance"), func() { ... })` (lines ~47 through end-of-block) should be removed in full. The three new blocks replace it.

- [ ] **Step 6: Add a header comment to the file**

At the top of `onionbalance_test.go`, after the existing package + imports, add:

```go
// Spec authoring rules for this file (codified by the v0.4.x stable-e2e-pipeline design):
//   1. No spec depends on another Describe block's state — each block re-creates
//      its own Gateway/OBP/Secret in its own namespace.
//   2. Within an Ordered block, observer specs come before mutator specs.
//   3. Use Label("ob-failover") on mutator specs and Label("ob-crossns") on
//      cross-namespace specs so the CI matrix can route them correctly.
//   4. Generous setup budgets (5-10m), tight assertion budgets (<=2m).
```

- [ ] **Step 7: Verify**

```bash
cd /Volumes/source-code/Personal/torGateway
go vet ./test/e2e/...
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v 2>&1 | grep -E 'Describe|OnionBalance HA'
```

Expected: 3 distinct `Describe` lines (`— happy path`, `— mutations`, `— cross-NS + NetworkPolicy`).

```bash
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v -ginkgo.label-filter='onionbalance && !ob-failover && !ob-crossns && !networkpolicy' 2>&1 | grep '  It'
```

Expected: only Block A's 2 specs.

```bash
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v -ginkgo.label-filter='onionbalance && (ob-failover || ob-crossns || networkpolicy)' 2>&1 | grep '  It'
```

Expected: Block B's 3 mutator specs + Block C's 2 specs (cross-NS + NP coverage).

```bash
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v -ginkgo.label-filter='!onionbalance' 2>&1 | grep -E '  It' | head -20
```

Expected: ~14 specs, none from onionbalance_test.go.

`./bin/golangci-lint run --timeout 5m` must report 0 issues.

- [ ] **Step 8: Commit**

```bash
git add test/e2e/onionbalance_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "test(e2e): decompose Mode B Ordered cascade into 3 sibling Describes"
```

---

### Task 3: Add `make test-e2e-suite` target

**Why:** The CI matrix (Task 4) calls a label-filter-aware target. We want `make test-e2e` unchanged for local "run everything", and a new target that honors `$E2E_LABEL_FILTER`.

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Locate the existing `test-e2e` block**

```bash
grep -n -B1 -A12 '^.PHONY: test-e2e' Makefile | head -30
```

You should see `test-e2e: setup-test-e2e manifests generate fmt vet ...`. Read the full recipe to understand the env prelude (KUBEBUILDER_ASSETS, KIND_CLUSTER setup, etc.) — `test-e2e-suite` will share the same prelude.

- [ ] **Step 2: Add the new target immediately after `test-e2e`**

In `Makefile`, after the existing `test-e2e:` recipe (around line 127), insert:

```makefile
.PHONY: test-e2e-suite
test-e2e-suite: setup-test-e2e manifests generate fmt vet ## Run a label-filtered subset of e2e specs. Requires $E2E_LABEL_FILTER.
	@if [ -z "$$E2E_LABEL_FILTER" ]; then \
		echo "fatal: E2E_LABEL_FILTER must be set; e.g. E2E_LABEL_FILTER='onionbalance' make test-e2e-suite"; \
		exit 2; \
	fi
	@echo "Running e2e suite with label-filter=$$E2E_LABEL_FILTER"
	KUBECONFIG=$$($(KIND) get kubeconfig-path --name=$(KIND_CLUSTER) 2>/dev/null || echo "$$HOME/.kube/config") \
		go test -tags=e2e -timeout 30m ./test/e2e/ -v -ginkgo.v \
		-ginkgo.label-filter="$$E2E_LABEL_FILTER"
	$(MAKE) cleanup-test-e2e
```

**IMPORTANT:** match whatever env/kubeconfig prelude `test-e2e` uses. The snippet above shows the typical pattern but the exact `KUBECONFIG=` line should be copied from the existing `test-e2e` recipe to avoid drift.

- [ ] **Step 3: Verify the target parses and errors on missing env**

```bash
cd /Volumes/source-code/Personal/torGateway
make -n test-e2e-suite 2>&1 | head -5  # -n shows what would run without running
make test-e2e-suite 2>&1 | head -5     # actually invoke; should hit the missing-env guard
```

The second call should print `fatal: E2E_LABEL_FILTER must be set; ...` and exit 2.

```bash
echo $?  # expect 2
```

Then verify the happy-path validates the filter is propagated:

```bash
E2E_LABEL_FILTER='dataplane' make -n test-e2e-suite 2>&1 | grep -E 'label-filter|go test'
```

Expected: a `go test ... -ginkgo.label-filter="dataplane"` line appears in the dry-run output.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "build(make): add test-e2e-suite target driven by E2E_LABEL_FILTER"
```

---

### Task 4: Convert `test-e2e.yml` to a 3-row matrix

**Why:** This is the structural change that prevents Mode B flakes from cascading into Mode A reporting. Each matrix row is an independent kind cluster + ginkgo label filter.

**Files:**
- Modify: `.github/workflows/test-e2e.yml`

- [ ] **Step 1: Replace the workflow content**

Overwrite `.github/workflows/test-e2e.yml` with:

```yaml
name: E2E Tests

# E2E spins up Kind, builds and loads images, applies the operator, and
# exercises live reconcilers. Three-row matrix isolates Mode A from Mode B
# from Mode B mutations so a chutney flake in one suite doesn't mask the others.
on:
  push:
    branches: [main]
  workflow_dispatch: {}

permissions: {}

jobs:
  test-e2e:
    permissions:
      contents: read
    name: e2e (${{ matrix.suite }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - suite: core
            label_filter: '!onionbalance'
          - suite: onionbalance-base
            label_filter: 'onionbalance && !ob-failover && !ob-crossns && !networkpolicy'
          - suite: onionbalance-mutations
            label_filter: 'onionbalance && (ob-failover || ob-crossns || networkpolicy)'
    env:
      CONTAINER_TOOL: docker
    steps:
      - name: Clone the code
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false

      - name: Setup Go
        uses: actions/setup-go@4b73464bb391d4059bd26b0524d20df3927bd417 # v6.3.0
        with:
          go-version-file: go.mod

      - name: Install kind
        run: |
          curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.31.0/kind-linux-$(go env GOARCH)"
          chmod +x ./kind
          sudo mv ./kind /usr/local/bin/kind

      - name: Verify kind installation
        run: kind version

      - name: Run e2e (${{ matrix.suite }})
        env:
          E2E_LABEL_FILTER: ${{ matrix.label_filter }}
        run: |
          go mod tidy
          make test-e2e-suite
```

- [ ] **Step 2: Lint the YAML**

```bash
cd /Volumes/source-code/Personal/torGateway
yq eval '.jobs.test-e2e.strategy.matrix.include[].suite' .github/workflows/test-e2e.yml
```

Expected output (one per line):
```
core
onionbalance-base
onionbalance-mutations
```

If `yq` isn't installed, parse the file by hand — the three `suite:` keys must be present.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test-e2e.yml
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "ci(e2e): fan out into 3-row matrix scoped by ginkgo label filter"
```

---

### Task 5: Add diagnostic artifact upload on failure

**Why:** Today, diagnosing a CI flake requires re-running locally with `make test-e2e-debug`. With per-suite artifacts, the failure is diagnosable from the GitHub Actions run page.

**Files:**
- Modify: `.github/workflows/test-e2e.yml`

- [ ] **Step 1: Add a diagnostic-collection step before the upload**

Insert the following steps in `.github/workflows/test-e2e.yml`, after the `Run e2e (${{ matrix.suite }})` step. Place them at the same indentation level as the existing steps.

```yaml
      - name: Collect diagnostics
        if: failure()
        run: |
          set +e
          mkdir -p "$RUNNER_TEMP/e2e-diagnostics"
          # Controller manager logs (current + previous instance if any).
          kubectl logs -n tor-gateway-system deployment/tor-gateway-controller-manager \
            > "$RUNNER_TEMP/e2e-diagnostics/controller-current.log" 2>&1
          kubectl logs -n tor-gateway-system deployment/tor-gateway-controller-manager --previous \
            > "$RUNNER_TEMP/e2e-diagnostics/controller-previous.log" 2>&1 || true
          # Chutney pod logs.
          kubectl logs -n tor-gateway-chutney pod/chutney-0 \
            > "$RUNNER_TEMP/e2e-diagnostics/chutney.log" 2>&1 || true
          # Describe + events for every namespace touched by the suite.
          for ns in tor-gateway-system tor-gateway-chutney tor-gateway-ha tor-gateway-ha-mut tor-gateway-ha-crossns ha-master-secrets; do
            kubectl describe pods -n "$ns" \
              > "$RUNNER_TEMP/e2e-diagnostics/describe-pods-$ns.txt" 2>&1 || true
            kubectl get events -n "$ns" --sort-by='.lastTimestamp' \
              > "$RUNNER_TEMP/e2e-diagnostics/events-$ns.txt" 2>&1 || true
          done
          # All-pods snapshot.
          kubectl get pods -A -o wide \
            > "$RUNNER_TEMP/e2e-diagnostics/all-pods.txt" 2>&1 || true
          # Ginkgo report — Task 6 makes test-e2e-suite emit this. Until then
          # the file may not exist; ignore failure.
          cp ginkgo-report.json "$RUNNER_TEMP/e2e-diagnostics/ginkgo-report.json" 2>/dev/null || true
          ls -la "$RUNNER_TEMP/e2e-diagnostics/"

      - name: Upload diagnostics
        if: failure()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: e2e-${{ matrix.suite }}-diagnostics
          path: ${{ runner.temp }}/e2e-diagnostics/
          retention-days: 7
          if-no-files-found: ignore
```

**Note on the upload-artifact action pin:** the version pinned above is the v4 line as of 2026. Verify the latest pinned SHA in the repo's other workflows (`.github/workflows/security.yml` or similar) — match the convention. If you're unsure, run:

```bash
grep -rn 'upload-artifact@' .github/workflows/
```

If the repo already pins `upload-artifact@<some-sha>` elsewhere, use the same SHA for consistency.

- [ ] **Step 2: Verify the YAML still parses**

```bash
yq eval '.jobs.test-e2e.steps | length' .github/workflows/test-e2e.yml
```

Expected: 7 (the 5 original steps + 2 new diagnostic steps).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test-e2e.yml
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "ci(e2e): upload per-suite diagnostics on failure"
```

---

### Task 6: Emit a ginkgo step summary on every run

**Why:** "13 passed, 1 failed, 7 skipped" is buried in 2000 lines of log. A `$GITHUB_STEP_SUMMARY` table at the top of the job page is one-glance diagnosis.

**Files:**
- Modify: `Makefile` (have `test-e2e-suite` emit a JSON report)
- Modify: `.github/workflows/test-e2e.yml` (parse the JSON into a step summary)

- [ ] **Step 1: Update `test-e2e-suite` to emit `ginkgo-report.json`**

Edit the `test-e2e-suite` recipe added in Task 3. Append `-ginkgo.json-report=ginkgo-report.json` to the `go test` line:

```makefile
.PHONY: test-e2e-suite
test-e2e-suite: setup-test-e2e manifests generate fmt vet ## Run a label-filtered subset of e2e specs. Requires $E2E_LABEL_FILTER.
	@if [ -z "$$E2E_LABEL_FILTER" ]; then \
		echo "fatal: E2E_LABEL_FILTER must be set; e.g. E2E_LABEL_FILTER='onionbalance' make test-e2e-suite"; \
		exit 2; \
	fi
	@echo "Running e2e suite with label-filter=$$E2E_LABEL_FILTER"
	KUBECONFIG=$$($(KIND) get kubeconfig-path --name=$(KIND_CLUSTER) 2>/dev/null || echo "$$HOME/.kube/config") \
		go test -tags=e2e -timeout 30m ./test/e2e/ -v -ginkgo.v \
		-ginkgo.label-filter="$$E2E_LABEL_FILTER" \
		-ginkgo.json-report=ginkgo-report.json
	$(MAKE) cleanup-test-e2e
```

Verify the file is generated by running locally if possible, or trust the ginkgo flag.

- [ ] **Step 2: Add a step-summary step to the workflow**

In `.github/workflows/test-e2e.yml`, insert this step AFTER `Run e2e` and BEFORE `Collect diagnostics`:

```yaml
      - name: Step summary
        if: always()
        run: |
          set +e
          if [ ! -f ginkgo-report.json ]; then
            echo "## e2e (${{ matrix.suite }}): report not generated" >> "$GITHUB_STEP_SUMMARY"
            exit 0
          fi
          # Parse the ginkgo JSON report. The schema is documented at
          # https://onsi.github.io/ginkgo/#machine-readable-reports — top level is an
          # array of suites; each suite has SpecReports[] with LeafNodeText + State.
          {
            echo "## e2e (${{ matrix.suite }}) summary"
            echo ""
            echo "| Spec | State | Duration |"
            echo "|---|---|---|"
            jq -r '.[0].SpecReports[]? |
              select(.LeafNodeType == "It") |
              [
                ((.ContainerHierarchyTexts // []) | join(" > ")) + " > " + .LeafNodeText,
                .State,
                ((.RunTime // 0) / 1000000000 | floor | tostring) + "s"
              ] | "| " + (.[0]) + " | " + (.[1]) + " | " + (.[2]) + " |"' ginkgo-report.json
          } >> "$GITHUB_STEP_SUMMARY"
```

(GitHub Actions ubuntu-latest has `jq` preinstalled.)

- [ ] **Step 3: Verify the JSON schema field names**

Ginkgo v2 emits `SpecReports` (capital S) and uses `LeafNodeText`, `ContainerHierarchyTexts`, `State`, `RunTime` (nanoseconds). Confirm with one local run if possible:

```bash
cd /Volumes/source-code/Personal/torGateway
# If you ran any e2e locally and have a ginkgo-report.json:
test -f ginkgo-report.json && jq -r '.[0].SpecReports[0] | keys' ginkgo-report.json
```

If the field names differ (older ginkgo emits slightly different keys), adjust the `jq` expression. Reference: ginkgo's `types.Report` Go struct in the vendored module.

- [ ] **Step 4: Commit**

```bash
git add Makefile .github/workflows/test-e2e.yml
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "ci(e2e): emit per-spec step summary from ginkgo JSON report"
```

---

### Task 7: Local validation

**Why:** Confirm the structural changes hold before the first CI push.

- [ ] **Step 1: Full build + lint + unit tests**

```bash
cd /Volumes/source-code/Personal/torGateway
go build ./...
go test ./... -count=1
./bin/golangci-lint run --timeout 5m
```

All clean.

- [ ] **Step 2: Dry-run each label filter**

For each matrix row, dry-run the ginkgo selection to confirm the right specs are routed:

```bash
echo "--- core: !onionbalance ---"
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v -ginkgo.label-filter='!onionbalance' 2>&1 | grep -E '  It' | wc -l

echo "--- onionbalance-base ---"
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v \
  -ginkgo.label-filter='onionbalance && !ob-failover && !ob-crossns && !networkpolicy' 2>&1 | grep -E '  It'

echo "--- onionbalance-mutations ---"
go test -tags=e2e ./test/e2e/ -ginkgo.dry-run -v \
  -ginkgo.label-filter='onionbalance && (ob-failover || ob-crossns || networkpolicy)' 2>&1 | grep -E '  It'
```

Expected:
- `core`: ~14 specs (gateway, dataplane, dataplane-crossns, referencegrant, clientauth, vanity, networkpolicy, manager).
- `onionbalance-base`: 2 specs (routes by path, isolates per-pod keys).
- `onionbalance-mutations`: 5 specs (pod kill, scale-down, scale-up SIGHUP, cross-NS master Secret, NP coverage).

Total across all three rows: ~21 specs. **No spec appears in more than one row.** Verify this by computing the intersection mentally — if a spec shows up under both `onionbalance-base` AND `onionbalance-mutations`, the label filter is wrong.

- [ ] **Step 3: Optional — run one matrix row locally if kind is available**

If you have docker + kind locally and time to spare (~5 min):

```bash
E2E_LABEL_FILTER='!onionbalance' make test-e2e-suite
```

Expected: kind cluster spins up, operator deploys, Mode A specs run, kind tears down. Total ~10-13 min.

(Skip this if it takes too long or the local docker daemon is slow. Trust the CI run.)

- [ ] **Step 4: Inspect the diff for any cross-file accidental edits**

```bash
git diff main..HEAD --stat
```

Expected files changed:
- `Makefile`
- `.github/workflows/test-e2e.yml`
- `test/e2e/onionbalance_test.go`
- (No other files.)

If unexpected files appear in the diff, investigate before pushing.

---

### Task 8: Final report

- [ ] **Step 1: Branch summary**

```bash
git log --oneline main..HEAD
```

Expected: 6-7 commits, one per task (Task 0 has no commit since it's just `git checkout -b`).

- [ ] **Step 2: Report to user**

```
Stable e2e pipeline branch ready on feat/stable-e2e-pipeline.

Changes:
- test-e2e.yml: 1 job -> 3 matrix rows (core / onionbalance-base / onionbalance-mutations)
- onionbalance_test.go: 1 Ordered Describe (7 specs) -> 3 sibling Ordered Describes (2 / 3 / 2 specs)
- New labels: ob-failover, ob-crossns
- Makefile: new test-e2e-suite target driven by E2E_LABEL_FILTER
- CI uploads per-suite diagnostics on failure
- CI emits ginkgo per-spec step summary on every run

A Mode B chutney flake will now fail exactly ONE matrix row, leaving Mode A
and unrelated Mode B suites visibly green. Diagnostic artifacts are
downloadable from the GitHub Actions run page; per-spec status is visible
at the top of the job page.

Ready for git rebase --signoff origin/main + push.
```

---

## Self-review notes

**Spec coverage check:**
- CI fan-out → Task 4 ✓
- Ginkgo decomposition → Task 2 ✓
- Label additions (`ob-failover`, `ob-crossns`) → Task 1 ✓
- `test-e2e-suite` Makefile target → Task 3 ✓
- Per-suite diagnostic artifacts → Task 5 ✓
- Step summary → Task 6 ✓
- Invariants codified → Task 2 (header comment) ✓
- Out-of-scope items (realtor-smoke, conformance flake, shared kind) → unchanged ✓

**Cross-task type consistency:**
- `E2E_LABEL_FILTER` env var used in Makefile (Task 3) AND workflow (Task 4) — same spelling, same shell-variable form.
- `ob-failover` / `ob-crossns` labels added in Task 1, consumed by filter expressions in Task 4.
- `modeBFixture` / `teardownModeBFixture` helpers defined in Task 2 Step 1, consumed by Tasks 2 Steps 2-4.
- `tor-gateway-ha-mut` / `ha-gw-mut-class` introduced in Task 2 Step 3, consistent in artifact-collection step (Task 5) which describes `tor-gateway-ha-mut` namespace.

**Acknowledged compromises:**
- Task 6 Step 3 depends on the exact ginkgo JSON schema field names. If the field names differ on the installed ginkgo version, the implementer must adjust the `jq` expression. The plan calls this out explicitly with a verification step.
- Task 2 Step 1 assumes the existing `BeforeAll` is parameterizable cleanly. If the body has unparametric assumptions (e.g., hardcoded image names tied to "ha-gw"), the helper may need additional parameters. Implementer should adapt rather than blindly copy.
- The `upload-artifact` action SHA in Task 5 may be stale; the plan tells the implementer to match the repo's existing pinning convention.
