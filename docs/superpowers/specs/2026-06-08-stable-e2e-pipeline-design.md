# Stable E2E Pipeline — Design

**Date:** 2026-06-08
**Status:** Shipped (waves 1-4). Partially superseded by `2026-06-12-e2e-pregen-retry-design.md` (retry posture, chutney pre-gen, spec relocation).

## Problem

E2E Tests has failed on 4 of the last 5 pushes to `main`. The failure mode is consistent:

- One Mode B spec (typically the first one, `OnionBalance HA (Mode B) — routes by path to the correct backend over the master .onion`) times out at the 5-minute `fetchOverTor` budget while waiting for chutney HSDir propagation.
- Because all 7 Mode B specs share a single `Describe(..., Ordered, ...)` block with one `BeforeAll`, a failure in any spec cascade-skips every following spec. A typical failure: 13 passed, 1 failed, 7 skipped.
- Mode A specs (gateway, dataplane, networkpolicy, etc.) are stable on their own but share the e2e job with the flaky Mode B suite, so a Mode B flake reports as "E2E Tests failed" without distinguishing which area broke.

Tests, Lint, Helm chart, Security, and Conformance have been stable. The flake is localized to Mode B / chutney-driven specs.

## Goals

1. A Mode B flake must not cancel-skip Mode A specs.
2. A flake in one Mode B sub-area (e.g., scale-down) must not skip unrelated Mode B specs (e.g., cross-NS).
3. The pipeline must still exercise the full e2e surface on every push to `main` — no demoting flaky specs to a nightly cron.
4. When a CI job fails, diagnosing the failure should not require re-running locally.

## Non-goals

- Reducing residual chutney timing variability. Chutney is fundamentally approximate; we accept that some Mode B specs may still occasionally fail. The goal is to ensure the failure signal is precise, not hidden inside an unrelated suite.
- Adding `--flake-attempts` or per-spec retry. Retries hide real bugs; the structural fix should be sufficient.
- A `BeforeAll`-level warmup of Tor circuits. Explicitly rejected during brainstorming — it couples blocks together and re-introduces the cascade we're escaping.

## Architecture

Two structural changes, no test-time tweaks.

### Change 1 — CI fan-out (`.github/workflows/test-e2e.yml`)

Replace the single `test-e2e` job with a `strategy.matrix` of three independent jobs, each spinning up its own kind cluster + chutney + operator, running a ginkgo `--label-filter`-scoped subset of specs.

| Matrix row | Ginkgo label filter | Specs covered |
|---|---|---|
| `core` | `!onionbalance` | gateway lifecycle, dataplane (chutney), dataplane-crossns, referencegrant, clientauth, vanity, networkpolicy, manager — ~14 specs |
| `onionbalance-base` | `onionbalance && !ob-failover && !ob-crossns && !networkpolicy` | Mode B routes-by-path + per-pod key isolation |
| `onionbalance-mutations` | `onionbalance && (ob-failover \|\| ob-crossns \|\| networkpolicy)` | Mode B pod-kill, scale-down, scale-up + SIGHUP, cross-NS master Secret, NP coverage |

Workflow shape:

```yaml
name: E2E Tests

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
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with: { persist-credentials: false }
      - uses: actions/setup-go@4b73464bb391d4059bd26b0524d20df3927bd417
        with: { go-version-file: go.mod }
      - name: Install kind
        run: |
          curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.31.0/kind-linux-$(go env GOARCH)"
          chmod +x ./kind
          sudo mv ./kind /usr/local/bin/kind
      - name: Verify kind
        run: kind version
      - name: Run e2e (${{ matrix.suite }})
        env:
          E2E_LABEL_FILTER: ${{ matrix.label_filter }}
        run: |
          go mod tidy
          make test-e2e-suite
      # Diagnostic artifacts (see Observability section).
```

Critical configuration:
- **`fail-fast: false`** — a flake in one row must not cancel the other rows.
- One kind cluster per matrix row. No shared state between rows. Total CI compute increases by ~30% (3 kind setups instead of 1) — acceptable for the reliability win.

### Change 2 — Ginkgo decomposition (`test/e2e/onionbalance_test.go`)

Split the single `Describe("OnionBalance HA (Mode B)", Ordered, Label("onionbalance"))` (currently 7 specs, one `BeforeAll`) into **three sibling top-level `Describe` blocks**, each `Ordered`, each with its own `BeforeAll`/`AfterAll`.

#### Block A — `OnionBalance HA — happy path`
- **Labels:** `onionbalance`
- **Namespace / GatewayClass:** `tor-gateway-ha` / `ha-gw-class` (existing names, unchanged)
- **Fixture:** baseline `ha-gw` Gateway + 3-replica OBP + master Secret + tor-client pod
- **Specs:**
  - `routes by path to the correct backend over the master .onion`
  - `isolates per-pod keys: a backend's tor container only sees its own onion key`
- **Mutations:** none. Pure observers. Safe to share the fixture.

#### Block B — `OnionBalance HA — mutations`
- **Labels:** `onionbalance`, `ob-failover`
- **Namespace / GatewayClass:** `tor-gateway-ha-mut` / `ha-gw-mut-class` (new — isolates mutations from Block A)
- **Fixture:** parallel `ha-gw-mut` Gateway + 3-replica OBP + master Secret + tor-client pod
- **Specs (in declared order):**
  - `remains reachable after a backend pod is killed`
  - `remains reachable after scaling replicas from 3 to 1`
  - `reloads onionbalance via SIGHUP when backends scale up`
- **Mutations:** all. Scale-down runs before scale-up so the cluster ends at the initial replica count. Block B's namespace is teardown-on-`AfterAll`.

#### Block C — `OnionBalance HA — cross-NS + NetworkPolicy`
- **Labels:** depends on spec — see below.
- **Namespace / GatewayClass:** baseline `tor-gateway-ha` / `ha-gw-class` for the NP-coverage observer; cross-NS spec uses its own self-contained namespaces (`ha-master-secrets`, `tor-gateway-ha-crossns`, `tor-gateway-ha-crossns-class`).
- **Specs:**
  - `supports a master Secret in a different namespace via ReferenceGrant` — labels: `onionbalance`, `ob-crossns`. Self-contained (creates + tears down its own NS + GatewayClass).
  - `covers Mode B frontend and backend pods with the per-Gateway NetworkPolicy` — labels: `networkpolicy`, `onionbalance`. Observer-only against the baseline `ha-gw` fixture.

#### Label additions

Two specs need new labels added inline:
- The 3 mutation specs in Block B get `Label("onionbalance", "ob-failover")`.
- The cross-NS spec gets `Label("onionbalance", "ob-crossns")` (the existing `crossns` label is kept for backwards-compat; `ob-crossns` is the new, namespaced version that avoids clashing with `dataplane-crossns`).
- The NP-coverage spec keeps `Label("networkpolicy", "onionbalance")`. No change.

#### Setup duplication trade-off

Each block re-runs ~3–5 minutes of fixture setup (Gateway + OBP + frontend Available + Gateway address publish + tor-client Ready). Block A pays this once; Block B pays it once; Block C pays it once.

**No fixture collision across blocks:** Block A's `ha-gw` (in `tor-gateway-ha`) lives in the `onionbalance-base` matrix row's kind cluster. Block C's NP-coverage spec also creates `ha-gw` in `tor-gateway-ha`, but inside the `onionbalance-mutations` row's separate kind cluster. Each matrix row spins up its own cluster, so the namespace names never collide. The cross-NS spec inside Block C uses its own self-contained namespaces (`ha-master-secrets`, `tor-gateway-ha-crossns`).

This is mitigated by the CI fan-out: Block A lives in `onionbalance-base`, Blocks B+C live in `onionbalance-mutations`. Per-matrix-job wall clock:

| Matrix row | Setup cost | Spec runtime | Total |
|---|---|---|---|
| `core` | ~3 min (one Mode A fixture, several smaller ones) | ~10 min | ~13 min |
| `onionbalance-base` | ~5 min (Block A only) | ~3 min | ~8 min |
| `onionbalance-mutations` | ~10 min (B + C) | ~7 min | ~17 min |

vs. current `~20 min` for the serial single-job run.

### Change 3 — Makefile (`Makefile`)

Add `test-e2e-suite`. Existing targets are unchanged.

```makefile
# Existing — unchanged. Runs the full suite locally.
.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet
	# existing body

# New — runs a label-filtered subset. Used by CI matrix.
# Honors $E2E_LABEL_FILTER; errors if unset.
# Local usage: E2E_LABEL_FILTER='onionbalance && !ob-failover' make test-e2e-suite
.PHONY: test-e2e-suite
test-e2e-suite: setup-test-e2e manifests generate fmt vet
	@if [ -z "$$E2E_LABEL_FILTER" ]; then \
		echo "fatal: E2E_LABEL_FILTER must be set; e.g. 'onionbalance' or '!onionbalance'"; \
		exit 2; \
	fi
	# same env+kubeconfig prelude as test-e2e:
	go test -tags=e2e -timeout 30m ./test/e2e/ -v -ginkgo.v \
		-ginkgo.label-filter="$$E2E_LABEL_FILTER"
	$(MAKE) cleanup-test-e2e

# Existing — unchanged.
.PHONY: test-e2e-realtor
test-e2e-realtor: ...

# Existing — unchanged.
.PHONY: test-e2e-debug
test-e2e-debug: ...
```

Notes:
- `test-e2e` stays exactly as today. Local "run everything" flow unchanged.
- `test-e2e-suite` requires `E2E_LABEL_FILTER`; errors clearly if missing. No new flag parsing.
- Per-suite timeout drops 45m → 30m (smaller surface, generous headroom).

## Observability when CI fails

Two additions, both cheap.

### Per-suite diagnostic artifacts

On failure, each matrix row uploads a GitHub Actions artifact named `e2e-${{ matrix.suite }}-diagnostics` containing:

- `kubectl logs deployment/tor-gateway-controller-manager -n tor-gateway-system --previous=false` (controller log)
- `kubectl logs deployment/tor-gateway-controller-manager -n tor-gateway-system --previous=true 2>/dev/null || true` (previous instance if any)
- `kubectl describe pods -n <suite-ns>` for each suite namespace touched
- `kubectl get events -n <suite-ns> --sort-by='.lastTimestamp'`
- `kubectl logs pod/chutney-0 -n tor-gateway-chutney`
- The ginkgo JSON report (`-ginkgo.json-report=report.json`)

The workflow's `Run e2e` step writes these to `$RUNNER_TEMP/e2e-diagnostics/`; a final `actions/upload-artifact` step uploads `if: failure()`.

### Step summary

After ginkgo runs (success or failure), the workflow extracts the JSON report's per-spec status and appends a compact table to `$GITHUB_STEP_SUMMARY`:

```
| Spec | Status | Duration |
|---|---|---|
| OnionBalance HA - happy path > routes by path | passed | 47s |
| OnionBalance HA - happy path > isolates per-pod keys | passed | 8s |
...
```

This is visible at the top of the job page; no scrolling 2000 lines of log.

## Invariants for spec authors

Codified in the design doc and a header comment in `test/e2e/onionbalance_test.go`:

1. **No spec depends on another `Describe` block's state.** Each block's `BeforeAll` re-creates its own Gateway/OBP/Secret in its own namespace. Block ordering is not guaranteed (the matrix runs them in parallel jobs).
2. **Within an `Ordered` block, observer specs come before mutator specs.** Block A is observer-only. Block B's mutators run scale-down before scale-up so the cluster ends at the initial replica count.
3. **`BeforeAll`/`AfterAll` are idempotent.** Use `kubectl apply` for create paths; `kubectl delete --ignore-not-found --wait=false` for teardown.
4. **Generous setup budgets, tight assertion budgets.** Setup waits use 5–10 min for HSDir-propagation-bound work (frontend Available, Gateway address publish, tor-client Ready). Assertion `Eventually` blocks inside specs use ≤2 min because the system should already be warm by then.
5. **Label discipline.** Adding `Label("onionbalance", ...)` to a new spec implicitly puts it in the Mode B matrix row. Use `ob-failover` for mutator specs, `ob-crossns` for cross-namespace specs.

## Out of scope (explicit)

- **`realtor-smoke` cleanup.** Spec is skipped on every chutney run today. Belongs on a nightly `schedule: cron: '0 3 * * *'` workflow. Tracked as a follow-up; not part of this design.
- **Shared kind cluster across matrix rows.** Caching kind state across jobs is non-trivial; the 3× setup cost is acceptable.
- **Conformance flakiness.** One failure in the last 30 runs (right after the Stack 2 manager-flag startup bug). Not a stabilization priority.
- **`test-e2e-realtor` target.** Unchanged; still runs the real-Tor spec on demand.

## Acceptance criteria

After implementation:

1. `test-e2e.yml` runs 3 parallel matrix rows, each its own kind cluster + ginkgo label filter.
2. `onionbalance_test.go` has 3 sibling `Describe(..., Ordered, ...)` blocks; no single block contains more than 4 specs.
3. Mutator specs live in Block B (or a clearly-named alternative block), labeled with `ob-failover`.
4. `make test-e2e` runs the full suite locally, unchanged behavior.
5. `E2E_LABEL_FILTER='onionbalance' make test-e2e-suite` runs only Mode B specs locally.
6. A simulated Mode B failure (e.g., breaking the HSDir propagation budget) produces `e2e (onionbalance-base)` failed + `e2e (core)` passed + `e2e (onionbalance-mutations)` passed — never a single "E2E Tests" failure that obscures which area broke.
7. A failed matrix row uploads a `e2e-<suite>-diagnostics` artifact containing controller log + suite-namespace describe + chutney log + ginkgo JSON report.
8. Step summary on every job page shows per-spec status table.

## Risks

- **Increased CI compute.** ~30% more total compute (3 kind setups). Wall-clock unchanged or improved (parallel). Acceptable.
- **Setup-duplication cost masking actual problems.** If Block B's BeforeAll fails because of a real bug in the operator, we only see it once. Mitigated by the diagnostic artifact upload.
- **Block ordering assumptions creeping back.** Mitigated by invariant #1 + the cross-namespace fixture for Block B (no name collision with Block A's `ha-gw`).
