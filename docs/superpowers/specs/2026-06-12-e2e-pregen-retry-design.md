# E2E Chutney Pre-Gen + Layered Retries — Design

**Date:** 2026-06-12
**Status:** Design approved; ready for plan.

## Problem

After the 2026-06-08 stable-e2e-pipeline work (matrix split, warmup, `--flake-attempts=2`),
the latest run on `main` (`f16e3cd`, run 27158888001) still failed both Mode B rows — and
both failures were in **setup**, not in specs:

- `onionbalance-base`: the chutney pod never became Ready within 18 minutes
  (`chutney_test.go:71`, BeforeSuite). The operator was never exercised.
- `onionbalance-mutations`: chutney came up, but the Mode B fixture's `.onion`
  warmup (10m) and Gateway-publish wait (60s) timed out on **both** flake
  attempts (`onionbalance_test.go:224`/`:205`, BeforeAll).

Two structural facts explain why the existing mitigations cannot catch this:

1. `ginkgo --flake-attempts` retries **specs**; it does not re-run a failed
   `BeforeSuite`, and a failed `BeforeAll` retry re-enters with the same broken
   fixture state. The retry knob is at the wrong granularity for the observed
   failure modes.
2. The root cause is resource starvation: an 8-node Tor network bootstrapping
   (key gen → descriptor upload → 3 dirauths voting → bandwidth self-test) on a
   2-vCPU `ubuntu-latest` runner, three times per push (once per matrix row).

## Goals

1. The pipeline tests **everything on every push** — no demotion of Mode B to a
   nightly tier. Correctness over wall-clock time.
2. Chutney's nondeterministic bootstrap is paid **once per CI run** (pre-gen
   job), not three times; matrix rows consume the result.
3. Every remaining flake point is retried at **its own granularity**, bounded,
   and **loudly visible** (step summary + `::warning::` annotations). A
   chronically-retrying path must read as a bug to fix, never as silence.
4. Assertions that don't need a live Tor network move down to the deterministic
   envtest layer; e2e keeps only the genuinely end-to-end surface.

## Non-goals

- Pipeline speed. Serialized or longer runs are acceptable; the design still
  avoids waste where it's free (build once, bootstrap once).
- Pre-baking network state at **image build** time. Tor consensus documents
  have validity windows; state must be generated fresh per run.
- Fixing the vanity-prefix local flake (mkp224o under load) or promoting
  `realtor-smoke` to a nightly tier. Both noted as follow-ups.

This design supersedes two positions taken in the 2026-06-08 spec: spec-level
retries ("no `--flake-attempts`") were already added by wave 4, and this design
keeps them as one bounded layer among four; and "reducing chutney variability"
was a non-goal there but is the core goal here (pre-gen + 4 vCPU).

## Architecture

Six changes. The first three make chutney state portable and pre-generated;
the rest are retry machinery, relocation, and runner resources.

### Change 1 — Portable network addressing (pinned Service ClusterIP)

A bootstrapped Tor network is welded to the addresses its relays advertise
(`DirAuthority` lines, router descriptors). Today the chutney image templates
those from `POD_IP`, which differs per cluster — state cannot move between
matrix rows.

- All chutney nodes advertise a **pinned Service ClusterIP** (`10.96.77.77`,
  set explicitly via `spec.clusterIP`; kind's service CIDR `10.96.0.0/12` is
  identical in every cluster) instead of `POD_IP`.
- The `chutney-network` Service exposes every node's OR + dir port toward the
  chutney pod.
- External consumers (operator-managed tor pods, tor-client pods) already dial
  whatever the `DirAuthority` fragment says; they transparently go via the VIP.
- The extracted fragment becomes byte-identical across rows and runs.

**Load-bearing risk:** relay↔relay traffic inside the chutney pod now hairpins
through the VIP (pod → Service → same pod). kube-proxy/kindnet handle hairpin
masquerade, but this is the **first thing to verify** in implementation, on a
local kind cluster, before building anything else on top. Fallback if hairpin
misbehaves: alias the VIP on the pod's loopback so intra-pod dials
short-circuit (requires `NET_ADMIN`; only adopted if needed).

### Change 2 — `chutney-pregen` job

New first job in `.github/workflows/test-e2e.yml` (arm64):

1. Build the chutney image; create a throwaway kind cluster (same environment
   as the consumers — no docker-run special-casing); apply the pinned Service +
   chutney pod; wait for `chutney verify` Ready using the Change-4 bootstrap
   retry.
2. `kubectl exec` + tar `/data/nodes`; download.
3. Upload **two artifacts**: the state tar and the chutney image tar (rows run
   the byte-identical image the state was generated with; `docker save`/`kind
   load image-archive` on the consumer side).

Matrix rows declare `needs: chutney-pregen`.

### Change 3 — Warm-start mode in the chutney entrypoint

- Entrypoint: if a seed marker + tar are present under `/data`, untar and start
  the existing nodes (no keygen/reconfigure); else fresh-bootstrap exactly as
  today. One image, two modes; local runs without an artifact are unaffected.
- The e2e `BeforeSuite` injects the seed via `kubectl cp` + marker file when
  `CHUTNEY_SEED_TAR` (path) is set in the environment, before nodes start.
- Dirauths re-vote on startup; with valid keys + recent cached state, a fresh
  consensus forms in 1–2 testing-network voting rounds (~1 min) rather than a
  full bootstrap. Consensus timestamps are valid because the artifact is
  minutes old, produced in the same run by NTP-synced runners.
- **Warm-start is an optimization, never a correctness dependency:** if
  `chutney verify` does not pass within ~5m, log loudly and fall back to a
  fresh bootstrap (with Change-4 retries). Every row can green up with no
  artifact at all.

### Change 4 — Layered, bounded, visible retries

| Layer | Trigger | Action | Cap |
|---|---|---|---|
| Bootstrap | chutney not Ready in ~7m per attempt | delete + recreate the chutney pod (a relay that missed consensus stays missed; a fresh start beats waiting out a stuck 18m budget) | 3 attempts |
| Fixture | Mode B `.onion` warmup fails in `BeforeAll` | tear down + rebuild the whole fixture (fresh namespace, fresh keys) | 1 retry |
| Spec | individual spec failure | existing ginkgo `--flake-attempts` | 2 attempts |
| Job | anything else | shell loop in the workflow re-runs `make test-e2e-suite` after `make cleanup-test-e2e` | 1 retry |

Visibility contract, every layer: a `::warning::` workflow annotation **and** a
step-summary line (e.g. `chutney bootstrap: attempt 2/3`,
`fixture rebuild: tor-gateway-ha-mut`, `passed on flake-attempt 2`,
`suite re-run: attempt 2/2`). The step summary also records the chutney source
(`warm-start (artifact)` vs `fresh bootstrap (fallback)`).

### Change 5 — Relocate non-Tor assertions to envtest

- **NP coverage** (Task 13 spec in `onionbalance_test.go`): move to
  `internal/controller` envtest. envtest has no kubelet, so assert the
  per-Gateway NetworkPolicy selector matches the **pod template labels** of the
  frontend Deployment and the backend StatefulSet — the deterministic
  equivalent of matching live pods. Check overlap with the existing
  `network_policy_test.go` first; extend rather than duplicate.
- **Cross-NS master Secret via ReferenceGrant** (Task 12): move to envtest.
  Assert: Gateway publishes the master `.onion` derived from the cross-NS
  Secret (controller-side read), and the `<gw>-frontend-master-fetch`
  RoleBinding lands in the source namespace.
  **Accepted gap:** envtest does not enforce RBAC for the frontend pod's real
  cross-NS Secret GET; that enforcement is only exercised live. The RoleBinding
  shape is asserted, and the same-NS fetch path is exercised live by the
  `onionbalance-base` row. Recorded here so it's a known, deliberate gap.
- **Stays in e2e:** routing-over-Tor, per-pod key isolation (needs
  kubelet + tor-init), pod-kill, scale-down/up reachability, SIGHUP reload.
- The 3-row matrix survives with slimmer Mode B rows; `ob-crossns` and
  `networkpolicy` labels disappear from the matrix filters once their specs
  move (`onionbalance-mutations` filter reduces to `onionbalance && ob-failover`).

### Change 6 — arm64 runners

All jobs in `test-e2e.yml` (pregen + 3 rows) move from `ubuntu-latest` (2 vCPU)
to `ubuntu-24.04-arm` (4 vCPU / 16 GB, free for public repos). This halves the
resource pressure that causes bootstrap starvation in the first place; pre-gen
and retries then only have to absorb the residual.

Pre-flight verification (before the switch lands):

- The wave-3 sha256 pins on `golang:1.26` and `alpine:3.21` must be
  **manifest-list** digests, not amd64 platform digests — re-pin if they are
  platform-specific, or arm builds fail at `FROM`.
- chutney and mkp224o images must build on arm64 (mkp224o is plain C with no
  amd64-only asm in the default build; verify, don't assume).
- kind v0.31.0 ships arm64 binaries (the workflow already selects by
  `go env GOARCH`).

## Error handling summary

- Pregen job fails after its 3 bootstrap attempts → matrix rows still run;
  `BeforeSuite` sees no artifact and fresh-bootstraps with its own retries.
  (Implementation: `needs.chutney-pregen` must not hard-fail the rows —
  `if: always()` on rows + tolerate a missing artifact download.)
- Warm-start verify fails → loud fallback to fresh bootstrap, same code path as
  no-artifact.
- All four retry layers exhausted → the row fails red. Bounded means a real
  Mode B regression surfaces within one run instead of retrying forever.

## Testing / verification

Local verification is in scope (kind on the development machine):

1. **Hairpin spike first** (gates Change 1): pinned-VIP chutney on local kind;
   `chutney verify` must pass with all nodes advertising the VIP.
2. Warm-start round-trip locally: bootstrap → tar → fresh cluster → seed →
   verify passes within the 5m budget.
3. Relocated envtest specs run in `make test` (they must not need any cluster).
4. Full local e2e runs per row (`E2E_LABEL_FILTER=... make test-e2e-suite`)
   before pushing; `make test-e2e-debug` for post-mortems.
5. CI proof: the workflow's step summaries on the first runs after merge are
   the acceptance evidence (warm-start used, attempt counts, all rows green).

## Out of scope / follow-ups

- `realtor-smoke` nightly cron tier (public-network smoke test).
- Vanity-prefix e2e flake under local machine load (pre-existing).
- Pre-baking consensus into the image (rejected: validity windows).
