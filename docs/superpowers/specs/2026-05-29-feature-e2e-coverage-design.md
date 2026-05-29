# Feature E2E / Conformance Coverage — Design

**Status:** approved, pending implementation plan
**Date:** 2026-05-29

## Problem

Three shipped features have **no real-cluster coverage** — only unit + envtest, where the relevant behavior is faked or absent:

- **Cross-namespace ReferenceGrant gating** — envtest covers the controller `ResolvedRefs` status and the router gate in isolation, but nothing exercises the full controller→status→router→data-plane chain on a cluster.
- **mkp224o vanity harvest** — envtest **fakes the Job** (no kubelet/Job controller), so the real Job running mkp224o, `vanity-finalize` writing the Secret, and the operator promoting/publishing the key is untested. (The v0.2.0 `-march=native` SIGILL would have been caught by such a test.)
- **v3 client auth (`TorClientAuthPolicy`)** — Strict/Audit modes and client-key mounting have zero e2e/conformance coverage.

envtest can run neither Jobs nor real Tor circuits. This work adds **five** real-cluster tests across the existing e2e (`//go:build e2e`, kind) and conformance (`//go:build conformance`, kind) harnesses.

## Goals

- ReferenceGrant cross-ns: status transition (deny→allow) **and** real-Tor routing.
- Vanity harvest: end-to-end (real Job → published vanity `.onion`).
- v3 client auth: end-to-end (Strict actually enforced over a real circuit).
- Reuse existing harness patterns: `applyYAML`/`getJSONPath` (kubectl shell-out), `fetchOverTor` (in-cluster Tor SOCKS client), the conformance controller-runtime client, and `buildAndLoadImage`.

## Non-goals

- **NetworkPolicy emission** — `SECURITY.md`/PLAN.md list it as a control, but the controller emits none. Not an e2e gap (the feature isn't built); separate follow-up to implement or correct the docs.
- **`retainPreviousKeys`** — a `TorServicePolicy` CRD field with no controller logic (dead field); separate follow-up.
- **Cross-namespace `clientsSecretRef`** — already descoped (needs a Secret-copy subsystem).
- **Production code changes** — these are test-only additions. The single non-test edit is registering `gwv1beta1` in the conformance suite's `newClient` (test helper).

## The five additions

### #1 — Operator e2e: ReferenceGrant `ResolvedRefs` (no Tor)
New `test/e2e/referencegrant_test.go` (`//go:build e2e`), `Describe("ReferenceGrant", Label("referencegrant"))`. Reuses the BeforeSuite-deployed operator (manager only — no router/Tor). Create an isolated gateway namespace + a separate backend namespace + a dedicated GatewayClass + a Gateway. `applyYAML` an HTTPRoute whose backendRef sets `namespace: <backend-ns>`; assert via `getJSONPath` Eventually that the parent `ResolvedRefs` is `False`/`RefNotPermitted`. `applyYAML` a `ReferenceGrant` in the backend ns (`from` HTTPRoute/gw-ns → `to` Service); assert `ResolvedRefs` flips to `True`. No backend Service needed (gate on the grant, not existence). jsonpath: `.status.parents[?(@.controllerName=="torgateway.io/gateway-controller")].conditions[?(@.type=="ResolvedRefs")].status` and `.reason`.

### #2 — Conformance: `ResolvedRefs` contract
Extend `test/conformance/conformance_test.go` (`//go:build conformance`) with `TestRouteResolvedRefsContract`. One helper change: add `gwv1beta1.Install(scheme)` to `newClient` so it can create `ReferenceGrant`. Using the controller-runtime client: create a cross-ns route, `waitCondition` for the parent `ResolvedRefs=RefNotPermitted`, create the grant, poll for `ResolvedRefs=True`. Add a small reader that extracts our parent's conditions from `route.Status.Parents`. Overlaps #1 in assertion but lives in the separate conformance "status-contract" gate (intentional, per the project's test strategy).

### #3 — Real-Tor e2e: cross-ns routing (control + gated path)
New `test/e2e/dataplane_crossns_test.go` (`//go:build e2e`), reusing `buildAndLoadImage` (router/tor-init/tor) + the `fetchOverTor` curl-over-SOCKS pattern. Gateway namespace with a `local` http-echo backend (body `local`) + a separate backend namespace with a `remote` backend (body `remote`). One Gateway/.onion; HTTPRoute with `/local`→local (same-ns) and `/remote`→remote (cross-ns). Sequence: (a) `Eventually /local == "local"` (proves the circuit is live); (b) `Consistently /remote` empty (denied — no grant); (c) `applyYAML` the ReferenceGrant; (d) `Eventually /remote == "remote"`. Exercises the full chain: controller flips `ResolvedRefs` on grant-add (the ReferenceGrant watch) → router rebuilds → cross-ns backend becomes routable.

### #4 — Operator e2e: vanity harvest (no Tor)
New `test/e2e/vanity_test.go` (`//go:build e2e`), `Describe("Vanity harvest", Label("vanity"))`. BeforeAll: `buildAndLoadImage` the `mkp224o` + `vanity-finalize` `:dev` images (operator flag defaults point at `:dev`; tag≠latest ⇒ `IfNotPresent` ⇒ uses the loaded images). Dedicated GatewayClass. `applyYAML` a key-less Gateway **with annotation `torgateway.io/await-vanity: "true"`** (sidesteps the apply-order race *and* exercises the annotation) + a `TorServicePolicy{vanityPrefix: "a"}` (1 char → seconds). Assert via `getJSONPath` Eventually: the `<gw>-vanity` Job appears, `status.addresses[0].value` matches `^a[a-z2-7]{55}\.onion$`, `Programmed=True`. No Tor circuit (assert the published address, not reachability). Proves the real Job + portable image + promotion chain; a broken/SIGILL image ⇒ Job crashloops ⇒ no publish ⇒ failure.

### #5 — Client-auth e2e (full, real Tor)
New `test/e2e/clientauth_test.go` (`//go:build e2e`). v3 client-auth formats (`internal/tor/clientauth.go`): the service-side Secret holds, per label, a **52-char RFC4648 base32 x25519 public key**; tor-init writes `authorized_clients/<label>.auth` = `descriptor:x25519:<pub>`. The client needs `<onion>:descriptor:x25519:<base32 private key>` in its `ClientOnionAuthDir`.
- **Keypair:** generate an X25519 pair at test time in Go (`crypto/ecdh` + `base32.StdEncoding.WithPadding(NoPadding)`; 32 bytes → 52 chars, matching the operator's validator). Pub → the service Secret; priv → the authorized client's auth file.
- **Service:** a backend + Gateway + HTTPRoute + a Secret `{<label>: base32(pub)}` + a `TorClientAuthPolicy{mode: Strict, clientsSecretRef: <secret>}`.
- **Two Tor SOCKS client pods** (robust positive+negative, mirroring #3): an **authorized** client whose `ClientOnionAuthDir` contains the `.auth_private`, and an **unauthorized** client with none. Assert `Eventually` the authorized client fetches the backend body (circuit live AND auth passes), and `Consistently` the unauthorized client gets nothing (proves Strict is enforced, not merely an open service).
- Loads router/tor-init/tor via `buildAndLoadImage`.

## Shared harness concerns

- **Build tags / targets:** e2e tests (`#1,#3,#4,#5`) run via `make test-e2e` (KIND_CLUSTER `tor-gateway-test-e2e`); the operator is deployed in BeforeSuite (manager image). `#3/#4/#5` load their extra images via `buildAndLoadImage` in their own BeforeAll. `#2` runs via `make test-conformance`. **No Makefile changes** (targets glob `./test/e2e/` and `./test/conformance`).
- **Helper reuse:** `buildAndLoadImage` is a package-level helper (reuse directly). `fetchOverTor` is currently a local closure in `dataplane_test.go`; `#3/#5` define their own small SOCKS-curl closure (or the plan extracts a shared helper — plan's call).
- **Isolation:** each Describe uses its own namespace(s) and a **dedicated GatewayClass name** (`tor-gateway-rg`, `tor-gateway-vanity`, etc.) to avoid the cross-spec collision class of bug.
- **Runtime:** `#1`, `#4` fast (~1–2 min); `#2` fast; `#3`, `#5` slow (real Tor descriptor publish, ~8–10 min each).

## TDD note

These verify **already-shipped** behavior, so each should pass green against the current operator; the meaningful "red" is historical (before the features: cross-ns routed ungated, vanity unguarded, no client auth). The plan will include, per test, a sanity step confirming the test actually exercises the gate (e.g., that `#3`'s `/remote` is genuinely empty before the grant, that `#4` would fail on a crashlooping image).

## Verification

`make test-e2e` (runs `#1,#3,#4,#5` + existing e2e) and `make test-conformance` (runs `#2` + existing) on a kind cluster. `make test` and `make lint` must stay green (test-only changes; the conformance `newClient` scheme tweak is test code). Document the slow runtime of `#3/#5`.

## Implementation surface

- **New:** `test/e2e/referencegrant_test.go`, `test/e2e/dataplane_crossns_test.go`, `test/e2e/vanity_test.go`, `test/e2e/clientauth_test.go`.
- **Modified:** `test/conformance/conformance_test.go` (add `TestRouteResolvedRefsContract`; `newClient` scheme += `gwv1beta1`; small route-parent condition reader).
- The plan should confirm whether `buildAndLoadImage`/`fetchOverTor` are reused directly or a shared `fetchOverTor` helper is extracted.
