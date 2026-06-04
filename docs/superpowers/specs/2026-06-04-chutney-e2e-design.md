# Chutney-backed e2e test suite (design)

Replace the public-Tor-network dependency in the e2e suite with a private chutney-managed Tor network running in the kind cluster. Keep ONE dedicated `make test-e2e-realtor` target that exercises a single dataplane fetch against the real Tor network on demand.

Why: every current e2e test depends on the public Tor network for descriptor publication + lookup. That window is 10–15 minutes per cycle and stochastic, which makes the suite slow (~25–40 min for a full run) and flaky (the HA initial-fetch test and the dataplane test both routinely time out or pass nondeterministically). Chutney is the Tor Project's own tool for spinning up a private Tor network for testing; with `TestingTorNetwork 1` enabled, descriptor cycles drop from 5–15 min to 20–60 s. End-state: full e2e run in ~5 min, no descriptor-cycle flakes.

## Upstream constraints

Verified against `github.com/torproject/chutney`, the chutney README + `lib/chutney/TorNet.py` + `torrc_templates/authority.i`, and onionbalance's chutney usage (`github.com/torproject/onionbalance/test/functional/util.py`).

| Constraint | Source | Consequence for our design |
|---|---|---|
| Chutney binds tor processes to `CHUTNEY_LISTEN_ADDRESS` (default `127.0.0.1`). **The address is baked into authority certificates at `./chutney configure` time**, not just torrc. | `lib/chutney/TorNet.py` — `'ip': os.environ.get('CHUTNEY_LISTEN_ADDRESS', '127.0.0.1')` | All chutney processes must be in the same network namespace AND `CHUTNEY_LISTEN_ADDRESS` must be set to the chutney pod's IP **before** `configure` runs. We use the downward API to surface the Pod IP and rebind there. |
| External tor processes (i.e. our operator-deployed pods + the test SOCKS client) join the chutney network via `TestingTorNetwork 1` + `DirAuthority <line>` torrc lines, extracted from any chutney node's generated torrc. | Chutney source, tor manpage: "TestingTorNetwork may only be set when using a non-default set of DirServers." | Test harness extracts the `DirAuthority` block from `/chutney/net/nodes/000c/torrc`, packs it into a ConfigMap, mounts it into the operator + every Tor client pod, and Tor's `%include` directive splices it into the rendered torrc. |
| `./chutney verify` is the canonical readiness gate — actually attempts SOCKS traffic to a hidden service rather than just polling bootstrap progress. | `tools/test-network.sh`, README | Pod readiness probe is `./chutney verify` (one-shot, exit 0 = ready). Bootstrap ceiling ~120 s (`CHUTNEY_START_TIME` default). |
| `CHUTNEY_TOR_SANDBOX=1` is the default on Linux; K8s default seccomp profiles abort tor when sandbox is enabled. | Chutney README, K8s seccomp docs | Container env sets `CHUTNEY_TOR_SANDBOX=0`. |
| Chutney uses 20-second voting interval with `TestingV3AuthInitialVotingInterval=20`. HS descriptor publish + propagation drops to ~30–60 s after the HS tor process bootstraps. | `torrc_templates/authority.i` | Per-test `Eventually` timeouts drop from 15 min (real Tor) to 2 min (chutney) with comfortable headroom. |
| No upstream chutney container image. Chutney is actively used in CI but rarely released; pin to a specific upstream commit. | `hub.docker.com/u/thetorproject` (chutney absent); chutney commit log | We build `images/chutney/` from `debian:bookworm-slim` + `tor` + Python + a pinned chutney checkout. Same discipline as the in-repo `images/mkp224o/`. |
| Chutney IPv6 support is "work in progress". | Chutney README | Force `ClientUseIPv6 0` alongside the `TestingTorNetwork 1` block. |
| Each chutney `configure` regenerates fresh node keys and embeds the current `CHUTNEY_LISTEN_ADDRESS` in certs. Preserving `net/nodes/` between runs *would* allow restart-without-reconfigure, but the bootstrap cost is only ~2 min. | Chutney source | We accept the bootstrap cost per e2e run; no PVC for chutney state in v1. |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ kind cluster                                                 │
│                                                              │
│ ns: tor-gateway-chutney                                      │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ Pod chutney (single pod, ~7 tor processes inside)        │ │
│ │   image: images/chutney/ (debian + tor + chutney)        │ │
│ │   env: CHUTNEY_LISTEN_ADDRESS=$POD_IP (downward API)     │ │
│ │   env: CHUTNEY_TOR_SANDBOX=0                             │ │
│ │   command: configure k8s-mini → start → wait_for_bootstrap│
│ │   readiness probe: ./chutney verify                      │ │
│ │   /chutney/net/nodes/000c/torrc contains the full        │ │
│ │     `DirAuthority …` block (3 lines)                     │ │
│ │   resources: requests 500m CPU 1Gi mem,                  │ │
│ │              limits 1 CPU 2Gi mem                        │ │
│ └──────────────────────────────────────────────────────────┘ │
│   Service chutney-network ClusterIP                          │
│     ports cover the OR + Dir ports of all chutney nodes      │
│                                                              │
│ ns: tor-gateway-system                                       │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ Deployment tor-gateway-controller-manager                │ │
│ │   args (e2e only): --testing-tor-network-file=           │ │
│ │     /etc/tor-gateway/testing-network/fragment            │ │
│ │   volumeMount: ConfigMap tor-gateway-testing-network at  │ │
│ │     /etc/tor-gateway/testing-network                     │ │
│ │ ConfigMap tor-gateway-testing-network                    │ │
│ │   data["fragment"] = "TestingTorNetwork 1\n              │ │
│ │                       ClientUseIPv6 0\n                  │ │
│ │                       DirAuthority auth0 …\n             │ │
│ │                       DirAuthority auth1 …\n             │ │
│ │                       DirAuthority auth2 …\n"            │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                              │
│ ns: <test-ns> (per-test)                                     │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ ConfigMap tor-gateway-testing-network (copied per-ns)    │ │
│ │ Operator-deployed Tor pods (Mode A and Mode B)           │ │
│ │   torrc (generated) ends with:                           │ │
│ │     %include /etc/tor-gateway/testing-network/fragment                   │ │
│ │ Tor SOCKS test client pod                                │ │
│ │   torrc inline + %include /etc/tor-gateway/testing-network/fragment      │ │
│ └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

**Key choices:**

- **One pod for chutney, not a StatefulSet.** Chutney's tor processes must share a network namespace. Certificate IPs are baked at `configure` time, so persistent state would only help across pod restarts — and the e2e run lifecycle creates the pod fresh per suite invocation.
- **`CHUTNEY_LISTEN_ADDRESS = $POD_IP`** via downward API. The Service in front routes by ClusterIP, but tor processes bind to (and authority certs embed) the Pod IP. Other pods reach the chutney network via the Pod IP directly; the Service is a convenience for the kubectl exec path in BeforeSuite.
- **`networks/k8s-mini` flavor:** custom flavor checked into `images/chutney/networks/k8s-mini/`. 3 authorities + 3 relays + 1 reference HS (the HS exists only as the readiness target for `./chutney verify`; the operator deploys all other HSes the tests exercise). ~7 tor processes, ~150–300 MB memory.
- **No frontend↔backend in-cluster Tor traffic.** Operator pods publish to the chutney HSDirs; the test SOCKS client fetches via the same chutney network. All HS-network traffic goes through the chutney pod.

## Operator changes

**New manager flag** (`cmd/manager/main.go`):

```go
var testingTorNetworkFile string
flag.StringVar(&testingTorNetworkFile, "testing-tor-network-file", "",
    "if set, path to a file containing DirAuthority lines that will be "+
    "appended (via Tor's %include directive) to every Tor pod's torrc, "+
    "along with TestingTorNetwork 1. Test-only.")
```

When empty (default), the operator behaves exactly as today — production-safe, zero divergence. When non-empty, the manager copies the flag value into `GatewayReconciler.TestingNetworkIncludePath` at startup. The reconciler does NOT read the file — the path is a string that the torrc renderer emits verbatim into a `%include <path>` directive. Tor reads the file at pod-startup time. Consequence: if the chutney dirauths change, only the Tor pods need restart (kubelet ConfigMap sync will already have replaced the file content) — the operator can keep running.

**`TorrcConfig` extension** (`internal/tor/torrc.go`):

```go
// TestingNetworkIncludePath, when non-empty, makes the renderer append
//   TestingTorNetwork 1
//   ClientUseIPv6 0
//   %include <TestingNetworkIncludePath>
// to the rendered torrc. Tor refuses TestingTorNetwork 1 without a
// non-default DirServer set, so the %include must point at a file
// containing at least one DirAuthority line. Production deployments
// leave this field empty.
TestingNetworkIncludePath string
```

**Render order:** The override lines go **before** the `HiddenService*` block. Order matters for tor parsing: `TestingTorNetwork 1` must precede HS directives so that the relaxed timeouts apply during HS publication.

**Renderer test additions** (`internal/tor/torrc_test.go`):

- `TestingNetworkIncludePath` empty → output byte-identical to a baseline render with the field unset (regression guard).
- `TestingNetworkIncludePath` set to `/etc/tor-gateway/testing-network/fragment` → output contains `TestingTorNetwork 1`, `ClientUseIPv6 0`, and `%include /etc/tor-gateway/testing-network/fragment` in that order, all before `HiddenServiceDir`.

**Plumbing the flag value into every torrc:**

- `GatewayReconciler.TestingNetworkIncludePath string` (loaded once at startup from the flag value).
- Every place that builds a `TorrcConfig` gets the field piped through:
  - `BuildTorrcConfigMap` (Mode A) — `internal/controller/gateway_resources.go`
  - `BuildBackendTorrcConfigMap` (Mode B backends) — `internal/controller/gateway_resources_ha.go`
  - Mode B frontend's torrc — currently a `const string` (`frontendTorrcContent`); becomes a builder that conditionally appends the same three lines.
- Backend torrc must `%include` the chutney fragment too so backend tor processes join the chutney network.
- Frontend tor (vanilla, control-port + cookie auth) must `%include` the fragment so the local tor onionbalance controls also joins chutney.

**No changes to the OBP / TSP / TCAP CRDs.** Testing config is operator-level, not a user-facing API.

**`%include` mechanics.** Tor's `%include <path>` directive is documented at `tor(1)` "INCLUDE FILES". It accepts a file path; the file is parsed inline as if its content appeared at that point in the torrc. The chutney fragment file is mounted at the same path inside every Tor pod (frontend, backend, Mode A standalone, and the test SOCKS client) so the `%include` directive resolves consistently. The mount path is fixed: `/etc/tor-gateway/testing-network/fragment`.

**ConfigMap distribution to test namespaces:**

The chutney ConfigMap lives in `tor-gateway-system` (the operator's namespace). Operator-deployed Tor pods need access to it from arbitrary test namespaces. ConfigMaps cannot be mounted cross-namespace in Kubernetes; the harness must copy the ConfigMap into each test namespace. Two viable patterns:

- **Test-time copy in BeforeAll/BeforeEach (chosen):** A new helper `copyChutneyFragmentTo(ns)` in `test/e2e/` runs `kubectl get cm -n tor-gateway-system tor-gateway-testing-network -o yaml | sed 's/namespace: .*/namespace: <ns>/' | kubectl apply -f -` once per test namespace. The operator's pod-template volumes reference `tor-gateway-testing-network` (in the local namespace).
- **Operator copies on Gateway reconcile (rejected):** Complicates the operator with test-only behaviour. The cross-namespace copy is a test concern, not an operator concern.

## e2e harness flow

**`make test-e2e` (default, chutney-backed):**

`test/e2e/e2e_suite_test.go` `BeforeSuite`:

1. (existing) Build per-pod images: `image-router`, `image-tor-init`, `image-tor`, `image-obrefresh`, `image-onionbalance`, kind-load each.
2. **NEW** Build `image-chutney`, kind-load.
3. (existing) Set up kind, install Gateway API CRDs, install our CRDs.
4. **NEW** Deploy chutney pod + Service in `tor-gateway-chutney` ns. Wait for readiness probe (`./chutney verify` exit 0). Timeout 3 min.
5. **NEW** Extract the `DirAuthority` block from the chutney pod:

   ```sh
   kubectl exec -n tor-gateway-chutney chutney -- sh -c "
       printf 'TestingTorNetwork 1\nClientUseIPv6 0\n';
       grep '^DirAuthority ' /chutney/net/nodes/000c/torrc
   "
   ```

   Captured stdout into a Go `string` in the test process.
6. **NEW** Create ConfigMap `tor-gateway-testing-network` in `tor-gateway-system` with `data["fragment"] = <captured string>`.
7. (existing) `make deploy IMG=...` deploys the operator.
8. **NEW** Patch the operator Deployment with two operations: (a) append `--testing-tor-network-file=/etc/tor-gateway/testing-network/fragment` to args, (b) add a Volume sourced from the ConfigMap and a VolumeMount at `/etc/tor-gateway/testing-network`. Wait for rollout (2-min timeout).
9. (existing) Patch the operator with `--cluster-pod-cidrs=10.244.0.0/16` and the HA image flags.

`AfterSuite`:

- (NEW) Unpatch the operator: remove the `--testing-tor-network-file` arg and the testing-network volume mount. Wait for rollout. (Simpler alternative: undeploy operator, since the suite cleans up CRDs next anyway.)
- (NEW) Delete the `tor-gateway-chutney` namespace (cascades pod, Service, etc.).
- (existing) Undeploy operator, uninstall CRDs.

**Per-test changes:**

- New helper `chutneyTorClient(ns string)` returns a `corev1.Pod` manifest for the test SOCKS client where:
  - An emptyDir is mounted at `/var/lib/tor`.
  - The chutney fragment ConfigMap is mounted at `/etc/tor-gateway/testing-network/`.
  - The pod's torrc (rendered into a small `<ns>-tor-client-torrc` ConfigMap by the helper) contains:

    ```
    SocksPort 0.0.0.0:9050
    DataDirectory /var/lib/tor/data
    %include /etc/tor-gateway/testing-network/fragment
    ```

  - The torrc ConfigMap is mounted at `/etc/tor/torrc` (single-file mount).
- Each test's BeforeAll (or BeforeEach) calls `copyChutneyFragmentTo(ns)` before creating any Tor pods in the test namespace.
- Test bodies are otherwise unchanged. Same `Eventually(fetchOverTor(...))` calls, same assertions. Only the timeout values shrink:
  - Initial HS fetch: `15m` → `2m` (chutney publishes in ~30–60 s).
  - Onionbalance scale-down: `15m` → `3m` (still gives onionbalance's `PUBLISH_DESCRIPTOR_CHECK_FREQUENCY=5*60` headroom — but with `TestingTorNetwork 1` the inherited timeouts drop, so 3 min is generous).
  - Backend pod kill: `2m` → `1m`.

**Failure modes:**

| Failure | Detection | Outcome |
|---|---|---|
| chutney pod never reaches `verify` exit 0 within 3 min | Readiness probe timeout | BeforeSuite fails with chutney pod logs |
| `DirAuthority` block empty / missing after extraction | `len(captured) == 0` or no `DirAuthority` lines | BeforeSuite fails — defensive guard |
| operator never picks up the flag | post-patch rollout timeout 2 min | BeforeSuite fails with manager logs |
| chutney pod crashes mid-suite | next test's Tor pod loses authority connectivity → fetch times out | The affected test fails; chutney crash visible in AfterSuite pod logs |
| Test ns ConfigMap copy fails | `kubectl apply` non-zero exit | BeforeAll fails per-test |

## Real-Tor smoke target

**`make test-e2e-realtor` (new):**

```make
.PHONY: test-e2e-realtor
test-e2e-realtor: setup-test-e2e manifests generate fmt vet
	KUBEBUILDER_ASSETS="..." go test -tags=e2e -timeout 30m ./test/e2e/ -v -ginkgo.v \
	  -ginkgo.label-filter='realtor-smoke'
```

- Runs only specs labelled `realtor-smoke`. Exactly ONE test gets the label initially: the dataplane `/` + `/api` fetch from `test/e2e/dataplane_test.go`.
- Does NOT deploy chutney, does NOT patch the operator with `--testing-tor-network-file`. The operator runs production-default.
- Tor SOCKS client pod uses default Tor dirauths (the real Tor network — no `%include`).
- 15-min `Eventually` budget for the real-Tor descriptor cycle.
- Invoked manually or as a nightly CI cron, never on PRs.

**`BeforeSuite` branching.** The harness needs to know which mode it's in. The cleanest path: a `TOR_GATEWAY_E2E_MODE` env var (`chutney` default, `realtor` for the smoke target). `BeforeSuite` reads it and conditionally runs the chutney-related setup steps. `realtor-smoke` Ginkgo label is what actually gates the test runs.

## Image build pipeline

**New image: `images/chutney/`.**

`images/chutney/Dockerfile`:

```dockerfile
# Two-stage. Build layer pins chutney to a known-good commit; runtime is
# debian:bookworm-slim + tor + Python.
FROM debian:bookworm-slim AS build
ARG CHUTNEY_REF=main
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git clone --depth 1 --branch ${CHUTNEY_REF} \
      https://github.com/torproject/chutney /chutney

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tor python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 65532 nonroot && useradd -u 65532 -g 65532 -M -s /sbin/nologin nonroot
COPY --from=build /chutney /chutney
COPY entrypoint.sh /entrypoint.sh
COPY networks/k8s-mini /chutney/networks/k8s-mini
RUN chown -R 65532:65532 /chutney /entrypoint.sh \
 && chmod 0555 /entrypoint.sh
USER 65532:65532
ENV CHUTNEY_DATA_DIR=/data \
    CHUTNEY_TOR_SANDBOX=0
WORKDIR /chutney
ENTRYPOINT ["/entrypoint.sh"]
```

`images/chutney/entrypoint.sh`:

```sh
#!/bin/sh
set -eu
: "${POD_IP:?POD_IP env var required (use downward API)}"
export CHUTNEY_LISTEN_ADDRESS="${POD_IP}"
./chutney configure networks/k8s-mini
./chutney start networks/k8s-mini
./chutney wait_for_bootstrap networks/k8s-mini
# Keep the pod alive after bootstrap; readiness probe re-verifies on demand.
exec tail -f /dev/null
```

`images/chutney/networks/k8s-mini`: a Python script (chutney's network-flavor format) describing 3 authorities + 3 relays + 1 reference HS. Modelled on `chutney/networks/hs-v3` with the client + HS instance counts trimmed.

**Makefile additions:**

```make
CHUTNEY_IMG ?= $(REGISTRY)/tor-gateway-chutney:$(IMAGE_TAG)

.PHONY: image-chutney
image-chutney:
	$(CONTAINER_TOOL) build -t $(CHUTNEY_IMG) images/chutney
```

`image-chutney` is added to the `images:` aggregate target so a single `make images` builds it.

**Excluded from the release workflow.** The chutney image is e2e-only — never published, never cosign-signed, never offered to users. `.github/workflows/release.yml` does NOT include `chutney` in its per-image build matrix.

**`README.md` cosign verification list:** chutney is NOT added (it isn't published).

## Helm chart changes

`charts/tor-gateway/values.yaml`:

```yaml
# TEST ONLY. Do not enable in production: a Gateway provisioned while
# this is enabled will publish .onion addresses that only the test chutney
# network can resolve. They will NOT be reachable from the public Tor
# network.
testingTorNetwork:
  enabled: false
  # ConfigMap (must exist in the release namespace) whose data["fragment"]
  # field contains the TestingTorNetwork 1 + DirAuthority block.
  configMapName: ""
```

The manager Deployment template conditionally:

- Appends `--testing-tor-network-file=/etc/tor-gateway/testing-network/fragment` to args.
- Adds a `Volume` sourced from the ConfigMap and a `VolumeMount` at `/etc/tor-gateway/testing-network`.

A new helm-lint check (or a custom test in `charts/tor-gateway/tests/`) asserts that `values.yaml` ships with `testingTorNetwork.enabled: false`.

## Security documentation

`SECURITY.md` gets a new "Testing mode" section between the "Hardening defaults" and "Known gaps" sections:

```markdown
### Testing mode (chutney)

The operator accepts a `--testing-tor-network-file=<path>` flag that
splices `TestingTorNetwork 1` + a caller-provided `DirAuthority` block
into every Tor pod's torrc. This exists to let our e2e tests bootstrap
against a private chutney-managed Tor network, with ~30-second
descriptor publication instead of the public Tor network's 5-15 minute
cycle.

**Never enable this in production.** When the flag is set, every
`.onion` the operator publishes is resolvable only by clients
participating in the configured testing network. A production cluster
that accidentally enabled the flag would silently publish unreachable
addresses.

The Helm chart's `testingTorNetwork.enabled` value defaults to `false`.
Explicit opt-in is required.

Do NOT reuse the same `.onion` keys between testing and production
deployments — once a key has been published to a chutney testing
network, it should be retired.
```

`docs/PLAN.md` gets a new bullet under "Implemented and tested":

> - e2e suite runs against an in-cluster chutney private Tor network; one `make test-e2e-realtor` smoke target covers the production path against the real Tor network.

## Out of scope (v2+)

- **Persistent chutney state.** A PVC that preserves `net/nodes/` across e2e runs would shave ~2 min off each run. Not worth the complexity for v1; revisit if the e2e suite grows >10 min on top of bootstrap.
- **Chutney for unit / envtest.** Unit and envtest already run without Tor at all. No value.
- **IPv6.** Chutney IPv6 is "work in progress" upstream. We force `ClientUseIPv6 0`.
- **Multiple parallel chutney networks (sharded tests).** All current e2e tests share a single chutney instance. Parallel sharding adds substantial complexity for a suite that's already <5 min.
- **Chutney exposed as a developer-facing convenience.** This is test infrastructure, not a feature. We document how the e2e harness uses it but do NOT support running chutney standalone for ad-hoc developer use.

## Repository layout impact

| Path | Action |
|---|---|
| `images/chutney/Dockerfile` | Create |
| `images/chutney/entrypoint.sh` | Create |
| `images/chutney/networks/k8s-mini/network` | Create (chutney flavor file) |
| `Makefile` | Add `CHUTNEY_IMG`, `image-chutney`, `test-e2e-realtor` targets. Include in `images:`. |
| `cmd/manager/main.go` | Add `--testing-tor-network-file` flag; load into reconciler field. |
| `internal/controller/gateway_resources.go` | Wire `TestingNetworkIncludePath` into `BuildTorrcConfigMap` (Mode A). |
| `internal/controller/gateway_resources_ha.go` | Same for `BuildBackendTorrcConfigMap` and `BuildFrontendTorrcConfigMap` (frontend torrc becomes a builder, not a const). |
| `internal/controller/gateway_controller.go` | Add `TestingNetworkIncludePath string` field on `GatewayReconciler` (loaded once from the flag value at startup); pass through where torrc is built. |
| `internal/tor/torrc.go` | Add `TestingNetworkIncludePath` field on `TorrcConfig`; conditionally emit `TestingTorNetwork 1` + `ClientUseIPv6 0` + `%include <path>`. |
| `internal/tor/torrc_test.go` | Add empty-vs-set assertions. |
| `test/e2e/e2e_suite_test.go` | Add chutney bootstrap + dirauth extraction + operator patch. Branch on `TOR_GATEWAY_E2E_MODE`. |
| `test/e2e/*.go` (all tests) | Replace ad-hoc tor-client manifests with a shared `chutneyTorClient(ns)` helper. Drop initial `Eventually` timeouts from 15m to 2m / 3m / 1m. Tag one test `Label("realtor-smoke")`. |
| `test/e2e/copy_fragment.go` | New helper `copyChutneyFragmentTo(ns)`. |
| `charts/tor-gateway/values.yaml` | Add `testingTorNetwork.enabled: false` (with warning comment). |
| `charts/tor-gateway/templates/deployment.yaml` | Conditional volume + flag injection. |
| `charts/tor-gateway/tests/values_test.yaml` (or equivalent) | Assert `testingTorNetwork.enabled` is `false` by default. |
| `SECURITY.md` | Add "Testing mode (chutney)" section. |
| `docs/PLAN.md` | Mark chutney e2e + realtor smoke target shipped. |
| `.github/workflows/release.yml` | NOT modified — chutney is not a published image. |
| `README.md` | NOT modified — chutney is not in the cosign verification list. |
