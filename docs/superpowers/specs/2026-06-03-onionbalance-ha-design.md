# Onionbalance HA (Mode B) — design

Implement Mode B from the architecture sketch in `docs/PLAN.md`: HA for a Gateway's hidden service via the Tor Project's **onionbalance** daemon. When an `OnionBalancePolicy` targets a Gateway, the operator stops provisioning the standalone Tor pod and instead provisions a single onionbalance frontend Deployment (publishing a user-supplied master `.onion`) plus a backend StatefulSet of N independent Tor instances (each with its own operator-generated key) that publish intro points behind that master address.

This is the last in-scope v1 feature on `docs/PLAN.md`. After this lands, the v1 backlog is empty.

## Upstream constraints we are designing around

Verified against `onionservices.torproject.org/apps/base/onionbalance/{tutorial,design,security,troubleshooting,changelog}`, `spec.torproject.org/rend-spec/hsdesc-encrypt.html`, and the onionbalance source on `gitlab.torproject.org/tpo/onion-services/onionbalance` (current `main`).

| Constraint | Source | Consequence for our design |
|---|---|---|
| Onionbalance `config.yaml` lists one `services[]` entry with `key: <path>` and `instances[].address: <backend>.onion`. No auto-discovery — the daemon only knows about backends listed in the file. | tutorial | `obrefresh` sidecar must own writing `config.yaml` and reloading the daemon. Backends are discovered by the operator and propagated via `config.yaml`, not by the daemon. |
| Backend Tor needs `HiddenServiceOnionbalanceInstance 1` in its `HiddenService` block, plus a file named `ob_config` in the backend's `HiddenServiceDir` containing `MasterOnionAddress <master>.onion`. | tutorial | Backend `tor-init` must derive and write `ob_config` from the master Secret's pubkey. Master `.onion` derivation logic lives in `internal/tor` (reuse Mode A's onion-address helper). |
| Master key file is either PEM (onionbalance's generator format) or raw `hs_ed25519_secret_key` (Tor binary format). Onionbalance derives the pubkey at load time; a paired `hs_ed25519_public_key` file is not required. | `onionbalance/hs_v3/service.py::_load_service_keys` | We accept *only* the Tor binary format — same Secret schema as Mode A's `<gw>-keys`. Requires both `hs_ed25519_secret_key` + `hs_ed25519_public_key` so the operator can validate the pair matches before mounting and derive the master `.onion` cheaply for `Gateway.status.addresses`. |
| Onionbalance reloads `config.yaml` on `SIGHUP` (since v0.2.1). | `common/signalhandler.py`, changelog | `obrefresh` reloads via `SIGHUP` to the pidfile. No process restart required. |
| Backend count is bounded by descriptor size: spec ceiling is 20 intro points (i.e. **10 backends** at the current `N_INTROS_PER_INSTANCE = 2`); the official `onionbalance-config` generator caps at **8**. The widely-cited "12" appears nowhere in current upstream sources. | `spec.torproject.org/rend-spec/hsdesc-encrypt.html`, `onionbalance/hs_v3/params.py`, `config_generator/config_generator.py` | We cap `replicas` at **8** (match upstream tooling); revisit if a real workload pushes against the limit. |
| Default schedule: backend descriptors fetched every 10 min, frontend republish checked every 5 min, frontend descriptor refreshed at least hourly, an instance is considered down after 1 h with no fresh descriptor. | `onionbalance/hs_v3/params.py` | Backend scale changes have an **inherent ~15 min worst-case lag** before clients see them. Surface as a `BackendsRolling` event on the Gateway. |
| Frontend is a single point of failure for descriptor publication. Upstream's own recommended HA story for the *frontend* is "deploy a second frontend with a separate `.onion`" — not multiple frontends sharing one master key. | security page | We pin `frontend.replicas: 1` (K8s pod auto-restart is the v1 mitigation). Multi-frontend is explicitly v2; it would be a different feature (separate addresses), not a knob on this one. |
| `HiddenServicePoWDefensesEnabled 1` on backends is currently **worse than no PoW** — without prioritization the queue degrades to a simple cap, and PoW parameters do not propagate to the frontend superdescriptor. Tracked in upstream onionbalance#13. | `onionservices.torproject.org/technology/security/pow/`, issue tracker | Operator silently force-disables PoW on backends regardless of `TorServicePolicy.poWDefensesEnabled`. Emit `PoWForcedOffInHA` event; surface in OBP `Accepted` condition message. |
| No official Tor Project onionbalance container image. | `containers/howto` page | We build `images/onionbalance/` — same hardening baseline as the existing `images/tor/`. |
| Onionbalance is actively maintained (last release v0.2.4, 2025-04-24; recent commits 2026-02). | changelog | Stable enough to commit to for v1. |

## Architecture

For a Gateway with an attached, Accepted `OnionBalancePolicy`, the operator provisions:

```
┌───────────────────────────────────────────────────────────┐
│ Deployment <gw>-frontend (replicas: 1) — no init          │
│                                                           │
│   container: tor (vanilla — ControlPort + cookie auth)    │
│     - reads /etc/tor/torrc (from ConfigMap)               │
│     - writes data + cookie to /var/lib/tor (emptyDir)     │
│   container: onionbalance (daemon)                        │
│     - reads /etc/onionbalance/config/config.yaml          │
│       (emptyDir, written by obrefresh)                    │
│     - key path references master key Secret               │
│       mounted at /etc/onionbalance/keys (mode 0400)       │
│     - controls local tor at 127.0.0.1:9051 via cookie     │
│     - publishes pidfile at /run/onionbalance              │
│   container: obrefresh (sidecar)                          │
│     - Secret informer scoped to backend label selector    │
│     - debounces by refreshInterval (default 30s)          │
│     - rewrites config.yaml; SIGHUPs onionbalance via pid  │
│                                                           │
│   ServiceAccount: <gw>-frontend                           │
│   Role: get;list;watch on Secrets labeled                 │
│     torgateway.io/gateway=<gw>, role=backend              │
│                                                           │
│   Volumes:                                                │
│     emptyDir: /var/lib/tor      (tor data + cookie)       │
│     emptyDir: /etc/onionbalance/config  (obrefresh write) │
│     emptyDir: /run/onionbalance (pidfile)                 │
│     ConfigMap: /etc/tor          (frontend torrc)         │
│     Secret  : /etc/onionbalance/keys (master key, 0400)   │
└───────────────────────────────────────────────────────────┘

publishes ONE .onion (master)

┌───────────────────────────────────────────────────────────┐
│ StatefulSet <gw>-backend (replicas: N, N ∈ [1, 8])        │
│                                                           │
│ Per-pod Secret <gw>-backend-<i>-keys                      │
│   (operator-generated ed25519; mounted at HSDir)          │
│                                                           │
│ Each pod runs the Mode A stack with two adjustments:      │
│   init: tor-init                                          │
│     - chown/perm fixes on HSDir (existing behaviour)      │
│     - writes ob_config containing MasterOnionAddress      │
│     - writes derived hostname back into the pod's Secret  │
│   container: tor                                          │
│     - torrc includes HiddenServiceOnionbalanceInstance 1  │
│     - PoW directives unconditionally omitted              │
│   container: router (byte-for-byte identical to Mode A)   │
│                                                           │
│   topologySpreadConstraints: hostname,                    │
│     whenUnsatisfiable: ScheduleAnyway (best-effort)       │
└───────────────────────────────────────────────────────────┘

Headless Service <gw>-backends — stable DNS only; obrefresh
discovery uses the Secret label-selector, not the Service.
```

**No frontend↔backend in-cluster traffic.** Each tier publishes descriptors to HSDirs over the public Tor network and is reached only via Tor circuits.

**HTTPRoute fan-out is unchanged.** Every backend pod runs the existing router sidecar (same image, same code path, same ServiceAccount + Role pattern as Mode A) and watches the same HTTPRoutes. Path rules apply identically on every backend.

## CRD changes

The `OnionBalancePolicy` type already exists at `api/v1alpha1/onionbalancepolicy_types.go`. Only two adjustments:

| Field | Before | After |
|---|---|---|
| `spec.replicas` | `kubebuilder:validation:Maximum=12` | `kubebuilder:validation:Maximum=8` |
| `spec.masterKeySecretRef` docstring | "The Secret MUST contain `hs_ed25519_secret_key` and `hs_ed25519_public_key` keys." | Same constraint, but explicit: **Tor binary format** (the bytes of a `HiddenServiceDir`'s key files), **not** the onionbalance PEM format. Matches the existing Mode A `<gw>-keys` schema so users can bootstrap via `mkp224o` or by copying from a prior HSDir. |

No new fields. Explicitly **not** added in v1:

- `backendKeyRetentionPolicy` — backend Secrets are owned by the Gateway and garbage-collected with it.
- `frontendReplicas` — pinned at 1; multi-frontend is v2.
- PoW knob — controlled exclusively by `TorServicePolicy.poWDefensesEnabled`; HA force-overrides it.
- `topologySpreadConstraints` knob — operator hard-codes a sensible default (hostname spread, best-effort); can be added later if anyone hits the limit.

## Reconciliation

Responsibility split mirrors `TorServicePolicy` / `TorClientAuthPolicy`:

**`OnionBalancePolicyReconciler`** (currently a stub at `internal/controller/onionbalancepolicy_controller.go`):

- Watches `OnionBalancePolicy`, the targeted Gateway(s), the master `Secret`, and the labeled backend `Secret`s.
- Validates each target:
  - The targeted Gateway exists and has `gatewayClassName: tor-gateway`. If not → `Accepted=False` reason `GatewayMissing`.
  - The `masterKeySecretRef` Secret exists in the policy's namespace (or, if cross-namespace, a `ReferenceGrant` permits the read). If denied → `Accepted=False` reason `MasterKeyCrossNamespaceDenied`. If missing → `Accepted=False` reason `MasterKeyMissing`.
  - The Secret contains both `hs_ed25519_secret_key` (64 bytes) and `hs_ed25519_public_key` (32 bytes) and they form a valid ed25519 pair. If not → `Accepted=False` reason `MasterKeyInvalid`.
- Writes per-ancestor `Accepted` condition; the condition's `message` includes the PoW-override note ("PoW disabled on backends — see onionbalance#13") when the targeted Gateway also has `TorServicePolicy.poWDefensesEnabled: true`.
- Computes and writes `status.readyBackends` by counting backend Secrets whose `hostname` field is populated.

**`GatewayReconciler`** (existing — extends, does not refactor):

- Already watches `TorServicePolicy` and `TorClientAuthPolicy`. Adds an `OnionBalancePolicy` watch with the same parentRef-Gateway predicate used for the other policies.
- On every reconcile, looks up any OBP targeting this Gateway. If found and its `Accepted` condition is `True`, provisions Mode B; otherwise Mode A.
- **All resources remain owned by the Gateway** (`OwnerReferences` point at the Gateway). This gives Mode A↔B transitions clean cleanup-by-reconcile semantics consistent with how TSP changes already work today.
- If an OBP is attached but **not** Accepted, the Gateway sets `Programmed=False` with reason `PolicyNotAccepted` and provisions **no Tor infrastructure** — the operator must not silently fall back to Mode A when the user expects HA.

## Mode transitions

A↔B transitions are user-visible because the published `.onion` changes. The operator emits a `MasterDescriptorChanged` event on the Gateway for every transition.

**Mode A → Mode B** (OBP attached + Accepted):
1. Operator deletes `<gw>` Deployment + Service (the standalone Tor pod).
2. Operator creates: `<gw>-frontend` Deployment, `<gw>-backend` StatefulSet, `<gw>-backends` headless Service, N `<gw>-backend-<i>-keys` Secrets, `<gw>-onionbalance-config` ConfigMap (initial empty config — obrefresh populates it once backends report their `.onion`), `<gw>-frontend` ServiceAccount + Role + RoleBinding.
3. `<gw>-keys` Secret (the Mode A key) is **preserved**, not garbage-collected. It is the user's only path back to the original `.onion` if they later detach the OBP.
4. `Gateway.status.addresses` switches from the Gateway-key-derived address to the master-key-derived address. The Gateway shows `Programmed=False` until the frontend pod is Ready and the first backend's descriptor lands in the superdescriptor (gate this on `status.readyBackends ≥ 1` from OBP status).

**Mode B → Mode A** (OBP detached or no longer Accepted):
1. Operator deletes the Mode B resource set.
2. Operator recreates the Mode A Deployment + Service using the preserved `<gw>-keys`.
3. `Gateway.status.addresses` reverts to the original Gateway-key `.onion`.

**Edge case:** the user deletes `<gw>-keys` while Mode B is active. The Secret is unused at that point, so the operator notices the deletion but does not regenerate (regenerating would mean silently choosing a new identity). On Mode B → A detach: `Gateway.status.conditions: Programmed=False / KeyMissing` (the existing Mode A failure mode). Documented in `SECURITY.md`.

## Data flow (single request, Mode B)

1. Client resolves `<master>.onion` → fetches superdescriptor from HSDirs.
2. Superdescriptor lists intro points belonging to **backend** Tor instances (because backends declare `HiddenServiceOnionbalanceInstance 1`).
3. Client picks one intro point, rendezvous with that backend's Tor.
4. Backend Tor delivers the request to its pod's loopback `127.0.0.1:9080`.
5. Backend's router sidecar (identical code to Mode A) does HTTPRoute path matching and proxies to the in-cluster `backendRefs`.

**Backend `.onion` discovery (how obrefresh learns the pool):**

- Each backend's `tor-init` reads the operator-generated key from the per-pod Secret mount, derives the `.onion` from the pubkey, and writes it back into the **same Secret** as a `hostname` field (mirroring how Mode A's `<gw>-keys` already records its hostname).
- The frontend pod's `obrefresh` sidecar runs a Kubernetes Secret informer scoped by label selector `torgateway.io/gateway=<gw>, torgateway.io/role=backend` in the Gateway's namespace. On any add/update/delete that changes the set of populated `hostname` values, the sidecar debounces by `refreshInterval` (default `30s`), rewrites `/etc/onionbalance/config.yaml`, and sends `SIGHUP` to the onionbalance daemon via its pidfile.

## Ops surface

**Status conditions:**

- `OnionBalancePolicy.status.ancestors[].conditions[type=Accepted]` — `True` / `False` (reasons: `MasterKeyMissing`, `MasterKeyInvalid`, `MasterKeyCrossNamespaceDenied`, `GatewayMissing`). Message carries the PoW-override note when applicable.
- `OnionBalancePolicy.status.readyBackends` — count of backend Secrets whose `hostname` is populated.
- `Gateway.status.addresses` — master `.onion` in Mode B, Gateway-key `.onion` in Mode A.
- `Gateway.status.conditions[type=Programmed]` — `False` with reason `PolicyNotAccepted` when an OBP targets the Gateway but is not Accepted; otherwise behaves as today.

**Events:**

- On Gateway: `MasterDescriptorChanged` (every Mode A↔B transition).
- On Gateway: `BackendsRolling` (replicas changed; emitted once per change, message notes the "up to ~15 min" descriptor propagation lag).
- On Gateway and on OnionBalancePolicy: `PoWForcedOffInHA` (emitted once on Mode B provisioning when the Gateway's TSP had PoW enabled).
- Standard Kubernetes events on the Deployment + StatefulSet for scheduling and readiness.

**NetworkPolicy (extends the v0.3.2 per-Gateway NP):**

- The existing per-Gateway egress NP keys off the `torgateway.io/gateway=<gw>` label. In Mode B that label is applied to both the frontend Deployment pods and the backend StatefulSet pods, so a single NP covers both pod sets.
- Egress allow-list (unchanged): DNS, kube-apiserver, resolved HTTPRoute backend Services (cross-namespace gated by `ReferenceGrant`), public internet minus chart-supplied `clusterPodCIDRs`.
- No in-cluster pod-to-pod rules are added — onionbalance never talks to backends directly; descriptor publication and lookup go entirely over the public Tor network.
- Opt-out remains the chart value `torPodNetworkPolicy.enabled=false`.

## Container images

New image: **`images/onionbalance/`** — base on the same hardening pattern as `images/tor/`: multi-stage build, fixed UID `65532`, `readOnlyRootFilesystem`-compatible, no shell in the final layer. Contents: Python runtime + `pip install onionbalance==0.2.4` (current latest). **No Tor binary** — the frontend pod runs Tor as a separate sibling container using the existing `images/tor/`, and onionbalance talks to it over the loopback control port. The image gets cosign signing + SBOM attestation alongside the existing images via `.github/workflows/release.yml`. Add `image-onionbalance` to the `images:` Make target and an `ONIONBALANCE_IMG ?= …` variable, mirroring `image-tor` and `TOR_IMG`.

The `obrefresh` binary at `cmd/obrefresh/main.go` already exists as a stub. Implementation: wire the Secret informer + debouncer + SIGHUP-via-pidfile logic, plus the rendering helper. The image is built from the **root multi-stage Dockerfile** via `make image-obrefresh` (already wired; `--build-arg BINARY=obrefresh`, no new image dir needed).

## Testing

**Unit (pure functions, no cluster):**

- Onionbalance `config.yaml` renderer — table-driven over `(master .onion, backend .onion[])` → expected YAML.
- Master-key validation: binary format detection, pubkey derivation, pair-match check, `.onion` derivation.
- `obrefresh` debouncer + render-on-change logic (fake informer events).
- Mode A↔B resource-set diff helper (given a Gateway and its policy attachments, produces the set of resources to create + the set to delete).

**Envtest (controller-runtime, fake apiserver):**

- `OnionBalancePolicyReconciler`: targetRefs validation, every Accepted=False reason (`MasterKeyMissing` / `MasterKeyInvalid` / `MasterKeyCrossNamespaceDenied` / `GatewayMissing`), ReferenceGrant cross-namespace happy path, `readyBackends` counting under simulated backend Secret writes.
- `GatewayReconciler` extension: Mode B provisioning emerges only when an OBP is Accepted; Mode A↔B transitions create/delete the right resource sets; `<gw>-keys` is preserved across A→B and reused on B→A; OBP detach while Mode B was running cleans up the backend Secrets, the frontend Deployment, the backend StatefulSet, the headless Service, the `onionbalance-config` ConfigMap, and the frontend ServiceAccount + Role + RoleBinding.
- Frontend Deployment template (master Secret mount, onionbalance + obrefresh containers, hardening defaults, RBAC).
- Backend StatefulSet template (per-pod Secret mount, `ob_config` in tor-init, `HiddenServiceOnionbalanceInstance 1` in torrc, PoW directives absent when TSP has PoW enabled, hostname spread present).
- Per-Gateway NetworkPolicy correctly selects both frontend and backend pods.

**Real-Tor e2e** (kind, matches the existing v0.3.x pattern under `test/e2e/`):

- Deploy a Gateway + a 3-backend `OnionBalancePolicy` + a 2-backend HTTPRoute fan-out.
- Wait for `Gateway.status.addresses` to publish the master `.onion`.
- Fetch the master `.onion` via an in-cluster Tor SOCKS client and assert path routing (`/`→A, `/api`→B).
- Kill one backend pod; verify the master `.onion` still serves.
- Scale `replicas: 3 → 1`; verify the master `.onion` still serves (after the bounded propagation window).

**API-shape conformance** (custom suite under `test/conformance/`):

- OBP `Accepted` condition format matches `PolicyAncestorStatus`.
- Gateway `Programmed=False / PolicyNotAccepted` is set when an OBP targets the Gateway but is not Accepted.

## Out of scope (v2+)

- **Multi-frontend HA** — upstream's recommended SPOF mitigation is "separate `.onion` per frontend." That is a different feature shape (different addresses, different policy), not a knob on this one.
- **PoW behind HA** — blocked on upstream onionbalance#13. We force-disable on backends until upstream lands a fix.
- **Backend key rotation** as a feature — manual via Secret deletion works (operator regenerates on next reconcile); no scheduled rotation. Consistent with the `keyRotation` removal decision (2026-06-03).
- **Master key rotation** — same as Mode A: the operator never auto-rotates user-supplied keys.
- **Cross-cluster federation.**
- **Backend `topologySpreadConstraints` as a CRD field** — default hard-coded for now.
- **Vanguards 30 kB descriptor size enforcement** — documented in `SECURITY.md`, no code enforcement.

## Repository layout impact

| Path | Action |
|---|---|
| `api/v1alpha1/onionbalancepolicy_types.go` | Tighten `replicas` cap (12 → 8); clarify `masterKeySecretRef` docstring. |
| `internal/controller/onionbalancepolicy_controller.go` | Implement (currently stub). |
| `internal/controller/gateway_resources.go` (and siblings) | Add Mode B resource builders; add OBP-attachment branch. |
| `internal/controller/gateway_controller.go` | Add OBP watch (same predicate as TSP/TCAP). |
| `internal/onionbalance/config.go` | New — `config.yaml` renderer. |
| `internal/onionbalance/refresher.go` | Replace stub `Run` with informer + debouncer + SIGHUP. |
| `internal/tor/torrc.go` | Backend torrc variant (add `HiddenServiceOnionbalanceInstance 1`, omit PoW directives). |
| `cmd/tor-init/main.go` | Backend variant: write `ob_config` containing `MasterOnionAddress <master>.onion`. |
| `cmd/obrefresh/main.go` | Already exists; wires the existing flag set. Refresher implementation lands behind it. |
| `images/onionbalance/` | New image (Python + pinned onionbalance; Tor runs as a sibling container from `images/tor/`). |
| `Makefile` | Add `image-onionbalance` target + `ONIONBALANCE_IMG` variable; include in `images:` and `docker-push:`. |
| `.github/workflows/release.yml` | Add `onionbalance` to the build/sign/SBOM matrix alongside the other non-Go images. |
| `README.md` | Add `onionbalance` to the cosign verification list (mirror the `tor-gateway-obrefresh` line). |
| `charts/tor-gateway/values.yaml` and templates | Image tag for `onionbalance` and `obrefresh` images. |
| `config/samples/` | Add an `OnionBalancePolicy` sample. |
| `test/e2e/onionbalance_test.go` | Real-Tor HA e2e. |
| `docs/PLAN.md` | Mark `OnionBalancePolicy` shipped at release time. |
| `SECURITY.md` | Add Mode B sections: frontend SPOF, master-key compromise, PoW-in-HA limitation, Vanguards descriptor size note. |
