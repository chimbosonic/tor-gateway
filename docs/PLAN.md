# tor-gateway — design & plan

A Kubernetes [Gateway API](https://gateway-api.sigs.k8s.io/) conformant operator that exposes in-cluster `Service`s as Tor v3 hidden services (`.onion` URLs). Drop in a `Gateway` of class `tor-gateway` plus `HTTPRoute`s, get a `.onion` published in `Gateway.status.addresses`.

No existing operator (`bugfest/tor-controller`, `agabani/tor-operator`) implements the Gateway API — they are CRD-only. This project fills that gap with a 2026-modern, typed-CRD UX (no annotations, no Ingress shim).

**Design pillars (non-negotiable):**
- **Gateway API native** — implement the v1.5 spec.
- **Tests first-class** — unit + envtest for every component; a custom API-shape conformance check against the live operator.
- **Secure by default** — non-root pods, read-only filesystems, strict key permissions, NetworkPolicies, supply-chain hygiene, explicit threat model (see [`SECURITY.md`](../SECURITY.md)).
- **Production / multi-tenant** — RBAC isolation, namespace scoping, cross-namespace via `ReferenceGrant`.

---

## Status

Implemented and tested:
- `internal/tor` — v3 `.onion` derivation, ed25519 key generation + Tor on-disk format, torrc rendering, permission enforcement, `mkp224o` Job rendering, client-auth `.auth` files (~88% coverage).
- Reconcilers — `GatewayClass`, `Gateway` (provisions Secret/ConfigMap/Deployment/Service, publishes `.onion`, OwnerReferences cascade), `HTTPRoute` (parent status + listener `attachedRoutes`), `TorServicePolicy`, `TorClientAuthPolicy` (Strict mounts client keys; Audit logs). Gateway reconciler watches the policy CRDs.
- `internal/router` — the in-pod router sidecar, fully wired. Pure routing core (path matching with Gateway API precedence, reverse-proxy handler, `HTTPRoute`→rules conversion, in-cluster Service resolver) plus `router.New()`: it watches the HTTPRoutes whose `parentRefs` target its Gateway via an informer and atomically rebuilds the route table on every add/update/delete. Unit-tested (route selection + fake-client sync) and covered by a package envtest (serves routes present at startup; picks up routes added later).
- Data plane (**proven end-to-end over real Tor**) — the operator provisions a hardened, nonroot Tor pod: `tor-init` copies the ed25519 keys from the Secret mount and fixes permissions in process-owned subdirs of the emptyDirs (so Tor and the init container run under `fsGroup`/UID 65532 with a read-only rootfs), the curated Tor daemon image (`images/tor`) runs the hidden service, and the router sidecar runs under a per-Gateway ServiceAccount + namespaced Role/RoleBinding (least-privilege `httproutes` get/list/watch). A request to the published `.onion` routes by path to the correct in-cluster backend over a real Tor circuit.
- Container images — `make images` builds the manager, router, obrefresh, tor-init, and the in-repo hardened Tor daemon image (`images/tor`).
- Tests/CI — envtest suites (controller + router), operator-side kind e2e, real-Tor data-plane e2e, custom API-shape conformance, lint, govulncheck, gosec.
- Distribution — the Helm chart installs a functional operator (RBAC + policy CRDs synced from `config/` via `make chart-sync`, CI drift guard, kind deploy-smoke). A `vX.Y.Z` tag publishes multi-arch, cosign-signed images + chart (OCI `ghcr.io` + GitHub Pages) with SBOM attestations; first release `v0.1.0`.

The critical path to a functionally deployable operator — container images, a real-Tor data-plane e2e, and a published, signed chart — is complete. Remaining work is the independent feature backlog: onionbalance HA (`OnionBalancePolicy`), `mkp224o` vanity harvest, cross-namespace `ReferenceGrant`.

---

## High-level architecture

Two deployment modes per `Gateway`, chosen by whether an `OnionBalancePolicy` targets it.

### Mode A — Standalone (default)

```
            tor-gateway operator (Go, controller-runtime)
                              │
                              ▼
            ┌─────────────────────────────────────────┐
            │ Tor daemon pod (Deployment, 1 replica)  │
            │  - torrc from ConfigMap                 │
            │  - hs_ed25519_secret_key from Secret    │
            │  - authorized_clients from Secret       │
            │  - HiddenServicePort 80 → 127.0.0.1:9080│
            │  - sidecar router → HTTPRoute backends  │
            └─────────────────────────────────────────┘
```

One `Gateway` ⇒ one Tor pod ⇒ one `.onion`.

### Mode B — HA via onionbalance (when `OnionBalancePolicy` attached)

```
                    ┌──────────────────────────────┐
                    │ onionbalance frontend pod    │
                    │  - holds MASTER ed25519 key  │
                    │  - publishes superdescriptor │
                    │  - obrefresh sidecar watches │
                    │    backends, SIGHUPs daemon  │
                    └──────────────────────────────┘
                                  │
                publishes single .onion (master address)
                                  │
                  ┌───────────────┼───────────────┐
                  ▼               ▼               ▼
        ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
        │ Backend Tor │ │ Backend Tor │ │ Backend Tor │  (StatefulSet)
        │ instance-0  │ │ instance-1  │ │ instance-2  │
        │ own ed25519 │ │ own ed25519 │ │ own ed25519 │
        │ + sidecar   │ │ + sidecar   │ │ + sidecar   │
        └─────────────┘ └─────────────┘ └─────────────┘
                          each runs HiddenServiceOnionbalanceInstance 1
```

The user still sees one `.onion` (the master). Backends each have their own key and act as introduction-point providers; the frontend stitches their descriptors.

**Key idea (both modes):** Tor only sees a single `HiddenServicePort 80 → 127.0.0.1:9080` per pod — the sidecar router does the HTTPRoute-aware fan-out to in-cluster `backendRefs`. Tor's config stays trivial; routing logic lives in testable Go.

---

## CRDs and resources

### Standard Gateway API resources

| Kind | Notes |
|---|---|
| `GatewayClass` | We register `torgateway.io/gateway-controller`. |
| `Gateway` | Custom listener protocol `torgateway.io/HiddenService` (domain-prefixed, per spec). |
| `HTTPRoute` | Attached via `parentRefs`; drives in-cluster fan-out. |
| `ReferenceGrant` | For cross-namespace Secret refs (planned). |

### Policy CRDs — `policy.torgateway.io/v1alpha1`

Direct Policy attachment (GEP-2648): each policy `targetRefs` one or more Gateways and reports per-ancestor `Accepted` status. They are **not** inherited to HTTPRoutes — they configure the per-Gateway Tor daemon, which has no child routes to cascade to.

| Kind | Purpose |
|---|---|
| `TorServicePolicy` | Vanity prefix, log level, `poWDefensesEnabled`, resource requests, key rotation. |
| `TorClientAuthPolicy` | v3 client auth; references a Secret of client x25519 public keys; `Strict` / `Audit` mode. |
| `OnionBalancePolicy` | HA via onionbalance: `replicas` (1–12), `refreshInterval`, `masterKeySecretRef`. |

### Deliberately excluded

- No custom `Route` kinds — `HTTPRoute` suffices.
- No annotation-based config — typed Policy CRDs only.
- No Ingress shim — Gateway API only.

---

## Data path

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: blog, namespace: prod }
spec:
  gatewayClassName: tor-gateway
  listeners:
  - { name: onion, port: 80, protocol: torgateway.io/HiddenService }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: blog, namespace: prod }
spec:
  parentRefs: [{ name: blog }]
  rules:
  - matches: [{ path: { value: / } }]
    backendRefs: [{ name: ghost, port: 2368 }]
```

Reconcile:
1. **Keys** — generate an ed25519 keypair into `Secret <gw>-keys` if absent (never regenerated; loss is permanent). Vanity prefixes via an on-demand `mkp224o` Job.
2. **torrc** — render into `ConfigMap <gw>-torrc` (HiddenServiceDir, `HiddenServicePort 80 127.0.0.1:9080`, PoW defenses, client-auth dir when a policy applies).
3. **Pod** — `Deployment <gw>`: `tor-init` init container populates the HiddenServiceDir with strict perms; `tor` main container; `router` sidecar.
4. **Status** — publish `.onion` (derived from the pubkey) into `Gateway.status.addresses` (`type: Hostname`) and set `Accepted` / `Programmed` conditions + per-listener status.

---

## Repository layout

```
api/v1alpha1/            # Policy CRD Go types
cmd/{manager,router,obrefresh,tor-init}/
internal/
  controller/            # gatewayclass, gateway, httproute, policy reconcilers
  tor/                   # onion derivation, keys, torrc, permissions, vanity, client-auth
  onionbalance/          # frontend config gen + refresher (in progress)
  router/                # HTTPRoute → reverse-proxy core
  status/                # condition helpers
config/                  # kubebuilder kustomize (crd, rbac, manager, samples)
charts/tor-gateway/      # Helm chart
images/tor/              # hardened Tor daemon container image (Dockerfile)
test/{e2e,conformance}/  # kind e2e (incl. real-Tor data plane) + API-shape conformance
```

---

## Test strategy

| Layer | Tool | Covers |
|---|---|---|
| Unit | `go test`, table-driven | onion/key/torrc/permission/router logic — pure, no cluster |
| Integration | controller-runtime envtest | reconcilers vs a fake apiserver: child creation, OwnerReferences, status, CEL validation; router sidecar rebuilding its route table from live HTTPRoute changes |
| Conformance | custom (`test/conformance`) | the **deployed** operator satisfies the Gateway API status contract (GatewayClass/Gateway Accepted+Programmed, Hostname `.onion` address, listener status) |
| E2E | kind, operator-side + real-Tor | Gateway lifecycle, policy effects on torrc, HTTPRoute status, cascade delete; **real-Tor data plane**: deploy a Gateway + two-backend HTTPRoute, fetch the published `.onion` over the public Tor network via an in-cluster SOCKS client, and assert path routing (`/`→A, `/api`→B) |
| Security | govulncheck, gosec | CVE reachability + SAST on every PR |

**Why not the upstream Gateway API conformance suite:** its GATEWAY-HTTP profile drives real L7 traffic to IP-reachable addresses. A Tor gateway publishes `.onion` addresses reachable only over Tor, and provisioning a Tor pod per conformance Gateway overwhelms a single-node cluster. We assert the slice of the contract we *can* satisfy instead.

---

## Security model

Detailed threat model in [`SECURITY.md`](../SECURITY.md). Operative controls:

1. **Pod hardening** — `runAsNonRoot`, fixed UID 65532, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, drop `ALL` caps, `seccompProfile: RuntimeDefault`. HiddenServiceDir is an `emptyDir`; `tor-init` copies keys in and fixes perms (0700 dir, 0600 secret key).
2. **Keys** — private keys only in Secrets, mounted `0600`/`0400`, never logged, never in ConfigMaps. Generated in-process (non-vanity) or a one-shot Job (vanity), never in the long-running operator.
3. **NetworkPolicies** — emitted around Tor pods; egress to Tor directories + referenced backends only.
4. **RBAC** — least-privilege; the operator does not get blanket Secret read.
5. **Supply chain** — distroless images, SBOM (syft), cosign signing (keyless/OIDC), `govulncheck` in CI.
6. **Tor-specific** — PoW + intro-DoS defenses on by default; curated torrc (no raw passthrough).
7. **Failure modes** — lost key Secret = permanent address loss; surfaced via condition + event, never auto-regenerated.

---

## Decisions captured

- **Language**: Go + kubebuilder (controller-runtime) — matches upstream Gateway API tooling.
- **HA**: onionbalance (Mode B), v1 scope.
- **Distribution**: Helm chart to GitHub Pages + OCI (ghcr.io); cosign-signed images + chart.
- **UX**: pure Gateway API — no Ingress shim, no annotations, extension via typed Policy CRDs.
- **Policy attachment**: direct (GEP-2648), not inherited.

## Out of scope (v2+)

TCPRoute/UDPRoute/TLSRoute, Grafana dashboards, obfs4 bridges/pluggable transports.
