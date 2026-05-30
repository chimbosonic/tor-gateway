# Security policy

## Reporting a vulnerability

Please report security issues privately to `agl314@chimbosonic.com` (PGP key TBD). Do not open public issues for unpatched vulnerabilities. We aim to acknowledge within 72 hours.

## Threat model (summary)

`tor-gateway` runs Tor hidden services inside a Kubernetes cluster and bridges traffic to in-cluster `Service`s. The security-relevant assets are:

| Asset | Sensitivity | Where it lives |
|---|---|---|
| `hs_ed25519_secret_key` (per Gateway) | Critical — loss = address compromise | Kubernetes `Secret`, mounted at `0600` |
| Master onionbalance ed25519 key | Critical — same | Kubernetes `Secret`, frontend pod only |
| Client auth x25519 public keys (server side) | Low — public | `Secret` referenced by `TorClientAuthPolicy` |
| Client auth x25519 private keys | Critical for the client | Out of scope (client manages) |
| Operator service account token | High — controls all Tor pods | Kubernetes default flow |

### Adversary models considered

1. **Cluster co-tenant** — another namespace tries to read a Gateway's key Secret or reroute traffic.
   - Mitigations: per-namespace RBAC; operator never grants blanket `Secret` read. NetworkPolicy scoping is **not yet emitted by the operator** (tracked follow-up); scope ingress to the Tor pod (including its `MetricsPort`) with your own NetworkPolicy until then.
2. **Compromised backend Pod** — a Pod behind an HTTPRoute is breached.
   - Mitigations: the backend cannot read keys; the proxy sidecar only forwards to `backendRefs` resolved by the controller, not to arbitrary destinations chosen by the backend.
3. **External attacker over Tor** — public attack against the `.onion`.
   - Mitigations: Tor PoW / intro-point DoS defenses enabled by default; optional v3 client auth via `TorClientAuthPolicy`.
4. **Supply chain** — malicious operator image.
   - Mitigations: images signed with cosign (keyless via GitHub OIDC), SBOM (syft) attached to releases, distroless base, pinned digests, `govulncheck` + `trivy` in CI.

### Hardening defaults (enforced by the operator)

All pods produced by the operator:

- `runAsNonRoot: true`, fixed UID (65532), `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`, drop `ALL` capabilities
- `seccompProfile: { type: RuntimeDefault }`
- Key Secrets mounted with `defaultMode: 0600`
- Liveness / readiness / startup probes on the data-plane containers (router `/healthz` on `:8081`; Tor `MetricsPort` `/metrics` on `:9035`)

### Known gaps

- **NetworkPolicy is not yet emitted by the operator** (tracked follow-up). The Tor pod's `MetricsPort` exposes Prometheus-format counters (no key material, no descriptor content) on the pod IP; any in-cluster source can reach it until you scope ingress with your own NetworkPolicy or the operator-emitted policy ships.

### Known failure modes (documented, not auto-recovered)

- **Lost key Secret** = permanent `.onion` address loss. The operator sets a `KeyMissing` condition and emits a Warning event; it does NOT auto-regenerate.
- **Clock skew >30s** between cluster nodes can break Tor descriptor publication. Run NTP.
- **`HiddenServiceDir` permissions wrong** = Tor refuses to start. Init container enforces `700`; do not bypass.

See the design plan at `docs/PLAN.md` for the full architecture.
