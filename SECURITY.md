# Security policy

## Reporting a vulnerability

Please report security issues privately to `agl314@chimbosonic.com`. Do not open public issues for unpatched vulnerabilities. We aim to acknowledge within 72 hours.

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
   - Mitigations: per-namespace RBAC; operator never grants blanket `Secret` read. The operator emits a per-Gateway egress NetworkPolicy (v0.3.2) locking lateral movement to DNS, kube-apiserver, resolved HTTPRoute backend Services, and the public internet minus chart-supplied cluster pod CIDRs; scope inbound ingress to the Tor pod's `MetricsPort` with your own NetworkPolicy if you need to constrain scrape access.
2. **Compromised backend Pod** — a Pod behind an HTTPRoute is breached.
   - Mitigations: the backend cannot read keys; the proxy sidecar only forwards to `backendRefs` resolved by the controller, not to arbitrary destinations chosen by the backend.
3. **External attacker over Tor** — public attack against the `.onion`.
   - Mitigations: Tor PoW / intro-point DoS defenses enabled by default; optional v3 client auth via `TorClientAuthPolicy`.
4. **Supply chain** — malicious operator image.
   - Mitigations: images signed with cosign (keyless via GitHub OIDC), SBOM (syft) attached to releases, distroless base, `govulncheck` + `gosec` in CI.

### Hardening defaults (enforced by the operator)

All pods produced by the operator:

- `runAsNonRoot: true`, fixed UID (65532), `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`, drop `ALL` capabilities
- `seccompProfile: { type: RuntimeDefault }`
- Key Secrets mounted with `defaultMode: 0600`
- Liveness / readiness / startup probes on the data-plane containers (router `/healthz` on `:8081`; Tor `MetricsPort` `/metrics` on `:9035`)

### Known gaps

- **NetworkPolicy is opt-out per-Gateway** (v0.3.2). The operator emits a per-Gateway egress NetworkPolicy whitelisting DNS, kube-apiserver, the resolved HTTPRoute backend Services (cross-namespace gated by ReferenceGrant), and the public internet. The `clusterPodCIDRs` chart value MUST be set to your cluster's pod CIDR(s) for cluster-lateral lockdown to bite — without it, the broad public-internet rule allows in-cluster destinations too. CNIs without NetworkPolicy support (e.g. default Flannel) silently no-op the policy.
- **MetricsPort exposure**: Tor's `MetricsPort` continues to expose Prometheus-format counters on the pod IP (no key material, no descriptor content). With `clusterPodCIDRs` set and no inbound NetworkPolicy, only the kubelet probe reaches it through the node-local path; scrape from a Prometheus pod requires a tailored NetworkPolicy or external scrape via the host.

### Known failure modes (documented, not auto-recovered)

- **Lost key Secret** = permanent `.onion` address loss. The operator sets a `KeyMissing` condition and emits a Warning event; it does NOT auto-regenerate.
- **Clock skew >30s** between cluster nodes can break Tor descriptor publication. Run NTP.
- **`HiddenServiceDir` permissions wrong** = Tor refuses to start. Init container enforces `700`; do not bypass.
- **`ClientOnionAuthDir` ownership** — Tor refuses any `ClientOnionAuthDir` not owned by the Tor uid. Kubernetes `Secret` and `ConfigMap` volume root dirs are owned by root (`fsGroup` sets group but not owner), so client-auth-using deployments must stage the directory via an `emptyDir` + init container that creates it as uid 65532 — never mount the Secret directly as the auth dir.

See the design plan at `docs/PLAN.md` for the full architecture.
