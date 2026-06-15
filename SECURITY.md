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

### Onionbalance HA (Mode B)

When an `OnionBalancePolicy` targets a Gateway, the operator provisions a
frontend onionbalance pod and a backend StatefulSet of N independent Tor
instances. Mode-B-specific security properties:

**Backend-key isolation.** Each backend pod's runtime Tor container has no
Secret volume mount. Its onion key is delivered by an init container that
calls the operator's internal API (`GET /api/v1/secret`) and writes the
result into an in-pod `emptyDir`, which the Tor container then uses as its
`HiddenServiceDir`. The init container's ServiceAccount is granted
`secrets:get` scoped to the exact set of backend Secret names belonging to
that Gateway, so a node-level attacker sees only the emptyDir contents of
the pod they control. There is an RBAC limitation worth noting: because
StatefulSet does not template per-replica ServiceAccounts, the init
container's SA can fetch any of THIS Gateway's backend keys via the
Kubernetes API — not just its own. A compromised init container therefore
cannot reach other Gateways' keys or the master key, but it can read its
sibling replicas' keys within the same Gateway.

**Frontend SA scope.** The frontend pod's ServiceAccount is granted
`secrets:get` scoped to the master Secret plus all N backend Secrets by
name (`resourceNames`). `secrets:list/watch` remains namespace-wide (a
Kubernetes RBAC limitation — `resourceNames` cannot restrict list or watch
at the apiserver level). The operator narrows the informer in code with a
LabelSelector requiring `torgateway.io/owner-uid=<gw.UID>`, so only Secrets
the operator itself labelled are processed. A tenant-planted Secret that
does not carry the operator-set owner-UID label is silently skipped. For
the strongest isolation, deploy one Gateway per namespace so that the
namespace-wide list/watch permission does not cross tenant boundaries.

**Cross-namespace `MasterKeySecretRef`.** The `masterKeySecretRef` field
may name a Secret in a different namespace than the Gateway. A
`ReferenceGrant` in the source namespace is the authoritative gate and is
re-validated on every reconcile. The operator emits a per-Gateway `Role`
and `RoleBinding` in the source namespace granting the frontend SA `get` on
exactly the named Secret; old bindings are garbage-collected when the
reference changes namespace. A Gateway finalizer (added in v0.5) ensures
these cross-namespace Role and RoleBinding resources are reclaimed on Gateway
deletion — deleting a Mode B Gateway no longer leaves orphaned RBAC objects
in the master-Secret namespace.

**PoW in Mode B.** The Tor PoW intro-point defenses cannot be enabled on
onionbalance backend instances. The PoW challenge lives at the Tor protocol
layer — specifically at the introduction-point circuit — which is owned by
each backend's `tor` process. The onionbalance frontend cannot proxy or
aggregate those challenges across replicas, so enabling PoW on backends
would degrade rather than improve availability. When PoW would otherwise be
active (the default `TorServicePolicy` or an explicit policy with
`powDefenses.enabled: true`), the operator emits a `PoWForcedOffInHA`
Warning event, annotates the Gateway with
`torgateway.io/pow-override-emitted`, and includes a `PoW forced off` note
in the `OBPAccepted` condition message so the signal is visible in
`kubectl get gateway -o yaml`. Mitigations: rely on Tor's intro-point rate
limiting, restrict access to authorised clients via `TorClientAuthPolicy`,
or reduce the blast radius by routing a fraction of traffic to a Mode A
Gateway with PoW enabled.

**Frontend SPOF.** The frontend pod is a single point of failure for
descriptor publication. Kubernetes Deployment auto-restart is the current
mitigation (brief outage during pod restart, `.onion` address unchanged).
Running a second frontend with a separate master `.onion` is out of scope
for v1.

**Vanguards descriptor size.** Onionbalance descriptors with the maximum
number of intro points can exceed Vanguards' default 30 kB cap. If you set
`replicas` close to the cap (8) and run Vanguards, monitor descriptor sizes.

### Testing mode (chutney)

The operator accepts a `--testing-tor-network-file=<path>` flag that
splices `TestingTorNetwork 1` and a caller-provided `DirAuthority` block
into every Tor pod's torrc. This flag is operator-level only and is never
exposed to API tenants. It exists to let e2e tests bootstrap against a
private chutney-managed Tor network, with ~30-second descriptor publication
instead of the public network's 5–15 minute cycle.

**Never enable this in production.** When the flag is set, every `.onion`
the operator publishes is resolvable only by clients participating in the
configured testing network. A production cluster that accidentally enables
the flag silently publishes unreachable addresses.

When testing mode is active, the per-Gateway egress NetworkPolicy is
narrowed to the chutney pod CIDR plus the DirAuth/OR ports. Broader
namespace-level egress is not permitted, so a misconfigured test pod cannot
accidentally reach the public Tor network.

The Helm chart's `testingTorNetwork.enabled` value defaults to `false`. To
guard against accidental enablement, `helm template` fails at render time if
`testingTorNetwork.enabled` is `true` but either `testingTorNetwork.podNamespace`
or `testingTorNetwork.configMapName` is unset. Explicit, complete
configuration is required before the chart will render.

Do not reuse `.onion` keys between testing and production deployments —
once a key has been published to a chutney network, retire it.

### Known gaps

- **NetworkPolicy is opt-out per-Gateway** (v0.3.2). The operator emits a per-Gateway egress NetworkPolicy whitelisting DNS, kube-apiserver, the resolved HTTPRoute backend Services (cross-namespace gated by ReferenceGrant), and the public internet. The `clusterPodCIDRs` chart value MUST be set to your cluster's pod CIDR(s) for cluster-lateral lockdown to bite — without it, the broad public-internet rule allows in-cluster destinations too. CNIs without NetworkPolicy support (e.g. default Flannel) silently no-op the policy.
- **MetricsPort exposure**: Tor's `MetricsPort` continues to expose Prometheus-format counters on the pod IP (no key material, no descriptor content). With `clusterPodCIDRs` set and no inbound NetworkPolicy, only the kubelet probe reaches it through the node-local path; scrape from a Prometheus pod requires a tailored NetworkPolicy or external scrape via the host.

### Known failure modes (documented, not auto-recovered)

- **Lost key Secret** = permanent `.onion` address loss. The operator sets a `KeyMissing` condition and emits a Warning event; it does NOT auto-regenerate.
- **Clock skew >30s** between cluster nodes can break Tor descriptor publication. Run NTP.
- **`HiddenServiceDir` permissions wrong** = Tor refuses to start. Init container enforces `700`; do not bypass.
- **`ClientOnionAuthDir` ownership** — Tor refuses any `ClientOnionAuthDir` not owned by the Tor uid. Kubernetes `Secret` and `ConfigMap` volume root dirs are owned by root (`fsGroup` sets group but not owner), so client-auth-using deployments must stage the directory via an `emptyDir` + init container that creates it as uid 65532 — never mount the Secret directly as the auth dir.

See the design plan at `docs/PLAN.md` for the full architecture.
