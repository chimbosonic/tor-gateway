# v0.3.2 — Tor-pod NetworkPolicy (ReferenceGrant-aware) — design

## Why

`docs/PLAN.md` lists "Secure by default" as a design pillar, and `SECURITY.md` now openly tracks the operator-emitted NetworkPolicy as a known gap. v0.3.1 made the gap load-bearing by exposing `MetricsPort` on the Tor pod, reachable from any in-cluster source. v0.3.2 closes the gap: per-Gateway NetworkPolicy, ReferenceGrant-aware backend whitelist, opt-out via chart value.

Out of scope:
- Ingress restrictions (kubelet probe sources are provider-dependent; probe endpoints are non-sensitive — counters + 200 OK).
- Auto-discovery of cluster pod CIDRs (provider-dependent; we accept the value as chart config).
- `KeyRotationSpec` cleanup (deferred to its own brainstorm bundled with onionbalance HA, per the v0.3.2 brainstorm decision).

## Approach

Per-Gateway NetworkPolicy emitted by the operator (not the chart — chart-side wouldn't see per-Gateway state). Egress-only `policyTypes`. The egress allow-list is computed from HTTPRoutes targeting the Gateway, gated by ReferenceGrants for cross-namespace `backendRefs` (reusing the controller-authority helper from v0.3.0). A chart-supplied `clusterPodCIDRs` list lets a broad public-internet rule carve out cluster traffic so the per-backend whitelist actually bites; without it, the NetworkPolicy is shipped but lockdown is cosmetic — documented loudly.

## Architecture

### Builder

New file `internal/controller/network_policy.go`:

```go
// BuildNetworkPolicy emits the per-Gateway NetworkPolicy that locks Tor
// pod egress down to: DNS, the resolved backend Services (cross-ns gated
// by ReferenceGrant), and the public internet minus the cluster pod CIDRs.
//
// services is the set of backend Services the reconciler resolved (one
// per unique backendRef). missing/ExternalName/headless-without-selector
// services are skipped by the caller before this is invoked.
func BuildNetworkPolicy(
    gw *gwv1.Gateway,
    backends []ResolvedBackend,
    clusterPodCIDRs []string,
    scheme *runtime.Scheme,
) (*netv1.NetworkPolicy, error)

// ResolvedBackend is one entry in the egress allow-list: a backend
// Service that the reconciler successfully resolved AND that passes
// the ReferenceGrant gate when cross-namespace.
type ResolvedBackend struct {
    Namespace    string            // backend Service namespace
    PodSelector  map[string]string // Service.spec.selector
    TargetPort   intstr.IntOrString // Service.spec.ports[name=port].targetPort
    Protocol     corev1.Protocol   // TCP unless otherwise specified
}
```

Pure builder; no I/O. Easy to table-test. Matches `BuildDeployment`/`BuildService` pattern in the same package.

### Reconciler integration

`internal/controller/gateway_controller.go`:

- Add `BuildNetworkPolicy` call to the Gateway reconcile loop, after the existing children.
- Reuse the existing HTTPRoute list call (the reconciler already lists routes targeting the Gateway for `attachedRoutes` status).
- Reuse `referencegrant.Allows()` from v0.3.0 to gate cross-namespace `backendRefs`.
- New helper: `resolveBackends(ctx, gw, routes, grants) ([]ResolvedBackend, error)`:
  - For each `backendRef`, determine namespace (`backendRef.namespace` or default to route ns).
  - If cross-ns, call `Allows()` with the (route, backend) refs; skip when denied.
  - Get the backend Service (one apiserver call per unique `(ns, name)`).
  - Skip if Service missing / ExternalName / headless-without-selector (log at INFO).
  - Resolve `backendRef.port` → Service port → `targetPort`.
- Apply the NetworkPolicy via the existing `CreateOrUpdate` pattern; `controllerutil.SetControllerReference` for owner cascade.
- If `clusterPodCIDRs` is empty, the builder emits `to: ipBlock 0.0.0.0/0` (no `except`). If set, emits `to: ipBlock 0.0.0.0/0 except <cidrs>`.

### RBAC

Add one marker on the Gateway reconciler (lands in `config/rbac/role.yaml` via `make manifests`, then `make chart-sync`):

```go
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
```

### Chart config

```yaml
# values.yaml
torPodNetworkPolicy:
  # When true, the operator emits a per-Gateway NetworkPolicy that locks
  # Tor pod egress down (see SECURITY.md).
  enabled: true

  # The cluster's pod CIDR(s). The NetworkPolicy uses these as `except`
  # entries in the broad public-internet egress rule so cluster pods are
  # only reachable via the per-backend whitelist. WITHOUT THIS SET, the
  # NetworkPolicy still ships but cluster lateral movement is NOT blocked
  # — Tor pods can still reach any in-cluster Service IP. Pick the value
  # from your cluster's CNI config:
  #   kubeadm:  kubectl cluster-info dump | grep -m1 cluster-cidr
  #   GKE:      gcloud container clusters describe ... --format=...
  #   EKS:      look at the VPC CNI subnet CIDR
  # Multiple CIDRs allowed (dual-stack or aliased pod nets).
  clusterPodCIDRs: []
```

The operator manager binary takes a new CLI flag `--tor-pod-network-policy-enabled` (default `true`) and `--cluster-pod-cidrs` (comma-separated; default empty). The chart populates them from the values block. Disabling the flag short-circuits the reconciler's `BuildNetworkPolicy` call (no NetworkPolicy is created; any existing one is deleted next reconcile so the toggle is reversible).

## NetworkPolicy shape (the rendered object)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: <gateway-name>-netpol
  namespace: <gateway-namespace>
  labels:
    app.kubernetes.io/managed-by: tor-gateway
    torgateway.io/gateway: <gateway-name>
  ownerReferences: [{Gateway}]
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/managed-by: tor-gateway
      torgateway.io/gateway: <gateway-name>
  policyTypes: [Egress]
  egress:
    # 1. DNS to kube-system
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # 2. Kube-apiserver (kubeadm/k3s pattern; redundant-but-harmless on managed clusters)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: TCP
          port: 6443
        - protocol: TCP
          port: 443
    # 3. Per backendRef (one block per ResolvedBackend)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <backend.Namespace>
          podSelector:
            matchLabels: <backend.PodSelector>
      ports:
        - protocol: <backend.Protocol>
          port: <backend.TargetPort>
    # 4. Public internet (Tor's relay reach)
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: <clusterPodCIDRs>      # omitted when value empty
```

Rule 2 is needed because in-cluster apiserver pods (the kubeadm/k3s pattern) sit on the pod network and would be excluded by rule 4's `except` when `clusterPodCIDRs` is set — without rule 2 the router would lose its watch connection. Managed clusters (GKE/EKS/AKS) reach the apiserver via rule 4 (no `except` matches the external IP), so rule 2 is redundant there but harmless.

Ordering is deterministic (DNS, apiserver, backends sorted by `(namespace, port, podSelector-first-label-key)`, public-internet last) so the rendered NP is golden-testable. Backends are deduplicated upstream by `(namespace, name)` in `resolveBackends`, so the sort key never sees collisions on the same Service.

## Error handling

- **Missing backend Service**: skipped, INFO-logged with `gateway`, `route`, `backendRef`. NetworkPolicy still applies; that backend simply doesn't get a rule. The HTTPRoute already surfaces `ResolvedRefs=BackendNotFound` separately; the NetworkPolicy isn't where we surface missing-backend status.
- **ReferenceGrant denial on cross-ns backendRef**: skipped silently from the NetworkPolicy. Already surfaced as `ResolvedRefs=RefNotPermitted` on the HTTPRoute (v0.3.0). Don't double-emit.
- **Apiserver error during Service resolution**: requeue the Gateway. NetworkPolicy is left as-is (last good state); kubelet probes continue.
- **Malformed `clusterPodCIDRs`**: rejected at manager startup via flag parse with a clear error. Operator refuses to start rather than ship a broken NetworkPolicy.

## Testing

### Unit (table-driven, no envtest)

`internal/controller/network_policy_test.go`:

1. No backends, no CIDRs → DNS + apiserver + public-internet rule with no `except`. No per-backend rule.
2. No backends, CIDRs set → public-internet rule has `except` populated; apiserver rule still present.
3. One same-ns backend → DNS + apiserver + one per-backend rule + public.
4. One cross-ns backend, no grant → DNS + apiserver + public only (no per-backend rule). Caller is expected to filter; this test feeds an empty `backends` slice and verifies the builder doesn't infer.
5. One cross-ns backend with grant → per-backend rule with correct `namespaceSelector`.
6. Multiple backends → rules in deterministic sort order.
7. Backend with empty selector → builder rejects with a clear error (caller should have skipped; defense in depth).
8. Owner reference is set to the Gateway; labels are `ChildLabels`.

### envtest

`internal/controller/gateway_controller_test.go` (extend):

1. Create Gateway + HTTPRoute with one same-ns backend → assert NetworkPolicy is created with one per-backend egress rule.
2. Add a cross-ns backend without grant → assert the rule does NOT appear; add a grant → rule appears on the next reconcile.
3. Delete the HTTPRoute → assert the per-backend rule disappears.
4. Disable via the manager flag → assert no NetworkPolicy is created (delete existing one).

### e2e

`test/e2e/networkpolicy_test.go` (new, `//go:build e2e`):

Single spec with `clusterPodCIDRs` set to the kind cluster's pod CIDR:

1. Same namespace: Gateway + HTTPRoute → backend pod A. Deploy a non-backend pod B with the same labels-style service.
   - Curl from Tor pod to backend A via Service → succeeds (over Tor circuit).
   - Curl from Tor pod to non-backend B → blocked at the NetworkPolicy layer (connection times out / refused).
2. Cross namespace + ReferenceGrant: same as #1 but backend is in NS-2 with a grant; victim pod in NS-2 without.
   - Backend reachable, victim blocked.

Avoids real-Tor where possible to keep wall-clock manageable; the route-resolution + NP application are the only assertions needed. (Compare to v0.3.1 where the data-plane probes were implicitly covered by existing real-Tor e2e — here we want a direct assertion.)

## Migration

- **Default-on may break cross-ns deployments without ReferenceGrants.** Release notes call this out explicitly and direct users at the `enabled: false` flag for the rollback path.
- **Default-on may break deployments using `ExternalName`/headless backends.** Same mitigation.
- **`clusterPodCIDRs` unset** is acceptable in a "ship the surface, lock down later" mode. Users notice nothing changes until they set the value. Docs are explicit.

## Files

**New:**
- `internal/controller/network_policy.go` — `BuildNetworkPolicy`, `ResolvedBackend`.
- `internal/controller/network_policy_test.go` — unit tests.
- `test/e2e/networkpolicy_test.go` — e2e spec.

**Modified:**
- `internal/controller/gateway_controller.go` — RBAC marker, reconcile-loop integration, `resolveBackends` helper.
- `cmd/manager/main.go` — `--tor-pod-network-policy-enabled` and `--cluster-pod-cidrs` flags.
- `charts/tor-gateway/values.yaml` — `torPodNetworkPolicy` block + comments.
- `charts/tor-gateway/templates/deployment.yaml` — pass the two new flags to the manager.
- `config/rbac/role.yaml` — regenerated by `make manifests`.
- `charts/tor-gateway/files/rbac/manager-role-rules.yaml` — regenerated by `make chart-sync`.
- `SECURITY.md` — replace the "Known gaps: NetworkPolicy not yet implemented" entry with the actual coverage + the cluster-CIDR caveat.
- `docs/PLAN.md` — move the NetworkPolicy item from "follow-up" to "shipped v0.3.2 (with documented cluster-CIDR config requirement)".

## Release

After merge, cut `v0.3.2`. CI auto-versions `Chart.yaml` from the tag (same flow as v0.3.0/v0.3.1).

## Decisions / non-choices

- **Egress-only `policyTypes`.** Kubelet probe sources vary by provider; the probe endpoints expose non-sensitive content. Ingress restrictions on probes are fragile and provide little real value relative to the maintenance burden of debugging false-positive blocks across clusters.
- **`clusterPodCIDRs` from chart values, not auto-discovered.** Auto-discovery is provider-dependent (kubeadm vs. GKE vs. EKS vs. K3s all differ); a value the user names once is honest and portable.
- **Per-Service granularity, not per-pod.** Allowed: the backend's namespace + Service selector + Service target port. Not per-pod-IP. This is the natural NetworkPolicy granularity.
- **No per-Gateway annotation override.** The chart-level `enabled` switch is the only opt-out for v0.3.2. Adds less surface; opt-out is rare. Revisit if a real per-Gateway need surfaces.

## Risks

- **CNIs without NetworkPolicy support** (e.g., default Flannel) silently no-op the policy. Documented in chart README; not a regression (those users have no NetworkPolicy today either).
- **Service selector drift**: if a backend Service's selector changes after the NetworkPolicy is rendered, the policy is stale until the next reconcile. Mitigation: watch Services so a selector change triggers Gateway reconcile. v0.3.2 can rely on the existing Deployment-/Service-name watches to surface this; document the latency.
- **Backends behind a Service with empty selector** (headless, ExternalName) are silently skipped. Users with this pattern see no rule for that backend and traffic is blocked. Document.
