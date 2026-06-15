# Mode B Hardening & Graduation (v0.5) — Design

**Date:** 2026-06-15
**Status:** Design approved; ready for plan.

## Problem

Mode B (onionbalance HA) shipped **experimental** in v0.4.0. One known correctness
gap and several observability/robustness gaps stand between it and a stable
graduation:

1. **Cross-NS RBAC leak on deletion.** A Gateway deleted *while in Mode B* with a
   cross-namespace master Secret leaves its cross-namespace `Role` +
   `RoleBinding` behind. Those objects cannot carry an owner reference to the
   Gateway (owner refs are namespace-local), so Kubernetes garbage collection
   never reaps them. `cleanupModeBResources` already deletes them by label, but
   `Reconcile` returns early on `apierrors.IsNotFound` (the Gateway is already
   gone), so the cleanup never runs. `FinalizerName` is defined in `names.go`
   but never added — reserved for exactly this.
2. **Health is a bare count.** The OBP exposes `ReadyBackends int32`, and the
   Gateway's `Programmed` condition is set to `True` unconditionally once Mode B
   is provisioned (`updateStatusModeB`, `gateway_controller.go:1024-1031`). There
   is no single "is HA actually working" signal.
3. **In-sidecar failures are invisible.** obrefresh logs config-render and SIGHUP
   failures inside the frontend pod (`internal/onionbalance/refresher.go:192`);
   nothing surfaces to `kubectl`.
4. **Teardown/transition edges hot-loop.** A master Secret deleted while in use
   makes `ensureModeB` error and requeue-thrash instead of surfacing a clear
   condition.

## Goals

1. No resource leaks on Gateway deletion or Mode A↔B transition.
2. A single, honest, kubectl-visible health signal for Mode B.
3. In-sidecar (obrefresh) failures visible without reading pod logs.
4. Misconfiguration fails fast with a legible reason.
5. Graduate Mode B from experimental to stable once 1–4 land.

## Non-goals

- **Tor-level descriptor-liveness verification.** The manager cannot query HSDirs;
  health is reconcile-observable cluster state only. Actual reachability stays
  covered by the e2e/realtor smoke tests. The health condition's message states
  this boundary so it is not oversold.
- Master key rotation, multi-master, or any new Mode B *feature*. This is a
  hardening pass, not a feature release.
- Custom Prometheus metrics for Mode B (possible later; not required for
  graduation).

## Architecture

Six workstreams, sequenced **1 → 2 → 3 → 5 → 4 → 6**. Each lands independently
green. They share three surfaces: the Gateway reconciler
(`internal/controller/gateway_controller.go`), the OBP type/controller
(`api/v1alpha1/onionbalancepolicy_types.go`,
`internal/controller/onionbalancepolicy_controller.go`), and obrefresh
(`cmd/obrefresh/main.go`, `internal/onionbalance/refresher.go`).

### Workstream 1 — Finalizer (cross-NS leak fix)

Add `FinalizerName` (`torgateway.io/finalizer`, already defined) to **every
managed Gateway**, immediately after the `gatewayClassManagedByUs` check in
`Reconcile` and before mode dispatch — so the finalizer is present before any
cross-NS resource is created.

Deletion handling, inserted after the managed check:

```
if !gw.DeletionTimestamp.IsZero() {
    if controllerutil.ContainsFinalizer(gw, FinalizerName) {
        if err := r.cleanupModeBResources(ctx, gw); err != nil {
            return ctrl.Result{}, err   // requeue; finalizer stays until clean
        }
        controllerutil.RemoveFinalizer(gw, FinalizerName)
        if err := r.Update(ctx, gw); err != nil {
            return ctrl.Result{}, err
        }
    }
    return ctrl.Result{}, nil
}
if controllerutil.AddFinalizer(gw, FinalizerName) {
    if err := r.Update(ctx, gw); err != nil {
        return ctrl.Result{}, err
    }
}
```

- In-namespace children continue to cascade via owner references; the finalizer
  exists *solely* to run the cross-NS label GC before the Gateway object is
  removed. `cleanupModeBResources` is idempotent and `IgnoreNotFound`, so it is
  safe to run on a Mode A Gateway (deletes nothing).
- **Decision (approved):** add to *all* managed Gateways, not only Mode B ones.
  `cleanupModeBResources` is a no-op for Mode A, and Gateways transition modes,
  so scoping to Mode-B-only would invite a missed-cleanup race. Accepted
  tradeoff: a managed Gateway's deletion blocks while the operator is down — the
  standard finalizer cost, acceptable for an operator that owns these objects.
- The finalizer is only ever added to Gateways of our class, so Gateways of
  other classes are never blocked.

### Workstream 2 — Teardown / transition edges

- **Master Secret missing/deleted while in use:** `ensureModeB`'s master-key
  fetch failure becomes a `Programmed=False` / reason `MasterSecretNotFound`
  condition on the Gateway plus a `Warning` event, with no error returned that
  would hot-loop the reconcile (return nil after setting the condition; a Secret
  re-create re-triggers via the existing Watch). Distinguish genuinely-transient
  errors (API server blips → still return err to requeue) from
  Secret-not-found (surface + stop).
- **A↔B transition GC:** audit that `cleanupModeAResources` /
  `cleanupModeBResources` leave nothing orphaned, especially cross-NS pairs on
  B→A. Backed by an explicit envtest asserting zero leftover cross-NS
  Role/RoleBinding after a B→A transition.

### Workstream 3 — Health condition (manager-owned)

Replace the unconditional `Programmed=True` in `updateStatusModeB` with a
computed value:

- **Healthy (`Programmed=True`, reason `Programmed`)** when the frontend
  Deployment is `Available` AND the backend StatefulSet has `readyReplicas ≥ 1`.
- **Not yet (`Programmed=False`)** otherwise, with a specific reason:
  `FrontendNotReady` or `BackendsNotReady`, message naming the observed counts.

The manager already reads these objects elsewhere (`ReadyBackends` is computed by
listing backend pods); the health computation reuses that. The OBP's existing
`ReadyBackends` count is retained; the new condition is the summary signal. The
Gateway `Owns` the Deployment and StatefulSet, so readiness changes already
requeue the reconcile and refresh the condition.

Message text states the honesty boundary, e.g.:
`"Mode B provisioned; frontend Available and 3/3 backends ready (reconcile-observable; Tor descriptor liveness not verified here)"`.

### Workstream 4 — obrefresh failure Events

obrefresh emits `Warning` Kubernetes Events on the two failure paths it owns:
config-render failure and SIGHUP failure (`refresher.go` `rebuild`/`fire`). The
`involvedObject` is the **Gateway** (obrefresh already knows
`GatewayName`/`GatewayNamespace`), so `kubectl describe gateway <gw>` surfaces
refresh failures.

- obrefresh constructs an event recorder from its existing controller-runtime
  client (or a typed `corev1` client) targeting the Gateway by name/namespace.
- The frontend ServiceAccount's `Role` (built in `gateway_resources_ha.go`) gains
  `events: create` (and `patch` for event aggregation) in `gw.Namespace`.
- Failure events only — no Normal-on-success spam (the manager already emits
  Normal Gateway events like `BackendsRolling` for steady-state transitions).
- Reasons: `OnionbalanceConfigRenderFailed`, `OnionbalanceReloadFailed`.

### Workstream 5 — Validation hardening (audit + fill)

Most of this **already exists**: `onionbalancepolicy_controller.go` defines
`ReasonOBPGatewayMissing`, `ReasonOBPMasterKeyMissing`, `ReasonOBPMasterKeyInvalid`,
`ReasonOBPMasterKeyCrossNSDenied`, with `reasonFromMasterErr` mapping
`validateMasterKey` / `tor.ValidateMasterKeySecret` errors to them, and replica
bounds are CEL-enforced (1–8). Scope here is an **audit + gap-fill**, not a
rebuild:

- Confirm every `Accepted=False` path maps to a distinct, specific reason (no
  generic fall-through).
- Ensure the same master-key validation gating OBP acceptance also gates the
  Gateway-side `ensureModeB` so a policy that flips invalid post-acceptance
  surfaces consistently (ties into Workstream 2's `MasterSecretNotFound`).
- Add table-driven tests covering each reason if any are unencoded.

### Workstream 6 — Graduation (docs, last)

Only after 1–5 land green:

- Drop "experimental" from `README.md:80`, `docs/PLAN.md:37`, and the
  `SECURITY.md` Mode B section.
- Note the finalizer-backed clean teardown and the health condition as the
  graduation basis.
- Update the OBP CRD type doc comment if it implies experimental status.

## Error handling

- Finalizer cleanup that errors keeps the finalizer in place and requeues — the
  Gateway object lingers (Terminating) until cleanup succeeds, which is the
  correct, leak-free behavior.
- Master-Secret-not-found is surfaced and stops requeue-thrash; transient API
  errors still requeue.
- obrefresh event emission is best-effort: a failure to *emit* an event must
  never crash obrefresh or block a SIGHUP (log-and-continue).

## Testing

- **envtest (controller):** finalizer added on first reconcile of a managed
  Gateway; on delete, cross-NS Role/RoleBinding GC'd and finalizer removed;
  B→A transition leaves zero cross-NS pairs; health condition transitions
  False→True as frontend/backends become ready; `MasterSecretNotFound` surfaces
  without hot-loop; each validation reason asserted.
- **unit (obrefresh):** recorder receives `Warning`/`OnionbalanceConfigRenderFailed`
  on a render error and `OnionbalanceReloadFailed` on a SIGHUP failure; emission
  failure does not propagate.
- **No new e2e spec.** The deletion/finalizer flow needs neither real Tor nor a
  kubelet, and v0.4.0 deliberately relocated cross-NS coverage out of e2e to the
  controller layer (the `ob-crossns` e2e fixture was removed). envtest runs a
  real kube-apiserver that faithfully honors finalizers (object stays
  `Terminating` until the finalizer is removed), so the leak regression — set
  deletion, reconcile, assert cross-NS Role/RoleBinding deleted by our cleanup
  and finalizer removed — is covered there, consistent with the v0.4.0 layering
  decision. (Note: envtest has no GC controller, so we assert our *explicit*
  cleanup, not owner-ref cascade — which is exactly the cross-NS path that owner
  refs cannot cover anyway.)

## Out of scope / follow-ups

- Mode B Prometheus metrics.
- Tor-level descriptor-liveness probing from the manager.
- Master key rotation.
