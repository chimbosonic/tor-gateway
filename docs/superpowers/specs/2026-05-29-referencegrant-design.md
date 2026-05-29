# Cross-Namespace ReferenceGrant Enforcement — Design

**Status:** approved, pending implementation plan
**Date:** 2026-05-29

## Problem

The operator currently honors cross-namespace references with no authorization check, violating the Gateway API contract and the secure-by-default / multi-tenant pillars:

- **HTTPRoute `backendRefs`:** the in-pod router resolves `backendRef.Namespace` to `<svc>.<ns>.svc` (`internal/router/httproute.go:69`, `resolver.go`) with no permission check. The HTTPRoute reconciler sets only parent `Accepted` + `attachedRoutes` — it never evaluates backendRefs or sets `ResolvedRefs`. A tenant can route their Gateway to a Service in another namespace without that namespace's consent.
- **`TorClientAuthPolicy.clientsSecretRef`:** has an optional `Namespace` field that the controller deliberately ignores (`gateway_controller.go:243`), so cross-namespace client-auth Secrets are silently unsupported.

ReferenceGrant is the Gateway API's opt-in consent mechanism: a resource in namespace A may reference a resource in namespace B only if a `ReferenceGrant` in B permits it (`from` group/kind/namespace → `to` group/kind, optional name).

## Goals

- Gate cross-namespace HTTPRoute `backendRefs` behind a ReferenceGrant, reflected in the route's `ResolvedRefs` status, and enforced in the data plane (no traffic to un-permitted cross-ns backends).
- Enable cross-namespace `TorClientAuthPolicy.clientsSecretRef`, gated by a ReferenceGrant in the Secret's namespace.
- Keep the Tor data-plane pods (router sidecar) **least-privilege** — no new RBAC on them.
- Fail closed: when permission is absent or not yet evaluated, deny the cross-namespace reference.

## Non-goals

- `OnionBalancePolicy.masterKeySecretRef` cross-namespace support — onionbalance HA is not yet implemented, so its grant path can't be exercised end-to-end. Out of scope.
- `BackendNotFound` semantics (a backendRef whose Service does not exist). We only gate the **grant** (`RefNotPermitted`); existence checking is a separate concern.
- Cross-namespace `parentRef` gating (HTTPRoute attaching to a Gateway in another namespace). Out of scope for this iteration.
- New manager flags or Helm chart values (none needed).

## Approach

**Controller is the authority; the router fails closed.** The operator (which already runs cluster-wide with broad RBAC and watches HTTPRoutes cluster-wide) evaluates ReferenceGrants and owns status. The router (one sidecar per Gateway, least-privilege, watches only its Gateway's namespace) gains **no** new permissions; it defers to the controller-written `ResolvedRefs` status. This was chosen over router-side enforcement specifically to avoid granting every Tor data-plane pod cluster-wide ReferenceGrant read.

Tradeoff accepted: data-plane granularity is route-level. A route mixing a permitted and an un-permitted cross-namespace backendRef resolves to `RefNotPermitted`, and the router drops *both* cross-namespace backends (fail-closed, safe, coarse). Same-namespace backends are never affected.

## Components

### A. Shared ReferenceGrant evaluator (pure)

A pure function with no client dependency (unit-testable in isolation), e.g. in a small `internal/refgrant` package or alongside the controller helpers:

```
Allows(grants []gwv1beta1.ReferenceGrant,
       from FromRef,   // {Group, Kind, Namespace}
       to   ToRef)     // {Group, Kind, Name}
       bool
```

Returns true iff some grant has a `spec.from` entry matching `from` exactly AND a `spec.to` entry matching `to`'s group+kind with `to.Name` empty (any) or equal to the referenced name. Core API group is the empty string `""`. The caller is responsible for passing the grants from the correct (target) namespace.

### B. backendRefs — controller status + router fail-closed

- **HTTPRoute reconciler** (`internal/controller/httproute_controller.go`):
  - Add RBAC marker `referencegrants: get;list;watch`; add a `Watches(&gwv1beta1.ReferenceGrant{}, ...)` whose map function enqueues HTTPRoutes located in each `spec.from[].namespace` of the changed grant.
  - For each managed route + parent, evaluate every `backendRef` whose effective namespace differs from the route's namespace: `from = {gateway.networking.k8s.io, HTTPRoute, route-ns}`, `to = {"", Service, backendRef-name}`, grants listed from the backend's namespace. Set the per-parent `ResolvedRefs` condition: `status=True, reason=ResolvedRefs` when all cross-ns backendRefs are permitted (or there are none); `status=False, reason=RefNotPermitted` otherwise. Same-namespace backendRefs are always permitted.
- **Router** (`internal/router/`): when converting an HTTPRoute to rules, include a backendRef whose namespace differs from the route's namespace **only if** the route's `ResolvedRefs` condition for this Gateway parent is `True`. Same-namespace backendRefs are always included. A rule left with no usable backend serves a 502 (consistent with an unavailable backend). No RBAC change.

### C. clientsSecretRef — controller-side check

In `findEffectiveClientAuth` (`gateway_controller.go`): if `clientsSecretRef.Namespace` is set and differs from the policy's namespace, require a ReferenceGrant in the Secret's namespace (`from = {policy.torgateway.io, TorClientAuthPolicy, policy-ns}`, `to = {"", Secret, secret-name}`). Permitted → use the cross-namespace Secret (mount path unchanged). Denied → fail closed: do not mount it, set a `False/RefNotPermitted` condition on the policy's ancestor status and emit an event. Same-namespace refs behave as today.

## Status & edge behavior

- `ResolvedRefs` reasons used: `ResolvedRefs` (True) and `RefNotPermitted` (False). `BackendNotFound` is out of scope.
- Deleting a grant flips affected routes to `RefNotPermitted`; the router drops the cross-ns backend on its next watch-driven rebuild. Re-adding the grant restores it.
- Until the controller has evaluated a freshly-created cross-ns route, `ResolvedRefs` is unset and the router excludes the cross-ns backend (fail-closed). Same-ns backends route immediately.
- A denied `clientsSecretRef` leaves the Tor service running without that client-auth Secret; the policy condition + event surface the denial (never silently enabled with an unauthorized Secret).

## Testing — TDD is mandatory

Every task in the implementation plan is **test-first**: write the failing test, run it to confirm it fails, write the minimal implementation, confirm green, commit. No production code is written before a failing test exists for it.

- **Unit (pure):** table-driven tests for `Allows` — exact from match, to group/kind match, name-scoped vs. any-name (`to.Name` empty), and no-match cases.
- **envtest (controller):**
  - cross-ns backendRef with no grant → `ResolvedRefs=False/RefNotPermitted`; create a matching ReferenceGrant → reconcile → `ResolvedRefs=True`.
  - same-ns backendRef → `ResolvedRefs=True` with no grant present.
  - name-scoped grant (`to.name` set) permits only the named Service.
  - `clientsSecretRef` cross-ns: denied (no grant) sets the policy `RefNotPermitted` condition and does not mount; granted mounts and enables auth.
- **Router unit:** a cross-ns backendRef is dropped when the route's `ResolvedRefs` is not True, included when True; same-ns backendRef always included; a rule reduced to zero backends yields no route/502.

## Implementation surface (no flags, no chart changes)

- Scheme: register `sigs.k8s.io/gateway-api/apis/v1beta1` in the manager (`cmd/manager/main.go`) and the envtest suite (`internal/controller/suite_test.go`) — currently only `apis/v1` (`gwv1.Install`) is registered. `ReferenceGrant` is served as `v1beta1` in gateway-api v1.5.1, so the watch/list must use `gwv1beta1.ReferenceGrant` (`v1beta1.ReferenceGrant` is a defined type based on `v1.ReferenceGrant`).
- New: shared `Allows` evaluator (+ its unit test).
- `internal/controller/httproute_controller.go`: ReferenceGrant watch + map func, backendRef evaluation, `ResolvedRefs` status, RBAC marker.
- `internal/controller/gateway_controller.go`: cross-ns `clientsSecretRef` grant check in `findEffectiveClientAuth` + policy condition/event.
- `internal/router/`: fail-closed cross-ns inclusion gated on `ResolvedRefs`.
- `config/rbac/role.yaml` + chart RBAC: regenerated for `referencegrants` read (operator only; router RBAC unchanged).
- Tests as above.
