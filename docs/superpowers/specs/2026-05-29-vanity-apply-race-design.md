# Vanity Harvest Apply-Order Race — Design

**Status:** approved, pending implementation plan
**Date:** 2026-05-29

## Problem

When a `Gateway` (class `tor-gateway`) and its `TorServicePolicy` (carrying a
`vanityPrefix`) are applied together, the Gateway can reconcile and generate a
key before the policy is observed. `ensureKeySecret` resolves the effective
policy from the **cached** client (`findEffectivePolicy` → informer `List`);
if the policy is not yet in cache, `VanityPrefix` is empty, so the operator
generates a **random** ed25519 key and persists it. Because keys are never
regenerated (a deliberate safety invariant — losing/replacing a key
permanently changes the published `.onion`), the vanity prefix is then
silently ignored: the published address does not match the requested prefix.

Observed 2026-05-29 deploying to the `cenosco-homelab` cluster: a Gateway with
`vanityPrefix: dp42` published a random `4q65…onion`. Deleting and recreating
the Gateway (with the policy already established) produced the correct
`dp42…onion`.

## Goals

- A Gateway whose `TorServicePolicy` sets a `vanityPrefix` reliably harvests a
  vanity key, even when Gateway and policy are applied together.
- Provide a deterministic, explicit way to guarantee the harvest regardless of
  apply ordering (including late / GitOps-staged policy application).
- Preserve the **never-regenerate** invariant absolutely: the fix only makes
  the *first* key-generation decision more careful; it never replaces an
  existing key.
- No penalty (no added delay) for plain non-vanity Gateways.

## Non-goals

- Re-harvesting or replacing a key that already exists (rejected:
  conflicts with the never-regenerate safety invariant).
- A wall-clock "grace window" heuristic (considered and dropped in favor of
  the two mechanisms below).
- New manager flags or Helm chart values (this design needs none).

## Approach

Two complementary mechanisms, both acting only on the "key Secret absent"
branch of `ensureKeySecret`:

- **A — Authoritative policy read (transparent default).** The race is a stale
  cache read. When the cached policy lookup finds no `vanityPrefix` on a
  keyless Gateway, perform one direct API-server read (via
  `mgr.GetAPIReader()`) of `TorServicePolicy` objects targeting the Gateway
  before committing to a random key. By the time a reconcile reaches key
  generation, a policy applied in the same `kubectl apply` is already in etcd
  (just not yet in the informer cache), so the authoritative read sees it.
  Requires no user action.

- **B — Explicit await annotation (opt-in).** A Gateway annotation
  `torgateway.io/await-vanity: "true"` instructs the operator never to
  generate a random key for that Gateway while no matching `vanityPrefix`
  policy exists. Deterministic for *every* ordering, including a policy that
  arrives much later or via a separate GitOps reconciliation. The existing
  policy watch re-enqueues the Gateway when a matching policy appears, so the
  harvest fires event-driven with no timed requeue.

A handles accidental races invisibly; B handles intentional late-binding
explicitly. They compose: A always runs on the keyless path; B only changes
the terminal fallback (wait vs. generate-random).

## Behavior — keyless key-generation decision

Within `ensureKeySecret`, when the canonical key Secret is absent, decide in
this order:

1. Cached effective policy has a non-empty `vanityPrefix` → **harvest**
   (existing `runVanityHarvest` path; unchanged).
2. No cached vanity policy → **authoritative re-read (A)**: direct API-server
   `List` of `TorServicePolicy` in the Gateway's namespace via `APIReader`,
   matched against the Gateway with the existing `policyTargets` logic. If a
   `vanityPrefix` is found → **harvest**.
3. Still no vanity policy, **and** the Gateway has annotation
   `torgateway.io/await-vanity: "true"` (B) → return sentinel
   `errAwaitingVanityPolicy`. `Reconcile` maps it to
   `Accepted=True / Programmed=False / AwaitingVanityPolicy` and returns
   without requeue. The policy watch re-enqueues on a matching policy create.
4. Otherwise → **generate a random key** (today's behavior; plain non-vanity
   Gateways are unaffected and undelayed).

The non-keyless branch (key Secret exists) is unchanged, including the
`VanityPrefixIgnored` event when a `vanityPrefix` is requested after a key
already exists.

## Implementation surface

No new flags, no Helm chart changes.

- `internal/controller/gateway_controller.go`
  - Add field `APIReader client.Reader` to `GatewayReconciler`.
  - Factor the list-and-match logic into
    `effectivePolicyFrom(ctx, reader client.Reader, gw) (EffectiveServicePolicy, error)`.
    `findEffectivePolicy` calls it with the cached client (hot path unchanged);
    the keyless double-check calls it with `r.APIReader`.
  - Add sentinel `errAwaitingVanityPolicy` and condition reason
    `ReasonAwaitingVanityPolicy = "AwaitingVanityPolicy"`.
  - Extend `ensureKeySecret`'s keyless branch with the decision order above;
    map the new sentinel in `Reconcile` (alongside `errHarvestPending` /
    `errHarvestFailed`) to `setProgrammingCondition`, returning
    `ctrl.Result{}, nil` (event-driven via the existing policy watch).
- `internal/controller/names.go`
  - `awaitVanityAnnotation = "torgateway.io/await-vanity"`.
- `cmd/manager/main.go`
  - Wire `APIReader: mgr.GetAPIReader()` into the `GatewayReconciler`.
- Docs / sample
  - Document that a vanity Gateway should set
    `torgateway.io/await-vanity: "true"` for a guaranteed harvest; mechanism A
    covers the common apply-together case automatically.

## Edge cases

- **Genuinely-late policy** (added after a real key exists): still ignored,
  surfaced by the existing `VanityPrefixIgnored` event. The annotation is how a
  user avoids this.
- **Operator restart** seeing an old keyless+annotated Gateway with no policy:
  remains `AwaitingVanityPolicy` (correct — explicit wait).
- **Annotation set but the policy targets a different Gateway:** no match →
  keeps waiting (the user's explicit choice).
- **Annotation set, policy never created:** Gateway stays
  `Programmed=False/AwaitingVanityPolicy` with a clear message; no key, no
  `.onion`. Acceptable because it is explicitly requested.

## Testing

- **Unit:** `effectivePolicyFrom` reads from whichever reader it is given
  (verifies the factoring and that the keyless path can use a distinct reader).
- **envtest (`internal/controller`):**
  - Annotated keyless Gateway, no policy → **no** key Secret created,
    `Programmed=False/AwaitingVanityPolicy`; then create a matching
    `vanityPrefix` policy → reconcile → harvest Job appears.
  - **Un**annotated keyless Gateway, no policy → random key still generated
    (regression guard for the unchanged non-vanity path).
  - Keyless Gateway with a matching `vanityPrefix` policy already present →
    harvests (existing behavior still passes).
- The pure cache-lag path (A) cannot be forced deterministically under envtest
  (the test client is not a lagging cache); its logic is covered by the
  `effectivePolicyFrom` unit test plus the existing harvest specs.

## Rollout

Behavioral-only change to the operator; ships in the next release. Combined
with the deployment guidance, the recommended workflow for a vanity Gateway is
to set `torgateway.io/await-vanity: "true"` on the Gateway (or apply the policy
first); mechanism A makes the common apply-together case work without it.
