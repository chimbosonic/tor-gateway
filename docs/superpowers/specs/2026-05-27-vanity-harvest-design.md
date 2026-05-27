# mkp224o vanity harvest orchestration — design

- **Date:** 2026-05-27
- **Status:** Approved, pending implementation
- **Owner:** Alexis Lowe

## Context

`internal/tor/vanity.go` already provides `VanityJob()` — a complete,
unit-tested builder that returns a hardened one-shot Job: an `mkp224o` init
container brute-forces a base32 prefix into an emptyDir, then a `finalize`
container reads the resulting `hs_ed25519_secret_key` / `hs_ed25519_public_key`
/ `hostname` and writes them into an output Secret. The `TorServicePolicy` CRD
exposes `vanityPrefix` (`^[a-z2-7]*$`, maxLength 8) and
`vanityAcknowledgeLongRunning`.

None of it is wired. `eff.VanityPrefix` is read into the effective policy config
in `gateway_resources.go` and then ignored; `ensureKeySecret` unconditionally
generates a random ed25519 keypair in-process whenever `<gw>-keys` is absent, so
a `vanityPrefix` has no effect. Concretely missing:

- the `finalize` binary the Job references (`FinalizeImage`) — there is no
  `cmd/` for it;
- an `mkp224o` container image (none exists in the repo);
- manager flags for the `mkp224o` / `finalize` images;
- enforcement of `vanityAcknowledgeLongRunning` — the type comment claims the
  operator caps attempts for prefixes over 6 chars, but the only `XValidation`
  on the type targets `targetRefs`;
- operator RBAC for `batch/jobs` (it grants `serviceaccounts` / `roles` /
  `rolebindings` for the router sidecar's per-Gateway SA, but not Jobs).

## Goals

- A `TorServicePolicy.vanityPrefix` on a Gateway with no key yet produces a
  hidden-service key whose `.onion` carries that prefix, provisioned via a
  one-shot Job — never in the long-running operator.
- The controller remains the **sole creator** of the canonical `<gw>-keys`
  Secret (OwnerReferences, labels, never-overwrite — as today).
- Bounded cost and honest status: a harvest that exceeds its deadline fails
  loudly and stops, rather than looping or silently substituting a random key.
- Tests cover the orchestration without running `mkp224o` in the unit/envtest
  path.

## Non-goals (YAGNI)

- Per-policy deadline / resource CRD fields (use a manager flag + the builder's
  defaults).
- Re-harvesting or replacing an existing key (would change a live `.onion`).
- Vanity for the onionbalance master key (HA is not built yet).
- Retry / backoff on a failed harvest.

## Decisions (settled during brainstorming)

| Question | Decision |
|---|---|
| When does a prefix trigger a harvest? | **Creation-time only.** Honored only when `<gw>-keys` is absent. A prefix set against an existing key is ignored (event); the key is never regenerated. |
| Harvest exceeds its deadline? | **Fail and stop.** `Programmed=False` + Warning event; no auto-retry, no random-key fallback. |
| `mkp224o` image | **Build in-repo** (`images/mkp224o`), joining the signed/SBOM'd release matrix. |
| Key handoff | **Promote via controller.** The controller pre-creates an empty `<gw>-vanity-out` (owner=Gateway); the harvest pod updates it in place; the controller parses it and creates `<gw>-keys` via `BuildKeySecret`. |
| `finalize` image | **Dedicated `cmd/vanity-finalize` image** (one-cmd-per-image convention; cheap cross-compiled Go). |

## Design

### A. Images & flags

- **`images/mkp224o/Dockerfile`** — multi-stage: build pinned `cathugger/mkp224o`
  (libsodium + autotools) → minimal nonroot runtime; `ENTRYPOINT ["mkp224o"]`;
  runs as UID 65532 under a read-only rootfs (writes only the emptyDir
  `/workdir`). Makefile `image-mkp224o` + `MKP224O_IMG`, wired into the `images`
  aggregate, `docker-push`, and the release matrix (multi-arch via QEMU, like
  `tor`).
- **`cmd/vanity-finalize/main.go`** → image `tor-gateway-vanity-finalize` via the
  shared `Dockerfile` (`--build-arg BINARY=vanity-finalize`). Reads the three key
  files from `--workdir` and **updates** the pre-created Secret `--secret-name`
  in `--namespace` with them (get → update), then exits. No owner-ref args — the
  controller owns the Secret it pre-created. Joins the release matrix as a
  cross-compiled Go binary.
- **Manager flags** — `--mkp224o-image`, `--vanity-finalize-image` (default to
  the released refs), `--vanity-active-deadline` (default `1h`). Extend
  `RuntimeImages` with `Mkp224o` + `VanityFinalize`; wire through chart
  `deployment.yaml`, `values.yaml` (`torRuntime.mkp224oImage`,
  `torRuntime.vanityFinalizeImage`), and the `tor-gateway.runtimeImage` helper.

### B. RBAC

- **Per-Gateway vanity identity** — `BuildVanityServiceAccount` /
  `BuildVanityRole` / `BuildVanityRoleBinding`: SA `<gw>-vanity`, a Role granting
  `get;update;patch` on the single named Secret `<gw>-vanity-out` (RBAC
  `resourceNames` constrains these verbs — unlike `create`), and the binding;
  all owner-referenced to the Gateway. Mirrors the existing router-SA builders.
- **Operator role** gains `batch`/`jobs`: `create;get;list;watch;delete`. Added
  to `config/rbac/role.yaml`, then `make chart-sync` propagates it to the chart
  (CI drift check covers it).

### C. Reconcile flow (creation-time only)

At the `ensureKeySecret` decision point:

```
<gw>-keys exists?
 ├─ yes → use it. If an applicable vanityPrefix is set and the live .onion does
 │        not start with it → emit Normal event VanityPrefixIgnored; continue.
 └─ no  → applicable TorServicePolicy with vanityPrefix set?
          ├─ no  → FreshKeyPair() in-process (unchanged).
          └─ yes → harvest:
                   1. ensure <gw>-vanity SA/Role/RoleBinding (owner=Gateway)
                      and the empty <gw>-vanity-out Secret (owner=Gateway)
                   2. ensure Job <gw>-vanity = tor.VanityJob{prefix, images,
                      deadline, SA, OutputSecretName=<gw>-vanity-out}
                      (owner=Gateway)
                   3. observe:
                      • <gw>-vanity-out populated (has the key files) →
                        tor.ParseFiles → BuildKeySecret → Create <gw>-keys
                        (owner+labels) → delete <gw>-vanity-out and the Job →
                        continue provisioning
                      • Job DeadlineExceeded/Failed → Programmed=False
                        (VanityHarvestFailed) + Warning event → stop
                      • else running → Programmed=False (VanityHarvestInProgress)
                        + Normal event → requeue
```

`ensureKeySecret` (or a wrapping step) returns a "harvest pending" signal so the
rest of reconcile (ConfigMap / Deployment / Service) waits rather than erroring
on a missing key. The reconciler adds `Owns(&batchv1.Job{})` so the Job's status
transitions — and updates to `<gw>-vanity-out` (an owned Secret) — re-enqueue the
Gateway. The throwaway Secret is owner-referenced to the Gateway (the controller
pre-creates it, so it sets the ref directly) for cascade safety, and the
controller deletes it explicitly after promotion.

### D. Validation, status, recovery

- **CRD validation** — add `XValidation` to `TorServicePolicySpec`:
  `self.vanityPrefix.size() <= 6 || self.vanityAcknowledgeLongRunning`,
  rejecting long prefixes without the acknowledgment at admission. Closes the
  unenforced-ack gap; regenerate `config/crd/bases/...`.
- **Conditions** (Gateway) — `Accepted=True` (config valid); `Programmed=False`
  with reason `VanityHarvestInProgress` while running and `VanityHarvestFailed`
  on deadline/failure.
- **Events** — Normal `VanityHarvestStarted`, Warning `VanityHarvestFailed`,
  Normal `VanityPrefixIgnored`.
- **Recovery (no auto-retry).** The controller records the failed prefix in the
  Gateway status, so a re-created Job is **not** spun up for a prefix already
  marked failed — this survives the Job's `TTLSecondsAfterFinished` GC and
  prevents an hourly retry loop. Editing `vanityPrefix` to a shorter value
  clears the recorded failure and triggers a fresh harvest; a too-hard prefix is
  the user's signal to pick a shorter one.

### E. Testing (first-class)

- **Unit** — `cmd/vanity-finalize` (workdir → Secret payload; missing-file /
  malformed errors; OwnerReference stamping). The `VanityJob` builder is already
  covered.
- **envtest** (controller; `mkp224o` is never run — the Job's output is faked):
  - new Gateway + `vanityPrefix` → asserts `<gw>-vanity` SA/Role/RoleBinding and
    the Job exist with correct args (prefix, images, deadline) and owner;
    `Programmed=False` / `VanityHarvestInProgress`.
  - inject `<gw>-vanity-out` → reconcile → canonical `<gw>-keys` created
    (owner + labels), `.onion` derived, throwaway + Job deleted, provisioning
    proceeds.
  - mark the Job `DeadlineExceeded` → `Programmed=False` /
    `VanityHarvestFailed`, no recreate, Warning event; failed prefix recorded.
  - existing `<gw>-keys` + `vanityPrefix` → no Job, `VanityPrefixIgnored` event.
  - CEL ack rule rejects a 7-char prefix without acknowledgment (apply-time).
- **Image smoke** — `make image-mkp224o` builds; harvest a 1-char prefix
  (sub-second) as UID 65532 under a read-only rootfs → valid key files whose
  format `tor.ParseFiles` accepts.
- **Optional kind e2e** (slow, non-gating, matching the existing e2e philosophy)
  — a real 1-char harvest end-to-end through the operator → a `.onion` carrying
  the prefix.

## Files touched

- **Create:** `images/mkp224o/Dockerfile`; `cmd/vanity-finalize/main.go` (+
  `_test.go`); `internal/controller/gateway_vanity_test.go` (envtest).
- **Modify:** `internal/controller/gateway_controller.go` (harvest
  orchestration, `Owns(&batchv1.Job{})`); `internal/controller/gateway_resources.go`
  (vanity RBAC builders, image plumbing into the `VanityJob` call);
  `internal/controller/names.go` (`<gw>-vanity`, `<gw>-vanity-out`);
  `cmd/manager/main.go` (flags + `RuntimeImages`).
- **Unchanged:** `internal/tor/vanity.go` — the `VanityJob` builder's finalize
  args (`--workdir`/`--namespace`/`--secret-name`) already suffice; finalize
  updates the pre-created, controller-owned Secret in place.
- **Modify:** `api/v1alpha1/torservicepolicy_types.go` (ack `XValidation`) →
  regenerate `config/crd/bases/...` → `make chart-sync`.
- **Modify:** `config/rbac/role.yaml` (`batch/jobs`) → `make chart-sync`.
- **Modify:** `Makefile` (`image-mkp224o`/`MKP224O_IMG`,
  `image-vanity-finalize`/`VANITY_FINALIZE_IMG`); `.github/workflows/release.yml`
  (matrix entries `mkp224o`, `tor-gateway-vanity-finalize`); chart
  `deployment.yaml` / `values.yaml` / `_helpers.tpl`.

## Verification

- envtest suite green (harvest start, promotion, failure, ignored-on-existing,
  ack rejection).
- `make image-mkp224o` builds; the smoke harvest produces a key
  `tor.ParseFiles` / `BuildKeySecret` accept.
- `make chart-sync && git diff --exit-code charts/` clean.
- `actionlint` passes on the extended release matrix.

## Risks / to resolve during planning

- **mkp224o multi-arch build** (C / autotools / libsodium) needs QEMU — confirm
  build time stays sane; mirror the `tor` image's caching approach.
- **Promotion window** — key material briefly lives in both `<gw>-vanity-out`
  and `<gw>-keys`. Mitigated by immediate deletion of the throwaway and its
  create-only, single-Secret RBAC scope.
- **Key-format parity** — `mkp224o` output must match the Tor on-disk
  `hs_ed25519_secret_key` format (header included) that `tor.ParseFiles` expects;
  verify in the image smoke before relying on promotion.
- **"Harvest pending" threading** — `ensureKeySecret` currently returns
  `(secret, keypair, error)`; the pending signal must propagate without looking
  like an error to the main reconcile loop. Settle the exact signature in the
  plan.
