# v0.4.0 release fixes — design

**Target tag:** `v0.4.0`
**Status:** design approved 2026-06-05
**Predecessor review:** pre-release multi-angle review of `v0.3.3..HEAD` (72 commits) — 5 P0, 10 P1, 8 P2, ~10 P3 findings.

## Goal

Ship a single `v0.4.0` that fixes every finding from the pre-release review. After v0.4.0, Onionbalance HA (Mode B) is **functionally correct on a fresh chart install** and the security posture matches the `SECURITY.md` claims. Mode B remains experimental; the OBP CRD stays `v1alpha1`.

## Non-goals

- Graduating Mode B to stable. That waits for v0.5.
- Reworking Mode A behavior. Mode A only changes where Stack 3 corrects the leaks in `cleanupModeAResources` and adds Mode B coverage to the per-Gateway NetworkPolicy.
- Introducing new external dependencies (CSI Secrets store, admission webhooks, etc.).
- CHANGELOG.md. Release notes will be authored at the GitHub Release tag.

## Architecture

Three stacks of work; each is one PR. Stack 1 must merge before Stacks 2 and 3.

### Stack 1 — API-fetch architecture for Secrets

The architectural rework. Addresses:

- **H3** backend-key containment (every backend pod mounted every backend Secret via Projected volume)
- **H4** frontend SA over-broad (`secrets get/list/watch` namespace-wide with no scoping)
- **B4** cross-NS `MasterKeySecretRef` advertised but broken at pod mount
- **M5** cross-NS ReferenceGrant race (no re-validation in `ensureModeB`)

**Pattern:** drop Secret volume mounts on both pod templates. An init container fetches only the bytes a given pod needs via the in-cluster Kubernetes API and writes them to an `emptyDir` consumed by the runtime container.

#### Binary surface

`cmd/tor-init` is reused with a new flag `--api-fetch-secret=<namespace>/<name>` that writes the referenced Secret's `hs_ed25519_secret_key`, `hs_ed25519_public_key`, and `hostname` fields to the destination path. Implementation:

- Import `k8s.io/client-go/kubernetes` and `k8s.io/client-go/rest`.
- Use `rest.InClusterConfig()` to pick up the pod's mounted SA token.
- New flag replaces the role of `--per-pod-keys-base` (which currently expects a pre-mounted projected volume). The existing flag is removed.
- Existing flags (`--dst`, `--src`, `--ob-master-address`, etc.) are unchanged.

No new image. No new cosign target. No new chart value.

#### Backend StatefulSet (`gateway_resources_ha.go`)

- Remove the `keys` Projected volume from `backendPodVolumes`.
- Init container `tor-init` invocation: add `--api-fetch-secret=$(METADATA_NAMESPACE)/<gw>-backend-${INDEX}-keys` where `INDEX` is derived from `POD_NAME`'s ordinal suffix via the downward API. Pseudo-args:

  ```
  - --dst=/var/lib/tor/hs/hs
  - --ob-master-address=<master>
  - --api-fetch-secret=$(METADATA_NAMESPACE)/<gw>-backend-$(POD_ORDINAL)-keys
  ```

  `tor-init` extracts the ordinal from `POD_NAME` itself (`strings.LastIndex(name, "-")`) — no extra downward API substitution needed in the manifest.

- Backend pods continue to use the existing per-Gateway router ServiceAccount (`RouterSAName(gw)`). Its Role gains:

  ```yaml
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get]
    resourceNames: [<gw>-backend-0-keys, ..., <gw>-backend-(N-1)-keys]
  ```

  The `resourceNames` list is materialized at reconcile time from `OBP.Spec.Replicas`. `ensureRouterRBAC` is updated to emit this rule when Mode B is active; otherwise only the Mode A rule (`httproutes get/list/watch`) is emitted.

#### Frontend Deployment (`gateway_resources_ha.go`)

- Remove the `ob-keys` SecretVolumeSource entirely.
- New init container `master-fetch` runs `tor-init --api-fetch-secret=<masterRef.Namespace>/<masterRef.Name> --dst=/etc/onionbalance/keys`.
- The `ob-config` volume stays an `emptyDir`; `obrefresh` populates it as today (M4 removes the now-orphan `BuildOnionbalanceConfigMap`).
- Frontend pod's ServiceAccount is `FrontendName(gw)` (existing). `BuildFrontendRole` is rewritten:

  ```yaml
  # In gw.Namespace
  - apiGroups: [""]
    resources: [secrets]
    verbs: [list, watch]
    # No resourceNames (RBAC limitation). Narrowed in code by informer filters.
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get]
    resourceNames: [<gw>-backend-0-keys, ..., <gw>-backend-(N-1)-keys]
  ```

  When `MasterKeySecretRef.Namespace == ""` or equals `gw.Namespace`, the master Secret name is appended to the in-namespace `get` rule's `resourceNames`.

  When `MasterKeySecretRef.Namespace != gw.Namespace`, the operator additionally creates:

  ```yaml
  # In masterRef.Namespace
  kind: Role
  rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get]
    resourceNames: [<masterRef.Name>]

  kind: RoleBinding
  subjects:
  - kind: ServiceAccount
    name: <FrontendName(gw)>
    namespace: <gw.Namespace>
  roleRef:
    kind: Role
    name: <derived>
  ```

  Both carry an `ownerRef` to the Gateway so they GC on Gateway deletion. The cross-NS RoleBinding is recreated whenever `MasterKeySecretRef.Namespace` changes.

  The operator's existing cluster-scoped RBAC already permits `rolebindings/roles create/delete/get/list/patch/update/watch` (confirmed: `charts/tor-gateway/files/rbac/manager-role-rules.yaml:110-122`). No new manager-level privilege.

#### `obrefresh` informer

The Secret informer's `LabelSelector` adds `torgateway.io/owner-uid=<gw.UID>` in addition to `gateway` + `role=backend`. `BuildBackendKeySecret` sets this label. Tenant-planted Secrets without the operator-set UID are skipped. (Defense in depth alongside the H9 ownerRef check inside `backendsFromSecrets`.)

#### `ensureModeB` ReferenceGrant re-validation (M5)

`ensureModeB` calls the OBP reconciler's existing `masterKeyReferenceGrantAllows` helper before reading the master Secret. If the grant is missing or revoked, the function returns a `ReferenceGrantMissing`-tagged error; the caller flips `Programmed=False` with reason `PolicyNotAccepted` and emits an Event. This closes the race where an OBP author edits `MasterKeySecretRef.Namespace` after `Accepted=True`.

#### Removal of `BuildOnionbalanceConfigMap` (M4)

The function and its caller in `ensureModeB` are deleted. The `<gw>-onionbalance-config` ConfigMap is added to the cleanup paths for one release so existing installs GC their orphan. (After v0.5, the cleanup line can be removed.)

#### Failure modes

| Trigger | Behavior |
|---|---|
| Init `API GET` fails (RBAC, transient) | Init container exits non-zero; kubelet retries with StatefulSet backoff. `emptyDir` stays empty. |
| Secret not yet created (race) | Init container 404s, retries. Eventually consistent. |
| Cross-NS RG revoked | Next reconcile re-checks, OBP flips `Accepted=False`, `ensureModeB` enters cleanup. Existing pods keep their already-fetched master key on `emptyDir` until restart — credentials are not retroactively revoked, but no new pods can fetch. Documented in SECURITY.md. |
| Master Secret rotated in source NS | Pod restart picks up new bytes. No persistent stale state. |

### Stack 2 — Mechanical fixes

Independent commits. Each fixes one ticket. Land in parallel after Stack 1.

#### Controller (`internal/controller/gateway_controller.go`, `onionbalancepolicy_controller.go`)

| ID | Change |
|---|---|
| H1 | `OnionBalancePolicyReconciler.SetupWithManager` adds `.Watches` for `Secret`, `Gateway`, `ReferenceGrant`, `TorServicePolicy` with `EnqueueRequestsFromMapFunc` that returns dependent OBPs. |
| H5 | `cleanupModeAResources` deletes `KeySecretName(gw)`, `TorrcConfigMapName(gw)`, `NetworkPolicyName(gw)`, vanity Jobs, vanity output Secrets, and the `RouterRBACName(gw)` SA/Role/RoleBinding trio. |
| H6 | `ensureModeB` shrink-then-GC: shrink the StatefulSet first; `gcOrphanBackendSecrets` runs on the next reconcile only when `StatefulSet.Status.Replicas == Spec.Replicas`. |
| H7 | `findEffectiveOnionBalance` adds lexical-min tiebreak (`if matched == nil \|\| p.Name < matched.Name`). Accepted check is scoped to the ancestor whose `AncestorRef` matches the current `gw`. |
| M2 | `cleanupModeBResources` annotation gate changes from `if gw.Annotations != nil` to precise key-existence checks. Error from `r.Update` is propagated, not discarded. |
| M3 | `updateStatusModeB` wraps both writes in `retry.RetryOnConflict(retry.DefaultRetry, ...)`. |
| L8 | Drop the 30s `RequeueAfter` polling fallback; Watches added in H1 cover it. |

#### Onionbalance (`internal/onionbalance/refresher.go`)

| ID | Change |
|---|---|
| B3 | Frontend PodSpec sets `shareProcessNamespace: true`. SIGHUP path works. |
| M1 | `rebuild()` empty-backends branch writes an empty config + SIGHUPs (or returns an error surfaced as `Programmed=False`); does not silently retain stale config. |
| H9 | `backendsFromSecrets` adds an `OwnerReferences` check requiring the Secret to be owned by `gw`. |
| L3 | `NewRefresher` validates `cfg.Master` non-zero. |

#### Builders (`gateway_resources_ha.go`)

| ID | Change |
|---|---|
| B5 | `BuildBackendStatefulSet` and `BuildFrontendDeployment` return error if any image is empty (mirror `gateway_resources.go:187`). |
| H10 | Onionbalance container gets a `LivenessProbe` (exec checking pidfile presence + `config.yaml` mtime within window). `obrefresh` container gets a `LivenessProbe` exec'ing a new `--healthcheck` flag that checks "last successful reconcile within 2× RefreshInterval." |
| L4 | `BuildBackendKeySecret` accepts an existing `*corev1.Secret`; reuses keypair data if present. Caller reads existing first. |
| L5 | `BuildBackendKeySecret` writes `data["hostname"]` with trailing `\n` to match Mode A. `refresher.go:41` docstring updated. |
| L7 | `BuildBackendKeySecret` doc comment rewritten to describe actual behavior. |
| L9 | `updateStatusModeB` merges into `gw.Status.Addresses` instead of replacing. |

#### CRD (`api/v1alpha1/onionbalancepolicy_types.go`)

| ID | Change |
|---|---|
| H8 | `Replicas` `+kubebuilder:validation:Maximum` reverts to `12` for backwards compat with v0.3.3-era objects. |
| M6 | `RefreshInterval` adds `+kubebuilder:validation:Format=duration` and a CEL `self >= "5s"` validation. Programmatic clamp also added in `NewRefresher`. |

#### Manager (`cmd/manager/main.go`)

`--onionbalance-image` and `--obrefresh-image` validated non-empty after `flag.Parse`, before `mgr.Start`. Fail-fast.

### Stack 3 — NetworkPolicy + chart + docs + e2e

Depends on Stacks 1 & 2 settling.

#### NetworkPolicy

| ID | Change |
|---|---|
| B2 | `ensureModeB` calls `ensureNetworkPolicy` after HA resources. |
| HALabels | `HALabels` (`gateway_resources_ha.go:43`) adds `app.kubernetes.io/managed-by: tor-gateway` so the existing `ChildLabels`-based NP selector matches Mode B pods. |
| M8 | Testing-mode egress narrows to: `podSelector` matching chutney pod labels + `ports` enumerating chutney's DirAuth + OR ports. No bare-namespace egress. |
| Test | `network_policy_test.go::TestNetworkPolicySelectsBothModeBPodSets` strengthened: build a real Mode B frontend Pod spec and a backend StatefulSet pod spec, run the NP selector against their actual labels via `labels.SelectorFromSet`, assert match. |

#### Chart (`charts/tor-gateway/`)

| ID | Change |
|---|---|
| B1 | `values.yaml:83` `onionbalanceImage.repository` corrected to `ghcr.io/chimbosonic/tor-gateway-onionbalance`. |
| B1.2 | `values.yaml:84` `onionbalanceImage.tag` changes from `"0.2-latest"` to `""` (falls through to `.Chart.AppVersion`). |
| M7 | `templates/deployment.yaml` adds Helm `required` cross-check: `testingTorNetwork.enabled=true` implies `testingTorNetwork.podNamespace` is non-empty. |
| L6 | `images/onionbalance/Dockerfile` and `images/chutney/Dockerfile` pin base layers via `@sha256:<digest>`. Document the pin discipline in `SECURITY.md`. |

#### Docs

`SECURITY.md` — Mode B section rewritten:

- **Backend-key containment:** describe the API-fetch pattern. State the contained guarantee: a backend init-container compromise yields only that pod's onion key. The runtime tor container has no mount of any Secret. A node-local attacker observing the kubelet's local mount sees only the in-pod `emptyDir`.
- **Frontend SA scope:** `secrets get` is `resourceNames`-scoped; `list/watch` is namespace-wide due to RBAC limitation but the informer enforces label + ownerRef filters. Strongest isolation: one Gateway per namespace.
- **Cross-NS `MasterKeySecretRef`:** works as designed. ReferenceGrant gate authoritative, re-validated each reconcile. Cross-NS `RoleBinding` scopes the frontend SA to the named master Secret only.
- **PoW in Mode B:** PoW directives are not propagated to backend instances. When PoW is enabled via `TorServicePolicy` OR via the default policy, the operator emits a `PoWForcedOffInHA` Event and sets the `torgateway.io/pow-override-emitted` annotation. (Closes H2 by extending the existing detection to the no-TSP default-policy case.)

`README.md` — Mode B section: experimental flag still present.

`docs/PLAN.md` — append: "v0.4.0 (in progress): pre-release review fixes covering Mode B correctness, NetworkPolicy coverage, RBAC narrowing, and chart configuration."

#### E2E (`test/e2e/`)

| ID | Test |
|---|---|
| New | `Mode B per-pod key isolation` — exec into a backend pod's tor container, verify only its own key bytes are visible; the `emptyDir` contains exactly one keypair. |
| New | `Mode B SIGHUP reload` — scale 3→4, assert frontend onionbalance logs SIGHUP and the new backend's intro point appears in the published descriptor within 2× RefreshInterval. |
| New | `Cross-NS master Secret` — source ns has master Secret + ReferenceGrant; target ns has Gateway + OBP. Assert HA programs and master `.onion` resolves. |
| New | `Mode B pods covered by per-Gateway NP` — list Mode B pods, run NP selector against their labels, assert match. |
| L10 | Chutney pod changes to `restartPolicy: OnFailure` + liveness probe. |

## Stack dependencies

```
Stack 1 (API-fetch) ──┐
                      ├──► Stack 2 (mechanical) ──► merge
                      └──► Stack 3 (NP+chart+docs+e2e) ──► merge
                                                          │
                                                          ▼
                                                       tag v0.4.0
```

Within Stack 2, items are independent; can be split into per-item commits or batched.

## Testing strategy

- Every controller-touching ticket gets a unit test in the matching `*_test.go`.
- Stack 1 ships with a `gateway_resources_ha_test.go` block verifying the per-Gateway Role's `resourceNames` matches `OBP.Spec.Replicas` and updates on replica change.
- Stack 1 ships with a `master_fetch_test.go` for `tor-init` covering: present Secret, missing Secret, RBAC denied, malformed key bytes.
- E2E (Stack 3) is the integration gate; both chutney and the realtor smoke harness must pass before tag.

## Risk & rollback

- **API-fetch in tor-init** is the largest correctness risk. Mitigation: extensive unit test coverage of `--api-fetch-secret` parsing, error paths, and key-byte handling; staged rollout in personal cluster before tag.
- **Cross-NS RoleBinding lifecycle** has a hidden failure mode if `MasterKeySecretRef.Namespace` changes between reconciles — the old RoleBinding becomes orphan. Mitigation: every `ensureModeB` enumerates and deletes stale cross-NS bindings labeled with `gw.UID` whose `Role.Rules[].ResourceNames` no longer matches the current spec.
- **Rollback:** if v0.4.0 ships and an unforeseen issue surfaces, downgrade to v0.3.3 is **not safe** for Mode B users (the chart is broken there; B1 makes Mode B unusable). A patch release `v0.4.1` is the rollback path. Users not on Mode B can downgrade freely.

## Post-tag follow-ups

Not in this release's scope:

- Graduate Mode B to stable (`v0.5`).
- Drop the cleanup-line for the now-removed `BuildOnionbalanceConfigMap` (one release later).
- CHANGELOG.md (decide separately).
- Bump `README.md` and `docs/PLAN.md` "current release" lines after the tag is cut (existing pattern, e.g. `e1213be`).
