# Helm chart completion — design

- **Date:** 2026-05-27
- **Status:** Implemented (chart RBAC + policy CRDs synced from `config/` via `make chart-sync`, CI drift guard in `chart.yml`, kind `chart-smoke` deploy test).
- **Owner:** Alexis Lowe

## Context

`helm install tor-gateway ./charts/tor-gateway` is the README Quickstart, but
the chart is a scaffold stub. It renders only `Deployment`, `GatewayClass`,
`NetworkPolicy`, and `ServiceAccount` — **no operator RBAC and no CRDs**. A
chart-installed operator therefore has the `default`-less permissions of a
bare ServiceAccount (it can't watch Gateways/HTTPRoutes or create children)
and the cluster has no policy CRDs. The operator's real RBAC lives only in
`config/rbac/` (kustomize, applied by `make deploy`), which the e2e and
conformance suites use — so the chart has never deployed a working operator
and the gap was invisible.

This also caused a real CI failure: when the router RBAC work updated
`config/rbac/role.yaml`, the chart wasn't updated (it has no RBAC at all).
The chart's CI job only lints/renders the chart, so a `config/`-only change
isn't caught.

## Goals

- `helm install` deploys a **functional** operator: full RBAC + the policy
  CRDs, matching what `make deploy` (kustomize) installs.
- The chart's RBAC/CRDs are **kept in sync with `config/`** (the single
  source of truth) and **drift fails CI**.
- A **chart-deploy smoke test** proves the installed operator actually
  reconciles, so this class of gap can't regress.

## Non-goals (YAGNI)

- Bundling upstream **Gateway API CRDs** — documented as a cluster
  prerequisite (the chart ships only this project's policy CRDs).
- The policy **admin/editor/viewer** aggregated roles (`config/rbac/*_admin
  /editor/viewer_role.yaml`) — user-facing convenience RBAC, not needed to
  run the operator.
- Chart **publishing / cosign / SBOM** — a separate backlog item.
- Rewriting the existing hand-crafted templates (deployment, SA,
  networkpolicy, gatewayclass) — they stay as-is.

## Decisions (settled during brainstorming)

| Question | Decision |
|---|---|
| Sync strategy | Automated sync from `config/` + a CI drift check. |
| CRD delivery | `templates/` gated by a `crds.install` toggle (default true). |
| Verification | A kind-based chart-deploy smoke (`helm install` → reconcile a Gateway). |

## Design

### 1. What the chart gains (synced from `config/`)

New chart templates, all carrying the chart's standard labels/helpers and
bound to the chart's existing ServiceAccount:

- **Operator `ClusterRole` + `ClusterRoleBinding`** — rules from
  `config/rbac/role.yaml` (the 9 rule groups, incl. the serviceaccounts /
  roles / rolebindings + httproutes perms the router-RBAC work added);
  binding subject is the chart SA. Gated by a `rbac.create` value (default
  true) for users who manage RBAC out of band.
- **Leader-election `Role` + `RoleBinding`** — rules from
  `config/rbac/leader_election_role.yaml`; gated by the existing
  `manager.leaderElection.enabled`.
- **Metrics RBAC** — `metrics_auth_role` (+ binding) and `metrics_reader_role`
  from `config/rbac/`; gated by the existing `manager.metrics` values.
- **Policy CRDs** — the three CRDs from `config/crd/bases/`
  (`torservicepolicies`, `torclientauthpolicies`, `onionbalancepolicies`),
  rendered as templates gated by a new `crds.install` (default true).

### 2. Sync mechanism + drift guard

Source of truth stays `config/`. A new `make chart-sync` target copies the
*volatile bodies* into the chart under a generated, raw-YAML directory
(`charts/tor-gateway/files/`):

- `files/rbac/<role>-rules.yaml` — the `rules:` extracted from each
  `config/rbac/*role.yaml`.
- `files/crds/*.yaml` — the CRD definitions copied verbatim from
  `config/crd/bases/`.

The new templates are **hand-written thin wrappers** that consume those raw
files and add the Helm-specific parts (name, labels, namespace, toggles,
bindings):

- a `ClusterRole`/`Role` template sets `rules:` from
  `{{ .Files.Get "files/rbac/<role>-rules.yaml" }}`;
- the CRD template ranges `{{ .Files.Glob "files/crds/*.yaml" }}` inside a
  `{{- if .Values.crds.install }}` guard.

This separates *synced static content* (`files/`, pure YAML, trivially
diffable) from *hand-templated wrappers* (`templates/`, full Helm idioms).

**Drift guard:** CI runs `make chart-sync && git diff --exit-code charts/`. A
future `config/`-only RBAC/CRD change (exactly the case that just slipped
through) fails CI until `chart-sync` is re-run and committed.

### 3. Verification

- **Static** (existing chart job): `helm lint`, `helm template`,
  `kubeconform -strict`, **plus** the new sync/drift check.
- **Smoke (new):** a kind-based test, on its own deploy path (separate from
  the kustomize e2e):
  1. build + `kind load` the manager image;
  2. install the Gateway API CRDs (prerequisite);
  3. `helm install` the chart;
  4. wait for the operator Deployment `Available`;
  5. create a `Gateway` (class `tor-gateway`) and assert it is **reconciled**
     — `Accepted`+`Programmed` true (and/or its child Secret/ConfigMap/
     Deployment/Service exist). A manager pod can be "Available" yet unable to
     reconcile without RBAC, so asserting reconciliation is what catches an
     RBAC/CRD gap.

### 4. README

The Quickstart works after this. Add a one-line note that the Gateway API
CRDs are a cluster prerequisite (installed separately), since the chart does
not bundle them.

## Files touched

- `charts/tor-gateway/templates/` — add `clusterrole.yaml`,
  `clusterrolebinding.yaml`, `leader-election-rbac.yaml`, `metrics-rbac.yaml`,
  `crds.yaml` (thin wrappers).
- `charts/tor-gateway/files/` — generated raw RBAC rules + CRDs (by
  `chart-sync`).
- `charts/tor-gateway/values.yaml` — add `crds.install` and `rbac.create`.
- `Makefile` — add `chart-sync`.
- `.github/workflows/chart.yml` — add the drift-check step and the
  chart-deploy smoke job (kind).
- `README.md` — Gateway API CRD prerequisite note.
- `charts/tor-gateway/.helmignore` — ensure `files/` is packaged (not
  ignored), so `.Files.Get`/`.Files.Glob` resolve at install time.

## To resolve during planning

- **Rule extraction tooling** for `chart-sync` (e.g. `yq '.rules'` vs a small
  awk/script) and whether `yq` is an acceptable new dev dependency.
- **Resource naming** for the cluster-scoped ClusterRole(s): release-prefixed
  (chart convention, multi-release safe) vs a fixed name. Single operator per
  cluster is the norm, but prefer release-prefixed for correctness.
- **Smoke-test form:** a dedicated CI job/script in `chart.yml` vs a Ginkgo
  suite with its own (non-kustomize) setup. It must NOT reuse the e2e
  `BeforeSuite` (which deploys via `make deploy`).
- Confirm the `manager.metrics` / `manager.leaderElection` value shapes the
  conditional RBAC keys off.

## Verification of this work

- `make chart-sync` is idempotent; `git diff --exit-code charts/` clean after
  running.
- `helm lint` + `helm template` + `kubeconform -strict` pass on the rendered
  chart (now including RBAC + CRDs).
- The smoke test goes green: chart-installed operator reconciles a Gateway.
