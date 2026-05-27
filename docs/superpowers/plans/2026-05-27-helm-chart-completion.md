# Helm chart completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `helm install tor-gateway ./charts/tor-gateway` deploy a fully functional operator (RBAC + policy CRDs), kept in sync with `config/` and proven by a chart-deploy smoke test.

**Architecture:** `config/` (kustomize) stays the source of truth. `make chart-sync` extracts the RBAC `rules:` and copies the CRDs from `config/` into `charts/tor-gateway/files/` (raw YAML); thin hand-written templates consume them via `.Files.Get`/`.Files.Glob` and add Helm metadata/labels/toggles/bindings. CI runs `make chart-sync && git diff --exit-code` to catch drift, plus a kind-based smoke that installs the chart and asserts a Gateway reconciles.

**Tech Stack:** Helm v4, yq v4, kubeconform, kind, kubectl, Make.

**Spec:** `docs/superpowers/specs/2026-05-27-helm-chart-completion-design.md`

**Key facts (already verified):**
- `charts/tor-gateway/values.yaml` already defines `crds.install: true` and `rbac.create: true` (stubbed; no templates consume them yet), plus `manager.leaderElection.enabled` and `manager.metrics.{enabled,secure}`.
- Helpers in `_helpers.tpl`: `tor-gateway.fullname`, `tor-gateway.labels`, `tor-gateway.selectorLabels`, `tor-gateway.serviceAccountName`.
- The chart's ServiceAccount name = `include "tor-gateway.serviceAccountName" .`.
- RBAC sources: `config/rbac/{role,role_binding,leader_election_role,leader_election_role_binding,metrics_auth_role,metrics_auth_role_binding,metrics_reader_role}.yaml`.
- CRD sources: `config/crd/bases/policy.torgateway.io_{onionbalancepolicies,torclientauthpolicies,torservicepolicies}.yaml`.
- `.helmignore` does NOT exclude `files/`, so `.Files.Get`/`.Files.Glob` resolve at install time. No `.helmignore` change needed.
- `yq` (v4.53.2) and `helm` (v4.0.5) are installed locally.

**No `Co-Authored-By` trailer in any commit** (project preference).

---

## Task 1: `make chart-sync` — generate `files/` from `config/`

**Files:**
- Modify: `Makefile` (add the `chart-sync` target + a `YQ ?= yq` var near the other tool vars)
- Create (generated): `charts/tor-gateway/files/rbac/*.yaml`, `charts/tor-gateway/files/crds/*.yaml`

- [ ] **Step 1: Add the `YQ` variable and `chart-sync` target**

In `Makefile`, near the existing tool variables (e.g. after `KIND ?= ...`/the `##@ Build` area), add:

```makefile
YQ ?= yq

.PHONY: chart-sync
chart-sync: ## Sync the Helm chart's RBAC rules + CRDs from config/ (source of truth).
	@mkdir -p charts/tor-gateway/files/rbac charts/tor-gateway/files/crds
	$(YQ) '.rules' config/rbac/role.yaml                  > charts/tor-gateway/files/rbac/manager-role-rules.yaml
	$(YQ) '.rules' config/rbac/leader_election_role.yaml  > charts/tor-gateway/files/rbac/leader-election-role-rules.yaml
	$(YQ) '.rules' config/rbac/metrics_auth_role.yaml     > charts/tor-gateway/files/rbac/metrics-auth-role-rules.yaml
	$(YQ) '.rules' config/rbac/metrics_reader_role.yaml   > charts/tor-gateway/files/rbac/metrics-reader-role-rules.yaml
	@rm -f charts/tor-gateway/files/crds/*.yaml
	cp config/crd/bases/*.yaml charts/tor-gateway/files/crds/
```

- [ ] **Step 2: Run it and inspect the output**

Run:
```bash
make chart-sync
ls charts/tor-gateway/files/rbac charts/tor-gateway/files/crds
head -5 charts/tor-gateway/files/rbac/manager-role-rules.yaml
```
Expected: 4 rule files + 3 CRD files; `manager-role-rules.yaml` starts with a YAML sequence (`- apiGroups:` …).

- [ ] **Step 3: Verify idempotency (the drift-check relies on this)**

Run:
```bash
make chart-sync && git add -A charts/tor-gateway/files && git status --porcelain charts/tor-gateway/files
make chart-sync && git diff --exit-code charts/tor-gateway/files
echo "idempotent exit=$?"
```
Expected: the second `make chart-sync` produces no diff (`exit=0`). If `yq` output is non-deterministic, pin its flags until it is.

- [ ] **Step 4: Commit**

```bash
git add Makefile charts/tor-gateway/files
git commit -m "build(chart): add chart-sync to generate RBAC rules + CRDs from config/"
```

---

## Task 2: Operator ClusterRole + ClusterRoleBinding templates

**Files:**
- Create: `charts/tor-gateway/templates/clusterrole.yaml`
- Create: `charts/tor-gateway/templates/clusterrolebinding.yaml`

- [ ] **Step 1: Create `clusterrole.yaml`**

```yaml
{{- if .Values.rbac.create }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "tor-gateway.fullname" . }}-manager
  labels: {{- include "tor-gateway.labels" . | nindent 4 }}
rules:
{{- .Files.Get "files/rbac/manager-role-rules.yaml" | nindent 0 }}
{{- end }}
```

- [ ] **Step 2: Create `clusterrolebinding.yaml`**

```yaml
{{- if .Values.rbac.create }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "tor-gateway.fullname" . }}-manager
  labels: {{- include "tor-gateway.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "tor-gateway.fullname" . }}-manager
subjects:
- kind: ServiceAccount
  name: {{ include "tor-gateway.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
```

- [ ] **Step 3: Render and verify the rules survived intact**

Run:
```bash
helm template tor-gateway charts/tor-gateway | yq 'select(.kind=="ClusterRole" and (.metadata.name|test("-manager$"))) | .rules | length'
```
Expected: `9` (the manager role has 9 rule groups). If the render errors on indentation, adjust the `nindent` in Step 1 until `helm template` succeeds and the rule count is 9.

- [ ] **Step 4: kubeconform the render**

Run:
```bash
helm template tor-gateway charts/tor-gateway > /tmp/r.yaml
kubeconform -strict -ignore-missing-schemas -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  -summary /tmp/r.yaml
```
Expected: `Valid` for all resources, exit 0. (Install kubeconform if absent: `go run github.com/yannh/kubeconform/cmd/kubeconform@latest` or the release binary.)

- [ ] **Step 5: Verify the toggle**

Run: `helm template tor-gateway charts/tor-gateway --set rbac.create=false | grep -c 'kind: ClusterRole'`
Expected: `0`.

- [ ] **Step 6: Commit**

```bash
git add charts/tor-gateway/templates/clusterrole.yaml charts/tor-gateway/templates/clusterrolebinding.yaml
git commit -m "feat(chart): operator ClusterRole + ClusterRoleBinding (synced from config/rbac)"
```

---

## Task 3: Leader-election + metrics RBAC templates

**Files:**
- Create: `charts/tor-gateway/templates/leader-election-rbac.yaml`
- Create: `charts/tor-gateway/templates/metrics-rbac.yaml`

- [ ] **Step 1: Create `leader-election-rbac.yaml`** (namespaced Role + RoleBinding)

```yaml
{{- if and .Values.rbac.create .Values.manager.leaderElection.enabled }}
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "tor-gateway.fullname" . }}-leader-election
  namespace: {{ .Release.Namespace }}
  labels: {{- include "tor-gateway.labels" . | nindent 4 }}
rules:
{{- .Files.Get "files/rbac/leader-election-role-rules.yaml" | nindent 0 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "tor-gateway.fullname" . }}-leader-election
  namespace: {{ .Release.Namespace }}
  labels: {{- include "tor-gateway.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "tor-gateway.fullname" . }}-leader-election
subjects:
- kind: ServiceAccount
  name: {{ include "tor-gateway.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
```

- [ ] **Step 2: Create `metrics-rbac.yaml`** (auth ClusterRole+Binding gated by `secure`, plus the reader ClusterRole)

```yaml
{{- if and .Values.rbac.create .Values.manager.metrics.enabled }}
{{- if .Values.manager.metrics.secure }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "tor-gateway.fullname" . }}-metrics-auth
  labels: {{- include "tor-gateway.labels" . | nindent 4 }}
rules:
{{- .Files.Get "files/rbac/metrics-auth-role-rules.yaml" | nindent 0 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "tor-gateway.fullname" . }}-metrics-auth
  labels: {{- include "tor-gateway.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "tor-gateway.fullname" . }}-metrics-auth
subjects:
- kind: ServiceAccount
  name: {{ include "tor-gateway.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
---
{{- end }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "tor-gateway.fullname" . }}-metrics-reader
  labels: {{- include "tor-gateway.labels" . | nindent 4 }}
rules:
{{- .Files.Get "files/rbac/metrics-reader-role-rules.yaml" | nindent 0 }}
{{- end }}
```

- [ ] **Step 3: Render + verify toggles**

Run:
```bash
helm template tor-gateway charts/tor-gateway | grep -E 'kind: Role$|leader-election|metrics-auth|metrics-reader'
helm template tor-gateway charts/tor-gateway --set manager.leaderElection.enabled=false | grep -c leader-election
helm template tor-gateway charts/tor-gateway --set manager.metrics.enabled=false | grep -c metrics-auth
```
Expected: default render shows the leader-election Role/RoleBinding + metrics-auth + metrics-reader; with `leaderElection.enabled=false` → `0` leader-election; with `metrics.enabled=false` → `0` metrics-auth.

- [ ] **Step 4: kubeconform**

Run the kubeconform command from Task 2 Step 4 again; expected exit 0, all Valid.

- [ ] **Step 5: Commit**

```bash
git add charts/tor-gateway/templates/leader-election-rbac.yaml charts/tor-gateway/templates/metrics-rbac.yaml
git commit -m "feat(chart): leader-election + metrics RBAC (synced from config/rbac)"
```

---

## Task 4: Policy CRDs template

**Files:**
- Create: `charts/tor-gateway/templates/crds.yaml`

- [ ] **Step 1: Create `crds.yaml`** (renders each synced CRD, gated by `crds.install`)

```yaml
{{- if .Values.crds.install }}
{{- range $path, $_ := .Files.Glob "files/crds/*.yaml" }}
---
{{ $.Files.Get $path }}
{{- end }}
{{- end }}
```

- [ ] **Step 2: Render + verify the 3 CRDs appear**

Run:
```bash
helm template tor-gateway charts/tor-gateway | yq 'select(.kind=="CustomResourceDefinition") | .metadata.name'
```
Expected (3 lines):
```
onionbalancepolicies.policy.torgateway.io
torclientauthpolicies.policy.torgateway.io
torservicepolicies.policy.torgateway.io
```

- [ ] **Step 3: Verify the toggle**

Run: `helm template tor-gateway charts/tor-gateway --set crds.install=false | grep -c 'kind: CustomResourceDefinition'`
Expected: `0`.

- [ ] **Step 4: kubeconform the full render**

Run the kubeconform command from Task 2 Step 4. Expected: exit 0, all Valid (now including 3 CRDs). This is the render that the chart CI validates.

- [ ] **Step 5: Commit**

```bash
git add charts/tor-gateway/templates/crds.yaml
git commit -m "feat(chart): ship policy CRDs as crds.install-toggled templates"
```

---

## Task 5: CI drift-check

**Files:**
- Modify: `.github/workflows/chart.yml` (add a step to the `lint-and-template` job, before/after `helm lint`)

- [ ] **Step 1: Add a yq-install + drift-check step**

In `.github/workflows/chart.yml`, in the `lint-and-template` job's `steps:`, add after the `Setup Helm` step (before `Helm lint`):

```yaml
      - name: Install yq
        run: |
          curl -L https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 \
            -o /usr/local/bin/yq && chmod +x /usr/local/bin/yq
      - name: Verify chart is in sync with config/
        run: |
          make chart-sync
          git diff --exit-code charts/ \
            || { echo "::error::charts/ is out of sync with config/. Run 'make chart-sync' and commit."; exit 1; }
```

> Note: this job's `on.push`/`on.pull_request` `paths` already includes `charts/**`. Also add `config/rbac/**` and `config/crd/**` to the `paths` so a `config/`-only RBAC/CRD change (the case that slipped through before) re-triggers this job and the drift-check catches it.

- [ ] **Step 2: Update the workflow `paths`**

In `.github/workflows/chart.yml`, change both `on.push.paths` and `on.pull_request.paths` to include the config sources:

```yaml
    paths:
      - "charts/**"
      - "config/rbac/**"
      - "config/crd/**"
      - "Makefile"
      - ".github/workflows/chart.yml"
```

- [ ] **Step 3: Verify the check passes when in sync**

Run:
```bash
make chart-sync && git diff --exit-code charts/ && echo "in sync (PASS)"
```
Expected: `in sync (PASS)` (exit 0). The failure path is symmetric: when `config/`'s RBAC/CRDs change without a matching `make chart-sync` commit, the regenerated `files/` differ from what's committed and `git diff --exit-code` returns non-zero — which is exactly the case that slipped through before. (To see it: edit a rule in `config/rbac/role.yaml`, run `make chart-sync`, and observe `git diff charts/` is non-empty; then `git checkout -- config charts`.)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/chart.yml
git commit -m "ci(chart): fail when the chart drifts from config/ RBAC/CRDs"
```

---

## Task 6: Chart-deploy smoke test

**Files:**
- Modify: `Makefile` (add `chart-smoke` target)
- Modify: `.github/workflows/chart.yml` (add a `deploy-smoke` job)
- Create: `test/chart/gateway.yaml` (a minimal Gateway fixture)

- [ ] **Step 1: Create the Gateway fixture `test/chart/gateway.yaml`**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: smoke
  namespace: default
spec:
  gatewayClassName: tor-gateway
  listeners:
  - { name: onion, port: 80, protocol: torgateway.io/HiddenService }
```

- [ ] **Step 2: Add the `chart-smoke` target to `Makefile`**

```makefile
.PHONY: chart-smoke
chart-smoke: setup-test-e2e install-gateway-api-crds ## Install the chart in kind and verify the operator reconciles a Gateway.
	$(MAKE) docker-build IMG=ghcr.io/chimbosonic/tor-gateway-manager:$(IMAGE_TAG)
	$(KIND) load docker-image ghcr.io/chimbosonic/tor-gateway-manager:$(IMAGE_TAG) --name $(KIND_CLUSTER)
	helm upgrade --install tor-gateway charts/tor-gateway \
		--namespace tor-gateway-system --create-namespace \
		--set manager.image.tag=$(IMAGE_TAG)
	kubectl -n tor-gateway-system wait --for=condition=Available deployment \
		-l app.kubernetes.io/name=tor-gateway --timeout=120s
	kubectl apply -f test/chart/gateway.yaml
	# The operator can only set these conditions if its RBAC + the CRDs are present.
	kubectl -n default wait --for=jsonpath='{.status.conditions[?(@.type=="Accepted")].status}'=True   gateway/smoke --timeout=120s
	kubectl -n default wait --for=jsonpath='{.status.conditions[?(@.type=="Programmed")].status}'=True gateway/smoke --timeout=120s
	@echo "chart-smoke PASS: chart-installed operator reconciled the Gateway"
	$(MAKE) cleanup-test-e2e
```

> Notes: the chart installs the `tor-gateway` GatewayClass (`gatewayClass.install=true` default), so the fixture's `gatewayClassName` resolves. The Gateway's Tor pod will not pull its images (router/tor/tor-init aren't loaded) — that's intentional; we assert *reconciliation* (status conditions), which only succeeds if the operator has the synced RBAC and the CRDs exist. `IMAGE_TAG` defaults to `dev`, so the chart's manager image is `...-manager:dev` (built and loaded above); `manager.image.tag` is overridden to match.

- [ ] **Step 3: Run the smoke locally**

Run: `make chart-smoke`
Expected: ends with `chart-smoke PASS: chart-installed operator reconciled the Gateway`. If the Gateway never reaches `Accepted=True`, inspect with `kubectl -n tor-gateway-system logs deploy -l app.kubernetes.io/name=tor-gateway` and `kubectl describe gateway smoke` — a missing-RBAC regression shows as the manager logging `forbidden` on Gateways. Use the systematic-debugging skill if it fails.

- [ ] **Step 4: Add the `deploy-smoke` job to `.github/workflows/chart.yml`**

Append this job (peer to `lint-and-template`):

```yaml
  deploy-smoke:
    name: Deploy smoke (kind)
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - uses: azure/setup-helm@v4
      - name: Create kind cluster
        uses: helm/kind-action@v1
        with:
          cluster_name: tor-gateway-test-e2e
      - name: Chart smoke
        run: make chart-smoke KIND_CLUSTER=tor-gateway-test-e2e
```

> The `helm/kind-action` provisions kind; `make chart-smoke`'s `setup-test-e2e` is a no-op when the cluster already exists. If the action's cluster name differs, pass it through `KIND_CLUSTER=`.

- [ ] **Step 5: Commit**

```bash
git add Makefile test/chart/gateway.yaml .github/workflows/chart.yml
git commit -m "test(chart): kind smoke that the chart deploys a reconciling operator"
```

---

## Task 7: README Gateway API CRD prerequisite

**Files:**
- Modify: `README.md` (Quickstart section)

- [ ] **Step 1: Note the prerequisite**

In `README.md`'s Quickstart, immediately before the `helm install` line, add:

```markdown
> The chart ships this operator's policy CRDs but not the upstream Gateway API
> CRDs — install those first (e.g. `kubectl apply -f` the gateway-api standard
> channel, or `make install-gateway-api-crds`).
```

- [ ] **Step 2: Verify the doc renders sensibly**

Run: `sed -n '/## Quickstart/,/## /p' README.md`
Expected: the prerequisite note appears before `helm install`.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): note Gateway API CRDs as a chart prerequisite"
```

---

## Self-review notes

- **Spec coverage:** RBAC sync (Tasks 1-3), CRDs toggle (Tasks 1+4), drift guard (Task 5), smoke (Task 6), README (Task 7). values toggles (`crds.install`, `rbac.create`) already exist — no task needed. ✓
- **Type/name consistency:** all templates use `tor-gateway.fullname`/`tor-gateway.labels`/`tor-gateway.serviceAccountName`; synced files are referenced by the exact paths `chart-sync` writes (`files/rbac/manager-role-rules.yaml`, etc.); resource names are release-prefixed (`<fullname>-manager`, `-leader-election`, `-metrics-auth`, `-metrics-reader`). ✓
- **Open implementation risks:** (1) the `.Files.Get | nindent 0` whitespace under `rules:` may need tuning — every RBAC task verifies via `helm template` + kubeconform, so a wrong indent fails fast. (2) Templated CRDs apply before the Deployment per Helm's install-kind order, but CRD `Established` isn't waited on; controller-runtime retries cache sync, and the smoke's `kubectl wait` tolerates a transient manager restart.
