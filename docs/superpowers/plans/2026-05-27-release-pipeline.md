# Release pipeline (publish + sign images and chart) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `vX.Y.Z` git tag publishes a complete, signed, installable release — all five images built multi-arch + cosign-signed + SBOM-attested on ghcr, and the Helm chart (stamped to the version, deploying the released images) pushed to OCI (signed) and GitHub Pages.

**Architecture:** A new `.github/workflows/release.yml` triggered on `push: tags: ['v*']`, with an `images` matrix job (buildx multi-arch → cosign keyless sign by digest → syft SBOM → cosign attest) and a `chart` job (stamp `Chart.yaml`, OCI `helm push` + cosign sign, GitHub Pages via `chart-releaser-action`). A prerequisite chart change wires the manager's runtime-image flags from chart values so the released chart's operator uses the released images.

**Tech Stack:** GitHub Actions, docker buildx, cosign (keyless/Sigstore), syft/anchore sbom-action, Helm (OCI + chart-releaser), yq.

**Spec:** `docs/superpowers/specs/2026-05-27-chart-publish-release-design.md`

**Key facts (verified):**
- Images + Makefile vars: `tor-gateway-manager`, `tor-gateway-router`, `tor-gateway-obrefresh`, `tor-gateway-tor-init` (built from the shared `Dockerfile` with `--build-arg BINARY=<name>`), and `tor` (built from `images/tor/Dockerfile`). Registry namespace `ghcr.io/chimbosonic`.
- The manager flags exist: `--router-image`, `--tor-init-image`, `--tor-image` (`cmd/manager/main.go`); no flags for obrefresh/onionbalance yet.
- The chart's `deployment.yaml` does NOT currently pass those flags; `values.yaml` `torRuntime.{routerImage,obrefreshImage,torImage,onionbalanceImage}` exist but are unused, and there's no `torInitImage`.
- Helper `tor-gateway.managerImage` in `_helpers.tpl`: `printf "%s:%s" .repository (default .Chart.AppVersion .tag)`.
- Repo pins actions to SHAs with a `# vX.Y.Z` comment, e.g. `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2`, `actions/setup-go@4b73464bb391d4059bd26b0524d20df3927bd417 # v6.3.0`. yq is installed in `chart.yml` via `curl …/v4.53.2/yq_linux_amd64`.
- The project distrusts mutable tags — so released images use the version tag only (no `:latest`).

**No `Co-Authored-By` trailer in commits.**

---

## Task 1: Wire the chart's runtime images (prerequisite)

So a chart-installed operator uses the chart-configured (released) images instead of the manager's baked-in `:dev` defaults.

**Files:**
- Modify: `charts/tor-gateway/values.yaml`
- Modify: `charts/tor-gateway/templates/_helpers.tpl`
- Modify: `charts/tor-gateway/templates/deployment.yaml`

- [ ] **Step 1: Add a `torInitImage` value + annotate the unused ones**

In `charts/tor-gateway/values.yaml`, under `torRuntime:`, add a `torInitImage` entry next to `routerImage` (same shape), and add a comment marking obrefresh/onionbalance as reserved:

```yaml
  routerImage:
    repository: ghcr.io/chimbosonic/tor-gateway-router
    tag: ""
    pullPolicy: IfNotPresent
  torInitImage:
    repository: ghcr.io/chimbosonic/tor-gateway-tor-init
    tag: ""
    pullPolicy: IfNotPresent
  # Reserved for onionbalance HA (Mode B); not yet injected by the operator.
  obrefreshImage:
    repository: ghcr.io/chimbosonic/tor-gateway-obrefresh
    tag: ""
    pullPolicy: IfNotPresent
  torImage:
    repository: ghcr.io/chimbosonic/tor
    tag: "0.4.9"
    pullPolicy: IfNotPresent
  # Reserved for onionbalance HA (Mode B); not yet injected by the operator.
  onionbalanceImage:
    repository: ghcr.io/chimbosonic/onionbalance
    tag: "0.2-latest"
    pullPolicy: IfNotPresent
```

- [ ] **Step 2: Add a runtime-image helper**

In `charts/tor-gateway/templates/_helpers.tpl`, after `tor-gateway.managerImage`, add a helper that takes `(list <imageDict> <root>)` so the tag can default to `.Chart.AppVersion`:

```gotemplate
{{- define "tor-gateway.runtimeImage" -}}
{{- $img := index . 0 -}}
{{- $root := index . 1 -}}
{{- printf "%s:%s" $img.repository (default $root.Chart.AppVersion $img.tag) -}}
{{- end -}}
```

- [ ] **Step 3: Pass the runtime-image flags from the chart**

In `charts/tor-gateway/templates/deployment.yaml`, in the manager container `args:` list (after `--zap-log-level=…`), add:

```yaml
            - --router-image={{ include "tor-gateway.runtimeImage" (list .Values.torRuntime.routerImage .) }}
            - --tor-init-image={{ include "tor-gateway.runtimeImage" (list .Values.torRuntime.torInitImage .) }}
            - --tor-image={{ include "tor-gateway.runtimeImage" (list .Values.torRuntime.torImage .) }}
```

- [ ] **Step 4: Verify the flags render with the right image refs**

Run:
```bash
helm template tor-gateway charts/tor-gateway | \
  yq 'select(.kind=="Deployment").spec.template.spec.containers[0].args[]' | grep -- '-image='
```
Expected (appVersion is `0.1.0`; tor is pinned `0.4.9`):
```
--router-image=ghcr.io/chimbosonic/tor-gateway-router:0.1.0
--tor-init-image=ghcr.io/chimbosonic/tor-gateway-tor-init:0.1.0
--tor-image=ghcr.io/chimbosonic/tor:0.4.9
```
Also confirm the chart still passes static checks:
```bash
helm lint charts/tor-gateway | tail -1   # 0 chart(s) failed
make chart-sync && git diff --exit-code charts/ && echo "in sync"
```

- [ ] **Step 5: Extend the chart smoke to assert the configured image**

In the `chart-smoke` Makefile target (after the Gateway is Accepted), add an assertion that the provisioned Tor pod's router container references the chart-configured image (not `:dev`). Insert before the final `@echo`:

```makefile
	@img=$$($(KUBECTL) -n default get pod -l torgateway.io/gateway=smoke \
		-o jsonpath='{.items[0].spec.containers[?(@.name=="router")].image}'); \
		echo "router image: $$img"; \
		case "$$img" in *tor-gateway-router:0.1.0) ;; *) echo "ERROR: router image is $$img, expected …router:0.1.0"; exit 1;; esac
```
(The pod need not be Ready — only its image *reference* must be the chart-configured one; this catches an unwired-flags regression. `0.1.0` is the chart's current appVersion.)

- [ ] **Step 6: Commit**

```bash
git add charts/tor-gateway/values.yaml charts/tor-gateway/templates/_helpers.tpl charts/tor-gateway/templates/deployment.yaml Makefile
git commit --no-gpg-sign -m "feat(chart): inject released runtime images into the operator"
```

---

## Task 2: Release workflow `.github/workflows/release.yml`

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/release.yml`. Action versions are shown as `@vN`; Step 2 pins them to SHAs.

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions: {}

jobs:
  images:
    name: Build, sign, SBOM images
    permissions:
      contents: read
      packages: write
      id-token: write
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - { name: tor-gateway-manager,  context: ".",          file: Dockerfile,            build_args: "BINARY=manager" }
          - { name: tor-gateway-router,   context: ".",          file: Dockerfile,            build_args: "BINARY=router" }
          - { name: tor-gateway-obrefresh,context: ".",          file: Dockerfile,            build_args: "BINARY=obrefresh" }
          - { name: tor-gateway-tor-init, context: ".",          file: Dockerfile,            build_args: "BINARY=tor-init" }
          - { name: tor,                  context: "images/tor", file: images/tor/Dockerfile, build_args: "" }
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - id: ver
        run: echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"
      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - id: build
        uses: docker/build-push-action@v6
        with:
          context: ${{ matrix.context }}
          file: ${{ matrix.file }}
          platforms: linux/amd64,linux/arm64
          push: true
          build-args: ${{ matrix.build_args }}
          tags: ghcr.io/chimbosonic/${{ matrix.name }}:${{ steps.ver.outputs.version }}
      - uses: sigstore/cosign-installer@v3
      - name: Sign image (keyless, by digest)
        run: cosign sign --yes "ghcr.io/chimbosonic/${{ matrix.name }}@${{ steps.build.outputs.digest }}"
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: "ghcr.io/chimbosonic/${{ matrix.name }}@${{ steps.build.outputs.digest }}"
          format: spdx-json
          output-file: sbom.spdx.json
      - name: Attest SBOM
        run: cosign attest --yes --type spdxjson --predicate sbom.spdx.json "ghcr.io/chimbosonic/${{ matrix.name }}@${{ steps.build.outputs.digest }}"

  chart:
    name: Package, sign, publish chart
    needs: images
    permissions:
      contents: write
      packages: write
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          fetch-depth: 0
          persist-credentials: false
      - id: ver
        run: echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"
      - uses: azure/setup-helm@v4
      - uses: sigstore/cosign-installer@v3
      - name: Install yq
        run: |
          sudo curl -fsSL https://github.com/mikefarah/yq/releases/download/v4.53.2/yq_linux_amd64 \
            -o /usr/local/bin/yq && sudo chmod +x /usr/local/bin/yq
      - name: Stamp chart version
        run: |
          yq -i '.version = "${{ steps.ver.outputs.version }}" | .appVersion = "${{ steps.ver.outputs.version }}"' \
            charts/tor-gateway/Chart.yaml
      - name: Package, push (OCI), and sign the chart
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | helm registry login ghcr.io -u ${{ github.actor }} --password-stdin
          helm package charts/tor-gateway -d /tmp/chart
          out=$(helm push "/tmp/chart/tor-gateway-${{ steps.ver.outputs.version }}.tgz" oci://ghcr.io/chimbosonic/charts 2>&1 | tee /dev/stderr)
          digest=$(echo "$out" | awk '/Digest:/ {print $2}')
          test -n "$digest" || { echo "could not parse pushed chart digest"; exit 1; }
          cosign sign --yes "ghcr.io/chimbosonic/charts/tor-gateway@${digest}"
      - name: Publish to GitHub Pages
        uses: helm/chart-releaser-action@v1
        with:
          charts_dir: charts
        env:
          CR_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 2: Pin every action to a SHA (repo convention)**

For each `uses: <action>@vN` added above, replace with the commit SHA of that release tag plus a `# vN.N.N` comment, matching the existing workflows. Resolve each SHA with the GitHub API, e.g.:
```bash
gh api repos/docker/build-push-action/git/refs/tags/v6 -q .object.sha   # then dereference to the commit if it's an annotated tag
```
Pin: `docker/setup-qemu-action`, `docker/setup-buildx-action`, `docker/login-action`, `docker/build-push-action`, `sigstore/cosign-installer`, `anchore/sbom-action`, `azure/setup-helm`, `helm/chart-releaser-action`. (`actions/checkout` is already SHA-pinned above.)

- [ ] **Step 3: Lint the workflow**

Run:
```bash
go run github.com/rhysd/actionlint/cmd/actionlint@latest .github/workflows/release.yml
```
Expected: no errors. Also confirm YAML parses: `yq '.' .github/workflows/release.yml > /dev/null && echo ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit --no-gpg-sign -m "ci(release): publish + cosign-sign + SBOM images and chart on tag"
```

---

## Task 3: actionlint CI + README publish/verify docs

**Files:**
- Modify: `.github/workflows/lint.yml` (add an actionlint job/step)
- Modify: `README.md`

- [ ] **Step 1: Add actionlint to CI**

In `.github/workflows/lint.yml`, add a job that lints all workflows (so `release.yml` is checked on PRs that touch it):

```yaml
  actionlint:
    name: Lint workflows
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - name: actionlint
        run: |
          bash <(curl -fsSL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash)
          ./actionlint -color
```
(Match `lint.yml`'s existing trigger/permissions style; if it only triggers on `**.go`/lint paths, add `.github/workflows/**` to its `paths`.)

- [ ] **Step 2: Document install + verify + one-time setup in README**

In `README.md`, replace the Quickstart `helm install` guidance with the published-artifact path and add a short "Releasing" note. Include:
- Install from OCI: `helm install tor-gateway oci://ghcr.io/chimbosonic/charts/tor-gateway --version X.Y.Z` (still note the Gateway API CRD prerequisite already documented).
- Or via the Helm repo: `helm repo add tor-gateway https://chimbosonic.github.io/torGateway && helm install …`.
- Verify signatures: `cosign verify ghcr.io/chimbosonic/tor-gateway-manager:X.Y.Z --certificate-identity-regexp '^https://github.com/chimbosonic/torGateway' --certificate-oidc-issuer https://token.actions.githubusercontent.com` and `cosign verify-attestation --type spdxjson …`.
- A "Releasing" subsection: tag `vX.Y.Z` to trigger the pipeline; **one-time setup**: create an orphan `gh-pages` branch, and after the first release set the ghcr packages to public.

- [ ] **Step 3: Verify docs render**

Run: `sed -n '/## Quickstart/,/## /p' README.md` and confirm the OCI/repo install lines and the cosign verify example are present and the code fences are intact.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/lint.yml README.md
git commit --no-gpg-sign -m "ci(release): lint workflows; docs(readme): published install + verify + release setup"
```

---

## Acceptance (real-tag verification — do after merge + one-time setup)

This pipeline can't be unit-tested. After `gh-pages` exists, cut a pre-release tag and verify consumer-side:
```bash
git tag v0.0.1-rc1 && git push origin v0.0.1-rc1
# once the workflow completes and packages are public:
cosign verify ghcr.io/chimbosonic/tor-gateway-manager:0.0.1-rc1 \
  --certificate-identity-regexp '^https://github.com/chimbosonic/torGateway' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type spdxjson ghcr.io/chimbosonic/tor-gateway-manager:0.0.1-rc1 \
  --certificate-identity-regexp '^https://github.com/chimbosonic/torGateway' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker manifest inspect ghcr.io/chimbosonic/tor-gateway-manager:0.0.1-rc1 | grep -E 'amd64|arm64'
helm install rc oci://ghcr.io/chimbosonic/charts/tor-gateway --version 0.0.1-rc1 -n tg --create-namespace
kubectl -n <gw-ns> get pod -l torgateway.io/gateway=<gw> \
  -o jsonpath='{.items[0].spec.containers[?(@.name=="router")].image}'  # → …router:0.0.1-rc1
```

## Self-review notes

- **Spec coverage:** Section A (chart wiring) → Task 1; images build/sign/SBOM → Task 2 `images`; chart stamp/OCI-sign/GH-Pages → Task 2 `chart`; one-time setup + verify + docs → Task 3; multi-arch, keyless cosign, SPDX attest all in Task 2. The `:latest` convenience is intentionally dropped (project distrusts mutable tags) — a refinement of the spec's "stable-only `:latest`". ✓
- **Placeholders:** action SHAs are not invented — Task 2 Step 2 is an explicit pinning step with the resolution method (the only honest way; SHAs require lookup). Everything else is concrete.
- **Consistency:** image names match the Makefile vars; the `--router/-tor-init/-tor-image` flags match `cmd/manager/main.go`; the smoke assertion's `0.1.0` matches the chart's current appVersion; yq pin matches `chart.yml`.
- **Risk:** `helm push` digest parsing (`awk '/Digest:/'`) — verified at release time; the `test -n "$digest"` guard fails loudly if the output format differs. `chart-releaser-action` on a tag push (vs main) — confirm it packages the stamped chart; pin its SHA.
```
