# Release pipeline: publish + sign images and chart — design

- **Date:** 2026-05-27
- **Status:** Implemented — shipped in `v0.1.0` (`.github/workflows/release.yml`: multi-arch images + chart, cosign-signed, SBOM; chart runtime-image wiring in `deployment.yaml`).
- **Owner:** Alexis Lowe

## Context

Nothing is published yet: no release workflow exists, the five container
images (`manager`, `router`, `obrefresh`, `tor-init`, `tor`) are not in any
public registry, and the (now-complete) Helm chart is not published. `make
docker-push`/`docker-buildx` exist but no CI invokes them. The PLAN's
distribution decision: "Helm chart to GitHub Pages + OCI (ghcr.io);
cosign-signed images + chart."

A second, blocking gap surfaced while scoping: the chart's `deployment.yaml`
does **not** pass the manager's `--router-image`/`--tor-init-image`/
`--tor-image` flags, so a chart-installed operator uses the manager's
baked-in defaults (`…router:dev`, `…tor-init:dev`, `…tor:0.4.9`). The
`torRuntime.*Image` values in `values.yaml` are dead config, and there is no
`torInitImage` value. Publishing a chart whose operator requests `:dev`
images would be pointless, so wiring these is part of this work.

## Goals

- A `vX.Y.Z` git tag produces a complete, **installable, signed** release:
  - all five images built multi-arch (amd64+arm64), pushed to ghcr,
    cosign-signed (keyless), with an SBOM attestation each;
  - the Helm chart version/appVersion stamped to `X.Y.Z`, pushed as an OCI
    artifact (cosign-signed) **and** published to a GitHub Pages Helm repo;
  - the released chart deploys an operator that uses the **released** images.

## Non-goals (YAGNI)

- SLSA provenance beyond cosign signatures + SBOM attestation.
- Image vulnerability-scan gates in the release path.
- Auto-generated changelog / release notes.
- Signing keys/rotation (keyless needs none).
- Floating tags beyond a single convenience `:latest`.
- Wiring the `obrefresh`/`onionbalance` images into the operator (no flags
  exist for them yet; they belong to the not-yet-built HA path). They are
  still built + pushed + signed for future use, but not injected.

## Decisions (settled during brainstorming)

| Question | Decision |
|---|---|
| Scope | Full pipeline: images **and** chart. |
| Trigger / version | Git tag `vX.Y.Z`; version = `${tag#v}`. |
| Chart distribution | OCI (`oci://ghcr.io/chimbosonic/charts`) **and** GitHub Pages. |
| Image architectures | `linux/amd64,linux/arm64` (multi-arch manifests). |
| Image signing | cosign **keyless** (Sigstore OIDC via `id-token: write`), by digest. |
| SBOM | `syft` SPDX-JSON, attached via `cosign attest --type spdxjson`. |

## Design

### A. Prerequisite — wire the chart's runtime images (chart change)

So the released chart's operator uses the released images:
- Add the missing `torRuntime.torInitImage` value; keep `routerImage` and
  `torImage` (drop/defer `obrefreshImage`/`onionbalanceImage` from the wired
  set — unused until HA).
- In `charts/tor-gateway/templates/deployment.yaml`, pass the manager flags
  from those values: `--router-image=<repo:tag>`, `--tor-init-image=…`,
  `--tor-image=…`, with the tag defaulting to `.Chart.AppVersion` for our
  own images (`router`, `tor-init`) and to the pinned upstream tag for `tor`
  (`0.4.9`). Use a small `_helpers.tpl` helper mirroring `tor-gateway.managerImage`.
- The chart smoke test (existing) should additionally assert the Tor pod
  references the chart-configured images (not `:dev`).

### B. Release workflow `.github/workflows/release.yml`

`on: { push: { tags: ['v*'] } }`; top-level `permissions: { contents: write,
packages: write, id-token: write }`. A `version` is derived once
(`${GITHUB_REF_NAME#v}`).

**Job `images`** (matrix over `manager, router, obrefresh, tor-init, tor`):
- `docker/setup-qemu-action` + `docker/setup-buildx-action` +
  `docker/login-action` (ghcr, `GITHUB_TOKEN`).
- `docker/build-push-action` builds `linux/amd64,linux/arm64` and pushes
  `ghcr.io/chimbosonic/<image>:X.Y.Z` (plus `:latest` only for stable tags —
  not pre-releases like `v0.0.1-rc1`); the Go images
  cross-compile via `TARGETARCH`, `tor` uses QEMU. Build context/Dockerfile:
  the shared `Dockerfile` with `--build-arg BINARY=<name>` for the four Go
  binaries; `images/tor/Dockerfile` for `tor`. The action emits the pushed
  **digest** (`outputs.digest`).
- `sigstore/cosign-installer`, then `cosign sign --yes
  ghcr.io/chimbosonic/<image>@<digest>` (keyless).
- `anchore/sbom-action` (or `syft`) → SPDX-JSON, then `cosign attest --yes
  --type spdxjson --predicate sbom.spdx.json …@<digest>`.

**Job `chart`** (`needs: images`):
- `yq` stamps `Chart.yaml` `version` + `appVersion` to `X.Y.Z`.
- OCI: `helm registry login ghcr.io`, `helm package charts/tor-gateway`,
  `helm push tor-gateway-X.Y.Z.tgz oci://ghcr.io/chimbosonic/charts`, then
  `cosign sign --yes ghcr.io/chimbosonic/charts/tor-gateway@<chart-digest>`.
- GitHub Pages: `helm/chart-releaser-action` packages the chart, creates the
  per-chart GitHub Release, and updates `index.yaml` on the `gh-pages` branch.

Image names follow the existing Makefile vars
(`tor-gateway-manager`/`-router`/`-obrefresh`/`-tor-init`, and `tor`).

### C. One-time setup (documented, not automated)

- Create an (orphan) `gh-pages` branch for the Helm repo.
- After the first release, set the ghcr packages **public** (they inherit
  private) so users pull without auth; cosign signatures/attestations live
  beside each package.
- README: add install instructions for both paths (`helm install
  oci://…` and `helm repo add …`) and a `cosign verify` example.

## Files touched

- Create: `.github/workflows/release.yml`.
- Modify: `charts/tor-gateway/templates/deployment.yaml` (manager image
  flags), `charts/tor-gateway/templates/_helpers.tpl` (runtime-image helper),
  `charts/tor-gateway/values.yaml` (`torRuntime.torInitImage`; prune unused).
- Modify: `test/chart/gateway.yaml` smoke / the `chart-smoke` assertions
  (verify the configured images).
- Modify: `README.md` (install + verify + one-time setup notes).
- Possibly: `.github/cr.yaml` (chart-releaser config) if defaults need tuning.

## Verification

A release pipeline can't be unit-tested; verify by cutting a pre-release tag
(`v0.0.1-rc1`) and checking, consumer-side:
- `cosign verify ghcr.io/chimbosonic/tor-gateway-manager:0.0.1-rc1 …` and
  `cosign verify-attestation --type spdxjson …` succeed.
- `docker manifest inspect` shows amd64 + arm64.
- `helm install oci://ghcr.io/chimbosonic/charts/tor-gateway --version
  0.0.1-rc1` deploys, and the Tor pod references the released images
  (`…router:0.0.1-rc1`, `…tor:0.4.9`), not `:dev`.
- `helm repo add` from the GH Pages URL lists the chart.
- `actionlint` (added as a lint step) passes on the workflow.

## Risks / to resolve during planning

- **cosign digest plumbing:** sign/attest must use the pushed image **digest**
  (from `build-push-action` `outputs.digest`), not the tag, for immutable
  signatures — confirm the action exposes it per matrix entry.
- **Multi-arch `tor` build needs QEMU** (Alpine `apk` runs in-target); the Go
  images cross-compile (fast). Confirm buildx caching keeps build time sane.
- **chart-releaser vs OCI** both run in one workflow on the same tag —
  confirm `chart-releaser-action`'s tagging/release naming doesn't collide
  with the git tag, and that it operates correctly when invoked on a tag push
  (it's commonly run on `main`); pin its action SHA per repo convention.
- **Chart runtime-image wiring (Section A)** is a real correctness change to
  the chart, with its own review — keep it a distinct commit/task.
- ghcr package visibility + `gh-pages` existence are manual one-time steps;
  the first release will partially fail until they're set up — document
  clearly.
