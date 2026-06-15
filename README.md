# tor-gateway

A Kubernetes [Gateway API](https://gateway-api.sigs.k8s.io/) conformant operator that exposes in-cluster `Service`s as Tor v3 hidden services (`.onion` URLs).

Drop in a `Gateway` of class `tor-gateway` and one or more `HTTPRoute`s, and the operator provisions a Tor daemon, manages its ed25519 keys, and publishes the resulting `.onion` address in `Gateway.status.addresses`.

## Status

Alpha — `v0.4.0` is the current release: installable, with signed multi-arch images + chart (see [Quickstart](#quickstart) and [Verifying signatures](#verifying-signatures)). See [the design plan](./docs/PLAN.md) and [`SECURITY.md`](./SECURITY.md).

## Quickstart

> Prerequisite: install the upstream Gateway API CRDs first (the chart ships
> this operator's policy CRDs but not the Gateway API ones), e.g.
> `make install-gateway-api-crds`.

```sh
make setup-test-e2e
```

Published packages (OCI + Helm repo) exist once a `vX.Y.Z` release is cut (see [Releasing](#releasing)); before the first release, use the local-development install below.

Install from the published OCI chart (recommended):

```sh
helm install tor-gateway oci://ghcr.io/chimbosonic/charts/tor-gateway --version X.Y.Z
```

Or via the Helm repo:

```sh
helm repo add tor-gateway https://chimbosonic.github.io/tor-gateway
helm repo update
helm install tor-gateway tor-gateway/tor-gateway --version X.Y.Z
```

For local development, the chart can also be installed directly:

```sh
helm install tor-gateway ./charts/tor-gateway
```

```sh
kubectl apply -f config/samples/blog-gateway.yaml
kubectl get gateway blog -o jsonpath='{.status.addresses[0].value}'
```

## Verifying signatures

Images are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) via keyless signing in CI. To verify:

```sh
cosign verify ghcr.io/chimbosonic/tor-gateway-manager:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/chimbosonic/tor-gateway/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type spdxjson ghcr.io/chimbosonic/tor-gateway-manager:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/chimbosonic/tor-gateway/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The same verification applies to the other images the chart deploys: `tor-gateway-router`, `tor-gateway-tor-init`, `tor-gateway-vanity-finalize`, `mkp224o`, `tor`, and (for the HA path) `tor-gateway-obrefresh` and `tor-gateway-onionbalance`.

## Releasing

Pushing a `vX.Y.Z` tag triggers `.github/workflows/release.yml`, which builds and signs the images, attaches SBOMs, and publishes the Helm chart to both OCI (`oci://ghcr.io/chimbosonic/charts/tor-gateway`) and GitHub Pages.

**One-time setup:**

1. Create an orphan `gh-pages` branch so the chart index has a home:
   ```sh
   git checkout --orphan gh-pages && git rm -rf . && git commit --allow-empty -m "init gh-pages" && git push origin gh-pages
   ```
2. After the first release, set the ghcr packages to **public** so users can pull without authenticating: the chart (`ghcr.io/chimbosonic/charts/tor-gateway`) and every image the chart deploys (`tor-gateway-manager`, `tor-gateway-router`, `tor-gateway-tor-init`, `tor-gateway-vanity-finalize`, `mkp224o`, and `tor`; plus `tor-gateway-obrefresh` once the HA path uses it). Leaving the runtime images private deploys the operator but leaves Tor pods in `ImagePullBackOff`.

## Features (v1 target)

- Gateway API v1.5 conformance (Gateway + HTTPRoute + ReferenceGrant).
- Persistent v3 keys via Secrets.
- v3 client authorization via `TorClientAuthPolicy`.
- HA via onionbalance via `OnionBalancePolicy` (Mode B, experimental in v0.4.0; requires chart appVersion ≥ 0.4.0 because earlier installs reference the wrong onionbalance image repo).
- Vanity address prefixes via `TorServicePolicy.vanityPrefix` (on-demand `mkp224o` Job).
- Prometheus metrics, cosign-signed images, SBOM.

## License

Apache 2.0.
