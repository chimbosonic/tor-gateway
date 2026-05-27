#!/usr/bin/env bash
# read-sbom.sh — fetch and inspect the SPDX SBOM that release.yml attaches to a
# tor-gateway image as a cosign attestation.
#
# Usage:
#   hack/read-sbom.sh [-v] [-o OUTFILE] [IMAGE] [TAG]
#
#   IMAGE    short name under ghcr.io/chimbosonic (default: tor-gateway-manager).
#            One of: tor-gateway-manager tor-gateway-router tor-gateway-tor-init
#            tor-gateway-obrefresh tor
#   TAG      image tag. Defaults to DEFAULT_VERSION below, except `tor` which is
#            pinned independently (TOR_TAG).
#   -v       verify provenance (cosign verify-attestation) as well as extract.
#   -o FILE  where to write the SPDX JSON (default: sbom-<image>-<tag>.spdx.json).
#
# Requires: cosign, jq. If the package is private, `docker login ghcr.io` first
# (cosign reuses docker's credentials).
set -euo pipefail

DEFAULT_VERSION="0.0.1-rc1"   # bump to the release you want to inspect
TOR_TAG="0.4.9"               # the upstream `tor` image is version-locked here
REGISTRY="ghcr.io/chimbosonic"
IDENTITY_REGEXP='^https://github.com/chimbosonic/tor-gateway/\.github/workflows/release\.yml@'
OIDC_ISSUER="https://token.actions.githubusercontent.com"
SPDX_PREDICATE_TYPE="https://spdx.dev/Document"

verify=false
out=""
while getopts ":vo:h" opt; do
  case "$opt" in
    v) verify=true ;;
    o) out="$OPTARG" ;;
    h) sed -n '2,17p' "$0"; exit 0 ;;
    \?) echo "unknown option -$OPTARG (try -h)" >&2; exit 2 ;;
    :)  echo "option -$OPTARG needs an argument" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

image="${1:-tor-gateway-manager}"
if [ "$image" = "tor" ]; then
  tag="${2:-$TOR_TAG}"
else
  tag="${2:-$DEFAULT_VERSION}"
fi
ref="${REGISTRY}/${image}:${tag}"
out="${out:-sbom-${image}-${tag}.spdx.json}"

for tool in cosign jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool not found (brew install $tool)" >&2; exit 1; }
done

if $verify; then
  echo ">> verifying + extracting SBOM for ${ref}" >&2
  fetch() {
    cosign verify-attestation --type spdxjson \
      --certificate-identity-regexp "$IDENTITY_REGEXP" \
      --certificate-oidc-issuer "$OIDC_ISSUER" "$ref"
  }
else
  echo ">> downloading SBOM for ${ref}" >&2
  fetch() { cosign download attestation --predicate-type "$SPDX_PREDICATE_TYPE" "$ref"; }
fi

# cosign emits one DSSE envelope per attestation; slurp them, unwrap each
# in-toto payload to its predicate, keep the SPDX document.
fetch | jq -s '
  map(.payload | @base64d | fromjson | .predicate)
  | map(select(.spdxVersion != null))
  | (.[0] // ("no SPDX attestation found for '"$ref"'" | halt_error(1)))
' > "$out"

count=$(jq '.packages | length' "$out")
echo ">> wrote ${out}  (${count} packages)" >&2
echo "------------------------------------------------------------" >&2
jq -r '.packages[] | "\(.name) \(.versionInfo // "-")"' "$out" | sort -u
