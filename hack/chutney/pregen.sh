#!/usr/bin/env bash
# Bootstrap the chutney testing network once and export portable artifacts:
#   chutney-nodes.tar.gz  - /data/nodes state (VIP-addressed, cluster-portable)
#   chutney-image.tar     - the exact image the state was generated with
# Consumed by the chutney-pregen CI job; runnable locally for debugging.
set -euo pipefail

# Env knobs (all optional): PREGEN_KIND_CLUSTER, CHUTNEY_IMG, PREGEN_OUT_DIR,
# PREGEN_READY_TIMEOUT (kubectl duration, unit suffix required, e.g. 1080s).
CLUSTER="${PREGEN_KIND_CLUSTER:-tor-gateway-pregen}"
IMG="${CHUTNEY_IMG:-ghcr.io/chimbosonic/tor-gateway-chutney:dev}"
NS=tor-gateway-chutney
ATTEMPTS=3
# Generous single-attempt budget: a fresh bootstrap routinely needs >7min
# under load, so anything shorter burns attempts on healthy runs. (The e2e
# suite itself retries 3x7m fresh attempts — chutneyFreshBudget.)
READY_TIMEOUT="${PREGEN_READY_TIMEOUT:-1080s}"
OUT_DIR="${PREGEN_OUT_DIR:-.}"

note() { echo "[pregen] $*"; }
warn() {
    echo "::warning::$*"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$*" >>"$GITHUB_STEP_SUMMARY"
    note "$*"
}

make image-chutney CHUTNEY_IMG="$IMG"

if ! kind get clusters | grep -qx "$CLUSTER"; then
    kind create cluster --name "$CLUSTER"
fi
trap 'kind delete cluster --name "$CLUSTER"' EXIT
kind load docker-image "$IMG" --name "$CLUSTER"
KCTX="kind-$CLUSTER"

apply_manifest() {
    sed 's/__CHUTNEY_WAIT_SEED__/0/' hack/chutney/chutney.yaml |
        kubectl --context "$KCTX" apply -f -
}

# The first apply races the default-ServiceAccount controller in the
# brand-new namespace (pod creation is Forbidden until the SA exists);
# retry the apply itself so the race doesn't burn a bootstrap attempt.
applied=0
for _ in 1 2 3 4 5; do
    if apply_manifest; then
        applied=1
        break
    fi
    sleep 2
done
if [ "$applied" != 1 ]; then
    warn "chutney pregen: manifest apply failed repeatedly"
    exit 1
fi

ok=0
attempt=0
for attempt in $(seq 1 "$ATTEMPTS"); do
    # Attempt 1's pod was just created by the SA-race loop above; on
    # retries the pod was force-deleted, so re-apply recreates it.
    if [ "$attempt" -gt 1 ]; then
        apply_manifest
    fi
    note "bootstrap attempt ${attempt}/${ATTEMPTS} (budget ${READY_TIMEOUT})"
    if kubectl --context "$KCTX" -n "$NS" wait --for=condition=Ready \
        "pod/chutney" --timeout="$READY_TIMEOUT"; then
        ok=1
        break
    fi
    warn "chutney pregen bootstrap attempt ${attempt}/${ATTEMPTS} timed out; recreating pod"
    kubectl --context "$KCTX" -n "$NS" delete pod chutney --force --grace-period=0 --ignore-not-found
done
if [ "$ok" != 1 ]; then
    warn "chutney pregen failed after ${ATTEMPTS} attempts; e2e rows will fresh-bootstrap"
    exit 1
fi

note "exporting network state"
# Stop the relays before archiving: a clean shutdown flushes tor's state
# files and freezes the tree (tar errors with "file changed as we read it"
# on live logs). The cluster is deleted right after, so nothing misses it.
# A partial stop is tolerated — the tar below is the real gate.
kubectl --context "$KCTX" -n "$NS" exec chutney -- ./chutney stop networks/k8s-mini || true
# /data/nodes is a symlink to /data/nodes.<timestamp>, and the generated
# torrcs embed absolute /data/nodes.<timestamp>/... paths, so archive the
# symlink AND its target verbatim — dereferencing breaks those paths.
# Exclude runtime-only files: pid files and control sockets don't tar/restore.
# shellcheck disable=SC2016 # $(readlink) must expand in the pod, not here
kubectl --context "$KCTX" -n "$NS" exec chutney -- \
    sh -c 'tar -czf - --exclude="*.pid" --exclude="control" \
        -C /data nodes "$(basename "$(readlink /data/nodes)")"' \
    >"$OUT_DIR/chutney-nodes.tar.gz"
docker save -o "$OUT_DIR/chutney-image.tar" "$IMG"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "chutney pregen: ready on attempt ${attempt}/${ATTEMPTS}" >>"$GITHUB_STEP_SUMMARY"
fi
note "done: $OUT_DIR/chutney-nodes.tar.gz + $OUT_DIR/chutney-image.tar"
