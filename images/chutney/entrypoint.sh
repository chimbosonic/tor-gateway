#!/bin/sh
# Reads POD_IP (downward API), rebinds chutney to that IP so authority
# certs embed the in-cluster Pod IP (otherwise external pods cannot reach
# the network). Then configures + starts the chutney processes and
# tail -f's. We deliberately do NOT make the pod's lifetime depend on
# chutney's wait_for_bootstrap exit code — the readiness probe runs
# `./chutney verify` on a cadence and is the real gate. If consensus
# converges after a few voting cycles, the probe goes green; the pod
# stays alive throughout.
#
# This decouples the k8s pod lifetime from chutney's internal
# CHUTNEY_START_TIME (default 60s, sometimes too tight under kind
# scheduler load). The previous design exited on wait_for_bootstrap
# timeout, the pod went to Error/restartPolicy:Never, and Tor died.
set -eu
: "${POD_IP:?POD_IP env var required (use downward API)}"
# Advertise the pinned Service VIP (cluster-portable) when set; fall back
# to POD_IP so the image keeps working outside the e2e harness.
export CHUTNEY_LISTEN_ADDRESS="${CHUTNEY_ADVERTISE_IP:-$POD_IP}"
./chutney configure networks/k8s-mini
./chutney start networks/k8s-mini
./chutney wait_for_bootstrap networks/k8s-mini || true
exec tail -f /dev/null
