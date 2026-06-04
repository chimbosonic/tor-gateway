#!/bin/sh
# Reads POD_IP (downward API), rebinds chutney to that IP so authority
# certs embed the in-cluster Pod IP (otherwise external pods cannot reach
# the network), configures + starts + waits for bootstrap, then sleeps.
# The readiness probe re-runs `./chutney verify` on demand.
set -eu
: "${POD_IP:?POD_IP env var required (use downward API)}"
export CHUTNEY_LISTEN_ADDRESS="${POD_IP}"
./chutney configure networks/k8s-mini
./chutney start networks/k8s-mini
./chutney wait_for_bootstrap networks/k8s-mini
exec tail -f /dev/null
