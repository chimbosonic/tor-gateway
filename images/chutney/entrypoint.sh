#!/bin/sh
# Reads POD_IP (downward API), rebinds chutney to that IP so authority
# certs embed the in-cluster Pod IP (otherwise external pods cannot reach
# the network), configures + starts + waits for bootstrap, then sleeps.
# The readiness probe re-runs `./chutney verify` on demand.
set -eu
: "${POD_IP:?POD_IP env var required (use downward API)}"
export CHUTNEY_LISTEN_ADDRESS="${POD_IP}"
# Default 60s is too short for a single-node kind cluster: relays do not
# get into the first consensus before chutney's bootstrap timeout fires.
# 180s gives enough budget for two voting cycles (TestingV3AuthInitialVotingInterval=20).
export CHUTNEY_START_TIME="${CHUTNEY_START_TIME:-180}"
./chutney configure networks/k8s-mini
./chutney start networks/k8s-mini
./chutney wait_for_bootstrap networks/k8s-mini
exec tail -f /dev/null
