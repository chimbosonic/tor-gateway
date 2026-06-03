#!/bin/sh
# Wait until obrefresh has populated /etc/onionbalance/config/config.yaml
# with at least one backend instance. Onionbalance refuses to start on an
# empty instances list ("Config file is bad. No backend instances are set.
# Onionbalance needs at least 1."), so we cannot race it against the first
# Secret-informer event in obrefresh.
set -eu
CONFIG="${ONIONBALANCE_CONFIG:-/etc/onionbalance/config/config.yaml}"
while ! grep -qE '^[[:space:]]*-[[:space:]]+address:' "$CONFIG" 2>/dev/null; do
    echo "onionbalance: waiting for obrefresh to populate at least one backend in $CONFIG..." >&2
    sleep 5
done
exec onionbalance "$@"
