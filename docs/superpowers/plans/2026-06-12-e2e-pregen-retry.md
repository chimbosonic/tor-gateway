# E2E Chutney Pre-Gen + Layered Retries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the e2e pipeline reliably green on every push by pre-generating the chutney Tor network once per CI run, retrying every flake point at its own granularity (bounded + visible), relocating non-Tor assertions to the controller test layer, and moving e2e CI to 4-vCPU arm64 runners.

**Architecture:** Chutney relays advertise a pinned Service ClusterIP (`10.96.77.77`) instead of `POD_IP`, making `/data/nodes` cluster-portable. A `chutney-pregen` CI job bootstraps once and uploads the state + image as artifacts; matrix rows warm-start from them with fresh-bootstrap fallback. Retries: bootstrap (3×, pod recreate), Mode B fixture (1 rebuild), spec (`--flake-attempts=2`, existing), job (1 re-run). Spec: `docs/superpowers/specs/2026-06-12-e2e-pregen-retry-design.md`.

**Tech Stack:** Go 1.26, Ginkgo v2, kind v0.31.0, chutney (pinned ref), GitHub Actions (`ubuntu-24.04-arm`), POSIX sh.

**Pre-verified facts (don't re-litigate):**
- All base-image digest pins (`golang:1.26@sha256:68cb…`, `alpine:3.21@sha256:48b0…`, `python:3.12-slim@sha256:090b…`, `debian:bookworm-slim@sha256:0104…`) are OCI **index** (manifest-list) digests with arm64 entries — arm builds need no re-pinning. Verified 2026-06-12 via `docker buildx imagetools inspect`.
- `internal/controller/network_policy_test.go:301-337` (`TestNetworkPolicySelectsBothModeBPodSets`, `TestNetworkPolicySelectorMatchesModeBPodLabels`, `TestNetworkPolicyMatchesRenderedModeBPods`) already covers everything the e2e NP-coverage spec asserts. No new NP test needed — relocation = deletion.
- `ensureModeB` (`internal/controller/gateway_controller.go:603`) ends by calling `updateStatusModeB` (line 697), so a fake-client `ensureModeB` call exercises status publication.
- kind is NOT preinstalled on GitHub runners; the workflow installs it selecting arch via `go env GOARCH` — works on arm unchanged.
- Local dev machine is an arm64 Mac with Docker + kind: local runs validate the arm64 path before CI does.

**Failure modes this plan must not regress:** the e2e core row is green and stable today. Mode A specs never touch any of the chutney plumbing except `DeployChutneyAndExtractFragment` — every change there must keep the no-artifact path working (local `make test-e2e` has no artifacts).

---

## Task 1: Extract chutney manifest to a file + pin VIP addressing, validate on local kind

This is the spike that gates the whole design. Do not start later tasks until step 8 passes.

**Files:**
- Create: `hack/chutney/chutney.yaml` (manifest moves out of Go so the pregen script and the e2e suite share one source)
- Modify: `images/chutney/entrypoint.sh`
- Modify: `test/e2e/chutney_test.go` (replace `chutneyManifest()` with file loading)

- [ ] **Step 1: Write the manifest file**

Create `hack/chutney/chutney.yaml`. This is the current manifest from `chutney_test.go:170-231` plus: pinned `clusterIP`, the full OR/dir port list, `CHUTNEY_ADVERTISE_IP`, and the `__CHUTNEY_WAIT_SEED__` token (substituted by consumers; Task 3 uses `1`):

```yaml
# Single source of truth for the e2e chutney deployment.
# Consumed by test/e2e/chutney_test.go (token-substituted in Go) and
# hack/chutney/pregen.sh (token-substituted with sed).
# clusterIP is pinned so relays can advertise a cluster-independent address:
# bootstrapped network state under /data/nodes then works in ANY kind cluster
# (kind's service CIDR 10.96.0.0/12 is identical everywhere), which is what
# makes the pre-gen artifact portable. 10.96.77.77 is far from the range
# kube allocates sequentially from, so collision is implausible.
apiVersion: v1
kind: Namespace
metadata:
  name: tor-gateway-chutney
---
apiVersion: v1
kind: Service
metadata:
  name: chutney-network
  namespace: tor-gateway-chutney
spec:
  clusterIP: 10.96.77.77
  selector: { app: chutney }
  ports:
  - { name: or-5000, port: 5000, targetPort: 5000 }
  - { name: or-5001, port: 5001, targetPort: 5001 }
  - { name: or-5002, port: 5002, targetPort: 5002 }
  - { name: or-5003, port: 5003, targetPort: 5003 }
  - { name: or-5004, port: 5004, targetPort: 5004 }
  - { name: or-5005, port: 5005, targetPort: 5005 }
  - { name: dir-7000, port: 7000, targetPort: 7000 }
  - { name: dir-7001, port: 7001, targetPort: 7001 }
  - { name: dir-7002, port: 7002, targetPort: 7002 }
  - { name: dir-7003, port: 7003, targetPort: 7003 }
  - { name: dir-7004, port: 7004, targetPort: 7004 }
  - { name: dir-7005, port: 7005, targetPort: 7005 }
---
apiVersion: v1
kind: Pod
metadata:
  name: chutney
  namespace: tor-gateway-chutney
  labels: { app: chutney }
spec:
  restartPolicy: OnFailure
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
  containers:
  - name: chutney
    image: ghcr.io/chimbosonic/tor-gateway-chutney:dev
    imagePullPolicy: Never
    env:
    - name: POD_IP
      valueFrom:
        fieldRef:
          fieldPath: status.podIP
    - name: CHUTNEY_ADVERTISE_IP
      value: "10.96.77.77"
    - name: CHUTNEY_WAIT_SEED
      value: "__CHUTNEY_WAIT_SEED__"
    volumeMounts:
    - { name: data, mountPath: /data }
    readinessProbe:
      exec:
        command: ["./chutney", "verify", "networks/k8s-mini"]
      initialDelaySeconds: 60
      periodSeconds: 15
      timeoutSeconds: 60
      failureThreshold: 30
    livenessProbe:
      exec:
        command: ["pgrep", "tor"]
      initialDelaySeconds: 600
      periodSeconds: 60
      failureThreshold: 5
    resources:
      requests: { cpu: "750m", memory: "1.5Gi" }
      limits:   { cpu: "1750m", memory: "3Gi" }
  volumes:
  - { name: data, emptyDir: {} }
```

Port-list caveat: 5000-5005/7000-7005 is the expected chutney allocation for the 8-node k8s-mini network (authorities idx 0-2, relays idx 3-5; clients/HS have no OR/dir ports). Step 7 verifies against reality; adjust the list there if it differs. Extra unused ports are harmless.

- [ ] **Step 2: Update the entrypoint to advertise the VIP**

Replace the address block at the top of `images/chutney/entrypoint.sh`. Keep the existing comment block; change only the address lines:

```sh
set -eu
: "${POD_IP:?POD_IP env var required (use downward API)}"
# Advertise the pinned Service VIP (cluster-portable) when set; fall back
# to POD_IP so the image keeps working outside the e2e harness.
export CHUTNEY_LISTEN_ADDRESS="${CHUTNEY_ADVERTISE_IP:-$POD_IP}"
./chutney configure networks/k8s-mini
./chutney start networks/k8s-mini
./chutney wait_for_bootstrap networks/k8s-mini || true
exec tail -f /dev/null
```

Known risk (the point of this spike): chutney uses `CHUTNEY_LISTEN_ADDRESS` to template both the advertised `Address` and possibly listener binds. Tor cannot *bind* a VIP that isn't a local interface address. If step 7 shows bind failures (`Could not bind to 10.96.77.77`), inspect the generated torrcs (`kubectl exec ... -- cat /data/nodes/000a/torrc`) and the chutney templates (`/chutney/torrc_templates/`). Fix by overriding the torrc templates in the image (copy modified templates in the Dockerfile next to the `networks/k8s-mini` COPY) so that `Address <VIP>` is advertise-only and `OrPort`/`DirPort` lines have no explicit bind address (binds 0.0.0.0). Do NOT fall back to the `NET_ADMIN` loopback-alias variant without checking templates first — template override is strictly simpler.

- [ ] **Step 3: Load the manifest from the file in Go**

In `test/e2e/chutney_test.go`, replace the `chutneyManifest()` function (lines 170-231) with:

```go
// chutneyManifest loads hack/chutney/chutney.yaml (shared with
// hack/chutney/pregen.sh) and substitutes the seed-mode token.
func chutneyManifest(waitSeed bool) string {
	projectDir, err := utils.GetProjectDir()
	Expect(err).NotTo(HaveOccurred(), "resolve project dir")
	raw, err := os.ReadFile(filepath.Join(projectDir, "hack", "chutney", "chutney.yaml"))
	Expect(err).NotTo(HaveOccurred(), "read hack/chutney/chutney.yaml")
	v := "0"
	if waitSeed {
		v = "1"
	}
	return strings.ReplaceAll(string(raw), "__CHUTNEY_WAIT_SEED__", v)
}
```

Update the call site in `DeployChutneyAndExtractFragment` to `applyYAML(chutneyManifest(false))` (Task 3 makes it conditional). Add `"path/filepath"` to imports. If `utils.GetProjectDir()` does not exist in `test/utils/utils.go` (it is standard kubebuilder scaffolding — check first), add it:

```go
// GetProjectDir returns the project root (the directory containing go.mod),
// derived from the test working directory.
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}
```

- [ ] **Step 4: Compile-check**

Run: `go vet -tags=e2e ./test/e2e/`
Expected: clean exit.

- [ ] **Step 5: Build the chutney image**

Run: `make image-chutney`
Expected: image builds (arm64 locally — this also validates the arm path).

- [ ] **Step 6: Spin up the VIP-addressed chutney on local kind**

```bash
make setup-test-e2e
kind load docker-image ghcr.io/chimbosonic/tor-gateway-chutney:dev --name tor-gateway-test-e2e
sed 's/__CHUTNEY_WAIT_SEED__/0/' hack/chutney/chutney.yaml | kubectl --context kind-tor-gateway-test-e2e apply -f -
```

Expected: Service created with `CLUSTER-IP: 10.96.77.77` (`kubectl -n tor-gateway-chutney get svc`).

- [ ] **Step 7: Verify bootstrap converges with VIP addressing**

```bash
kubectl --context kind-tor-gateway-test-e2e -n tor-gateway-chutney wait --for=condition=Ready pod/chutney --timeout=600s
kubectl --context kind-tor-gateway-test-e2e -n tor-gateway-chutney exec chutney -- sh -c "grep -h '^Address\|^OrPort\|^DirPort' /data/nodes/*/torrc | sort -u"
```

Expected: pod Ready (readiness = `./chutney verify` passes, which exercises relay↔relay reachability via the VIP — this IS the hairpin test); torrcs show `Address 10.96.77.77` and OR/dir ports matching the Service port list from step 1 (fix the list if not). If the pod never goes Ready, debug per step 2's known-risk note before proceeding — this gate decides the design.

- [ ] **Step 8: Verify an external pod can use the network via the extracted fragment**

The fragment now embeds VIP addresses. Run the full core e2e row locally — it deploys the operator with the fragment and pushes real traffic through the network:

```bash
make cleanup-test-e2e
E2E_LABEL_FILTER='!onionbalance' make test-e2e-suite
```

Expected: PASS. This proves operator tor pods bootstrap against VIP-advertised dirauths through the per-Gateway NetworkPolicy objects (kind doesn't enforce NP, but the operator's `--testing-tor-network-*` plumbing is fully exercised).

- [ ] **Step 9: Commit**

```bash
git add hack/chutney/chutney.yaml images/chutney/entrypoint.sh test/e2e/chutney_test.go test/utils/utils.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "test(e2e): pin chutney addressing to a fixed Service ClusterIP

Relays now advertise 10.96.77.77 (explicit spec.clusterIP; kind's
service CIDR is identical in every cluster) instead of POD_IP, making
bootstrapped network state under /data/nodes cluster-portable — the
prerequisite for pre-generating the network once per CI run. The
manifest moves to hack/chutney/chutney.yaml so the upcoming pregen
script and the e2e suite share one source."
```

---

## Task 2: Warm-start mode in the chutney entrypoint

**Files:**
- Modify: `images/chutney/entrypoint.sh`

- [ ] **Step 1: Add the seed-wait branch**

Full new entrypoint body (after the existing comment block):

```sh
set -eu
: "${POD_IP:?POD_IP env var required (use downward API)}"
# Advertise the pinned Service VIP (cluster-portable) when set; fall back
# to POD_IP so the image keeps working outside the e2e harness.
export CHUTNEY_LISTEN_ADDRESS="${CHUTNEY_ADVERTISE_IP:-$POD_IP}"

SEED_DIR=/data/seed
# Warm-start: when CHUTNEY_WAIT_SEED=1 the harness will `kubectl cp` a
# pre-generated /data/nodes tarball into SEED_DIR and touch SEED_DIR/ready.
# Existing keys + recent cached state let the dirauths re-vote a fresh
# consensus in 1-2 testing-network voting rounds instead of a full
# bootstrap. If the seed never arrives, fall through to a fresh bootstrap —
# warm-start is an optimization, never a correctness dependency.
if [ "${CHUTNEY_WAIT_SEED:-0}" = "1" ]; then
    echo "[entrypoint] waiting up to 300s for seed at ${SEED_DIR}/ready"
    i=0
    while [ "$i" -lt 300 ] && [ ! -f "${SEED_DIR}/ready" ]; do
        i=$((i + 1))
        sleep 1
    done
    if [ -f "${SEED_DIR}/ready" ]; then
        echo "[entrypoint] warm-start: extracting pre-generated network state"
        tar -xzf "${SEED_DIR}/nodes.tar.gz" -C /data
        ./chutney start networks/k8s-mini
        ./chutney wait_for_bootstrap networks/k8s-mini || true
        exec tail -f /dev/null
    fi
    echo "[entrypoint] seed never arrived; falling back to fresh bootstrap"
fi

./chutney configure networks/k8s-mini
./chutney start networks/k8s-mini
./chutney wait_for_bootstrap networks/k8s-mini || true
exec tail -f /dev/null
```

Note `./chutney start` without `configure` on the warm path: `configure` would regenerate keys/torrcs and discard the seed. The torrcs in the tar reference absolute `/data/nodes/...` paths, which are identical in the new pod.

- [ ] **Step 2: Rebuild and sanity-check fresh mode still works**

```bash
make image-chutney
docker run --rm -e POD_IP=127.0.0.1 -e CHUTNEY_WAIT_SEED=0 --entrypoint sh ghcr.io/chimbosonic/tor-gateway-chutney:dev -c 'sh -n /entrypoint.sh && echo SYNTAX-OK'
```

Expected: `SYNTAX-OK`.

- [ ] **Step 3: Commit**

```bash
git add images/chutney/entrypoint.sh
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "test(chutney): add warm-start mode to the entrypoint

With CHUTNEY_WAIT_SEED=1 the entrypoint waits up to 300s for a seeded
/data/nodes tarball (kubectl cp'd by the harness), starts the existing
nodes without reconfiguring, and falls back to a fresh bootstrap if the
seed never arrives. Dirauths re-vote a fresh consensus from existing
keys in 1-2 testing voting rounds instead of a full bootstrap."
```

---

## Task 3: Pregen script + Makefile target

**Files:**
- Create: `hack/chutney/pregen.sh`
- Modify: `Makefile` (new `pregen-chutney` target; bump `test-e2e-suite` go-test timeout)

- [ ] **Step 1: Write the pregen script**

Create `hack/chutney/pregen.sh` (mode 0755):

```bash
#!/usr/bin/env bash
# Bootstrap the chutney testing network once and export portable artifacts:
#   chutney-nodes.tar.gz  - /data/nodes state (VIP-addressed, cluster-portable)
#   chutney-image.tar     - the exact image the state was generated with
# Consumed by the chutney-pregen CI job; runnable locally for debugging.
set -euo pipefail

CLUSTER="${PREGEN_KIND_CLUSTER:-tor-gateway-pregen}"
IMG="${CHUTNEY_IMG:-ghcr.io/chimbosonic/tor-gateway-chutney:dev}"
NS=tor-gateway-chutney
ATTEMPTS=3
READY_TIMEOUT=420s
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

ok=0
for attempt in $(seq 1 "$ATTEMPTS"); do
    sed 's/__CHUTNEY_WAIT_SEED__/0/' hack/chutney/chutney.yaml |
        kubectl --context "$KCTX" apply -f -
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
# Exclude runtime-only files: pid files and control sockets don't tar/restore.
kubectl --context "$KCTX" -n "$NS" exec chutney -- \
    tar -czf - --exclude='*.pid' --exclude='control' -C /data nodes \
    >"$OUT_DIR/chutney-nodes.tar.gz"
docker save -o "$OUT_DIR/chutney-image.tar" "$IMG"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && {
    echo "chutney pregen: ready on attempt ${attempt}/${ATTEMPTS}" >>"$GITHUB_STEP_SUMMARY"
}
note "done: $OUT_DIR/chutney-nodes.tar.gz + $OUT_DIR/chutney-image.tar"
```

- [ ] **Step 2: Add the Makefile target and bump the suite timeout**

In `Makefile`, next to the other e2e targets (after `cleanup-test-e2e`, ~line 169):

```make
.PHONY: pregen-chutney
pregen-chutney: ## Bootstrap chutney once and export portable network-state + image artifacts (CI pregen job).
	hack/chutney/pregen.sh
```

In `test-e2e-suite` (~line 142), change `go test -tags=e2e -timeout 30m` to `-timeout 60m` (in-suite bootstrap retries of up to 3×7m can push a worst-case fresh-bootstrap row past 30m).

- [ ] **Step 3: Run the pregen script locally**

Run: `chmod +x hack/chutney/pregen.sh && make pregen-chutney`
Expected: `chutney-nodes.tar.gz` and `chutney-image.tar` appear in the repo root (gitignored? check — add `/chutney-nodes.tar.gz` and `/chutney-image.tar` to `.gitignore` if not covered); pregen kind cluster is deleted by the trap.

- [ ] **Step 4: Warm-start round-trip on local kind**

```bash
make setup-test-e2e
docker load -i chutney-image.tar
kind load docker-image ghcr.io/chimbosonic/tor-gateway-chutney:dev --name tor-gateway-test-e2e
sed 's/__CHUTNEY_WAIT_SEED__/1/' hack/chutney/chutney.yaml | kubectl --context kind-tor-gateway-test-e2e apply -f -
kubectl --context kind-tor-gateway-test-e2e -n tor-gateway-chutney wait --for=jsonpath='{.status.phase}'=Running pod/chutney --timeout=120s
kubectl --context kind-tor-gateway-test-e2e -n tor-gateway-chutney exec chutney -- mkdir -p /data/seed
kubectl --context kind-tor-gateway-test-e2e -n tor-gateway-chutney cp chutney-nodes.tar.gz chutney:/data/seed/nodes.tar.gz
kubectl --context kind-tor-gateway-test-e2e -n tor-gateway-chutney exec chutney -- touch /data/seed/ready
time kubectl --context kind-tor-gateway-test-e2e -n tor-gateway-chutney wait --for=condition=Ready pod/chutney --timeout=300s
make cleanup-test-e2e
```

Expected: Ready within the 300s budget, and meaningfully faster than a fresh bootstrap (compare against Task 1 step 7's time). If warm-start is NOT faster or doesn't converge, stop and reassess with the user before building CI on it — the fallback path still makes the design safe, but the artifact machinery wouldn't be paying rent.

- [ ] **Step 5: Commit**

```bash
git add hack/chutney/pregen.sh Makefile .gitignore
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "build(e2e): add chutney pregen script + make target

pregen-chutney bootstraps the VIP-addressed network once in a throwaway
kind cluster (3 bounded attempts, pod recreate between) and exports
/data/nodes plus the exact image as portable artifacts for the e2e
matrix rows. Suite go-test timeout 30m -> 60m to leave room for
worst-case in-suite bootstrap retries."
```

---

## Task 4: CI visibility helpers

**Files:**
- Create: `test/utils/ci.go`

- [ ] **Step 1: Write the helpers**

```go
/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package utils

import (
	"fmt"
	"os"
)

// CIWarning emits a GitHub Actions warning annotation (and a plain line for
// local runs). Workflow commands are parsed from any `run:` step's stdout,
// which includes `go test` output.
func CIWarning(format string, a ...any) {
	fmt.Fprintf(os.Stdout, "::warning::"+format+"\n", a...)
}

// StepSummary appends a line to the GitHub Actions step summary when
// available; always echoes to stdout so local runs see it too.
func StepSummary(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stdout, "[summary] "+line)
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintln(f, line)
}
```

- [ ] **Step 2: Compile-check and commit**

Run: `go vet ./test/utils/`
Expected: clean.

```bash
git add test/utils/ci.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "test(utils): add CIWarning + StepSummary helpers

Retry layers added next must surface every retry as a ::warning::
annotation and a step-summary line — a chronically retrying path has to
read as a bug, never as silence."
```

---

## Task 5: Bootstrap retry + seed injection in the e2e harness

**Files:**
- Modify: `test/e2e/chutney_test.go` (restructure `DeployChutneyAndExtractFragment`)

- [ ] **Step 1: Restructure `DeployChutneyAndExtractFragment` with the attempt loop**

Replace the function body (keep the doc comment, update it to mention retries). New code:

```go
const (
	chutneyFreshBudget = 7 * time.Minute
	chutneyWarmBudget  = 5 * time.Minute
	chutneyMaxAttempts = 3
)

func DeployChutneyAndExtractFragment() string {
	loadChutneyImage()

	seedTar := os.Getenv("CHUTNEY_SEED_TAR")
	for attempt := 1; attempt <= chutneyMaxAttempts; attempt++ {
		// Warm-start only on the first attempt: if seeded state failed
		// once, assume the artifact is the problem and bootstrap fresh.
		useSeed := seedTar != "" && attempt == 1
		budget := chutneyFreshBudget
		mode := "fresh bootstrap"
		if useSeed {
			budget = chutneyWarmBudget
			mode = "warm-start (artifact)"
		}

		By(fmt.Sprintf("deploying chutney: %s, attempt %d/%d", mode, attempt, chutneyMaxAttempts))
		applyYAML(chutneyManifest(useSeed))
		if useSeed {
			injectChutneySeed(seedTar)
		}
		if waitChutneyReady(budget) {
			utils.StepSummary("chutney ready: %s, attempt %d/%d", mode, attempt, chutneyMaxAttempts)
			return finishChutneySetup()
		}
		utils.CIWarning("chutney %s attempt %d/%d not Ready within %s; recreating pod",
			mode, attempt, chutneyMaxAttempts, budget)
		utils.StepSummary("chutney bootstrap retry: %s attempt %d/%d timed out", mode, attempt, chutneyMaxAttempts)
		_, _ = utils.Run(exec.Command("kubectl", "-n", chutneyNamespace, "delete", "pod",
			chutneyPodName, "--force", "--grace-period=0", "--ignore-not-found"))
	}
	Fail(fmt.Sprintf("chutney never became Ready after %d attempts", chutneyMaxAttempts))
	return "" // unreachable
}

// waitChutneyReady polls the Ready condition for up to budget. Returns false
// on timeout instead of failing, so the caller can retry.
func waitChutneyReady(budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		out, _ := utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
			"get", "pod", chutneyPodName,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}"))
		if strings.TrimSpace(out) == "True" {
			return true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

// loadChutneyImage prefers a pre-built image artifact (byte-identical to the
// one the pregen state was generated with); otherwise builds locally.
func loadChutneyImage() {
	if imgTar := os.Getenv("CHUTNEY_IMAGE_TAR"); imgTar != "" {
		By("loading the pre-built chutney image from artifact")
		_, err := utils.Run(exec.Command("docker", "load", "-i", imgTar))
		Expect(err).NotTo(HaveOccurred(), "docker load chutney image artifact")
		Expect(utils.LoadImageToKindClusterWithName(chutneyImage)).To(Succeed(),
			"kind-load chutney image from artifact")
		return
	}
	By("building and kind-loading the chutney image")
	buildAndLoadImage("image-chutney", chutneyImage)
}

// injectChutneySeed copies the pregen state tarball into the running pod and
// touches the marker the entrypoint waits for.
func injectChutneySeed(seedTar string) {
	By("injecting pre-generated chutney network state")
	Eventually(func() string {
		out, _ := utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
			"get", "pod", chutneyPodName, "-o", "jsonpath={.status.phase}"))
		return strings.TrimSpace(out)
	}, "2m", "2s").Should(Equal("Running"), "chutney pod must be Running to receive the seed")
	_, err := utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
		"exec", chutneyPodName, "--", "mkdir", "-p", "/data/seed"))
	Expect(err).NotTo(HaveOccurred(), "mkdir /data/seed")
	_, err = utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
		"cp", seedTar, chutneyPodName+":/data/seed/nodes.tar.gz"))
	Expect(err).NotTo(HaveOccurred(), "kubectl cp seed tarball")
	_, err = utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
		"exec", chutneyPodName, "--", "touch", "/data/seed/ready"))
	Expect(err).NotTo(HaveOccurred(), "touch seed-ready marker")
}

// finishChutneySetup is the post-Ready tail of the old function: extract the
// DirAuthority fragment, create the ConfigMap, patch + roll the operator.
func finishChutneySetup() string {
	By("extracting the DirAuthority block from the chutney pod")
	fragment := mustExtractChutneyFragment()

	By("creating the testing-network ConfigMap in the operator namespace")
	applyYAML(testingNetworkConfigMap(chutneyOperatorNS, fragment))

	By("patching the operator Deployment to mount + reference the fragment")
	patchOperatorForChutney()

	By("waiting for the operator rollout after the chutney patch")
	_, err := utils.Run(exec.Command("kubectl", "-n", chutneyOperatorNS,
		"rollout", "status", "deployment/"+chutneyOperatorDeploy,
		"--timeout="+chutneyRolloutTimeout.String()))
	Expect(err).NotTo(HaveOccurred(), "operator never rolled out with --testing-tor-network-file")

	return fragment
}
```

Delete the now-unused `chutneyReadyTimeout` const. Keep `chutneyRolloutTimeout`.

- [ ] **Step 2: Compile-check**

Run: `go vet -tags=e2e ./test/e2e/`
Expected: clean.

- [ ] **Step 3: Verify the no-artifact path locally (regression gate for core row)**

Run: `E2E_LABEL_FILTER='!onionbalance' make test-e2e-suite`
Expected: PASS, log shows `fresh bootstrap, attempt 1/3` and a `chutney ready` summary line.

- [ ] **Step 4: Verify the artifact path locally**

```bash
PREGEN_OUT_DIR=/tmp make pregen-chutney
CHUTNEY_SEED_TAR=/tmp/chutney-nodes.tar.gz CHUTNEY_IMAGE_TAR=/tmp/chutney-image.tar \
  E2E_LABEL_FILTER='!onionbalance' make test-e2e-suite
```

Expected: PASS, log shows `warm-start (artifact), attempt 1/3` and BeforeSuite completes faster than step 3's run.

- [ ] **Step 5: Commit**

```bash
git add test/e2e/chutney_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "test(e2e): bounded chutney bootstrap retries + pregen artifact consumption

BeforeSuite now warm-starts chutney from CHUTNEY_SEED_TAR /
CHUTNEY_IMAGE_TAR when set (5m budget, first attempt only) and falls
back to fresh bootstraps with pod recreation between attempts (7m x3)
otherwise. ginkgo --flake-attempts cannot retry BeforeSuite — this loop
is the retry layer matched to the failure mode that killed the last
onionbalance-base run. Every retry emits ::warning:: + step summary."
```

---

## Task 6: Mode B fixture retry

**Files:**
- Modify: `test/e2e/onionbalance_test.go` (split `modeBFixture` into build + warmup, retry once)

- [ ] **Step 1: Extract the warmup into an error-returning poll**

In `onionbalance_test.go`, remove the warmup `Eventually` block at the end of `modeBFixture` (lines 215-225) and rename the remaining function to `buildModeBFixture` (same signature/return). Add:

```go
// warmUpMasterOnion polls the master .onion until it serves a backend
// response. Error-returning (not Expect-failing) so the caller can rebuild
// the fixture and retry — a ginkgo BeforeAll failure is otherwise terminal.
func warmUpMasterOnion(ns, pod, onion string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last string
	for time.Now().Before(deadline) {
		out, _ := utils.Run(exec.Command("kubectl", "-n", ns, "exec", pod, "-c", "curl", "--",
			"curl", "-s", "--max-time", "30", "--socks5-hostname", "127.0.0.1:9050",
			"http://"+onion+"/"))
		last = strings.TrimSpace(out)
		if last == "backend-A" || last == "backend-B" {
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	return fmt.Errorf("master .onion not reachable within %s (last output %q)", budget, last)
}

// modeBFixture builds the fixture and warms the master .onion circuit,
// rebuilding the whole fixture once (fresh namespace, fresh keys) if the
// warmup times out.
func modeBFixture(ns, gwClass, gwName string) string {
	const warmupBudget = 10 * time.Minute
	torClientPod := gwName + "-tor-client"

	masterOnion := buildModeBFixture(ns, gwClass, gwName)
	By("warming up the Tor circuit to the master .onion (absorbs HSDir propagation latency)")
	err := warmUpMasterOnion(ns, torClientPod, masterOnion, warmupBudget)
	if err == nil {
		return masterOnion
	}

	utils.CIWarning("mode B fixture warmup failed in %s; rebuilding fixture once: %v", ns, err)
	utils.StepSummary("fixture rebuild: %s (warmup timeout)", ns)
	teardownModeBFixture(ns, gwClass)
	waitForNamespaceGone(ns)

	masterOnion = buildModeBFixture(ns, gwClass, gwName)
	By("warming up the Tor circuit after fixture rebuild")
	err = warmUpMasterOnion(ns, torClientPod, masterOnion, warmupBudget)
	Expect(err).NotTo(HaveOccurred(), "mode B fixture warmup failed again after rebuild")
	utils.StepSummary("fixture ready after rebuild: %s", ns)
	return masterOnion
}

// waitForNamespaceGone blocks until the namespace finishes deleting
// (teardownModeBFixture deletes with --wait=false).
func waitForNamespaceGone(ns string) {
	Eventually(func() string {
		out, _ := utils.Run(exec.Command("kubectl", "get", "ns", ns,
			"-o", "jsonpath={.metadata.name}", "--ignore-not-found"))
		return strings.TrimSpace(out)
	}, "3m", "5s").Should(BeEmpty(), "namespace %s should finish deleting before rebuild", ns)
}
```

Inside `buildModeBFixture`, the comment block above the (removed) warmup stays with the new `warmUpMasterOnion` call sites. The `By("deploying an in-cluster Tor SOCKS client...")` step and everything before it remain in `buildModeBFixture` unchanged.

- [ ] **Step 2: Compile-check**

Run: `go vet -tags=e2e ./test/e2e/`
Expected: clean.

- [ ] **Step 3: Run the onionbalance-base row locally**

Run: `E2E_FLAKE_ATTEMPTS=2 E2E_LABEL_FILTER='onionbalance && !ob-failover && !ob-crossns && !networkpolicy' make test-e2e-suite`
Expected: PASS (happy-path + key-isolation specs). On a healthy local network the rebuild path won't trigger — that's fine; it's exercised by fault injection only if you want (optional: `kubectl delete ns tor-gateway-chutney` mid-warmup to watch it fire).

- [ ] **Step 4: Commit**

```bash
git add test/e2e/onionbalance_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "test(e2e): rebuild the Mode B fixture once when the .onion warmup times out

The onionbalance-mutations row died in BeforeAll on both flake attempts
last run — ginkgo spec retries re-enter with the same broken fixture.
Splitting warmup out of the fixture into an error-returning poll lets
the BeforeAll tear the whole thing down (fresh namespace, fresh keys)
and rebuild once before failing for real. Retries surface via
::warning:: + step summary."
```

---

## Task 7: Relocate cross-NS + NP specs out of e2e

**Files:**
- Modify: `internal/controller/gateway_controller_modeb_test.go` (one gap test)
- Modify: `test/e2e/onionbalance_test.go` (delete the third `Describe` block)

- [ ] **Step 1: Write the failing-by-absence gap test**

The e2e cross-NS spec's unique assertion not yet covered at the controller layer: the Gateway status address equals the onion derived from the **cross-NS** master Secret. Append to `gateway_controller_modeb_test.go`:

```go
// TestEnsureModeB_CrossNSMasterOnionPublishedInStatus covers the assertion
// relocated from the e2e cross-NS spec: with a ReferenceGrant in place, the
// master .onion derived from a Secret in ANOTHER namespace ends up in
// Gateway.status.addresses. (RBAC enforcement of the frontend pod's cross-NS
// GET is live-only and deliberately not covered here — see the 2026-06-12
// e2e-pregen-retry design spec, "accepted gap".)
func TestEnsureModeB_CrossNSMasterOnionPublishedInStatus(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(1)
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName

	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	masterSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testMasterSecretName, Namespace: testMasterSecretNS},
		Data: map[string][]byte{
			tor.FileSecretKeyName: kp.SecretKeyFile(),
			tor.FilePublicKeyName: kp.PublicKeyFile(),
		},
	}
	rg := &gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-blog", Namespace: testMasterSecretNS},
		Spec: gwv1beta1.ReferenceGrantSpec{
			From: []gwv1beta1.ReferenceGrantFrom{{
				Group:     "policy.torgateway.io",
				Kind:      "OnionBalancePolicy",
				Namespace: gwv1beta1.Namespace(gw.Namespace),
			}},
			To: []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Secret"}},
		},
	}
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).
		WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).
		WithObjects(gw, obp, masterSecret, rg).
		Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}
	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB: %v", err)
	}

	var got gwv1.Gateway
	if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	want := kp.OnionAddress().String()
	for _, a := range got.Status.Addresses {
		if a.Value == want {
			return
		}
	}
	t.Errorf("status.addresses = %v, want to contain %s (onion derived from the cross-NS master Secret)",
		got.Status.Addresses, want)
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/controller/ -run TestEnsureModeB_CrossNSMasterOnionPublishedInStatus -v`
Expected: PASS (this is coverage relocation, not new behavior — if it FAILS, that's a real finding; stop and investigate before deleting anything from e2e).

- [ ] **Step 3: Delete the relocated e2e block**

In `test/e2e/onionbalance_test.go`, delete the entire third Describe block `Describe("OnionBalance HA — cross-NS + NetworkPolicy", ...)` (lines 422-598 pre-Task-6 numbering) and the now-unused `obpNS` const (line 53), plus any imports that go unused (`networkingv1`, `metav1`, `labels`, `json`, `sha256`/`hex` stay only if the remaining blocks use them — let the compiler tell you).

NP-coverage justification for deletion without replacement: `network_policy_test.go:301-337` already asserts the NP selector matches both Mode B pod sets, including against the **rendered** workload template labels (`TestNetworkPolicyMatchesRenderedModeBPods`) — strictly stronger than the e2e spec's live-pod-label check.

- [ ] **Step 4: Update spec-authoring comment + compile-check**

Update the header comment in `onionbalance_test.go` (rule 3, lines 24-25): `ob-crossns` and `networkpolicy` labels no longer exist; rule becomes "Use Label(\"ob-failover\") on mutator specs so the CI matrix can route them."

Run: `go vet -tags=e2e ./test/e2e/ && go test ./internal/controller/ -count=1`
Expected: clean vet; controller tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controller/gateway_controller_modeb_test.go test/e2e/onionbalance_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "test: relocate cross-NS + NP-coverage assertions from e2e to controller tests

Neither spec needed a live Tor network. NP selector coverage was
already asserted (more strongly) by TestNetworkPolicyMatchesRenderedModeBPods;
the cross-NS spec's one uncovered assertion — the master .onion derived
from a cross-NS Secret landing in Gateway.status.addresses — gets a
fake-client test. Live RBAC enforcement of the frontend's cross-NS
Secret GET is an accepted gap per the 2026-06-12 design spec."
```

---

## Task 8: Workflow rewrite — pregen job, artifact consumption, job retry, arm64

**Files:**
- Modify: `.github/workflows/test-e2e.yml`

- [ ] **Step 1: Pin actions/download-artifact**

The repo pins actions by commit SHA (mutable tags are distrusted here). Resolve the current release SHA — do NOT copy one from memory:

```bash
gh api repos/actions/download-artifact/releases/latest --jq .tag_name
gh api repos/actions/download-artifact/git/ref/tags/$(gh api repos/actions/download-artifact/releases/latest --jq .tag_name) --jq .object.sha
```

If the tag object SHA is an annotated tag, deref once more: `gh api repos/actions/download-artifact/git/tags/<sha> --jq .object.sha`. Use `<sha> # vX.Y.Z` in the workflow.

- [ ] **Step 2: Rewrite the workflow**

Full new `.github/workflows/test-e2e.yml` (checkout/setup-go/kind-install steps keep their existing pinned SHAs; `<DL_SHA>` from step 1):

```yaml
name: E2E Tests

# E2E spins up Kind, builds and loads images, applies the operator, and
# exercises live reconcilers. chutney-pregen bootstraps the Tor testing
# network ONCE per run and exports portable state (relays advertise a
# pinned Service ClusterIP); the three matrix rows warm-start from the
# artifact and fall back to fresh bootstraps if it is absent or stale.
# Every retry layer (bootstrap/fixture/spec/job) is bounded and emits
# ::warning:: + step-summary lines.
on:
  push:
    branches: [main]
  workflow_dispatch: {}

permissions: {}

jobs:
  chutney-pregen:
    permissions:
      contents: read
    name: chutney pre-gen
    runs-on: ubuntu-24.04-arm
    steps:
      - name: Clone the code
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false

      - name: Setup Go
        uses: actions/setup-go@4b73464bb391d4059bd26b0524d20df3927bd417 # v6.3.0
        with:
          go-version-file: go.mod

      - name: Install kind
        run: |
          curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.31.0/kind-linux-$(go env GOARCH)"
          chmod +x ./kind
          sudo mv ./kind /usr/local/bin/kind

      - name: Pre-generate the chutney network
        run: |
          mkdir -p "$RUNNER_TEMP/pregen"
          PREGEN_OUT_DIR="$RUNNER_TEMP/pregen" make pregen-chutney

      - name: Upload pregen artifacts
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: chutney-pregen
          path: ${{ runner.temp }}/pregen/
          retention-days: 1

  test-e2e:
    permissions:
      contents: read
    name: e2e (${{ matrix.suite }})
    runs-on: ubuntu-24.04-arm
    needs: chutney-pregen
    # Rows must run even when pregen fails — they fresh-bootstrap without
    # the artifact (warm-start is an optimization, never a dependency).
    if: ${{ !cancelled() }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - suite: core
            label_filter: '!onionbalance'
            flake_attempts: 1
          - suite: onionbalance-base
            label_filter: 'onionbalance && !ob-failover'
            flake_attempts: 2
          - suite: onionbalance-mutations
            label_filter: 'onionbalance && ob-failover'
            flake_attempts: 2
    env:
      CONTAINER_TOOL: docker
    steps:
      - name: Clone the code
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false

      - name: Setup Go
        uses: actions/setup-go@4b73464bb391d4059bd26b0524d20df3927bd417 # v6.3.0
        with:
          go-version-file: go.mod

      - name: Install kind
        run: |
          curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.31.0/kind-linux-$(go env GOARCH)"
          chmod +x ./kind
          sudo mv ./kind /usr/local/bin/kind

      - name: Download pre-generated chutney network
        continue-on-error: true
        uses: actions/download-artifact@<DL_SHA> # vX.Y.Z
        with:
          name: chutney-pregen
          path: ${{ runner.temp }}/pregen

      - name: Run e2e (${{ matrix.suite }})
        env:
          E2E_LABEL_FILTER: ${{ matrix.label_filter }}
          E2E_FLAKE_ATTEMPTS: ${{ matrix.flake_attempts }}
        run: |
          go mod tidy
          if [ -f "$RUNNER_TEMP/pregen/chutney-nodes.tar.gz" ]; then
            export CHUTNEY_SEED_TAR="$RUNNER_TEMP/pregen/chutney-nodes.tar.gz"
            export CHUTNEY_IMAGE_TAR="$RUNNER_TEMP/pregen/chutney-image.tar"
            echo "chutney source: warm-start (artifact)" >> "$GITHUB_STEP_SUMMARY"
          else
            echo "::warning::no chutney pregen artifact; fresh bootstrap (${{ matrix.suite }})"
            echo "chutney source: fresh bootstrap (no artifact)" >> "$GITHUB_STEP_SUMMARY"
          fi
          rc=1
          for attempt in 1 2; do
            if make test-e2e-suite; then
              rc=0
              break
            fi
            if [ "$attempt" -lt 2 ]; then
              echo "::warning::e2e suite attempt ${attempt}/2 failed (${{ matrix.suite }}); cleaning up and re-running"
              echo "suite re-run: attempt $((attempt + 1))/2 (${{ matrix.suite }})" >> "$GITHUB_STEP_SUMMARY"
              make cleanup-test-e2e || true
            fi
          done
          exit $rc

      - name: Step summary
        if: always()
        run: |
          set +e
          if [ ! -f ginkgo-report.json ]; then
            echo "## e2e (${{ matrix.suite }}): report not generated" >> "$GITHUB_STEP_SUMMARY"
            exit 0
          fi
          {
            echo "## e2e (${{ matrix.suite }}) summary"
            echo ""
            echo "| Spec | State | Duration |"
            echo "|---|---|---|"
            jq -r '.[0].SpecReports[]? |
              select(.LeafNodeType == "It") |
              [
                ((.ContainerHierarchyTexts // []) | join(" > ")) + " > " + .LeafNodeText,
                .State,
                ((.RunTime // 0) / 1000000000 | floor | tostring) + "s"
              ] | "| " + (.[0]) + " | " + (.[1]) + " | " + (.[2]) + " |"' ginkgo-report.json
          } >> "$GITHUB_STEP_SUMMARY"

      - name: Collect diagnostics
        if: failure()
        run: |
          set +e
          mkdir -p "$RUNNER_TEMP/e2e-diagnostics"
          kubectl logs -n tor-gateway-system deployment/tor-gateway-controller-manager \
            > "$RUNNER_TEMP/e2e-diagnostics/controller-current.log" 2>&1
          kubectl logs -n tor-gateway-system deployment/tor-gateway-controller-manager --previous \
            > "$RUNNER_TEMP/e2e-diagnostics/controller-previous.log" 2>&1 || true
          kubectl logs -n tor-gateway-chutney pod/chutney \
            > "$RUNNER_TEMP/e2e-diagnostics/chutney.log" 2>&1 || true
          for ns in tor-gateway-system tor-gateway-chutney tor-gateway-ha tor-gateway-ha-mut; do
            kubectl describe pods -n "$ns" \
              > "$RUNNER_TEMP/e2e-diagnostics/describe-pods-$ns.txt" 2>&1 || true
            kubectl get events -n "$ns" --sort-by='.lastTimestamp' \
              > "$RUNNER_TEMP/e2e-diagnostics/events-$ns.txt" 2>&1 || true
          done
          kubectl get pods -A -o wide \
            > "$RUNNER_TEMP/e2e-diagnostics/all-pods.txt" 2>&1 || true
          cp ginkgo-report.json "$RUNNER_TEMP/e2e-diagnostics/ginkgo-report.json" 2>/dev/null || true
          ls -la "$RUNNER_TEMP/e2e-diagnostics/"

      - name: Upload diagnostics
        if: failure()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: e2e-${{ matrix.suite }}-diagnostics
          path: ${{ runner.temp }}/e2e-diagnostics/
          retention-days: 7
          if-no-files-found: ignore
```

Notes vs the old file: runners → `ubuntu-24.04-arm`; label filters drop the deleted `ob-crossns`/`networkpolicy` labels; diagnostics drop the deleted `tor-gateway-ha-crossns`/`ha-master-secrets` namespaces; the run step gains artifact wiring + the bounded job retry.

- [ ] **Step 3: Lint the workflow**

Run: `actionlint .github/workflows/test-e2e.yml` (install via `brew install actionlint` if absent; if you choose not to install, at minimum `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/test-e2e.yml'))" && echo YAML-OK`).
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/test-e2e.yml
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "ci(e2e): pregen chutney once per run, consume via artifact, arm64 runners

New chutney-pregen job bootstraps the VIP-addressed network once and
uploads state + image; the matrix rows (now ubuntu-24.04-arm, 4 vCPU)
warm-start from it and fresh-bootstrap when it is absent — rows run
even if pregen fails. A bounded 2-attempt loop around make
test-e2e-suite is the job-level retry backstop. Matrix filters drop the
labels of the specs relocated to the controller layer."
```

---

## Task 9: Docs + full local verification

**Files:**
- Modify: `docs/PLAN.md` (v0.4.0 paragraph, ~line 37)
- Modify: `docs/superpowers/specs/2026-06-08-stable-e2e-pipeline-design.md` (status header)
- Check: `AGENTS.md` (update only if it documents the matrix filters/labels)

- [ ] **Step 1: Update PLAN.md**

Append to the `v0.4.0` paragraph (after "...graduation targeted for v0.5."):

```
The e2e pipeline pre-generates the chutney network once per run (relays advertise a pinned Service ClusterIP, making state portable across kind clusters), warm-starts the matrix rows from the artifact, retries bounded-and-visibly at bootstrap/fixture/spec/job granularity, and runs on 4-vCPU arm64 runners; non-Tor assertions (cross-NS master Secret, NP selector coverage) live in the controller test layer (see docs/superpowers/specs/2026-06-12-e2e-pregen-retry-design.md).
```

- [ ] **Step 2: Mark the superseded spec**

In `2026-06-08-stable-e2e-pipeline-design.md`, change the `**Status:**` line to:

```
**Status:** Shipped (waves 1-4). Partially superseded by `2026-06-12-e2e-pregen-retry-design.md` (retry posture, chutney pre-gen, spec relocation).
```

- [ ] **Step 3: Check AGENTS.md**

Run: `grep -n "onionbalance\|ob-crossns\|networkpolicy\|label" AGENTS.md`
If it documents e2e label filters, update them to match Task 8's matrix; otherwise no change.

- [ ] **Step 4: Full local verification sweep**

```bash
make test                                            # unit + envtest, includes the new gap test
E2E_LABEL_FILTER='!onionbalance' make test-e2e-suite # core row
E2E_FLAKE_ATTEMPTS=2 E2E_LABEL_FILTER='onionbalance && !ob-failover' make test-e2e-suite
E2E_FLAKE_ATTEMPTS=2 E2E_LABEL_FILTER='onionbalance && ob-failover' make test-e2e-suite
```

Expected: all PASS. These are the exact row invocations CI will run (minus artifacts). ~60-90 min total; run sequentially.

- [ ] **Step 5: Commit docs**

```bash
git add docs/PLAN.md docs/superpowers/specs/2026-06-08-stable-e2e-pipeline-design.md AGENTS.md
git commit --no-gpg-sign --author="Alexis Lowe <claude-fable-5@chimbosonic.com>" -m "docs: record e2e pregen pipeline in PLAN.md, mark 06-08 spec superseded"
```

- [ ] **Step 6: CI acceptance (after the user pushes)**

The user pushes (never push for them). Acceptance evidence on the first runs: pregen job green with `chutney pregen: ready on attempt N/3` in its summary; each row's summary shows `chutney source: warm-start (artifact)` and all specs Passed; warnings (if any) enumerate exactly which retry layers fired. If `onionbalance-*` rows still fail after all four retry layers on 4 vCPU, that's a real signal — reopen the design with the user rather than adding attempts.

---

## Self-review notes

- **Spec coverage:** Change 1 → Task 1; Change 2 → Task 3 + 8; Change 3 → Task 2 + 5; Change 4 → Tasks 3 (pregen retry), 5 (bootstrap), 6 (fixture), 8 (job) — spec layer pre-exists; Change 5 → Task 7; Change 6 → Task 8 (digest re-pin verified unnecessary, recorded in header); error-handling section → Task 8 (`if: !cancelled()` + `continue-on-error` download); testing section → Tasks 1/3/5/6/9.
- **Ordering:** Task 1 is the gate. Tasks 2-3 depend on 1; 4 is independent; 5-6 depend on 4; 7 independent; 8 depends on 3+5+7 (env names, labels); 9 last.
- **Consistency:** env names `CHUTNEY_SEED_TAR`/`CHUTNEY_IMAGE_TAR`/`CHUTNEY_ADVERTISE_IP`/`CHUTNEY_WAIT_SEED`, token `__CHUTNEY_WAIT_SEED__`, VIP `10.96.77.77`, artifact name `chutney-pregen`, helpers `utils.CIWarning`/`utils.StepSummary`, funcs `buildModeBFixture`/`warmUpMasterOnion`/`waitForNamespaceGone`/`waitChutneyReady`/`loadChutneyImage`/`injectChutneySeed`/`finishChutneySetup` — used identically across tasks.
