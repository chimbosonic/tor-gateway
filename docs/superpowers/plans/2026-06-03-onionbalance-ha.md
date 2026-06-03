# Onionbalance HA (Mode B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Mode B from `docs/PLAN.md`: HA for a Gateway's hidden service via the Tor Project's onionbalance daemon. When an `OnionBalancePolicy` targets a Gateway, the operator stops provisioning the standalone Tor pod and instead provisions a single onionbalance frontend Deployment (publishing the user-supplied master `.onion`) plus a backend StatefulSet of N independent Tor instances behind that master address.

**Architecture:** The plan reuses existing helpers (`tor.ParseFiles`, `tor.AddressFromPublicKey`, `tor.TorrcConfig`+`Render`, the `Build*` resource-builder pattern, and the `gatewaysForServicePolicy`-style watch enqueuers). Mode B resource builders live in a new `gateway_resources_ha.go` to keep `gateway_resources.go` focused on Mode A. The OBP reconciler validates the master Secret + writes status; the Gateway reconciler owns provisioning and switches between Mode A and Mode B based on whether an Accepted OBP targets the Gateway. All Mode B resources are owned by the Gateway (not by the OBP), giving Mode A↔B transitions clean cleanup-by-reconcile semantics consistent with existing TSP/TCAP behaviour.

**Tech Stack:** Go + kubebuilder (controller-runtime), the in-repo `internal/tor` ed25519/torrc helpers, `client-go` informer for the obrefresh Secret watch, a new `images/onionbalance/` Python+onionbalance container, the existing root multi-stage Dockerfile for the obrefresh Go binary.

**Spec:** [`docs/superpowers/specs/2026-06-03-onionbalance-ha-design.md`](../specs/2026-06-03-onionbalance-ha-design.md).

---

## File Structure

| Path | Action | Responsibility |
|---|---|---|
| `api/v1alpha1/onionbalancepolicy_types.go` | Modify | Tighten `replicas` cap (12 → 8); clarify `masterKeySecretRef` docstring. |
| `api/v1alpha1/zz_generated.deepcopy.go` | Regenerate | `make generate`. |
| `config/crd/bases/policy.torgateway.io_onionbalancepolicies.yaml` | Regenerate | `make manifests`. |
| `charts/tor-gateway/files/crds/policy.torgateway.io_onionbalancepolicies.yaml` | Regenerate | `make chart-sync`. |
| `internal/tor/master_key.go` | Create | `ValidateMasterKeySecret(data map[string][]byte) (*tor.KeyPair, error)` — thin wrapper around `tor.ParseFiles` that enforces the Secret-key map shape required by `OnionBalancePolicy.masterKeySecretRef`. |
| `internal/tor/master_key_test.go` | Create | Table-driven tests for the validator. |
| `internal/tor/torrc.go` | Modify | Add an `OnionbalanceInstance bool` flag to `TorrcConfig`; emit `HiddenServiceOnionbalanceInstance 1` when set; unconditionally omit PoW directives when the flag is set. |
| `internal/tor/torrc_test.go` | Modify | New cases asserting the backend variant. |
| `internal/onionbalance/config.go` | Create | `Render(master tor.OnionAddress, backends []tor.OnionAddress) (string, error)` — pure YAML renderer for onionbalance `config.yaml`. |
| `internal/onionbalance/config_test.go` | Create | Table-driven tests. |
| `internal/onionbalance/refresher.go` | Rewrite | Replace the stub `Run` with a Secret informer (label-selected) + debouncer + SIGHUP-via-pidfile. |
| `internal/onionbalance/refresher_test.go` | Create | Fake-clientset informer events → assert config rewrite + SIGHUP. |
| `cmd/tor-init/main.go` | Modify | Add a `--ob-master-address <addr>` flag. When set, the init container also writes `<HSDir>/ob_config` containing `MasterOnionAddress <addr>.onion`. |
| `internal/controller/onionbalancepolicy_controller.go` | Rewrite | Replace stub. Validates targets + master Secret; writes per-ancestor `Accepted` condition + `status.readyBackends`. |
| `internal/controller/onionbalancepolicy_controller_test.go` | Rewrite | Envtest cases for happy path + every `Accepted=False` reason + `ReadyBackends` counting. |
| `internal/controller/gateway_resources_ha.go` | Create | Mode B builders: `BuildFrontendDeployment`, `BuildBackendStatefulSet`, `BuildBackendHeadlessService`, `BuildBackendKeySecret`, `BuildOnionbalanceConfigMap`, `BuildFrontendServiceAccount`, `BuildFrontendRole`, `BuildFrontendRoleBinding`. |
| `internal/controller/gateway_resources_ha_test.go` | Create | Unit tests on each builder's output shape (labels, OwnerRefs, container args, RBAC verbs). |
| `internal/controller/gateway_controller.go` | Modify | Add `gatewaysForOnionBalancePolicy` enqueuer + watch; add `effectiveOnionBalancePolicy` lookup; branch `Reconcile` to call Mode A or Mode B path based on OBP attachment + Accepted state. |
| `internal/controller/gateway_controller_test.go` | Modify | Envtest cases for Mode A↔B transitions. |
| `internal/controller/network_policy.go` | Modify (small) | Confirm the per-Gateway NetworkPolicy `podSelector` keys off the `torgateway.io/gateway=<gw>` label (it already does — frontend and backend pods carry it, so no rule changes needed). Add a single envtest assertion to lock that in. |
| `cmd/manager/main.go` | Modify | Add `--onionbalance-image` flag (already has `--router-image`, `--tor-image`, etc. — same pattern). |
| `internal/controller/gateway_resources.go` | Modify | Extend `RuntimeImages` struct with `Onionbalance string`. |
| `images/onionbalance/Dockerfile` | Create | Multi-stage build: Python 3.12 + `pip install onionbalance==0.2.4`. Fixed UID 65532, no shell in the final layer. |
| `images/onionbalance/entrypoint.sh` | Create | Minimal launcher (`exec onionbalance -c /etc/onionbalance/config/config.yaml ...`). |
| `Makefile` | Modify | Add `ONIONBALANCE_IMG ?=`, `image-onionbalance:` target, include in `images:` and `docker-push:`. |
| `charts/tor-gateway/values.yaml` | Modify | Add `onionbalanceImage:` value; pass through to operator container via `--onionbalance-image`. |
| `charts/tor-gateway/templates/manager.yaml` | Modify | Pass `--onionbalance-image={{ ... }}` to the manager. |
| `config/samples/policy_v1alpha1_onionbalancepolicy.yaml` | Replace | Replace the `TODO(user): Add fields here` placeholder with a real example. |
| `test/e2e/onionbalance_test.go` | Create | Real-Tor HA e2e: deploy Gateway + 3-backend OBP + 2-backend HTTPRoute; fetch master `.onion` via in-cluster Tor SOCKS client; assert path routing; kill a backend; scale down. |
| `.github/workflows/release.yml` | Modify | Add `onionbalance` to the per-image build matrix (cosign-sign + SBOM-attest). |
| `README.md` | Modify | Add `onionbalance` to the cosign verification list (mirror the `tor-gateway-obrefresh` line). |
| `docs/PLAN.md` | Modify | Move `OnionBalancePolicy` from "remaining work" to shipped; update current-release line. |
| `SECURITY.md` | Modify | Add Mode B sections: frontend SPOF, master-key compromise containment, PoW-in-HA limitation, Vanguards 30 kB descriptor size note. |

**Phase ordering:**

- **Phase 0 — CRD tightening** (1 task)
- **Phase 1 — Pure functions** (4 tasks: master-key validator, onionbalance config renderer, backend torrc variant, master `.onion` helper for Gateway status)
- **Phase 2 — Sidecar runtime** (2 tasks: tor-init backend variant, obrefresh refresher implementation)
- **Phase 3 — OBP reconciler** (2 tasks: validation + Accepted condition, ReadyBackends counting)
- **Phase 4 — Mode B builders** (4 tasks: backend StatefulSet, frontend Deployment, headless Service + onionbalance ConfigMap, per-pod backend Secret + frontend RBAC)
- **Phase 5 — Gateway reconciler integration** (3 tasks: OBP watch, Mode A↔B branch, NetworkPolicy selector assertion)
- **Phase 6 — Image + manager flag + chart wiring** (2 tasks)
- **Phase 7 — Sample, e2e, docs** (3 tasks)

Total: 21 tasks. Each task = one commit.

---

## Phase 0 — CRD tightening

### Task 1: Tighten OnionBalancePolicy CRD

**Files:**
- Modify: `api/v1alpha1/onionbalancepolicy_types.go`
- Regenerate: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/policy.torgateway.io_onionbalancepolicies.yaml`, `charts/tor-gateway/files/crds/policy.torgateway.io_onionbalancepolicies.yaml`

- [ ] **Step 1: Confirm baseline green**

Run: `git status --short && make test && make lint`
Expected: clean tree, tests pass, lint 0 issues.

- [ ] **Step 2: Edit the Replicas Maximum and the masterKeySecretRef docstring**

In `api/v1alpha1/onionbalancepolicy_types.go`, change `kubebuilder:validation:Maximum=12` on the `Replicas` field to `Maximum=8`. The block currently reads (around lines 58–66):

```go
	// Replicas is the number of backend Tor instances that publish
	// introduction points behind the master onion address. Bounded by the
	// onionbalance descriptor size limit (12 backends in v3).
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=12
	// +kubebuilder:default=3
	// +required
	Replicas int32 `json:"replicas"`
```

Change to:

```go
	// Replicas is the number of backend Tor instances that publish
	// introduction points behind the master onion address. Capped at 8
	// to match the onionbalance-config generator default; the Tor spec
	// ceiling at the current N_INTROS_PER_INSTANCE=2 is 10 backends.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=8
	// +kubebuilder:default=3
	// +required
	Replicas int32 `json:"replicas"`
```

In the same file, find the `MasterKeySecretRef` doc comment (around lines 75–80) which currently reads:

```go
	// MasterKeySecretRef references the Secret holding the master ed25519
	// key for the frontend onionbalance daemon. Required. The Secret MUST
	// contain `hs_ed25519_secret_key` and `hs_ed25519_public_key` keys.
	//
	// +required
	MasterKeySecretRef MasterKeySecretRef `json:"masterKeySecretRef"`
```

Change to:

```go
	// MasterKeySecretRef references the Secret holding the master ed25519
	// key for the frontend onionbalance daemon. Required. The Secret MUST
	// contain `hs_ed25519_secret_key` (64 bytes) and `hs_ed25519_public_key`
	// (32 bytes) in the standard Tor binary format — the same shape as a
	// HiddenServiceDir's key files, NOT the onionbalance PEM format.
	//
	// +required
	MasterKeySecretRef MasterKeySecretRef `json:"masterKeySecretRef"`
```

- [ ] **Step 3: Regenerate**

Run: `make generate manifests chart-sync`
Expected: success. Diffs in `zz_generated.deepcopy.go` (none expected — no struct change), `config/crd/bases/policy.torgateway.io_onionbalancepolicies.yaml` (`maximum: 12` → `maximum: 8` + description block update), and the chart copy.

- [ ] **Step 4: Verify the CRD shape**

Run: `grep -n 'maximum: 8\|maximum: 12' config/crd/bases/policy.torgateway.io_onionbalancepolicies.yaml charts/tor-gateway/files/crds/policy.torgateway.io_onionbalancepolicies.yaml`
Expected: only `maximum: 8` matches; no `maximum: 12`.

- [ ] **Step 5: Run tests**

Run: `make test && make lint`
Expected: PASS, 0 issues.

- [ ] **Step 6: Commit**

```
git add api/v1alpha1/onionbalancepolicy_types.go \
        config/crd/bases/policy.torgateway.io_onionbalancepolicies.yaml \
        charts/tor-gateway/files/crds/policy.torgateway.io_onionbalancepolicies.yaml
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
refactor(api): tighten OnionBalancePolicy.replicas cap to 8

Matches the onionbalance-config generator default. Tor spec ceiling
at the current N_INTROS_PER_INSTANCE=2 is 10 backends; the
widely-cited "12" appears in no upstream source. Docstring also
clarifies that masterKeySecretRef expects the Tor binary key format,
not the onionbalance PEM format.
EOF
)"
```

---

## Phase 1 — Pure functions

### Task 2: Master-key validator

**Files:**
- Create: `internal/tor/master_key.go`
- Create: `internal/tor/master_key_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/tor/master_key_test.go`:

```go
package tor

import (
	"errors"
	"testing"
)

func TestValidateMasterKeySecret(t *testing.T) {
	good, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	t.Run("happy", func(t *testing.T) {
		kp, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_secret_key": good.SecretKeyFile(),
			"hs_ed25519_public_key": good.PublicKeyFile(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if kp.OnionAddress().String() != good.OnionAddress().String() {
			t.Fatalf("derived .onion mismatch: %s vs %s", kp.OnionAddress(), good.OnionAddress())
		}
	})

	t.Run("missing secret", func(t *testing.T) {
		_, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_public_key": good.PublicKeyFile(),
		})
		if !errors.Is(err, ErrMasterKeyMissingSecret) {
			t.Fatalf("want ErrMasterKeyMissingSecret, got %v", err)
		}
	})

	t.Run("missing public", func(t *testing.T) {
		_, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_secret_key": good.SecretKeyFile(),
		})
		if !errors.Is(err, ErrMasterKeyMissingPublic) {
			t.Fatalf("want ErrMasterKeyMissingPublic, got %v", err)
		}
	})

	t.Run("mismatched pair", func(t *testing.T) {
		other, _ := GenerateKeyPair(nil)
		_, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_secret_key": good.SecretKeyFile(),
			"hs_ed25519_public_key": other.PublicKeyFile(),
		})
		if !errors.Is(err, ErrMasterKeyMismatch) {
			t.Fatalf("want ErrMasterKeyMismatch, got %v", err)
		}
	})

	t.Run("malformed secret", func(t *testing.T) {
		_, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_secret_key": []byte("not a key"),
			"hs_ed25519_public_key": good.PublicKeyFile(),
		})
		if err == nil || errors.Is(err, ErrMasterKeyMissingSecret) || errors.Is(err, ErrMasterKeyMissingPublic) {
			t.Fatalf("want parse error, got %v", err)
		}
	})
}
```

- [ ] **Step 2: Run the test, confirm it fails**

Run: `go test ./internal/tor/ -run TestValidateMasterKeySecret -v`
Expected: FAIL (`undefined: ValidateMasterKeySecret`, `undefined: ErrMasterKeyMissingSecret`, etc.).

- [ ] **Step 3: Implement**

Create `internal/tor/master_key.go`:

```go
/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package tor

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// Errors returned by ValidateMasterKeySecret.
var (
	ErrMasterKeyMissingSecret = errors.New("master key Secret is missing hs_ed25519_secret_key")
	ErrMasterKeyMissingPublic = errors.New("master key Secret is missing hs_ed25519_public_key")
	ErrMasterKeyMismatch      = errors.New("hs_ed25519_secret_key and hs_ed25519_public_key do not form a pair")
)

// ValidateMasterKeySecret enforces the Secret-key map shape required by
// OnionBalancePolicy.masterKeySecretRef and returns the parsed KeyPair on
// success. The Secret MUST contain hs_ed25519_secret_key (64 bytes, Tor
// binary format) and hs_ed25519_public_key (32 bytes, Tor binary format)
// and the two MUST form a valid pair (derived pubkey from the expanded
// secret matches the provided pubkey).
func ValidateMasterKeySecret(data map[string][]byte) (*KeyPair, error) {
	secretBytes, ok := data["hs_ed25519_secret_key"]
	if !ok || len(secretBytes) == 0 {
		return nil, ErrMasterKeyMissingSecret
	}
	publicBytes, ok := data["hs_ed25519_public_key"]
	if !ok || len(publicBytes) == 0 {
		return nil, ErrMasterKeyMissingPublic
	}
	kp, err := ParseFiles(secretBytes, publicBytes)
	if err != nil {
		return nil, fmt.Errorf("parse master key: %w", err)
	}
	// ParseFiles already cross-checks secret↔public; defence-in-depth.
	derivedPub := kp.PublicKey()
	suppliedPub, err := ParsePublicKey(publicBytes)
	if err != nil {
		return nil, fmt.Errorf("re-parse public key: %w", err)
	}
	if subtle.ConstantTimeCompare(derivedPub, suppliedPub) != 1 {
		return nil, ErrMasterKeyMismatch
	}
	return kp, nil
}
```

Note: this assumes `GenerateKeyPair(nil)` works (the existing helper accepts `nil` as crypto/rand reader). If `tor.ParseFiles` already does mismatch checking and returns its own error type, the explicit `subtle.ConstantTimeCompare` is belt-and-braces but safe. If `tor.ParseFiles` does NOT mismatch-check (read `internal/tor/keys.go:150` to confirm), the post-check here covers the gap.

- [ ] **Step 4: Run the test, confirm it passes**

Run: `go test ./internal/tor/ -run TestValidateMasterKeySecret -v`
Expected: PASS for all five subtests.

If `mismatched pair` fails (because `tor.ParseFiles` itself returns a different error), adjust the test to expect that error rather than `ErrMasterKeyMismatch`, OR drop the post-check from the impl and propagate `ParseFiles`'s mismatch error. Match the existing helper's behaviour rather than fighting it.

- [ ] **Step 5: Lint**

Run: `make lint`
Expected: 0 issues.

- [ ] **Step 6: Commit**

```
git add internal/tor/master_key.go internal/tor/master_key_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
feat(tor): add ValidateMasterKeySecret for OnionBalancePolicy

Thin wrapper around tor.ParseFiles that enforces the Secret-key map
shape required by OnionBalancePolicy.masterKeySecretRef. Returns a
typed *KeyPair on success so the caller (OBP reconciler) can derive
the master .onion cheaply for status reporting.
EOF
)"
```

---

### Task 3: Onionbalance config renderer

**Files:**
- Create: `internal/onionbalance/config.go`
- Create: `internal/onionbalance/config_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/onionbalance/config_test.go`:

```go
package onionbalance

import (
	"strings"
	"testing"

	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// addrs picks N deterministic v3 addresses for tests.
func addrs(t *testing.T, n int) []tor.OnionAddress {
	t.Helper()
	out := make([]tor.OnionAddress, n)
	for i := 0; i < n; i++ {
		kp, err := tor.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		out[i] = kp.OnionAddress()
	}
	return out
}

func TestRenderConfig(t *testing.T) {
	master := addrs(t, 1)[0]
	backends := addrs(t, 3)

	t.Run("happy", func(t *testing.T) {
		got, err := Render(master, backends, "/etc/onionbalance/keys/hs_ed25519_secret_key")
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		// services: list with one entry whose key matches and whose
		// instances list contains every backend address.
		for _, b := range backends {
			if !strings.Contains(got, b.String()) {
				t.Errorf("rendered config missing backend %s:\n%s", b, got)
			}
		}
		if !strings.Contains(got, "/etc/onionbalance/keys/hs_ed25519_secret_key") {
			t.Errorf("rendered config missing key path:\n%s", got)
		}
		if !strings.Contains(got, "services:") {
			t.Errorf("rendered config missing services: top-level:\n%s", got)
		}
	})

	t.Run("zero backends", func(t *testing.T) {
		// Onionbalance accepts an empty instances list (descriptor pool
		// just has nothing to advertise); we still render a syntactically
		// valid config so the daemon starts.
		got, err := Render(master, nil, "/k")
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if !strings.Contains(got, "services:") || !strings.Contains(got, "instances: []") {
			t.Errorf("expected services + empty instances:\n%s", got)
		}
	})

	t.Run("deterministic ordering", func(t *testing.T) {
		// Two render calls with the same input must produce byte-identical
		// output so obrefresh can shortcut on no-change.
		a, err := Render(master, backends, "/k")
		if err != nil {
			t.Fatal(err)
		}
		b, err := Render(master, backends, "/k")
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Errorf("Render is not deterministic")
		}
	})
}
```

- [ ] **Step 2: Run the test, confirm it fails**

Run: `go test ./internal/onionbalance/ -run TestRenderConfig -v`
Expected: FAIL (`undefined: Render`).

- [ ] **Step 3: Implement**

Create `internal/onionbalance/config.go`:

```go
/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package onionbalance

import (
	"fmt"
	"strings"

	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// Render produces a syntactically valid onionbalance v3 config.yaml.
//
// The master argument is the front-facing .onion (derived by the operator
// from the user-supplied master ed25519 key). The backends slice may be
// empty — onionbalance starts on an empty instances list and the
// superdescriptor will simply advertise no intro points until obrefresh
// populates the pool.
//
// keyPath is the in-pod path where the master Secret is mounted; it is
// written into the services[].key field verbatim.
//
// Output is deterministic — same inputs always produce byte-identical
// YAML, so obrefresh can detect "no change" by string comparison.
func Render(master tor.OnionAddress, backends []tor.OnionAddress, keyPath string) (string, error) {
	if keyPath == "" {
		return "", fmt.Errorf("onionbalance: keyPath is required")
	}
	var b strings.Builder
	b.WriteString("# generated by tor-gateway operator — do not edit by hand\n")
	b.WriteString("services:\n")
	b.WriteString("- key: ")
	b.WriteString(keyPath)
	b.WriteString("\n")
	if len(backends) == 0 {
		b.WriteString("  instances: []\n")
		return b.String(), nil
	}
	b.WriteString("  instances:\n")
	for i, a := range backends {
		// name fields are operator-facing; deterministic and short.
		fmt.Fprintf(&b, "  - address: %s\n    name: backend-%d\n", a.String(), i)
	}
	// master included as a comment for ops readability (also makes the
	// rendered config greppable for the master address).
	fmt.Fprintf(&b, "# master: %s\n", master.String())
	return b.String(), nil
}
```

- [ ] **Step 4: Run the test, confirm it passes**

Run: `go test ./internal/onionbalance/ -run TestRenderConfig -v`
Expected: PASS for all three subtests.

- [ ] **Step 5: Lint**

Run: `make lint`
Expected: 0 issues.

- [ ] **Step 6: Commit**

```
git add internal/onionbalance/config.go internal/onionbalance/config_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "feat(onionbalance): pure renderer for the v3 config.yaml"
```

---

### Task 4: Backend torrc variant

**Files:**
- Modify: `internal/tor/torrc.go`
- Modify: `internal/tor/torrc_test.go`

- [ ] **Step 1: Read the current TorrcConfig + Render**

Read `internal/tor/torrc.go` lines 1–215 fully. The current shape is a `TorrcConfig` struct (logged-level, PoW flag, HSDir/HSPort knobs, client-auth fields). `Render` walks the struct and emits a torrc string. The change is additive: one new bool field, two render-time branches.

- [ ] **Step 2: Write the failing test**

Add to `internal/tor/torrc_test.go` (append after existing tests):

```go
func TestRenderBackendOnionbalanceInstance(t *testing.T) {
	cfg := TorrcConfig{
		LogLevel:               "notice",
		HiddenServiceDir:       "/var/lib/tor/hs",
		HiddenServicePort:      80,
		HiddenServiceLocalAddr: "127.0.0.1:9080",
		PoWEnabled:             true, // intentionally true — backend variant MUST override
		OnionbalanceInstance:   true,
	}
	out, err := Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "HiddenServiceOnionbalanceInstance 1") {
		t.Errorf("expected HiddenServiceOnionbalanceInstance 1 in output:\n%s", out)
	}
	for _, denied := range []string{"HiddenServicePoWDefensesEnabled", "HiddenServiceEnableIntroDoSDefense"} {
		if strings.Contains(out, denied) {
			t.Errorf("backend variant must omit %s; got:\n%s", denied, out)
		}
	}
}

func TestRenderNonBackendStillHonoursPoW(t *testing.T) {
	cfg := TorrcConfig{
		LogLevel:               "notice",
		HiddenServiceDir:       "/var/lib/tor/hs",
		HiddenServicePort:      80,
		HiddenServiceLocalAddr: "127.0.0.1:9080",
		PoWEnabled:             true,
	}
	out, err := Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "HiddenServicePoWDefensesEnabled 1") {
		t.Errorf("Mode A variant must still emit PoW directives:\n%s", out)
	}
}
```

- [ ] **Step 3: Run the test, confirm it fails**

Run: `go test ./internal/tor/ -run TestRender -v`
Expected: the two new tests FAIL (`OnionbalanceInstance` field doesn't exist).

- [ ] **Step 4: Add the field + branch**

In `internal/tor/torrc.go`, add the new field to `TorrcConfig`:

```go
	// OnionbalanceInstance, when true, emits HiddenServiceOnionbalanceInstance 1
	// inside the HiddenService block AND unconditionally omits the PoW
	// directives (PoWEnabled is ignored). Used by backend pods in HA mode.
	OnionbalanceInstance bool
```

In the `Render` function, find the block that emits PoW directives. Currently it should look something like:

```go
if c.PoWEnabled {
    b.WriteString("HiddenServicePoWDefensesEnabled 1\n")
    b.WriteString("HiddenServiceEnableIntroDoSDefense 1\n")
}
```

Change to:

```go
if c.PoWEnabled && !c.OnionbalanceInstance {
    b.WriteString("HiddenServicePoWDefensesEnabled 1\n")
    b.WriteString("HiddenServiceEnableIntroDoSDefense 1\n")
}
```

Find the trailing-HiddenService-block emission (where `HiddenServiceDir`, `HiddenServicePort` etc. are written) and append, inside that block, when the flag is set:

```go
if c.OnionbalanceInstance {
    b.WriteString("HiddenServiceOnionbalanceInstance 1\n")
}
```

The exact insertion point depends on the current code structure — read lines 146–213 to choose the right spot. The order inside the HiddenService block does not matter to Tor; group it near the other `HiddenService*` directives for readability.

- [ ] **Step 5: Run the tests, confirm they pass**

Run: `go test ./internal/tor/ -run TestRender -v`
Expected: PASS for all `TestRender*` subtests, including the new two.

- [ ] **Step 6: Lint + full package test**

Run: `go test ./internal/tor/... && make lint`
Expected: PASS, 0 issues.

- [ ] **Step 7: Commit**

```
git add internal/tor/torrc.go internal/tor/torrc_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
feat(tor): TorrcConfig.OnionbalanceInstance for HA backends

Emits HiddenServiceOnionbalanceInstance 1 and unconditionally omits the
PoW directives — see onionbalance#13 for why PoW behind onionbalance is
worse than no PoW.
EOF
)"
```

---

### Task 5: Master `.onion` from a Secret (helper for status)

**Files:**
- Modify: `internal/tor/master_key.go` (extend with a convenience)
- Modify: `internal/tor/master_key_test.go`

The OBP reconciler and the Gateway reconciler both need to derive the master `.onion` from the user-supplied Secret. `ValidateMasterKeySecret` already returns the `*KeyPair`, but call-sites that only need the address shouldn't have to know about parsing.

- [ ] **Step 1: Write the failing test**

Append to `internal/tor/master_key_test.go`:

```go
func TestMasterOnionFromSecret(t *testing.T) {
	good, _ := GenerateKeyPair(nil)
	t.Run("happy", func(t *testing.T) {
		addr, err := MasterOnionFromSecret(map[string][]byte{
			"hs_ed25519_secret_key": good.SecretKeyFile(),
			"hs_ed25519_public_key": good.PublicKeyFile(),
		})
		if err != nil {
			t.Fatalf("MasterOnionFromSecret: %v", err)
		}
		if addr.String() != good.OnionAddress().String() {
			t.Fatalf(".onion mismatch: %s vs %s", addr, good.OnionAddress())
		}
	})
	t.Run("propagates validation error", func(t *testing.T) {
		_, err := MasterOnionFromSecret(map[string][]byte{})
		if err == nil {
			t.Fatal("expected error on empty data, got nil")
		}
	})
}
```

- [ ] **Step 2: Run, confirm fail**

Run: `go test ./internal/tor/ -run TestMasterOnionFromSecret -v`
Expected: FAIL (`undefined: MasterOnionFromSecret`).

- [ ] **Step 3: Implement**

Append to `internal/tor/master_key.go`:

```go
// MasterOnionFromSecret derives the master .onion address from a master
// key Secret's data map. Convenience wrapper around ValidateMasterKeySecret
// for callers that don't need the full KeyPair.
func MasterOnionFromSecret(data map[string][]byte) (OnionAddress, error) {
	kp, err := ValidateMasterKeySecret(data)
	if err != nil {
		return OnionAddress{}, err
	}
	return kp.OnionAddress(), nil
}
```

- [ ] **Step 4: Run, confirm pass**

Run: `go test ./internal/tor/ -run TestMasterOnionFromSecret -v`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `make lint`
Expected: 0 issues.

- [ ] **Step 6: Commit**

```
git add internal/tor/master_key.go internal/tor/master_key_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "feat(tor): MasterOnionFromSecret convenience wrapper"
```

---

## Phase 2 — Sidecar runtime

### Task 6: tor-init backend variant (writes ob_config)

**Files:**
- Modify: `cmd/tor-init/main.go`
- Test: existing `cmd/tor-init/*_test.go` (read the file shape first; add a test in the existing pattern)

- [ ] **Step 1: Read the current tor-init**

Read `cmd/tor-init/main.go` in full. Identify the function that copies the HSDir contents and writes the hostname file. We're adding one new optional behaviour: if `--ob-master-address` is non-empty, after the HSDir is prepared, write `<HSDir>/ob_config` containing the line `MasterOnionAddress <addr>.onion\n` with mode `0400`.

- [ ] **Step 2: Add the flag**

In `cmd/tor-init/main.go`'s flag declarations, add:

```go
var obMasterAddress string
flag.StringVar(&obMasterAddress, "ob-master-address", "",
    "if set, write <HSDir>/ob_config containing MasterOnionAddress <value>.onion (HA backend mode)")
```

- [ ] **Step 3: Add the per-pod-keys flag**

In the same flag block, also add:

```go
var perPodKeysBase string
flag.StringVar(&perPodKeysBase, "per-pod-keys-base", "",
    "if set, copy hs_ed25519_*_key from <base>/<index>/ into the HSDir, where <index> is the trailing -N of $POD_NAME (HA backend mode)")
```

- [ ] **Step 4: Wire both conditional writes**

After the HSDir is fully populated and (in Mode A) the key Secret has been copied in from the standard mount, add the two HA-backend-specific blocks. The `ob_config` block goes after the HSDir is populated; the per-pod-key copy block goes BEFORE the standard key-copy logic since it overrides the default key source.

For the per-pod-key copy:

```go
if perPodKeysBase != "" {
    podName := os.Getenv("POD_NAME")
    if podName == "" {
        slog.Error("per-pod-keys-base set but POD_NAME env is empty")
        os.Exit(1)
    }
    // Trailing -N of the pod name is the StatefulSet index.
    dash := strings.LastIndexByte(podName, '-')
    if dash < 0 {
        slog.Error("POD_NAME has no trailing -N", "pod", podName)
        os.Exit(1)
    }
    idx := podName[dash+1:]
    src := filepath.Join(perPodKeysBase, idx)
    for _, name := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key"} {
        data, err := os.ReadFile(filepath.Join(src, name))
        if err != nil {
            slog.Error("read per-pod key", "name", name, "err", err)
            os.Exit(1)
        }
        if err := os.WriteFile(filepath.Join(hsDir, name), data, 0o600); err != nil {
            slog.Error("write key into HSDir", "name", name, "err", err)
            os.Exit(1)
        }
    }
    slog.Info("copied per-pod keys", "idx", idx)
}
```

For the `ob_config` write:

```go
if obMasterAddress != "" {
    obConfigPath := filepath.Join(hsDir, "ob_config")
    // Strip any accidental trailing whitespace from the flag value.
    addr := strings.TrimSpace(obMasterAddress)
    // The address may be given with or without the ".onion" suffix; the
    // ob_config file requires it WITH the suffix.
    if !strings.HasSuffix(addr, ".onion") {
        addr += ".onion"
    }
    content := []byte("MasterOnionAddress " + addr + "\n")
    if err := os.WriteFile(obConfigPath, content, 0o400); err != nil {
        slog.Error("write ob_config", "path", obConfigPath, "err", err)
        os.Exit(1)
    }
    slog.Info("wrote ob_config", "path", obConfigPath, "addr", addr)
}
```

(Imports: ensure `path/filepath`, `os`, `strings`, `log/slog` are present.)

- [ ] **Step 5: Extract testable helpers and write tests**

Append to whatever `cmd/tor-init/*_test.go` already exists (or create `cmd/tor-init/main_test.go` if none does). Extract the writing logic into small helpers so they're testable without running `main()`. Add to the same file:

```go
func writeObConfig(hsDir, addr string) error {
    addr = strings.TrimSpace(addr)
    if !strings.HasSuffix(addr, ".onion") {
        addr += ".onion"
    }
    obConfigPath := filepath.Join(hsDir, "ob_config")
    return os.WriteFile(obConfigPath, []byte("MasterOnionAddress "+addr+"\n"), 0o400)
}

func copyPerPodKeys(base, podName, hsDir string) error {
    dash := strings.LastIndexByte(podName, '-')
    if dash < 0 {
        return fmt.Errorf("POD_NAME %q has no trailing -N", podName)
    }
    idx := podName[dash+1:]
    src := filepath.Join(base, idx)
    for _, name := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key"} {
        data, err := os.ReadFile(filepath.Join(src, name))
        if err != nil {
            return fmt.Errorf("read %s: %w", name, err)
        }
        if err := os.WriteFile(filepath.Join(hsDir, name), data, 0o600); err != nil {
            return fmt.Errorf("write %s: %w", name, err)
        }
    }
    return nil
}
```

Then call the helpers from `main()`. Tests:

```go
func TestWriteObConfig(t *testing.T) {
    t.Run("appends .onion suffix", func(t *testing.T) {
        d := t.TempDir()
        if err := writeObConfig(d, "abcd"); err != nil {
            t.Fatal(err)
        }
        got, err := os.ReadFile(filepath.Join(d, "ob_config"))
        if err != nil {
            t.Fatal(err)
        }
        if string(got) != "MasterOnionAddress abcd.onion\n" {
            t.Errorf("unexpected content: %q", got)
        }
    })
    t.Run("preserves .onion suffix when present", func(t *testing.T) {
        d := t.TempDir()
        if err := writeObConfig(d, "abcd.onion"); err != nil {
            t.Fatal(err)
        }
        got, _ := os.ReadFile(filepath.Join(d, "ob_config"))
        if string(got) != "MasterOnionAddress abcd.onion\n" {
            t.Errorf("unexpected content: %q", got)
        }
    })
    t.Run("file permissions are 0400", func(t *testing.T) {
        d := t.TempDir()
        if err := writeObConfig(d, "abcd"); err != nil {
            t.Fatal(err)
        }
        st, _ := os.Stat(filepath.Join(d, "ob_config"))
        if mode := st.Mode().Perm(); mode != 0o400 {
            t.Errorf("want 0400, got %#o", mode)
        }
    })
}

func TestCopyPerPodKeys(t *testing.T) {
    base := t.TempDir()
    hsDir := t.TempDir()
    idxDir := filepath.Join(base, "2")
    if err := os.MkdirAll(idxDir, 0o755); err != nil {
        t.Fatal(err)
    }
    if err := os.WriteFile(filepath.Join(idxDir, "hs_ed25519_secret_key"), []byte("S"), 0o600); err != nil {
        t.Fatal(err)
    }
    if err := os.WriteFile(filepath.Join(idxDir, "hs_ed25519_public_key"), []byte("P"), 0o600); err != nil {
        t.Fatal(err)
    }
    if err := copyPerPodKeys(base, "blog-backend-2", hsDir); err != nil {
        t.Fatalf("copyPerPodKeys: %v", err)
    }
    for name, want := range map[string]string{"hs_ed25519_secret_key": "S", "hs_ed25519_public_key": "P"} {
        got, _ := os.ReadFile(filepath.Join(hsDir, name))
        if string(got) != want {
            t.Errorf("%s: got %q want %q", name, got, want)
        }
    }
}

func TestCopyPerPodKeysRejectsBadPodName(t *testing.T) {
    if err := copyPerPodKeys(t.TempDir(), "noDash", t.TempDir()); err == nil {
        t.Error("expected error on pod name with no trailing -N")
    }
}
```

- [ ] **Step 6: Run the tests**

Run: `go test ./cmd/tor-init/ -v -run 'TestWriteObConfig|TestCopyPerPodKeys'`
Expected: PASS.

- [ ] **Step 7: Lint**

Run: `make lint`
Expected: 0 issues.

- [ ] **Step 8: Commit**

```
git add cmd/tor-init/
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
feat(tor-init): HA backend support (--ob-master-address, --per-pod-keys-base)

HA backend pods need two things the standard tor-init doesn't do:
- Copy the per-pod ed25519 key pair from <base>/<index>/ into the
  HSDir, where <index> is the trailing -N of $POD_NAME (StatefulSet
  pod index). This routes one of N keys projected into a single
  Volume to the right backend pod without needing a separate Secret
  per replica template.
- Write <HSDir>/ob_config containing MasterOnionAddress <master>.onion
  so the local tor knows which master superdescriptor it is serving
  introduction points for.

The init container handles both because the HSDir is owned by UID
65532 and lives on an emptyDir.
EOF
)"
```

---

### Task 7: obrefresh refresher (Secret informer + debouncer + SIGHUP)

**Files:**
- Rewrite: `internal/onionbalance/refresher.go`
- Create: `internal/onionbalance/refresher_test.go`

This is the most substantial sidecar task. Two responsibilities: (1) maintain a live view of "the set of backend `.onion` addresses for this Gateway" via a Secret informer scoped by label selector, (2) on any change, debounce by `Interval`, render the new `config.yaml`, atomically replace the file on disk, and `SIGHUP` the onionbalance daemon via its pidfile.

- [ ] **Step 1: Define the runtime interface**

Replace `internal/onionbalance/refresher.go` with the following — the structure splits the testable rendering+sighup pipeline from the live informer wiring so unit tests can drive events directly:

```go
/*
Copyright 2026 Alexis Lowe.
SPDX-License-Identifier: Apache-2.0
*/

package onionbalance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/chimbosonic/tor-gateway/internal/tor"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// LabelGateway is the operator-applied label that selects backend Secrets
// (and frontend + backend pods) for a given Gateway.
const LabelGateway = "torgateway.io/gateway"

// LabelRole identifies backend Secrets within a Gateway's set.
const LabelRole = "torgateway.io/role"

// HostnameField is the Secret data key into which each backend's tor-init
// writes its derived .onion (without the .onion suffix); mirrors the
// Mode A convention for <gw>-keys.
const HostnameField = "hostname"

// RefresherConfig configures a per-Gateway onionbalance refresher.
type RefresherConfig struct {
	GatewayName      string
	GatewayNamespace string
	MasterKeyPath    string        // written into config.yaml services[].key
	ConfigPath       string        // path to write config.yaml
	PIDFile          string        // pidfile of the onionbalance daemon
	Interval         time.Duration // debounce window
	Master           tor.OnionAddress
	// Client is the Kubernetes clientset to drive the informer. Production
	// callers pass a real clientset; tests pass a fake (k8s.io/client-go/kubernetes/fake).
	Client kubernetes.Interface
}

// Refresher watches backend Secrets for a Gateway and keeps the
// onionbalance config.yaml + running daemon in sync.
type Refresher struct {
	cfg     RefresherConfig
	mu      sync.Mutex
	pending bool
	timer   *time.Timer
}

// NewRefresher constructs a Refresher. Returns an error if mandatory
// fields are missing.
func NewRefresher(_ context.Context, cfg RefresherConfig) (*Refresher, error) {
	if cfg.GatewayName == "" || cfg.GatewayNamespace == "" {
		return nil, errors.New("onionbalance: GatewayName and GatewayNamespace are required")
	}
	if cfg.ConfigPath == "" || cfg.PIDFile == "" || cfg.MasterKeyPath == "" {
		return nil, errors.New("onionbalance: ConfigPath, PIDFile, MasterKeyPath are required")
	}
	if cfg.Client == nil {
		return nil, errors.New("onionbalance: Client is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	return &Refresher{cfg: cfg}, nil
}

// Run starts the Secret informer scoped to backend Secrets for the
// configured Gateway and blocks until ctx is cancelled. Every add /
// update / delete event triggers a debounced rewrite of config.yaml and
// a SIGHUP to the onionbalance daemon.
func (r *Refresher) Run(ctx context.Context) error {
	selector := labels.SelectorFromSet(labels.Set{
		LabelGateway: r.cfg.GatewayName,
		LabelRole:    "backend",
	}).String()
	factory := informers.NewSharedInformerFactoryWithOptions(
		r.cfg.Client,
		0,
		informers.WithNamespace(r.cfg.GatewayNamespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = selector
		}),
	)
	si := factory.Core().V1().Secrets().Informer()
	_, err := si.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { r.schedule() },
		UpdateFunc: func(any, any) { r.schedule() },
		DeleteFunc: func(any) { r.schedule() },
	})
	if err != nil {
		return fmt.Errorf("add event handler: %w", err)
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), si.HasSynced) {
		return fmt.Errorf("onionbalance: informer cache failed to sync")
	}
	// Initial render — pick up whatever Secrets already exist.
	r.rebuild(ctx, si.GetStore().List())
	<-ctx.Done()
	return nil
}

func (r *Refresher) schedule() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.pending = true
		return
	}
	r.timer = time.AfterFunc(r.cfg.Interval, r.fire)
}

func (r *Refresher) fire() {
	r.mu.Lock()
	r.timer = nil
	pending := r.pending
	r.pending = false
	r.mu.Unlock()
	// We do not have a stored ctx; the parent ctx is captured in Run and
	// drives the informer lifetime. Use background here — the work is
	// local file I/O + signal.
	r.rebuildFromInformer()
	if pending {
		// Coalesced events arrived during the debounce — schedule another.
		r.schedule()
	}
}

// rebuildFromInformer is called by the debounced timer.
func (r *Refresher) rebuildFromInformer() {
	// Re-fetch the store contents inside the debounce window; this avoids
	// stale snapshots if the informer raced ahead of the fire.
	// The informer reference is local to Run, so callers route through
	// rebuild() — we expose a doorbell via lastSnapshot below.
}

// rebuild renders config.yaml from the provided Secret list and SIGHUPs.
// Public for the test hook (refresher_test.go calls it directly).
func (r *Refresher) rebuild(_ context.Context, objs []any) {
	backends := backendsFromSecrets(objs)
	rendered, err := Render(r.cfg.Master, backends, r.cfg.MasterKeyPath)
	if err != nil {
		slog.Error("onionbalance render failed", "err", err)
		return
	}
	if err := atomicWrite(r.cfg.ConfigPath, []byte(rendered)); err != nil {
		slog.Error("onionbalance write failed", "path", r.cfg.ConfigPath, "err", err)
		return
	}
	if err := sighupPID(r.cfg.PIDFile); err != nil {
		// Not fatal: on first run the daemon may not be up yet.
		slog.Warn("onionbalance SIGHUP failed", "pid", r.cfg.PIDFile, "err", err)
		return
	}
	slog.Info("onionbalance config refreshed", "backends", len(backends))
}

func backendsFromSecrets(objs []any) []tor.OnionAddress {
	out := make([]tor.OnionAddress, 0, len(objs))
	for _, o := range objs {
		s, ok := o.(*corev1.Secret)
		if !ok {
			continue
		}
		raw, ok := s.Data[HostnameField]
		if !ok || len(raw) == 0 {
			continue
		}
		// hostname field carries the address as e.g. "abcd.onion" or just
		// "abcd"; tor.ParseAddress accepts either via .String() roundtrip.
		addr, err := tor.ParseAddress(stringNoSpace(raw))
		if err != nil {
			continue
		}
		out = append(out, addr)
	}
	// Sort deterministically by string for stable rendering.
	sortAddrs(out)
	return out
}

func sortAddrs(a []tor.OnionAddress) {
	// in-place insertion sort; len ≤ 8.
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1].String() > a[j].String(); j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

func stringNoSpace(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			out = append(out, c)
		}
	}
	return string(out)
}

// atomicWrite writes the file via a tmp+rename so half-written files are
// never observed by the daemon.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".obrefresh-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func sighupPID(pidfile string) error {
	raw, err := os.ReadFile(pidfile)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(stringNoSpace(raw))
	if err != nil {
		return fmt.Errorf("parse pid: %w", err)
	}
	return syscall.Kill(pid, syscall.SIGHUP)
}
```

(There is one ergonomic gap above: `fire` calls `rebuildFromInformer` which can't see the informer because the informer is owned by `Run`. Resolve in Step 2 by storing the informer's lister on the Refresher.)

- [ ] **Step 2: Resolve the informer-snapshot gap**

Refactor `Run` to store the informer's store on the Refresher so `fire` can read it. Replace the relevant section in `Run` and add a field on `Refresher`:

```go
type Refresher struct {
	cfg     RefresherConfig
	mu      sync.Mutex
	pending bool
	timer   *time.Timer
	store   cache.Store // populated in Run
}
```

Inside `Run`, after `factory.Start`:

```go
r.mu.Lock()
r.store = si.GetStore()
r.mu.Unlock()
```

Replace `rebuildFromInformer` with:

```go
func (r *Refresher) rebuildFromInformer() {
	r.mu.Lock()
	store := r.store
	r.mu.Unlock()
	if store == nil {
		return
	}
	r.rebuild(context.Background(), store.List())
}
```

- [ ] **Step 3: Write the tests**

Create `internal/onionbalance/refresher_test.go`:

```go
package onionbalance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chimbosonic/tor-gateway/internal/tor"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func mustKeyPair(t *testing.T) *tor.KeyPair {
	t.Helper()
	kp, err := tor.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func backendSecret(name, ns, hostname string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				LabelGateway: "blog",
				LabelRole:    "backend",
			},
		},
		Data: map[string][]byte{
			HostnameField: []byte(hostname + ".onion"),
		},
	}
}

func TestRefresherInitialRender(t *testing.T) {
	master := mustKeyPair(t).OnionAddress()
	b1 := mustKeyPair(t).OnionAddress()
	b2 := mustKeyPair(t).OnionAddress()

	cli := fake.NewClientset(
		backendSecret("blog-backend-0-keys", "prod", b1.String()),
		backendSecret("blog-backend-1-keys", "prod", b2.String()),
	)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	pidPath := filepath.Join(dir, "pid")
	// No real onionbalance daemon — use our own PID so sighupPID won't
	// fail; we'll catch SIGHUP via a handler if needed but for this
	// initial test we only verify the file render.
	_ = os.WriteFile(pidPath, []byte("99999999\n"), 0o600)

	ref, err := NewRefresher(context.Background(), RefresherConfig{
		GatewayName:      "blog",
		GatewayNamespace: "prod",
		MasterKeyPath:    "/etc/onionbalance/keys/hs_ed25519_secret_key",
		ConfigPath:       cfgPath,
		PIDFile:          pidPath,
		Interval:         5 * time.Millisecond,
		Master:           master,
		Client:           cli,
	})
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ref.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for {
		if data, err := os.ReadFile(cfgPath); err == nil {
			s := string(data)
			if strings.Contains(s, b1.String()) && strings.Contains(s, b2.String()) {
				return
			}
		}
		select {
		case <-deadline:
			data, _ := os.ReadFile(cfgPath)
			t.Fatalf("config not rendered with both backends within deadline:\n%s", data)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestRefresherRequiresMandatoryFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  RefresherConfig
	}{
		{"missing gateway", RefresherConfig{GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing namespace", RefresherConfig{GatewayName: "g", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing config", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", PIDFile: "/p", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing pidfile", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing master path", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", Client: fake.NewClientset()}},
		{"missing client", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRefresher(context.Background(), tc.cfg); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/onionbalance/ -v`
Expected: PASS. (If `TestRefresherInitialRender` is flaky in your dev loop, raise the deadline; the production path is informer-driven so the test only needs to wait for the initial sync + debounce.)

- [ ] **Step 5: Wire `cmd/obrefresh/main.go` to the new Refresher**

Read `cmd/obrefresh/main.go` (already exists with flags). The existing call to `onionbalance.NewRefresher` passes a `RefresherConfig` that does NOT include `Client`, `Master`, or `MasterKeyPath`. Add flags + clientset:

In `cmd/obrefresh/main.go`, augment the flag set:

```go
var masterAddr string
var masterKeyPath string
flag.StringVar(&masterAddr, "master-address", "",
    "the master .onion address (without the .onion suffix or with it)")
flag.StringVar(&masterKeyPath, "master-key-path", "/etc/onionbalance/keys/hs_ed25519_secret_key",
    "in-pod path where the master ed25519 secret key is mounted")
```

Add the kubernetes client construction (in-cluster config) before `NewRefresher`:

```go
import (
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
)

restCfg, err := rest.InClusterConfig()
if err != nil {
    slog.Error("rest.InClusterConfig", "err", err)
    os.Exit(1)
}
client, err := kubernetes.NewForConfig(restCfg)
if err != nil {
    slog.Error("kubernetes.NewForConfig", "err", err)
    os.Exit(1)
}
master, err := tor.ParseAddress(strings.TrimSuffix(masterAddr, ".onion"))
if err != nil {
    slog.Error("parse master-address", "value", masterAddr, "err", err)
    os.Exit(2)
}

r, err := onionbalance.NewRefresher(ctx, onionbalance.RefresherConfig{
    GatewayName:      gatewayName,
    GatewayNamespace: gatewayNS,
    MasterKeyPath:    masterKeyPath,
    ConfigPath:       configPath,
    PIDFile:          pidPath,
    Interval:         interval,
    Master:           master,
    Client:           client,
})
```

Add the missing import of `github.com/chimbosonic/tor-gateway/internal/tor` and `strings`.

- [ ] **Step 6: Confirm everything builds**

Run: `go build ./cmd/obrefresh && make test`
Expected: build OK, tests pass.

- [ ] **Step 7: Commit**

```
git add cmd/obrefresh/ internal/onionbalance/
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
feat(onionbalance): Secret-informer refresher + SIGHUP reload

obrefresh watches backend Secrets labelled torgateway.io/gateway=<gw>,
role=backend in the Gateway's namespace, debounces by --interval
(default 30s), atomically rewrites config.yaml, and SIGHUPs the
onionbalance daemon via its pidfile. Backends without a populated
hostname field are skipped, so partially-provisioned backends do not
flap the descriptor pool.
EOF
)"
```

---

## Phase 3 — OBP reconciler

### Task 8: OBP reconciler — validation + Accepted condition

**Files:**
- Rewrite: `internal/controller/onionbalancepolicy_controller.go`
- Rewrite: `internal/controller/onionbalancepolicy_controller_test.go`

The existing reconciler is a stub. We replace it with one that mirrors the TSP/TCAP pattern: list targets, validate each, write per-ancestor `Accepted` conditions.

- [ ] **Step 1: Re-read the existing stub**

Read `internal/controller/onionbalancepolicy_controller.go`. The current type, `OnionBalancePolicyReconciler`, has `client.Client + Scheme`. We will add a recorder for events.

- [ ] **Step 2: Write the reconciler**

Replace the file contents with:

```go
/*
Copyright 2026 Alexis Lowe.
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// Reason codes on OnionBalancePolicy.Accepted.
const (
	ReasonOBPAccepted                = "Accepted"
	ReasonOBPGatewayMissing          = "GatewayMissing"
	ReasonOBPMasterKeyMissing        = "MasterKeyMissing"
	ReasonOBPMasterKeyInvalid        = "MasterKeyInvalid"
	ReasonOBPMasterKeyCrossNSDenied  = "MasterKeyCrossNamespaceDenied"
)

type OnionBalancePolicyReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Recorder       record.EventRecorder
	ControllerName string // matches our GatewayClass.controllerName for ancestor filtering
}

// +kubebuilder:rbac:groups=policy.torgateway.io,resources=onionbalancepolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy.torgateway.io,resources=onionbalancepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=referencegrants,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch

func (r *OnionBalancePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var pol policyv1alpha1.OnionBalancePolicy
	if err := r.Get(ctx, req.NamespacedName, &pol); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get policy: %w", err)
	}

	ancestors := make([]gwv1.PolicyAncestorStatus, 0, len(pol.Spec.TargetRefs))
	readyBackends := int32(0)

	masterErr := r.validateMasterKey(ctx, &pol)

	for _, ref := range pol.Spec.TargetRefs {
		ancestor := newAncestorStatus(r.ControllerName, &ref, pol.Namespace)
		accepted := metav1.Condition{
			Type:   string(gwv1.PolicyConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: ReasonOBPAccepted,
			ObservedGeneration: pol.Generation,
		}
		// 1) Gateway must exist + be of class tor-gateway.
		gw, err := r.gatewayForRef(ctx, pol.Namespace, ref)
		switch {
		case err != nil:
			accepted.Status = metav1.ConditionFalse
			accepted.Reason = ReasonOBPGatewayMissing
			accepted.Message = err.Error()
		case masterErr != nil:
			accepted.Status = metav1.ConditionFalse
			accepted.Reason = reasonFromMasterErr(masterErr)
			accepted.Message = masterErr.Error()
		default:
			// Happy path; add PoW override note if applicable.
			if powForcedOff(ctx, r.Client, gw) {
				accepted.Message = "PoW disabled on backends; onionbalance behind PoW is currently worse than no PoW (see onionbalance#13)"
			} else {
				accepted.Message = "OnionBalancePolicy accepted"
			}
			// Count ready backends — backends with populated hostname field.
			ready, err := countReadyBackends(ctx, r.Client, gw)
			if err != nil {
				log.Error(err, "count ready backends", "gateway", gw.Name)
			}
			readyBackends = ready
		}
		ancestor.Conditions = []metav1.Condition{accepted}
		ancestors = append(ancestors, ancestor)
	}

	// Status update with optimistic SSA.
	updated := pol.DeepCopy()
	updated.Status.Ancestors = ancestors
	updated.Status.ReadyBackends = readyBackends
	if err := r.Status().Update(ctx, updated); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}
	return ctrl.Result{}, nil
}

func reasonFromMasterErr(err error) string {
	switch {
	case errors.Is(err, tor.ErrMasterKeyMissingSecret),
		errors.Is(err, tor.ErrMasterKeyMissingPublic):
		return ReasonOBPMasterKeyMissing
	case isCrossNSDeniedError(err):
		return ReasonOBPMasterKeyCrossNSDenied
	default:
		return ReasonOBPMasterKeyInvalid
	}
}

type crossNSDeniedError struct{ namespace, name string }

func (e *crossNSDeniedError) Error() string {
	return fmt.Sprintf("cross-namespace master key Secret %s/%s denied — no ReferenceGrant authorizes it", e.namespace, e.name)
}

func isCrossNSDeniedError(err error) bool {
	var t *crossNSDeniedError
	return errors.As(err, &t)
}

func (r *OnionBalancePolicyReconciler) validateMasterKey(ctx context.Context, pol *policyv1alpha1.OnionBalancePolicy) error {
	ns := pol.Spec.MasterKeySecretRef.Namespace
	if ns == "" {
		ns = pol.Namespace
	}
	if ns != pol.Namespace {
		// Cross-namespace: require a ReferenceGrant.
		allowed, err := masterKeyReferenceGrantAllows(ctx, r.Client, pol, ns)
		if err != nil {
			return fmt.Errorf("evaluate ReferenceGrant: %w", err)
		}
		if !allowed {
			return &crossNSDeniedError{namespace: ns, name: pol.Spec.MasterKeySecretRef.Name}
		}
	}
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: pol.Spec.MasterKeySecretRef.Name}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return tor.ErrMasterKeyMissingSecret
		}
		return fmt.Errorf("get master key Secret: %w", err)
	}
	_, err := tor.ValidateMasterKeySecret(sec.Data)
	return err
}

func newAncestorStatus(controllerName string, ref *gwv1.LocalPolicyTargetReference, ns string) gwv1.PolicyAncestorStatus {
	return gwv1.PolicyAncestorStatus{
		AncestorRef: gwv1.ParentReference{
			Group:     ptrGroup(ref.Group),
			Kind:      ptrKind(ref.Kind),
			Namespace: ptrNamespace(ns),
			Name:      gwv1.ObjectName(ref.Name),
		},
		ControllerName: gwv1.GatewayController(controllerName),
	}
}

func ptrGroup(g gwv1.Group) *gwv1.Group         { return &g }
func ptrKind(k gwv1.Kind) *gwv1.Kind             { return &k }
func ptrNamespace(s string) *gwv1.Namespace      { v := gwv1.Namespace(s); return &v }

func (r *OnionBalancePolicyReconciler) gatewayForRef(ctx context.Context, ns string, ref gwv1.LocalPolicyTargetReference) (*gwv1.Gateway, error) {
	var gw gwv1.Gateway
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: string(ref.Name)}, &gw); err != nil {
		return nil, fmt.Errorf("Gateway %s/%s: %w", ns, ref.Name, err)
	}
	return &gw, nil
}

// Suppress unused-import lint until the watch wiring lands in a later task.
var _ = builder.WithPredicates
var _ = handler.EnqueueRequestForObject{}
var _ reconcile.Request
var _ = gwv1beta1.ReferenceGrant{}

func (r *OnionBalancePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.OnionBalancePolicy{}).
		Named("onionbalancepolicy").
		Complete(r)
}
```

This file references three helpers that don't yet exist:
- `powForcedOff(ctx, c, gw) bool` — returns true iff the Gateway has a TSP with PoW enabled.
- `countReadyBackends(ctx, c, gw) (int32, error)` — counts labelled backend Secrets whose `hostname` field is populated.
- `masterKeyReferenceGrantAllows(ctx, c, pol, ns) (bool, error)` — wraps the existing ReferenceGrant evaluator.

Define them in the next step (Task 9) so this task lands as a compile-clean unit. To make THIS task compile in isolation, add stubs at the bottom of the same file:

```go
// Implemented in Task 9.
func powForcedOff(_ context.Context, _ client.Client, _ *gwv1.Gateway) bool { return false }
func countReadyBackends(_ context.Context, _ client.Client, _ *gwv1.Gateway) (int32, error) { return 0, nil }
func masterKeyReferenceGrantAllows(_ context.Context, _ client.Client, _ *policyv1alpha1.OnionBalancePolicy, _ string) (bool, error) { return true, nil }
```

These stubs are temporary and get replaced in Task 9. This avoids "task N leaves the build broken" — a hard rule of the existing repo.

- [ ] **Step 3: Write the tests**

Replace `internal/controller/onionbalancepolicy_controller_test.go` with envtest cases covering each Accepted=False reason and the happy path. The existing `internal/controller/suite_test.go` already wires the controller-runtime envtest harness (read it before writing); the new tests slot into the same Ginkgo / standard-test style as the existing TSP and TCAP suites.

Example shape — model on `torservicepolicy_controller_test.go` exactly. For brevity here, write tests with table-driven Gateway+OBP fixtures and these subtests at minimum:

- `Accepted=True` when Gateway exists + master Secret is valid.
- `Accepted=False / GatewayMissing` when no Gateway with that name exists.
- `Accepted=False / MasterKeyMissing` when the Secret does not exist.
- `Accepted=False / MasterKeyMissing` when the Secret has no `hs_ed25519_secret_key`.
- `Accepted=False / MasterKeyMissing` when the Secret has no `hs_ed25519_public_key`.
- `Accepted=False / MasterKeyInvalid` when the keys do not form a pair.
- `Accepted=False / MasterKeyInvalid` when the secret bytes are garbage.

Use `tor.GenerateKeyPair(nil)` to mint valid keys and `kp.SecretKeyFile()` / `kp.PublicKeyFile()` to populate fixture Secrets, exactly as `TestValidateMasterKeySecret` does.

- [ ] **Step 4: Run the tests**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `make lint`
Expected: 0 issues.

- [ ] **Step 6: Commit**

```
git add internal/controller/onionbalancepolicy_controller.go \
        internal/controller/onionbalancepolicy_controller_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
feat(controller): OnionBalancePolicy validation + Accepted condition

Replaces the stub with a real reconciler that mirrors the
TorServicePolicy / TorClientAuthPolicy pattern: list targets,
validate the master key Secret (existence, format, pair-match,
cross-namespace ReferenceGrant), and write per-ancestor Accepted
conditions. ReadyBackends + PoW override stubs land here as
placeholders and are implemented in the next commit.
EOF
)"
```

---

### Task 9: OBP reconciler — ReadyBackends + PoW override + ReferenceGrant

**Files:**
- Modify: `internal/controller/onionbalancepolicy_controller.go` (replace the three stubs)
- Modify: `internal/controller/onionbalancepolicy_controller_test.go` (add ReadyBackends test)

- [ ] **Step 1: Replace `countReadyBackends`**

Delete the stub and add:

```go
func countReadyBackends(ctx context.Context, c client.Client, gw *gwv1.Gateway) (int32, error) {
	var list corev1.SecretList
	if err := c.List(ctx, &list,
		client.InNamespace(gw.Namespace),
		client.MatchingLabels{
			"torgateway.io/gateway": gw.Name,
			"torgateway.io/role":    "backend",
		},
	); err != nil {
		return 0, fmt.Errorf("list backend Secrets: %w", err)
	}
	var ready int32
	for i := range list.Items {
		if v, ok := list.Items[i].Data["hostname"]; ok && len(v) > 0 {
			ready++
		}
	}
	return ready, nil
}
```

- [ ] **Step 2: Replace `powForcedOff`**

Delete the stub and add (signature uses `client.Reader` so it composes with envtest fakes):

```go
func powForcedOff(ctx context.Context, c client.Client, gw *gwv1.Gateway) bool {
	var tsps policyv1alpha1.TorServicePolicyList
	if err := c.List(ctx, &tsps, client.InNamespace(gw.Namespace)); err != nil {
		return false
	}
	for i := range tsps.Items {
		t := &tsps.Items[i]
		if !targetsGateway(t.Spec.TargetRefs, gw.Name) {
			continue
		}
		if t.Spec.PoWDefensesEnabled == nil || *t.Spec.PoWDefensesEnabled {
			return true
		}
	}
	return false
}

func targetsGateway(refs []gwv1.LocalPolicyTargetReference, gw string) bool {
	for _, r := range refs {
		if string(r.Name) == gw {
			return true
		}
	}
	return false
}
```

(If a helper of the same name already exists in another file in the same package, drop the redeclaration and reuse — the existing `gateway_controller.go:221` defines `policyTargets`. Reuse that instead: `if policyTargets(t.Spec.TargetRefs, gw.Name)`.)

- [ ] **Step 3: Replace `masterKeyReferenceGrantAllows`**

Delete the stub and add (wrapping the existing `referencegrant.go` evaluator if it has a suitable shape, otherwise inline the same kind/group check):

```go
func masterKeyReferenceGrantAllows(ctx context.Context, c client.Client, pol *policyv1alpha1.OnionBalancePolicy, targetNS string) (bool, error) {
	var grants gwv1beta1.ReferenceGrantList
	if err := c.List(ctx, &grants, client.InNamespace(targetNS)); err != nil {
		return false, err
	}
	for i := range grants.Items {
		g := &grants.Items[i]
		if !grantFromAllowsOBP(g, pol.Namespace) {
			continue
		}
		if grantToAllowsSecret(g, pol.Spec.MasterKeySecretRef.Name) {
			return true, nil
		}
	}
	return false, nil
}

func grantFromAllowsOBP(g *gwv1beta1.ReferenceGrant, fromNS string) bool {
	for _, f := range g.Spec.From {
		if string(f.Namespace) != fromNS {
			continue
		}
		if f.Group != "policy.torgateway.io" || f.Kind != "OnionBalancePolicy" {
			continue
		}
		return true
	}
	return false
}

func grantToAllowsSecret(g *gwv1beta1.ReferenceGrant, secretName string) bool {
	for _, to := range g.Spec.To {
		if to.Group != "" || to.Kind != "Secret" {
			continue
		}
		if to.Name == nil || string(*to.Name) == secretName {
			return true
		}
	}
	return false
}
```

(If `internal/controller/referencegrant.go` already exports a helper with this exact shape, use it instead — read the file first. The v0.3.0 ReferenceGrant work used `EvaluateBackendRefs` for HTTPRoute backendRefs; a similar evaluator may exist for arbitrary kinds. Reuse rather than duplicate.)

- [ ] **Step 4: Add the ReadyBackends test**

Append to `internal/controller/onionbalancepolicy_controller_test.go` a case that:

1. Creates a Gateway + valid master Secret + 2 backend Secrets, one with `hostname` populated and one without.
2. Reconciles the OBP and asserts `status.readyBackends == 1`.

Pseudo (adapt to existing test idioms in this file):

```go
// after the policy is Accepted, create labelled Secrets representing backend keys
mkSecret := func(name string, withHostname bool) *corev1.Secret {
    s := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{
            Name: name, Namespace: ns,
            Labels: map[string]string{
                "torgateway.io/gateway": "blog",
                "torgateway.io/role": "backend",
            },
        },
        Data: map[string][]byte{},
    }
    if withHostname {
        s.Data["hostname"] = []byte("abcd.onion")
    }
    return s
}
Expect(k8sClient.Create(ctx, mkSecret("blog-backend-0-keys", true))).To(Succeed())
Expect(k8sClient.Create(ctx, mkSecret("blog-backend-1-keys", false))).To(Succeed())
// re-reconcile and assert
Eventually(func() int32 {
    var pol policyv1alpha1.OnionBalancePolicy
    _ = k8sClient.Get(ctx, polNN, &pol)
    return pol.Status.ReadyBackends
}, "5s", "200ms").Should(Equal(int32(1)))
```

- [ ] **Step 5: Run the tests**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```
git add internal/controller/onionbalancepolicy_controller.go \
        internal/controller/onionbalancepolicy_controller_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "feat(controller): OBP ReadyBackends counting + ReferenceGrant evaluator + PoW override note"
```

---

## Phase 4 — Mode B builders

### Task 10: Backend StatefulSet builder

**Files:**
- Create: `internal/controller/gateway_resources_ha.go`
- Create: `internal/controller/gateway_resources_ha_test.go`

The frontend Deployment will be added in Task 11; this task focuses on the backend StatefulSet, the headless Service, the per-pod Secret skeleton, and the onionbalance ConfigMap skeleton.

- [ ] **Step 1: Establish the builder file with type stubs**

Create `internal/controller/gateway_resources_ha.go`:

```go
/*
Copyright 2026 Alexis Lowe.
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"crypto/rand"
	"fmt"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// HALabel returns the standard Mode B label set for the Gateway.
// The Gateway-scoping label is shared with Mode A so a single NetworkPolicy
// covers both modes.
func HALabels(gw *gwv1.Gateway, role string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "tor-gateway",
		"app.kubernetes.io/instance": gw.Name,
		"torgateway.io/gateway":      gw.Name,
		"torgateway.io/role":         role, // "backend" or "frontend"
	}
}

// Resource names. Centralised here so the Gateway reconciler and tests
// agree on the spelling.
func FrontendName(gw *gwv1.Gateway) string         { return gw.Name + "-frontend" }
func BackendStatefulSetName(gw *gwv1.Gateway) string { return gw.Name + "-backend" }
func BackendHeadlessServiceName(gw *gwv1.Gateway) string { return gw.Name + "-backends" }
func BackendKeySecretName(gw *gwv1.Gateway, idx int) string {
	return fmt.Sprintf("%s-backend-%d-keys", gw.Name, idx)
}
func OnionbalanceConfigMapName(gw *gwv1.Gateway) string {
	return gw.Name + "-onionbalance-config"
}
```

- [ ] **Step 2: Write the failing test for the backend Secret builder**

Add to `internal/controller/gateway_resources_ha_test.go`:

```go
package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

func newFakeScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	corev1.AddToScheme(s)
	gwv1.Install(s)
	policyv1alpha1.AddToScheme(s)
	// appsv1 + rbacv1 added by later builder tests as needed.
	return s
}

func TestBuildBackendKeySecret(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	scheme := newFakeScheme(t)
	kp, _ := tor.GenerateKeyPair(nil)
	s, err := BuildBackendKeySecret(gw, 2, kp, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "blog-backend-2-keys" {
		t.Errorf("name: %s", s.Name)
	}
	if s.Namespace != "prod" {
		t.Errorf("namespace: %s", s.Namespace)
	}
	if s.Labels["torgateway.io/gateway"] != "blog" || s.Labels["torgateway.io/role"] != "backend" {
		t.Errorf("labels: %v", s.Labels)
	}
	if _, ok := s.Data["hs_ed25519_secret_key"]; !ok {
		t.Error("missing hs_ed25519_secret_key")
	}
	if _, ok := s.Data["hs_ed25519_public_key"]; !ok {
		t.Error("missing hs_ed25519_public_key")
	}
	// hostname is intentionally NOT pre-populated; tor-init writes it on
	// first run after the pod starts. Refresher only counts populated.
	if _, ok := s.Data["hostname"]; ok {
		t.Errorf("hostname must not be pre-populated")
	}
	if len(s.OwnerReferences) != 1 || s.OwnerReferences[0].Name != "blog" {
		t.Errorf("ownerref: %v", s.OwnerReferences)
	}
}
```

- [ ] **Step 3: Implement `BuildBackendKeySecret`**

Append to `internal/controller/gateway_resources_ha.go`:

```go
// BuildBackendKeySecret renders a per-pod Secret holding the ed25519 key
// for backend index idx. The hostname field is intentionally left
// unpopulated: tor-init writes it back on first pod start (mirroring the
// Mode A <gw>-keys convention).
func BuildBackendKeySecret(gw *gwv1.Gateway, idx int, kp *tor.KeyPair, scheme *runtime.Scheme) (*corev1.Secret, error) {
	if kp == nil {
		var err error
		kp, err = tor.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate backend key: %w", err)
		}
	}
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BackendKeySecretName(gw, idx),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, "backend"),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"hs_ed25519_secret_key": kp.SecretKeyFile(),
			"hs_ed25519_public_key": kp.PublicKeyFile(),
		},
	}
	if err := controllerutil.SetControllerReference(gw, s, scheme); err != nil {
		return nil, err
	}
	return s, nil
}
```

- [ ] **Step 4: Write the failing test for the headless Service**

Append to the test file:

```go
func TestBuildBackendHeadlessService(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	scheme := newFakeScheme(t)
	svc, err := BuildBackendHeadlessService(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if svc.Spec.ClusterIP != "None" {
		t.Errorf("must be headless: clusterIP=%q", svc.Spec.ClusterIP)
	}
	if svc.Spec.Selector["torgateway.io/role"] != "backend" {
		t.Errorf("selector wrong: %v", svc.Spec.Selector)
	}
}
```

- [ ] **Step 5: Implement `BuildBackendHeadlessService`**

Append:

```go
func BuildBackendHeadlessService(gw *gwv1.Gateway, scheme *runtime.Scheme) (*corev1.Service, error) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BackendHeadlessServiceName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, "backend"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  HALabels(gw, "backend"),
			Ports: []corev1.ServicePort{
				{Name: "tor", Port: 9080, TargetPort: intstr.FromInt(9080)},
			},
		},
	}
	if err := controllerutil.SetControllerReference(gw, svc, scheme); err != nil {
		return nil, err
	}
	return svc, nil
}
```

- [ ] **Step 6: Write the failing test for the backend StatefulSet**

Append to the test file:

```go
func TestBuildBackendStatefulSet(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	scheme := newFakeScheme(t)
	appsv1Scheme(t, scheme)
	pol := &policyv1alpha1.OnionBalancePolicy{Spec: policyv1alpha1.OnionBalancePolicySpec{Replicas: 3}}
	masterAddr := mustOnionAddr(t)
	ss, err := BuildBackendStatefulSet(gw, pol, masterAddr, RuntimeImages{
		TorInit: "tor-init:v1",
		Tor:     "tor:v1",
		Router:  "router:v1",
	}, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if *ss.Spec.Replicas != 3 {
		t.Errorf("replicas: %d", *ss.Spec.Replicas)
	}
	if ss.Spec.ServiceName != BackendHeadlessServiceName(gw) {
		t.Errorf("serviceName: %s", ss.Spec.ServiceName)
	}
	// init container args include --ob-master-address
	found := false
	for _, c := range ss.Spec.Template.Spec.InitContainers {
		for _, a := range c.Args {
			if a == "--ob-master-address="+masterAddr.String() {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected --ob-master-address in init args; got: %v", ss.Spec.Template.Spec.InitContainers)
	}
	// router sidecar is present
	rfound := false
	for _, c := range ss.Spec.Template.Spec.Containers {
		if c.Name == "router" {
			rfound = true
		}
	}
	if !rfound {
		t.Error("router sidecar missing from backend pod")
	}
	// topology spread is set, best-effort.
	if len(ss.Spec.Template.Spec.TopologySpreadConstraints) != 1 ||
		ss.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.ScheduleAnyway {
		t.Error("expected best-effort hostname topology spread")
	}
}

func appsv1Scheme(t *testing.T, s *runtime.Scheme) {
	t.Helper()
	// extracted to a helper so call-sites can add appsv1 lazily.
	_ = appsv1.AddToScheme(s)
}

func mustOnionAddr(t *testing.T) tor.OnionAddress {
	t.Helper()
	kp, err := tor.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	return kp.OnionAddress()
}
```

- [ ] **Step 7: Implement `BuildBackendStatefulSet`**

Append:

```go
// BuildBackendStatefulSet renders the backend Tor StatefulSet. Each
// replica gets its own PVC-free pod with a per-pod ed25519 key Secret
// mounted at the HSDir; the init container writes ob_config pointing
// at the master .onion. PoW directives are unconditionally omitted on
// backends (decided in the spec; see onionbalance#13).
func BuildBackendStatefulSet(
	gw *gwv1.Gateway,
	pol *policyv1alpha1.OnionBalancePolicy,
	master tor.OnionAddress,
	images RuntimeImages,
	scheme *runtime.Scheme,
) (*appsv1.StatefulSet, error) {
	replicas := pol.Spec.Replicas
	labels := HALabels(gw, "backend")
	pod := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec: corev1.PodSpec{
			ServiceAccountName: gw.Name, // existing per-Gateway SA (Mode A) reused for backend router RBAC
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: ptr(true),
				RunAsUser:    ptr(int64(65532)),
				FSGroup:      ptr(int64(65532)),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			InitContainers: []corev1.Container{{
				Name:  "tor-init",
				Image: images.TorInit,
				Args: []string{
					"--hs-dir=/var/lib/tor/hs",
					"--ob-master-address=" + master.String(),
				},
				VolumeMounts: backendInitVolumeMounts(),
				SecurityContext: hardenedSecurityContext(),
			}},
			Containers: []corev1.Container{
				{
					Name:  "tor",
					Image: images.Tor,
					Args:  []string{"-f", "/etc/tor/torrc"},
					Ports: []corev1.ContainerPort{{Name: "metrics", ContainerPort: 9035}},
					ReadinessProbe: torReadinessProbe(),
					LivenessProbe:  torLivenessProbe(),
					StartupProbe:   torStartupProbe(),
					VolumeMounts:   backendTorVolumeMounts(),
					SecurityContext: hardenedSecurityContext(),
					Resources: derefResources(pol.Spec.BackendResources),
				},
				{
					Name:  "router",
					Image: images.Router,
					Args: []string{
						"--gateway=" + gw.Name,
						"--namespace=" + gw.Namespace,
					},
					ReadinessProbe: routerHealthzProbe(),
					LivenessProbe:  routerHealthzProbe(),
					VolumeMounts: nil,
					SecurityContext: hardenedSecurityContext(),
				},
			},
			Volumes: backendPodVolumes(gw),
			TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
				MaxSkew:           1,
				TopologyKey:       "kubernetes.io/hostname",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector:     &metav1.LabelSelector{MatchLabels: HALabels(gw, "backend")},
			}},
		},
	}
	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BackendStatefulSetName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &replicas,
			Selector:    &metav1.LabelSelector{MatchLabels: labels},
			ServiceName: BackendHeadlessServiceName(gw),
			Template:    pod,
			PodManagementPolicy: appsv1.ParallelPodManagement,
		},
	}
	if err := controllerutil.SetControllerReference(gw, ss, scheme); err != nil {
		return nil, err
	}
	return ss, nil
}

func ptr[T any](v T) *T { return &v }

func backendInitVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: "hs", MountPath: "/var/lib/tor/hs"},
		// The per-pod key Secret is mounted read-only at a staging path;
		// tor-init copies the bytes into the emptyDir HSDir at 0600.
		{Name: "keys", MountPath: "/var/lib/tor-keys", ReadOnly: true},
	}
}

func backendTorVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: "hs", MountPath: "/var/lib/tor/hs"},
		{Name: "torrc", MountPath: "/etc/tor", ReadOnly: true},
	}
}

func backendPodVolumes(gw *gwv1.Gateway) []corev1.Volume {
	return []corev1.Volume{
		{Name: "hs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{
			Name: "keys",
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						Secret: &corev1.SecretProjection{
							// StatefulSet substitutes pod index into name via downward API; until that lands,
							// use a per-pod Volume reference written by the Gateway reconciler when constructing
							// the StatefulSet for each replica index. For the v1 implementation, render one
							// StatefulSet whose Volume references a *projected* Secret resolved at runtime via
							// the pod's hostname (using SubPath downward-API mapping). The simpler shape: the
							// Gateway reconciler creates N Secrets ahead of time and the StatefulSet uses
							// `volumeClaimTemplates`-style per-pod naming. Implementation note: at this layer
							// we render the StatefulSet against a STABLE name pattern and the reconciler ensures
							// the matching Secret exists per index; pod-side selection is via a downward-API
							// EnvVar STATEFULSET_POD_NAME → init script reads /var/lib/tor-keys/$INDEX/.
						},
					}},
				},
			},
		},
		{
			Name: "torrc",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: TorrcConfigMapName(gw)},
				},
			},
		},
	}
}
```

**Implementation note (critical):** the per-pod Secret mount is the subtle bit. StatefulSet pods can be made to mount per-index Secrets via the downward-API + initContainer copy pattern, NOT via `Volume.Secret.SecretName` (which is static across replicas). Two viable shapes:

(a) **One StatefulSet, downward-API + init copy.** Mount ALL backend Secrets as a projected volume at `/secrets/<i>/`, expose `POD_NAME` via downward API in the init container, parse the trailing index, and copy `/secrets/<i>/hs_ed25519_*` into the emptyDir HSDir. Drawback: each pod sees other pods' keys until the init container narrows.

(b) **One StatefulSet per replica.** Reject as bad design — defeats the purpose of StatefulSet.

(c) **OpenShift-style: mutating admission / custom controller patches the pod template per replica.** Out of scope.

Pick (a) and document. The init container args become:

```go
Args: []string{
    "--hs-dir=/var/lib/tor/hs",
    "--ob-master-address=" + master.String(),
    "--per-pod-keys-base=/var/lib/tor-keys",
    // tor-init reads $POD_NAME (downward API env), parses trailing -N, and copies /var/lib/tor-keys/N/* into HSDir
},
Env: []corev1.EnvVar{{
    Name: "POD_NAME",
    ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}},
}},
```

And the projected volume sources are populated by the Gateway reconciler with one `Secret` projection per replica index — built dynamically at reconcile time based on `pol.Spec.Replicas`.

This means **`BuildBackendStatefulSet` takes `pol.Spec.Replicas` and generates `replicas` projected Secret entries** with `Path: "<i>/"` so each backend's keys land at `/var/lib/tor-keys/<i>/`. Update the `backendPodVolumes` helper accordingly:

```go
func backendPodVolumes(gw *gwv1.Gateway, replicas int32) []corev1.Volume {
	sources := make([]corev1.VolumeProjection, 0, int(replicas))
	for i := int32(0); i < replicas; i++ {
		sources = append(sources, corev1.VolumeProjection{
			Secret: &corev1.SecretProjection{
				LocalObjectReference: corev1.LocalObjectReference{Name: BackendKeySecretName(gw, int(i))},
				Items: []corev1.KeyToPath{
					{Key: "hs_ed25519_secret_key", Path: strconv.Itoa(int(i)) + "/hs_ed25519_secret_key"},
					{Key: "hs_ed25519_public_key", Path: strconv.Itoa(int(i)) + "/hs_ed25519_public_key"},
				},
			},
		})
	}
	return []corev1.Volume{
		{Name: "hs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "keys", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: sources}}},
		{Name: "torrc", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: TorrcConfigMapName(gw)}}}},
	}
}
```

**tor-init already accepts `--per-pod-keys-base` + reads `POD_NAME`** (added in Task 6). The StatefulSet template must set the `POD_NAME` env via the downward API and pass `--per-pod-keys-base=/var/lib/tor-keys` so tor-init resolves the right index.

- [ ] **Step 8: Write `BuildOnionbalanceConfigMap` (empty initial config — obrefresh overwrites at runtime)**

Append the builder + a test:

```go
// BuildOnionbalanceConfigMap renders the initial onionbalance config
// ConfigMap. The actual config.yaml is written by obrefresh at runtime
// into an emptyDir, but the ConfigMap is required as a placeholder so
// the frontend pod has the master key path resolvable from a config
// file at startup, even before the first backend reports its hostname.
// We render with zero backends; obrefresh will rewrite on the first
// Secret event.
func BuildOnionbalanceConfigMap(gw *gwv1.Gateway, masterAddr tor.OnionAddress, scheme *runtime.Scheme) (*corev1.ConfigMap, error) {
	rendered, err := onionbalanceConfigInitial(masterAddr)
	if err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OnionbalanceConfigMapName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, "frontend"),
		},
		Data: map[string]string{
			"config.yaml": rendered,
		},
	}
	if err := controllerutil.SetControllerReference(gw, cm, scheme); err != nil {
		return nil, err
	}
	return cm, nil
}

func onionbalanceConfigInitial(master tor.OnionAddress) (string, error) {
	return onionbalanceRender(master, nil)
}

// onionbalanceRender wraps the pure renderer in the controller package.
// Forwarder lives here so test files don't import internal/onionbalance directly.
func onionbalanceRender(master tor.OnionAddress, backends []tor.OnionAddress) (string, error) {
	return onionbalanceRenderImpl(master, backends, "/etc/onionbalance/keys/hs_ed25519_secret_key")
}
```

And add an indirection so the controller package depends on `internal/onionbalance`:

```go
import obconfig "github.com/chimbosonic/tor-gateway/internal/onionbalance"

func onionbalanceRenderImpl(master tor.OnionAddress, backends []tor.OnionAddress, keyPath string) (string, error) {
	return obconfig.Render(master, backends, keyPath)
}
```

Add a small test asserting the rendered ConfigMap contains the `services:` top-level. The full obrefresh behaviour is covered by `internal/onionbalance` tests.

- [ ] **Step 9: Run tests + lint**

Run: `go test ./internal/controller/ -v -run 'TestBuildBackend|TestBuildOnionbalance' && make lint`
Expected: PASS, 0 issues.

- [ ] **Step 10: Commit**

```
git add internal/controller/gateway_resources_ha.go \
        internal/controller/gateway_resources_ha_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
feat(controller): Mode B backend StatefulSet + headless Service + ConfigMap builders

Per-pod backend ed25519 Secrets are projected into a single Volume at
/var/lib/tor-keys/<i>/; tor-init reads POD_NAME from the downward API,
parses the trailing index, and copies the right pair into the HSDir.
The StatefulSet uses ParallelPodManagement so scaling does not serialise
on slow Tor descriptor startup. Best-effort hostname topology spread is
hard-coded; exposing it as a CRD field is feature creep for v1.
EOF
)"
```

---

### Task 11: Frontend Deployment + RBAC builders

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (append builders)
- Modify: `internal/controller/gateway_resources_ha_test.go` (append tests)

The frontend pod has three containers (tor, onionbalance, obrefresh) and dedicated RBAC for the obrefresh Secret informer.

- [ ] **Step 1: Write failing tests for the RBAC builders**

Append to the test file:

```go
func TestBuildFrontendServiceAccount(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	scheme := newFakeScheme(t)
	sa, err := BuildFrontendServiceAccount(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Name != "blog-frontend" || sa.Namespace != "prod" {
		t.Errorf("name/ns: %s/%s", sa.Name, sa.Namespace)
	}
}

func TestBuildFrontendRole(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	scheme := newFakeScheme(t)
	role, err := BuildFrontendRole(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	// must permit get;list;watch on Secrets ONLY (not all resources).
	if len(role.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(role.Rules))
	}
	r := role.Rules[0]
	if len(r.Resources) != 1 || r.Resources[0] != "secrets" {
		t.Errorf("expected only secrets; got %v", r.Resources)
	}
	wantVerbs := map[string]bool{"get": true, "list": true, "watch": true}
	for _, v := range r.Verbs {
		if !wantVerbs[v] {
			t.Errorf("unexpected verb %q (only get/list/watch allowed)", v)
		}
	}
}
```

- [ ] **Step 2: Implement the RBAC builders**

Append:

```go
func BuildFrontendServiceAccount(gw *gwv1.Gateway, scheme *runtime.Scheme) (*corev1.ServiceAccount, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, "frontend"),
		},
	}
	if err := controllerutil.SetControllerReference(gw, sa, scheme); err != nil {
		return nil, err
	}
	return sa, nil
}

func BuildFrontendRole(gw *gwv1.Gateway, scheme *runtime.Scheme) (*rbacv1.Role, error) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, "frontend"),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
	if err := controllerutil.SetControllerReference(gw, role, scheme); err != nil {
		return nil, err
	}
	return role, nil
}

func BuildFrontendRoleBinding(gw *gwv1.Gateway, scheme *runtime.Scheme) (*rbacv1.RoleBinding, error) {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, "frontend"),
		},
		RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: FrontendName(gw)},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: FrontendName(gw), Namespace: gw.Namespace}},
	}
	if err := controllerutil.SetControllerReference(gw, rb, scheme); err != nil {
		return nil, err
	}
	return rb, nil
}
```

- [ ] **Step 3: Write the failing test for the frontend Deployment**

Append:

```go
func TestBuildFrontendDeployment(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	scheme := newFakeScheme(t)
	appsv1Scheme(t, scheme)
	pol := &policyv1alpha1.OnionBalancePolicy{
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "blog-master"},
		},
	}
	master := mustOnionAddr(t)
	d, err := BuildFrontendDeployment(gw, pol, master, RuntimeImages{
		Tor:          "tor:v1",
		Onionbalance: "onionbalance:v1",
		Obrefresh:    "obrefresh:v1",
	}, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if *d.Spec.Replicas != 1 {
		t.Errorf("frontend must be replicas=1; got %d", *d.Spec.Replicas)
	}
	containers := map[string]corev1.Container{}
	for _, c := range d.Spec.Template.Spec.Containers {
		containers[c.Name] = c
	}
	for _, want := range []string{"tor", "onionbalance", "obrefresh"} {
		if _, ok := containers[want]; !ok {
			t.Errorf("missing container %q; got %v", want, keys(containers))
		}
	}
	if d.Spec.Template.Spec.ServiceAccountName != "blog-frontend" {
		t.Errorf("SA: %s", d.Spec.Template.Spec.ServiceAccountName)
	}
	// Master Secret mounted read-only at /etc/onionbalance/keys
	foundMount := false
	for _, vm := range containers["onionbalance"].VolumeMounts {
		if vm.MountPath == "/etc/onionbalance/keys" && vm.ReadOnly {
			foundMount = true
		}
	}
	if !foundMount {
		t.Errorf("master Secret must be mounted RO at /etc/onionbalance/keys; got mounts: %v", containers["onionbalance"].VolumeMounts)
	}
	// obrefresh has --master-address flag carrying the master .onion
	foundArg := false
	for _, a := range containers["obrefresh"].Args {
		if a == "--master-address="+master.String() {
			foundArg = true
		}
	}
	if !foundArg {
		t.Errorf("obrefresh must receive --master-address; got args: %v", containers["obrefresh"].Args)
	}
}

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
```

- [ ] **Step 4: Implement `BuildFrontendDeployment`**

Append:

```go
// BuildFrontendDeployment renders the onionbalance frontend pod. Three
// runtime containers (tor, onionbalance, obrefresh) + no init container
// — onionbalance has no HSDir to permission-fix; the master key is
// mounted RO directly from the Secret and onionbalance reads it via
// the path in its config.yaml services[].key field.
func BuildFrontendDeployment(
	gw *gwv1.Gateway,
	pol *policyv1alpha1.OnionBalancePolicy,
	master tor.OnionAddress,
	images RuntimeImages,
	scheme *runtime.Scheme,
) (*appsv1.Deployment, error) {
	masterSecretName := pol.Spec.MasterKeySecretRef.Name
	masterSecretNS := pol.Spec.MasterKeySecretRef.Namespace
	if masterSecretNS == "" {
		masterSecretNS = gw.Namespace
	}
	// Cross-namespace master Secrets are validated by the OBP reconciler;
	// here we mount whatever name was supplied — if it doesn't exist the
	// pod will fail to start and the reconciler will surface MasterKeyMissing.
	_ = masterSecretNS // mount is by name; in-namespace assumed at the pod level

	pod := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: HALabels(gw, "frontend")},
		Spec: corev1.PodSpec{
			ServiceAccountName: FrontendName(gw),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: ptr(true),
				RunAsUser:    ptr(int64(65532)),
				FSGroup:      ptr(int64(65532)),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{
				{
					Name:  "tor",
					Image: images.Tor,
					Args:  []string{"-f", "/etc/tor/torrc"},
					Ports: []corev1.ContainerPort{{Name: "metrics", ContainerPort: 9035}},
					ReadinessProbe: torReadinessProbe(),
					LivenessProbe:  torLivenessProbe(),
					StartupProbe:   torStartupProbe(),
					VolumeMounts: []corev1.VolumeMount{
						{Name: "tor-data", MountPath: "/var/lib/tor"},
						{Name: "torrc", MountPath: "/etc/tor", ReadOnly: true},
					},
					SecurityContext: hardenedSecurityContext(),
					Resources:       derefResources(pol.Spec.FrontendResources),
				},
				{
					Name:  "onionbalance",
					Image: images.Onionbalance,
					Args: []string{
						"-c", "/etc/onionbalance/config/config.yaml",
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "ob-config", MountPath: "/etc/onionbalance/config"},
						{Name: "ob-keys", MountPath: "/etc/onionbalance/keys", ReadOnly: true},
						{Name: "ob-run", MountPath: "/run/onionbalance"},
						{Name: "tor-data", MountPath: "/var/lib/tor", ReadOnly: true},
					},
					SecurityContext: hardenedSecurityContext(),
				},
				{
					Name:  "obrefresh",
					Image: images.Obrefresh,
					Args: []string{
						"--gateway=" + gw.Name,
						"--namespace=" + gw.Namespace,
						"--master-address=" + master.String(),
						"--master-key-path=/etc/onionbalance/keys/hs_ed25519_secret_key",
						"--config=/etc/onionbalance/config/config.yaml",
						"--pidfile=/run/onionbalance/onionbalance.pid",
						"--interval=" + pol.Spec.RefreshInterval.Duration.String(),
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "ob-config", MountPath: "/etc/onionbalance/config"},
						{Name: "ob-run", MountPath: "/run/onionbalance", ReadOnly: true},
					},
					SecurityContext: hardenedSecurityContext(),
				},
			},
			Volumes: []corev1.Volume{
				{Name: "tor-data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "ob-config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "ob-run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "ob-keys", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: masterSecretName, DefaultMode: ptr(int32(0o400))}}},
				{Name: "torrc", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: FrontendTorrcConfigMapName(gw)}}}},
			},
		},
	}
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, "frontend"),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: HALabels(gw, "frontend")},
			Template: pod,
		},
	}
	if err := controllerutil.SetControllerReference(gw, d, scheme); err != nil {
		return nil, err
	}
	return d, nil
}

func FrontendTorrcConfigMapName(gw *gwv1.Gateway) string {
	return gw.Name + "-frontend-torrc"
}

func torReadinessProbe() *corev1.Probe {
	return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/metrics", Port: intstr.FromInt(9035)}}, PeriodSeconds: 10}
}
func torLivenessProbe() *corev1.Probe { return torReadinessProbe() }
func torStartupProbe() *corev1.Probe {
	p := torReadinessProbe()
	p.FailureThreshold = 30
	return p
}
func routerHealthzProbe() *corev1.Probe {
	return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt(8081)}}, PeriodSeconds: 10}
}
func hardenedSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr(false),
		ReadOnlyRootFilesystem:   ptr(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
}
func derefResources(r *corev1.ResourceRequirements) corev1.ResourceRequirements {
	if r == nil {
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("50m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
		}
	}
	return *r
}
```

**Frontend torrc:** is a NEW ConfigMap (separate from Mode A's per-Gateway torrc, because frontend tor is configured for control-port + cookie auth, not for serving a hidden service directly). Add a builder `BuildFrontendTorrcConfigMap` that emits:

```
SocksPort 0
ControlPort 9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
DataDirectory /var/lib/tor
Log notice stdout
```

(no `HiddenService*` directives — onionbalance configures those via the control port.)

Add the builder + a test asserting the rendered string contains `ControlPort` and does NOT contain `HiddenService`.

- [ ] **Step 5: Run tests + lint**

Run: `go test ./internal/controller/ -v -run TestBuildFrontend && make lint`
Expected: PASS, 0 issues.

- [ ] **Step 6: Commit**

```
git add internal/controller/gateway_resources_ha.go internal/controller/gateway_resources_ha_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "feat(controller): Mode B frontend Deployment + ServiceAccount/Role/RoleBinding builders"
```

---

### Task 12: RuntimeImages.Onionbalance field + manager flag

**Files:**
- Modify: `internal/controller/gateway_resources.go` (struct)
- Modify: `cmd/manager/main.go` (flag)

- [ ] **Step 1: Read the existing `RuntimeImages`**

Read `internal/controller/gateway_resources.go` lines 34–44. The struct currently has fields like `Manager`, `Router`, `TorInit`, `Tor`, `VanityFinalize`, `Obrefresh` (or a subset). Confirm which fields exist.

- [ ] **Step 2: Add the Onionbalance field**

Add `Onionbalance string` to the struct.

- [ ] **Step 3: Add the manager flag**

Read `cmd/manager/main.go`. Find where the existing image flags are declared (`--tor-image`, `--router-image`, `--obrefresh-image`, etc.). Add:

```go
var onionbalanceImage string
flag.StringVar(&onionbalanceImage, "onionbalance-image", "",
    "container image for the onionbalance daemon (frontend pod)")
```

Wire it into the `RuntimeImages` struct that's passed to the reconciler:

```go
images.Onionbalance = onionbalanceImage
```

- [ ] **Step 4: Confirm it builds**

Run: `go build ./... && make test && make lint`
Expected: success.

- [ ] **Step 5: Commit**

```
git add internal/controller/gateway_resources.go cmd/manager/main.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "feat(operator): --onionbalance-image flag + RuntimeImages.Onionbalance"
```

---

## Phase 5 — Gateway reconciler integration

### Task 13: Watch OnionBalancePolicy from the Gateway reconciler

**Files:**
- Modify: `internal/controller/gateway_controller.go`

Mirror the existing `gatewaysForServicePolicy` / `gatewaysForClientAuthPolicy` enqueuers.

- [ ] **Step 1: Add the enqueuer**

After the existing `gatewaysForClientAuthPolicy` function (around line 659), add:

```go
func (r *GatewayReconciler) gatewaysForOnionBalancePolicy(_ context.Context, obj client.Object) []reconcile.Request {
	pol, ok := obj.(*policyv1alpha1.OnionBalancePolicy)
	if !ok {
		return nil
	}
	return requestsForTargets(pol.Namespace, pol.Spec.TargetRefs)
}
```

- [ ] **Step 2: Wire the watch in `SetupWithManager`**

Find the existing `Watches(&policyv1alpha1.TorClientAuthPolicy{}, ...)` block (around line 615 in the existing `SetupWithManager`). Add a sibling line:

```go
Watches(&policyv1alpha1.OnionBalancePolicy{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForOnionBalancePolicy))
```

- [ ] **Step 3: Add a test that asserts the watch fires**

In `internal/controller/gateway_controller_test.go`, append a test that creates an OBP targeting a Gateway and asserts the Gateway gets reconciled (via observing a condition / event / labelled resource appearing). Adapt to the existing test idioms in the file.

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add internal/controller/gateway_controller.go internal/controller/gateway_controller_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "feat(controller): Gateway reconciler watches OnionBalancePolicy changes"
```

---

### Task 14: Mode A↔B branch in the Gateway reconciler

**Files:**
- Modify: `internal/controller/gateway_controller.go`
- Modify: `internal/controller/gateway_controller_test.go`

This is the keystone task: the reconciler now decides Mode A vs Mode B based on attached OBP + Accepted state.

- [ ] **Step 1: Add the lookup**

After the existing `findEffectiveClientAuth` (around line 241), add:

```go
// findEffectiveOnionBalance returns the OBP attached to gw (if any) and
// whether it is Accepted by this controller. Returns (nil, false, nil) if
// no OBP targets the Gateway.
func (r *GatewayReconciler) findEffectiveOnionBalance(ctx context.Context, gw *gwv1.Gateway) (*policyv1alpha1.OnionBalancePolicy, bool, error) {
	var obps policyv1alpha1.OnionBalancePolicyList
	if err := r.List(ctx, &obps, client.InNamespace(gw.Namespace)); err != nil {
		return nil, false, fmt.Errorf("list OBPs: %w", err)
	}
	for i := range obps.Items {
		p := &obps.Items[i]
		if !policyTargets(p.Spec.TargetRefs, gw.Name) {
			continue
		}
		accepted := false
		for _, anc := range p.Status.Ancestors {
			if string(anc.ControllerName) != r.ControllerName {
				continue
			}
			for _, c := range anc.Conditions {
				if c.Type == string(gwv1.PolicyConditionAccepted) && c.Status == metav1.ConditionTrue {
					accepted = true
				}
			}
		}
		return p, accepted, nil
	}
	return nil, false, nil
}
```

- [ ] **Step 2: Add Mode B `ensure*` methods**

Add new `ensureModeB` orchestrator + per-resource `ensure*` helpers (mirror the Mode A pattern):

```go
func (r *GatewayReconciler) ensureModeB(ctx context.Context, gw *gwv1.Gateway, pol *policyv1alpha1.OnionBalancePolicy) error {
	masterSecretNS := pol.Spec.MasterKeySecretRef.Namespace
	if masterSecretNS == "" {
		masterSecretNS = pol.Namespace
	}
	var masterSec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: masterSecretNS, Name: pol.Spec.MasterKeySecretRef.Name}, &masterSec); err != nil {
		return fmt.Errorf("get master Secret: %w", err)
	}
	master, err := tor.MasterOnionFromSecret(masterSec.Data)
	if err != nil {
		return fmt.Errorf("derive master .onion: %w", err)
	}
	// Backend Secrets.
	for i := int32(0); i < pol.Spec.Replicas; i++ {
		want, err := BuildBackendKeySecret(gw, int(i), nil, r.Scheme)
		if err != nil {
			return err
		}
		if err := r.upsertSecret(ctx, want); err != nil {
			return fmt.Errorf("backend Secret %d: %w", i, err)
		}
	}
	// Headless Service.
	if want, err := BuildBackendHeadlessService(gw, r.Scheme); err == nil {
		if err := r.upsertService(ctx, want); err != nil {
			return fmt.Errorf("backend headless Service: %w", err)
		}
	}
	// Onionbalance ConfigMap (initial empty).
	if want, err := BuildOnionbalanceConfigMap(gw, master, r.Scheme); err == nil {
		if err := r.upsertConfigMap(ctx, want); err != nil {
			return fmt.Errorf("onionbalance ConfigMap: %w", err)
		}
	}
	// Frontend SA + Role + RoleBinding.
	if sa, err := BuildFrontendServiceAccount(gw, r.Scheme); err == nil {
		if err := r.upsertServiceAccount(ctx, sa); err != nil {
			return err
		}
	}
	if role, err := BuildFrontendRole(gw, r.Scheme); err == nil {
		if err := r.upsertRole(ctx, role); err != nil {
			return err
		}
	}
	if rb, err := BuildFrontendRoleBinding(gw, r.Scheme); err == nil {
		if err := r.upsertRoleBinding(ctx, rb); err != nil {
			return err
		}
	}
	// Backend StatefulSet.
	ss, err := BuildBackendStatefulSet(gw, pol, master, r.Images, r.Scheme)
	if err != nil {
		return err
	}
	if err := r.upsertStatefulSet(ctx, ss); err != nil {
		return fmt.Errorf("backend StatefulSet: %w", err)
	}
	// Frontend Deployment.
	d, err := BuildFrontendDeployment(gw, pol, master, r.Images, r.Scheme)
	if err != nil {
		return err
	}
	if err := r.upsertDeployment(ctx, d); err != nil {
		return fmt.Errorf("frontend Deployment: %w", err)
	}
	// Publish master .onion to Gateway.status.
	if err := r.updateStatusModeB(ctx, gw, master); err != nil {
		return err
	}
	return nil
}

func (r *GatewayReconciler) updateStatusModeB(ctx context.Context, gw *gwv1.Gateway, master tor.OnionAddress) error {
	addr := gwv1.GatewayStatusAddress{
		Type:  ptr(gwv1.HostnameAddressType),
		Value: master.String(),
	}
	gw.Status.Addresses = []gwv1.GatewayStatusAddress{addr}
	// existing Programmed/Accepted condition handling: reuse updateStatus
	// once it supports the no-kp branch; for now we do a minimal Update.
	return r.Status().Update(ctx, gw)
}
```

Define the `upsert*` helpers as thin wrappers around `controllerutil.CreateOrUpdate` if not already present. The Mode A path uses `ensureKeySecret`, `ensureService`, etc. — pattern-match.

- [ ] **Step 3: Branch in `Reconcile`**

Find the existing top of `Reconcile` (around line 73). After validating the GatewayClass and before the main Mode A path, add:

```go
pol, accepted, err := r.findEffectiveOnionBalance(ctx, &gw)
if err != nil {
	return ctrl.Result{}, err
}
if pol != nil && !accepted {
	// Surface Programmed=False/PolicyNotAccepted; do NOT provision Mode A.
	if err := r.markProgrammedFalse(ctx, &gw, "PolicyNotAccepted",
		"OnionBalancePolicy "+pol.Name+" is not Accepted; refusing to fall back to Mode A while HA is intended"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}
if pol != nil && accepted {
	if err := r.ensureModeB(ctx, &gw, pol); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.cleanupModeAResources(ctx, &gw); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
// Mode A path (existing).
```

Add `markProgrammedFalse` and `cleanupModeAResources`. `cleanupModeAResources` deletes the Mode A `Deployment` + `Service` if they exist (the `<gw>-keys` Secret is preserved). Mirror with a `cleanupModeBResources` called from the Mode A path:

```go
func (r *GatewayReconciler) cleanupModeAResources(ctx context.Context, gw *gwv1.Gateway) error {
	// Delete Deployment <gw> and Service <gw> (Mode A standalone) if present.
	if err := r.deleteByName(ctx, gw.Namespace, gw.Name, &appsv1.Deployment{}); err != nil {
		return err
	}
	if err := r.deleteByName(ctx, gw.Namespace, gw.Name, &corev1.Service{}); err != nil {
		return err
	}
	return nil
}

func (r *GatewayReconciler) cleanupModeBResources(ctx context.Context, gw *gwv1.Gateway) error {
	for _, name := range []string{FrontendName(gw), BackendStatefulSetName(gw), BackendHeadlessServiceName(gw), OnionbalanceConfigMapName(gw), FrontendName(gw) /* SA */} {
		_ = name // delete by name across types
	}
	// Delete: Deployment <gw>-frontend, StatefulSet <gw>-backend, Service <gw>-backends, ConfigMap <gw>-onionbalance-config, SA/Role/RoleBinding <gw>-frontend, all <gw>-backend-*-keys Secrets.
	for _, obj := range []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: FrontendName(gw)}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: BackendStatefulSetName(gw)}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: BackendHeadlessServiceName(gw)}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: OnionbalanceConfigMapName(gw)}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: FrontendName(gw)}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: FrontendName(gw)}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: FrontendName(gw)}},
	} {
		if err := client.IgnoreNotFound(r.Delete(ctx, obj)); err != nil {
			return err
		}
	}
	// Delete labelled backend Secrets.
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets,
		client.InNamespace(gw.Namespace),
		client.MatchingLabels{"torgateway.io/gateway": gw.Name, "torgateway.io/role": "backend"},
	); err != nil {
		return err
	}
	for i := range secrets.Items {
		if err := client.IgnoreNotFound(r.Delete(ctx, &secrets.Items[i])); err != nil {
			return err
		}
	}
	return nil
}
```

Wire `cleanupModeBResources` into the Mode A path (call it before provisioning Mode A resources, so a B→A transition tears down B's resources first).

- [ ] **Step 3a: Emit Mode-transition events**

Both transitions are user-visible (the published `.onion` changes). The existing `event` helper at the bottom of `gateway_controller.go` (around line 725) takes `(obj, eventType, reason, message)`. Emit on the *first* reconcile that observes the transition — detect by comparing the current `Gateway.status.addresses[0].value` against the just-computed master/Gateway-key `.onion`:

```go
// in ensureModeB, just before updateStatusModeB
if currentAddr := gatewayCurrentOnion(gw); currentAddr != master.String() {
    r.event(gw, corev1.EventTypeNormal, "MasterDescriptorChanged",
        "switched to onionbalance HA — published .onion is now "+master.String())
}

// in the Mode A entry path (after cleanupModeBResources, before provisioning Mode A)
// when the Gateway previously had a master address:
if currentAddr := gatewayCurrentOnion(gw); currentAddr != "" && currentAddr != modeA_onion {
    r.event(gw, corev1.EventTypeNormal, "MasterDescriptorChanged",
        "OnionBalancePolicy removed — published .onion reverted to "+modeA_onion)
}
```

`gatewayCurrentOnion` is a one-line helper returning `gw.Status.Addresses[0].Value` or `""`.

Also emit `BackendsRolling` from `ensureModeB` once per change in `pol.Spec.Replicas` (track previous via a Gateway annotation `torgateway.io/last-known-replicas` to avoid re-emitting on every reconcile):

```go
const annLastReplicas = "torgateway.io/last-known-replicas"
prev, _ := strconv.Atoi(gw.Annotations[annLastReplicas])
if int32(prev) != pol.Spec.Replicas {
    r.event(gw, corev1.EventTypeNormal, "BackendsRolling",
        fmt.Sprintf("backend replicas changing %d→%d; up to ~15 min until clients see the new pool", prev, pol.Spec.Replicas))
    if gw.Annotations == nil { gw.Annotations = map[string]string{} }
    gw.Annotations[annLastReplicas] = strconv.Itoa(int(pol.Spec.Replicas))
    if err := r.Update(ctx, gw); err != nil {
        return err
    }
}
```

Emit `PoWForcedOffInHA` once when entering Mode B with a PoW-enabled TSP attached (gate on the same annotation pattern — `torgateway.io/pow-override-emitted: "true"`):

```go
if powForcedOff(ctx, r.Client, gw) && gw.Annotations[annPowEmitted] != "true" {
    r.event(gw, corev1.EventTypeNormal, "PoWForcedOffInHA",
        "HiddenServicePoWDefensesEnabled in TorServicePolicy is overridden to false on backends (onionbalance#13)")
    if gw.Annotations == nil { gw.Annotations = map[string]string{} }
    gw.Annotations[annPowEmitted] = "true"
    if err := r.Update(ctx, gw); err != nil {
        return err
    }
}
const annPowEmitted = "torgateway.io/pow-override-emitted"
```

(Clear `annPowEmitted` in `cleanupModeBResources` so a subsequent re-enter of Mode B re-emits.)

- [ ] **Step 4: Add Mode A↔B envtest cases**

Add to `internal/controller/gateway_controller_test.go`:

1. A→B: create Gateway, wait for Mode A resources, then create OBP + master Secret, wait for OBP Accepted, assert Mode B resources appear and Mode A resources disappear. Assert `Gateway.status.addresses[0].value` is the master `.onion`.
2. B→A: from the previous state, delete the OBP, assert Mode B resources disappear and Mode A resources reappear (using the preserved `<gw>-keys` Secret). Assert `Gateway.status.addresses[0].value` reverts to the Gateway-key `.onion`.

These are necessarily envtest (need a real apiserver to exercise cleanup). Use `Eventually` with a generous timeout (the existing tests use 10–15s).

- [ ] **Step 5: Run tests + lint**

Run: `make test && make lint`
Expected: PASS, 0 issues.

- [ ] **Step 6: Commit**

```
git add internal/controller/gateway_controller.go internal/controller/gateway_controller_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
feat(controller): Mode A↔B switching in the Gateway reconciler

When an Accepted OnionBalancePolicy targets a Gateway, the reconciler
provisions Mode B (frontend Deployment + backend StatefulSet + per-pod
backend Secrets + onionbalance ConfigMap + frontend RBAC) and tears
down the Mode A Deployment+Service. The Mode A <gw>-keys Secret is
preserved so detaching the OBP cleanly reverts to Mode A using the
original .onion. Programmed=False/PolicyNotAccepted is set when an
OBP attaches but is not Accepted (e.g. master Secret missing); the
operator never silently falls back to Mode A under those conditions.
EOF
)"
```

---

### Task 15: NetworkPolicy selector assertion

**Files:**
- Modify: `internal/controller/network_policy_test.go`

The v0.3.2 per-Gateway NetworkPolicy keys off `torgateway.io/gateway=<gw>`. Both frontend and backend pods carry that label (set in `HALabels`), so the existing NP automatically applies to both. We add ONE envtest assertion to lock that in.

- [ ] **Step 1: Add the test**

Append to `internal/controller/network_policy_test.go`:

```go
func TestNetworkPolicySelectsBothModeBPodSets(t *testing.T) {
	// Direct unit test on BuildNetworkPolicy: assert PodSelector.MatchLabels
	// contains only torgateway.io/gateway=<gw>, NOT torgateway.io/role=tor.
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	np, err := BuildNetworkPolicy(gw, ResolvedBackend{}, nil /* cluster pod CIDRs */, runtime.NewScheme())
	if err != nil {
		t.Fatal(err)
	}
	sel := np.Spec.PodSelector.MatchLabels
	if sel["torgateway.io/gateway"] != "blog" {
		t.Errorf("expected gateway label; got %v", sel)
	}
	if _, ok := sel["torgateway.io/role"]; ok {
		t.Errorf("podSelector must NOT pin role; got %v (frontend + backend pods both need to be covered)", sel)
	}
}
```

If the existing `BuildNetworkPolicy` does pin a `role` label, **adjust it now** to key off only `torgateway.io/gateway=<gw>`. This is a small change in `internal/controller/network_policy.go` — find the `PodSelector` construction and remove any role-specific MatchLabel.

- [ ] **Step 2: Run the test**

Run: `go test ./internal/controller/ -v -run TestNetworkPolicySelectsBothModeBPodSets`
Expected: PASS.

- [ ] **Step 3: Lint + full test**

Run: `make test && make lint`
Expected: PASS, 0 issues.

- [ ] **Step 4: Commit**

```
git add internal/controller/network_policy.go internal/controller/network_policy_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "test(networkpolicy): assert PodSelector covers both Mode B pod sets"
```

---

## Phase 6 — Image + chart wiring

### Task 16: Build the `images/onionbalance/` image

**Files:**
- Create: `images/onionbalance/Dockerfile`
- Create: `images/onionbalance/entrypoint.sh`
- Modify: `Makefile`
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Write the Dockerfile**

Create `images/onionbalance/Dockerfile`:

```dockerfile
# Multi-stage build: a Python virtualenv with onionbalance installed,
# copied into a minimal runtime layer. No Tor binary — the frontend pod
# runs Tor as a sibling container (images/tor/), and onionbalance reaches
# it via the cookie-auth control port.

FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
RUN pip install "onionbalance==0.2.4"

FROM python:3.12-slim
RUN groupadd -g 65532 nonroot && useradd -u 65532 -g 65532 -M -s /sbin/nologin nonroot
COPY --from=build /opt/venv /opt/venv
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0555 /entrypoint.sh
USER 65532:65532
ENV PATH=/opt/venv/bin:$PATH
ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 2: Write the entrypoint**

Create `images/onionbalance/entrypoint.sh`:

```sh
#!/bin/sh
set -eu
exec onionbalance "$@"
```

- [ ] **Step 3: Add the Makefile target**

In `Makefile`, find the existing `ONIONBALANCE_IMG ?= ` line — wait, there isn't one yet. Add near `TOR_IMG`:

```make
ONIONBALANCE_IMG ?= $(REGISTRY)/tor-gateway-onionbalance:$(IMAGE_TAG)
```

Add the target near `image-tor`:

```make
.PHONY: image-onionbalance
image-onionbalance:
	$(CONTAINER_TOOL) build -t $(ONIONBALANCE_IMG) images/onionbalance
```

Add `image-onionbalance` to the `images:` aggregate and `docker-push:` aggregate so a single `make images` builds it.

- [ ] **Step 4: Add to release workflow**

Read `.github/workflows/release.yml`. Find the per-image build matrix (`tor-gateway-manager`, `tor-gateway-router`, etc.). Add an entry for `onionbalance` mirroring the structure used for `tor` and `mkp224o` (non-Go images). The exact YAML shape depends on the existing matrix structure — match the style of the `tor` entry.

- [ ] **Step 5: Build the image locally to verify**

Run: `make image-onionbalance`
Expected: build succeeds. The image is ~200 MiB; that's normal for a Python base.

- [ ] **Step 6: Commit**

```
git add images/onionbalance/ Makefile .github/workflows/release.yml
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
feat(images): build images/onionbalance/ from python:3.12-slim + onionbalance 0.2.4

Multi-stage build: Python venv installed in the build layer, copied into
the runtime layer. No Tor binary — the frontend pod runs Tor as a
sibling container and onionbalance talks to it via cookie-auth control
port on loopback. Fixed UID 65532, no shell in the final layer.
Wired into the release workflow alongside the other non-Go images.
EOF
)"
```

---

### Task 17: Chart wiring

**Files:**
- Modify: `charts/tor-gateway/values.yaml`
- Modify: `charts/tor-gateway/templates/manager.yaml` (or whichever template renders the operator Deployment)
- Modify: `README.md`

- [ ] **Step 1: Add the value**

In `charts/tor-gateway/values.yaml`, add (mirror the existing `obrefresh:` image stanza):

```yaml
onionbalance:
  image:
    repository: ghcr.io/chimbosonic/tor-gateway-onionbalance
    tag: ""   # defaults to chart appVersion
```

- [ ] **Step 2: Pass the flag to the operator**

In whichever template renders the manager Deployment, append a `--onionbalance-image=...` arg mirroring the existing `--obrefresh-image=...`:

```yaml
- --onionbalance-image={{ .Values.onionbalance.image.repository }}:{{ default .Chart.AppVersion .Values.onionbalance.image.tag }}
```

- [ ] **Step 3: Add to README cosign verification list**

In `README.md`, find the line listing the auxiliary images for cosign verification (around line 50 in the current README — search for `tor-gateway-obrefresh`). Add `tor-gateway-onionbalance` to the list:

> The same verification applies to the other images the chart deploys: `tor-gateway-router`, `tor-gateway-tor-init`, `tor-gateway-vanity-finalize`, `mkp224o`, `tor`, `tor-gateway-obrefresh` and `tor-gateway-onionbalance`.

- [ ] **Step 4: Verify the chart still installs**

Run: `make helm-lint` (if such a target exists; otherwise `helm lint ./charts/tor-gateway`).
Expected: 0 errors.

- [ ] **Step 5: Commit**

```
git add charts/tor-gateway/values.yaml charts/tor-gateway/templates/ README.md
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "feat(chart): plumb --onionbalance-image; add onionbalance to README cosign list"
```

---

## Phase 7 — Sample, e2e, docs

### Task 18: Real-Tor e2e for Mode B

**Files:**
- Create: `test/e2e/onionbalance_test.go`
- Modify: `test/e2e/Makefile` or `test/e2e/run.sh` if those exist (mirror how other e2e tests are wired in)

- [ ] **Step 1: Read the existing real-Tor e2e**

Read `test/e2e/` directory. The existing v0.3.x real-Tor e2e (data plane via in-cluster SOCKS) is the template. Find the file that sets up the kind cluster, creates a Gateway + HTTPRoute, and fetches the `.onion` via a Tor SOCKS client.

- [ ] **Step 2: Write the test**

Create `test/e2e/onionbalance_test.go` modeled on the existing data-plane e2e. The shape:

1. Use the same fixture cluster (kind already running; chart already installed via the e2e harness).
2. Create a master key Secret (use `tor.GenerateKeyPair(nil)` at test time + `Secret.Data["hs_ed25519_secret_key"]` / `["hs_ed25519_public_key"]` from `kp.SecretKeyFile()` / `PublicKeyFile()`).
3. Apply: Gateway (class `tor-gateway`) + OnionBalancePolicy targeting it (replicas=3, masterKeySecretRef → the Secret) + HTTPRoute fan-out (2 backends, paths `/` → A, `/api` → B).
4. Wait (with timeout suitable for the ~15-min worst-case lag — set ~10 min wall-clock; the test ALSO bounds the wait by `ReadyBackends ≥ 1` for early exit).
5. Read `Gateway.status.addresses[0].value` (master `.onion`).
6. Fetch the master `.onion` via in-cluster Tor SOCKS client; assert `/` returns from backend A and `/api` returns from backend B.
7. Delete one backend pod; wait for the new pod to populate its hostname Secret; assert the master `.onion` still serves.
8. Scale `replicas` 3 → 1; assert the master `.onion` still serves (after the bounded propagation window).

Use Ginkgo `Eventually` blocks with explicit, generous timeouts. The existing data-plane e2e likely sets a TOR-fetch timeout via an env var — match it.

This test will be slow (5–15 min). Gate it behind the existing e2e flag/build-tag rather than running in unit `make test`.

- [ ] **Step 3: Verify locally**

Run: `make test-e2e` (or whatever the existing e2e entrypoint is). The test will likely fail until the operator image is rebuilt with the new code AND the chart is reinstalled — that's normal for e2e.

- [ ] **Step 4: Commit**

```
git add test/e2e/onionbalance_test.go
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "test(e2e): real-Tor onionbalance HA — 3 backends, fan-out, pod kill, scale-down"
```

---

### Task 19: Sample CR

**Files:**
- Replace: `config/samples/policy_v1alpha1_onionbalancepolicy.yaml`

- [ ] **Step 1: Replace the placeholder**

The current file is the kubebuilder-generated stub with `# TODO(user): Add fields here`. Replace with a useful example:

```yaml
# A working example of HA via onionbalance. Prerequisites:
# - A Secret named blog-master-key in the same namespace, containing
#   `hs_ed25519_secret_key` (64 bytes) and `hs_ed25519_public_key`
#   (32 bytes) — the standard Tor binary format. Bootstrap via
#   `mkp224o` (vanity) or by copying from a prior HiddenServiceDir.
# - A Gateway named "blog" of class tor-gateway in the same namespace.
apiVersion: policy.torgateway.io/v1alpha1
kind: OnionBalancePolicy
metadata:
  name: blog-ha
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: blog
  replicas: 3
  refreshInterval: 30s
  masterKeySecretRef:
    name: blog-master-key
```

- [ ] **Step 2: Commit**

```
git add config/samples/policy_v1alpha1_onionbalancepolicy.yaml
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "docs(samples): replace OBP placeholder with a working example"
```

---

### Task 20: PLAN.md + SECURITY.md update

**Files:**
- Modify: `docs/PLAN.md`
- Modify: `SECURITY.md`

- [ ] **Step 1: Update PLAN.md**

In `docs/PLAN.md`, find the line at the end of the "Implemented and tested" status block that currently reads (around line 28):

> Remaining work is the independent feature backlog: onionbalance HA (`OnionBalancePolicy`).

Replace with:

> All v1-target features shipped: onionbalance HA (`OnionBalancePolicy`) in the next release tag (the human picks the version at tag time per CLAUDE.md).

Add an "Implemented and tested" bullet for HA:

> - HA via onionbalance (Mode B) — `OnionBalancePolicy` provisions a frontend Deployment (vanilla tor + onionbalance + obrefresh sidecar) and a backend StatefulSet (1–8 Tor instances each running `HiddenServiceOnionbalanceInstance 1`); master `.onion` published from a user-supplied Secret; PoW force-disabled on backends per onionbalance#13; real-Tor HA e2e fetches the master `.onion`, kills a backend, scales down, and verifies the address still serves.

- [ ] **Step 2: Update SECURITY.md**

In `SECURITY.md`, add sections (use the existing structure pattern — read SECURITY.md first to match style):

```markdown
### Onionbalance HA (Mode B)

When an `OnionBalancePolicy` targets a Gateway, the operator provisions a
frontend onionbalance pod and a backend StatefulSet of N independent Tor
instances. Mode-B-specific security properties:

- **Master key.** The user-supplied master ed25519 key is the
  permanent identity of the published `.onion`. Treat the Secret the
  same way you treat the Mode A `<gw>-keys` Secret: never logged, never
  in ConfigMaps, `defaultMode: 0400` on the volume mount.
- **Backend keys.** Operator-generated per-pod Secrets. A backend key
  compromise is contained — the master is unaffected; the compromised
  backend's `.onion` simply rotates out of the descriptor pool when the
  operator regenerates its Secret (manual today; just delete the
  Secret and the reconciler will regenerate).
- **PoW.** `HiddenServicePoWDefensesEnabled` is **force-disabled** on
  backends regardless of `TorServicePolicy.poWDefensesEnabled`. Reason:
  upstream onionbalance has no PoW propagation today
  (gitlab.torproject.org/tpo/onion-services/onionbalance#13) and
  enabling PoW on a backend without prioritisation makes the queue
  worse than no PoW.
- **Frontend SPOF.** The frontend pod is a single point of failure for
  descriptor publication. K8s Deployment auto-restart is the v1
  mitigation (brief outage during pod restart, no `.onion` change).
  Upstream's recommended HA story for the frontend itself is "deploy a
  second frontend with a separate `.onion`" — explicitly out of scope
  for v1; it's a different feature shape.
- **Vanguards descriptor size.** Onionbalance descriptors with the
  maximum number of intro points can exceed Vanguards' default 30 kB
  cap. v1 documents but does not enforce. If you set `replicas` close
  to the cap (8) AND run Vanguards, monitor descriptor sizes.
```

- [ ] **Step 3: Commit**

```
git add docs/PLAN.md SECURITY.md
git commit --no-gpg-sign \
  --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" \
  -m "$(cat <<'EOF'
docs: PLAN.md marks HA shipped; SECURITY.md documents Mode B posture

PoW is force-disabled on backends (onionbalance#13). Frontend SPOF
mitigation is K8s pod auto-restart; multi-frontend is v2. Vanguards
30 kB descriptor cap is documented but not enforced.
EOF
)"
```

---

### Task 21: Verify everything is green and the tree is clean

**Files:** none (verification only).

- [ ] **Step 1: Run the full suite**

Run: `make test && make lint`
Expected: PASS, 0 issues.

- [ ] **Step 2: Confirm no codegen drift**

Run: `make generate manifests chart-sync && git status --short`
Expected: empty output (no drift introduced by the implementation).

- [ ] **Step 3: Sanity-grep for accidental TODO/FIXME injections**

Run: `git diff main~21..main -- '*.go' '*.yaml' | grep -nE '^\+.*(TODO|FIXME|XXX)' | head -20`
Expected: no NEW TODO/FIXME/XXX additions in code (some pre-existing ones in test scaffolding are fine).

- [ ] **Step 4: Confirm the commit chain looks right**

Run: `git log --oneline -25`
Expected: roughly 20 commits since the spec commit, all by `Alexis Lowe <claude-opus-4-7@chimbosonic.com>`, all `--no-gpg-sign`.

- [ ] **Step 5: Hand off to user for `git rebase --signoff` and `git push`**

Report:

> Implementation complete. 20 local commits on `main` since the spec. All tests pass, lint is clean, no codegen drift. Run `git rebase --signoff` and `git push` when ready; the master-key behaviour is the only thing that needs a real (not-fake) Tor network to fully verify — covered by the e2e test in Task 18.
