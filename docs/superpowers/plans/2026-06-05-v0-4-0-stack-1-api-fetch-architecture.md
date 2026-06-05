# v0.4.0 — Stack 1: API-fetch architecture for Secrets

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace pod-level Secret mounts (Projected for backends, SecretVolumeSource for master) with init-container API fetches, so each backend pod sees only its own onion key and the cross-NS `MasterKeySecretRef` works end-to-end.

**Architecture:** `cmd/tor-init` gains a `--api-fetch-secret=<namespace>/<name>` flag that pulls a Secret via the in-cluster API and writes its `hs_ed25519_*_key` + `hostname` bytes to the destination. Backend StatefulSet pods invoke it with their own ordinal; the frontend Deployment gains a `master-fetch` init container for the OBP's master Secret. RBAC tightens via `resourceNames`-scoped `get`; `list/watch` stays namespace-wide but the informer filters by `owner-uid`. Cross-NS support is provided by an operator-emitted RoleBinding in the source namespace.

**Tech Stack:** Go, controller-runtime, client-go in-cluster config, kubebuilder, Ginkgo+Gomega tests.

**Tickets covered:** B4, H3 (partial), H4 (partial), M4, M5, plus L7 doc fix on `BuildBackendKeySecret`.

**Predecessor:** spec `docs/superpowers/specs/2026-06-05-v0-4-0-release-fixes-design.md`.

**Branching:** create a feature branch `feat/v0.4.0-stack-1-api-fetch` off `main`. All commits land there; merge to `main` via PR before Stack 2 and Stack 3 begin.

---

### Task 1: `tor-init` gains `--api-fetch-secret` flag (happy path)

**Files:**
- Modify: `cmd/tor-init/main.go`
- Test: `cmd/tor-init/main_test.go`
- (Reference only) `go.mod` already lists `k8s.io/client-go` via the controller-runtime dependency; no go.mod change needed.

- [ ] **Step 1: Write the failing test**

Append to `cmd/tor-init/main_test.go`:

```go
import (
    "context"
    "os"
    "path/filepath"
    "testing"

    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes/fake"
)

func TestApiFetchSecret_WritesKeyFilesAndHostname(t *testing.T) {
    dst := t.TempDir()
    secret := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{Name: "blog-backend-2-keys", Namespace: "default"},
        Data: map[string][]byte{
            "hs_ed25519_secret_key": []byte("SECRET-KEY-BYTES"),
            "hs_ed25519_public_key": []byte("PUBLIC-KEY-BYTES"),
            "hostname":              []byte("aaaaaaaaaaaaaaaaaaaaaaaa.onion\n"),
        },
    }
    cs := fake.NewSimpleClientset(secret)
    if err := fetchSecretToDir(context.Background(), cs, "default", "blog-backend-2-keys", dst); err != nil {
        t.Fatalf("fetchSecretToDir: %v", err)
    }
    for _, name := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key", "hostname"} {
        b, err := os.ReadFile(filepath.Join(dst, name))
        if err != nil {
            t.Fatalf("read %s: %v", name, err)
        }
        if len(b) == 0 {
            t.Fatalf("%s empty", name)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/tor-init/ -run TestApiFetchSecret_WritesKeyFilesAndHostname -v`
Expected: FAIL with `undefined: fetchSecretToDir`.

- [ ] **Step 3: Implement `fetchSecretToDir`**

Add to `cmd/tor-init/main.go` (above `main()`):

```go
import (
    "context"
    // ...existing imports...
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

// fetchSecretToDir GETs the named Secret and writes each of its data
// entries as a file under dst, preserving the entry names verbatim.
func fetchSecretToDir(ctx context.Context, cs kubernetes.Interface, namespace, name, dst string) error {
    s, err := cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
    if err != nil {
        return fmt.Errorf("get secret %s/%s: %w", namespace, name, err)
    }
    if err := os.MkdirAll(dst, tor.HiddenServiceDirMode); err != nil {
        return err
    }
    for k, v := range s.Data {
        if err := os.WriteFile(filepath.Join(dst, k), v, 0o600); err != nil {
            return fmt.Errorf("write %s: %w", k, err)
        }
    }
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/tor-init/ -run TestApiFetchSecret_WritesKeyFilesAndHostname -v`
Expected: PASS.

- [ ] **Step 5: Wire the flag into `main()` and `run()`**

In `cmd/tor-init/main.go`, add the flag and threading:

```go
// add to var block at top of main():
var apiFetchSecret string

// add to flag.StringVar block:
flag.StringVar(&apiFetchSecret, "api-fetch-secret", "",
    "if set (NAMESPACE/NAME), fetch the named Secret via the in-cluster API and "+
        "write its data entries into <dst>")
```

Change the `run` signature and call:

```go
if err := run(context.Background(), src, dst, clientAuthSrc, perPodKeysBase, obMasterAddress, apiFetchSecret); err != nil {
```

In `run`, after `os.MkdirAll(dst, ...)`:

```go
if apiFetchSecret != "" {
    parts := strings.SplitN(apiFetchSecret, "/", 2)
    if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
        return fmt.Errorf("--api-fetch-secret expects NAMESPACE/NAME, got %q", apiFetchSecret)
    }
    cfg, err := rest.InClusterConfig()
    if err != nil {
        return fmt.Errorf("in-cluster config: %w", err)
    }
    cs, err := kubernetes.NewForConfig(cfg)
    if err != nil {
        return fmt.Errorf("kubernetes client: %w", err)
    }
    if err := fetchSecretToDir(ctx, cs, parts[0], parts[1], dst); err != nil {
        return fmt.Errorf("api-fetch: %w", err)
    }
    slog.Info("tor-init: api-fetched secret", "ref", apiFetchSecret)
}
```

Add `"k8s.io/client-go/rest"` to imports.

- [ ] **Step 6: Run the full test file**

Run: `go test ./cmd/tor-init/ -v`
Expected: PASS (existing tests + new test).

- [ ] **Step 7: Commit**

```bash
git checkout -b feat/v0.4.0-stack-1-api-fetch
git add cmd/tor-init/main.go cmd/tor-init/main_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(tor-init): --api-fetch-secret flag for in-cluster Secret fetch"
```

---

### Task 2: `tor-init` `--api-fetch-secret` error paths

**Files:**
- Modify: `cmd/tor-init/main.go`
- Test: `cmd/tor-init/main_test.go`

- [ ] **Step 1: Write failing tests for malformed flag and missing Secret**

Append to `cmd/tor-init/main_test.go`:

```go
import (
    apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func TestApiFetchSecret_BadFlagFormat(t *testing.T) {
    dst := t.TempDir()
    cs := fake.NewSimpleClientset()
    err := fetchSecretToDir(context.Background(), cs, "", "name", dst)
    if err == nil {
        t.Fatal("expected error for empty namespace")
    }
}

func TestApiFetchSecret_NotFound(t *testing.T) {
    dst := t.TempDir()
    cs := fake.NewSimpleClientset() // no Secrets
    err := fetchSecretToDir(context.Background(), cs, "default", "missing", dst)
    if err == nil {
        t.Fatal("expected not-found error")
    }
    if !apierrors.IsNotFound(err) && !strings.Contains(err.Error(), "not found") {
        t.Fatalf("expected not-found, got: %v", err)
    }
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./cmd/tor-init/ -run 'TestApiFetchSecret_BadFlagFormat|TestApiFetchSecret_NotFound' -v`
Expected: PASS for `_NotFound` (already works because `Get` returns IsNotFound). FAIL for `_BadFlagFormat` because `fetchSecretToDir` doesn't validate empty namespace. (The flag-level validation lives in `run`; the helper accepts whatever it's given.)

- [ ] **Step 3: Add explicit empty-namespace/name guard in `fetchSecretToDir`**

Prepend to the helper body:

```go
if namespace == "" || name == "" {
    return fmt.Errorf("namespace and name must be non-empty, got %q/%q", namespace, name)
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./cmd/tor-init/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/tor-init/main.go cmd/tor-init/main_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "test(tor-init): error paths for --api-fetch-secret"
```

---

### Task 3: Remove the now-superseded `--per-pod-keys-base` flag

**Files:**
- Modify: `cmd/tor-init/main.go`
- Test: `cmd/tor-init/main_test.go` (delete the old per-pod-keys tests if any)
- Modify: `internal/controller/gateway_resources_ha.go` — backend StatefulSet builder no longer emits `--per-pod-keys-base` (this will be re-done in Task 5; the cleanest sequence is to remove the flag here so it's an explicit error if anyone forgets to update a caller).

- [ ] **Step 1: Find callers and tests of `--per-pod-keys-base`**

Run: `grep -rn 'per-pod-keys-base\|perPodKeysBase\|copyPerPodKeys' --include='*.go' .`
Expected: matches in `cmd/tor-init/main.go`, possibly tests, and in `internal/controller/gateway_resources_ha.go` (backend init container args).

- [ ] **Step 2: Write a failing test asserting the flag is gone**

Append to `cmd/tor-init/main_test.go`:

```go
func TestRunRejectsPerPodKeysBase(t *testing.T) {
    // Sanity: the function signature should no longer accept perPodKeysBase.
    // This test will fail to compile if Task 3 hasn't been applied — that's
    // the intended TDD signal. (After completion, this test is a marker.)
    _ = runV2Signature
}

// Marker so the test fails to compile until run() is renamed/reshaped.
var runV2Signature = func(ctx context.Context, src, dst, clientAuthSrc, obMasterAddress, apiFetchSecret string) error {
    return nil
}
```

- [ ] **Step 3: Run to verify compile failure**

Run: `go build ./cmd/tor-init/...`
Expected: build fails because `run` still takes `perPodKeysBase`.

- [ ] **Step 4: Update `run()` signature and remove the per-pod-keys block**

In `cmd/tor-init/main.go`:

- Remove the `perPodKeysBase string` var declaration.
- Remove `flag.StringVar(&perPodKeysBase, ...)`.
- Change `run` signature to `func run(ctx context.Context, src, dst, clientAuthSrc, obMasterAddress, apiFetchSecret string) error`.
- Remove the `if perPodKeysBase != "" { ... }` block from `run`.
- Delete the `copyPerPodKeys` function entirely.
- Update the call in `main()` to match the new signature.

- [ ] **Step 5: Delete or update any tests that referenced `--per-pod-keys-base`**

Grep results from Step 1 listed any tests; delete them. The marker test from Step 2 stays as documentation; remove it after compilation succeeds (it has no assertion value beyond signaling the signature change).

Actually, just delete the marker test too:

```bash
# Remove the marker test you added in Step 2.
```

- [ ] **Step 6: Update the backend builder so the project still compiles**

In `internal/controller/gateway_resources_ha.go`, find `BuildBackendStatefulSet` and remove any `--per-pod-keys-base=...` arg from the init container args list. Replace with a placeholder comment for Task 5 to fill in:

```go
// TASK-5: replace with --api-fetch-secret=$(POD_NAMESPACE)/<gw>-backend-<idx>-keys
Args: []string{
    "--dst=" + hsServiceDir,
    "--src=",
    "--ob-master-address=" + master.String(),
},
```

This intentionally leaves Mode B backend pods unable to load their keys until Task 5; the unit tests for backend StatefulSet assertions will fail. Task 5 restores correctness.

- [ ] **Step 7: Run unit tests for the controller package**

Run: `go test ./internal/controller/ -count=1`
Expected: failures in `gateway_resources_ha_test.go` for backend init container args (we just removed them); other tests pass.

Mark these failures as expected; Task 5 will fix them.

- [ ] **Step 8: Commit**

```bash
git add cmd/tor-init/main.go cmd/tor-init/main_test.go internal/controller/gateway_resources_ha.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "refactor(tor-init): drop --per-pod-keys-base in favor of --api-fetch-secret"
```

---

### Task 4: `BuildBackendKeySecret` adds `owner-uid` label and corrects doc

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (BuildBackendKeySecret at line ~65)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Write failing test**

Append to `gateway_resources_ha_test.go`:

```go
func TestBuildBackendKeySecret_OwnerUIDLabel(t *testing.T) {
    gw := &gwv1.Gateway{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "blog",
            Namespace: "default",
            UID:       "abc-123",
        },
    }
    s, err := BuildBackendKeySecret(gw, 0, nil, scheme())
    if err != nil {
        t.Fatalf("build: %v", err)
    }
    if got := s.Labels["torgateway.io/owner-uid"]; got != "abc-123" {
        t.Errorf("owner-uid = %q, want abc-123", got)
    }
}
```

(If `scheme()` is not yet a helper in the file, use `runtime.NewScheme()` after registering corev1.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/controller/ -run TestBuildBackendKeySecret_OwnerUIDLabel -v`
Expected: FAIL — `owner-uid = ""` because the label is not set.

- [ ] **Step 3: Add `owner-uid` to `HALabels` consumers (not HALabels itself)**

In `BuildBackendKeySecret`, after `Labels: HALabels(gw, haRoleBackend),` change to:

```go
Labels: ownerLabels(gw, haRoleBackend),
```

Add a helper right above `BuildBackendKeySecret`:

```go
// ownerLabels extends HALabels with torgateway.io/owner-uid, which the
// obrefresh informer requires to skip tenant-planted Secrets that happen to
// match the gateway/role labels (H9 + Stack-1 defense in depth).
func ownerLabels(gw *gwv1.Gateway, role string) map[string]string {
    l := HALabels(gw, role)
    l["torgateway.io/owner-uid"] = string(gw.UID)
    return l
}
```

- [ ] **Step 4: Update the doc comment to match reality (L7)**

Replace the comment block above `BuildBackendKeySecret` (lines ~65-68) with:

```go
// BuildBackendKeySecret renders a per-pod Secret holding the ed25519 key
// for backend index idx. data["hostname"] is pre-populated from the key
// pair so obrefresh's readiness gate (which checks the field is non-empty)
// fires immediately and so the renderer never depends on a tor-init
// write-back. The owner-uid label lets the obrefresh informer filter out
// tenant-planted Secrets carrying the same gateway/role labels.
```

Also adjust the matching docstring in `internal/onionbalance/refresher.go` near `HostnameField` (around line 39-43) so it no longer claims to "mirror the Mode A convention" if newline is missing — that's an L5 ticket in Stack 2 and out of scope here. Leave the docstring alone for now.

- [ ] **Step 5: Run test to verify pass**

Run: `go test ./internal/controller/ -run TestBuildBackendKeySecret_OwnerUIDLabel -v`
Expected: PASS.

- [ ] **Step 6: Run all controller tests**

Run: `go test ./internal/controller/ -count=1`
Expected: most pass; backend StatefulSet tests still fail from Task 3 (expected, Task 5 will fix).

- [ ] **Step 7: Commit**

```bash
git add internal/controller/gateway_resources_ha.go internal/controller/gateway_resources_ha_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(controller): backend Secrets carry owner-uid label + corrected doc"
```

---

### Task 5: Backend StatefulSet uses API-fetch init container

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildBackendStatefulSet`, `backendPodVolumes`, `backendInitVolumeMounts`)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Write failing test for removed projected volume**

Append to `gateway_resources_ha_test.go`:

```go
func TestBuildBackendStatefulSet_NoProjectedKeysVolume(t *testing.T) {
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    ss, err := BuildBackendStatefulSet(gw, obp, tor.OnionAddress{}, RuntimeImages{Tor: "tor:x", TorInit: "init:x"}, DefaultPolicy(), EffectiveClientAuth{}, "", scheme())
    if err != nil {
        t.Fatalf("build: %v", err)
    }
    for _, v := range ss.Spec.Template.Spec.Volumes {
        if v.Name == "keys" {
            t.Fatalf("backend pod still has projected 'keys' volume — should be API-fetched")
        }
    }
}

func TestBuildBackendStatefulSet_InitContainerUsesApiFetch(t *testing.T) {
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    ss, err := BuildBackendStatefulSet(gw, obp, tor.OnionAddress{}, RuntimeImages{Tor: "tor:x", TorInit: "init:x"}, DefaultPolicy(), EffectiveClientAuth{}, "", scheme())
    if err != nil {
        t.Fatalf("build: %v", err)
    }
    init := ss.Spec.Template.Spec.InitContainers[0]
    var sawApiFetch bool
    for _, a := range init.Args {
        if strings.HasPrefix(a, "--api-fetch-secret=") {
            sawApiFetch = true
            // ordinal substitution lives inside tor-init via POD_NAME; the manifest just names the prefix
            if !strings.Contains(a, "blog-backend-") {
                t.Errorf("--api-fetch-secret missing backend name prefix: %s", a)
            }
        }
    }
    if !sawApiFetch {
        t.Fatal("init container has no --api-fetch-secret arg")
    }
    // POD_NAME must be downward-API'd
    var sawPodName bool
    for _, e := range init.Env {
        if e.Name == "POD_NAME" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "metadata.name" {
            sawPodName = true
        }
    }
    if !sawPodName {
        t.Error("init container missing POD_NAME downward-API env var")
    }
}
```

Helpers `testGateway`, `testOBP`, `scheme()` are likely already in the test file; if not, add minimal ones.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/controller/ -run 'TestBuildBackendStatefulSet_NoProjectedKeysVolume|TestBuildBackendStatefulSet_InitContainerUsesApiFetch' -v`
Expected: FAIL — projected volume present and `--api-fetch-secret` arg missing.

- [ ] **Step 3: Update `backendPodVolumes`**

Find `backendPodVolumes` (~lines 275-296) and remove the entire Projected `keys` volume block. Keep `hs`, `tor-data`, `torrc`.

```go
func backendPodVolumes(_ *gwv1.Gateway, _ int32) []corev1.Volume {
    return []corev1.Volume{
        {Name: "hs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
        {Name: dataVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
        {Name: "torrc", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: BackendTorrcConfigMapName(gw)}}}},
    }
}
```

Update the function signature: the `replicas` and per-pod-key parameters are no longer used. (Tests for the function need to be updated if they passed those args.)

- [ ] **Step 4: Update `backendInitVolumeMounts`**

Remove the `keys` mount entry. Result:

```go
func backendInitVolumeMounts() []corev1.VolumeMount {
    return []corev1.VolumeMount{
        {Name: "hs", MountPath: hsDirMountPath},
    }
}
```

- [ ] **Step 5: Update the backend init container args + env**

In `BuildBackendStatefulSet`, replace the init container `Args` and add `Env`:

```go
podName := "$(POD_NAME)" // tor-init reads POD_NAME at runtime
// note: kubelet doesn't substitute $(POD_NAME) inside Args, so the
// substitution happens at tor-init runtime by reading the env var.
backendSecretArg := fmt.Sprintf("--api-fetch-secret=$(POD_NAMESPACE)/%s-backend-$(POD_ORDINAL)-keys", gw.Name)
// We don't have a POD_ORDINAL downward field; instead pass the secret name template that tor-init expands.
// Simpler: tor-init derives <gw>-backend-<idx>-keys from POD_NAME on its own (see Task 5b).
```

Actually for clarity the manifest passes the *prefix* and lets tor-init append the ordinal. Pass:

```go
Args: []string{
    "--dst=" + hsServiceDir,
    "--src=",
    "--ob-master-address=" + master.String(),
    fmt.Sprintf("--api-fetch-secret-prefix=%s-backend-", gw.Name),
},
Env: []corev1.EnvVar{
    {Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
    {Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
},
```

- [ ] **Step 6: Adjust tor-init to support `--api-fetch-secret-prefix`**

Realisation: we have two ways to thread the ordinal into the Secret name. The cleaner path is for tor-init to compute the full name itself. Edit `cmd/tor-init/main.go`:

- Add `apiFetchSecretPrefix string` flag.
- In `run`, when `apiFetchSecretPrefix != ""`:
  - Read `POD_NAME` and `POD_NAMESPACE` env vars (both required).
  - Compute `idx := podName[strings.LastIndexByte(podName, '-')+1:]`.
  - Compute `name := apiFetchSecretPrefix + idx + "-keys"`.
  - Call `fetchSecretToDir(ctx, cs, podNamespace, name, dst)`.

Keep the existing `--api-fetch-secret=NS/NAME` for the frontend master-fetch case (Task 6).

```go
flag.StringVar(&apiFetchSecretPrefix, "api-fetch-secret-prefix", "",
    "if set, fetch <prefix><POD_ORDINAL>-keys from the pod's namespace via the in-cluster API")

// in run(), after the api-fetch-secret block:
if apiFetchSecretPrefix != "" {
    podName := os.Getenv("POD_NAME")
    podNamespace := os.Getenv("POD_NAMESPACE")
    if podName == "" || podNamespace == "" {
        return fmt.Errorf("--api-fetch-secret-prefix requires POD_NAME and POD_NAMESPACE")
    }
    dash := strings.LastIndexByte(podName, '-')
    if dash < 0 {
        return fmt.Errorf("POD_NAME %q has no trailing -N", podName)
    }
    name := apiFetchSecretPrefix + podName[dash+1:] + "-keys"
    cfg, err := rest.InClusterConfig()
    if err != nil { return fmt.Errorf("in-cluster config: %w", err) }
    cs, err := kubernetes.NewForConfig(cfg)
    if err != nil { return fmt.Errorf("kubernetes client: %w", err) }
    if err := fetchSecretToDir(ctx, cs, podNamespace, name, dst); err != nil {
        return fmt.Errorf("api-fetch-prefix: %w", err)
    }
    slog.Info("tor-init: api-fetched per-pod secret", "name", name)
}
```

- [ ] **Step 7: Add a unit test for the prefix path**

Append to `cmd/tor-init/main_test.go`:

```go
func TestApiFetchSecretPrefix_DerivesOrdinal(t *testing.T) {
    // Uses fetchSecretToDir directly (the prefix-derivation lives in run()
    // but we cover the wiring via TestRun_ApiFetchPrefix below).
}

func TestRun_ApiFetchPrefix(t *testing.T) {
    // Not feasible without faking rest.InClusterConfig. Cover indirectly:
    // assert the ordinal-derivation helper.
}

// Move ordinal extraction into a helper so we can unit-test it without k8s.
```

Better: extract ordinal logic into a small pure function for testability:

```go
// In main.go:
func podOrdinal(podName string) (string, error) {
    dash := strings.LastIndexByte(podName, '-')
    if dash < 0 || dash == len(podName)-1 {
        return "", fmt.Errorf("POD_NAME %q has no trailing -N", podName)
    }
    return podName[dash+1:], nil
}
```

Then test:

```go
func TestPodOrdinal(t *testing.T) {
    cases := []struct {
        in, want string
        wantErr  bool
    }{
        {"blog-backend-0", "0", false},
        {"blog-backend-7", "7", false},
        {"no-trailing-", "", true},
        {"single", "", true},
    }
    for _, c := range cases {
        got, err := podOrdinal(c.in)
        if (err != nil) != c.wantErr {
            t.Errorf("%q: err=%v wantErr=%v", c.in, err, c.wantErr)
        }
        if got != c.want {
            t.Errorf("%q: got %q want %q", c.in, got, c.want)
        }
    }
}
```

Use `podOrdinal` in the `--api-fetch-secret-prefix` branch.

- [ ] **Step 8: Run all unit tests**

Run: `go test ./cmd/tor-init/ -count=1 -v`
Run: `go test ./internal/controller/ -count=1`

Expected: PASS on both packages. The backend builder tests from Step 1 now pass.

- [ ] **Step 9: Commit**

```bash
git add cmd/tor-init/main.go cmd/tor-init/main_test.go internal/controller/gateway_resources_ha.go internal/controller/gateway_resources_ha_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(controller): backend StatefulSet pods fetch their own key via API"
```

---

### Task 6: Frontend Deployment uses `master-fetch` init container

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildFrontendDeployment` around line 535-630)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Write failing test**

Append:

```go
func TestBuildFrontendDeployment_MasterFetchInitContainer(t *testing.T) {
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns" // cross-NS
    dep, err := BuildFrontendDeployment(gw, obp, tor.OnionAddress{}, RuntimeImages{TorInit: "init:x", Onionbalance: "ob:x", Obrefresh: "obr:x"}, false, scheme())
    if err != nil {
        t.Fatalf("build: %v", err)
    }
    // No SecretVolumeSource for master key.
    for _, v := range dep.Spec.Template.Spec.Volumes {
        if v.Secret != nil && v.Name == "ob-keys" {
            t.Fatalf("frontend still mounts ob-keys SecretVolumeSource")
        }
    }
    // ob-keys volume should be an emptyDir now.
    var found bool
    for _, v := range dep.Spec.Template.Spec.Volumes {
        if v.Name == "ob-keys" && v.EmptyDir != nil {
            found = true
        }
    }
    if !found {
        t.Fatal("ob-keys is not an emptyDir")
    }
    // Init container fetches master from secrets-ns.
    var sawMasterFetch bool
    for _, c := range dep.Spec.Template.Spec.InitContainers {
        for _, a := range c.Args {
            if a == "--api-fetch-secret=secrets-ns/"+obp.Spec.MasterKeySecretRef.Name {
                sawMasterFetch = true
            }
        }
    }
    if !sawMasterFetch {
        t.Errorf("no init container with --api-fetch-secret=secrets-ns/<masterRef.Name>; args: %v", dep.Spec.Template.Spec.InitContainers)
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/controller/ -run TestBuildFrontendDeployment_MasterFetchInitContainer -v`
Expected: FAIL.

- [ ] **Step 3: Remove `ob-keys` SecretVolumeSource and add an emptyDir + init container**

Find the volume definition for `ob-keys` (currently `Secret: &corev1.SecretVolumeSource{SecretName: masterSecretName, ...}`) and replace with:

```go
{Name: "ob-keys", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
```

Add a master-fetch init container at the head of `InitContainers`:

```go
masterNS := pol.Spec.MasterKeySecretRef.Namespace
if masterNS == "" {
    masterNS = gw.Namespace
}
masterName := pol.Spec.MasterKeySecretRef.Name

masterFetch := corev1.Container{
    Name:            "master-fetch",
    Image:           images.TorInit,
    ImagePullPolicy: corev1.PullIfNotPresent,
    Args: []string{
        "--dst=/etc/onionbalance/keys",
        fmt.Sprintf("--api-fetch-secret=%s/%s", masterNS, masterName),
    },
    VolumeMounts: []corev1.VolumeMount{
        {Name: "ob-keys", MountPath: "/etc/onionbalance/keys"},
    },
    SecurityContext: hardenedSecurityContext(),
}
// Prepend to existing init containers.
```

Then in `Spec.Template.Spec.InitContainers`:

```go
InitContainers: append([]corev1.Container{masterFetch}, existingInitContainers...),
```

- [ ] **Step 4: Verify the tor container's `ob-keys` mount stays read-only and points at the same path**

The runtime container's VolumeMount entry should already be `{Name: "ob-keys", MountPath: "/etc/onionbalance/keys", ReadOnly: true}`. Confirm and leave alone.

- [ ] **Step 5: Run the test**

Run: `go test ./internal/controller/ -run TestBuildFrontendDeployment_MasterFetchInitContainer -v`
Expected: PASS.

- [ ] **Step 6: Run the whole package**

Run: `go test ./internal/controller/ -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/controller/gateway_resources_ha.go internal/controller/gateway_resources_ha_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(controller): frontend pod fetches master Secret via init container"
```

---

### Task 7: `BuildFrontendRole` — narrow `get` via `resourceNames`, keep `list/watch` namespace-wide

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildFrontendRole` around line 425-445)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestBuildFrontendRole_GetIsResourceNamesScoped(t *testing.T) {
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    obp.Spec.MasterKeySecretRef.Name = "ob-master"
    role, err := BuildFrontendRole(gw, obp, scheme())
    if err != nil {
        t.Fatalf("build: %v", err)
    }
    var gotGet, gotListWatch bool
    for _, r := range role.Rules {
        switch {
        case sliceEqual(r.Verbs, []string{"get"}):
            gotGet = true
            wantNames := []string{
                "blog-backend-0-keys", "blog-backend-1-keys", "blog-backend-2-keys",
                "ob-master",
            }
            sort.Strings(r.ResourceNames)
            sort.Strings(wantNames)
            if !reflect.DeepEqual(r.ResourceNames, wantNames) {
                t.Errorf("get resourceNames = %v, want %v", r.ResourceNames, wantNames)
            }
        case sliceEqual(r.Verbs, []string{"list", "watch"}):
            gotListWatch = true
            if len(r.ResourceNames) != 0 {
                t.Errorf("list/watch must not have resourceNames; got %v", r.ResourceNames)
            }
        }
    }
    if !gotGet { t.Error("missing get rule") }
    if !gotListWatch { t.Error("missing list/watch rule") }
}

// sliceEqual helper if not already present:
func sliceEqual(a, b []string) bool {
    if len(a) != len(b) { return false }
    for i := range a { if a[i] != b[i] { return false } }
    return true
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/controller/ -run TestBuildFrontendRole_GetIsResourceNamesScoped -v`
Expected: FAIL.

- [ ] **Step 3: Rewrite `BuildFrontendRole`**

```go
func BuildFrontendRole(gw *gwv1.Gateway, pol *policyv1alpha1.OnionBalancePolicy, scheme *runtime.Scheme) (*rbacv1.Role, error) {
    // get: enumerate backend Secret names + the in-namespace master Secret name (when same NS).
    backendNames := make([]string, 0, pol.Spec.Replicas+1)
    for i := int32(0); i < pol.Spec.Replicas; i++ {
        backendNames = append(backendNames, BackendKeySecretName(gw, int(i)))
    }
    masterNS := pol.Spec.MasterKeySecretRef.Namespace
    if masterNS == "" || masterNS == gw.Namespace {
        backendNames = append(backendNames, pol.Spec.MasterKeySecretRef.Name)
    }

    role := &rbacv1.Role{
        ObjectMeta: metav1.ObjectMeta{
            Name:      FrontendName(gw),
            Namespace: gw.Namespace,
            Labels:    HALabels(gw, haRoleFrontend),
        },
        Rules: []rbacv1.PolicyRule{
            {
                APIGroups:     []string{""},
                Resources:     []string{"secrets"},
                Verbs:         []string{"get"},
                ResourceNames: backendNames,
            },
            {
                APIGroups: []string{""},
                Resources: []string{"secrets"},
                Verbs:     []string{"list", "watch"},
            },
        },
    }
    if err := controllerutil.SetControllerReference(gw, role, scheme); err != nil {
        return nil, err
    }
    return role, nil
}
```

- [ ] **Step 4: Run the test**

Run: `go test ./internal/controller/ -run TestBuildFrontendRole_GetIsResourceNamesScoped -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controller/gateway_resources_ha.go internal/controller/gateway_resources_ha_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(controller): frontend Role narrows get to resourceNames"
```

---

### Task 8: `ensureRouterRBAC` adds backend-Secret `get` for Mode B

**Files:**
- Modify: `internal/controller/gateway_controller.go` (function `ensureRouterRBAC`, extracted in commit `1132d9b`)
- Test: `internal/controller/gateway_controller_test.go`

- [ ] **Step 1: Find `ensureRouterRBAC`**

Run: `grep -n 'func.*ensureRouterRBAC' internal/controller/gateway_controller.go`

- [ ] **Step 2: Write failing test**

Append to `gateway_controller_test.go` (next to existing RBAC tests):

```go
func TestEnsureRouterRBAC_ModeBAddsBackendSecretGet(t *testing.T) {
    ctx := context.Background()
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    cl := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(gw, obp).Build()
    r := &GatewayReconciler{Client: cl, Scheme: scheme()}
    if err := r.ensureRouterRBAC(ctx, gw, obp /* new optional arg */); err != nil {
        t.Fatalf("ensureRouterRBAC: %v", err)
    }
    var role rbacv1.Role
    if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: RouterRBACName(gw.Name)}, &role); err != nil {
        t.Fatalf("get Role: %v", err)
    }
    var sawSecretGet bool
    for _, rule := range role.Rules {
        if len(rule.Resources) == 1 && rule.Resources[0] == "secrets" && containsString(rule.Verbs, "get") {
            sawSecretGet = true
            for i := 0; i < 3; i++ {
                want := BackendKeySecretName(gw, i)
                if !containsString(rule.ResourceNames, want) {
                    t.Errorf("missing resourceName %q", want)
                }
            }
        }
    }
    if !sawSecretGet {
        t.Fatal("expected a secrets-get rule in the router Role when Mode B is active")
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/controller/ -run TestEnsureRouterRBAC_ModeBAddsBackendSecretGet -v`
Expected: FAIL (either signature mismatch or missing rule).

- [ ] **Step 4: Update `ensureRouterRBAC` to accept an optional OBP**

Change signature from `ensureRouterRBAC(ctx, gw)` to `ensureRouterRBAC(ctx, gw, obp *policyv1alpha1.OnionBalancePolicy)`. When `obp != nil`, append a rule to the rendered Role:

```go
if obp != nil {
    names := make([]string, 0, obp.Spec.Replicas)
    for i := int32(0); i < obp.Spec.Replicas; i++ {
        names = append(names, BackendKeySecretName(gw, int(i)))
    }
    rules = append(rules, rbacv1.PolicyRule{
        APIGroups:     []string{""},
        Resources:     []string{"secrets"},
        Verbs:         []string{"get"},
        ResourceNames: names,
    })
}
```

Update both call sites in `gateway_controller.go`:
- Mode A path (`reconcileModeA`): pass `nil`.
- Mode B path (`ensureModeB`): pass the OBP.

- [ ] **Step 5: Run test to verify pass**

Run: `go test ./internal/controller/ -run TestEnsureRouterRBAC_ModeBAddsBackendSecretGet -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/controller/gateway_controller.go internal/controller/gateway_controller_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(controller): router RBAC adds backend Secret get for Mode B"
```

---

### Task 9: Cross-NS Role + RoleBinding builders for the frontend SA

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (add `BuildCrossNSMasterRole`, `BuildCrossNSMasterRoleBinding`)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestBuildCrossNSMasterRole_ScopedToMasterSecret(t *testing.T) {
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns"
    obp.Spec.MasterKeySecretRef.Name = "ob-master"
    role, err := BuildCrossNSMasterRole(gw, obp, scheme())
    if err != nil {
        t.Fatalf("build: %v", err)
    }
    if role.Namespace != "secrets-ns" {
        t.Errorf("role namespace = %q, want secrets-ns", role.Namespace)
    }
    if len(role.Rules) != 1 {
        t.Fatalf("rules len = %d, want 1", len(role.Rules))
    }
    if !sliceEqual(role.Rules[0].ResourceNames, []string{"ob-master"}) {
        t.Errorf("resourceNames = %v, want [ob-master]", role.Rules[0].ResourceNames)
    }
    if role.Labels["torgateway.io/owner-uid"] != string(gw.UID) {
        t.Errorf("owner-uid label missing")
    }
}

func TestBuildCrossNSMasterRoleBinding_LinksFrontendSA(t *testing.T) {
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns"
    obp.Spec.MasterKeySecretRef.Name = "ob-master"
    rb, err := BuildCrossNSMasterRoleBinding(gw, obp, scheme())
    if err != nil {
        t.Fatalf("build: %v", err)
    }
    if rb.Namespace != "secrets-ns" {
        t.Errorf("rolebinding namespace = %q, want secrets-ns", rb.Namespace)
    }
    if len(rb.Subjects) != 1 || rb.Subjects[0].Kind != "ServiceAccount" ||
        rb.Subjects[0].Namespace != gw.Namespace || rb.Subjects[0].Name != FrontendName(gw) {
        t.Errorf("subjects = %v, want frontend SA in gw NS", rb.Subjects)
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/controller/ -run 'TestBuildCrossNSMasterRole_ScopedToMasterSecret|TestBuildCrossNSMasterRoleBinding_LinksFrontendSA' -v`
Expected: FAIL.

- [ ] **Step 3: Implement the builders**

Append to `gateway_resources_ha.go`:

```go
// CrossNSMasterRoleName returns the name used for the cross-NS Role + RoleBinding pair.
func CrossNSMasterRoleName(gw *gwv1.Gateway) string {
    return FrontendName(gw) + "-master-fetch"
}

// BuildCrossNSMasterRole emits a Role in pol.Spec.MasterKeySecretRef.Namespace
// that allows `get` on exactly the named master Secret. Caller pairs it with
// BuildCrossNSMasterRoleBinding. NOT controller-referenced (cross-namespace
// owner refs are invalid); the operator GCs it on Gateway delete by label.
func BuildCrossNSMasterRole(gw *gwv1.Gateway, pol *policyv1alpha1.OnionBalancePolicy, _ *runtime.Scheme) (*rbacv1.Role, error) {
    if pol.Spec.MasterKeySecretRef.Namespace == "" {
        return nil, fmt.Errorf("BuildCrossNSMasterRole: MasterKeySecretRef.Namespace empty")
    }
    return &rbacv1.Role{
        ObjectMeta: metav1.ObjectMeta{
            Name:      CrossNSMasterRoleName(gw),
            Namespace: pol.Spec.MasterKeySecretRef.Namespace,
            Labels: map[string]string{
                "app.kubernetes.io/managed-by": "tor-gateway",
                gatewayLabelKey:                gw.Name,
                "torgateway.io/owner-uid":      string(gw.UID),
                "torgateway.io/gateway-ns":     gw.Namespace,
            },
        },
        Rules: []rbacv1.PolicyRule{{
            APIGroups:     []string{""},
            Resources:     []string{"secrets"},
            Verbs:         []string{"get"},
            ResourceNames: []string{pol.Spec.MasterKeySecretRef.Name},
        }},
    }, nil
}

func BuildCrossNSMasterRoleBinding(gw *gwv1.Gateway, pol *policyv1alpha1.OnionBalancePolicy, _ *runtime.Scheme) (*rbacv1.RoleBinding, error) {
    if pol.Spec.MasterKeySecretRef.Namespace == "" {
        return nil, fmt.Errorf("BuildCrossNSMasterRoleBinding: MasterKeySecretRef.Namespace empty")
    }
    return &rbacv1.RoleBinding{
        ObjectMeta: metav1.ObjectMeta{
            Name:      CrossNSMasterRoleName(gw),
            Namespace: pol.Spec.MasterKeySecretRef.Namespace,
            Labels: map[string]string{
                "app.kubernetes.io/managed-by": "tor-gateway",
                gatewayLabelKey:                gw.Name,
                "torgateway.io/owner-uid":      string(gw.UID),
                "torgateway.io/gateway-ns":     gw.Namespace,
            },
        },
        Subjects: []rbacv1.Subject{{
            Kind:      "ServiceAccount",
            Name:      FrontendName(gw),
            Namespace: gw.Namespace,
        }},
        RoleRef: rbacv1.RoleRef{
            APIGroup: "rbac.authorization.k8s.io",
            Kind:     "Role",
            Name:     CrossNSMasterRoleName(gw),
        },
    }, nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/controller/ -run 'CrossNSMaster' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controller/gateway_resources_ha.go internal/controller/gateway_resources_ha_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(controller): cross-NS Role + RoleBinding builders for master Secret"
```

---

### Task 10: `ensureModeB` re-validates ReferenceGrant and reconciles the cross-NS RoleBinding

**Files:**
- Modify: `internal/controller/gateway_controller.go` (`ensureModeB`)
- Modify: `internal/controller/onionbalancepolicy_controller.go` (export `masterKeyReferenceGrantAllows` if not exported)
- Test: `internal/controller/gateway_controller_test.go`

- [ ] **Step 1: Write failing test for re-validation**

```go
func TestEnsureModeB_RejectsCrossNSWithoutReferenceGrant(t *testing.T) {
    ctx := context.Background()
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns"
    obp.Spec.MasterKeySecretRef.Name = "ob-master"
    masterSecret := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{Name: "ob-master", Namespace: "secrets-ns"},
        Data:       map[string][]byte{"hs_ed25519_secret_key": validSecretKeyBytes(t)},
    }
    cl := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(gw, obp, masterSecret).Build()
    r := &GatewayReconciler{Client: cl, Scheme: scheme(), TorRuntime: testRuntimeImages()}
    err := r.ensureModeB(ctx, gw, obp)
    if err == nil {
        t.Fatal("expected ReferenceGrant-missing error, got nil")
    }
    if !strings.Contains(err.Error(), "ReferenceGrant") {
        t.Errorf("error = %q, want substring 'ReferenceGrant'", err)
    }
}

func TestEnsureModeB_CreatesCrossNSRoleBinding(t *testing.T) {
    ctx := context.Background()
    gw := testGateway("blog")
    obp := testOBP("blog-obp", 3)
    obp.Spec.MasterKeySecretRef.Namespace = "secrets-ns"
    obp.Spec.MasterKeySecretRef.Name = "ob-master"
    masterSecret := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{Name: "ob-master", Namespace: "secrets-ns"},
        Data:       map[string][]byte{"hs_ed25519_secret_key": validSecretKeyBytes(t)},
    }
    rg := &gwv1beta1.ReferenceGrant{
        ObjectMeta: metav1.ObjectMeta{Name: "allow-blog", Namespace: "secrets-ns"},
        Spec: gwv1beta1.ReferenceGrantSpec{
            From: []gwv1beta1.ReferenceGrantFrom{{
                Group: "policy.torgateway.io", Kind: "OnionBalancePolicy", Namespace: gwv1beta1.Namespace(gw.Namespace),
            }},
            To: []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Secret"}},
        },
    }
    cl := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(gw, obp, masterSecret, rg).Build()
    r := &GatewayReconciler{Client: cl, Scheme: scheme(), TorRuntime: testRuntimeImages()}
    if err := r.ensureModeB(ctx, gw, obp); err != nil {
        t.Fatalf("ensureModeB: %v", err)
    }
    var rb rbacv1.RoleBinding
    if err := cl.Get(ctx, types.NamespacedName{Namespace: "secrets-ns", Name: CrossNSMasterRoleName(gw)}, &rb); err != nil {
        t.Fatalf("cross-NS RoleBinding not created: %v", err)
    }
}
```

(`validSecretKeyBytes` is a tiny helper that returns a valid-shaped ed25519 secret key for the validator; either reuse an existing test helper or add a 96-zero-byte stub if the validator can be bypassed in tests.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/controller/ -run 'TestEnsureModeB_' -v`
Expected: FAIL.

- [ ] **Step 3: Add ReferenceGrant re-validation at the top of `ensureModeB`**

Find `ensureModeB` (around line 592). At the top, after fetching the OBP:

```go
if pol.Spec.MasterKeySecretRef.Namespace != "" && pol.Spec.MasterKeySecretRef.Namespace != gw.Namespace {
    ok, err := r.masterKeyReferenceGrantAllows(ctx, gw, pol)
    if err != nil {
        return fmt.Errorf("ReferenceGrant check: %w", err)
    }
    if !ok {
        return fmt.Errorf("ReferenceGrant missing for cross-NS master Secret %s/%s", pol.Spec.MasterKeySecretRef.Namespace, pol.Spec.MasterKeySecretRef.Name)
    }
}
```

The `masterKeyReferenceGrantAllows` method should already exist on the OBP reconciler from earlier work; copy it to a shared receiver or factor into a package helper. If it's currently a package-private method on `OnionBalancePolicyReconciler`, extract to:

```go
// internal/controller/referencegrant.go (new file)
package controller

// MasterKeyReferenceGrantAllows is a package-level helper consumed by both
// reconcilers.
func MasterKeyReferenceGrantAllows(ctx context.Context, c client.Client, gw *gwv1.Gateway, pol *policyv1alpha1.OnionBalancePolicy) (bool, error) {
    // (move the existing implementation from onionbalancepolicy_controller.go here)
}
```

Then call `MasterKeyReferenceGrantAllows` from both reconcilers.

- [ ] **Step 4: Add cross-NS RoleBinding lifecycle to `ensureModeB`**

After the ReferenceGrant re-validation:

```go
if pol.Spec.MasterKeySecretRef.Namespace != "" && pol.Spec.MasterKeySecretRef.Namespace != gw.Namespace {
    role, err := BuildCrossNSMasterRole(gw, pol, r.Scheme)
    if err != nil { return err }
    if err := upsert(ctx, r.Client, role); err != nil { return fmt.Errorf("cross-NS Role: %w", err) }
    rb, err := BuildCrossNSMasterRoleBinding(gw, pol, r.Scheme)
    if err != nil { return err }
    if err := upsert(ctx, r.Client, rb); err != nil { return fmt.Errorf("cross-NS RoleBinding: %w", err) }
}
```

`upsert` is a one-line helper (Create-or-Update by name). If the codebase uses `controllerutil.CreateOrUpdate`, use that with a mutate-fn that aligns Rules/Subjects.

- [ ] **Step 5: Run tests to verify pass**

Run: `go test ./internal/controller/ -run 'TestEnsureModeB_' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/controller/gateway_controller.go internal/controller/onionbalancepolicy_controller.go internal/controller/referencegrant.go internal/controller/gateway_controller_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(controller): ensureModeB revalidates ReferenceGrant and provisions cross-NS RoleBinding"
```

---

### Task 11: `obrefresh` informer filters by `owner-uid` label

**Files:**
- Modify: `internal/onionbalance/refresher.go` (informer setup ~line 92-95; `backendsFromSecrets` ~180-199)
- Modify: `cmd/obrefresh/main.go` (pass gw.UID as a CLI flag)
- Modify: `internal/controller/gateway_resources_ha.go` (BuildFrontendDeployment passes `--gateway-uid=$(GW_UID)`)
- Test: `internal/onionbalance/refresher_test.go`

- [ ] **Step 1: Add CLI flag in `cmd/obrefresh/main.go`**

Find existing flag block; add:

```go
var gatewayUID string
flag.StringVar(&gatewayUID, "gateway-uid", "", "Gateway.metadata.uid; used to label-filter backend Secrets")

// Pass to RefresherConfig:
cfg.OwnerUID = gatewayUID
```

In `internal/onionbalance/refresher.go`, add `OwnerUID string` to `RefresherConfig`, validate non-empty in `NewRefresher`:

```go
if cfg.OwnerUID == "" {
    return nil, fmt.Errorf("OwnerUID required")
}
```

- [ ] **Step 2: Write failing test**

```go
func TestBackendsFromSecrets_FilterByOwnerUID(t *testing.T) {
    legit := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{
            Name: "blog-backend-0-keys",
            Labels: map[string]string{
                "torgateway.io/gateway":   "blog",
                "torgateway.io/role":      "backend",
                "torgateway.io/owner-uid": "abc-123",
            },
            OwnerReferences: []metav1.OwnerReference{{
                APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Name: "blog", UID: "abc-123", Controller: ptr.To(true),
            }},
        },
        Data: map[string][]byte{"hostname": []byte("abc.onion\n")},
    }
    impostor := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{
            Name: "blog-backend-0-keys-evil",
            Labels: map[string]string{
                "torgateway.io/gateway":   "blog",
                "torgateway.io/role":      "backend",
                "torgateway.io/owner-uid": "different-uid",
            },
        },
        Data: map[string][]byte{"hostname": []byte("evil.onion\n")},
    }
    addrs := backendsFromSecrets([]any{legit, impostor}, "abc-123")
    if len(addrs) != 1 {
        t.Fatalf("want 1 address, got %d", len(addrs))
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/onionbalance/ -run TestBackendsFromSecrets_FilterByOwnerUID -v`
Expected: FAIL.

- [ ] **Step 4: Update `backendsFromSecrets` to accept and enforce ownerUID**

Change signature:

```go
func backendsFromSecrets(objs []any, ownerUID string) []tor.OnionAddress {
    out := make([]tor.OnionAddress, 0, len(objs))
    for _, o := range objs {
        s, ok := o.(*corev1.Secret)
        if !ok { continue }
        if s.Labels["torgateway.io/owner-uid"] != ownerUID { continue }
        // Also assert ownerRef (H9 belt-and-braces from Stack 2; can land here).
        ownedByGW := false
        for _, or := range s.OwnerReferences {
            if string(or.UID) == ownerUID && or.Controller != nil && *or.Controller {
                ownedByGW = true
                break
            }
        }
        if !ownedByGW { continue }
        hostname := stringNoSpace(s.Data["hostname"])
        if hostname == "" { continue }
        addr, err := tor.ParseOnionAddress(hostname)
        if err != nil { continue }
        out = append(out, addr)
    }
    return out
}
```

Update the caller `rebuild()` to pass `r.cfg.OwnerUID`.

- [ ] **Step 5: Tighten the informer's `LabelSelector`**

```go
informer := factory.ForResource(corev1.SchemeGroupVersion.WithResource("secrets")).Informer()
// inside the SharedInformerFactory construction:
ListOptions: func(o *metav1.ListOptions) {
    o.LabelSelector = fmt.Sprintf(
        "torgateway.io/gateway=%s,torgateway.io/role=backend,torgateway.io/owner-uid=%s",
        cfg.GatewayName, cfg.OwnerUID,
    )
},
```

(Adapt to the actual informer construction pattern; the line numbers above are approximate.)

- [ ] **Step 6: Pass `--gateway-uid` from the Deployment manifest**

In `BuildFrontendDeployment`, add to the obrefresh container's args:

```go
fmt.Sprintf("--gateway-uid=%s", gw.UID),
```

- [ ] **Step 7: Run tests**

Run: `go test ./internal/onionbalance/ -count=1`
Run: `go test ./internal/controller/ -count=1`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd/obrefresh/main.go internal/onionbalance/refresher.go internal/onionbalance/refresher_test.go internal/controller/gateway_resources_ha.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "feat(obrefresh): filter backend Secrets by torgateway.io/owner-uid"
```

---

### Task 12: Remove `BuildOnionbalanceConfigMap`; cleanup orphans

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (delete `BuildOnionbalanceConfigMap`)
- Modify: `internal/controller/gateway_controller.go` (`ensureModeB`, `cleanupModeBResources`)
- Test: `internal/controller/gateway_resources_ha_test.go`, `gateway_controller_test.go`

- [ ] **Step 1: Find callers**

Run: `grep -n 'BuildOnionbalanceConfigMap\|OnionbalanceConfigMapName\|ensureHAConfigMap' internal/controller/*.go`

- [ ] **Step 2: Write failing test asserting cleanup deletes the orphan CM**

```go
func TestCleanupModeBResources_DeletesOnionbalanceConfigMap(t *testing.T) {
    ctx := context.Background()
    gw := testGateway("blog")
    orphan := &corev1.ConfigMap{
        ObjectMeta: metav1.ObjectMeta{
            Name:      OnionbalanceConfigMapName(gw),
            Namespace: gw.Namespace,
        },
    }
    cl := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(gw, orphan).Build()
    r := &GatewayReconciler{Client: cl, Scheme: scheme()}
    if err := r.cleanupModeBResources(ctx, gw); err != nil {
        t.Fatalf("cleanup: %v", err)
    }
    err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: OnionbalanceConfigMapName(gw)}, &corev1.ConfigMap{})
    if !apierrors.IsNotFound(err) {
        t.Fatalf("expected NotFound, got %v", err)
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/controller/ -run TestCleanupModeBResources_DeletesOnionbalanceConfigMap -v`
Expected: FAIL.

- [ ] **Step 4: Delete `BuildOnionbalanceConfigMap` and its caller**

In `gateway_resources_ha.go`, delete the `BuildOnionbalanceConfigMap` function and `OnionbalanceConfigMapName` if no other code uses it (it's still referenced by the cleanup path, keep the name helper).

Actually keep `OnionbalanceConfigMapName(gw)` because `cleanupModeBResources` needs the name to delete the orphan. Delete only the builder + the `ensureHAConfigMap` call from `ensureModeB`.

- [ ] **Step 5: Add the CM to cleanup paths**

In `cleanupModeBResources` (~line 950+):

```go
if err := deleteByName(ctx, r.Client, &corev1.ConfigMap{}, types.NamespacedName{Namespace: gw.Namespace, Name: OnionbalanceConfigMapName(gw)}); client.IgnoreNotFound(err) != nil {
    return fmt.Errorf("orphan onionbalance ConfigMap: %w", err)
}
```

- [ ] **Step 6: Run all controller tests**

Run: `go test ./internal/controller/ -count=1`
Expected: PASS. (If any existing test asserted the CM existed, update it.)

- [ ] **Step 7: Commit**

```bash
git add internal/controller/gateway_resources_ha.go internal/controller/gateway_controller.go internal/controller/gateway_resources_ha_test.go internal/controller/gateway_controller_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "refactor(controller): remove orphan BuildOnionbalanceConfigMap; cleanup migrates existing installs"
```

---

### Task 13: Integration sanity — full unit-test sweep + `make build`

**Files:** none (build + test).

- [ ] **Step 1: Run the full test suite**

Run: `make test`
Expected: PASS. If any test fails, fix or surface to the user — do not amend prior commits unless instructed.

- [ ] **Step 2: Run `make generate` and `make manifests`**

Run: `make generate && make manifests`
Run: `git status --short`
Expected: no uncommitted changes. If there's drift (CRD or deepcopy), stage and commit:

```bash
git add .
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-7@chimbosonic.com>" -m "chore: regenerate manifests/deepcopy"
```

- [ ] **Step 3: Run `make build`**

Run: `make build`
Expected: PASS.

- [ ] **Step 4: Verify the branch is ready**

Run: `git log --oneline main..HEAD`
Expected: a clean sequence of 12-13 commits matching the task names.

- [ ] **Step 5: Hand back to the user**

Do not push. Do not tag. The user runs `git rebase --signoff` before pushing.

Report:
```
Stack 1 complete on branch feat/v0.4.0-stack-1-api-fetch.
Ready for `git rebase --signoff` + user push + PR.
Tickets covered: B4, H3 (partial), H4 (partial), M4, M5, L7.
Stacks 2 and 3 plans pending — to be written after Stack 1 merges.
```

---

## Self-review notes (author-side)

- **Spec coverage** (Stack 1 portion):
  - B4 cross-NS master Secret → Tasks 6, 9, 10. ✓
  - H3 backend-key containment → Tasks 5, 8, 11. ✓ (Fully: runtime container reads only its own key from emptyDir. SA's `get` is `resourceNames`-scoped. `list/watch` stays namespace-wide intentionally; informer enforces owner-uid.)
  - H4 frontend SA → Task 7 (Role narrowing) + Task 9 (cross-NS pattern). ✓
  - M4 orphan onionbalance ConfigMap → Task 12. ✓
  - M5 cross-NS ReferenceGrant race → Task 10. ✓
  - L7 doc fix → Task 4 (folded in). ✓

- **Tickets NOT in Stack 1** (deferred to Stack 2 plan):
  - B1, B2, B3, B5 (mostly mechanical or chart).
  - H1, H5, H6, H7, H8, H9 (note H9's owner-ref check was opportunistically included in Task 11 since it shares code; can de-dupe with Stack 2).
  - H10, M1, M2, M3, M6, M7, M8, all Ls except L7.

- **Placeholders:** none — every step has full code or a precise command.

- **Type consistency:** `RuntimeImages` field names (Tor, TorInit, Onionbalance, Obrefresh), `RefresherConfig.OwnerUID`, `MasterKeyReferenceGrantAllows` signature, `CrossNSMasterRoleName(gw)` — all consistent across tasks.

- **Risk note:** Task 5's "kubelet doesn't substitute `$(POD_NAME)` inside Args" subtlety is real; the resolution (tor-init reads POD_NAME env var) is correct but easy to mis-remember. Implementer should verify the integration test in chutney mode catches a botched expansion.
