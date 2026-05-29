# Vanity Apply-Order Race Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a `Gateway` whose `TorServicePolicy` sets a `vanityPrefix` reliably harvest a vanity key even when both are applied together, without ever regenerating an existing key.

**Architecture:** Two complementary mechanisms in the keyless branch of `ensureKeySecret`: (A) before generating a random key, re-read `TorServicePolicy` objects authoritatively from the API server (`mgr.GetAPIReader()`) to defeat informer-cache lag; (B) if the Gateway carries annotation `torgateway.io/await-vanity: "true"`, refuse to generate a random key and wait (event-driven, via the existing policy watch) until a matching policy appears. No new flags, no Helm chart changes.

**Tech Stack:** Go 1.26, controller-runtime (cached client + `APIReader`), kubebuilder, Gateway API v1, Ginkgo+envtest, plain `testing` + controller-runtime fake client.

---

## File Structure

**New files:**
- `internal/controller/effective_policy_test.go` — plain-`testing` unit test that `effectivePolicyFrom` reads from whichever `client.Reader` it is handed.
- `config/samples/vanity-gateway.yaml` — documented sample: a Gateway with the await annotation + a `TorServicePolicy` with a `vanityPrefix`.

**Modified files:**
- `internal/controller/gateway_controller.go` — add `APIReader client.Reader` field; factor `findEffectivePolicy` into `effectivePolicyFrom(ctx, reader, gw)`; extend the keyless branch of `ensureKeySecret` (authoritative re-read + await-annotation); map the new sentinel in `Reconcile`.
- `internal/controller/vanity.go` — add `errAwaitingVanityPolicy` sentinel and `ReasonAwaitingVanityPolicy` const next to the existing harvest sentinels/reasons.
- `internal/controller/names.go` — add `awaitVanityAnnotation` const.
- `cmd/manager/main.go` — wire `APIReader: mgr.GetAPIReader()`.
- `internal/controller/gateway_vanity_test.go` — set `APIReader` in `makeReconciler`; add the await-wait spec and the plain-keyless regression spec.

**Conventions (match existing code):**
- Apache license header block at the top of every new `.go` file (copy from `internal/controller/names.go`).
- Sentinel errors are unexported package vars; condition-reason consts are exported `Reason*` strings (see `vanity.go`).

---

### Task 1: Authoritative policy read plumbing

Refactor the policy lookup so it can run against any `client.Reader`, add the uncached reader to the reconciler, and wire it in `main.go`. Pure plumbing — no behavior change yet.

**Files:**
- Create: `internal/controller/effective_policy_test.go`
- Modify: `internal/controller/gateway_controller.go`
- Modify: `cmd/manager/main.go`
- Modify: `internal/controller/gateway_vanity_test.go`

- [ ] **Step 1: Write the failing unit test**

Create `internal/controller/effective_policy_test.go` (Apache header, then):

```go
package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
)

func TestEffectivePolicyFromUsesGivenReader(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	tsp := &policyv1alpha1.TorServicePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: gw.Namespace},
		Spec: policyv1alpha1.TorServicePolicySpec{
			TargetRefs: []gwv1.LocalPolicyTargetReference{{
				Group: GatewayAPIGroup, Kind: GatewayKind, Name: gwv1.ObjectName(gw.Name),
			}},
			VanityPrefix: "abc",
		},
	}
	withPolicy := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tsp).Build()
	empty := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := &GatewayReconciler{}

	got, err := r.effectivePolicyFrom(context.Background(), withPolicy, gw)
	if err != nil {
		t.Fatal(err)
	}
	if got.VanityPrefix != "abc" {
		t.Errorf("with policy reader: VanityPrefix = %q, want abc", got.VanityPrefix)
	}

	got2, err := r.effectivePolicyFrom(context.Background(), empty, gw)
	if err != nil {
		t.Fatal(err)
	}
	if got2.VanityPrefix != "" {
		t.Errorf("with empty reader: VanityPrefix = %q, want empty", got2.VanityPrefix)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/controller/ -run TestEffectivePolicyFromUsesGivenReader`
Expected: FAIL — `r.effectivePolicyFrom undefined`.

- [ ] **Step 3: Factor the lookup and add the APIReader field**

In `internal/controller/gateway_controller.go`, add the field to the struct:

```go
type GatewayReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Images         RuntimeImages
	Recorder       record.EventRecorder
	VanityDeadline time.Duration
	// APIReader reads directly from the API server (uncached). Used on the
	// keyless key-generation path to re-check for a vanity policy that the
	// informer cache may not have observed yet.
	APIReader client.Reader
}
```

Replace `findEffectivePolicy` with a thin wrapper plus the reader-parameterized core:

```go
func (r *GatewayReconciler) findEffectivePolicy(ctx context.Context, gw *gwv1.Gateway) (EffectiveServicePolicy, error) {
	return r.effectivePolicyFrom(ctx, r.Client, gw)
}

// effectivePolicyFrom resolves the effective TorServicePolicy for gw using the
// supplied reader. The hot path passes the cached client; the keyless
// key-generation path passes the uncached APIReader to defeat informer lag.
func (r *GatewayReconciler) effectivePolicyFrom(ctx context.Context, reader client.Reader, gw *gwv1.Gateway) (EffectiveServicePolicy, error) {
	list := &policyv1alpha1.TorServicePolicyList{}
	if err := reader.List(ctx, list, client.InNamespace(gw.Namespace)); err != nil {
		return DefaultPolicy(), err
	}
	var matched *policyv1alpha1.TorServicePolicy
	for i := range list.Items {
		p := &list.Items[i]
		if policyTargets(p.Spec.TargetRefs, gw.Name) {
			if matched == nil || p.Name < matched.Name {
				matched = p
			}
		}
	}
	return FromTorServicePolicy(matched), nil
}
```

- [ ] **Step 4: Run the unit test to verify it passes**

Run: `go test ./internal/controller/ -run TestEffectivePolicyFromUsesGivenReader -v`
Expected: PASS.

- [ ] **Step 5: Wire APIReader in main.go**

In `cmd/manager/main.go`, in the `GatewayReconciler` construction, add the `APIReader` field after `VanityDeadline`:

```go
		//nolint:staticcheck // record.EventRecorder API is used throughout the controller and its tests
		Recorder:       mgr.GetEventRecorderFor("gateway"),
		VanityDeadline: vanityDeadline,
		APIReader:      mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
```

- [ ] **Step 6: Set APIReader in the test reconciler**

In `internal/controller/gateway_vanity_test.go`, in `makeReconciler`, add `APIReader` so the harvest specs exercise the wired reader:

```go
		return &GatewayReconciler{
			Client:         k8sClient,
			Scheme:         k8sClient.Scheme(),
			Images:         RuntimeImages{Tor: "tor:t", Router: "r:t", TorInit: "i:t", Mkp224o: "mkp:t", VanityFinalize: "vf:t"},
			Recorder:       rec,
			VanityDeadline: time.Hour,
			APIReader:      k8sClient,
		}, rec
```

- [ ] **Step 7: Verify everything builds and existing tests pass**

Run: `go build ./... && make test`
(`make test` provisions the envtest binaries itself.)
Expected: builds; all existing controller specs still PASS (this task is a behavior-preserving refactor plus a not-yet-used field).

- [ ] **Step 8: Commit**

```bash
git add internal/controller/effective_policy_test.go internal/controller/gateway_controller.go cmd/manager/main.go internal/controller/gateway_vanity_test.go
git commit -m "refactor(controller): reader-parameterized policy lookup + uncached APIReader"
```

---

### Task 2: Await-vanity annotation + authoritative re-check

Add the annotation/sentinel/reason, then implement the keyless decision logic and its `Reconcile` mapping, TDD-driven by envtest specs.

**Files:**
- Modify: `internal/controller/names.go`
- Modify: `internal/controller/vanity.go`
- Modify: `internal/controller/gateway_controller.go`
- Test: `internal/controller/gateway_vanity_test.go`

- [ ] **Step 1: Add the annotation constant**

In `internal/controller/names.go`, in the child-naming `const (...)` block (next to `vanityPrefixLabel`), add:

```go
	// awaitVanityAnnotation, when set to "true" on a Gateway, makes the
	// operator wait for a vanityPrefix TorServicePolicy instead of generating
	// a random key (which could never be re-vanitied). Closes the apply-order
	// race deterministically regardless of when the policy is applied.
	awaitVanityAnnotation = "torgateway.io/await-vanity"
```

- [ ] **Step 2: Add the sentinel and condition reason**

In `internal/controller/vanity.go`, extend the existing sentinel `var (...)` block and reason `const (...)` block:

```go
var (
	errHarvestPending = errors.New("vanity harvest pending")
	errHarvestFailed  = errors.New("vanity harvest failed")
	// errAwaitingVanityPolicy is returned for a keyless Gateway that opted in
	// (await-vanity annotation) but has no matching vanityPrefix policy yet.
	errAwaitingVanityPolicy = errors.New("awaiting vanity policy")
)

const (
	ReasonVanityHarvestInProgress = "VanityHarvestInProgress"
	ReasonVanityHarvestFailed     = "VanityHarvestFailed"
	ReasonAwaitingVanityPolicy    = "AwaitingVanityPolicy"
)
```

- [ ] **Step 3: Write the failing envtest specs**

In `internal/controller/gateway_vanity_test.go`, add these specs inside the `Describe("Gateway vanity harvest", ...)` block (after the existing `It` blocks):

```go
	It("waits without a key when await-vanity is set and no policy exists yet", func() {
		gw := newGateway("van-await")
		gw.Annotations = map[string]string{awaitVanityAnnotation: "true"}
		Expect(k8sClient.Update(ctx, gw)).To(Succeed())
		r, _ := makeReconciler()
		Expect(reconcileGw(r, "van-await")).To(Succeed())

		By("not creating a key Secret")
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: KeySecretName("van-await")}, &corev1.Secret{})).To(HaveOccurred())

		By("reporting Programmed=False/AwaitingVanityPolicy")
		fresh := &gwv1.Gateway{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "van-await"}, fresh)).To(Succeed())
		Expect(conditionReason(fresh, string(gwv1.GatewayConditionProgrammed))).To(Equal(ReasonAwaitingVanityPolicy))

		By("harvesting once the matching policy is created")
		newVanityPolicy("tsp-van-await", "van-await", "abc")
		Expect(reconcileGw(r, "van-await")).To(Succeed())
		job := &batchv1.Job{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: VanityRBACName("van-await")}, job)).To(Succeed())
		Expect(job.Labels[vanityPrefixLabel]).To(Equal("abc"))
	})

	It("still generates a random key for a plain keyless Gateway (no policy, no annotation)", func() {
		newGateway("van-plain")
		r, _ := makeReconciler()
		Expect(reconcileGw(r, "van-plain")).To(Succeed())
		key := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: KeySecretName("van-plain")}, key)).To(Succeed())
		Expect(key.Data).To(HaveKey(tor.FileSecretKeyName))
	})
```

- [ ] **Step 4: Run the specs to verify the await spec fails**

Run: `go test ./internal/controller/ -run TestControllers 2>&1 | grep -iA2 "await-vanity"`
Expected: `waits without a key when await-vanity is set...` FAILS — a key Secret IS created (current code generates a random key), so the `HaveOccurred()` expectation on the Get fails. (The plain-keyless spec already passes — current behavior.)

- [ ] **Step 5: Implement the keyless decision logic**

In `internal/controller/gateway_controller.go`, replace the `apierrors.IsNotFound(err)` case body of `ensureKeySecret` with:

```go
	case apierrors.IsNotFound(err):
		// Creation-time only: a vanity prefix harvests the initial key via a
		// one-shot Job; otherwise generate a random key in-process.
		if policy.VanityPrefix != "" {
			return r.runVanityHarvest(ctx, gw, policy.VanityPrefix)
		}
		// The cached policy lookup can be stale when a Gateway and its
		// TorServicePolicy are applied together (informer lag). Re-check
		// authoritatively against the API server before committing to a
		// random key, so a same-apply vanity policy is honored.
		reader := client.Reader(r.Client)
		if r.APIReader != nil {
			reader = r.APIReader
		}
		fresh, freshErr := r.effectivePolicyFrom(ctx, reader, gw)
		if freshErr != nil {
			return nil, nil, freshErr
		}
		if fresh.VanityPrefix != "" {
			return r.runVanityHarvest(ctx, gw, fresh.VanityPrefix)
		}
		// No vanity policy. If the Gateway explicitly opted to wait for one,
		// do not generate a random key (it could never be re-vanitied).
		if gw.Annotations[awaitVanityAnnotation] == "true" {
			return nil, nil, errAwaitingVanityPolicy
		}
		kp, genErr := FreshKeyPair()
		if genErr != nil {
			return nil, nil, fmt.Errorf("generate keypair: %w", genErr)
		}
		secret, buildErr := BuildKeySecret(gw, kp, r.Scheme)
		if buildErr != nil {
			return nil, nil, buildErr
		}
		if createErr := r.Create(ctx, secret); createErr != nil {
			return nil, nil, createErr
		}
		return secret, kp, nil
```

- [ ] **Step 6: Map the sentinel in Reconcile**

In `internal/controller/gateway_controller.go`, in the `ensureKeySecret` error `switch` inside `Reconcile`, add a case before `default`:

```go
		case errors.Is(err, errAwaitingVanityPolicy):
			return ctrl.Result{}, r.setProgrammingCondition(ctx, gw,
				ReasonAwaitingVanityPolicy, "awaiting a TorServicePolicy with a vanityPrefix (torgateway.io/await-vanity=true)")
```

(No requeue: the existing `Watches(&policyv1alpha1.TorServicePolicy{}, ...)` re-enqueues the Gateway when a matching policy is created.)

- [ ] **Step 7: Run the specs to verify they pass**

Run: `go test ./internal/controller/ -run TestControllers 2>&1 | tail -3`
Expected: `ok` — both new specs pass and no regression in the existing harvest/validation specs.

- [ ] **Step 8: Commit**

```bash
git add internal/controller/names.go internal/controller/vanity.go internal/controller/gateway_controller.go internal/controller/gateway_vanity_test.go
git commit -m "fix(controller): honor vanityPrefix under apply races (authoritative read + await annotation)"
```

---

### Task 3: Sample manifest

Ship a documented sample so users know the bulletproof workflow.

**Files:**
- Create: `config/samples/vanity-gateway.yaml`

- [ ] **Step 1: Write the sample**

Create `config/samples/vanity-gateway.yaml`:

```yaml
# Vanity .onion Gateway.
#
# The torgateway.io/await-vanity annotation makes the operator WAIT for the
# TorServicePolicy below instead of generating a random key — this guarantees
# the vanity harvest even if the policy is observed after the Gateway (e.g.
# applied together, or staged separately by GitOps). Without it, the operator
# still re-checks the API server authoritatively, which covers the common
# "applied together" case; the annotation makes it deterministic for all
# orderings.
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: vanity-demo
  namespace: default
  annotations:
    torgateway.io/await-vanity: "true"
spec:
  gatewayClassName: tor-gateway
  listeners:
  - name: onion
    port: 80
    protocol: torgateway.io/HiddenService
---
apiVersion: policy.torgateway.io/v1alpha1
kind: TorServicePolicy
metadata:
  name: vanity-demo
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: vanity-demo
  # base32 charset only (a-z, 2-7). Keep it short: 2-3 chars harvest in
  # seconds; >6 chars requires vanityAcknowledgeLongRunning: true.
  vanityPrefix: "tor"
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: vanity-demo
  namespace: default
spec:
  parentRefs:
  - name: vanity-demo
  rules:
  - matches:
    - path: { type: PathPrefix, value: / }
    backendRefs:
    - name: my-http-service   # replace with your in-namespace HTTP Service
      port: 80
```

- [ ] **Step 2: Validate the YAML parses**

Run: `kubectl apply --dry-run=client -f config/samples/vanity-gateway.yaml`
Expected: the three objects report `(dry run)` with no parse errors. (Requires Gateway API + policy CRDs known to the target context; if unavailable, `yq 'true' config/samples/vanity-gateway.yaml` to confirm it is well-formed YAML.)

- [ ] **Step 3: Commit**

```bash
git add config/samples/vanity-gateway.yaml
git commit -m "docs(samples): vanity Gateway with await-vanity annotation"
```

---

### Task 4: Full verification gate

**Files:** none (verification only)

- [ ] **Step 1: Generate, build, vet — confirm clean tree**

Run:
```bash
make manifests generate fmt vet
git diff --exit-code
```
Expected: clean. This change adds no kubebuilder markers and no new RBAC (the operator already has `get;list;watch` on `torservicepolicies`), so generated files must not change.

- [ ] **Step 2: Full unit + envtest suite**

Run: `make test`
Expected: PASS, including `TestEffectivePolicyFromUsesGivenReader` and the two new `gateway_vanity_test.go` specs.

- [ ] **Step 3: Lint**

Run: `make lint`
Expected: `0 issues`.

- [ ] **Step 4: Final commit (only if anything changed)**

```bash
git add -A
git commit -m "chore(vanity): regenerate + verify apply-race fix" || echo "nothing to commit"
```

---

## Notes for the implementer

- **Why the APIReader is nil-safe:** other test reconcilers (`gateway_controller_test.go`, `httproute_controller_test.go`) construct `GatewayReconciler` without `APIReader`. The keyless branch falls back to `r.Client` when `APIReader` is nil, so those tests keep working unchanged; only the vanity suite sets it explicitly.
- **Why no requeue on await:** the Gateway already `Owns`/`Watches` `TorServicePolicy`, so creating the policy re-enqueues the Gateway and the harvest fires event-driven. A Gateway that waits forever (annotation set, policy never created) sits at `Programmed=False/AwaitingVanityPolicy` with a clear message — intended.
- **Never-regenerate is preserved:** every change is in the *key-absent* branch. The key-present branch (including the `VanityPrefixIgnored` event) is untouched.
