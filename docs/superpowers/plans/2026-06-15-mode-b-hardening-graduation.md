# Mode B Hardening & Graduation (v0.5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take onionbalance HA (Mode B) from experimental to stable: fix the cross-namespace RBAC leak on Gateway deletion with a finalizer, surface health and in-sidecar failures legibly, harden teardown and validation, then drop the "experimental" label.

**Architecture:** All controller-side changes live in `internal/controller` (the Gateway reconciler + OBP controller), the obrefresh change in `internal/onionbalance` + `cmd/obrefresh`. Status is manager-owned (single writer); obrefresh surfaces only its own in-sidecar failures via Kubernetes Events. Tests are fake-client/envtest unit tests in `internal/controller` and `internal/onionbalance` — no new e2e (consistent with v0.4.0 relocating cross-NS coverage off e2e).

**Tech Stack:** Go 1.26, controller-runtime, Ginkgo/Gomega + standard `testing`, client-go fake clients.

**Pre-verified facts (don't re-derive):**
- `FinalizerName = "torgateway.io/finalizer"` is already defined in `internal/controller/names.go:37` (currently unused).
- `controllerutil` is already imported in `gateway_controller.go:34`; it provides `AddFinalizer`, `RemoveFinalizer`, `ContainsFinalizer` (all return/accept `client.Object`).
- `cleanupModeBResources(ctx, gw)` (`gateway_controller.go:1133`) already deletes the in-namespace frontend resources AND label-GCs the cross-NS `Role`/`RoleBinding` pair (`torgateway.io/owner-uid` + `app.kubernetes.io/managed-by`). It is idempotent and `IgnoreNotFound`. It is a no-op on a Mode A Gateway.
- `GatewayReconciler` fields include `Client`, `Scheme`, `Images`, `Recorder record.EventRecorder`, `TestingNetworkInclude string` (`gateway_controller.go:~50`).
- `r.event(obj runtime.Object, eventType, reason, message string)` is a nil-safe Recorder wrapper (`gateway_controller.go:1446`).
- `setProgrammingCondition(ctx, gw, reason, message)` (`vanity.go:281`) writes `Accepted=True` + `Programmed=False(reason)` and `Status().Update`s only when changed.
- `updateStatusModeB(ctx, gw, master, pol)` (`gateway_controller.go:932`) publishes the master `.onion` and currently sets `Programmed=True` UNCONDITIONALLY (`:1024-1031`). This is the §3 change point.
- `countReadyBackends(ctx, c client.Client, gw)` (`onionbalancepolicy_controller.go:197`) returns the count of backend Secrets carrying a non-empty `hostname` — reuse it for backend readiness.
- OBP `Accepted=False` reason codes already exist (`onionbalancepolicy_controller.go:38-42`): `ReasonOBPGatewayMissing`, `ReasonOBPMasterKeyMissing`, `ReasonOBPMasterKeyInvalid`, `ReasonOBPMasterKeyCrossNSDenied`; `reasonFromMasterErr` maps errors to them.
- The controller-runtime fake client honors finalizers: `Delete` on an object carrying a finalizer sets `DeletionTimestamp` and retains the object until the finalizer is removed.
- Existing test helpers in `gateway_controller_modeb_test.go`: `sampleGateway()`, `samplePolicy(n)`, `testScheme(t)`, `testSchemeWithGrants(t)`, `testRESTMapper()`, `sampleImages()`, consts `testMasterSecretName`/`testMasterSecretNS`. Frontend/backend names: `FrontendName(gw)`, `BackendStatefulSetName(gw)`, `CrossNSMasterRoleName(gw)`.

**Sequence:** Task 1 → 2 → 3 → 4 (validation) → 5 (health) → 6 (obrefresh events) → 7 (docs). (Spec's logical 1→2→3→5→4→6 re-numbered to put the simpler validation audit before the health change.)

---

## Task 1: Finalizer add + delete-time cross-NS cleanup

**Files:**
- Modify: `internal/controller/gateway_controller.go` (Reconcile, after the managed check ~line 106)
- Test: `internal/controller/gateway_controller_modeb_test.go`

- [ ] **Step 1: Write the failing test**

Append to `gateway_controller_modeb_test.go`:

```go
// TestReconcile_FinalizerCleansCrossNSOnDelete verifies the finalizer runs
// cleanupModeBResources (GC'ing the cross-NS Role/RoleBinding that cannot carry
// an owner ref) and then removes itself so the Gateway can be reaped.
func TestReconcile_FinalizerCleansCrossNSOnDelete(t *testing.T) {
	ctx := context.Background()
	gc := &gwv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway"}, // matches sampleGateway().Spec.GatewayClassName
		Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
	}
	gw := sampleGateway()
	gw.Finalizers = []string{FinalizerName}
	// Cross-NS Role + RoleBinding as a prior reconcile would have left them.
	crossLabels := map[string]string{
		"app.kubernetes.io/managed-by": "tor-gateway",
		"torgateway.io/owner-uid":      string(gw.UID),
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
		Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS, Labels: crossLabels}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
		Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS, Labels: crossLabels}}

	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).
		WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).
		WithObjects(gc, gw, role, rb).
		Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	// Deleting a finalizer-bearing object sets DeletionTimestamp but retains it.
	if err := cl.Delete(ctx, gw); err != nil {
		t.Fatalf("delete gateway: %v", err)
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if err := cl.Get(ctx, types.NamespacedName{Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS},
		&rbacv1.Role{}); !apierrors.IsNotFound(err) {
		t.Errorf("cross-NS Role should be GC'd; got %v", err)
	}
	if err := cl.Get(ctx, types.NamespacedName{Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS},
		&rbacv1.RoleBinding{}); !apierrors.IsNotFound(err) {
		t.Errorf("cross-NS RoleBinding should be GC'd; got %v", err)
	}
	// Finalizer removed → fake client reaps the Gateway.
	if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace},
		&gwv1.Gateway{}); !apierrors.IsNotFound(err) {
		t.Errorf("Gateway should be gone after finalizer removal; got %v", err)
	}
}

// TestReconcile_AddsFinalizerToManagedGateway verifies a live managed Gateway
// gets the finalizer on first reconcile.
func TestReconcile_AddsFinalizerToManagedGateway(t *testing.T) {
	ctx := context.Background()
	gc := &gwv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway"}, // matches sampleGateway().Spec.GatewayClassName
		Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
	}
	gw := sampleGateway()
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).WithObjects(gc, gw).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got gwv1.Gateway
	if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&got, FinalizerName) {
		t.Errorf("expected finalizer %q on managed Gateway; finalizers=%v", FinalizerName, got.Finalizers)
	}
}
```

Verified: `sampleGateway()` sets `GatewayClassName: "tor-gateway"` (so the GatewayClass object must be named `tor-gateway`) and a non-empty `UID` (`11111111-…`), so the cross-NS `owner-uid` label match is meaningful with no extra setup. `ControllerName` (`names.go:27`, `gwv1.GatewayController = "torgateway.io/gateway-controller"`) is the const `gatewayClassManagedByUs` compares against.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/controller/ -run 'TestReconcile_Finalizer|TestReconcile_AddsFinalizer' -v`
Expected: FAIL — cross-NS objects still present / Gateway still present (no finalizer logic yet), and the add-test fails (finalizer absent).

- [ ] **Step 3: Implement the finalizer logic**

In `gateway_controller.go`, in `Reconcile`, insert immediately AFTER the managed check (after the `if !managed { return ctrl.Result{}, nil }` block, ~line 106) and BEFORE `findEffectiveOnionBalance`:

```go
	// Finalizer: ensures cross-NS Role/RoleBinding (which cannot carry an owner
	// ref) are GC'd before the Gateway object is removed. Added to every managed
	// Gateway; cleanupModeBResources is a no-op for Mode A.
	if !gw.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(gw, FinalizerName) {
			if err := r.cleanupModeBResources(ctx, gw); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(gw, FinalizerName)
			if err := r.Update(ctx, gw); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if controllerutil.AddFinalizer(gw, FinalizerName) {
		if err := r.Update(ctx, gw); err != nil {
			return ctrl.Result{}, err
		}
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/controller/ -run 'TestReconcile_Finalizer|TestReconcile_AddsFinalizer' -v`
Expected: PASS.

- [ ] **Step 5: Run the full package + vet**

Run: `go test ./internal/controller/ -count=1 && go vet ./internal/controller/`
Expected: all PASS, vet clean. (If a pre-existing Reconcile test now sees the finalizer Update and breaks on a missing GatewayClass or status subresource, adjust that test's fake-client setup minimally — do not weaken the finalizer logic.)

- [ ] **Step 6: Commit**

```bash
git add internal/controller/gateway_controller.go internal/controller/gateway_controller_modeb_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-8@chimbosonic.com>" -m "fix(controller): finalizer GCs cross-NS RBAC on Gateway deletion

A Gateway deleted while in Mode B with a cross-namespace master Secret
left its cross-NS Role/RoleBinding behind: they cannot carry an owner
ref, and Reconcile returns early on IsNotFound so cleanupModeBResources
never ran. Add FinalizerName to every managed Gateway and run the
existing cleanup (which already label-GCs the cross-NS pair) on
deletion before removing the finalizer. In-namespace children still
cascade via owner refs."
```

---

## Task 2: Master Secret missing surfaces without hot-loop

**Files:**
- Modify: `internal/controller/gateway_controller.go` (`ensureModeB`, master-Secret fetch ~line 615)
- Test: `internal/controller/gateway_controller_modeb_test.go`

- [ ] **Step 1: Write the failing test**

```go
// TestEnsureModeB_MasterSecretNotFoundSurfaces verifies a missing master Secret
// sets Programmed=False/MasterSecretNotFound and does NOT return an error (which
// would hot-loop the reconcile); a transient error path still returns an error.
func TestEnsureModeB_MasterSecretNotFoundSurfaces(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	obp := samplePolicy(1) // same-namespace master Secret ref, but Secret absent
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).WithObjects(gw, obp).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	if err := r.ensureModeB(ctx, gw, obp); err != nil {
		t.Fatalf("ensureModeB should not return an error for a missing master Secret; got %v", err)
	}
	var got gwv1.Gateway
	if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
		t.Fatal(err)
	}
	prog := meta.FindStatusCondition(got.Status.Conditions, string(gwv1.GatewayConditionProgrammed))
	if prog == nil || prog.Status != metav1.ConditionFalse || prog.Reason != ReasonMasterSecretNotFound {
		t.Errorf("Programmed = %v, want False/%s", prog, ReasonMasterSecretNotFound)
	}
}
```

(`meta` = `k8s.io/apimachinery/pkg/api/meta` — already imported by the test file per the v0.4.0 additions; if not, add it.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/controller/ -run TestEnsureModeB_MasterSecretNotFound -v`
Expected: FAIL — `ReasonMasterSecretNotFound` undefined / `ensureModeB` returns an error.

- [ ] **Step 3: Add the reason const and branch**

In `gateway_controller.go`, add near the other Gateway-side reason strings (or just above `ensureModeB`):

```go
// ReasonMasterSecretNotFound is the Programmed=False reason when the OBP's
// master-key Secret is absent at provisioning time.
const ReasonMasterSecretNotFound = "MasterSecretNotFound"
```

Change the master-Secret fetch in `ensureModeB` (currently `return fmt.Errorf("get master Secret: %w", err)`):

```go
	var masterSec corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Namespace: masterSecretNS, Name: pol.Spec.MasterKeySecretRef.Name}, &masterSec); err != nil {
		if apierrors.IsNotFound(err) {
			r.event(gw, corev1.EventTypeWarning, ReasonMasterSecretNotFound,
				fmt.Sprintf("master key Secret %s/%s not found; HA cannot be programmed until it exists",
					masterSecretNS, pol.Spec.MasterKeySecretRef.Name))
			return r.setProgrammingCondition(ctx, gw, ReasonMasterSecretNotFound,
				fmt.Sprintf("master key Secret %s/%s not found", masterSecretNS, pol.Spec.MasterKeySecretRef.Name))
		}
		return fmt.Errorf("get master Secret: %w", err) // transient → requeue
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/controller/ -run TestEnsureModeB_MasterSecretNotFound -v`
Expected: PASS.

- [ ] **Step 5: Full package + vet**

Run: `go test ./internal/controller/ -count=1 && go vet ./internal/controller/`
Expected: PASS, clean.

- [ ] **Step 6: Commit**

```bash
git add internal/controller/gateway_controller.go internal/controller/gateway_controller_modeb_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-8@chimbosonic.com>" -m "fix(controller): surface missing master Secret instead of hot-looping

A master-key Secret deleted (or never created) while an OBP targets a
Gateway made ensureModeB return an error every reconcile, thrashing the
queue with no operator-visible signal. Treat NotFound as a terminal
Programmed=False/MasterSecretNotFound condition + Warning event and
return nil; genuinely transient Get errors still requeue."
```

---

## Task 3: B→A transition leaves no cross-NS leak (regression guard)

**Files:**
- Test only: `internal/controller/gateway_controller_modea_test.go`

- [ ] **Step 1: Write the test**

This asserts existing behavior (a guard, not a fix). Append to `gateway_controller_modea_test.go`:

```go
// TestModeATransition_GCsCrossNSPairs verifies that reconciling a Gateway back
// to Mode A (no OBP) cleans up cross-NS Role/RoleBinding left from Mode B.
func TestModeATransition_GCsCrossNSPairs(t *testing.T) {
	ctx := context.Background()
	gw := sampleGateway()
	crossLabels := map[string]string{
		"app.kubernetes.io/managed-by": "tor-gateway",
		"torgateway.io/owner-uid":      string(gw.UID),
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
		Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS, Labels: crossLabels}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
		Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS, Labels: crossLabels}}
	sc := testSchemeWithGrants(t)
	cl := fake.NewClientBuilder().
		WithScheme(sc).WithRESTMapper(testRESTMapper()).
		WithStatusSubresource(gw).WithObjects(gw, role, rb).Build()
	r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}

	if err := r.cleanupModeBResources(ctx, gw); err != nil {
		t.Fatalf("cleanupModeBResources: %v", err)
	}
	for _, obj := range []client.Object{&rbacv1.Role{}, &rbacv1.RoleBinding{}} {
		if err := cl.Get(ctx, types.NamespacedName{Name: CrossNSMasterRoleName(gw), Namespace: testMasterSecretNS},
			obj); !apierrors.IsNotFound(err) {
			t.Errorf("%T should be GC'd on B→A transition; got %v", obj, err)
		}
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/controller/ -run TestModeATransition_GCsCrossNSPairs -v`
Expected: PASS (the GC already exists). If it FAILS, that's a real gap — stop and fix `cleanupModeBResources` before continuing, then re-run.

- [ ] **Step 3: Commit**

```bash
git add internal/controller/gateway_controller_modea_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-8@chimbosonic.com>" -m "test(controller): guard B→A transition GCs cross-NS RBAC pairs"
```

---

## Task 4: Validation-reason audit (gap-fill)

**Files:**
- Modify (only if a gap is found): `internal/controller/onionbalancepolicy_controller.go`
- Test: `internal/controller/onionbalancepolicy_controller_test.go` (or the existing OBP status test file)

- [ ] **Step 1: Write a table-driven test over every Accepted=False reason**

Append to the OBP controller test file:

```go
// TestOBPAcceptedReasons asserts each misconfiguration maps to its specific
// Accepted=False reason (no generic fall-through).
func TestOBPAcceptedReasons(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(gw *gwv1.Gateway, obp *policyv1alpha1.OnionBalancePolicy) []client.Object
		wantReason string
	}{
		{
			name: "missing master Secret",
			setup: func(gw *gwv1.Gateway, obp *policyv1alpha1.OnionBalancePolicy) []client.Object {
				obp.Spec.MasterKeySecretRef.Name = "absent"
				return []client.Object{gw, obp}
			},
			wantReason: ReasonOBPMasterKeyMissing,
		},
		{
			name: "invalid master key bytes",
			setup: func(gw *gwv1.Gateway, obp *policyv1alpha1.OnionBalancePolicy) []client.Object {
				sec := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: obp.Spec.MasterKeySecretRef.Name, Namespace: obp.Namespace},
					Data:       map[string][]byte{tor.FileSecretKeyName: []byte("garbage"), tor.FilePublicKeyName: []byte("garbage")},
				}
				return []client.Object{gw, obp, sec}
			},
			wantReason: ReasonOBPMasterKeyInvalid,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := sampleGateway()
			obp := samplePolicy(1)
			objs := tc.setup(gw, obp)
			sc := testSchemeWithGrants(t)
			cl := fake.NewClientBuilder().WithScheme(sc).WithRESTMapper(testRESTMapper()).
				WithStatusSubresource(obp).WithObjects(objs...).Build()
			r := &OnionBalancePolicyReconciler{Client: cl, Scheme: sc}
			if _, err := r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: obp.Name, Namespace: obp.Namespace}}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			var got policyv1alpha1.OnionBalancePolicy
			if err := cl.Get(ctx, types.NamespacedName{Name: obp.Name, Namespace: obp.Namespace}, &got); err != nil {
				t.Fatal(err)
			}
			// Accepted condition lives in the per-ancestor status.
			reason := acceptedReasonFor(&got, gw.Name)
			if reason != tc.wantReason {
				t.Errorf("Accepted reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}
```

Before writing, read `onionbalancepolicy_controller.go` to confirm: (a) the `OnionBalancePolicyReconciler` field set + how it's constructed in existing tests (mirror exactly), (b) where the `Accepted` condition is stored (per-ancestor `Status.Ancestors[].Conditions`), and write a small local helper `acceptedReasonFor(obp, gwName)` in the test that digs it out — or reuse an existing test helper if one already extracts ancestor conditions. If the existing tests already cover one of these reasons, keep only the genuinely-uncovered cases (YAGNI; this is an audit).

- [ ] **Step 2: Run it**

Run: `go test ./internal/controller/ -run TestOBPAcceptedReasons -v`
Expected: PASS if reasons are already wired. If a case FAILS or returns a generic reason, fix `reasonFromMasterErr` / `validateMasterKey` in `onionbalancepolicy_controller.go` so the specific reason is returned, then re-run to green.

- [ ] **Step 3: Full package + vet**

Run: `go test ./internal/controller/ -count=1 && go vet ./internal/controller/`
Expected: PASS, clean.

- [ ] **Step 4: Commit**

```bash
git add internal/controller/onionbalancepolicy_controller*.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-8@chimbosonic.com>" -m "test(controller): pin OnionBalancePolicy Accepted=False reason mapping

Table-driven coverage that each master-key misconfiguration surfaces
its specific Accepted reason rather than a generic fall-through, so a
bad OBP fails fast and legibly. <Note any gap-fill if a reason was
unwired.>"
```

---

## Task 5: Mode B health condition (Programmed reflects real readiness)

**Files:**
- Modify: `internal/controller/gateway_controller.go` (`updateStatusModeB` ~line 1015-1032; add a `modeBHealth` helper)
- Test: `internal/controller/gateway_controller_modeb_test.go`

- [ ] **Step 1: Write the failing test**

```go
// TestUpdateStatusModeB_ProgrammedReflectsReadiness verifies Programmed is True
// only when the frontend Deployment is Available AND at least one backend is
// ready; otherwise False with a specific reason.
func TestUpdateStatusModeB_ProgrammedReflectsReadiness(t *testing.T) {
	ctx := context.Background()
	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := kp.OnionAddress()

	newFrontend := func(available bool) *appsv1.Deployment {
		status := corev1.ConditionFalse
		if available {
			status = corev1.ConditionTrue
		}
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: FrontendName(sampleGateway()), Namespace: sampleGateway().Namespace},
			Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: status}}},
		}
	}
	readyBackendSecret := func() *corev1.Secret {
		gw := sampleGateway()
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: BackendKeySecretName(gw, 0), Namespace: gw.Namespace,
				Labels: map[string]string{"torgateway.io/gateway": gw.Name, "torgateway.io/role": "backend"}},
			Data: map[string][]byte{"hostname": []byte(master.String())},
		}
	}

	tests := []struct {
		name       string
		objs       []client.Object
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{"healthy", []client.Object{newFrontend(true), readyBackendSecret()}, metav1.ConditionTrue, string(gwv1.GatewayReasonProgrammed)},
		{"frontend not ready", []client.Object{newFrontend(false), readyBackendSecret()}, metav1.ConditionFalse, ReasonFrontendNotReady},
		{"backends not ready", []client.Object{newFrontend(true)}, metav1.ConditionFalse, ReasonBackendsNotReady},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := sampleGateway()
			pol := samplePolicy(1)
			sc := testScheme(t)
			objs := append([]client.Object{gw, pol}, tc.objs...)
			cl := fake.NewClientBuilder().WithScheme(sc).WithStatusSubresource(gw).WithObjects(objs...).Build()
			r := &GatewayReconciler{Client: cl, Scheme: sc, Images: sampleImages()}
			if err := r.updateStatusModeB(ctx, gw, master, pol); err != nil {
				t.Fatalf("updateStatusModeB: %v", err)
			}
			var got gwv1.Gateway
			if err := cl.Get(ctx, types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
				t.Fatal(err)
			}
			prog := meta.FindStatusCondition(got.Status.Conditions, string(gwv1.GatewayConditionProgrammed))
			if prog == nil || prog.Status != tc.wantStatus || prog.Reason != tc.wantReason {
				t.Errorf("Programmed = %v, want %s/%s", prog, tc.wantStatus, tc.wantReason)
			}
			// Address is published regardless of readiness.
			if len(got.Status.Addresses) == 0 || got.Status.Addresses[0].Value != master.String() {
				t.Errorf("master .onion should be published regardless of readiness; got %v", got.Status.Addresses)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/controller/ -run TestUpdateStatusModeB_ProgrammedReflectsReadiness -v`
Expected: FAIL — `ReasonFrontendNotReady`/`ReasonBackendsNotReady` undefined; Programmed currently always True.

- [ ] **Step 3: Add the reasons + health helper, make Programmed conditional**

Add reason consts near `ReasonMasterSecretNotFound`:

```go
const (
	ReasonFrontendNotReady = "FrontendNotReady"
	ReasonBackendsNotReady = "BackendsNotReady"
)
```

Add a helper (place beside `updateStatusModeB`):

```go
// modeBHealth reports reconcile-observable Mode B health: frontend Deployment
// Available and at least one backend Secret carrying a hostname. It does NOT
// verify Tor descriptor liveness (the manager cannot query HSDirs); that is
// covered by the e2e/realtor smoke tests.
func (r *GatewayReconciler) modeBHealth(ctx context.Context, gw *gwv1.Gateway) (healthy bool, reason, message string) {
	var fe appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: FrontendName(gw)}, &fe); err != nil {
		return false, ReasonFrontendNotReady, "frontend Deployment not found yet"
	}
	available := false
	for _, c := range fe.Status.Conditions {
		if c.Type == appsv1.DeploymentAvailable && c.Status == corev1.ConditionTrue {
			available = true
			break
		}
	}
	if !available {
		return false, ReasonFrontendNotReady, "frontend Deployment not yet Available"
	}
	ready, err := countReadyBackends(ctx, r.Client, gw)
	if err != nil || ready < 1 {
		return false, ReasonBackendsNotReady,
			fmt.Sprintf("%d backend instance(s) ready; need at least 1", ready)
	}
	return true, string(gwv1.GatewayReasonProgrammed),
		fmt.Sprintf("Mode B provisioned; frontend Available and %d backend(s) ready "+
			"(reconcile-observable; Tor descriptor liveness not verified here)", ready)
}
```

In `updateStatusModeB`, replace the hardcoded `Programmed` entry in `wantConds` (`:1024-1031`) with a computed condition. Just before building `wantConds`:

```go
		healthy, progReason, progMsg := r.modeBHealth(ctx, gw)
		progStatus := metav1.ConditionFalse
		if healthy {
			progStatus = metav1.ConditionTrue
		}
```

and the `Programmed` entry becomes:

```go
			{
				Type:               string(gwv1.GatewayConditionProgrammed),
				Status:             progStatus,
				Reason:             progReason,
				Message:            progMsg,
				ObservedGeneration: fresh.Generation,
				LastTransitionTime: metav1.Now(),
			},
```

(Compute `healthy/progReason/progMsg` once, outside the `RetryOnConflict` closure, to avoid re-reading per retry — declare them above the `return retry.RetryOnConflict(...)` call.)

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/controller/ -run TestUpdateStatusModeB_ProgrammedReflectsReadiness -v`
Expected: PASS.

- [ ] **Step 5: Full package + vet**

Run: `go test ./internal/controller/ -count=1 && go vet ./internal/controller/`
Expected: PASS, clean. (The existing `TestUpdateStatusModeB_RetriesOnConflict` and `TestUpdateStatusModeB_PreservesExistingAddressesOfOtherTypes` may now see `Programmed=False` because their fake clients have no frontend Deployment. Update those tests' assertions to either provision a ready frontend+backend, or assert on the address/annotation behavior they actually target and not on `Programmed=True`. Adjust minimally; do not revert the health logic.)

- [ ] **Step 6: Commit**

```bash
git add internal/controller/gateway_controller.go internal/controller/gateway_controller_modeb_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-8@chimbosonic.com>" -m "feat(controller): Programmed condition reflects real Mode B readiness

updateStatusModeB set Programmed=True the moment Mode B resources were
applied, regardless of whether the frontend was Available or any backend
had published. Compute health from reconcile-observable state (frontend
Deployment Available + >=1 ready backend) and set Programmed
True/False(FrontendNotReady|BackendsNotReady) accordingly. The master
.onion is still published regardless. Honest by construction: this is
not Tor descriptor-liveness, which the e2e/realtor smoke covers."
```

---

## Task 6: obrefresh emits Warning Events on internal failures

**Files:**
- Modify: `internal/onionbalance/refresher.go` (RefresherConfig + rebuild)
- Modify: `cmd/obrefresh/main.go` (construct recorder, pass it in)
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildFrontendRole`, add events rule)
- Test: `internal/onionbalance/refresher_test.go`, `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Write the failing refresher test**

In `refresher_test.go`, add (using a fake recorder):

```go
// TestRebuild_EmitsWarningOnRenderFailure verifies a render failure emits a
// Warning event with the expected reason and does not crash the refresher.
func TestRebuild_EmitsWarningOnRenderFailure(t *testing.T) {
	rec := record.NewFakeRecorder(10)
	r, err := NewRefresher(context.Background(), RefresherConfig{
		GatewayName: "blog", GatewayNamespace: "prod",
		ConfigPath: "/nonexistent-dir/config.yaml", // force atomicWrite failure
		PIDFile:    filepath.Join(t.TempDir(), "missing.pid"),
		MasterKeyPath: "/tmp/master", OwnerUID: "uid-1",
		Master:   mustOnion(t),
		Client:   k8sfake.NewSimpleClientset(),
		Recorder: rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A valid backend so Render succeeds but atomicWrite to a bad dir fails.
	r.rebuild(context.Background(), []any{backendSecret(t, "uid-1")})

	select {
	case ev := <-rec.Events:
		if !strings.Contains(ev, "Warning") || !strings.Contains(ev, ReasonReloadConfigFailed) {
			t.Errorf("event = %q, want Warning/%s", ev, ReasonReloadConfigFailed)
		}
	default:
		t.Error("expected a Warning event on write failure")
	}
}
```

Read `refresher_test.go` first to reuse its existing helpers (a backend-Secret constructor and an onion helper likely exist; if `mustOnion`/`backendSecret` aren't present, add minimal local helpers). `record` = `k8s.io/client-go/tools/record`; `k8sfake` = `k8s.io/client-go/kubernetes/fake`.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/onionbalance/ -run TestRebuild_EmitsWarning -v`
Expected: FAIL — `Recorder` field and `ReasonReloadConfigFailed` undefined.

- [ ] **Step 3: Add recorder support to the refresher**

In `refresher.go`, add to `RefresherConfig`:

```go
	// Recorder, when non-nil, receives Warning events for the refresher's own
	// internal failures (config render/write, SIGHUP), with the Gateway as the
	// involved object. Best-effort: nil disables event emission.
	Recorder record.EventRecorder
```

Add reason consts + a nil-safe emit helper:

```go
const (
	ReasonReloadConfigFailed = "OnionbalanceConfigRenderFailed"
	ReasonReloadSighupFailed = "OnionbalanceReloadFailed"
)

// emitWarning sends a Warning event against the Gateway, best-effort.
func (r *Refresher) emitWarning(reason, msg string) {
	if r.cfg.Recorder == nil {
		return
	}
	gwRef := &corev1.ObjectReference{
		APIVersion: "gateway.networking.k8s.io/v1",
		Kind:       "Gateway",
		Name:       r.cfg.GatewayName,
		Namespace:  r.cfg.GatewayNamespace,
	}
	r.cfg.Recorder.Event(gwRef, corev1.EventTypeWarning, reason, msg)
}
```

Wire it into `rebuild` (replace the three failure `return`s' bodies — keep the logging, add an emit):

```go
	rendered, err := Render(r.cfg.Master, backends, r.cfg.MasterKeyPath)
	if err != nil {
		slog.Error("onionbalance render failed", "err", err)
		r.emitWarning(ReasonReloadConfigFailed, "onionbalance config render failed: "+err.Error())
		return
	}
	if err := atomicWrite(r.cfg.ConfigPath, []byte(rendered)); err != nil {
		slog.Error("onionbalance write failed", "path", r.cfg.ConfigPath, "err", err)
		r.emitWarning(ReasonReloadConfigFailed, "onionbalance config write failed: "+err.Error())
		return
	}
	if err := sighupPID(r.cfg.PIDFile); err != nil {
		slog.Warn("onionbalance SIGHUP failed", "pid", r.cfg.PIDFile, "err", err)
		r.emitWarning(ReasonReloadSighupFailed, "onionbalance SIGHUP failed: "+err.Error())
		return
	}
```

Add imports as needed: `corev1 "k8s.io/api/core/v1"` and `"k8s.io/client-go/tools/record"` (check; corev1 is likely already imported).

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/onionbalance/ -run TestRebuild_EmitsWarning -v`
Expected: PASS.

- [ ] **Step 5: Construct the recorder in `cmd/obrefresh/main.go`**

Read `cmd/obrefresh/main.go` to find where `RefresherConfig` is built and the clientset created. Add, before constructing the config:

```go
	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: clientset.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "obrefresh"})
	defer broadcaster.Shutdown()
```

and set `Recorder: recorder` in the `RefresherConfig` literal. Imports: `"k8s.io/client-go/tools/record"`, `typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"`, `"k8s.io/client-go/kubernetes/scheme"`, `corev1 "k8s.io/api/core/v1"`. (`clientset` is the existing `kubernetes.Interface`; if it's named differently, match it.)

- [ ] **Step 6: Write the failing frontend-Role test**

In `gateway_resources_ha_test.go`:

```go
// TestBuildFrontendRole_AllowsEventCreate verifies the frontend Role grants
// events:create so obrefresh can emit Warning events.
func TestBuildFrontendRole_AllowsEventCreate(t *testing.T) {
	role, err := BuildFrontendRole(sampleGateway(), samplePolicy(2), testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range role.Rules {
		if slices.Contains(rule.Resources, "events") && slices.Contains(rule.Verbs, "create") {
			found = true
		}
	}
	if !found {
		t.Errorf("frontend Role must allow events:create; rules=%v", role.Rules)
	}
}
```

(`slices` is stdlib; add to imports if absent.)

- [ ] **Step 7: Run it to verify it fails**

Run: `go test ./internal/controller/ -run TestBuildFrontendRole_AllowsEventCreate -v`
Expected: FAIL — no events rule.

- [ ] **Step 8: Add the events rule to `BuildFrontendRole`**

In `gateway_resources_ha.go`, append to the `Rules` slice in `BuildFrontendRole`:

```go
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
```

- [ ] **Step 9: Run both new tests + packages + vet**

Run: `go test ./internal/onionbalance/ ./internal/controller/ -count=1 && go vet ./internal/onionbalance/ ./cmd/obrefresh/ ./internal/controller/`
Expected: PASS, clean. (`go build ./cmd/obrefresh/` too — confirm the recorder wiring compiles.)

- [ ] **Step 10: Commit**

```bash
git add internal/onionbalance/refresher.go internal/onionbalance/refresher_test.go cmd/obrefresh/main.go internal/controller/gateway_resources_ha.go internal/controller/gateway_resources_ha_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-8@chimbosonic.com>" -m "feat(obrefresh): surface config/SIGHUP failures as Gateway Warning events

obrefresh's render/write/SIGHUP failures were only visible in the
sidecar log. Emit Warning events (OnionbalanceConfigRenderFailed /
OnionbalanceReloadFailed) against the Gateway so kubectl describe
gateway shows a stuck refresh. Emission is best-effort (nil-safe, never
blocks a reload). The frontend Role gains events:create;patch."
```

---

## Task 7: Graduate Mode B (docs)

**Files:**
- Modify: `README.md` (~line 80), `docs/PLAN.md` (~line 37), `SECURITY.md` (Mode B section), `api/v1alpha1/onionbalancepolicy_types.go` (type doc, if it implies experimental)

- [ ] **Step 1: Update README**

In `README.md`, change the v1-target features line:

```
- HA via onionbalance via `OnionBalancePolicy` (Mode B; requires chart appVersion ≥ 0.4.0 because earlier installs reference the wrong onionbalance image repo).
```

(Drop "experimental in v0.4.0".)

- [ ] **Step 2: Update PLAN.md**

In `docs/PLAN.md:37`, change "Mode B remains experimental; graduation targeted for v0.5." to:

```
Mode B graduated to stable in v0.5: clean teardown via a Gateway finalizer (cross-NS RBAC no longer leaks on deletion), a Programmed condition that reflects real frontend/backend readiness, and obrefresh failures surfaced as Gateway events.
```

- [ ] **Step 3: Update SECURITY.md**

Read the `SECURITY.md` Mode B section; remove any "experimental" qualifier and add a sentence that cross-NS master-Secret RBAC is now reclaimed on Gateway deletion via the finalizer. Keep the existing security posture text otherwise.

- [ ] **Step 4: Check the CRD type doc**

Run: `grep -ni "experimental" api/v1alpha1/onionbalancepolicy_types.go`
If any comment calls the policy experimental, drop that qualifier. If none, no change.

- [ ] **Step 5: Verify docs build / no stale refs + commit**

Run: `grep -rni "mode b.*experimental\|experimental.*mode b\|experimental.*onionbalance" README.md docs/PLAN.md SECURITY.md`
Expected: no matches.

```bash
git add README.md docs/PLAN.md SECURITY.md api/v1alpha1/onionbalancepolicy_types.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-opus-4-8@chimbosonic.com>" -m "docs: graduate Mode B from experimental to stable

The v0.5 hardening (finalizer-backed clean teardown, readiness-reflecting
Programmed condition, obrefresh failure events) closes the last known
gaps. Drop the experimental qualifier from README, PLAN.md, and
SECURITY.md."
```

---

## Final verification (after all tasks)

- [ ] `make test` — full unit + envtest suite green (includes every new test above).
- [ ] `make lint` — `0 issues` (run it, not just `go vet`: the v0.4.0 release shipped an errcheck miss because lint was skipped locally).
- [ ] `go build ./...` — all binaries compile, including `cmd/obrefresh`.
- [ ] The post-release manager-side RBAC (`config/rbac`) is regenerated if any kubebuilder markers changed: `make manifests && make chart-sync` (the frontend Role is built in Go, not via markers, so likely no regen — but run the drift guard `make manifests` to be safe and commit any regenerated config).
- [ ] Hand the v0.5 tag command to the user per the established release flow (signed tag; user pushes). Bump README/PLAN current-release lines to v0.5.0 in the tagged commit, matching the v0.4.0 release-commit pattern.

## Self-review notes

- **Spec coverage:** §1 finalizer → Task 1; §2 teardown edges → Task 2 (master Secret) + Task 3 (B→A guard); §3 health → Task 5; §4 obrefresh events → Task 6; §5 validation → Task 4; §6 graduation → Task 7. Testing section → per-task TDD + Final verification.
- **Type consistency:** reason consts `ReasonMasterSecretNotFound`, `ReasonFrontendNotReady`, `ReasonBackendsNotReady` (controller pkg), `ReasonReloadConfigFailed`/`ReasonReloadSighupFailed` (onionbalance pkg); helper `modeBHealth`; reused `countReadyBackends`, `setProgrammingCondition`, `cleanupModeBResources`, `r.event`, `BuildFrontendRole`. Names are used identically across the tasks that reference them.
- **Known follow-on adjustments flagged inline:** Task 1 Step 5 and Task 5 Step 5 both warn that pre-existing `updateStatusModeB`/Reconcile tests may need minimal fake-client setup updates once Programmed becomes conditional and the finalizer Update is added — adjust the tests, never the new logic.
