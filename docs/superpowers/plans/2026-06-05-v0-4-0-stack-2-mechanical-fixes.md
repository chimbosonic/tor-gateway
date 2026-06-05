# v0.4.0 — Stack 2: Mechanical fixes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the independent mechanical fixes from the v0.4.0 pre-release review. Each ticket is its own commit. Most are 1-2 file changes with a unit-test gate. They depend on Stack 1's API-fetch architecture being merged.

**Architecture:** Independent commits, parallelizable. Land them sequentially on a single feature branch `feat/v0.4.0-stack-2-mechanical-fixes` off `main`. Each task is TDD: failing test → implementation → passing test → commit.

**Tech Stack:** Go, controller-runtime, kubebuilder, Ginkgo+Gomega tests.

**Tickets covered:** B3, B5, H1, H5, H6, H7, H8, H10, M1, M2, M3, M6, L3, L4, L5, L8, L9.

**Tickets explicitly NOT in this stack:** B1, B2, B4, M4, M5, M7, M8, H3, H4, H9 (Stack 1 or Stack 3 — see the spec). L6, L7, L10 (Stack 3 or already done).

**Spec:** `docs/superpowers/specs/2026-06-05-v0-4-0-release-fixes-design.md` (Stack 2 section).

**Branching:** create `feat/v0.4.0-stack-2-mechanical-fixes` off `main`. Commit each task. Merge to `main` via PR (or local merge after `git rebase --signoff origin/main`).

---

### Task 0: Branch setup

- [ ] **Step 1: Create branch**

```bash
git -C /Volumes/source-code/Personal/torGateway checkout main
git -C /Volumes/source-code/Personal/torGateway pull --ff-only origin main 2>&1 || true   # allowed to fail if offline
git -C /Volumes/source-code/Personal/torGateway checkout -b feat/v0.4.0-stack-2-mechanical-fixes
```

---

### Task 1: H1 — OBP reconciler watches Secrets, Gateway, ReferenceGrant, TorServicePolicy

**Why:** Today `OnionBalancePolicyReconciler.SetupWithManager` only registers `For(OnionBalancePolicy{})`. `status.readyBackends` and the `Accepted` condition therefore never re-converge when those external objects change, until the controller-runtime resync period (default 10h).

**Files:**
- Modify: `internal/controller/onionbalancepolicy_controller.go`
- Test: `internal/controller/onionbalancepolicy_controller_test.go`

- [ ] **Step 1: Write failing test**

Append:

```go
func TestOnionBalancePolicyReconciler_WatchSecretRequeuesOBP(t *testing.T) {
    obp := &policyv1alpha1.OnionBalancePolicy{
        ObjectMeta: metav1.ObjectMeta{Name: "blog-obp", Namespace: "default"},
        Spec: policyv1alpha1.OnionBalancePolicySpec{
            MasterKeySecretRef: gwv1.SecretObjectReference{Name: "ob-master"},
            TargetRefs: []policyv1alpha1.OBPTargetRef{{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "blog"}},
        },
    }
    secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ob-master", Namespace: "default"}}

    r := &OnionBalancePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(obp, secret).Build()}
    reqs := r.obpsForSecret(context.Background(), secret)
    if len(reqs) != 1 || reqs[0].Name != "blog-obp" {
        t.Fatalf("expected 1 request for blog-obp, got %+v", reqs)
    }
}
```

Add similar `TestOnionBalancePolicyReconciler_WatchGatewayRequeuesOBP`, `_WatchReferenceGrantRequeuesOBP`, `_WatchTorServicePolicyRequeuesOBP` — same pattern, different mapping func.

- [ ] **Step 2: Run to verify failure** — `go test ./internal/controller/ -run TestOnionBalancePolicyReconciler_Watch -v`

- [ ] **Step 3: Implement mapping functions + Watches**

Add to `onionbalancepolicy_controller.go`:

```go
// obpsForSecret returns reconcile requests for every OBP referencing the
// changed Secret as its master key.
func (r *OnionBalancePolicyReconciler) obpsForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
    s, ok := obj.(*corev1.Secret)
    if !ok {
        return nil
    }
    var list policyv1alpha1.OnionBalancePolicyList
    if err := r.List(ctx, &list); err != nil {
        return nil
    }
    var out []reconcile.Request
    for i := range list.Items {
        p := &list.Items[i]
        ns := p.Spec.MasterKeySecretRef.Namespace
        if ns == "" {
            ns = p.Namespace
        }
        if ns == s.Namespace && p.Spec.MasterKeySecretRef.Name == s.Name {
            out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: p.Name, Namespace: p.Namespace}})
            continue
        }
        // Also requeue when the Secret looks like a backend key Secret owned by a Gateway the OBP targets.
        if s.Labels["torgateway.io/role"] == "backend" && s.Labels["torgateway.io/gateway"] != "" {
            for _, ref := range p.Spec.TargetRefs {
                if string(ref.Name) == s.Labels["torgateway.io/gateway"] && s.Namespace == p.Namespace {
                    out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: p.Name, Namespace: p.Namespace}})
                }
            }
        }
    }
    return out
}

// obpsForGateway returns OBPs that target the changed Gateway.
func (r *OnionBalancePolicyReconciler) obpsForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
    gw, ok := obj.(*gwv1.Gateway)
    if !ok {
        return nil
    }
    var list policyv1alpha1.OnionBalancePolicyList
    if err := r.List(ctx, &list, client.InNamespace(gw.Namespace)); err != nil {
        return nil
    }
    var out []reconcile.Request
    for i := range list.Items {
        for _, ref := range list.Items[i].Spec.TargetRefs {
            if string(ref.Name) == gw.Name {
                out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: list.Items[i].Name, Namespace: list.Items[i].Namespace}})
            }
        }
    }
    return out
}

// obpsForReferenceGrant returns OBPs whose master Secret namespace matches the grant's namespace
// AND whose gateway namespace matches a "from" entry on the grant.
func (r *OnionBalancePolicyReconciler) obpsForReferenceGrant(ctx context.Context, obj client.Object) []reconcile.Request {
    rg, ok := obj.(*gwv1beta1.ReferenceGrant)
    if !ok {
        return nil
    }
    var list policyv1alpha1.OnionBalancePolicyList
    if err := r.List(ctx, &list); err != nil {
        return nil
    }
    var out []reconcile.Request
    for i := range list.Items {
        p := &list.Items[i]
        if p.Spec.MasterKeySecretRef.Namespace == "" || p.Spec.MasterKeySecretRef.Namespace != rg.Namespace {
            continue
        }
        for _, f := range rg.Spec.From {
            if string(f.Group) == policyv1alpha1.GroupVersion.Group && string(f.Kind) == "OnionBalancePolicy" && string(f.Namespace) == p.Namespace {
                out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: p.Name, Namespace: p.Namespace}})
                break
            }
        }
    }
    return out
}

// obpsForTorServicePolicy returns OBPs targeting any Gateway the TSP targets.
func (r *OnionBalancePolicyReconciler) obpsForTorServicePolicy(ctx context.Context, obj client.Object) []reconcile.Request {
    tsp, ok := obj.(*policyv1alpha1.TorServicePolicy)
    if !ok {
        return nil
    }
    var list policyv1alpha1.OnionBalancePolicyList
    if err := r.List(ctx, &list, client.InNamespace(tsp.Namespace)); err != nil {
        return nil
    }
    var gwNames []string
    for _, ref := range tsp.Spec.TargetRefs {
        gwNames = append(gwNames, string(ref.Name))
    }
    var out []reconcile.Request
    for i := range list.Items {
        for _, ref := range list.Items[i].Spec.TargetRefs {
            for _, n := range gwNames {
                if string(ref.Name) == n {
                    out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: list.Items[i].Name, Namespace: list.Items[i].Namespace}})
                }
            }
        }
    }
    return out
}
```

Wire them into `SetupWithManager`:

```go
return ctrl.NewControllerManagedBy(mgr).
    For(&policyv1alpha1.OnionBalancePolicy{}).
    Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.obpsForSecret)).
    Watches(&gwv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.obpsForGateway)).
    Watches(&gwv1beta1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(r.obpsForReferenceGrant)).
    Watches(&policyv1alpha1.TorServicePolicy{}, handler.EnqueueRequestsFromMapFunc(r.obpsForTorServicePolicy)).
    Complete(r)
```

Add imports: `sigs.k8s.io/controller-runtime/pkg/handler`, `sigs.k8s.io/controller-runtime/pkg/reconcile`, `k8s.io/apimachinery/pkg/types`.

- [ ] **Step 4: Run tests → PASS**

- [ ] **Step 5: Commit**

```bash
git add internal/controller/onionbalancepolicy_controller.go internal/controller/onionbalancepolicy_controller_test.go
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "feat(controller): OBP reconciler watches Secret/Gateway/RG/TSP"
```

---

### Task 2: H5 — `cleanupModeAResources` deletes all Mode A child objects on A→B transition

**Why:** Today the function deletes only the Mode A Deployment + Service. The Mode A NetworkPolicy, `<gw>-keys` Secret, `<gw>-torrc` ConfigMap, vanity Jobs/output Secrets, and router RBAC trio all leak. On a future B→A revert, `ensureKeySecret` reuses the surviving `<gw>-keys` Secret and silently re-publishes the retired onion.

**Files:**
- Modify: `internal/controller/gateway_controller.go`
- Test: `internal/controller/gateway_controller_test.go` (or a new `_cleanup_test.go`)

- [ ] **Step 1: Failing test**

```go
func TestCleanupModeAResources_DeletesAllChildren(t *testing.T) {
    ctx := context.Background()
    gw := sampleGateway()
    deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: DeploymentName(gw.Name), Namespace: gw.Namespace}}
    svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName(gw.Name), Namespace: gw.Namespace}}
    keys := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: KeySecretName(gw.Name), Namespace: gw.Namespace}}
    torrc := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: TorrcConfigMapName(gw.Name), Namespace: gw.Namespace}}
    np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: NetworkPolicyName(gw.Name), Namespace: gw.Namespace}}
    routerSA := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: gw.Namespace}}
    routerRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: gw.Namespace}}
    routerRB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: gw.Namespace}}
    cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw, deploy, svc, keys, torrc, np, routerSA, routerRole, routerRB).Build()
    r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
    if err := r.cleanupModeAResources(ctx, gw); err != nil {
        t.Fatalf("cleanup: %v", err)
    }
    for _, obj := range []struct {
        name string
        get  client.Object
    }{
        {"Deployment", &appsv1.Deployment{}},
        {"Service", &corev1.Service{}},
        {"KeySecret", &corev1.Secret{}},
        {"TorrcConfigMap", &corev1.ConfigMap{}},
        {"NetworkPolicy", &networkingv1.NetworkPolicy{}},
        {"RouterSA", &corev1.ServiceAccount{}},
        {"RouterRole", &rbacv1.Role{}},
        {"RouterRoleBinding", &rbacv1.RoleBinding{}},
    } {
        // (build the right key per type — for simplicity assert by NotFound on Get with the type's name)
    }
}
```

(Use a `t.Run` table; lookup name varies per type. Use the existing name helpers.)

- [ ] **Step 2: Failure** → impl deletes only Deployment + Service, so all other Get calls return NotFound after but ALSO before — write the test to confirm each object existed pre-cleanup and is gone post-cleanup. Adjust accordingly.

- [ ] **Step 3: Implement**

Extend `cleanupModeAResources` to delete all of: Deployment, Service, KeySecret, TorrcConfigMap, NetworkPolicy, Router{SA,Role,RoleBinding}, vanity Jobs (label-selector), vanity output Secrets (label-selector).

```go
toDelete := []client.Object{
    &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: DeploymentName(gw.Name), Namespace: gw.Namespace}},
    &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName(gw.Name), Namespace: gw.Namespace}},
    &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: KeySecretName(gw.Name), Namespace: gw.Namespace}},
    &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: TorrcConfigMapName(gw.Name), Namespace: gw.Namespace}},
    &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: NetworkPolicyName(gw.Name), Namespace: gw.Namespace}},
    &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: gw.Namespace}},
    &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: gw.Namespace}},
    &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RouterRBACName(gw.Name), Namespace: gw.Namespace}},
}
for _, obj := range toDelete {
    if err := client.IgnoreNotFound(r.Delete(ctx, obj)); err != nil {
        return fmt.Errorf("cleanupModeAResources: %T: %w", obj, err)
    }
}
// Vanity Jobs + output Secrets (label-based).
labels := client.MatchingLabels{"app.kubernetes.io/managed-by": "tor-gateway", "torgateway.io/gateway": gw.Name, "torgateway.io/role": "vanity"}
if err := r.DeleteAllOf(ctx, &batchv1.Job{}, client.InNamespace(gw.Namespace), labels); err != nil {
    return fmt.Errorf("vanity Jobs: %w", err)
}
if err := r.DeleteAllOf(ctx, &corev1.Secret{}, client.InNamespace(gw.Namespace), labels); err != nil {
    return fmt.Errorf("vanity output Secrets: %w", err)
}
```

- [ ] **Step 4: Tests pass.**

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "feat(controller): cleanupModeAResources deletes all Mode A children"
```

---

### Task 3: H6 — `ensureModeB` shrink StatefulSet before GC'ing backend Secrets

**Why:** Today `gcOrphanBackendSecrets` runs before `ensureHAStatefulSet`. On scale-down, Secret indices ≥ new replicas are deleted while excess pods still reference them via Projected volumes. After Stack 1 removed the Projected volume, the backend pods API-fetch their own Secret — so this race becomes "init container's API GET 404s during the brief window between Secret delete and pod terminate." Still wrong; fix the ordering.

**Files:**
- Modify: `internal/controller/gateway_controller.go` (`ensureModeB`)
- Test: `internal/controller/gateway_controller_modeb_test.go`

- [ ] **Step 1: Failing test**

```go
func TestEnsureModeB_ScaleDownShrinksBeforeGC(t *testing.T) {
    ctx := context.Background()
    gw := sampleGateway()
    obp := samplePolicy(2) // new replicas = 2
    // Existing StatefulSet at 4 replicas + 4 backend Secrets.
    ss := &appsv1.StatefulSet{
        ObjectMeta: metav1.ObjectMeta{Name: BackendStatefulSetName(gw), Namespace: gw.Namespace},
        Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(4))},
        Status:     appsv1.StatefulSetStatus{Replicas: 4, ReadyReplicas: 4},
    }
    seeds := []client.Object{ss}
    for i := 0; i < 4; i++ {
        seeds = append(seeds, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: BackendKeySecretName(gw, i), Namespace: gw.Namespace}})
    }
    cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(append(seeds, gw, obp)...).Build()
    r := &GatewayReconciler{Client: cl, Scheme: testScheme(t), TorRuntime: testRuntimeImages()}
    _ = r.ensureModeB(ctx, gw, obp)

    // After first reconcile, StatefulSet replicas should be 2 (shrunk) but
    // Secrets 2 and 3 should still exist — GC waits until SS.Status.Replicas
    // reaches Spec.Replicas.
    var got appsv1.StatefulSet
    if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: BackendStatefulSetName(gw)}, &got); err != nil {
        t.Fatalf("get SS: %v", err)
    }
    if *got.Spec.Replicas != 2 {
        t.Errorf("SS spec replicas = %d, want 2", *got.Spec.Replicas)
    }
    for i := 2; i < 4; i++ {
        var s corev1.Secret
        if err := cl.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: BackendKeySecretName(gw, i)}, &s); err != nil {
            t.Errorf("Secret backend-%d unexpectedly gone (should wait for pods): %v", i, err)
        }
    }
}

func TestEnsureModeB_ScaleDownGCsOnceReplicasMatch(t *testing.T) {
    // Same setup but ss.Status.Replicas == ss.Spec.Replicas before ensureModeB.
    // Assert Secrets 2 and 3 are deleted.
}
```

- [ ] **Step 2-4: Implement + verify**

In `ensureModeB`:

```go
// Always reconcile the StatefulSet first so a scale-down request lands.
if err := r.ensureHAStatefulSet(ctx, gw, obp, ...); err != nil { return err }

// GC orphan backend Secrets only when the StatefulSet's actual replicas
// have reached the desired spec — otherwise excess pods may still be
// API-fetching their (about-to-be-deleted) Secret.
var ss appsv1.StatefulSet
if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: BackendStatefulSetName(gw)}, &ss); err == nil {
    if ss.Spec.Replicas != nil && ss.Status.Replicas == *ss.Spec.Replicas {
        if err := r.gcOrphanBackendSecrets(ctx, gw, obp.Spec.Replicas); err != nil { return err }
    } else {
        // Requeue: come back when pods have terminated.
        return ctrl.Result{RequeueAfter: 5 * time.Second}, nil  // adapt return signature
    }
}
```

(Adapt to current `ensureModeB` return type — may be `error`. If it doesn't return `ctrl.Result`, you'll need a different mechanism — set an annotation, return early, and let the Watch on the StatefulSet trigger the next reconcile.)

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): scale-down shrinks StatefulSet before GC'ing backend Secrets"
```

---

### Task 4: H7 — `findEffectiveOnionBalance` lexical tiebreak + per-ancestor Accepted

**Why:** Two issues: (a) when two OBPs target the same Gateway the first match wins — non-deterministic across cache resyncs; (b) the Accepted check OR-aggregates across all ancestors, so an OBP that's Accepted for Gateway A but not B can incorrectly mark B as Accepted.

**Files:**
- Modify: `internal/controller/gateway_controller.go` (`findEffectiveOnionBalance` near line 336)
- Test: `internal/controller/gateway_controller_test.go`

- [ ] **Step 1: Failing tests**

```go
func TestFindEffectiveOnionBalance_LexicalTiebreak(t *testing.T) {
    gw := sampleGateway()
    obpZ := obpTargeting(gw, "obp-zebra")
    obpA := obpTargeting(gw, "obp-alpha")
    obpA.Status = makeAcceptedFor(gw)
    obpZ.Status = makeAcceptedFor(gw)
    cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw, obpA, obpZ).Build()
    r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
    got, _, err := r.findEffectiveOnionBalance(context.Background(), gw)
    if err != nil { t.Fatalf("%v", err) }
    if got == nil || got.Name != "obp-alpha" {
        t.Errorf("got %v, want obp-alpha", got)
    }
}

func TestFindEffectiveOnionBalance_PerAncestorAccepted(t *testing.T) {
    gwA := sampleGatewayName("gw-a")
    gwB := sampleGatewayName("gw-b")
    obp := obpTargetingMany("obp", "gw-a", "gw-b")
    obp.Status = makeAcceptedForOnly(gwA) // gw-b NOT accepted
    cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gwA, gwB, obp).Build()
    r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
    _, accepted, _ := r.findEffectiveOnionBalance(context.Background(), gwB)
    if accepted {
        t.Error("gw-b should NOT see Accepted=true; OBP only accepted for gw-a")
    }
    _, accepted, _ = r.findEffectiveOnionBalance(context.Background(), gwA)
    if !accepted {
        t.Error("gw-a should see Accepted=true")
    }
}
```

- [ ] **Step 2-4: Implement**

Inside `findEffectiveOnionBalance`, change the loop to track `matched` with `if matched == nil || p.Name < matched.Name`. For the Accepted check, iterate `Status.Ancestors` and find the one whose `AncestorRef.Name` matches `gw.Name`; check the `Accepted` condition on THAT ancestor only.

```go
acceptedForGW := func(p *policyv1alpha1.OnionBalancePolicy, gwName string) bool {
    for _, anc := range p.Status.Ancestors {
        if string(anc.AncestorRef.Name) != gwName {
            continue
        }
        for _, c := range anc.Conditions {
            if c.Type == string(gwv1.PolicyConditionAccepted) && c.Status == metav1.ConditionTrue {
                return true
            }
        }
    }
    return false
}
```

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): findEffectiveOnionBalance lexical tiebreak + per-ancestor Accepted"
```

---

### Task 5: M2 — `cleanupModeBResources` precise annotation gate + propagate Update error

**Why:** Today the function does `_ = r.Update(ctx, gw)` whenever `gw.Annotations != nil` — almost every real Gateway carries at least one annotation, so this fires on EVERY Mode A reconcile. Plus the swallowed error hides 409 conflicts.

**Files:**
- Modify: `internal/controller/gateway_controller.go`
- Test: `internal/controller/gateway_controller_test.go`

- [ ] **Step 1: Failing test**

```go
func TestCleanupModeBResources_NoUpdateWhenAnnotationsAbsent(t *testing.T) {
    gw := sampleGateway()
    gw.Annotations = map[string]string{"unrelated": "value"}
    rv := gw.ResourceVersion
    cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw).Build()
    r := &GatewayReconciler{Client: cl, Scheme: testScheme(t)}
    if err := r.cleanupModeBResources(context.Background(), gw); err != nil {
        t.Fatalf("cleanup: %v", err)
    }
    var got gwv1.Gateway
    if err := cl.Get(context.Background(), types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}, &got); err != nil {
        t.Fatalf("get: %v", err)
    }
    if got.ResourceVersion != rv {
        t.Errorf("ResourceVersion changed (%s -> %s); cleanup should not Update when no HA annotations present", rv, got.ResourceVersion)
    }
}
```

- [ ] **Step 2-4: Implement**

Replace:

```go
if gw.Annotations != nil {
    delete(gw.Annotations, annLastReplicas)
    delete(gw.Annotations, annPoWOverride)
    _ = r.Update(ctx, gw)
}
```

with:

```go
_, hasReplicas := gw.Annotations[annLastReplicas]
_, hasPoW := gw.Annotations[annPoWOverride]
if hasReplicas || hasPoW {
    delete(gw.Annotations, annLastReplicas)
    delete(gw.Annotations, annPoWOverride)
    if err := r.Update(ctx, gw); err != nil {
        return fmt.Errorf("cleanupModeBResources: clear annotations: %w", err)
    }
}
```

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): cleanupModeBResources precise annotation gate + propagate error"
```

---

### Task 6: M3 — `updateStatusModeB` retries on 409

**Files:**
- Modify: `internal/controller/gateway_controller.go` (`updateStatusModeB`)
- Test: `internal/controller/gateway_controller_test.go`

- [ ] **Step 1-2: Failing test**

A test that mutates the Gateway's `ResourceVersion` mid-call is fiddly with the fake client. Acceptable alternative: assert that the function wraps both writes in `retry.RetryOnConflict` by reading the source and matching a regexp — OR just trust the unit-test-via-implementation pattern: build a custom client that returns 409 on the first Update and succeeds on the second.

Practical path: write a small wrapper client (`type retryProbeClient struct { client.Client; updateAttempts int }`) that returns `apierrors.NewConflict(...)` on the first `Update` and delegates on subsequent calls. Inject it into the reconciler and assert `updateStatusModeB` returns nil + the expected status was set after the retry.

- [ ] **Step 3-4: Implement**

```go
import "k8s.io/client-go/util/retry"

func (r *GatewayReconciler) updateStatusModeB(ctx context.Context, gw *gwv1.Gateway, master tor.OnionAddress, pol *policyv1alpha1.OnionBalancePolicy) error {
    return retry.RetryOnConflict(retry.DefaultRetry, func() error {
        // existing body — possibly re-fetch gw inside the closure if you want
        // to handle the spec field properly.
        return r.Status().Update(ctx, gw)
    })
}
```

If the function does BOTH `r.Update(gw)` (for annotations) and `r.Status().Update(gw)` separately, wrap each in its own RetryOnConflict — and re-fetch the gateway between them to refresh ResourceVersion.

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): updateStatusModeB retries on 409 Conflict"
```

---

### Task 7: L8 — Drop the 30-second `RequeueAfter` polling when OBP not Accepted

**Files:**
- Modify: `internal/controller/gateway_controller.go` (~line 118)

- [ ] **Step 1: Identify and remove the polling fallback**

Find the code path that returns `ctrl.Result{RequeueAfter: 30 * time.Second}` when the OBP exists but is not Accepted. Replace with `return ctrl.Result{}, nil` — the H1 watches handle re-triggering when the OBP's status changes.

- [ ] **Step 2: Update any test that asserted the 30s requeue.**

- [ ] **Step 3: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "refactor(controller): drop 30s RequeueAfter polling; rely on Watches"
```

---

### Task 8: B3 — Frontend PodSpec sets `shareProcessNamespace: true`

**Why:** Currently `syscall.Kill(pid, SIGHUP)` in `refresher.go` cannot reach the onionbalance daemon because the obrefresh container and the onionbalance container live in separate PID namespaces.

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildFrontendDeployment`)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Failing test**

```go
func TestBuildFrontendDeployment_SharesProcessNamespace(t *testing.T) {
    dep, err := BuildFrontendDeployment(sampleGateway(), samplePolicy(2), tor.OnionAddress{}, sampleImages(), false, testScheme(t))
    if err != nil { t.Fatalf("%v", err) }
    if dep.Spec.Template.Spec.ShareProcessNamespace == nil || !*dep.Spec.Template.Spec.ShareProcessNamespace {
        t.Fatal("frontend PodSpec must set ShareProcessNamespace=true so obrefresh can SIGHUP onionbalance")
    }
}
```

- [ ] **Step 2-3: Implement**

In `BuildFrontendDeployment`'s `corev1.PodSpec`:

```go
ShareProcessNamespace: ptr.To(true),
```

- [ ] **Step 4: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): frontend pod sets shareProcessNamespace for SIGHUP reload"
```

---

### Task 9: M1 — `rebuild()` empty-backends writes empty config + SIGHUPs (not stale)

**Files:**
- Modify: `internal/onionbalance/refresher.go`
- Test: `internal/onionbalance/refresher_test.go`

- [ ] **Step 1: Failing test**

```go
func TestRebuild_EmptyBackends_WritesEmptyConfigAndSighups(t *testing.T) {
    dir := t.TempDir()
    cfg := RefresherConfig{
        // ...required fields including OwnerUID...
        ConfigPath:    filepath.Join(dir, "config.yaml"),
        PIDFile:       filepath.Join(dir, "ob.pid"),
        MasterKeyPath: filepath.Join(dir, "master_sk"),
        Master:        validOnionAddress(t),
    }
    // Pre-seed config.yaml with a stale 3-backend list.
    os.WriteFile(cfg.ConfigPath, []byte("services:\n- instances:\n  - x.onion\n  - y.onion\n  - z.onion\n"), 0o600)
    r, _ := NewRefresher(context.Background(), cfg)
    r.rebuild(context.Background(), nil) // 0 backends
    out, _ := os.ReadFile(cfg.ConfigPath)
    if strings.Contains(string(out), "x.onion") || strings.Contains(string(out), "y.onion") || strings.Contains(string(out), "z.onion") {
        t.Errorf("stale backends still in config.yaml after empty rebuild: %s", out)
    }
    if !strings.Contains(string(out), "instances: []") && !strings.Contains(string(out), "instances:\n") {
        t.Errorf("expected empty-backend config; got %s", out)
    }
}
```

- [ ] **Step 2-3: Implement**

Change the empty-branch in `rebuild` from early-return to "render an empty backends list, write it, SIGHUP." Pass `[]tor.OnionAddress{}` to `Render`.

- [ ] **Step 4-5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(refresher): empty-backends writes empty config instead of leaving stale"
```

---

### Task 10: L3 — `NewRefresher` validates `cfg.Master` non-zero

**Files:**
- Modify: `internal/onionbalance/refresher.go` (`NewRefresher`)
- Test: `internal/onionbalance/refresher_test.go`

- [ ] **Step 1: Failing test**

Append a case to `TestRefresherRequiresMandatoryFields`:

```go
{name: "missing master", cfg: cfgWithout(t, "Master"), wantErr: true},
```

Where `cfgWithout` builds a fully-populated config and zeros the named field.

- [ ] **Step 2-3: Implement**

In `NewRefresher`:

```go
if cfg.Master.Equal(tor.OnionAddress{}) {
    return nil, fmt.Errorf("Master required")
}
```

(If `tor.OnionAddress` has no `Equal` method, compare with a zero literal via `reflect.DeepEqual`, or compare the string form to empty.)

- [ ] **Step 4-5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(refresher): NewRefresher validates cfg.Master is non-zero"
```

---

### Task 11: B5 — Empty-image guards (Mode B builders + manager flag validation)

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildBackendStatefulSet`, `BuildFrontendDeployment`)
- Modify: `cmd/manager/main.go` (post-flag.Parse validation)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Failing tests**

```go
func TestBuildFrontendDeployment_RejectsEmptyImages(t *testing.T) {
    cases := []RuntimeImages{
        {Tor: "", TorInit: "init:x", Onionbalance: "ob:x", Obrefresh: "obr:x"},
        {Tor: "tor:x", TorInit: "", Onionbalance: "ob:x", Obrefresh: "obr:x"},
        {Tor: "tor:x", TorInit: "init:x", Onionbalance: "", Obrefresh: "obr:x"},
        {Tor: "tor:x", TorInit: "init:x", Onionbalance: "ob:x", Obrefresh: ""},
    }
    for _, imgs := range cases {
        _, err := BuildFrontendDeployment(sampleGateway(), samplePolicy(2), tor.OnionAddress{}, imgs, false, testScheme(t))
        if err == nil {
            t.Errorf("expected error for empty image in %+v", imgs)
        }
    }
}

func TestBuildBackendStatefulSet_RejectsEmptyImages(t *testing.T) {
    // Similar for Tor + TorInit (Onionbalance/Obrefresh aren't used by backends).
}
```

- [ ] **Step 2-3: Implement**

In both builders, mirror `gateway_resources.go:187`'s pattern:

```go
if images.Tor == "" || images.TorInit == "" /* etc */ {
    return nil, fmt.Errorf("BuildFrontendDeployment: required image flag not set; check --onionbalance-image, --obrefresh-image, --tor-init-image, --tor-image")
}
```

In `cmd/manager/main.go` after `flag.Parse()`:

```go
if onionbalanceImage == "" || obrefreshImage == "" || torInitImage == "" || torImage == "" {
    fmt.Fprintln(os.Stderr, "fatal: --onionbalance-image, --obrefresh-image, --tor-init-image, --tor-image are required")
    os.Exit(2)
}
```

- [ ] **Step 4-5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller, manager): reject empty image strings for Mode B builds"
```

---

### Task 12: H10 — Liveness probes on onionbalance + obrefresh containers

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildFrontendDeployment`)
- Modify: `cmd/obrefresh/main.go` (new `--healthcheck` flag)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Implement `--healthcheck` flag in obrefresh**

In `cmd/obrefresh/main.go`:

```go
var healthcheck bool
flag.BoolVar(&healthcheck, "healthcheck", false, "exit 0 if the last refresh succeeded within 2× --interval, else exit 1")
// if --healthcheck: read a small status file (e.g. /run/obrefresh/last-success.timestamp) the
// refresher writes on each successful rebuild; compare to time.Now() against 2*RefreshInterval.
```

The refresher writes the timestamp on success — add that to `refresher.go` `rebuild` happy path.

- [ ] **Step 2: Failing test**

```go
func TestBuildFrontendDeployment_OnionbalanceLivenessProbe(t *testing.T) {
    dep, _ := BuildFrontendDeployment(sampleGateway(), samplePolicy(2), tor.OnionAddress{}, sampleImages(), false, testScheme(t))
    for _, c := range dep.Spec.Template.Spec.Containers {
        if c.Name == "onionbalance" || c.Name == "obrefresh" {
            if c.LivenessProbe == nil {
                t.Errorf("%s container missing LivenessProbe", c.Name)
            }
        }
    }
}
```

- [ ] **Step 3-4: Implement** in `BuildFrontendDeployment`:

```go
// onionbalance probe: exec test -f the pidfile + age of config.yaml < 2*RefreshInterval
// obrefresh probe: exec obrefresh --healthcheck
```

Concrete:

```go
Containers: []corev1.Container{
    /* tor (unchanged) */,
    {
        Name: "onionbalance",
        /* ... */
        LivenessProbe: &corev1.Probe{
            ProbeHandler: corev1.ProbeHandler{
                Exec: &corev1.ExecAction{Command: []string{"sh", "-c", "test -s /run/onionbalance/onionbalance.pid"}},
            },
            InitialDelaySeconds: 15,
            PeriodSeconds:       30,
            FailureThreshold:    3,
        },
    },
    {
        Name: "obrefresh",
        /* ... */
        LivenessProbe: &corev1.Probe{
            ProbeHandler: corev1.ProbeHandler{
                Exec: &corev1.ExecAction{Command: []string{"obrefresh", "--healthcheck"}},
            },
            InitialDelaySeconds: 60,
            PeriodSeconds:       30,
            FailureThreshold:    3,
        },
    },
},
```

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "feat(controller, obrefresh): liveness probes on onionbalance + obrefresh"
```

---

### Task 13: L4 — `BuildBackendKeySecret` reuses existing keypair data

**Why:** Today every Mode B reconcile generates a fresh ed25519 keypair via `tor.GenerateKeyPair`, which is then discarded by `ensureBackendKeySecret` if the Secret already exists. Wastes entropy + leaves discarded private keys on the heap until GC.

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildBackendKeySecret`)
- Modify: `internal/controller/gateway_controller.go` (caller `ensureBackendKeySecret`)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Failing test**

```go
func TestBuildBackendKeySecret_ReusesExistingKeypair(t *testing.T) {
    gw := sampleGateway()
    existing := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{Name: BackendKeySecretName(gw, 0), Namespace: gw.Namespace},
        Data: map[string][]byte{
            "hs_ed25519_secret_key": []byte("OLD-SECRET"),
            "hs_ed25519_public_key": []byte("OLD-PUBLIC"),
            "hostname":              []byte("aaaaa.onion\n"),
        },
    }
    s, err := BuildBackendKeySecret(gw, 0, existing, testScheme(t))
    if err != nil { t.Fatalf("%v", err) }
    if !bytes.Equal(s.Data["hs_ed25519_secret_key"], []byte("OLD-SECRET")) {
        t.Errorf("expected existing secret reused; got %q", s.Data["hs_ed25519_secret_key"])
    }
}
```

(The function signature already takes a `*corev1.Secret` argument — the change is to actually USE it when non-nil.)

- [ ] **Step 2-3: Implement**

```go
func BuildBackendKeySecret(gw *gwv1.Gateway, idx int, existing *corev1.Secret, scheme *runtime.Scheme) (*corev1.Secret, error) {
    var data map[string][]byte
    if existing != nil && len(existing.Data["hs_ed25519_secret_key"]) > 0 {
        data = existing.Data
    } else {
        kp, err := tor.GenerateKeyPair(rand.Reader)
        if err != nil { return nil, err }
        data = map[string][]byte{
            "hs_ed25519_secret_key": kp.SecretKeyFile(),
            "hs_ed25519_public_key": kp.PublicKeyFile(),
            "hostname":              []byte(kp.OnionAddress().String() + "\n"), // see Task 14 for the \n
        }
    }
    s := &corev1.Secret{ /* ... */, Data: data}
    // ...
}
```

Update caller to fetch the existing Secret first (if any) before calling.

- [ ] **Step 4-5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "perf(controller): BuildBackendKeySecret reuses existing keypair data"
```

---

### Task 14: L5 — Mode B hostname Secret data format matches Mode A (trailing `\n`)

**Files:**
- Modify: `internal/controller/gateway_resources_ha.go` (`BuildBackendKeySecret`)
- Modify: `internal/onionbalance/refresher.go` (docstring for `HostnameField`)
- Test: `internal/controller/gateway_resources_ha_test.go`

- [ ] **Step 1: Failing test**

```go
func TestBuildBackendKeySecret_HostnameHasTrailingNewline(t *testing.T) {
    s, _ := BuildBackendKeySecret(sampleGateway(), 0, nil, testScheme(t))
    if !bytes.HasSuffix(s.Data["hostname"], []byte(".onion\n")) {
        t.Errorf("hostname must end with .onion\\n to match Mode A; got %q", s.Data["hostname"])
    }
}
```

- [ ] **Step 2-3: Append `\n` when building the hostname value (already shown in Task 13 above).**

- [ ] **Step 4: Update the `HostnameField` docstring in `refresher.go` if it makes claims about format.**

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): backend Secret hostname carries trailing newline (mirrors Mode A)"
```

---

### Task 15: L9 — `updateStatusModeB` merges into `Status.Addresses` instead of replacing

**Files:**
- Modify: `internal/controller/gateway_controller.go` (`updateStatusModeB`)
- Test: `internal/controller/gateway_controller_test.go`

- [ ] **Step 1: Failing test**

```go
func TestUpdateStatusModeB_PreservesExistingAddressesOfOtherTypes(t *testing.T) {
    gw := sampleGateway()
    gw.Status.Addresses = []gwv1.GatewayStatusAddress{
        {Type: ptr.To(gwv1.HostnameAddressType), Value: "external.example"},
    }
    master := tor.OnionAddress{ /* ... valid ... */ }
    r := &GatewayReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(gw).Build(), Scheme: testScheme(t)}
    _ = r.updateStatusModeB(context.Background(), gw, master, samplePolicy(2))

    var got gwv1.Gateway
    _ = r.Get(context.Background(), client.ObjectKeyFromObject(gw), &got)
    var sawHostname, sawOnion bool
    for _, a := range got.Status.Addresses {
        if a.Value == "external.example" { sawHostname = true }
        if strings.HasSuffix(a.Value, ".onion") { sawOnion = true }
    }
    if !sawHostname { t.Error("expected preexisting hostname address preserved") }
    if !sawOnion    { t.Error("expected master onion address added") }
}
```

- [ ] **Step 2-3: Implement** — replace the unconditional slice replacement with a merge that keeps non-onion entries and replaces (or appends) the master onion.

- [ ] **Step 5: Commit**

```bash
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(controller): updateStatusModeB merges Status.Addresses instead of replacing"
```

---

### Task 16: H8 — CRD `OnionBalancePolicy.Replicas` max reverts to 12

**Why:** Mode B stays experimental in v0.4.0. The tightened cap (12→8) in v0.3.3 broke compat with stored OBPs created against the old schema. Revert to 12 for v0.4.0; consider tightening in v0.5 when graduating.

**Files:**
- Modify: `api/v1alpha1/onionbalancepolicy_types.go`
- Regenerated: `config/crd/bases/policy.torgateway.io_onionbalancepolicies.yaml`, `charts/tor-gateway/files/crds/policy.torgateway.io_onionbalancepolicies.yaml`
- Test: `internal/controller/validation_test.go` (if it asserts the cap)

- [ ] **Step 1: Change the kubebuilder marker**

```go
// +kubebuilder:validation:Maximum=12
Replicas int32 `json:"replicas"`
```

- [ ] **Step 2: Regenerate**

```bash
make generate
make manifests
make chart-sync
```

- [ ] **Step 3: Update / verify any test asserting the cap.**

- [ ] **Step 4: Commit**

```bash
git add api/ config/ charts/
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "revert(api): relax OnionBalancePolicy.Replicas max back to 12 for compat"
```

---

### Task 17: M6 — `RefreshInterval` lower bound (CEL + programmatic clamp)

**Files:**
- Modify: `api/v1alpha1/onionbalancepolicy_types.go`
- Modify: `internal/onionbalance/refresher.go` (`NewRefresher` clamp)
- Test: `internal/onionbalance/refresher_test.go`

- [ ] **Step 1: Add CEL validation on the field**

```go
// +kubebuilder:default="30s"
// +kubebuilder:validation:Format=duration
// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('5s')",message="refreshInterval must be at least 5s"
RefreshInterval metav1.Duration `json:"refreshInterval,omitempty"`
```

- [ ] **Step 2: Programmatic clamp in `NewRefresher`**

```go
const minInterval = 5 * time.Second
if cfg.Interval > 0 && cfg.Interval < minInterval {
    slog.Warn("refresher: clamping interval to minimum", "got", cfg.Interval, "min", minInterval)
    cfg.Interval = minInterval
}
```

- [ ] **Step 3: Failing test**

```go
func TestNewRefresher_ClampsTooShortInterval(t *testing.T) {
    cfg := /* valid base config */
    cfg.Interval = 1 * time.Millisecond
    r, err := NewRefresher(context.Background(), cfg)
    if err != nil { t.Fatalf("%v", err) }
    if r.cfg.Interval < 5*time.Second {
        t.Errorf("interval not clamped; got %v", r.cfg.Interval)
    }
}
```

- [ ] **Step 4: Regenerate manifests + chart sync**

- [ ] **Step 5: Commit**

```bash
git add api/ config/ charts/ internal/onionbalance/
git commit --no-gpg-sign --author="Alexis Lowe <claude-sonnet-4-6@chimbosonic.com>" -m "fix(api, refresher): OBP.refreshInterval has a 5s lower bound"
```

---

### Task 18: Final sanity sweep

- [ ] **Step 1: `make test` end to end**

Run: `make test`. All tests pass.

- [ ] **Step 2: `make generate && make manifests && make chart-sync`**

Run them. `git status -s` should be clean. If anything drifted, stage + commit as a `chore:` commit.

- [ ] **Step 3: `make build`**

Confirm all binaries compile.

- [ ] **Step 4: Branch summary**

`git log --oneline main..HEAD` — should show roughly 17 commits, one per task plus possibly a chore commit.

- [ ] **Step 5: Report to user**

```
Stack 2 complete on branch feat/v0.4.0-stack-2-mechanical-fixes.

Tickets: B3, B5, H1, H5, H6, H7, H8, H10, M1, M2, M3, M6, L3, L4, L5, L8, L9.
Pending: Stack 3 (NetworkPolicy + chart + docs + e2e).

Ready for git rebase --signoff origin/main + push + PR.
```

---

## Self-review notes

**Spec coverage check:** B3 ✓ (Task 8), B5 ✓ (Task 11), H1 ✓ (Task 1), H5 ✓ (Task 2), H6 ✓ (Task 3), H7 ✓ (Task 4), H8 ✓ (Task 16), H10 ✓ (Task 12), M1 ✓ (Task 9), M2 ✓ (Task 5), M3 ✓ (Task 6), M6 ✓ (Task 17), L3 ✓ (Task 10), L4 ✓ (Task 13), L5 ✓ (Task 14), L8 ✓ (Task 7), L9 ✓ (Task 15).

**Cross-task consistency:** Task 13 references trailing `\n` (Task 14's concern); both touch `BuildBackendKeySecret`. Implementer can land Task 14 first or fold them — either works.

**Tests:** Each task ships a unit test. Integration smoke (chutney e2e) runs in Task 18 / handoff.

**Deferred / acknowledged gaps:**
- The M3 fake-client retry test requires a custom client wrapper; if too fiddly, an implementer may settle for asserting the retry call via source-code regex. Note it as a known compromise.
- L9 currently has no production use of multi-address `.status` outside Mode B/A — the test is forward-looking.
