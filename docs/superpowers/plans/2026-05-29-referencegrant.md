# Cross-Namespace ReferenceGrant (backendRefs) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **TDD is mandatory: write the failing test, run it to confirm it fails, then the minimal implementation, then green, then commit. Never write production code before a failing test exists for it.**

**Goal:** Gate cross-namespace HTTPRoute `backendRefs` behind a Gateway-API `ReferenceGrant` — the operator evaluates grants and sets the route's `ResolvedRefs` status, and the in-pod router fails closed (won't proxy to an un-permitted cross-namespace backend) with no new sidecar RBAC.

**Architecture:** Controller is the authority. A pure `Allows` evaluator decides whether a `ReferenceGrant` permits a reference. The HTTPRoute reconciler evaluates each cross-namespace `backendRef` against grants in the backend's namespace, sets `ResolvedRefs=True|False(RefNotPermitted)` per parent, and watches `ReferenceGrant`s. The router reads that status and drops cross-namespace backends on routes whose refs aren't resolved (same-namespace backends are never gated).

**Tech Stack:** Go 1.26, controller-runtime, kubebuilder, Gateway API v1.5.1 (`ReferenceGrant` served as `v1beta1`), Ginkgo+envtest, plain `testing`.

**Scope note:** Cross-namespace `clientsSecretRef` is explicitly OUT of scope (it needs a Secret-copy subsystem — see the spec's Non-goals). This plan touches only backendRefs. The `Allows` evaluator is built for reuse by that future feature.

---

## File Structure

**New files:**
- `internal/controller/referencegrant.go` — pure `Allows(grants, from, to)` evaluator + `FromRef`/`ToRef` types.
- `internal/controller/referencegrant_test.go` — table-driven unit tests for `Allows`.

**Modified files:**
- `cmd/manager/main.go` — register the gateway-api `v1beta1` scheme.
- `internal/controller/suite_test.go` — register `v1beta1` in the envtest scheme.
- `internal/controller/httproute_controller.go` — `ResolvedRefs` status, backendRef evaluation, `ReferenceGrant` watch + map func, RBAC marker.
- `internal/controller/httproute_controller_test.go` — envtest specs for the status outcomes.
- `internal/router/aggregate.go` — gate cross-namespace backends on `ResolvedRefs`; new `refsResolvedFor` + `dropCrossNSBackends` helpers.
- `internal/router/aggregate_test.go` — unit tests for the new helpers + gating.
- `config/rbac/role.yaml`, `charts/tor-gateway/files/rbac/manager-role-rules.yaml` — regenerated (`referencegrants` read).

**Conventions:** Apache header on new `.go` files (copy from `internal/controller/names.go`). The repo aliases `gwv1 "sigs.k8s.io/gateway-api/apis/v1"`; add `gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"` where needed. Commit with `git -c commit.gpgsign=false commit` (the human signs before pushing); no `Co-Authored-By` trailer.

---

### Task 1: Pure ReferenceGrant evaluator

**Files:**
- Create: `internal/controller/referencegrant.go`
- Test: `internal/controller/referencegrant_test.go`

- [ ] **Step 1: Write the failing table-driven test**

Create `internal/controller/referencegrant_test.go` (Apache header, then):

```go
package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func grant(ns string, from gwv1beta1.ReferenceGrantFrom, to gwv1beta1.ReferenceGrantTo) gwv1beta1.ReferenceGrant {
	return gwv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: ns},
		Spec:       gwv1beta1.ReferenceGrantSpec{From: []gwv1beta1.ReferenceGrantFrom{from}, To: []gwv1beta1.ReferenceGrantTo{to}},
	}
}

func TestAllows(t *testing.T) {
	httpRouteFrom := gwv1beta1.ReferenceGrantFrom{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: "team-a"}
	serviceToAny := gwv1beta1.ReferenceGrantTo{Group: "", Kind: "Service"}
	serviceToNamed := gwv1beta1.ReferenceGrantTo{Group: "", Kind: "Service", Name: ptr.To(gwv1.ObjectName("app"))}

	from := FromRef{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: "team-a"}
	to := ToRef{Group: "", Kind: "Service", Name: "app"}

	tests := []struct {
		name   string
		grants []gwv1beta1.ReferenceGrant
		from   FromRef
		to     ToRef
		want   bool
	}{
		{"any-name grant permits", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToAny)}, from, to, true},
		{"named grant permits matching name", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToNamed)}, from, to, true},
		{"named grant denies other name", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToNamed)}, from, ToRef{Group: "", Kind: "Service", Name: "other"}, false},
		{"wrong from namespace denies", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, serviceToAny)}, FromRef{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: "team-x"}, to, false},
		{"wrong to kind denies", []gwv1beta1.ReferenceGrant{grant("team-b", httpRouteFrom, gwv1beta1.ReferenceGrantTo{Group: "", Kind: "Secret"})}, from, to, false},
		{"no grants denies", nil, from, to, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Allows(tc.grants, tc.from, tc.to); got != tc.want {
				t.Errorf("Allows = %v, want %v", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/controller/ -run TestAllows`
Expected: FAIL — `undefined: Allows` / `undefined: FromRef` / `undefined: ToRef`.

- [ ] **Step 3: Implement the evaluator**

Create `internal/controller/referencegrant.go` (Apache header, then):

```go
package controller

import gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

// FromRef identifies the referrer (group/kind/namespace) in a cross-namespace
// reference being authorized.
type FromRef struct{ Group, Kind, Namespace string }

// ToRef identifies the referent (group/kind/name). Core API group is "".
type ToRef struct{ Group, Kind, Name string }

// Allows reports whether any ReferenceGrant permits the from→to reference. A
// grant permits it when it has a matching `from` entry AND a matching `to`
// entry (a `to` with empty Name matches any object of that group/kind). The
// caller must pass grants from the referent's (to) namespace.
func Allows(grants []gwv1beta1.ReferenceGrant, from FromRef, to ToRef) bool {
	for i := range grants {
		g := &grants[i]
		if grantMatchesFrom(g, from) && grantMatchesTo(g, to) {
			return true
		}
	}
	return false
}

func grantMatchesFrom(g *gwv1beta1.ReferenceGrant, from FromRef) bool {
	for _, f := range g.Spec.From {
		if string(f.Group) == from.Group && string(f.Kind) == from.Kind && string(f.Namespace) == from.Namespace {
			return true
		}
	}
	return false
}

func grantMatchesTo(g *gwv1beta1.ReferenceGrant, to ToRef) bool {
	for _, t := range g.Spec.To {
		if string(t.Group) != to.Group || string(t.Kind) != to.Kind {
			continue
		}
		if t.Name == nil || string(*t.Name) == "" || string(*t.Name) == to.Name {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/controller/ -run TestAllows -v`
Expected: PASS (all sub-cases).

- [ ] **Step 5: Commit**

```bash
git add internal/controller/referencegrant.go internal/controller/referencegrant_test.go
git -c commit.gpgsign=false commit -m "feat(controller): pure ReferenceGrant Allows evaluator"
```

---

### Task 2: Register the gateway-api v1beta1 scheme

`ReferenceGrant` is served as `v1beta1`; the manager and envtest currently register only `apis/v1`. Without this, listing/watching `ReferenceGrant` fails. Plumbing — verified by build + existing suite.

**Files:**
- Modify: `cmd/manager/main.go`
- Modify: `internal/controller/suite_test.go`

- [ ] **Step 1: Register v1beta1 in the manager scheme**

In `cmd/manager/main.go`, add the import `gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"` alongside the existing `gwv1 "sigs.k8s.io/gateway-api/apis/v1"`. Then, immediately after the existing `utilruntime.Must(gwv1.Install(scheme))` line, add:

```go
	utilruntime.Must(gwv1beta1.Install(scheme))
```

- [ ] **Step 2: Register v1beta1 in the envtest scheme**

In `internal/controller/suite_test.go`, add the same `gwv1beta1` import. After the existing `err = gwv1.Install(scheme.Scheme)` / `Expect(err).NotTo(HaveOccurred())` block, add:

```go
	err = gwv1beta1.Install(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
```

- [ ] **Step 3: Verify build + existing tests pass**

Run: `go build ./... && make test`
Expected: builds; all existing specs still PASS (no behavior change — only a new type registered).

- [ ] **Step 4: Commit**

```bash
git add cmd/manager/main.go internal/controller/suite_test.go
git -c commit.gpgsign=false commit -m "chore(controller): register gateway-api v1beta1 scheme (ReferenceGrant)"
```

---

### Task 3: HTTPRoute reconciler — ResolvedRefs + ReferenceGrant watch + RBAC

**Files:**
- Modify: `internal/controller/httproute_controller.go`
- Test: `internal/controller/httproute_controller_test.go`
- Regenerate: `config/rbac/role.yaml`, `charts/tor-gateway/files/rbac/manager-role-rules.yaml`

- [ ] **Step 1: Write the failing envtest specs**

In `internal/controller/httproute_controller_test.go`, add a new `Describe` block (uses the package's existing `k8sClient`, `ctx`; imports `corev1`, `rbacv1`-not-needed, `gwv1`, `gwv1beta1`, `metav1`, `types`, `reconcile`, `ptr` — add any missing to the file's import block). Use a dedicated GatewayClass name to avoid cross-spec collisions:

```go
var _ = Describe("HTTPRoute cross-namespace ReferenceGrant", func() {
	const gwNS = "default"
	const backendNS = "rg-backends"

	reconcileRoute := func(name string) error {
		r := &HTTPRouteReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: gwNS, Name: name}})
		return err
	}

	resolvedReason := func(routeName, gwName string) string {
		route := &gwv1.HTTPRoute{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: gwNS, Name: routeName}, route)).To(Succeed())
		for _, p := range route.Status.Parents {
			if string(p.ParentRef.Name) != gwName || p.ControllerName != ControllerName {
				continue
			}
			for _, c := range p.Conditions {
				if c.Type == string(gwv1.RouteConditionResolvedRefs) {
					return c.Reason
				}
			}
		}
		return ""
	}

	BeforeEach(func() {
		_ = k8sClient.Create(ctx, &gwv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "tor-gateway-rg"},
			Spec:       gwv1.GatewayClassSpec{ControllerName: ControllerName},
		})
		_ = k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: backendNS}})
		gw := &gwv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "rg-gw", Namespace: gwNS},
			Spec: gwv1.GatewaySpec{
				GatewayClassName: "tor-gateway-rg",
				Listeners:        []gwv1.Listener{{Name: "onion", Port: 80, Protocol: HiddenServiceProtocol}},
			},
		}
		_ = k8sClient.Create(ctx, gw)
	})

	makeRoute := func(name string, backendNamespace *gwv1.Namespace) {
		route := &gwv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gwNS},
			Spec: gwv1.HTTPRouteSpec{
				CommonRouteSpec: gwv1.CommonRouteSpec{ParentRefs: []gwv1.ParentReference{{Name: "rg-gw"}}},
				Rules: []gwv1.HTTPRouteRule{{
					BackendRefs: []gwv1.HTTPBackendRef{{BackendRef: gwv1.BackendRef{
						BackendObjectReference: gwv1.BackendObjectReference{Name: "app", Namespace: backendNamespace, Port: ptr.To(gwv1.PortNumber(80))},
					}}},
				}},
			},
		}
		Expect(k8sClient.Create(ctx, route)).To(Succeed())
	}

	It("denies a cross-namespace backendRef with no grant", func() {
		bns := gwv1.Namespace(backendNS)
		makeRoute("rg-route-deny", &bns)
		Expect(reconcileRoute("rg-route-deny")).To(Succeed())
		Expect(resolvedReason("rg-route-deny", "rg-gw")).To(Equal(string(gwv1.RouteReasonRefNotPermitted)))
	})

	It("permits a cross-namespace backendRef with a matching grant", func() {
		bns := gwv1.Namespace(backendNS)
		makeRoute("rg-route-allow", &bns)
		Expect(k8sClient.Create(ctx, &gwv1beta1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-routes", Namespace: backendNS},
			Spec: gwv1beta1.ReferenceGrantSpec{
				From: []gwv1beta1.ReferenceGrantFrom{{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: gwNS}},
				To:   []gwv1beta1.ReferenceGrantTo{{Group: "", Kind: "Service"}},
			},
		})).To(Succeed())
		Expect(reconcileRoute("rg-route-allow")).To(Succeed())
		Expect(resolvedReason("rg-route-allow", "rg-gw")).To(Equal(string(gwv1.RouteReasonResolvedRefs)))
	})

	It("permits a same-namespace backendRef with no grant", func() {
		makeRoute("rg-route-samens", nil)
		Expect(reconcileRoute("rg-route-samens")).To(Succeed())
		Expect(resolvedReason("rg-route-samens", "rg-gw")).To(Equal(string(gwv1.RouteReasonResolvedRefs)))
	})
})
```

- [ ] **Step 2: Run to verify the deny spec fails**

Run: `go test ./internal/controller/ -run TestControllers 2>&1 | grep -iA2 "cross-namespace ReferenceGrant"`
Expected: `denies a cross-namespace backendRef with no grant` FAILS — the reconciler doesn't set a `ResolvedRefs` condition yet, so `resolvedReason` returns `""`, not `RefNotPermitted`.

- [ ] **Step 3: Add the backendRef evaluator + ResolvedRefs status**

In `internal/controller/httproute_controller.go`:

Add imports: `"k8s.io/apimachinery/pkg/types"`, `"sigs.k8s.io/controller-runtime/pkg/handler"`, `"sigs.k8s.io/controller-runtime/pkg/reconcile"`, `gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"`.

Add the RBAC marker next to the existing httproutes markers (around line 39):

```go
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=referencegrants,verbs=get;list;watch
```

Add the evaluator method:

```go
// backendRefsPermitted reports whether every cross-namespace backendRef in the
// route is authorized by a ReferenceGrant in the backend's namespace.
// Same-namespace backendRefs never require a grant.
func (r *HTTPRouteReconciler) backendRefsPermitted(ctx context.Context, route *gwv1.HTTPRoute) (bool, error) {
	for _, rule := range route.Spec.Rules {
		for _, bref := range rule.BackendRefs {
			ns := route.Namespace
			if bref.Namespace != nil {
				ns = string(*bref.Namespace)
			}
			if ns == route.Namespace {
				continue
			}
			grants := &gwv1beta1.ReferenceGrantList{}
			if err := r.List(ctx, grants, client.InNamespace(ns)); err != nil {
				return false, err
			}
			ok := Allows(grants.Items,
				FromRef{Group: GatewayAPIGroup, Kind: "HTTPRoute", Namespace: route.Namespace},
				ToRef{Group: "", Kind: "Service", Name: string(bref.Name)})
			if !ok {
				return false, nil
			}
		}
	}
	return true, nil
}
```

In `buildRouteParentStatuses`, replace the `out = append(out, gwv1.RouteParentStatus{...})` block so each managed parent carries BOTH the Accepted condition and a ResolvedRefs condition:

```go
		resolved, err := r.backendRefsPermitted(ctx, route)
		if err != nil {
			return nil, err
		}
		resolvedCond := metav1.Condition{
			Type:               string(gwv1.RouteConditionResolvedRefs),
			Status:             metav1.ConditionTrue,
			Reason:             string(gwv1.RouteReasonResolvedRefs),
			Message:            "All backendRefs resolved",
			ObservedGeneration: route.Generation,
			LastTransitionTime: metav1.Now(),
		}
		if !resolved {
			resolvedCond.Status = metav1.ConditionFalse
			resolvedCond.Reason = string(gwv1.RouteReasonRefNotPermitted)
			resolvedCond.Message = "a cross-namespace backendRef is not permitted by any ReferenceGrant"
		}
		out = append(out, gwv1.RouteParentStatus{
			ParentRef:      pr,
			ControllerName: ControllerName,
			Conditions:     []metav1.Condition{cond, resolvedCond},
		})
```

- [ ] **Step 4: Add the ReferenceGrant watch + map func**

Add the map function:

```go
// httproutesForReferenceGrant enqueues HTTPRoutes located in each namespace a
// changed ReferenceGrant grants FROM (Kind=HTTPRoute), so their ResolvedRefs
// are recomputed when grants are added or removed.
func (r *HTTPRouteReconciler) httproutesForReferenceGrant(ctx context.Context, obj client.Object) []reconcile.Request {
	grant, ok := obj.(*gwv1beta1.ReferenceGrant)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	var reqs []reconcile.Request
	for _, f := range grant.Spec.From {
		if string(f.Group) != gwv1.GroupName || string(f.Kind) != "HTTPRoute" {
			continue
		}
		ns := string(f.Namespace)
		if _, dup := seen[ns]; dup {
			continue
		}
		seen[ns] = struct{}{}
		routes := &gwv1.HTTPRouteList{}
		if err := r.List(ctx, routes, client.InNamespace(ns)); err != nil {
			continue
		}
		for i := range routes.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: routes.Items[i].Namespace, Name: routes.Items[i].Name,
			}})
		}
	}
	return reqs
}
```

Update `SetupWithManager`:

```go
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.HTTPRoute{}).
		Watches(&gwv1beta1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(r.httproutesForReferenceGrant)).
		Named("httproute").
		Complete(r)
}
```

- [ ] **Step 5: Run the envtest specs to verify they pass**

Run: `go test ./internal/controller/ -run TestControllers 2>&1 | tail -3`
Expected: `ok` — all three new specs pass and no regression in existing HTTPRoute/Gateway/policy specs.

- [ ] **Step 6: Regenerate operator + chart RBAC**

Run:
```bash
make manifests
grep -A4 'referencegrants' config/rbac/role.yaml
make chart-sync
git diff --stat config/rbac/ charts/
```
Expected: `config/rbac/role.yaml` gains a `referencegrants` `get;list;watch` rule; `charts/tor-gateway/files/rbac/manager-role-rules.yaml` updated to match.

- [ ] **Step 7: Commit**

```bash
git add internal/controller/httproute_controller.go internal/controller/httproute_controller_test.go config/rbac/role.yaml charts/tor-gateway/files/rbac/
git -c commit.gpgsign=false commit -m "feat(controller): ReferenceGrant-gated ResolvedRefs for cross-ns backendRefs"
```

---

### Task 4: Router fail-closed gate

The router includes a cross-namespace backend only when the route's `ResolvedRefs` (for our Gateway parent) is True. Implemented as two pure helpers used by `rulesForGateway`; `RulesFromHTTPRoute`/`convertBackends` stay unchanged (no churn to existing router tests).

**Files:**
- Modify: `internal/router/aggregate.go`
- Test: `internal/router/aggregate_test.go`

- [ ] **Step 1: Write the failing tests**

In `internal/router/aggregate_test.go` (create if absent, Apache header + `package router`; if it exists, append these and add any missing imports — `metav1`, `gwv1`, `types`):

```go
func resolvedRoute(routeNS, gwName string, status metav1.ConditionStatus, withCond bool) gwv1.HTTPRoute {
	r := gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: routeNS},
		Spec: gwv1.HTTPRouteSpec{
			CommonRouteSpec: gwv1.CommonRouteSpec{ParentRefs: []gwv1.ParentReference{{Name: gwv1.ObjectName(gwName)}}},
			Rules: []gwv1.HTTPRouteRule{{BackendRefs: []gwv1.HTTPBackendRef{
				{BackendRef: gwv1.BackendRef{BackendObjectReference: gwv1.BackendObjectReference{Name: "local", Port: ptrPort(80)}}},
				{BackendRef: gwv1.BackendRef{BackendObjectReference: gwv1.BackendObjectReference{Name: "remote", Namespace: nsPtr("other"), Port: ptrPort(80)}}},
			}}},
		},
	}
	if withCond {
		r.Status.Parents = []gwv1.RouteParentStatus{{
			ParentRef:  gwv1.ParentReference{Name: gwv1.ObjectName(gwName)},
			Conditions: []metav1.Condition{{Type: string(gwv1.RouteConditionResolvedRefs), Status: status}},
		}}
	}
	return r
}

func ptrPort(p int32) *gwv1.PortNumber { v := gwv1.PortNumber(p); return &v }
func nsPtr(s string) *gwv1.Namespace   { v := gwv1.Namespace(s); return &v }

func backendNames(rules []Rule) []string {
	var out []string
	for _, r := range rules {
		for _, b := range r.Backends {
			out = append(out, b.Name)
		}
	}
	return out
}

func TestRulesForGatewayDropsUnresolvedCrossNS(t *testing.T) {
	gw := types.NamespacedName{Namespace: "gwns", Name: "gw"}

	// ResolvedRefs=True → both backends kept.
	ok := resolvedRoute("gwns", "gw", metav1.ConditionTrue, true)
	if got := backendNames(rulesForGateway([]gwv1.HTTPRoute{ok}, gw)); len(got) != 2 {
		t.Errorf("resolved: backends = %v, want both", got)
	}

	// ResolvedRefs=False → cross-ns "remote" dropped, same-ns "local" kept.
	bad := resolvedRoute("gwns", "gw", metav1.ConditionFalse, true)
	got := backendNames(rulesForGateway([]gwv1.HTTPRoute{bad}, gw))
	if len(got) != 1 || got[0] != "local" {
		t.Errorf("unresolved: backends = %v, want [local]", got)
	}

	// No ResolvedRefs condition → fail closed, cross-ns dropped.
	none := resolvedRoute("gwns", "gw", metav1.ConditionFalse, false)
	got = backendNames(rulesForGateway([]gwv1.HTTPRoute{none}, gw))
	if len(got) != 1 || got[0] != "local" {
		t.Errorf("missing condition: backends = %v, want [local]", got)
	}
}
```

(The route's parentRef has no explicit namespace, so it defaults to the route namespace `gwns`, matching `gw`.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/router/ -run TestRulesForGatewayDropsUnresolvedCrossNS`
Expected: FAIL — currently `rulesForGateway` keeps all backends, so the unresolved cases return 2 backends, not 1.

- [ ] **Step 3: Implement the gate**

In `internal/router/aggregate.go`, add `metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"` to the imports. Replace `rulesForGateway` and add the two helpers:

```go
func rulesForGateway(routes []gwv1.HTTPRoute, gw types.NamespacedName) []Rule {
	var rules []Rule
	for _, route := range routes {
		if !routeTargetsGateway(route, gw) {
			continue
		}
		rls := RulesFromHTTPRoute(route)
		if !refsResolvedFor(route, gw) {
			rls = dropCrossNSBackends(rls, route.Namespace)
		}
		rules = append(rules, rls...)
	}
	return rules
}

// refsResolvedFor reports whether route's ResolvedRefs condition is True for
// the parent gw. Missing/False is treated as not resolved (fail closed), so
// cross-namespace backends are excluded until the controller authorizes them.
func refsResolvedFor(route gwv1.HTTPRoute, gw types.NamespacedName) bool {
	for _, p := range route.Status.Parents {
		if string(p.ParentRef.Name) != gw.Name {
			continue
		}
		ns := route.Namespace
		if p.ParentRef.Namespace != nil {
			ns = string(*p.ParentRef.Namespace)
		}
		if ns != gw.Namespace {
			continue
		}
		for _, c := range p.Conditions {
			if c.Type == string(gwv1.RouteConditionResolvedRefs) {
				return c.Status == metav1.ConditionTrue
			}
		}
	}
	return false
}

// dropCrossNSBackends removes backends whose namespace differs from routeNS.
func dropCrossNSBackends(rules []Rule, routeNS string) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		kept := make([]Backend, 0, len(r.Backends))
		for _, b := range r.Backends {
			if b.Namespace == routeNS {
				kept = append(kept, b)
			}
		}
		r.Backends = kept
		out = append(out, r)
	}
	return out
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/router/ -v -run TestRulesForGatewayDropsUnresolvedCrossNS`
Expected: PASS. Also run the full router package: `go test ./internal/router/` — Expected: PASS (existing tests untouched; `RulesFromHTTPRoute`/`convertBackends` signatures unchanged).

- [ ] **Step 5: Commit**

```bash
git add internal/router/aggregate.go internal/router/aggregate_test.go
git -c commit.gpgsign=false commit -m "feat(router): fail closed on cross-ns backends until ResolvedRefs is True"
```

---

### Task 5: Full verification gate

**Files:** none (verification only)

- [ ] **Step 1: Generate, build, vet — confirm clean tree**

Run:
```bash
make manifests generate fmt vet
git diff --exit-code
```
Expected: clean (the only generated change — the `referencegrants` RBAC — was committed in Task 3).

- [ ] **Step 2: Full unit + envtest suite**

Run: `make test`
Expected: PASS, including `TestAllows`, the new HTTPRoute ReferenceGrant specs, and `TestRulesForGatewayDropsUnresolvedCrossNS`.

- [ ] **Step 3: Lint**

Run: `make lint`
Expected: `0 issues`.

- [ ] **Step 4: Chart drift guard**

Run: `make chart-sync && git diff --exit-code charts/`
Expected: clean (chart RBAC already synced in Task 3).

- [ ] **Step 5: Final commit (only if anything changed)**

```bash
git add -A
git -c commit.gpgsign=false commit -m "chore(referencegrant): regenerate + verify" || echo "nothing to commit"
```

---

## Notes for the implementer

- **Least-privilege preserved:** only the operator gains `referencegrants` read (Task 3 RBAC marker). The router sidecar's RBAC is unchanged — it enforces purely by reading `ResolvedRefs` status it already receives.
- **Route-level granularity is intended:** a route mixing a permitted and an un-permitted cross-ns backend resolves to `RefNotPermitted`, and the router drops all of that route's cross-ns backends (fail-closed). Same-namespace backends are never gated.
- **Why `RulesFromHTTPRoute` is left unchanged:** the gate lives in `rulesForGateway` + helpers so existing router tests and the pure conversion API don't churn.
- **Out of scope:** cross-ns `clientsSecretRef` (needs a Secret-copy subsystem) and `BackendNotFound` (Service existence) — see the spec.
