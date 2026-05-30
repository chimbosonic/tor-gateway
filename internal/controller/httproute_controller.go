/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
)

// HTTPRouteReconciler accepts HTTPRoutes whose ParentRefs target a Gateway
// managed by this controller. It writes the per-parent route status (with
// our ControllerName) and updates the parent Gateway's per-listener
// AttachedRoutes counter.
//
// It does NOT yet program the data path: actual request routing is handled
// in-pod by the router sidecar reading HTTPRoutes via its own informer.
type HTTPRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=referencegrants,verbs=get;list;watch

func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("httproute", req.NamespacedName)

	route := &gwv1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	parents, err := r.buildRouteParentStatuses(ctx, route)
	if err != nil {
		return ctrl.Result{}, err
	}
	if r.mergeRouteParentStatuses(route, parents) {
		if err := r.Status().Update(ctx, route); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("HTTPRoute status updated", "parents", len(parents))
	}

	// For each Gateway we attached to, recompute AttachedRoutes per listener.
	for _, p := range parents {
		gwName := string(p.ParentRef.Name)
		gwNS := route.Namespace
		if p.ParentRef.Namespace != nil {
			gwNS = string(*p.ParentRef.Namespace)
		}
		if err := r.updateGatewayAttachedRoutes(ctx, gwName, gwNS); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// buildRouteParentStatuses returns one RouteParentStatus entry per ParentRef
// that resolves to a Gateway we manage. Foreign or missing parents are
// skipped (other controllers write those entries themselves).
func (r *HTTPRouteReconciler) buildRouteParentStatuses(
	ctx context.Context,
	route *gwv1.HTTPRoute,
) ([]gwv1.RouteParentStatus, error) {
	// backendRefs are route-scoped (parent-independent), so resolve them once.
	resolved, err := r.backendRefsPermitted(ctx, route)
	if err != nil {
		return nil, err
	}
	out := make([]gwv1.RouteParentStatus, 0, len(route.Spec.ParentRefs))
	for _, pr := range route.Spec.ParentRefs {
		managed, listenerExists, err := r.parentManagedByUs(ctx, pr, route.Namespace)
		if err != nil {
			return nil, err
		}
		if !managed {
			continue
		}
		cond := metav1.Condition{
			Type:               string(gwv1.RouteConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gwv1.RouteReasonAccepted),
			Message:            "Route accepted by tor-gateway",
			ObservedGeneration: route.Generation,
			LastTransitionTime: metav1.Now(),
		}
		if !listenerExists {
			cond.Status = metav1.ConditionFalse
			cond.Reason = string(gwv1.RouteReasonNoMatchingParent)
			cond.Message = "ParentRef sectionName does not match any listener"
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
			resolvedCond.Message = "A cross-namespace backendRef is not permitted by any ReferenceGrant"
		}
		out = append(out, gwv1.RouteParentStatus{
			ParentRef:      pr,
			ControllerName: ControllerName,
			Conditions:     []metav1.Condition{cond, resolvedCond},
		})
	}
	return out, nil
}

// parentManagedByUs resolves a ParentRef to a Gateway and reports whether
// the Gateway's class is ours and whether the optional SectionName resolves
// to a listener on that Gateway.
func (r *HTTPRouteReconciler) parentManagedByUs(
	ctx context.Context,
	pr gwv1.ParentReference,
	defaultNS string,
) (managed, listenerExists bool, err error) {
	// Defaults per Gateway API: missing Group/Kind imply gateway.networking.k8s.io/Gateway.
	group := GatewayAPIGroup
	if pr.Group != nil {
		group = string(*pr.Group)
	}
	kind := GatewayKind
	if pr.Kind != nil {
		kind = string(*pr.Kind)
	}
	if group != GatewayAPIGroup || kind != GatewayKind {
		return false, false, nil
	}
	ns := defaultNS
	if pr.Namespace != nil {
		ns = string(*pr.Namespace)
	}

	gw := &gwv1.Gateway{}
	if err := r.Get(ctx, client.ObjectKey{Name: string(pr.Name), Namespace: ns}, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return false, false, nil
		}
		return false, false, err
	}
	gc := &gwv1.GatewayClass{}
	if err := r.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gc); err != nil {
		if apierrors.IsNotFound(err) {
			return false, false, nil
		}
		return false, false, err
	}
	if gc.Spec.ControllerName != ControllerName {
		return false, false, nil
	}
	// Listener resolution: if SectionName is set, verify it matches a listener.
	if pr.SectionName != nil {
		for _, l := range gw.Spec.Listeners {
			if l.Name == *pr.SectionName {
				return true, true, nil
			}
		}
		return true, false, nil
	}
	return true, true, nil
}

// mergeRouteParentStatuses merges desired parent statuses (those we own) into
// the route's existing Parents list, leaving foreign entries untouched.
// Returns true if the list changed.
func (r *HTTPRouteReconciler) mergeRouteParentStatuses(
	route *gwv1.HTTPRoute,
	desired []gwv1.RouteParentStatus,
) bool {
	// Drop our existing entries; keep foreign ones.
	kept := make([]gwv1.RouteParentStatus, 0, len(route.Status.Parents))
	for _, p := range route.Status.Parents {
		if p.ControllerName != ControllerName {
			kept = append(kept, p)
		}
	}
	merged := append(kept, desired...)
	if routeParentsEqual(route.Status.Parents, merged) {
		return false
	}
	route.Status.Parents = merged
	return true
}

// updateGatewayAttachedRoutes recomputes per-listener AttachedRoutes for the
// named Gateway by listing every HTTPRoute that points at it.
func (r *HTTPRouteReconciler) updateGatewayAttachedRoutes(ctx context.Context, gwName, gwNS string) error {
	gw := &gwv1.Gateway{}
	if err := r.Get(ctx, client.ObjectKey{Name: gwName, Namespace: gwNS}, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Count routes per listener name. Listener absent from the map means 0.
	counts := make(map[gwv1.SectionName]int32, len(gw.Spec.Listeners))
	for _, l := range gw.Spec.Listeners {
		counts[l.Name] = 0
	}

	routes := &gwv1.HTTPRouteList{}
	if err := r.List(ctx, routes); err != nil {
		return err
	}
	for i := range routes.Items {
		route := &routes.Items[i]
		for _, pr := range route.Spec.ParentRefs {
			if !parentRefMatches(pr, gwName, gwNS, route.Namespace) {
				continue
			}
			if pr.SectionName != nil {
				if _, ok := counts[*pr.SectionName]; ok {
					counts[*pr.SectionName]++
				}
				continue
			}
			// No sectionName means "all listeners of this Gateway".
			for k := range counts {
				counts[k]++
			}
		}
	}

	changed := false
	for i := range gw.Status.Listeners {
		ls := &gw.Status.Listeners[i]
		newCount := counts[ls.Name]
		if ls.AttachedRoutes != newCount {
			ls.AttachedRoutes = newCount
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return r.Status().Update(ctx, gw)
}

// parentRefGroupKindIsGateway reports whether pr names a Gateway-API Gateway
// (with nil/empty group/kind defaulting per the Gateway API spec).
func parentRefGroupKindIsGateway(pr gwv1.ParentReference) bool {
	if pr.Group != nil && *pr.Group != "" && string(*pr.Group) != GatewayAPIGroup {
		return false
	}
	if pr.Kind != nil && *pr.Kind != "" && string(*pr.Kind) != GatewayKind {
		return false
	}
	return true
}

// parentRefMatches reports whether pr resolves to the named Gateway in the
// given namespace, defaulting Namespace to the route's namespace.
func parentRefMatches(pr gwv1.ParentReference, gwName, gwNS, routeNS string) bool {
	if !parentRefGroupKindIsGateway(pr) {
		return false
	}
	ns := routeNS
	if pr.Namespace != nil {
		ns = string(*pr.Namespace)
	}
	return string(pr.Name) == gwName && ns == gwNS
}

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

// httproutesForReferenceGrant enqueues HTTPRoutes in each namespace a changed
// ReferenceGrant grants FROM (Kind=HTTPRoute), so their ResolvedRefs are
// recomputed when grants are added or removed.
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

// SetupWithManager registers the reconciler.
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.HTTPRoute{}).
		Watches(&gwv1beta1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(r.httproutesForReferenceGrant)).
		Named("httproute").
		Complete(r)
}

func routeParentsEqual(a, b []gwv1.RouteParentStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ControllerName != b[i].ControllerName ||
			a[i].ParentRef.Name != b[i].ParentRef.Name {
			return false
		}
		if len(a[i].Conditions) != len(b[i].Conditions) {
			return false
		}
		for j := range a[i].Conditions {
			ac, bc := a[i].Conditions[j], b[i].Conditions[j]
			if ac.Type != bc.Type || ac.Status != bc.Status || ac.Reason != bc.Reason {
				return false
			}
		}
	}
	return true
}

// Defensive: ensure policyv1alpha1 stays linked even though this file
// doesn't reference it directly — future status helpers will.
var _ = policyv1alpha1.GroupVersion
