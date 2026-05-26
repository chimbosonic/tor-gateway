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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
)

// TorServicePolicyReconciler maintains the per-ancestor status of every
// TorServicePolicy. The policy's *effect* on the Tor daemon is applied by
// the Gateway reconciler (which reads policies attached to its Gateway);
// this reconciler is responsible for reporting acceptance back to the
// policy author via .status.ancestors.
type TorServicePolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=policy.torgateway.io,resources=torservicepolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=policy.torgateway.io,resources=torservicepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch

func (r *TorServicePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("torservicepolicy", req.NamespacedName)

	tsp := &policyv1alpha1.TorServicePolicy{}
	if err := r.Get(ctx, req.NamespacedName, tsp); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	ancestors, err := r.buildAncestors(ctx, tsp)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ancestorsEqual(tsp.Status.Ancestors, ancestors) {
		tsp.Status.Ancestors = ancestors
		if err := r.Status().Update(ctx, tsp); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("TorServicePolicy status updated", "ancestors", len(ancestors))
	}
	return ctrl.Result{}, nil
}

// buildAncestors evaluates each TargetRef and returns one PolicyAncestorStatus
// per target. Possible per-ancestor Accepted Reasons:
//
//   - Accepted              : target Gateway exists and is managed by us
//   - TargetNotFound        : referenced Gateway does not exist
//   - TargetNotManaged      : Gateway exists but its GatewayClass is not ours
func (r *TorServicePolicyReconciler) buildAncestors(
	ctx context.Context,
	tsp *policyv1alpha1.TorServicePolicy,
) ([]gwv1.PolicyAncestorStatus, error) {
	out := make([]gwv1.PolicyAncestorStatus, 0, len(tsp.Spec.TargetRefs))
	for _, ref := range tsp.Spec.TargetRefs {
		ancestor := gwv1.PolicyAncestorStatus{
			AncestorRef: gwv1.ParentReference{
				Group:     refPtr(ref.Group),
				Kind:      refPtr(ref.Kind),
				Name:      ref.Name,
				Namespace: refPtr(gwv1.Namespace(tsp.Namespace)),
			},
			ControllerName: ControllerName,
		}
		status, reason, msg, err := r.evaluateTarget(ctx, ref, tsp.Namespace)
		if err != nil {
			return nil, err
		}
		ancestor.Conditions = []metav1.Condition{{
			Type:               string(gwv1.PolicyConditionAccepted),
			Status:             status,
			Reason:             reason,
			Message:            msg,
			ObservedGeneration: tsp.Generation,
			LastTransitionTime: metav1.Now(),
		}}
		out = append(out, ancestor)
	}
	return out, nil
}

func (r *TorServicePolicyReconciler) evaluateTarget(
	ctx context.Context,
	ref gwv1.LocalPolicyTargetReference,
	ns string,
) (metav1.ConditionStatus, string, string, error) {
	gw := &gwv1.Gateway{}
	err := r.Get(ctx, client.ObjectKey{Name: string(ref.Name), Namespace: ns}, gw)
	switch {
	case apierrors.IsNotFound(err):
		return metav1.ConditionFalse, "TargetNotFound", "Referenced Gateway does not exist", nil
	case err != nil:
		return "", "", "", err
	}
	gc := &gwv1.GatewayClass{}
	if err := r.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gc); err != nil {
		if apierrors.IsNotFound(err) {
			return metav1.ConditionFalse, "TargetNotManaged",
				"Gateway's GatewayClass does not exist", nil
		}
		return "", "", "", err
	}
	if gc.Spec.ControllerName != ControllerName {
		return metav1.ConditionFalse, "TargetNotManaged",
			"Gateway is managed by a different controller", nil
	}
	return metav1.ConditionTrue, string(gwv1.PolicyReasonAccepted), "Policy accepted by tor-gateway", nil
}

// SetupWithManager registers the reconciler.
func (r *TorServicePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.TorServicePolicy{}).
		Named("torservicepolicy").
		Complete(r)
}

// refPtr returns a pointer to v. Tiny helper because the gateway-api types
// use *Group / *Kind / *Namespace heavily.
func refPtr[T any](v T) *T { return &v }

func ancestorsEqual(a, b []gwv1.PolicyAncestorStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ar, br := a[i].AncestorRef, b[i].AncestorRef
		if !objEqual(ar.Group, br.Group) || !objEqual(ar.Kind, br.Kind) ||
			ar.Name != br.Name || !objEqual(ar.Namespace, br.Namespace) {
			return false
		}
		if a[i].ControllerName != b[i].ControllerName {
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

func objEqual[T comparable](a, b *T) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
