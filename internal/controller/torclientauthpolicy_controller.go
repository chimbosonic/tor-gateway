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

// TorClientAuthPolicyReconciler maintains the per-ancestor status of every
// TorClientAuthPolicy. The policy's *effect* (mounting the clients Secret
// into the Tor pod and laying down authorized_clients/*.auth) is applied
// by the Gateway reconciler; this reconciler is responsible only for
// reporting acceptance back via .status.ancestors.
type TorClientAuthPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=policy.torgateway.io,resources=torclientauthpolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=policy.torgateway.io,resources=torclientauthpolicies/status,verbs=get;update;patch

func (r *TorClientAuthPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("torclientauthpolicy", req.NamespacedName)

	tcap := &policyv1alpha1.TorClientAuthPolicy{}
	if err := r.Get(ctx, req.NamespacedName, tcap); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	ancestors, err := r.buildAncestors(ctx, tcap)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ancestorsEqual(tcap.Status.Ancestors, ancestors) {
		tcap.Status.Ancestors = ancestors
		if err := r.Status().Update(ctx, tcap); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("TorClientAuthPolicy status updated", "ancestors", len(ancestors))
	}
	return ctrl.Result{}, nil
}

func (r *TorClientAuthPolicyReconciler) buildAncestors(
	ctx context.Context,
	tcap *policyv1alpha1.TorClientAuthPolicy,
) ([]gwv1.PolicyAncestorStatus, error) {
	out := make([]gwv1.PolicyAncestorStatus, 0, len(tcap.Spec.TargetRefs))
	policyNS := gwv1.Namespace(tcap.Namespace)
	for _, ref := range tcap.Spec.TargetRefs {
		// Loop var is per-iteration since Go 1.22 so taking its address
		// is safe; copy the local for the closure not to outlive the loop.
		grp, kind := ref.Group, ref.Kind
		ancestor := gwv1.PolicyAncestorStatus{
			AncestorRef: gwv1.ParentReference{
				Group:     &grp,
				Kind:      &kind,
				Name:      ref.Name,
				Namespace: &policyNS,
			},
			ControllerName: ControllerName,
		}
		status, reason, msg, err := evaluatePolicyTarget(ctx, r.Client, ref, tcap.Namespace)
		if err != nil {
			return nil, err
		}
		ancestor.Conditions = []metav1.Condition{{
			Type:               string(gwv1.PolicyConditionAccepted),
			Status:             status,
			Reason:             reason,
			Message:            msg,
			ObservedGeneration: tcap.Generation,
			LastTransitionTime: metav1.Now(),
		}}
		out = append(out, ancestor)
	}
	return out, nil
}

// SetupWithManager registers the reconciler.
func (r *TorClientAuthPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.TorClientAuthPolicy{}).
		Named("torclientauthpolicy").
		Complete(r)
}
