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
)

// GatewayClassReconciler accepts GatewayClasses whose ControllerName matches
// ours and marks them Accepted=True. It performs no other side effects.
type GatewayClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses/status,verbs=get;update;patch

func (r *GatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("gatewayclass", req.Name)

	gc := &gwv1.GatewayClass{}
	if err := r.Get(ctx, req.NamespacedName, gc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if gc.Spec.ControllerName != ControllerName {
		// Not ours. Don't touch status.
		return ctrl.Result{}, nil
	}

	acceptedCond := metav1.Condition{
		Type:               string(gwv1.GatewayClassConditionStatusAccepted),
		Status:             metav1.ConditionTrue,
		Reason:             string(gwv1.GatewayClassReasonAccepted),
		Message:            "GatewayClass accepted by tor-gateway controller",
		ObservedGeneration: gc.Generation,
		LastTransitionTime: metav1.Now(),
	}

	if setCondition(&gc.Status.Conditions, acceptedCond) {
		if err := r.Status().Update(ctx, gc); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("GatewayClass accepted")
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *GatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.GatewayClass{}).
		Named("gatewayclass").
		Complete(r)
}

// setCondition merges cond into conds keyed by Type and returns true if the
// list changed (so the caller knows whether to issue a status update). The
// LastTransitionTime stays the same when the Status field hasn't flipped.
func setCondition(conds *[]metav1.Condition, cond metav1.Condition) bool {
	for i, existing := range *conds {
		if existing.Type != cond.Type {
			continue
		}
		if existing.Status == cond.Status &&
			existing.Reason == cond.Reason &&
			existing.Message == cond.Message &&
			existing.ObservedGeneration == cond.ObservedGeneration {
			return false
		}
		// Preserve the LastTransitionTime when only the message/generation
		// changed but the status did not.
		if existing.Status == cond.Status {
			cond.LastTransitionTime = existing.LastTransitionTime
		}
		(*conds)[i] = cond
		return true
	}
	*conds = append(*conds, cond)
	return true
}
