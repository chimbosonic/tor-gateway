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
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// Reason codes on OnionBalancePolicy Accepted conditions.
const (
	ReasonOBPAccepted               = "Accepted"
	ReasonOBPGatewayMissing         = "GatewayMissing"
	ReasonOBPMasterKeyMissing       = "MasterKeyMissing"
	ReasonOBPMasterKeyInvalid       = "MasterKeyInvalid"
	ReasonOBPMasterKeyCrossNSDenied = "MasterKeyCrossNamespaceDenied"
)

// OnionBalancePolicyReconciler maintains the per-ancestor status of every
// OnionBalancePolicy. The policy's effect on the cluster is applied by the
// Gateway reconciler; this reconciler validates inputs and reports acceptance
// via .status.ancestors.
type OnionBalancePolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=policy.torgateway.io,resources=onionbalancepolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=policy.torgateway.io,resources=onionbalancepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=referencegrants,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch

func (r *OnionBalancePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("onionbalancepolicy", req.NamespacedName)

	pol := &policyv1alpha1.OnionBalancePolicy{}
	if err := r.Get(ctx, req.NamespacedName, pol); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	ancestors, readyBackends, err := r.buildAncestors(ctx, pol)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ancestorsEqual(pol.Status.Ancestors, ancestors) || pol.Status.ReadyBackends != readyBackends {
		updated := pol.DeepCopy()
		updated.Status.Ancestors = ancestors
		updated.Status.ReadyBackends = readyBackends
		if err := r.Status().Update(ctx, updated); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("OnionBalancePolicy status updated", "ancestors", len(ancestors))
	}
	return ctrl.Result{}, nil
}

func (r *OnionBalancePolicyReconciler) buildAncestors(
	ctx context.Context,
	pol *policyv1alpha1.OnionBalancePolicy,
) ([]gwv1.PolicyAncestorStatus, int32, error) {
	masterErr := r.validateMasterKey(ctx, pol)

	out := make([]gwv1.PolicyAncestorStatus, 0, len(pol.Spec.TargetRefs))
	policyNS := gwv1.Namespace(pol.Namespace)
	var readyBackends int32

	for _, ref := range pol.Spec.TargetRefs {
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

		accepted := metav1.Condition{
			Type:               string(gwv1.PolicyConditionAccepted),
			ObservedGeneration: pol.Generation,
			LastTransitionTime: metav1.Now(),
		}

		gw := &gwv1.Gateway{}
		gwErr := r.Get(ctx, types.NamespacedName{Namespace: pol.Namespace, Name: string(ref.Name)}, gw)
		switch {
		case apierrors.IsNotFound(gwErr):
			accepted.Status = metav1.ConditionFalse
			accepted.Reason = ReasonOBPGatewayMissing
			accepted.Message = fmt.Sprintf("Gateway %s/%s does not exist", pol.Namespace, ref.Name)
		case gwErr != nil:
			return nil, 0, gwErr
		case masterErr != nil:
			accepted.Status = metav1.ConditionFalse
			accepted.Reason = reasonFromMasterErr(masterErr)
			accepted.Message = masterErr.Error()
		default:
			accepted.Status = metav1.ConditionTrue
			accepted.Reason = ReasonOBPAccepted
			if powForcedOff(ctx, r.Client, gw) {
				accepted.Message = "PoW disabled on backends; onionbalance behind PoW is currently worse than no PoW (see onionbalance#13)"
			} else {
				accepted.Message = "OnionBalancePolicy accepted"
			}
			ready, err := countReadyBackends(ctx, r.Client, gw)
			if err != nil {
				log.FromContext(ctx).Error(err, "count ready backends", "gateway", gw.Name)
			}
			readyBackends += ready
		}

		ancestor.Conditions = []metav1.Condition{accepted}
		out = append(out, ancestor)
	}
	return out, readyBackends, nil
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

// Stubs replaced by Task 9.
func powForcedOff(_ context.Context, _ client.Client, _ *gwv1.Gateway) bool { return false }
func countReadyBackends(_ context.Context, _ client.Client, _ *gwv1.Gateway) (int32, error) {
	return 0, nil
}
func masterKeyReferenceGrantAllows(_ context.Context, _ client.Client, _ *policyv1alpha1.OnionBalancePolicy, _ string) (bool, error) {
	return true, nil
}

// Avoid unused-import on gwv1beta1 until Task 9 uses ReferenceGrantList.
var _ = gwv1beta1.ReferenceGrant{}

// SetupWithManager registers the reconciler.
func (r *OnionBalancePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.OnionBalancePolicy{}).
		Named("onionbalancepolicy").
		Complete(r)
}
