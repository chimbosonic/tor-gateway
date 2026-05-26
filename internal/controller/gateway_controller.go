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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// GatewayReconciler reconciles Gateway resources whose GatewayClass is
// managed by this controller. For each such Gateway it provisions the
// per-Gateway Secret (ed25519 keys), torrc ConfigMap, Deployment (init +
// tor + router sidecar), and headless Service; then publishes the .onion
// address in Gateway.status.
type GatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Images RuntimeImages
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy.torgateway.io,resources=torservicepolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps;services,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("gateway", req.NamespacedName)

	gw := &gwv1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	managed, err := r.gatewayClassManagedByUs(ctx, string(gw.Spec.GatewayClassName))
	if err != nil {
		return ctrl.Result{}, err
	}
	if !managed {
		// Not ours; do not write status, do not provision children.
		return ctrl.Result{}, nil
	}

	policy, err := r.findEffectivePolicy(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	auth, err := r.findEffectiveClientAuth(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 1. Keys (Secret). Generated once; never overwritten on subsequent reconciles.
	secret, kp, err := r.ensureKeySecret(ctx, gw)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure key secret: %w", err)
	}
	_ = secret // retained for explicit ownership trace; child objects use the name

	// 2. torrc ConfigMap.
	if _, err := r.ensureTorrcConfigMap(ctx, gw, policy, auth); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure torrc configmap: %w", err)
	}

	// 3. Deployment.
	if _, err := r.ensureDeployment(ctx, gw, policy, auth); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure deployment: %w", err)
	}

	// 4. Headless Service.
	if _, err := r.ensureService(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure service: %w", err)
	}

	// 5. Status: addresses + conditions + per-listener status.
	if err := r.updateStatus(ctx, gw, kp); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}
	logger.Info("Gateway reconciled", "onion", kp.OnionAddress())
	return ctrl.Result{}, nil
}

// gatewayClassManagedByUs reports whether the given GatewayClass exists and
// has our ControllerName.
func (r *GatewayReconciler) gatewayClassManagedByUs(ctx context.Context, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	gc := &gwv1.GatewayClass{}
	if err := r.Get(ctx, client.ObjectKey{Name: name}, gc); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return gc.Spec.ControllerName == ControllerName, nil
}

// findEffectivePolicy scans TorServicePolicies in the Gateway's namespace
// and returns the effective policy for that Gateway, applying defaults
// for any unset fields. If multiple policies target the same Gateway,
// the lexically-first by name wins (deterministic conflict resolution).
func (r *GatewayReconciler) findEffectivePolicy(ctx context.Context, gw *gwv1.Gateway) (EffectiveServicePolicy, error) {
	list := &policyv1alpha1.TorServicePolicyList{}
	if err := r.List(ctx, list, client.InNamespace(gw.Namespace)); err != nil {
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

// policyTargets reports whether the policy targets the named Gateway
// (Group=gateway.networking.k8s.io, Kind=Gateway).
func policyTargets(refs []gwv1.LocalPolicyTargetReference, gw string) bool {
	for _, r := range refs {
		if r.Group != GatewayAPIGroup || r.Kind != GatewayKind {
			continue
		}
		if string(r.Name) == gw {
			return true
		}
	}
	return false
}

// findEffectiveClientAuth scans TorClientAuthPolicies in the Gateway's
// namespace and returns the effective client-auth settings to use when
// building child resources. Multiple policies targeting the same Gateway
// resolve to the lexically-first by name (matching findEffectivePolicy).
//
// In Audit mode the operator emits a log line and proceeds as if no auth
// were configured. A future iteration will surface this via a Kubernetes
// Event so the user can see it without reading operator logs.
func (r *GatewayReconciler) findEffectiveClientAuth(
	ctx context.Context,
	gw *gwv1.Gateway,
) (EffectiveClientAuth, error) {
	logger := log.FromContext(ctx)
	list := &policyv1alpha1.TorClientAuthPolicyList{}
	if err := r.List(ctx, list, client.InNamespace(gw.Namespace)); err != nil {
		return EffectiveClientAuth{}, err
	}
	var matched *policyv1alpha1.TorClientAuthPolicy
	for i := range list.Items {
		p := &list.Items[i]
		if policyTargets(p.Spec.TargetRefs, gw.Name) {
			if matched == nil || p.Name < matched.Name {
				matched = p
			}
		}
	}
	if matched == nil {
		return EffectiveClientAuth{}, nil
	}
	if matched.Spec.Mode == policyv1alpha1.ClientAuthModeAudit {
		logger.Info("TorClientAuthPolicy in Audit mode; allowing unauthorized clients",
			"policy", matched.Name)
		return EffectiveClientAuth{}, nil
	}
	// Cross-namespace SecretRefs require ReferenceGrant and are not yet
	// supported; the policy's CRD-level validation accepts a Namespace
	// field but the Gateway reconciler ignores it for now.
	return EffectiveClientAuth{
		Enabled:    true,
		SecretName: matched.Spec.ClientsSecretRef.Name,
	}, nil
}

func (r *GatewayReconciler) ensureKeySecret(
	ctx context.Context,
	gw *gwv1.Gateway,
) (*corev1.Secret, *tor.KeyPair, error) {
	name := KeySecretName(gw.Name)
	existing := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: name}, existing)
	switch {
	case apierrors.IsNotFound(err):
		// Generate fresh keys, then create the Secret.
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
	case err != nil:
		return nil, nil, err
	}

	// Secret exists; re-derive the in-memory KeyPair from its files so we
	// can derive the .onion for status without re-generating keys.
	kp, parseErr := tor.ParseFiles(
		existing.Data[tor.FileSecretKeyName],
		existing.Data[tor.FilePublicKeyName],
	)
	if parseErr != nil {
		return nil, nil, fmt.Errorf("parse existing key Secret: %w", parseErr)
	}
	return existing, kp, nil
}

func (r *GatewayReconciler) ensureTorrcConfigMap(
	ctx context.Context,
	gw *gwv1.Gateway,
	policy EffectiveServicePolicy,
	auth EffectiveClientAuth,
) (*corev1.ConfigMap, error) {
	desired, err := BuildTorrcConfigMap(gw, policy, auth, r.Scheme)
	if err != nil {
		return nil, err
	}
	current := &corev1.ConfigMap{}
	current.Name = desired.Name
	current.Namespace = desired.Namespace
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		current.Labels = desired.Labels
		current.Data = desired.Data
		current.OwnerReferences = desired.OwnerReferences
		return nil
	}); err != nil {
		return nil, err
	}
	return current, nil
}

func (r *GatewayReconciler) ensureDeployment(
	ctx context.Context,
	gw *gwv1.Gateway,
	policy EffectiveServicePolicy,
	auth EffectiveClientAuth,
) (*appsv1.Deployment, error) {
	desired, err := BuildDeployment(gw, policy, auth, r.Images, r.Scheme)
	if err != nil {
		return nil, err
	}
	current := &appsv1.Deployment{}
	current.Name = desired.Name
	current.Namespace = desired.Namespace
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		current.Labels = desired.Labels
		current.Spec = desired.Spec
		current.OwnerReferences = desired.OwnerReferences
		return nil
	}); err != nil {
		return nil, err
	}
	return current, nil
}

func (r *GatewayReconciler) ensureService(ctx context.Context, gw *gwv1.Gateway) (*corev1.Service, error) {
	desired, err := BuildService(gw, r.Scheme)
	if err != nil {
		return nil, err
	}
	current := &corev1.Service{}
	current.Name = desired.Name
	current.Namespace = desired.Namespace
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		current.Labels = desired.Labels
		// Preserve cluster-assigned ClusterIP (immutable on update).
		if current.Spec.ClusterIP == "" {
			current.Spec.ClusterIP = desired.Spec.ClusterIP
		}
		current.Spec.Selector = desired.Spec.Selector
		current.Spec.Ports = desired.Spec.Ports
		current.OwnerReferences = desired.OwnerReferences
		return nil
	}); err != nil {
		return nil, err
	}
	return current, nil
}

func (r *GatewayReconciler) updateStatus(ctx context.Context, gw *gwv1.Gateway, kp *tor.KeyPair) error {
	onion := kp.OnionAddress().String()

	addressType := gwv1.HostnameAddressType
	wantAddresses := []gwv1.GatewayStatusAddress{{
		Type:  &addressType,
		Value: onion,
	}}

	wantConds := []metav1.Condition{
		{
			Type:               string(gwv1.GatewayConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gwv1.GatewayReasonAccepted),
			Message:            "Gateway accepted by tor-gateway",
			ObservedGeneration: gw.Generation,
			LastTransitionTime: metav1.Now(),
		},
		{
			Type:               string(gwv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionTrue,
			Reason:             string(gwv1.GatewayReasonProgrammed),
			Message:            "Tor pod provisioned; .onion published",
			ObservedGeneration: gw.Generation,
			LastTransitionTime: metav1.Now(),
		},
	}

	// Build per-listener status (one entry per spec.listeners; we accept
	// any HiddenServiceProtocol listeners).
	listenerStatuses := make([]gwv1.ListenerStatus, 0, len(gw.Spec.Listeners))
	for _, l := range gw.Spec.Listeners {
		ls := gwv1.ListenerStatus{
			Name:           l.Name,
			SupportedKinds: []gwv1.RouteGroupKind{{Group: ptr.To[gwv1.Group]("gateway.networking.k8s.io"), Kind: "HTTPRoute"}},
			AttachedRoutes: 0,
			Conditions: []metav1.Condition{{
				Type:               string(gwv1.ListenerConditionAccepted),
				Status:             metav1.ConditionTrue,
				Reason:             string(gwv1.ListenerReasonAccepted),
				Message:            "Listener accepted",
				ObservedGeneration: gw.Generation,
				LastTransitionTime: metav1.Now(),
			}, {
				Type:               string(gwv1.ListenerConditionProgrammed),
				Status:             metav1.ConditionTrue,
				Reason:             string(gwv1.ListenerReasonProgrammed),
				Message:            "Listener programmed",
				ObservedGeneration: gw.Generation,
				LastTransitionTime: metav1.Now(),
			}},
		}
		// Preserve attachedRoutes if HTTPRoute reconciler already set it.
		for _, existing := range gw.Status.Listeners {
			if existing.Name == l.Name {
				ls.AttachedRoutes = existing.AttachedRoutes
			}
		}
		listenerStatuses = append(listenerStatuses, ls)
	}

	changed := false

	if !equalGatewayAddresses(gw.Status.Addresses, wantAddresses) {
		gw.Status.Addresses = wantAddresses
		changed = true
	}
	for _, c := range wantConds {
		if setCondition(&gw.Status.Conditions, c) {
			changed = true
		}
	}
	if !equalListenerStatus(gw.Status.Listeners, listenerStatuses) {
		gw.Status.Listeners = listenerStatuses
		changed = true
	}

	if !changed {
		return nil
	}
	return r.Status().Update(ctx, gw)
}

// SetupWithManager registers the Gateway reconciler.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.Gateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Named("gateway").
		Complete(r)
}

func equalGatewayAddresses(a, b []gwv1.GatewayStatusAddress) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Value != b[i].Value {
			return false
		}
		if (a[i].Type == nil) != (b[i].Type == nil) {
			return false
		}
		if a[i].Type != nil && *a[i].Type != *b[i].Type {
			return false
		}
	}
	return true
}

func equalListenerStatus(a, b []gwv1.ListenerStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].AttachedRoutes != b[i].AttachedRoutes {
			return false
		}
		// Conditions compared by Type/Status/Reason only — ignore
		// LastTransitionTime jitter.
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
