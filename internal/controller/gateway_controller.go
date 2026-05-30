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
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
	Scheme         *runtime.Scheme
	Images         RuntimeImages
	Recorder       record.EventRecorder
	VanityDeadline time.Duration
	// APIReader is a direct, uncached API-server reader (defeats informer lag).
	APIReader                  client.Reader
	TorPodNetworkPolicyEnabled bool
	ClusterPodCIDRs            []string
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy.torgateway.io,resources=torservicepolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps;services,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch

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
	secret, kp, err := r.ensureKeySecret(ctx, gw, policy)
	if err != nil {
		switch {
		case errors.Is(err, errHarvestPending):
			return ctrl.Result{}, r.setProgrammingCondition(ctx, gw,
				ReasonVanityHarvestInProgress, "vanity .onion harvest in progress")
		case errors.Is(err, errHarvestFailed):
			return ctrl.Result{}, r.setProgrammingCondition(ctx, gw,
				ReasonVanityHarvestFailed, "vanity harvest exceeded its deadline; choose a shorter vanityPrefix")
		case errors.Is(err, errAwaitingVanityPolicy):
			return ctrl.Result{}, r.setProgrammingCondition(ctx, gw,
				ReasonAwaitingVanityPolicy, "awaiting a TorServicePolicy with a vanityPrefix (torgateway.io/await-vanity=true)")
		default:
			return ctrl.Result{}, fmt.Errorf("ensure key secret: %w", err)
		}
	}
	_ = secret // retained for explicit ownership trace; child objects use the name

	// 2. torrc ConfigMap.
	if _, err := r.ensureTorrcConfigMap(ctx, gw, policy, auth); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure torrc configmap: %w", err)
	}

	// 3. Per-Gateway RBAC for the router sidecar (SA must exist before the pod).
	if err := r.ensureServiceAccount(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure service account: %w", err)
	}
	if err := r.ensureRole(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure role: %w", err)
	}
	if err := r.ensureRoleBinding(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure rolebinding: %w", err)
	}

	// 4. Deployment.
	if _, err := r.ensureDeployment(ctx, gw, policy, auth); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure deployment: %w", err)
	}

	// 5. Headless Service.
	if _, err := r.ensureService(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure service: %w", err)
	}

	// List HTTPRoutes targeting this Gateway for the NetworkPolicy egress
	// whitelist (same query used for attachedRoutes status).
	var routes []gwv1.HTTPRoute
	{
		routeList := &gwv1.HTTPRouteList{}
		if err := r.Client.List(ctx, routeList); err != nil {
			return ctrl.Result{}, err
		}
		for i := range routeList.Items {
			if routeTargetsGateway(&routeList.Items[i], gw) {
				routes = append(routes, routeList.Items[i])
			}
		}
	}
	if err := r.ensureNetworkPolicy(ctx, gw, routes); err != nil {
		logger.Error(err, "ensureNetworkPolicy failed")
		return ctrl.Result{}, err
	}

	// 6. Status: addresses + conditions + per-listener status.
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
	return r.effectivePolicyFrom(ctx, r.Client, gw)
}

// effectivePolicyFrom resolves the effective TorServicePolicy for gw using the
// supplied reader (cached client on the hot path, uncached APIReader when a
// stale read would be unsafe).
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
	policy EffectiveServicePolicy,
) (*corev1.Secret, *tor.KeyPair, error) {
	name := KeySecretName(gw.Name)
	existing := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: name}, existing)
	switch {
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
		reader := r.APIReader
		if reader == nil { // unset in some unit tests; fall back to the cache
			reader = r.Client
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
		if await, _ := strconv.ParseBool(gw.Annotations[awaitVanityAnnotation]); await {
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
	case err != nil:
		return nil, nil, err
	}

	kp, parseErr := tor.ParseFiles(
		existing.Data[tor.FileSecretKeyName],
		existing.Data[tor.FilePublicKeyName],
	)
	if parseErr != nil {
		return nil, nil, fmt.Errorf("parse existing key Secret: %w", parseErr)
	}
	// A prefix requested after the key already exists is ignored — keys are
	// never regenerated. Surface it so the user is not silently confused.
	if policy.VanityPrefix != "" && !strings.HasPrefix(kp.OnionAddress().String(), policy.VanityPrefix) {
		r.event(gw, corev1.EventTypeNormal, "VanityPrefixIgnored",
			fmt.Sprintf("vanityPrefix %q ignored: a key already exists for this Gateway", policy.VanityPrefix))
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

func (r *GatewayReconciler) ensureServiceAccount(ctx context.Context, gw *gwv1.Gateway) error {
	desired, err := BuildServiceAccount(gw, r.Scheme)
	if err != nil {
		return err
	}
	current := &corev1.ServiceAccount{}
	current.Name = desired.Name
	current.Namespace = desired.Namespace
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		current.Labels = desired.Labels
		current.OwnerReferences = desired.OwnerReferences
		return nil
	})
	return err
}

func (r *GatewayReconciler) ensureRole(ctx context.Context, gw *gwv1.Gateway) error {
	desired, err := BuildRole(gw, r.Scheme)
	if err != nil {
		return err
	}
	current := &rbacv1.Role{}
	current.Name = desired.Name
	current.Namespace = desired.Namespace
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		current.Labels = desired.Labels
		current.Rules = desired.Rules
		current.OwnerReferences = desired.OwnerReferences
		return nil
	})
	return err
}

func (r *GatewayReconciler) ensureRoleBinding(ctx context.Context, gw *gwv1.Gateway) error {
	desired, err := BuildRoleBinding(gw, r.Scheme)
	if err != nil {
		return err
	}
	current := &rbacv1.RoleBinding{}
	current.Name = desired.Name
	current.Namespace = desired.Namespace
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		current.Labels = desired.Labels
		current.RoleRef = desired.RoleRef
		current.Subjects = desired.Subjects
		current.OwnerReferences = desired.OwnerReferences
		return nil
	})
	return err
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

func (r *GatewayReconciler) ensureNetworkPolicy(
	ctx context.Context,
	gw *gwv1.Gateway,
	routes []gwv1.HTTPRoute,
) error {
	if !r.TorPodNetworkPolicyEnabled {
		// Feature off: best-effort delete any stale NetworkPolicy so toggling
		// the flag is reversible.
		stale := &netv1.NetworkPolicy{}
		stale.Name = NetworkPolicyName(gw.Name)
		stale.Namespace = gw.Namespace
		if err := r.Client.Delete(ctx, stale); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return nil
	}

	backends, err := r.resolveBackends(ctx, gw, routes)
	if err != nil {
		return err
	}
	desired, err := BuildNetworkPolicy(gw, backends, r.ClusterPodCIDRs, r.Scheme)
	if err != nil {
		return err
	}
	current := &netv1.NetworkPolicy{}
	current.Name = desired.Name
	current.Namespace = desired.Namespace
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		current.Labels = desired.Labels
		current.Spec = desired.Spec
		current.OwnerReferences = desired.OwnerReferences
		return nil
	})
	return err
}

// routeTargetsGateway reports whether route's parentRefs designate gw.
func routeTargetsGateway(route *gwv1.HTTPRoute, gw *gwv1.Gateway) bool {
	for _, p := range route.Spec.ParentRefs {
		if parentRefMatches(p, gw.Name, gw.Namespace, route.Namespace) {
			return true
		}
	}
	return false
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
//
// Besides owning its child resources, the Gateway reconciler watches the
// policy CRDs that influence rendered output (TorServicePolicy,
// TorClientAuthPolicy). Without these watches, creating or editing a
// policy after its target Gateway already exists would not re-render the
// torrc/Deployment until the next Gateway event.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.Gateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&batchv1.Job{}).
		Owns(&netv1.NetworkPolicy{}).
		Watches(&policyv1alpha1.TorServicePolicy{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForServicePolicy)).
		Watches(&policyv1alpha1.TorClientAuthPolicy{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForClientAuthPolicy)).
		Watches(&gwv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForHTTPRoute)).
		Named("gateway").
		Complete(r)
}

// gatewaysForHTTPRoute maps an HTTPRoute to reconcile requests for every
// Gateway named by its parentRefs. Without this, an HTTPRoute add/update/
// delete leaves the per-Gateway NetworkPolicy's per-backend egress rules
// stale until something else triggers reconciliation.
func (r *GatewayReconciler) gatewaysForHTTPRoute(_ context.Context, obj client.Object) []reconcile.Request {
	route, ok := obj.(*gwv1.HTTPRoute)
	if !ok {
		return nil
	}
	var reqs []reconcile.Request
	for _, p := range route.Spec.ParentRefs {
		if !parentRefGroupKindIsGateway(p) {
			continue
		}
		ns := route.Namespace
		if p.Namespace != nil {
			ns = string(*p.Namespace)
		}
		reqs = append(reqs, reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: ns, Name: string(p.Name)},
		})
	}
	return reqs
}

// gatewaysForServicePolicy maps a TorServicePolicy to reconcile requests for
// every Gateway it targets in the same namespace.
func (r *GatewayReconciler) gatewaysForServicePolicy(_ context.Context, obj client.Object) []reconcile.Request {
	p, ok := obj.(*policyv1alpha1.TorServicePolicy)
	if !ok {
		return nil
	}
	return requestsForTargets(p.Namespace, p.Spec.TargetRefs)
}

// gatewaysForClientAuthPolicy maps a TorClientAuthPolicy to reconcile
// requests for every Gateway it targets in the same namespace.
func (r *GatewayReconciler) gatewaysForClientAuthPolicy(_ context.Context, obj client.Object) []reconcile.Request {
	p, ok := obj.(*policyv1alpha1.TorClientAuthPolicy)
	if !ok {
		return nil
	}
	return requestsForTargets(p.Namespace, p.Spec.TargetRefs)
}

// requestsForTargets turns a policy's Gateway targetRefs into reconcile
// requests, ignoring refs that don't point at a Gateway.
func requestsForTargets(ns string, refs []gwv1.LocalPolicyTargetReference) []reconcile.Request {
	var out []reconcile.Request
	for _, ref := range refs {
		if ref.Group != GatewayAPIGroup || ref.Kind != GatewayKind {
			continue
		}
		out = append(out, reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: ns, Name: string(ref.Name)},
		})
	}
	return out
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

// event records a Kubernetes Event against obj when a Recorder is configured.
// It is nil-safe so tests can construct the reconciler without a recorder.
func (r *GatewayReconciler) event(obj runtime.Object, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(obj, eventType, reason, message)
	}
}
