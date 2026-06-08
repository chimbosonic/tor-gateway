/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import gwv1 "sigs.k8s.io/gateway-api/apis/v1"

// Gateway API identifiers owned by this operator.
const (
	// GatewayAPIGroup is the API group of upstream Gateway API resources.
	GatewayAPIGroup = "gateway.networking.k8s.io"

	// GatewayKind is the Kind we match against in ParentRefs and policy
	// TargetRefs.
	GatewayKind = "Gateway"

	// ControllerName is the value the operator writes into
	// GatewayClass.spec.controllerName / PolicyAncestorStatus.controllerName.
	// Per Gateway API conventions this MUST be a domain/path string.
	ControllerName gwv1.GatewayController = "torgateway.io/gateway-controller"

	// HiddenServiceProtocol is the custom listener protocol the operator
	// recognizes on Gateways. Per the Gateway API spec, all non-core
	// protocols must be domain-prefixed.
	HiddenServiceProtocol gwv1.ProtocolType = "torgateway.io/HiddenService"

	// FinalizerName marks Gateways we have begun reconciling. Currently
	// unused (we rely on OwnerReferences for cascade delete); reserved
	// for future migration to a finalizer-driven teardown.
	FinalizerName = "torgateway.io/finalizer"
)

// Resource naming conventions for child objects of a Gateway. Centralized
// here so reconcilers and tests can agree without string-template drift.
const (
	keySecretSuffix       = "-keys"
	torrcConfigSuffix     = "-torrc"
	deploymentSuffix      = ""
	serviceSuffix         = ""
	routerRBACSuffix      = "-router"
	vanityRBACSuffix      = "-vanity"
	vanityOutSecretSuffix = "-vanity-out"
	networkPolicySuffix   = "-netpol"
	// vanityFailedAnnotation records the prefix whose harvest exceeded its
	// deadline so the controller does not relaunch a Job for it (this
	// survives the Job's TTL GC). Cleared when the prefix changes.
	vanityFailedAnnotation = "torgateway.io/vanity-failed"
	// vanityPrefixLabel records the prefix a harvest Job targets, so the
	// controller can detect a changed prefix and recreate the Job.
	vanityPrefixLabel = "torgateway.io/vanity-prefix"
	// awaitVanityAnnotation, when set to "true" on a Gateway, makes the
	// operator wait for a vanityPrefix TorServicePolicy instead of generating
	// a random key (which could never be re-vanitied). Closes the apply-order
	// race deterministically regardless of when the policy is applied.
	awaitVanityAnnotation = "torgateway.io/await-vanity"
	dataVolumeName        = "tor-data"
	keysVolumeName        = "tor-keys"
	configVolumeName      = "tor-config"
	hsDirVolumeName       = "tor-hsdir"
	torContainerName      = "tor"
	routerContainer       = "router"
	obrefreshContainer    = "obrefresh"
	initContainerName     = "tor-init"
	managedByLabelKey     = "app.kubernetes.io/managed-by"
	managedByLabelVal     = "tor-gateway"
	gatewayLabelKey       = "torgateway.io/gateway"
	hsDirMountPath        = "/var/lib/tor/hs"
	dataMountPath         = "/var/lib/tor/data"
	// Tor and tor-init run as nonroot UID 65532. fsGroup leaves the emptyDir
	// mount roots owned by root, but Tor and tor-init's chmod require dirs
	// *owned* by 65532. So the working dirs are nested one level inside the
	// group-writable mounts; the 65532 process creates them and thus owns them.
	hsServiceDir       = hsDirMountPath + "/hs"  // actual HiddenServiceDir
	torDataDir         = dataMountPath + "/data" // actual DataDirectory
	keysMountPath      = "/etc/tor/keys"
	configMountPath    = "/etc/tor"
	loopbackTargetHost = "127.0.0.1"
	loopbackTargetPort = 9080
	routerProbePort    = 8081
	torMetricsPort     = 9035

	// clientAuthVolumeName / clientAuthMountPath are used when a
	// TorClientAuthPolicy is attached: the Secret holding client pubkeys
	// is mounted read-only at clientAuthMountPath, then tor-init reads
	// each entry and writes the matching <label>.auth file into the
	// hidden-service authorized_clients/ subdir.
	clientAuthVolumeName = "tor-client-auth"
	clientAuthMountPath  = "/etc/tor-client-auth"
)

// KeySecretName returns the deterministic Secret name holding the per-Gateway
// hidden-service keys.
func KeySecretName(gw string) string { return gw + keySecretSuffix }

// TorrcConfigMapName returns the deterministic ConfigMap name holding the
// rendered torrc for the Gateway.
func TorrcConfigMapName(gw string) string { return gw + torrcConfigSuffix }

// DeploymentName returns the deterministic Deployment name for the Tor pod.
func DeploymentName(gw string) string { return gw + deploymentSuffix }

// ServiceName returns the deterministic Service name for the Tor pod.
func ServiceName(gw string) string { return gw + serviceSuffix }

// RouterRBACName is the shared name of the per-Gateway ServiceAccount, Role,
// and RoleBinding that grant the router sidecar read access to HTTPRoutes.
func RouterRBACName(gw string) string { return gw + routerRBACSuffix }

// VanityRBACName is the shared name of the per-Gateway vanity ServiceAccount,
// Role, RoleBinding, and Job used to harvest a vanity .onion key.
func VanityRBACName(gw string) string { return gw + vanityRBACSuffix }

// VanityOutSecretName is the throwaway Secret the vanity Job writes the
// harvested keys into, before the controller promotes them into <gw>-keys.
func VanityOutSecretName(gw string) string { return gw + vanityOutSecretSuffix }

// NetworkPolicyName is the name of the per-Gateway egress NetworkPolicy
// emitted by the operator.
func NetworkPolicyName(gw string) string { return gw + networkPolicySuffix }

// ChildLabels returns the standard label set we put on every child resource
// of a Gateway. Used both for SetControllerReference indirection and for
// LabelSelector queries (e.g. "which children belong to this Gateway").
func ChildLabels(gw string) map[string]string {
	return map[string]string{
		managedByLabelKey: managedByLabelVal,
		gatewayLabelKey:   gw,
	}
}
