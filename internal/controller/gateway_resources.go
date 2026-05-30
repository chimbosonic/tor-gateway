/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"crypto/rand"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// RuntimeImages selects the container images the operator injects into Tor
// pods. Centralized here so the reconciler doesn't carry image strings and
// the builders can be unit-tested with synthetic values.
type RuntimeImages struct {
	Tor            string
	Router         string
	TorInit        string
	Mkp224o        string
	VanityFinalize string
	Operator       string // currently unused; kept for forward compat (e.g. webhook)
}

// EffectiveServicePolicy carries the values from a TorServicePolicy after
// defaults have been resolved. Nil means no policy attached; callers fall
// back to operator defaults.
type EffectiveServicePolicy struct {
	LogLevel           string
	PoWDefensesEnabled bool
	VanityPrefix       string
	Resources          corev1.ResourceRequirements
}

// EffectiveClientAuth resolves any TorClientAuthPolicy attached to a
// Gateway. When Enabled is false the Tor pod runs as a public hidden
// service; when true the operator mounts SecretName as a read-only volume
// and tor-init lays the resulting <label>.auth files under
// <HiddenServiceDir>/authorized_clients/.
type EffectiveClientAuth struct {
	Enabled    bool
	SecretName string
}

// DefaultPolicy returns the values used when no TorServicePolicy targets a
// Gateway. Mirrors the +kubebuilder:default markers on TorServicePolicySpec.
func DefaultPolicy() EffectiveServicePolicy {
	return EffectiveServicePolicy{
		LogLevel:           "notice",
		PoWDefensesEnabled: true,
	}
}

// FromTorServicePolicy folds a TorServicePolicy into an EffectiveServicePolicy,
// applying defaults for any unset optional fields.
func FromTorServicePolicy(p *policyv1alpha1.TorServicePolicy) EffectiveServicePolicy {
	eff := DefaultPolicy()
	if p == nil {
		return eff
	}
	if p.Spec.LogLevel != "" {
		eff.LogLevel = string(p.Spec.LogLevel)
	}
	if p.Spec.PoWDefensesEnabled != nil {
		eff.PoWDefensesEnabled = *p.Spec.PoWDefensesEnabled
	}
	eff.VanityPrefix = p.Spec.VanityPrefix
	if p.Spec.Resources != nil {
		eff.Resources = *p.Spec.Resources
	}
	return eff
}

// FreshKeyPair is a small indirection over tor.GenerateKeyPair so the
// reconciler can pass in a deterministic source (or any io.Reader) in
// tests.
var FreshKeyPair = func() (*tor.KeyPair, error) {
	return tor.GenerateKeyPair(rand.Reader)
}

// BuildKeySecret builds the Secret holding the per-Gateway hidden-service
// keys. The Secret has Type=Opaque and three data keys: the two binary
// Tor on-disk files plus a hostname file holding the .onion address. The
// hostname is duplicated here so consumers can read the address without
// running base32 + SHA3 themselves.
func BuildKeySecret(gw *gwv1.Gateway, kp *tor.KeyPair, scheme *runtime.Scheme) (*corev1.Secret, error) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      KeySecretName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			tor.FileSecretKeyName: kp.SecretKeyFile(),
			tor.FilePublicKeyName: kp.PublicKeyFile(),
			tor.FileHostnameName:  kp.Hostname(),
		},
	}
	if err := controllerutil.SetControllerReference(gw, s, scheme); err != nil {
		return nil, err
	}
	return s, nil
}

// BuildTorrcConfigMap renders the torrc for the Gateway+policy combo into a
// ConfigMap.
func BuildTorrcConfigMap(
	gw *gwv1.Gateway,
	policy EffectiveServicePolicy,
	auth EffectiveClientAuth,
	scheme *runtime.Scheme,
) (*corev1.ConfigMap, error) {
	cfg := &tor.TorrcConfig{
		HiddenServiceDir:   hsServiceDir,
		DataDirectory:      torDataDir,
		LogLevel:           policy.LogLevel,
		PoWDefensesEnabled: policy.PoWDefensesEnabled,
		HiddenServicePort: tor.PortMapping{
			VirtualPort: 80,
			TargetHost:  loopbackTargetHost,
			TargetPort:  loopbackTargetPort,
		},
		MetricsPort:       torMetricsPort,
		MetricsPortPolicy: "accept 0.0.0.0/0",
	}
	if auth.Enabled {
		cfg.ClientAuthDir = hsServiceDir + "/" + tor.AuthorizedClientsSubdir
	}
	rendered, err := tor.Render(cfg)
	if err != nil {
		return nil, fmt.Errorf("render torrc: %w", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      TorrcConfigMapName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
		Data: map[string]string{
			"torrc": rendered,
		},
	}
	if err := controllerutil.SetControllerReference(gw, cm, scheme); err != nil {
		return nil, err
	}
	return cm, nil
}

// BuildDeployment emits the per-Gateway Deployment: init container that
// populates the HiddenServiceDir with strict permissions, tor as the main
// container, and the router sidecar. When auth.Enabled is true, the
// builder also mounts auth.SecretName at clientAuthMountPath read-only and
// hands tor-init a --client-auth-src flag so it lays down the
// authorized_clients/*.auth files.
func BuildDeployment(
	gw *gwv1.Gateway,
	policy EffectiveServicePolicy,
	auth EffectiveClientAuth,
	images RuntimeImages,
	scheme *runtime.Scheme,
) (*appsv1.Deployment, error) {
	if images.Tor == "" || images.Router == "" || images.TorInit == "" {
		return nil, fmt.Errorf("missing image references: %+v", images)
	}
	labels := ChildLabels(gw.Name)

	// Pointer-to-literal locals; using ptr.To(true) trips modernize's
	// `newexpr` rule, whose suggested rewrite to new(T) silently swaps
	// in the zero value (false / 0) and would weaken pod security.
	nonRoot := true
	allowEsc := false
	readOnlyFS := true
	uidGid := int64(65532)
	replicasOne := int32(1)
	keysMode := int32(0o600)
	clientAuthMode := int32(0o400)

	podSec := &corev1.PodSecurityContext{
		RunAsNonRoot: &nonRoot,
		RunAsUser:    &uidGid,
		RunAsGroup:   &uidGid,
		FSGroup:      &uidGid,
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
	hardenedContainerSec := func() *corev1.SecurityContext {
		return &corev1.SecurityContext{
			AllowPrivilegeEscalation: &allowEsc,
			ReadOnlyRootFilesystem:   &readOnlyFS,
			RunAsNonRoot:             &nonRoot,
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		}
	}

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicasOne,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: RouterRBACName(gw.Name),
					SecurityContext:    podSec,
					Volumes: []corev1.Volume{
						{
							Name: keysVolumeName,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  KeySecretName(gw.Name),
									DefaultMode: &keysMode,
								},
							},
						},
						{
							Name: configVolumeName,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: TorrcConfigMapName(gw.Name),
									},
								},
							},
						},
						{
							Name:         hsDirVolumeName,
							VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
						},
						{
							Name:         dataVolumeName,
							VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
						},
					},
					InitContainers: []corev1.Container{{
						Name:            initContainerName,
						Image:           images.TorInit,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            initContainerArgs(auth),
						SecurityContext: hardenedContainerSec(),
						VolumeMounts:    initContainerMounts(auth),
					}},
					Containers: []corev1.Container{
						{
							Name:            torContainerName,
							Image:           images.Tor,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args:            []string{"-f", configMountPath + "/torrc"},
							Resources:       policy.Resources,
							SecurityContext: hardenedContainerSec(),
							Ports: []corev1.ContainerPort{
								{Name: "metrics", ContainerPort: torMetricsPort, Protocol: corev1.ProtocolTCP},
							},
							StartupProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/metrics",
										Port: intstr.FromInt(torMetricsPort),
									},
								},
								PeriodSeconds:    5,
								TimeoutSeconds:   2,
								FailureThreshold: 30,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/metrics",
										Port: intstr.FromInt(torMetricsPort),
									},
								},
								PeriodSeconds:    10,
								TimeoutSeconds:   2,
								FailureThreshold: 3,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/metrics",
										Port: intstr.FromInt(torMetricsPort),
									},
								},
								PeriodSeconds:    10,
								TimeoutSeconds:   2,
								FailureThreshold: 3,
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: configVolumeName, MountPath: configMountPath, ReadOnly: true},
								{Name: hsDirVolumeName, MountPath: hsDirMountPath},
								{Name: dataVolumeName, MountPath: dataMountPath},
							},
						},
						{
							Name:            routerContainer,
							Image:           images.Router,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								"--listen", fmt.Sprintf("%s:%d", loopbackTargetHost, loopbackTargetPort),
								"--gateway", gw.Name,
								"--namespace", gw.Namespace,
							},
							Ports: []corev1.ContainerPort{
								{Name: "probe", ContainerPort: routerProbePort, Protocol: corev1.ProtocolTCP},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstr.FromInt(routerProbePort),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
								TimeoutSeconds:      2,
								FailureThreshold:    3,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstr.FromInt(routerProbePort),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
								TimeoutSeconds:      2,
								FailureThreshold:    3,
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("250m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							SecurityContext: hardenedContainerSec(),
						},
					},
				},
			},
		},
	}
	if auth.Enabled {
		dep.Spec.Template.Spec.Volumes = append(dep.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: clientAuthVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  auth.SecretName,
					DefaultMode: &clientAuthMode,
				},
			},
		})
	}

	if err := controllerutil.SetControllerReference(gw, dep, scheme); err != nil {
		return nil, err
	}
	return dep, nil
}

// BuildServiceAccount emits the per-Gateway ServiceAccount the router sidecar
// runs under. Its name is shared with the Role and RoleBinding.
func BuildServiceAccount(gw *gwv1.Gateway, scheme *runtime.Scheme) (*corev1.ServiceAccount, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      RouterRBACName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
	}
	if err := controllerutil.SetControllerReference(gw, sa, scheme); err != nil {
		return nil, err
	}
	return sa, nil
}

// BuildRole emits the per-Gateway namespaced Role granting the router sidecar
// read access to HTTPRoutes.
func BuildRole(gw *gwv1.Gateway, scheme *runtime.Scheme) (*rbacv1.Role, error) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      RouterRBACName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"httproutes"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
	if err := controllerutil.SetControllerReference(gw, role, scheme); err != nil {
		return nil, err
	}
	return role, nil
}

// BuildRoleBinding emits the per-Gateway RoleBinding that binds the router
// ServiceAccount to the router Role.
func BuildRoleBinding(gw *gwv1.Gateway, scheme *runtime.Scheme) (*rbacv1.RoleBinding, error) {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      RouterRBACName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     RouterRBACName(gw.Name),
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      RouterRBACName(gw.Name),
			Namespace: gw.Namespace,
		}},
	}
	if err := controllerutil.SetControllerReference(gw, rb, scheme); err != nil {
		return nil, err
	}
	return rb, nil
}

// initContainerArgs returns the flag list passed to tor-init. When client
// auth is enabled, the --client-auth-src flag points at the Secret mount.
func initContainerArgs(auth EffectiveClientAuth) []string {
	args := []string{
		"--src", keysMountPath,
		"--dst", hsServiceDir,
	}
	if auth.Enabled {
		args = append(args, "--client-auth-src", clientAuthMountPath)
	}
	return args
}

// initContainerMounts returns the volume mount list for tor-init. The
// client-auth mount is added only when auth is enabled so we don't fail
// pod admission referencing a Secret that wasn't required.
func initContainerMounts(auth EffectiveClientAuth) []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{Name: keysVolumeName, MountPath: keysMountPath, ReadOnly: true},
		{Name: hsDirVolumeName, MountPath: hsDirMountPath},
	}
	if auth.Enabled {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      clientAuthVolumeName,
			MountPath: clientAuthMountPath,
			ReadOnly:  true,
		})
	}
	return mounts
}

// BuildService emits a headless Service in front of the Tor pod. Used for
// onionbalance backend discovery (later) and for health-check wiring.
func BuildService(gw *gwv1.Gateway, scheme *runtime.Scheme) (*corev1.Service, error) {
	labels := ChildLabels(gw.Name)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone, // headless
			Selector:  labels,
			Ports: []corev1.ServicePort{{
				Name:       "router",
				Port:       int32(loopbackTargetPort),
				TargetPort: intstr.FromInt(loopbackTargetPort),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
	if err := controllerutil.SetControllerReference(gw, svc, scheme); err != nil {
		return nil, err
	}
	return svc, nil
}
