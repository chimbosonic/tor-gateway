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
	"strings"

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

const (
	haRoleBackend  = "backend"
	haRoleFrontend = "frontend"
	haRoleKey      = "torgateway.io/role"
)

// HALabels returns the standard Mode B label set for the Gateway. The
// Gateway-scoping label is shared with Mode A so a single NetworkPolicy
// covers both modes.
func HALabels(gw *gwv1.Gateway, role string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "tor-gateway",
		"app.kubernetes.io/instance": gw.Name,
		gatewayLabelKey:              gw.Name,
		haRoleKey:                    role,
	}
}

// Resource name helpers. Centralised so the Gateway reconciler and tests
// agree on the spelling.

func FrontendName(gw *gwv1.Gateway) string               { return gw.Name + "-frontend" }
func BackendStatefulSetName(gw *gwv1.Gateway) string     { return gw.Name + "-backend" }
func BackendHeadlessServiceName(gw *gwv1.Gateway) string { return gw.Name + "-backends" }
func BackendKeySecretName(gw *gwv1.Gateway, idx int) string {
	return fmt.Sprintf("%s-backend-%d-keys", gw.Name, idx)
}
func OnionbalanceConfigMapName(gw *gwv1.Gateway) string {
	return gw.Name + "-onionbalance-config"
}

// ownerLabels extends HALabels with torgateway.io/owner-uid, which the
// obrefresh informer requires to skip tenant-planted Secrets that happen
// to match the gateway/role labels (defense in depth).
func ownerLabels(gw *gwv1.Gateway, role string) map[string]string {
	l := HALabels(gw, role)
	l["torgateway.io/owner-uid"] = string(gw.UID)
	return l
}

// BuildBackendKeySecret renders a per-pod Secret holding the ed25519 key
// for backend index idx. When existing is non-nil and already contains key
// material, its data is reused verbatim — this avoids regenerating and
// discarding a fresh keypair on every reconcile. When existing is nil or
// empty, a new ed25519 keypair is generated. data["hostname"] is
// pre-populated from the key pair (with trailing "\n" to match Mode A's
// on-disk format) so obrefresh's readiness gate fires immediately and the
// renderer never depends on a tor-init write-back. The owner-uid label lets
// the obrefresh informer filter out tenant-planted Secrets carrying the same
// gateway/role labels.
func BuildBackendKeySecret(gw *gwv1.Gateway, idx int, existing *corev1.Secret, scheme *runtime.Scheme) (*corev1.Secret, error) {
	var data map[string][]byte
	if existing != nil && len(existing.Data[tor.FileSecretKeyName]) > 0 {
		data = existing.Data
	} else {
		kp, err := tor.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate backend key: %w", err)
		}
		data = map[string][]byte{
			tor.FileSecretKeyName: kp.SecretKeyFile(),
			tor.FilePublicKeyName: kp.PublicKeyFile(),
			tor.FileHostnameName:  kp.Hostname(),
		}
	}
	// Pre-compute the .onion address here: obrefresh's readiness check
	// keys off Secret.Data["hostname"], and we own this Secret end-to-end
	// (no tor-side write-back is needed). Without this field the refresher
	// treats every backend as not-yet-ready and never writes a real config.
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BackendKeySecretName(gw, idx),
			Namespace: gw.Namespace,
			Labels:    ownerLabels(gw, haRoleBackend),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	if err := controllerutil.SetControllerReference(gw, s, scheme); err != nil {
		return nil, err
	}
	return s, nil
}

// BuildBackendHeadlessService renders the headless Service that gives the
// StatefulSet pods stable DNS names.
func BuildBackendHeadlessService(gw *gwv1.Gateway, scheme *runtime.Scheme) (*corev1.Service, error) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BackendHeadlessServiceName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, haRoleBackend),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  HALabels(gw, haRoleBackend),
			Ports: []corev1.ServicePort{
				{Name: "tor", Port: loopbackTargetPort, TargetPort: intstr.FromInt(loopbackTargetPort)},
			},
		},
	}
	if err := controllerutil.SetControllerReference(gw, svc, scheme); err != nil {
		return nil, err
	}
	return svc, nil
}

// BuildBackendStatefulSet renders the backend Tor StatefulSet. Each
// replica gets its own per-pod ed25519 key Secret projected into a
// single Volume at /var/lib/tor-keys/<i>/; tor-init reads POD_NAME from
// the downward API, parses the trailing index, and copies the right
// pair into the HSDir. PoW directives are unconditionally omitted on
// backends per the spec (see onionbalance#13).
func BuildBackendStatefulSet(
	gw *gwv1.Gateway,
	pol *policyv1alpha1.OnionBalancePolicy,
	master tor.OnionAddress,
	images RuntimeImages,
	scheme *runtime.Scheme,
) (*appsv1.StatefulSet, error) {
	if images.Tor == "" || images.TorInit == "" {
		return nil, fmt.Errorf("BuildBackendStatefulSet: required image flag not set; check --tor-image, --tor-init-image")
	}
	replicas := pol.Spec.Replicas
	labels := HALabels(gw, haRoleBackend)

	// Pointer-to-literal locals; using ptr.To(true) trips modernize's
	// newexpr rule, whose suggested rewrite to new(T) silently swaps in
	// the zero value and would weaken pod security.
	nonRoot := true
	uid := int64(65532)

	pod := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec: corev1.PodSpec{
			ServiceAccountName: RouterRBACName(gw.Name),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   &nonRoot,
				RunAsUser:      &uid,
				RunAsGroup:     &uid,
				FSGroup:        &uid,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			InitContainers: []corev1.Container{{
				Name:  initContainerName,
				Image: images.TorInit,
				Args: []string{
					"--dst=" + hsServiceDir,
					"--src=",
					"--ob-master-address=" + master.String(),
					fmt.Sprintf("--api-fetch-secret-prefix=%s-backend-", gw.Name),
				},
				Env: []corev1.EnvVar{
					{
						Name: "POD_NAME",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
						},
					},
					{
						Name: "POD_NAMESPACE",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
						},
					},
				},
				VolumeMounts:    backendInitVolumeMounts(),
				SecurityContext: haHardenedSecurityContext(),
			}},
			Containers: []corev1.Container{
				{
					Name:            torContainerName,
					Image:           images.Tor,
					Args:            []string{"-f", "/etc/tor/torrc"},
					Ports:           []corev1.ContainerPort{{Name: "metrics", ContainerPort: torMetricsPort}},
					ReadinessProbe:  torReadinessProbeHA(),
					LivenessProbe:   torLivenessProbeHA(),
					StartupProbe:    torStartupProbeHA(),
					VolumeMounts:    backendTorVolumeMounts(),
					SecurityContext: haHardenedSecurityContext(),
					Resources:       derefResources(pol.Spec.BackendResources),
				},
				{
					Name:  routerContainer,
					Image: images.Router,
					Args: []string{
						"--gateway=" + gw.Name,
						"--namespace=" + gw.Namespace,
					},
					ReadinessProbe:  routerHealthzProbeHA(),
					LivenessProbe:   routerHealthzProbeHA(),
					SecurityContext: haHardenedSecurityContext(),
				},
			},
			Volumes: backendPodVolumes(gw),
			TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
				MaxSkew:           1,
				TopologyKey:       "kubernetes.io/hostname",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector:     &metav1.LabelSelector{MatchLabels: HALabels(gw, haRoleBackend)},
			}},
		},
	}
	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BackendStatefulSetName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:            &replicas,
			Selector:            &metav1.LabelSelector{MatchLabels: labels},
			ServiceName:         BackendHeadlessServiceName(gw),
			Template:            pod,
			PodManagementPolicy: appsv1.ParallelPodManagement,
		},
	}
	if err := controllerutil.SetControllerReference(gw, ss, scheme); err != nil {
		return nil, err
	}
	return ss, nil
}

func backendInitVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: "hs", MountPath: hsDirMountPath},
	}
}

func backendTorVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: "hs", MountPath: hsDirMountPath},
		// tor-data carries Tor's DataDirectory (descriptors, cookies, etc.).
		// Mode A mounts the same emptyDir; without it Tor cannot write under
		// the read-only rootfs and fails to start.
		{Name: dataVolumeName, MountPath: dataMountPath},
		{Name: "torrc", MountPath: configMountPath, ReadOnly: true},
	}
}

func backendPodVolumes(gw *gwv1.Gateway) []corev1.Volume {
	return []corev1.Volume{
		{Name: "hs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: dataVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "torrc", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: BackendTorrcConfigMapName(gw)},
		}}},
	}
}

// BackendTorrcConfigMapName returns the name of the ConfigMap holding the
// backend Tor torrc.
func BackendTorrcConfigMapName(gw *gwv1.Gateway) string {
	return gw.Name + "-backend-torrc"
}

// BuildBackendTorrcConfigMap renders the torrc for backend Tor instances.
// Identical to Mode A's torrc but with OnionbalanceInstance=true (which
// emits HiddenServiceOnionbalanceInstance 1 and unconditionally omits
// the PoW directives — see onionbalance#13).
// testingNetworkInclude, when non-empty, is spliced verbatim into the
// rendered torrc; pass "" for production deployments.
func BuildBackendTorrcConfigMap(
	gw *gwv1.Gateway,
	pol *policyv1alpha1.OnionBalancePolicy,
	eff EffectiveServicePolicy,
	auth EffectiveClientAuth,
	testingNetworkInclude string,
	scheme *runtime.Scheme,
) (*corev1.ConfigMap, error) {
	cfg := &tor.TorrcConfig{
		HiddenServiceDir:      hsServiceDir,
		DataDirectory:         torDataDir,
		LogLevel:              eff.LogLevel,
		PoWDefensesEnabled:    eff.PoWDefensesEnabled,
		OnionbalanceInstance:  true,
		TestingNetworkInclude: testingNetworkInclude,
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
		return nil, fmt.Errorf("render backend torrc: %w", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BackendTorrcConfigMapName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, haRoleBackend),
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

// haHardenedSecurityContext returns a container SecurityContext with the
// minimal privilege set required by all Mode B containers.
func haHardenedSecurityContext() *corev1.SecurityContext {
	// Pointer-to-literal locals; using ptr.To(false/true) trips modernize's
	// newexpr rule, whose suggested rewrite to new(T) silently substitutes
	// the zero value and would weaken security.
	allowEsc := false
	readOnly := true
	nonRoot := true
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &allowEsc,
		ReadOnlyRootFilesystem:   &readOnly,
		RunAsNonRoot:             &nonRoot,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
}

// derefResources returns the given ResourceRequirements, substituting a
// conservative default when nil.
func derefResources(r *corev1.ResourceRequirements) corev1.ResourceRequirements {
	if r == nil {
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("50m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
		}
	}
	return *r
}

func torReadinessProbeHA() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:  corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/metrics", Port: intstr.FromInt(torMetricsPort)}},
		PeriodSeconds: 10,
	}
}

func torLivenessProbeHA() *corev1.Probe { return torReadinessProbeHA() }

func torStartupProbeHA() *corev1.Probe {
	p := torReadinessProbeHA()
	p.FailureThreshold = 30
	return p
}

func routerHealthzProbeHA() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:  corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt(routerProbePort)}},
		PeriodSeconds: 10,
	}
}

// BuildFrontendServiceAccount emits the per-Gateway ServiceAccount used by
// the frontend pod (tor + onionbalance + obrefresh).
func BuildFrontendServiceAccount(gw *gwv1.Gateway, scheme *runtime.Scheme) (*corev1.ServiceAccount, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, haRoleFrontend),
		},
	}
	if err := controllerutil.SetControllerReference(gw, sa, scheme); err != nil {
		return nil, err
	}
	return sa, nil
}

// BuildFrontendRole emits the per-Gateway Role granting the frontend pod
// read-only access to Secrets. The get verb is scoped to the specific backend
// key Secrets (and the in-namespace master Secret when applicable) via
// resourceNames. list/watch must remain namespace-wide due to RBAC limitations;
// the informer's label-selector narrows what is actually observed in code.
func BuildFrontendRole(gw *gwv1.Gateway, pol *policyv1alpha1.OnionBalancePolicy, scheme *runtime.Scheme) (*rbacv1.Role, error) {
	backendNames := make([]string, 0, pol.Spec.Replicas+1)
	for i := int32(0); i < pol.Spec.Replicas; i++ {
		backendNames = append(backendNames, BackendKeySecretName(gw, int(i)))
	}
	masterNS := pol.Spec.MasterKeySecretRef.Namespace
	if masterNS == "" || masterNS == gw.Namespace {
		backendNames = append(backendNames, pol.Spec.MasterKeySecretRef.Name)
	}

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, haRoleFrontend),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				Verbs:         []string{"get"},
				ResourceNames: backendNames,
			},
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"list", "watch"},
			},
		},
	}
	if err := controllerutil.SetControllerReference(gw, role, scheme); err != nil {
		return nil, err
	}
	return role, nil
}

// BuildFrontendRoleBinding binds the frontend ServiceAccount to the frontend Role.
func BuildFrontendRoleBinding(gw *gwv1.Gateway, scheme *runtime.Scheme) (*rbacv1.RoleBinding, error) {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, haRoleFrontend),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     FrontendName(gw),
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
		}},
	}
	if err := controllerutil.SetControllerReference(gw, rb, scheme); err != nil {
		return nil, err
	}
	return rb, nil
}

// renderFrontendTorrc returns the torrc body for the frontend tor daemon.
// When testingNetworkInclude is non-empty, its content is spliced verbatim
// before the rest of the directives so the frontend tor joins the chutney
// network.
//
// The frontend tor is a vanilla tor with a loopback ControlPort and cookie
// auth; HiddenService directives are absent because onionbalance manages
// them via the control port. DataDirectory and CookieAuthFile both point at
// a subdirectory of the mount, not the mount root: Tor refuses a
// DataDirectory not owned by its uid, and emptyDir mount roots stay
// root-owned even with FSGroup. Tor creates the subdir itself owned by
// 65532 the first time it runs. This mirrors the Mode A torrc shape (see
// names.go: dataMountPath / torDataDir).
func renderFrontendTorrc(testingNetworkInclude string) string {
	var b strings.Builder
	b.WriteString("# generated by tor-gateway operator — do not edit by hand\n")
	if testingNetworkInclude != "" {
		b.WriteString(testingNetworkInclude)
		if !strings.HasSuffix(testingNetworkInclude, "\n") {
			b.WriteString("\n")
		}
	}
	b.WriteString("SocksPort 0\n")
	b.WriteString("ControlPort 9051\n")
	b.WriteString("CookieAuthentication 1\n")
	b.WriteString("CookieAuthFile /var/lib/tor/data/control_auth_cookie\n")
	b.WriteString("DataDirectory /var/lib/tor/data\n")
	b.WriteString("MetricsPort 0.0.0.0:9035\n")
	b.WriteString("MetricsPortPolicy accept 0.0.0.0/0\n")
	b.WriteString("Log notice stdout\n")
	return b.String()
}

// FrontendTorrcConfigMapName returns the name of the ConfigMap holding the
// frontend tor's torrc.
func FrontendTorrcConfigMapName(gw *gwv1.Gateway) string {
	return gw.Name + "-frontend-torrc"
}

// BuildFrontendTorrcConfigMap renders the ConfigMap holding the frontend
// tor daemon's torrc. The optional testingNetworkInclude parameter, when
// non-empty, is spliced verbatim into the torrc so the frontend tor joins
// the chutney network.
func BuildFrontendTorrcConfigMap(gw *gwv1.Gateway, testingNetworkInclude string, scheme *runtime.Scheme) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendTorrcConfigMapName(gw),
			Namespace: gw.Namespace,
			Labels:    HALabels(gw, haRoleFrontend),
		},
		Data: map[string]string{"torrc": renderFrontendTorrc(testingNetworkInclude)},
	}
	if err := controllerutil.SetControllerReference(gw, cm, scheme); err != nil {
		return nil, err
	}
	return cm, nil
}

// CrossNSMasterRoleName returns the name used for the cross-NS Role + RoleBinding pair.
func CrossNSMasterRoleName(gw *gwv1.Gateway) string {
	return FrontendName(gw) + "-master-fetch"
}

// BuildCrossNSMasterRole emits a Role in pol.Spec.MasterKeySecretRef.Namespace
// that allows `get` on exactly the named master Secret. The Role is NOT
// controller-referenced (cross-namespace owner refs are invalid); it is GC'd
// by label in cleanupModeBResources and when the spec namespace changes.
func BuildCrossNSMasterRole(gw *gwv1.Gateway, pol *policyv1alpha1.OnionBalancePolicy, _ *runtime.Scheme) (*rbacv1.Role, error) {
	if pol.Spec.MasterKeySecretRef.Namespace == "" {
		return nil, fmt.Errorf("BuildCrossNSMasterRole: MasterKeySecretRef.Namespace empty")
	}
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: pol.Spec.MasterKeySecretRef.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				gatewayLabelKey:                gw.Name,
				"torgateway.io/owner-uid":      string(gw.UID),
				"torgateway.io/gateway-ns":     gw.Namespace,
			},
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			Verbs:         []string{"get"},
			ResourceNames: []string{pol.Spec.MasterKeySecretRef.Name},
		}},
	}, nil
}

// BuildCrossNSMasterRoleBinding emits a RoleBinding in MasterKeySecretRef.Namespace
// linking the frontend ServiceAccount (in gw.Namespace) to the cross-NS Role.
func BuildCrossNSMasterRoleBinding(gw *gwv1.Gateway, pol *policyv1alpha1.OnionBalancePolicy, _ *runtime.Scheme) (*rbacv1.RoleBinding, error) {
	if pol.Spec.MasterKeySecretRef.Namespace == "" {
		return nil, fmt.Errorf("BuildCrossNSMasterRoleBinding: MasterKeySecretRef.Namespace empty")
	}
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CrossNSMasterRoleName(gw),
			Namespace: pol.Spec.MasterKeySecretRef.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tor-gateway",
				gatewayLabelKey:                gw.Name,
				"torgateway.io/owner-uid":      string(gw.UID),
				"torgateway.io/gateway-ns":     gw.Namespace,
			},
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     CrossNSMasterRoleName(gw),
		},
	}, nil
}

// BuildFrontendDeployment renders the onionbalance frontend Deployment. A
// master-fetch init container populates the ob-keys emptyDir by fetching the
// master key Secret via the tor-init API-fetch path. Three runtime containers
// (tor, onionbalance, obrefresh) then consume the keys read-only; obrefresh
// writes the onionbalance config into the ob-config emptyDir and signals the
// onionbalance process via the ob-run emptyDir pidfile.
func BuildFrontendDeployment(
	gw *gwv1.Gateway,
	pol *policyv1alpha1.OnionBalancePolicy,
	master tor.OnionAddress,
	images RuntimeImages,
	testingMode bool,
	scheme *runtime.Scheme,
) (*appsv1.Deployment, error) {
	if images.Tor == "" || images.TorInit == "" || images.Onionbalance == "" || images.Obrefresh == "" {
		return nil, fmt.Errorf("BuildFrontendDeployment: required image flag not set; check --onionbalance-image, --obrefresh-image, --tor-init-image, --tor-image")
	}
	labels := HALabels(gw, haRoleFrontend)

	// In testing mode, --is-testnet drops onionbalance's descriptor cycle
	// from production timings (FETCH 600s / PUBLISH 300s / LIFETIME 3600s)
	// down to testnet timings (20s / 10s / 20s). Without this, the first
	// HA descriptor publish on chutney takes 5–10 min and times out e2e.
	obArgs := []string{"-c", "/etc/onionbalance/config/config.yaml"}
	if testingMode {
		obArgs = append(obArgs, "--is-testnet")
	}

	// Resolve the master Secret namespace: default to the Gateway's own
	// namespace when the ref omits one (same-namespace Secret).
	masterNS := pol.Spec.MasterKeySecretRef.Namespace
	if masterNS == "" {
		masterNS = gw.Namespace
	}
	masterName := pol.Spec.MasterKeySecretRef.Name

	// Pointer-to-literal locals; using ptr.To(true) trips modernize's
	// newexpr rule, whose suggested rewrite to new(T) silently swaps in
	// the zero value and would weaken pod security.
	nonRoot := true
	shareProc := true
	uid := int64(65532)
	replicas := int32(1)

	masterFetch := corev1.Container{
		Name:            "master-fetch",
		Image:           images.TorInit,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args: []string{
			"--dst=/etc/onionbalance/keys",
			"--src=",
			fmt.Sprintf("--api-fetch-secret=%s/%s", masterNS, masterName),
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "ob-keys", MountPath: "/etc/onionbalance/keys"},
		},
		SecurityContext: haHardenedSecurityContext(),
	}

	pod := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec: corev1.PodSpec{
			ServiceAccountName:    FrontendName(gw),
			ShareProcessNamespace: &shareProc,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   &nonRoot,
				RunAsUser:      &uid,
				RunAsGroup:     &uid,
				FSGroup:        &uid,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			InitContainers: []corev1.Container{masterFetch},
			Containers: []corev1.Container{
				{
					Name:           "tor",
					Image:          images.Tor,
					Args:           []string{"-f", "/etc/tor/torrc"},
					ReadinessProbe: torReadinessProbeHA(),
					LivenessProbe:  torLivenessProbeHA(),
					StartupProbe:   torStartupProbeHA(),
					VolumeMounts: []corev1.VolumeMount{
						{Name: "tor-data", MountPath: "/var/lib/tor"},
						{Name: "torrc", MountPath: "/etc/tor", ReadOnly: true},
					},
					SecurityContext: haHardenedSecurityContext(),
					Resources:       derefResources(pol.Spec.FrontendResources),
				},
				{
					Name:  "onionbalance",
					Image: images.Onionbalance,
					Args:  obArgs,
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{"sh", "-c", "test -s /run/onionbalance/onionbalance.pid"},
							},
						},
						InitialDelaySeconds: 15,
						PeriodSeconds:       30,
						FailureThreshold:    3,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "ob-config", MountPath: "/etc/onionbalance/config"},
						{Name: "ob-keys", MountPath: "/etc/onionbalance/keys", ReadOnly: true},
						{Name: "ob-run", MountPath: "/run/onionbalance"},
						{Name: "tor-data", MountPath: "/var/lib/tor", ReadOnly: true},
					},
					SecurityContext: haHardenedSecurityContext(),
				},
				{
					Name:  obrefreshContainer,
					Image: images.Obrefresh,
					Args: []string{
						"--gateway=" + gw.Name,
						"--namespace=" + gw.Namespace,
						fmt.Sprintf("--gateway-uid=%s", gw.UID),
						"--master-address=" + master.String(),
						"--master-key-path=/etc/onionbalance/keys/hs_ed25519_secret_key",
						"--config=/etc/onionbalance/config/config.yaml",
						"--pidfile=/run/onionbalance/onionbalance.pid",
						"--interval=" + pol.Spec.RefreshInterval.Duration.String(),
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								// The obrefresh image is distroless; the binary is
								// copied in as /usr/local/bin/app (see Dockerfile).
								// --interval must match the daemon's value so the
								// healthcheck window (2×interval) covers the actual
								// write cadence; omitting it would default to 30s and
								// fire spuriously when RefreshInterval > 90s.
								Command: []string{
									"/usr/local/bin/app",
									"--healthcheck",
									"--interval=" + pol.Spec.RefreshInterval.Duration.String(),
								},
							},
						},
						InitialDelaySeconds: 60,
						PeriodSeconds:       30,
						FailureThreshold:    3,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "ob-config", MountPath: "/etc/onionbalance/config"},
						{Name: "ob-run", MountPath: "/run/onionbalance", ReadOnly: true},
						{Name: "ob-refresh-run", MountPath: "/run/obrefresh"},
					},
					SecurityContext: haHardenedSecurityContext(),
				},
			},
			Volumes: []corev1.Volume{
				{Name: "tor-data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "ob-config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "ob-run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "ob-keys", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "ob-refresh-run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{
					Name: "torrc",
					VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: FrontendTorrcConfigMapName(gw)},
					}},
				},
			},
		},
	}
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FrontendName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: pod,
		},
	}
	if err := controllerutil.SetControllerReference(gw, d, scheme); err != nil {
		return nil, err
	}
	return d, nil
}
