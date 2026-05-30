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
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// testScheme returns a runtime.Scheme with every type the builders need
// for SetControllerReference to find the Gateway kind.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(gwv1.Install(s))
	utilruntime.Must(policyv1alpha1.AddToScheme(s))
	return s
}

// testGwNamespace is the namespace of the fixtures sampleGateway builds.
const testGwNamespace = "prod"

func sampleGateway() *gwv1.Gateway {
	return &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "blog",
			Namespace: testGwNamespace,
			UID:       "11111111-2222-3333-4444-555555555555",
		},
		Spec: gwv1.GatewaySpec{
			GatewayClassName: "tor-gateway",
			Listeners: []gwv1.Listener{{
				Name:     "onion",
				Port:     80,
				Protocol: HiddenServiceProtocol,
			}},
		},
	}
}

func sampleImages() RuntimeImages {
	return RuntimeImages{
		Tor:      "ghcr.io/chimbosonic/tor:0.4.9",
		Router:   "ghcr.io/chimbosonic/tor-gateway-router:dev",
		TorInit:  "ghcr.io/chimbosonic/tor-gateway-tor-init:dev",
		Operator: "ghcr.io/chimbosonic/tor-gateway-manager:dev",
	}
}

// --- BuildKeySecret ---

func TestBuildKeySecret_HasExpectedDataAndOwner(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := BuildKeySecret(gw, kp, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Name != "blog-keys" || secret.Namespace != testGwNamespace {
		t.Fatalf("wrong meta: %s/%s", secret.Namespace, secret.Name)
	}
	if got := secret.Type; got != corev1.SecretTypeOpaque {
		t.Fatalf("type = %s, want Opaque", got)
	}
	for _, key := range []string{tor.FileSecretKeyName, tor.FilePublicKeyName, tor.FileHostnameName} {
		if _, ok := secret.Data[key]; !ok {
			t.Fatalf("Secret missing data[%q]", key)
		}
	}
	if len(secret.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference, got %d", len(secret.OwnerReferences))
	}
	if secret.OwnerReferences[0].UID != gw.UID {
		t.Fatalf("owner UID = %s, want %s", secret.OwnerReferences[0].UID, gw.UID)
	}
	if !*secret.OwnerReferences[0].Controller {
		t.Fatal("owner reference should be controller=true")
	}
	if got := string(secret.Data[tor.FileHostnameName]); !strings.HasSuffix(strings.TrimSpace(got), ".onion") {
		t.Fatalf("hostname does not end with .onion: %q", got)
	}
}

// --- BuildTorrcConfigMap ---

func TestBuildTorrcConfigMap_UsesPolicyValues(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	cm, err := BuildTorrcConfigMap(gw, EffectiveServicePolicy{
		LogLevel:           "debug",
		PoWDefensesEnabled: false,
	}, EffectiveClientAuth{}, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Name != "blog-torrc" || cm.Namespace != testGwNamespace {
		t.Fatalf("wrong meta: %s/%s", cm.Namespace, cm.Name)
	}
	torrc := cm.Data["torrc"]
	if !strings.Contains(torrc, "Log debug stdout") {
		t.Fatalf("policy LogLevel not propagated: %q", torrc)
	}
	if strings.Contains(torrc, "HiddenServicePoWDefensesEnabled 1") {
		t.Fatalf("PoW directives should be absent when policy.PoWDefensesEnabled=false; got %q", torrc)
	}
	if len(cm.OwnerReferences) != 1 {
		t.Fatal("expected OwnerReference")
	}
}

func TestBuildTorrcConfigMap_DefaultPolicyEnablesPoW(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	cm, err := BuildTorrcConfigMap(gw, DefaultPolicy(), EffectiveClientAuth{}, scheme)
	if err != nil {
		t.Fatal(err)
	}
	torrc := cm.Data["torrc"]
	if !strings.Contains(torrc, "HiddenServicePoWDefensesEnabled 1") {
		t.Fatalf("default policy should enable PoW defenses; got %q", torrc)
	}
	if !strings.Contains(torrc, "Log notice stdout") {
		t.Fatalf("default log level should be notice; got %q", torrc)
	}
}

// --- BuildDeployment ---

func TestBuildDeployment_ContainersAndHardening(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	dep, err := BuildDeployment(gw, DefaultPolicy(), EffectiveClientAuth{}, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	tpl := dep.Spec.Template.Spec
	if len(tpl.InitContainers) != 1 || tpl.InitContainers[0].Name != initContainerName {
		t.Fatalf("expected init container %q, got %+v", initContainerName, tpl.InitContainers)
	}
	names := make([]string, 0, len(tpl.Containers))
	for _, c := range tpl.Containers {
		names = append(names, c.Name)
	}
	if !slices.Contains(names, torContainerName) || !slices.Contains(names, routerContainer) {
		t.Fatalf("missing expected containers; got %v", names)
	}

	for _, c := range append(tpl.InitContainers, tpl.Containers...) {
		if c.SecurityContext == nil ||
			c.SecurityContext.AllowPrivilegeEscalation == nil ||
			*c.SecurityContext.AllowPrivilegeEscalation {
			t.Fatalf("container %s does not deny privilege escalation", c.Name)
		}
		if c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			t.Fatalf("container %s root FS not read-only", c.Name)
		}
		if c.SecurityContext.Capabilities == nil ||
			!hasCap(c.SecurityContext.Capabilities.Drop, "ALL") {
			t.Fatalf("container %s does not drop ALL caps", c.Name)
		}
	}

	if tpl.SecurityContext == nil ||
		tpl.SecurityContext.SeccompProfile == nil ||
		tpl.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatal("pod must use RuntimeDefault seccomp profile")
	}
}

func TestBuildDeployment_VolumeWiring(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	dep, err := BuildDeployment(gw, DefaultPolicy(), EffectiveClientAuth{}, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	tpl := dep.Spec.Template.Spec

	var keysVol, configVol *corev1.Volume
	for i := range tpl.Volumes {
		v := &tpl.Volumes[i]
		switch v.Name {
		case keysVolumeName:
			keysVol = v
		case configVolumeName:
			configVol = v
		}
	}
	if keysVol == nil || keysVol.Secret == nil {
		t.Fatal("keys volume is not backed by a Secret")
	}
	if keysVol.Secret.SecretName != "blog-keys" {
		t.Fatalf("keys Secret name = %q, want blog-keys", keysVol.Secret.SecretName)
	}
	if keysVol.Secret.DefaultMode == nil || *keysVol.Secret.DefaultMode != 0o600 {
		t.Fatal("keys Secret defaultMode must be 0600")
	}
	if configVol == nil || configVol.ConfigMap == nil {
		t.Fatal("config volume is not backed by a ConfigMap")
	}
	if configVol.ConfigMap.Name != "blog-torrc" {
		t.Fatalf("torrc ConfigMap name = %q, want blog-torrc", configVol.ConfigMap.Name)
	}
}

func TestBuildDeployment_RequiresImages(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	if _, err := BuildDeployment(gw, DefaultPolicy(), EffectiveClientAuth{}, RuntimeImages{Router: "x", TorInit: "y"}, scheme); err == nil {
		t.Fatal("expected error with missing Tor image")
	}
}

// --- BuildService ---

func TestBuildService_HeadlessWithRouterPort(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	svc, err := BuildService(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if svc.Spec.ClusterIP != corev1.ClusterIPNone {
		t.Fatalf("Service should be headless; got ClusterIP=%q", svc.Spec.ClusterIP)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != int32(loopbackTargetPort) {
		t.Fatalf("Service ports = %+v", svc.Spec.Ports)
	}
}

// --- FromTorServicePolicy ---

func TestFromTorServicePolicy_AppliesDefaults(t *testing.T) {
	eff := FromTorServicePolicy(nil)
	if eff.LogLevel != "notice" {
		t.Fatalf("nil policy LogLevel = %q, want notice", eff.LogLevel)
	}
	if !eff.PoWDefensesEnabled {
		t.Fatal("nil policy must enable PoW defenses")
	}
	if eff.VanityPrefix != "" {
		t.Fatalf("nil policy VanityPrefix = %q, want empty", eff.VanityPrefix)
	}
}

func TestFromTorServicePolicy_RespectsSpec(t *testing.T) {
	disabled := false
	p := &policyv1alpha1.TorServicePolicy{
		Spec: policyv1alpha1.TorServicePolicySpec{
			LogLevel:           "debug",
			PoWDefensesEnabled: &disabled,
			VanityPrefix:       "foo",
		},
	}
	eff := FromTorServicePolicy(p)
	if eff.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q", eff.LogLevel)
	}
	if eff.PoWDefensesEnabled {
		t.Fatal("PoWDefensesEnabled must follow spec=false")
	}
	if eff.VanityPrefix != "foo" {
		t.Fatalf("VanityPrefix = %q", eff.VanityPrefix)
	}
}

func hasCap(list []corev1.Capability, want corev1.Capability) bool {
	return slices.Contains(list, want)
}

// --- Client auth wiring ---

func TestBuildTorrcConfigMap_ClientAuthEnabled_SetsAuthDir(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	cm, err := BuildTorrcConfigMap(gw, DefaultPolicy(),
		EffectiveClientAuth{Enabled: true, SecretName: "blog-clients"}, scheme)
	if err != nil {
		t.Fatal(err)
	}
	torrc := cm.Data["torrc"]
	if !strings.Contains(torrc, "client authorization enabled") {
		t.Fatalf("expected client-auth marker comment in torrc; got %q", torrc)
	}
}

func TestBuildDeployment_ClientAuth_AddsVolumeMountAndFlag(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	dep, err := BuildDeployment(gw, DefaultPolicy(),
		EffectiveClientAuth{Enabled: true, SecretName: "blog-clients"},
		sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	tpl := dep.Spec.Template.Spec

	var clientAuthVol *corev1.Volume
	for i := range tpl.Volumes {
		if tpl.Volumes[i].Name == clientAuthVolumeName {
			clientAuthVol = &tpl.Volumes[i]
			break
		}
	}
	if clientAuthVol == nil {
		t.Fatal("expected a tor-client-auth Volume when ClientAuth is enabled")
	}
	if clientAuthVol.Secret == nil || clientAuthVol.Secret.SecretName != "blog-clients" {
		t.Fatalf("client-auth volume should reference SecretName=%q, got %+v",
			"blog-clients", clientAuthVol.Secret)
	}

	if len(tpl.InitContainers) != 1 {
		t.Fatalf("expected one init container, got %d", len(tpl.InitContainers))
	}
	init := tpl.InitContainers[0]
	if !slices.Contains(init.Args, "--client-auth-src") {
		t.Fatalf("tor-init args missing --client-auth-src; got %v", init.Args)
	}
	mountSeen := false
	for _, m := range init.VolumeMounts {
		if m.Name == clientAuthVolumeName {
			mountSeen = true
			if !m.ReadOnly {
				t.Fatal("client-auth mount must be read-only")
			}
		}
	}
	if !mountSeen {
		t.Fatal("tor-init init container missing tor-client-auth mount")
	}
}

func TestBuildTorrc_DirsAreProcessOwnedSubdirs(t *testing.T) {
	cm, err := BuildTorrcConfigMap(sampleGateway(), DefaultPolicy(), EffectiveClientAuth{}, testScheme(t))
	if err != nil {
		t.Fatalf("BuildTorrcConfigMap: %v", err)
	}
	torrc := cm.Data["torrc"]

	// The HiddenServiceDir and DataDirectory must be nested *inside* the
	// emptyDir mount roots, not equal to them: fsGroup leaves the mount root
	// owned by root, and Tor/tor-init require dirs owned by UID 65532, which
	// only happens for subdirs the process creates itself.
	if !strings.Contains(torrc, "HiddenServiceDir "+hsDirMountPath+"/") {
		t.Fatalf("HiddenServiceDir must be a subdir of %q; got torrc:\n%s", hsDirMountPath, torrc)
	}
	if strings.Contains(torrc, "HiddenServiceDir "+hsDirMountPath+"\n") {
		t.Fatalf("HiddenServiceDir must not equal the mount root %q", hsDirMountPath)
	}
	if !strings.Contains(torrc, "DataDirectory "+dataMountPath+"/") {
		t.Fatalf("DataDirectory must be a subdir of %q; got torrc:\n%s", dataMountPath, torrc)
	}
	if strings.Contains(torrc, "DataDirectory "+dataMountPath+"\n") {
		t.Fatalf("DataDirectory must not equal the mount root %q", dataMountPath)
	}

	// tor-init's --dst must equal the (subdir) HiddenServiceDir so it creates
	// and perms exactly the directory Tor will use.
	args := initContainerArgs(EffectiveClientAuth{})
	if !slices.Contains(args, hsServiceDir) {
		t.Fatalf("tor-init --dst should be %q; got args %v", hsServiceDir, args)
	}
}

func TestBuildDeployment_ClientAuthDisabled_NoExtraVolume(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	dep, err := BuildDeployment(gw, DefaultPolicy(),
		EffectiveClientAuth{}, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == clientAuthVolumeName {
			t.Fatalf("client-auth volume should be absent when ClientAuth.Enabled=false")
		}
	}
	if slices.Contains(dep.Spec.Template.Spec.InitContainers[0].Args, "--client-auth-src") {
		t.Fatalf("tor-init args should not include --client-auth-src when ClientAuth.Enabled=false")
	}
}

// --- Router RBAC builders ---

func TestBuildServiceAccount_NameNamespaceOwner(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	sa, err := BuildServiceAccount(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Name != RouterRBACName("blog") {
		t.Fatalf("name = %q, want %q", sa.Name, RouterRBACName("blog"))
	}
	if sa.Namespace != testGwNamespace {
		t.Fatalf("namespace = %q, want prod", sa.Namespace)
	}
	if len(sa.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference, got %d", len(sa.OwnerReferences))
	}
	if sa.OwnerReferences[0].UID != gw.UID {
		t.Fatalf("owner UID = %s, want %s", sa.OwnerReferences[0].UID, gw.UID)
	}
}

func TestBuildRole_GrantsHTTPRouteRead(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	role, err := BuildRole(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if role.Name != RouterRBACName("blog") {
		t.Fatalf("name = %q, want %q", role.Name, RouterRBACName("blog"))
	}
	if role.Namespace != testGwNamespace {
		t.Fatalf("namespace = %q, want prod", role.Namespace)
	}
	if len(role.OwnerReferences) != 1 || role.OwnerReferences[0].UID != gw.UID {
		t.Fatalf("expected Gateway owner ref, got %+v", role.OwnerReferences)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("expected exactly 1 rule, got %d", len(role.Rules))
	}
	rule := role.Rules[0]
	if !slices.Contains(rule.APIGroups, "gateway.networking.k8s.io") {
		t.Fatalf("rule.APIGroups = %v, want [gateway.networking.k8s.io]", rule.APIGroups)
	}
	if !slices.Contains(rule.Resources, "httproutes") {
		t.Fatalf("rule.Resources = %v, want [httproutes]", rule.Resources)
	}
	for _, v := range []string{"get", "list", "watch"} {
		if !slices.Contains(rule.Verbs, v) {
			t.Fatalf("rule.Verbs = %v, missing %q", rule.Verbs, v)
		}
	}
	for _, v := range []string{"create", "update", "delete"} {
		if slices.Contains(rule.Verbs, v) {
			t.Fatalf("rule.Verbs = %v, must NOT contain %q", rule.Verbs, v)
		}
	}
}

func TestBuildRoleBinding_BindsServiceAccountToRole(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	rb, err := BuildRoleBinding(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if rb.Name != RouterRBACName("blog") {
		t.Fatalf("name = %q, want %q", rb.Name, RouterRBACName("blog"))
	}
	if rb.Namespace != testGwNamespace {
		t.Fatalf("namespace = %q, want prod", rb.Namespace)
	}
	if len(rb.OwnerReferences) != 1 || rb.OwnerReferences[0].UID != gw.UID {
		t.Fatalf("expected Gateway owner ref, got %+v", rb.OwnerReferences)
	}
	if rb.RoleRef.Kind != "Role" {
		t.Fatalf("RoleRef.Kind = %q, want Role", rb.RoleRef.Kind)
	}
	if rb.RoleRef.Name != RouterRBACName("blog") {
		t.Fatalf("RoleRef.Name = %q, want %q", rb.RoleRef.Name, RouterRBACName("blog"))
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(rb.Subjects))
	}
	sub := rb.Subjects[0]
	if sub.Kind != "ServiceAccount" {
		t.Fatalf("Subject.Kind = %q, want ServiceAccount", sub.Kind)
	}
	if sub.Name != RouterRBACName("blog") {
		t.Fatalf("Subject.Name = %q, want %q", sub.Name, RouterRBACName("blog"))
	}
	if sub.Namespace != testGwNamespace {
		t.Fatalf("Subject.Namespace = %q, want prod", sub.Namespace)
	}
}

func TestBuildDeployment_UsesRouterServiceAccount(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	dep, err := BuildDeployment(gw, DefaultPolicy(), EffectiveClientAuth{}, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	if dep.Spec.Template.Spec.ServiceAccountName != RouterRBACName("blog") {
		t.Fatalf("ServiceAccountName = %q, want %q",
			dep.Spec.Template.Spec.ServiceAccountName, RouterRBACName("blog"))
	}
}

func TestBuildDeployment_RouterHasProbePortAndProbes(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	dep, err := BuildDeployment(gw, DefaultPolicy(), EffectiveClientAuth{}, sampleImages(), scheme)
	if err != nil {
		t.Fatalf("BuildDeployment: %v", err)
	}
	var router *corev1.Container
	for i, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == "router" {
			router = &dep.Spec.Template.Spec.Containers[i]
			break
		}
	}
	if router == nil {
		t.Fatal("router container not found")
	}
	// containerPort
	var probePortFound bool
	for _, p := range router.Ports {
		if p.Name == "probe" && p.ContainerPort == 8081 {
			probePortFound = true
		}
	}
	if !probePortFound {
		t.Errorf("router missing probe containerPort 8081; got ports=%v", router.Ports)
	}
	// liveness probe
	if router.LivenessProbe == nil || router.LivenessProbe.HTTPGet == nil {
		t.Fatalf("router missing httpGet livenessProbe")
	}
	if router.LivenessProbe.HTTPGet.Path != "/healthz" || router.LivenessProbe.HTTPGet.Port.IntValue() != 8081 {
		t.Errorf("router livenessProbe httpGet wrong: %+v", router.LivenessProbe.HTTPGet)
	}
	// readiness probe
	if router.ReadinessProbe == nil || router.ReadinessProbe.HTTPGet == nil {
		t.Fatalf("router missing httpGet readinessProbe")
	}
	if router.ReadinessProbe.HTTPGet.Path != "/healthz" || router.ReadinessProbe.HTTPGet.Port.IntValue() != 8081 {
		t.Errorf("router readinessProbe httpGet wrong: %+v", router.ReadinessProbe.HTTPGet)
	}
}

func TestBuildDeployment_TorHasMetricsPortAndProbes(t *testing.T) {
	gw := sampleGateway()
	dep, err := BuildDeployment(gw, DefaultPolicy(), EffectiveClientAuth{}, sampleImages(), testScheme(t))
	if err != nil {
		t.Fatalf("BuildDeployment: %v", err)
	}
	var tor *corev1.Container
	for i, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == "tor" {
			tor = &dep.Spec.Template.Spec.Containers[i]
			break
		}
	}
	if tor == nil {
		t.Fatal("tor container not found")
	}
	// containerPort
	var metricsPortFound bool
	for _, p := range tor.Ports {
		if p.Name == "metrics" && p.ContainerPort == 9035 {
			metricsPortFound = true
		}
	}
	if !metricsPortFound {
		t.Errorf("tor missing metrics containerPort 9035; got ports=%v", tor.Ports)
	}
	for _, probe := range []struct {
		name string
		p    *corev1.Probe
	}{
		{"startup", tor.StartupProbe},
		{"liveness", tor.LivenessProbe},
		{"readiness", tor.ReadinessProbe},
	} {
		if probe.p == nil || probe.p.HTTPGet == nil {
			t.Fatalf("tor missing httpGet %sProbe", probe.name)
		}
		if probe.p.HTTPGet.Path != "/metrics" || probe.p.HTTPGet.Port.IntValue() != 9035 {
			t.Errorf("tor %sProbe wrong: %+v", probe.name, probe.p.HTTPGet)
		}
	}
}

func TestBuildTorrcConfigMap_SetsMetricsPort(t *testing.T) {
	gw := sampleGateway()
	cm, err := BuildTorrcConfigMap(gw, DefaultPolicy(), EffectiveClientAuth{}, testScheme(t))
	if err != nil {
		t.Fatalf("BuildTorrcConfigMap: %v", err)
	}
	torrc := cm.Data["torrc"]
	for _, want := range []string{"MetricsPort 0.0.0.0:9035", "MetricsPortPolicy accept 0.0.0.0/0"} {
		if !strings.Contains(torrc, want) {
			t.Errorf("torrc missing %q\n--- torrc ---\n%s", want, torrc)
		}
	}
}
