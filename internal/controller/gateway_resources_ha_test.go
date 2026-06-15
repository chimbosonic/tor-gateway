/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

func TestBuildFrontendRole_AllowsEventCreate(t *testing.T) {
	role, err := BuildFrontendRole(sampleGateway(), samplePolicy(2), testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range role.Rules {
		if slices.Contains(rule.Resources, "events") && slices.Contains(rule.Verbs, "create") {
			found = true
		}
	}
	if !found {
		t.Errorf("frontend Role must allow events:create; rules=%v", role.Rules)
	}
}

func samplePolicy(replicas int32) *policyv1alpha1.OnionBalancePolicy {
	return &policyv1alpha1.OnionBalancePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ha-policy",
			Namespace: testGwNamespace,
		},
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			Replicas: replicas,
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{
				Name: "master-keys",
			},
		},
	}
}

func sampleMasterAddr(t *testing.T) tor.OnionAddress {
	t.Helper()
	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return kp.OnionAddress()
}

// --- BuildBackendKeySecret ---

func TestBuildBackendKeySecret_NamingAndLabels(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	s, err := BuildBackendKeySecret(gw, 2, nil, scheme)
	if err != nil {
		t.Fatal(err)
	}
	want := "blog-backend-2-keys"
	if s.Name != want {
		t.Fatalf("name = %q, want %q", s.Name, want)
	}
	if s.Namespace != testGwNamespace {
		t.Fatalf("namespace = %q, want %q", s.Namespace, testGwNamespace)
	}
	if s.Labels[haRoleKey] != haRoleBackend {
		t.Fatalf("label %s = %q, want %q", haRoleKey, s.Labels[haRoleKey], haRoleBackend)
	}
	if s.Labels[gatewayLabelKey] != gw.Name {
		t.Fatalf("label %s = %q, want %q", gatewayLabelKey, s.Labels[gatewayLabelKey], gw.Name)
	}
}

func TestBuildBackendKeySecret_DataAndHostname(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	s, err := BuildBackendKeySecret(gw, 0, nil, scheme)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{tor.FileSecretKeyName, tor.FilePublicKeyName, tor.FileHostnameName} {
		if len(s.Data[key]) == 0 {
			t.Fatalf("Secret missing populated data[%q]", key)
		}
	}
	hostname := string(s.Data[tor.FileHostnameName])
	if !strings.HasSuffix(hostname, ".onion\n") {
		t.Fatalf("hostname must end with .onion\\n; got %q", hostname)
	}
}

func TestBuildBackendKeySecret_OwnerReference(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	s, err := BuildBackendKeySecret(gw, 0, nil, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference, got %d", len(s.OwnerReferences))
	}
	ref := s.OwnerReferences[0]
	if ref.UID != gw.UID {
		t.Fatalf("owner UID = %s, want %s", ref.UID, gw.UID)
	}
	if !*ref.Controller {
		t.Fatal("OwnerReference must have Controller=true")
	}
}

func TestBuildBackendKeySecret_GeneratesKeyWhenNil(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	s, err := BuildBackendKeySecret(gw, 1, nil, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Data["hs_ed25519_secret_key"]) == 0 {
		t.Fatal("auto-generated key must populate hs_ed25519_secret_key")
	}
}

func TestBuildBackendKeySecret_ReusesExistingKeypair(t *testing.T) {
	gw := sampleGateway()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: BackendKeySecretName(gw, 0), Namespace: gw.Namespace},
		Data: map[string][]byte{
			tor.FileSecretKeyName: []byte("OLD-SECRET"),
			tor.FilePublicKeyName: []byte("OLD-PUBLIC"),
			tor.FileHostnameName:  []byte("aaaaa.onion\n"),
		},
	}
	s, err := BuildBackendKeySecret(gw, 0, existing, testScheme(t))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(s.Data[tor.FileSecretKeyName], []byte("OLD-SECRET")) {
		t.Errorf("expected existing secret reused; got %q", s.Data[tor.FileSecretKeyName])
	}
}

func TestBuildBackendKeySecret_HostnameHasTrailingNewline(t *testing.T) {
	s, _ := BuildBackendKeySecret(sampleGateway(), 0, nil, testScheme(t))
	if !bytes.HasSuffix(s.Data[tor.FileHostnameName], []byte(".onion\n")) {
		t.Errorf("hostname must end with .onion\\n to match Mode A; got %q", s.Data[tor.FileHostnameName])
	}
}

// --- BuildBackendHeadlessService ---

func TestBuildBackendHeadlessService_Headless(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	svc, err := BuildBackendHeadlessService(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != BackendHeadlessServiceName(gw) {
		t.Fatalf("name = %q, want %q", svc.Name, BackendHeadlessServiceName(gw))
	}
	if svc.Spec.ClusterIP != corev1.ClusterIPNone {
		t.Fatalf("ClusterIP = %q, want None", svc.Spec.ClusterIP)
	}
	if svc.Spec.Selector[haRoleKey] != haRoleBackend {
		t.Fatalf("selector missing role=backend; got %v", svc.Spec.Selector)
	}
}

func TestBuildBackendHeadlessService_OwnerReference(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()

	svc, err := BuildBackendHeadlessService(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.OwnerReferences) != 1 || svc.OwnerReferences[0].UID != gw.UID {
		t.Fatalf("expected Gateway owner ref, got %+v", svc.OwnerReferences)
	}
}

// --- BuildBackendStatefulSet ---

func sampleStatefulSetGateway() *gwv1.Gateway {
	gw := sampleGateway()
	gw.Name = "ha-gw"
	return gw
}

func TestBuildBackendStatefulSet_ReplicasAndServiceName(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(3)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	if ss.Spec.Replicas == nil || *ss.Spec.Replicas != 3 {
		t.Fatalf("Replicas = %v, want 3", ss.Spec.Replicas)
	}
	if ss.Spec.ServiceName != BackendHeadlessServiceName(gw) {
		t.Fatalf("ServiceName = %q, want %q", ss.Spec.ServiceName, BackendHeadlessServiceName(gw))
	}
}

func TestBuildBackendStatefulSet_InitContainerArgs(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(2)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss.Spec.Template.Spec.InitContainers) != 1 {
		t.Fatalf("expected 1 init container, got %d", len(ss.Spec.Template.Spec.InitContainers))
	}
	init := ss.Spec.Template.Spec.InitContainers[0]
	args := init.Args

	// Must include master address flag.
	found := false
	for _, a := range args {
		if strings.HasPrefix(a, "--ob-master-address=") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("init container args missing --ob-master-address; got %v", args)
	}

	// Must pass --src= explicitly (empty value), which tells tor-init to
	// skip the Mode A key-Secret copy. Without the flag, tor-init would
	// fall back to the default "/etc/tor-keys" and either crash (path
	// doesn't exist on backends) or clobber the per-pod keys.
	if !slices.Contains(args, "--src=") {
		t.Fatalf("init container must pass --src= (empty) to skip the Mode A copy; got %v", args)
	}
}

func TestBuildBackendStatefulSet_InitContainerDownwardAPI(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(2)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	init := ss.Spec.Template.Spec.InitContainers[0]
	found := false
	for _, e := range init.Env {
		if e.Name == "POD_NAME" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil &&
			e.ValueFrom.FieldRef.FieldPath == "metadata.name" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("init container missing POD_NAME downward API env; got %v", init.Env)
	}
}

func TestBuildBackendStatefulSet_RouterSidecarPresent(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(2)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(ss.Spec.Template.Spec.Containers))
	for _, c := range ss.Spec.Template.Spec.Containers {
		names = append(names, c.Name)
	}
	if !slices.Contains(names, routerContainer) {
		t.Fatalf("router sidecar not present; containers = %v", names)
	}
	if !slices.Contains(names, torContainerName) {
		t.Fatalf("tor container not present; containers = %v", names)
	}
}

func TestBuildBackendStatefulSet_NoProjectedKeysVolume(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(3)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, v := range ss.Spec.Template.Spec.Volumes {
		if v.Name == "keys" {
			t.Fatalf("backend pod still has 'keys' volume — should be API-fetched")
		}
	}
}

func TestBuildBackendStatefulSet_InitContainerUsesApiFetchPrefix(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(3)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	init := ss.Spec.Template.Spec.InitContainers[0]
	var prefixArg string
	for _, a := range init.Args {
		if strings.HasPrefix(a, "--api-fetch-secret-prefix=") {
			prefixArg = a
		}
	}
	if prefixArg == "" {
		t.Fatal("init container missing --api-fetch-secret-prefix arg")
	}
	if !strings.Contains(prefixArg, "ha-gw-backend-") {
		t.Errorf("prefix arg = %q, want substring 'ha-gw-backend-'", prefixArg)
	}
	// POD_NAME downward API
	var sawPodName, sawPodNamespace bool
	for _, e := range init.Env {
		if e.Name == "POD_NAME" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "metadata.name" {
			sawPodName = true
		}
		if e.Name == "POD_NAMESPACE" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "metadata.namespace" {
			sawPodNamespace = true
		}
	}
	if !sawPodName {
		t.Error("init container missing POD_NAME downward API env var")
	}
	if !sawPodNamespace {
		t.Error("init container missing POD_NAMESPACE downward API env var")
	}
}

func TestBuildBackendStatefulSet_TopologySpreadBestEffort(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(2)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss.Spec.Template.Spec.TopologySpreadConstraints) != 1 {
		t.Fatalf("expected 1 TopologySpreadConstraint, got %d", len(ss.Spec.Template.Spec.TopologySpreadConstraints))
	}
	tsc := ss.Spec.Template.Spec.TopologySpreadConstraints[0]
	if tsc.WhenUnsatisfiable != corev1.ScheduleAnyway {
		t.Fatalf("WhenUnsatisfiable = %q, want ScheduleAnyway", tsc.WhenUnsatisfiable)
	}
}

func TestBuildBackendStatefulSet_OwnerReference(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(2)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss.OwnerReferences) != 1 || ss.OwnerReferences[0].UID != gw.UID {
		t.Fatalf("expected Gateway owner ref, got %+v", ss.OwnerReferences)
	}
}

func TestBuildBackendStatefulSet_ParallelPodManagement(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(2)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	if ss.Spec.PodManagementPolicy != "Parallel" {
		t.Fatalf("PodManagementPolicy = %q, want Parallel", ss.Spec.PodManagementPolicy)
	}
}

func TestBuildBackendStatefulSet_ServiceAccountName(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(1)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	want := RouterRBACName(gw.Name)
	if got := ss.Spec.Template.Spec.ServiceAccountName; got != want {
		t.Errorf("ServiceAccountName: got %q want %q", got, want)
	}
}

func TestBuildBackendStatefulSet_Hardening(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	pol := samplePolicy(2)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	tpl := ss.Spec.Template.Spec
	for _, c := range append(tpl.InitContainers, tpl.Containers...) {
		if c.SecurityContext == nil {
			t.Fatalf("container %s missing SecurityContext", c.Name)
		}
		if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
			t.Fatalf("container %s must deny privilege escalation", c.Name)
		}
		if c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			t.Fatalf("container %s must have ReadOnlyRootFilesystem=true", c.Name)
		}
		if c.SecurityContext.Capabilities == nil || !hasCap(c.SecurityContext.Capabilities.Drop, "ALL") {
			t.Fatalf("container %s must drop ALL capabilities", c.Name)
		}
	}
	if tpl.SecurityContext == nil || tpl.SecurityContext.SeccompProfile == nil ||
		tpl.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatal("pod must use RuntimeDefault seccomp profile")
	}
}

// --- HALabels ---

func TestHALabels_ContainsGatewayAndRole(t *testing.T) {
	gw := sampleGateway()
	labels := HALabels(gw, haRoleBackend)
	if labels[gatewayLabelKey] != gw.Name {
		t.Fatalf("label %s = %q, want %q", gatewayLabelKey, labels[gatewayLabelKey], gw.Name)
	}
	if labels[haRoleKey] != haRoleBackend {
		t.Fatalf("label %s = %q, want %q", haRoleKey, labels[haRoleKey], haRoleBackend)
	}
}

func TestHALabels_IncludesManagedBy(t *testing.T) {
	gw := sampleGateway()
	got := HALabels(gw, "backend")
	if got[managedByLabelKey] != managedByLabelVal {
		t.Errorf("HALabels missing %s=%s; got %v", managedByLabelKey, managedByLabelVal, got)
	}
}

// --- BuildFrontendServiceAccount ---

func TestBuildFrontendServiceAccount(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	sa, err := BuildFrontendServiceAccount(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Name != "blog-frontend" || sa.Namespace != "prod" {
		t.Errorf("name/ns: %s/%s", sa.Name, sa.Namespace)
	}
	if sa.Labels[haRoleKey] != "frontend" {
		t.Errorf("role label: %v", sa.Labels)
	}
	if len(sa.OwnerReferences) != 1 || sa.OwnerReferences[0].Name != "blog" {
		t.Errorf("ownerref: %v", sa.OwnerReferences)
	}
}

// --- BuildFrontendRole ---

func TestBuildFrontendRole(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	pol := samplePolicy(2)
	role, err := BuildFrontendRole(gw, pol, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(role.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(role.Rules))
	}
	var sawGet, sawListWatch bool
	for _, r := range role.Rules {
		if slices.Contains(r.Resources, "events") {
			continue
		}
		if len(r.Resources) != 1 || r.Resources[0] != rbacResSecrets {
			t.Errorf("expected only secrets; got %v", r.Resources)
		}
		if len(r.Verbs) == 1 && r.Verbs[0] == rbacVerbGet {
			sawGet = true
			if len(r.ResourceNames) == 0 {
				t.Error("get rule must have resourceNames")
			}
		}
		if slices.Contains(r.Verbs, "list") && slices.Contains(r.Verbs, "watch") {
			sawListWatch = true
			if len(r.ResourceNames) != 0 {
				t.Errorf("list/watch rule must not have resourceNames; got %v", r.ResourceNames)
			}
		}
	}
	if !sawGet {
		t.Error("missing get rule")
	}
	if !sawListWatch {
		t.Error("missing list/watch rule")
	}
}

// --- BuildFrontendRoleBinding ---

func TestBuildFrontendRoleBinding(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	rb, err := BuildFrontendRoleBinding(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if rb.RoleRef.Name != FrontendName(gw) {
		t.Errorf("roleRef: %v", rb.RoleRef)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != FrontendName(gw) || rb.Subjects[0].Kind != rbacv1.ServiceAccountKind {
		t.Errorf("subjects: %v", rb.Subjects)
	}
}

// --- BuildFrontendTorrcConfigMap ---

func TestBuildFrontendTorrcConfigMap(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	cm, err := BuildFrontendTorrcConfigMap(gw, "", scheme)
	if err != nil {
		t.Fatal(err)
	}
	rendered := cm.Data["torrc"]
	if rendered == "" {
		t.Fatal("expected non-empty torrc")
	}
	if !strings.Contains(rendered, "ControlPort") {
		t.Errorf("frontend torrc must enable ControlPort:\n%s", rendered)
	}
	if !strings.Contains(rendered, "CookieAuthentication 1") {
		t.Errorf("frontend torrc must enable CookieAuthentication:\n%s", rendered)
	}
	if strings.Contains(rendered, "HiddenService") {
		t.Errorf("frontend torrc must NOT contain any HiddenService directives:\n%s", rendered)
	}
	if !strings.Contains(rendered, "MetricsPort 0.0.0.0:9035") {
		t.Errorf("frontend torrc must enable MetricsPort on 9035 (the kubelet probe target):\n%s", rendered)
	}
}

func TestBuildFrontendTorrcConfigMap_PropagatesTestingNetworkInclude(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	const fragment = "TestingTorNetwork 1\nClientUseIPv6 0\nDirAuthority test\n"
	cm, err := BuildFrontendTorrcConfigMap(gw, fragment, scheme)
	if err != nil {
		t.Fatalf("BuildFrontendTorrcConfigMap: %v", err)
	}
	rendered := cm.Data["torrc"]
	for _, required := range []string{
		"TestingTorNetwork 1",
		"ClientUseIPv6 0",
		"DirAuthority test",
		// Frontend torrc fundamentals MUST be preserved:
		"ControlPort",
		"CookieAuthentication 1",
		"MetricsPort 0.0.0.0:9035",
	} {
		if !strings.Contains(rendered, required) {
			t.Errorf("expected %q in frontend torrc:\n%s", required, rendered)
		}
	}
	if strings.Contains(rendered, "%include") {
		t.Errorf("frontend torrc must NOT contain %%include (content is inlined):\n%s", rendered)
	}
	if strings.Contains(rendered, "HiddenService") {
		t.Errorf("frontend torrc must NOT contain HiddenService directives:\n%s", rendered)
	}
}

func TestBuildFrontendTorrcConfigMap_EmptyIncludeEmitsNoTestingBlock(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	cm, err := BuildFrontendTorrcConfigMap(gw, "", scheme)
	if err != nil {
		t.Fatalf("BuildFrontendTorrcConfigMap: %v", err)
	}
	rendered := cm.Data["torrc"]
	for _, denied := range []string{"TestingTorNetwork", "%include", "ClientUseIPv6 0"} {
		if strings.Contains(rendered, denied) {
			t.Errorf("frontend torrc must not contain %q with empty path; got:\n%s", denied, rendered)
		}
	}
	// And the production essentials MUST still be there:
	for _, required := range []string{"ControlPort", "CookieAuthentication 1", "MetricsPort"} {
		if !strings.Contains(rendered, required) {
			t.Errorf("frontend torrc missing %q with empty path:\n%s", required, rendered)
		}
	}
}

// --- BuildFrontendDeployment ---

func TestBuildFrontendDeployment(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	pol := &policyv1alpha1.OnionBalancePolicy{
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "blog-master"},
		},
	}
	master := sampleMasterAddr(t)
	d, err := BuildFrontendDeployment(gw, pol, master, RuntimeImages{
		Tor:          "tor:v1",
		TorInit:      "torinit:v1",
		Onionbalance: "onionbalance:v1",
		Obrefresh:    "obrefresh:v1",
	}, false, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if *d.Spec.Replicas != 1 {
		t.Errorf("frontend must be replicas=1; got %d", *d.Spec.Replicas)
	}
	containers := map[string]corev1.Container{}
	for _, c := range d.Spec.Template.Spec.Containers {
		containers[c.Name] = c
	}
	for _, want := range []string{"tor", "onionbalance", obrefreshContainer} {
		if _, ok := containers[want]; !ok {
			t.Errorf("missing container %q; got containers: %v", want, mapKeys(containers))
		}
	}
	if d.Spec.Template.Spec.ServiceAccountName != FrontendName(gw) {
		t.Errorf("SA: %s want %s", d.Spec.Template.Spec.ServiceAccountName, FrontendName(gw))
	}
	// master Secret must be mounted RO at /etc/onionbalance/keys
	foundMount := false
	for _, vm := range containers["onionbalance"].VolumeMounts {
		if vm.MountPath == "/etc/onionbalance/keys" && vm.ReadOnly {
			foundMount = true
		}
	}
	if !foundMount {
		t.Errorf("master Secret must be mounted RO at /etc/onionbalance/keys; got mounts: %v", containers["onionbalance"].VolumeMounts)
	}
	// obrefresh must carry --master-address flag
	foundArg := false
	for _, a := range containers[obrefreshContainer].Args {
		if a == "--master-address="+master.String() {
			foundArg = true
		}
	}
	if !foundArg {
		t.Errorf("obrefresh must receive --master-address; got args: %v", containers[obrefreshContainer].Args)
	}
}

func TestBuildFrontendDeployment_IsTestnetFlag(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	pol := &policyv1alpha1.OnionBalancePolicy{
		Spec: policyv1alpha1.OnionBalancePolicySpec{
			MasterKeySecretRef: policyv1alpha1.MasterKeySecretRef{Name: "blog-master"},
		},
	}
	master := sampleMasterAddr(t)
	imgs := RuntimeImages{Tor: "tor:v1", TorInit: "torinit:v1", Onionbalance: "ob:v1", Obrefresh: "obr:v1"}

	for _, tc := range []struct {
		name        string
		testingMode bool
		wantFlag    bool
	}{
		{"prod omits --is-testnet", false, false},
		{"testing emits --is-testnet", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := BuildFrontendDeployment(gw, pol, master, imgs, tc.testingMode, scheme)
			if err != nil {
				t.Fatal(err)
			}
			var obArgs []string
			for _, c := range d.Spec.Template.Spec.Containers {
				if c.Name == "onionbalance" {
					obArgs = c.Args
				}
			}
			has := false
			for _, a := range obArgs {
				if a == "--is-testnet" {
					has = true
				}
			}
			if has != tc.wantFlag {
				t.Errorf("onionbalance args = %v; want --is-testnet=%v", obArgs, tc.wantFlag)
			}
		})
	}
}

func TestBuildBackendKeySecret_OwnerUIDLabel(t *testing.T) {
	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "blog",
			Namespace: "default",
			UID:       testGwUID,
		},
	}
	s, err := BuildBackendKeySecret(gw, 0, nil, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := s.Labels["torgateway.io/owner-uid"]; got != testGwUID {
		t.Errorf("owner-uid = %q, want abc-123", got)
	}
}

func mapKeys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestBuildFrontendDeployment_NoSecretVolumeForMasterKey(t *testing.T) {
	gw := sampleGateway()
	obp := samplePolicy(1)
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	dep, err := BuildFrontendDeployment(gw, obp, tor.OnionAddress{}, sampleImages(), false, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == "ob-keys" {
			if v.Secret != nil {
				t.Fatalf("ob-keys still uses SecretVolumeSource; should be emptyDir")
			}
			if v.EmptyDir == nil {
				t.Fatalf("ob-keys should be emptyDir; got %+v", v.VolumeSource)
			}
		}
	}
}

func TestBuildFrontendDeployment_MasterFetchInitContainer(t *testing.T) {
	gw := sampleGateway()
	obp := samplePolicy(1)
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	dep, err := BuildFrontendDeployment(gw, obp, tor.OnionAddress{}, sampleImages(), false, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var sawFetch bool
	for _, c := range dep.Spec.Template.Spec.InitContainers {
		var foundFetch, foundSrcEmpty bool
		for _, a := range c.Args {
			if a == "--api-fetch-secret=secrets-ns/ob-master" {
				foundFetch = true
			}
			if a == "--src=" {
				foundSrcEmpty = true
			}
		}
		if !foundFetch {
			continue
		}
		sawFetch = true
		// --src= must be empty so tor-init skips the Mode A copy path
		// (which defaults to /etc/tor-keys — a directory this init container
		// does not mount).
		if !foundSrcEmpty {
			t.Errorf("master-fetch init container missing --src= (empty); args: %v", c.Args)
		}
		var sawMount bool
		for _, m := range c.VolumeMounts {
			if m.Name == "ob-keys" && m.MountPath == "/etc/onionbalance/keys" {
				sawMount = true
			}
		}
		if !sawMount {
			t.Errorf("master-fetch init container missing ob-keys mount; mounts: %v", c.VolumeMounts)
		}
	}
	if !sawFetch {
		t.Fatalf("no init container with --api-fetch-secret=secrets-ns/ob-master")
	}
}

func TestBuildFrontendDeployment_MasterFetchUsesGatewayNamespaceWhenMasterRefNamespaceEmpty(t *testing.T) {
	gw := sampleGateway()
	obp := samplePolicy(1)
	obp.Spec.MasterKeySecretRef.Namespace = ""
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	dep, err := BuildFrontendDeployment(gw, obp, tor.OnionAddress{}, sampleImages(), false, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	wantArg := "--api-fetch-secret=" + gw.Namespace + "/ob-master"
	var sawFetch bool
	for _, c := range dep.Spec.Template.Spec.InitContainers {
		for _, a := range c.Args {
			if a == wantArg {
				sawFetch = true
			}
		}
	}
	if !sawFetch {
		t.Fatalf("expected fetch arg %q to use gateway namespace; init containers: %+v", wantArg, dep.Spec.Template.Spec.InitContainers)
	}
}

// --- BuildBackendTorrcConfigMap ---

func TestBuildBackendTorrcConfigMap(t *testing.T) {
	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "blog", Namespace: "prod"}}
	scheme := testScheme(t)
	pol := &policyv1alpha1.OnionBalancePolicy{Spec: policyv1alpha1.OnionBalancePolicySpec{Replicas: 1}}
	cm, err := BuildBackendTorrcConfigMap(gw, pol, EffectiveServicePolicy{
		LogLevel:           "notice",
		PoWDefensesEnabled: true,
	}, EffectiveClientAuth{}, "", scheme)
	if err != nil {
		t.Fatal(err)
	}
	rendered := cm.Data["torrc"]
	if !strings.Contains(rendered, "HiddenServiceOnionbalanceInstance 1") {
		t.Errorf("backend torrc must include HiddenServiceOnionbalanceInstance 1:\n%s", rendered)
	}
	for _, denied := range []string{"HiddenServicePoWDefensesEnabled", "HiddenServiceEnableIntroDoSDefense"} {
		if strings.Contains(rendered, denied) {
			t.Errorf("backend torrc must NOT contain %s:\n%s", denied, rendered)
		}
	}
	if cm.Name != "blog-backend-torrc" {
		t.Errorf("name: %s", cm.Name)
	}
}

func TestBuildBackendTorrcConfigMap_PropagatesTestingNetworkInclude(t *testing.T) {
	gw := sampleGateway()
	scheme := testScheme(t)
	pol := samplePolicy(2)
	const fragment = "TestingTorNetwork 1\nClientUseIPv6 0\nDirAuthority test\n"
	cm, err := BuildBackendTorrcConfigMap(
		gw, pol,
		EffectiveServicePolicy{LogLevel: "notice"},
		EffectiveClientAuth{},
		fragment,
		scheme,
	)
	if err != nil {
		t.Fatalf("BuildBackendTorrcConfigMap: %v", err)
	}
	rendered := cm.Data["torrc"]
	if !strings.Contains(rendered, "TestingTorNetwork 1") {
		t.Errorf("rendered backend torrc missing TestingTorNetwork 1:\n%s", rendered)
	}
	if !strings.Contains(rendered, "ClientUseIPv6 0") {
		t.Errorf("rendered backend torrc missing ClientUseIPv6 0:\n%s", rendered)
	}
	if !strings.Contains(rendered, "DirAuthority test") {
		t.Errorf("rendered backend torrc missing DirAuthority line:\n%s", rendered)
	}
	if strings.Contains(rendered, "%include") {
		t.Errorf("rendered backend torrc must not contain %%include (content is inlined):\n%s", rendered)
	}
	// Backend torrc MUST still contain the onionbalance instance directive.
	if !strings.Contains(rendered, "HiddenServiceOnionbalanceInstance 1") {
		t.Errorf("backend torrc lost HiddenServiceOnionbalanceInstance 1:\n%s", rendered)
	}
}

func TestBuildCrossNSMasterRole_ScopedToMasterSecret(t *testing.T) {
	gw := sampleGateway()
	gw.UID = testGwUID
	obp := samplePolicy(1)
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	role, err := BuildCrossNSMasterRole(gw, obp, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if role.Namespace != testMasterSecretNS {
		t.Errorf("role namespace = %q, want secrets-ns", role.Namespace)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(role.Rules))
	}
	if !reflect.DeepEqual(role.Rules[0].ResourceNames, []string{testMasterSecretName}) {
		t.Errorf("resourceNames = %v, want [ob-master]", role.Rules[0].ResourceNames)
	}
	if role.Labels["torgateway.io/owner-uid"] != testGwUID {
		t.Errorf("owner-uid label missing")
	}
	if role.Labels["torgateway.io/gateway-ns"] != gw.Namespace {
		t.Errorf("gateway-ns label = %q, want %q", role.Labels["torgateway.io/gateway-ns"], gw.Namespace)
	}
}

func TestBuildCrossNSMasterRole_RejectsEmptyNamespace(t *testing.T) {
	gw := sampleGateway()
	obp := samplePolicy(1)
	obp.Spec.MasterKeySecretRef.Namespace = "" // empty — should error
	_, err := BuildCrossNSMasterRole(gw, obp, testScheme(t))
	if err == nil {
		t.Fatal("expected error for empty MasterKeySecretRef.Namespace")
	}
}

func TestBuildCrossNSMasterRoleBinding_LinksFrontendSA(t *testing.T) {
	gw := sampleGateway()
	gw.UID = testGwUID
	obp := samplePolicy(1)
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	rb, err := BuildCrossNSMasterRoleBinding(gw, obp, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rb.Namespace != testMasterSecretNS {
		t.Errorf("rolebinding namespace = %q, want secrets-ns", rb.Namespace)
	}
	if len(rb.Subjects) != 1 ||
		rb.Subjects[0].Kind != "ServiceAccount" ||
		rb.Subjects[0].Namespace != gw.Namespace ||
		rb.Subjects[0].Name != FrontendName(gw) {
		t.Errorf("subjects = %+v, want frontend SA in gw NS", rb.Subjects)
	}
	if rb.RoleRef.Name != CrossNSMasterRoleName(gw) {
		t.Errorf("roleRef.Name = %q, want %q", rb.RoleRef.Name, CrossNSMasterRoleName(gw))
	}
}

func TestBuildFrontendRole_GetIsResourceNamesScoped(t *testing.T) {
	gw := sampleGateway()
	obp := samplePolicy(3)
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	obp.Spec.MasterKeySecretRef.Namespace = "" // same NS
	role, err := BuildFrontendRole(gw, obp, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var gotGet, gotListWatch bool
	for _, r := range role.Rules {
		switch {
		case len(r.Verbs) == 1 && r.Verbs[0] == rbacVerbGet:
			gotGet = true
			wantNames := []string{
				BackendKeySecretName(gw, 0),
				BackendKeySecretName(gw, 1),
				BackendKeySecretName(gw, 2),
				testMasterSecretName,
			}
			gotNames := append([]string(nil), r.ResourceNames...)
			sort.Strings(gotNames)
			sort.Strings(wantNames)
			if !reflect.DeepEqual(gotNames, wantNames) {
				t.Errorf("get resourceNames = %v, want %v", gotNames, wantNames)
			}
		case len(r.Verbs) == 2 && slices.Contains(r.Verbs, "list") && slices.Contains(r.Verbs, "watch"):
			gotListWatch = true
			if len(r.ResourceNames) != 0 {
				t.Errorf("list/watch rule must not have resourceNames; got %v", r.ResourceNames)
			}
		}
	}
	if !gotGet {
		t.Error("missing get rule")
	}
	if !gotListWatch {
		t.Error("missing list/watch rule")
	}
}

func TestBuildFrontendDeployment_SharesProcessNamespace(t *testing.T) {
	dep, err := BuildFrontendDeployment(sampleGateway(), samplePolicy(2), tor.OnionAddress{}, sampleImages(), false, testScheme(t))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if dep.Spec.Template.Spec.ShareProcessNamespace == nil || !*dep.Spec.Template.Spec.ShareProcessNamespace {
		t.Fatal("frontend PodSpec must set ShareProcessNamespace=true so obrefresh can SIGHUP onionbalance")
	}
}

func TestBuildFrontendDeployment_ObrefreshGatewayUIDArg(t *testing.T) {
	gw := sampleGateway()
	gw.UID = testGwUID
	obp := samplePolicy(3)
	dep, err := BuildFrontendDeployment(gw, obp, tor.OnionAddress{}, sampleImages(), false, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var sawArg bool
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name != obrefreshContainer {
			continue
		}
		for _, a := range c.Args {
			if a == "--gateway-uid=abc-123" {
				sawArg = true
			}
		}
	}
	if !sawArg {
		t.Fatalf("obrefresh missing --gateway-uid arg")
	}
}

func TestBuildFrontendDeployment_RejectsEmptyImages(t *testing.T) {
	cases := []RuntimeImages{
		{Tor: "", TorInit: "init:x", Onionbalance: "ob:x", Obrefresh: "obr:x"},
		{Tor: "tor:x", TorInit: "", Onionbalance: "ob:x", Obrefresh: "obr:x"},
		{Tor: "tor:x", TorInit: "init:x", Onionbalance: "", Obrefresh: "obr:x"},
		{Tor: "tor:x", TorInit: "init:x", Onionbalance: "ob:x", Obrefresh: ""},
	}
	for _, imgs := range cases {
		_, err := BuildFrontendDeployment(sampleGateway(), samplePolicy(2), tor.OnionAddress{}, imgs, false, testScheme(t))
		if err == nil {
			t.Errorf("expected error for empty image in %+v", imgs)
		}
	}
}

func TestBuildBackendStatefulSet_RejectsEmptyImages(t *testing.T) {
	cases := []RuntimeImages{
		{Tor: "", TorInit: "init:x"},
		{Tor: "tor:x", TorInit: ""},
	}
	master := sampleMasterAddr(t)
	for _, imgs := range cases {
		_, err := BuildBackendStatefulSet(sampleStatefulSetGateway(), samplePolicy(2), master, imgs, testScheme(t))
		if err == nil {
			t.Errorf("expected error for empty image in %+v", imgs)
		}
	}
}

func TestBuildFrontendRole_CrossNSMasterOmitsFromInNSResourceNames(t *testing.T) {
	gw := sampleGateway()
	obp := samplePolicy(2)
	obp.Spec.MasterKeySecretRef.Name = testMasterSecretName
	obp.Spec.MasterKeySecretRef.Namespace = testMasterSecretNS // different from gw.Namespace
	role, err := BuildFrontendRole(gw, obp, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, r := range role.Rules {
		if len(r.Verbs) == 1 && r.Verbs[0] == "get" {
			for _, n := range r.ResourceNames {
				if n == testMasterSecretName {
					t.Fatalf("cross-NS master should NOT be in in-namespace get resourceNames; got %v", r.ResourceNames)
				}
			}
		}
	}
}

func TestBuildFrontendDeployment_OnionbalanceLivenessProbe(t *testing.T) {
	dep, err := BuildFrontendDeployment(sampleGateway(), samplePolicy(2), tor.OnionAddress{}, sampleImages(), false, testScheme(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == "onionbalance" || c.Name == obrefreshContainer {
			if c.LivenessProbe == nil {
				t.Errorf("%s container missing LivenessProbe", c.Name)
			}
		}
	}
}

func TestBuildFrontendDeployment_ObrefreshProbeUsesConfiguredInterval(t *testing.T) {
	pol := samplePolicy(2)
	pol.Spec.RefreshInterval = metav1.Duration{Duration: 120 * time.Second}
	dep, err := BuildFrontendDeployment(sampleGateway(), pol, tor.OnionAddress{}, sampleImages(), false, testScheme(t))
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name != obrefreshContainer {
			continue
		}
		if c.LivenessProbe == nil || c.LivenessProbe.Exec == nil {
			t.Fatal("obrefresh missing exec probe")
		}
		cmd := strings.Join(c.LivenessProbe.Exec.Command, " ")
		want := (120 * time.Second).String() // "2m0s"
		if !strings.Contains(cmd, want) {
			t.Errorf("obrefresh probe must pass --interval=%v; got %v", want, c.LivenessProbe.Exec.Command)
		}
		return
	}
	t.Fatal("obrefresh container not found")
}
