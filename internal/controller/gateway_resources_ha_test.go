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
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	policyv1alpha1 "github.com/chimbosonic/tor-gateway/api/v1alpha1"
	"github.com/chimbosonic/tor-gateway/internal/tor"
)

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

	kp, err := tor.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := BuildBackendKeySecret(gw, 0, kp, scheme)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key", "hostname"} {
		if len(s.Data[key]) == 0 {
			t.Fatalf("Secret missing populated data[%q]", key)
		}
	}
	if got, want := string(s.Data["hostname"]), kp.OnionAddress().String(); got != want {
		t.Fatalf("hostname: got %q want %q", got, want)
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

	// Must include per-pod-keys-base flag.
	if !slices.Contains(args, "--per-pod-keys-base=/var/lib/tor-keys") {
		t.Fatalf("init container args missing --per-pod-keys-base; got %v", args)
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

func TestBuildBackendStatefulSet_ProjectedVolumeHasReplicasSources(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleStatefulSetGateway()
	replicas := int32(3)
	pol := samplePolicy(replicas)
	master := sampleMasterAddr(t)

	ss, err := BuildBackendStatefulSet(gw, pol, master, sampleImages(), scheme)
	if err != nil {
		t.Fatal(err)
	}
	var keysVol *corev1.Volume
	for i := range ss.Spec.Template.Spec.Volumes {
		if ss.Spec.Template.Spec.Volumes[i].Name == "keys" {
			keysVol = &ss.Spec.Template.Spec.Volumes[i]
			break
		}
	}
	if keysVol == nil || keysVol.Projected == nil {
		t.Fatal("keys volume must be a Projected volume")
	}
	if int32(len(keysVol.Projected.Sources)) != replicas {
		t.Fatalf("projected volume has %d sources, want %d", len(keysVol.Projected.Sources), replicas)
	}
	// Verify each source references the right secret name and per-index key paths.
	for i := range replicas {
		src := keysVol.Projected.Sources[i]
		if src.Secret == nil {
			t.Fatalf("source[%d] is not a Secret projection", i)
		}
		want := BackendKeySecretName(gw, int(i))
		if src.Secret.Name != want {
			t.Fatalf("source[%d].Secret.Name = %q, want %q", i, src.Secret.Name, want)
		}
		items := src.Secret.Items
		if len(items) != 2 {
			t.Errorf("source[%d]: want 2 items, got %d", i, len(items))
			continue
		}
		prefix := strconv.Itoa(int(i)) + "/"
		expected := map[string]string{
			"hs_ed25519_secret_key": prefix + "hs_ed25519_secret_key",
			"hs_ed25519_public_key": prefix + "hs_ed25519_public_key",
		}
		for _, it := range items {
			if expected[it.Key] != it.Path {
				t.Errorf("source[%d] key %q: path %q != expected %q", i, it.Key, it.Path, expected[it.Key])
			}
		}
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

// --- BuildOnionbalanceConfigMap ---

func TestBuildOnionbalanceConfigMap_ContainsServicesAndEmptyInstances(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	master := sampleMasterAddr(t)

	cm, err := BuildOnionbalanceConfigMap(gw, master, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Name != OnionbalanceConfigMapName(gw) {
		t.Fatalf("name = %q, want %q", cm.Name, OnionbalanceConfigMapName(gw))
	}
	data, ok := cm.Data["config.yaml"]
	if !ok {
		t.Fatal("ConfigMap missing data[config.yaml]")
	}
	if !strings.Contains(data, "services:") {
		t.Fatalf("config.yaml missing 'services:' key; got:\n%s", data)
	}
	if !strings.Contains(data, "instances: []") {
		t.Fatalf("config.yaml missing 'instances: []' for zero backends; got:\n%s", data)
	}
}

func TestBuildOnionbalanceConfigMap_OwnerReference(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	master := sampleMasterAddr(t)

	cm, err := BuildOnionbalanceConfigMap(gw, master, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].UID != gw.UID {
		t.Fatalf("expected Gateway owner ref, got %+v", cm.OwnerReferences)
	}
}

func TestBuildOnionbalanceConfigMap_LabelsFrontend(t *testing.T) {
	scheme := testScheme(t)
	gw := sampleGateway()
	master := sampleMasterAddr(t)

	cm, err := BuildOnionbalanceConfigMap(gw, master, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Labels[haRoleKey] != haRoleFrontend {
		t.Fatalf("label %s = %q, want frontend", haRoleKey, cm.Labels[haRoleKey])
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
	role, err := BuildFrontendRole(gw, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(role.Rules))
	}
	r := role.Rules[0]
	if len(r.Resources) != 1 || r.Resources[0] != "secrets" {
		t.Errorf("expected only secrets; got %v", r.Resources)
	}
	wantVerbs := map[string]bool{"get": true, "list": true, "watch": true}
	for _, v := range r.Verbs {
		if !wantVerbs[v] {
			t.Errorf("unexpected verb %q (only get/list/watch allowed)", v)
		}
	}
	if len(r.Verbs) != 3 {
		t.Errorf("expected 3 verbs (get/list/watch), got %d: %v", len(r.Verbs), r.Verbs)
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
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != FrontendName(gw) || rb.Subjects[0].Kind != "ServiceAccount" {
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
	for _, want := range []string{"tor", "onionbalance", "obrefresh"} {
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
	for _, a := range containers["obrefresh"].Args {
		if a == "--master-address="+master.String() {
			foundArg = true
		}
	}
	if !foundArg {
		t.Errorf("obrefresh must receive --master-address; got args: %v", containers["obrefresh"].Args)
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
	imgs := RuntimeImages{Tor: "tor:v1", Onionbalance: "ob:v1", Obrefresh: "obr:v1"}

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

func mapKeys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
