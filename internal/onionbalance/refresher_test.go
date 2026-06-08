/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package onionbalance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chimbosonic/tor-gateway/internal/tor"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func mustKeyPair(t *testing.T) *tor.KeyPair {
	t.Helper()
	kp, err := tor.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

const testGatewayUID = "test-gw-uid-0001"

func backendSecret(name, ns, hostname string) *corev1.Secret {
	ctrl := true
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				LabelGateway:  "blog",
				LabelRole:     "backend",
				LabelOwnerUID: testGatewayUID,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "gateway.networking.k8s.io/v1",
				Kind:       "Gateway",
				Name:       "blog",
				UID:        testGatewayUID,
				Controller: &ctrl,
			}},
		},
		Data: map[string][]byte{
			// hostname is the full "<56chars>.onion" string as written by tor-init.
			HostnameField: []byte(hostname),
		},
	}
}

func TestRefresherInitialRender(t *testing.T) {
	master := mustKeyPair(t).OnionAddress()
	b1 := mustKeyPair(t).OnionAddress()
	b2 := mustKeyPair(t).OnionAddress()

	cli := fake.NewClientset(
		backendSecret("blog-backend-0-keys", "prod", b1.String()),
		backendSecret("blog-backend-1-keys", "prod", b2.String()),
	)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	pidPath := filepath.Join(dir, "pid")
	// Use an unlikely-to-exist PID so sighupPID's syscall.Kill returns ESRCH
	// and the warning path is exercised — the test verifies the config file
	// is written regardless of SIGHUP outcome.
	_ = os.WriteFile(pidPath, []byte("99999999\n"), 0o600)

	ref, err := NewRefresher(context.Background(), RefresherConfig{
		GatewayName:      "blog",
		GatewayNamespace: "prod",
		MasterKeyPath:    "/etc/onionbalance/keys/hs_ed25519_secret_key",
		ConfigPath:       cfgPath,
		PIDFile:          pidPath,
		Interval:         5 * time.Millisecond,
		Master:           master,
		OwnerUID:         testGatewayUID,
		Client:           cli,
	})
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	ctx := t.Context()
	go func() { _ = ref.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for {
		if data, err := os.ReadFile(cfgPath); err == nil {
			s := string(data)
			if strings.Contains(s, b1.String()) && strings.Contains(s, b2.String()) {
				return
			}
		}
		select {
		case <-deadline:
			data, _ := os.ReadFile(cfgPath)
			t.Fatalf("config not rendered with both backends within deadline:\n%s", data)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestRefresherRequiresMandatoryFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  RefresherConfig
	}{
		{"missing gateway", RefresherConfig{GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", OwnerUID: "uid", Client: fake.NewClientset()}},
		{"missing namespace", RefresherConfig{GatewayName: "g", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", OwnerUID: "uid", Client: fake.NewClientset()}},
		{"missing config", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", PIDFile: "/p", MasterKeyPath: "/k", OwnerUID: "uid", Client: fake.NewClientset()}},
		{"missing pidfile", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", MasterKeyPath: "/k", OwnerUID: "uid", Client: fake.NewClientset()}},
		{"missing master path", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", OwnerUID: "uid", Client: fake.NewClientset()}},
		{"missing client", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", OwnerUID: "uid"}},
		{"missing owner uid", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing master", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", OwnerUID: "uid", Client: fake.NewClientset()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRefresher(context.Background(), tc.cfg); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestNewRefresher_ClampsTooShortInterval(t *testing.T) {
	master := mustKeyPair(t).OnionAddress()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	pidPath := filepath.Join(dir, "pid")

	cfg := RefresherConfig{
		GatewayName:      "blog",
		GatewayNamespace: "prod",
		MasterKeyPath:    "/etc/onionbalance/keys/hs_ed25519_secret_key",
		ConfigPath:       cfgPath,
		PIDFile:          pidPath,
		Interval:         1 * time.Millisecond,
		Master:           master,
		OwnerUID:         testGatewayUID,
		Client:           fake.NewClientset(),
	}
	r, err := NewRefresher(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	if r.cfg.Interval < 5*time.Second {
		t.Errorf("interval not clamped; got %v", r.cfg.Interval)
	}
}

func TestBackendsFromSecrets_FilterByOwnerUID(t *testing.T) {
	legitAddr := mustKeyPair(t).OnionAddress()
	impostorAddr := mustKeyPair(t).OnionAddress()
	ctrl := true
	legit := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blog-backend-0-keys",
			Labels: map[string]string{
				"torgateway.io/gateway":   "blog",
				"torgateway.io/role":      "backend",
				"torgateway.io/owner-uid": "abc-123",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "gateway.networking.k8s.io/v1",
				Kind:       "Gateway",
				Name:       "blog",
				UID:        "abc-123",
				Controller: &ctrl,
			}},
		},
		Data: map[string][]byte{"hostname": []byte(legitAddr.String())},
	}
	impostor := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blog-backend-0-keys-evil",
			Labels: map[string]string{
				"torgateway.io/gateway":   "blog",
				"torgateway.io/role":      "backend",
				"torgateway.io/owner-uid": "different-uid",
			},
		},
		Data: map[string][]byte{"hostname": []byte(impostorAddr.String())},
	}
	addrs := backendsFromSecrets([]any{legit, impostor}, "abc-123")
	if len(addrs) != 1 {
		t.Fatalf("want 1 address, got %d: %v", len(addrs), addrs)
	}
}

func TestBackendsFromSecrets_RequiresOwnerReference(t *testing.T) {
	// Labels match but no owner reference → skip.
	addr := mustKeyPair(t).OnionAddress()
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blog-backend-0-keys",
			Labels: map[string]string{
				"torgateway.io/gateway":   "blog",
				"torgateway.io/role":      "backend",
				"torgateway.io/owner-uid": "abc-123",
			},
		},
		Data: map[string][]byte{"hostname": []byte(addr.String())},
	}
	addrs := backendsFromSecrets([]any{s}, "abc-123")
	if len(addrs) != 0 {
		t.Errorf("expected 0 addrs (no controller ownerRef), got %d", len(addrs))
	}
}

func TestRebuild_EmptyBackends_WritesEmptyConfigAndSighups(t *testing.T) {
	dir := t.TempDir()
	master := mustKeyPair(t).OnionAddress()

	cfgPath := filepath.Join(dir, "config.yaml")
	pidPath := filepath.Join(dir, "ob.pid")
	masterKeyPath := filepath.Join(dir, "master_sk")

	// Pre-seed config.yaml with a stale 3-backend list.
	_ = os.WriteFile(cfgPath, []byte("services:\n- instances:\n  - x.onion\n  - y.onion\n  - z.onion\n"), 0o600)
	// Use an unlikely-to-exist PID so sighupPID's syscall.Kill returns ESRCH —
	// the test verifies the config file is overwritten regardless of SIGHUP outcome.
	_ = os.WriteFile(pidPath, []byte("99999999\n"), 0o600)

	ref, err := NewRefresher(context.Background(), RefresherConfig{
		GatewayName:      "blog",
		GatewayNamespace: "prod",
		MasterKeyPath:    masterKeyPath,
		ConfigPath:       cfgPath,
		PIDFile:          pidPath,
		Interval:         5 * time.Millisecond,
		Master:           master,
		OwnerUID:         testGatewayUID,
		Client:           fake.NewClientset(),
	})
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}

	ref.rebuild(context.Background(), nil) // 0 backends

	out, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config.yaml not written: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "x.onion") || strings.Contains(s, "y.onion") || strings.Contains(s, "z.onion") {
		t.Errorf("stale backends still in config.yaml after empty rebuild: %s", s)
	}
	if !strings.Contains(s, "instances: []") {
		t.Errorf("expected empty-backend config with 'instances: []'; got %s", s)
	}
}
