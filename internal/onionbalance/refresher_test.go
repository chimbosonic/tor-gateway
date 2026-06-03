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

func backendSecret(name, ns, hostname string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				LabelGateway: "blog",
				LabelRole:    "backend",
			},
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
		{"missing gateway", RefresherConfig{GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing namespace", RefresherConfig{GatewayName: "g", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing config", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", PIDFile: "/p", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing pidfile", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", MasterKeyPath: "/k", Client: fake.NewClientset()}},
		{"missing master path", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", Client: fake.NewClientset()}},
		{"missing client", RefresherConfig{GatewayName: "g", GatewayNamespace: "ns", ConfigPath: "/c", PIDFile: "/p", MasterKeyPath: "/k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRefresher(context.Background(), tc.cfg); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}
