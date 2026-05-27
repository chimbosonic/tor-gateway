/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// startEnvtest boots a control plane with the gateway-api CRDs installed and
// returns its rest.Config. It skips (not fails) when the envtest binaries are
// absent, so pure unit tests in this package still run without them.
func startEnvtest(t *testing.T) *rest.Config {
	t.Helper()

	binDir := firstEnvtestBinDir()
	if binDir == "" {
		t.Skip("envtest binaries not found under ../../bin/k8s; run 'make setup-envtest'")
	}

	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/gateway-api").Output()
	if err != nil {
		t.Fatalf("locate gateway-api module: %v", err)
	}
	gwCRDs := filepath.Join(strings.TrimSpace(string(out)), "config", "crd", "standard")

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{gwCRDs},
		ErrorIfCRDPathMissing: true,
		BinaryAssetsDirectory: binDir,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	return cfg
}

func firstEnvtestBinDir() string {
	base := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			return filepath.Join(base, e.Name())
		}
	}
	return ""
}

func TestNew_ServesRoutesPresentAtStartup(t *testing.T) {
	cfg := startEnvtest(t)

	k8s, err := client.New(cfg, client.Options{Scheme: gwScheme(t)})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	route := routeFor("default", "blog", "blog-gw", ghostBackend)
	if err := k8s.Create(ctx, &route); err != nil {
		t.Fatalf("create HTTPRoute: %v", err)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(ghostBackend))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	h, err := New(ctx, Config{
		GatewayName:      "blog-gw",
		GatewayNamespace: "default",
		RestConfig:       cfg,
		Resolve:          func(Backend) (*url.URL, bool) { return backendURL, true },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (route present at startup should be served)", rec.Code)
	}
	if got := rec.Body.String(); got != ghostBackend {
		t.Fatalf("body = %q, want ghost", got)
	}
}

func TestNew_PicksUpRoutesAddedAfterStartup(t *testing.T) {
	cfg := startEnvtest(t)

	k8s, err := client.New(cfg, client.Options{Scheme: gwScheme(t)})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(ghostBackend))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	h, err := New(ctx, Config{
		GatewayName:      "blog-gw",
		GatewayNamespace: "default",
		RestConfig:       cfg,
		Resolve:          func(Backend) (*url.URL, bool) { return backendURL, true },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// No HTTPRoute exists yet: the handler serves nothing.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d before any route, want 404", rec.Code)
	}

	// Create a route after startup; the informer must rebuild the table.
	route := routeFor("default", "blog", "blog-gw", ghostBackend)
	if err := k8s.Create(ctx, &route); err != nil {
		t.Fatalf("create HTTPRoute: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Code == http.StatusOK && rec.Body.String() == ghostBackend {
			break // informer observed the new route and rebuilt the table
		}
		if time.Now().After(deadline) {
			t.Fatalf("route added after startup was never served: last status %d body %q", rec.Code, rec.Body.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}
