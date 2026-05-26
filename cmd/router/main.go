/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Command router is the in-pod HTTP router sidecar that runs alongside Tor.
//
// Tor exposes a single HiddenServicePort -> 127.0.0.1:9080 inside the pod;
// this binary listens on that port, watches the HTTPRoutes targeting the
// owning Gateway via a Kubernetes informer, and reverse-proxies requests to
// the matching in-cluster Service backendRefs.
//
// The router is deliberately small and pure: all Tor-specific behavior is
// outside it, so it can be unit-tested without a Tor daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chimbosonic/tor-gateway/internal/router"
)

func main() {
	var (
		addr        string
		gatewayName string
		gatewayNS   string
	)
	flag.StringVar(&addr, "listen", "127.0.0.1:9080", "address the router listens on (Tor connects here)")
	flag.StringVar(&gatewayName, "gateway", "", "name of the Gateway this router serves")
	flag.StringVar(&gatewayNS, "namespace", "", "namespace of the Gateway this router serves")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if gatewayName == "" || gatewayNS == "" {
		slog.Error("--gateway and --namespace are required")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	handler, err := router.New(ctx, router.Config{
		GatewayName:      gatewayName,
		GatewayNamespace: gatewayNS,
	})
	if err != nil {
		slog.Error("router init failed", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Info("router listening", "addr", addr, "gateway", gatewayName, "namespace", gatewayNS)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("router exited with error", "err", err)
		os.Exit(1)
	}
}
