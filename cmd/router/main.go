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
// A second, narrow listener on --probe-addr serves GET /healthz for
// kubelet probes (the traffic listener is loopback only so kubelet can't
// reach it directly).
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

// healthzHandler returns a handler that responds 200 OK to GET /healthz.
// The probe listener is started only after the route aggregator has loaded
// its initial rule set, so a successful probe means "rules loaded and
// listener up", not just "process alive".
func healthzHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func main() {
	var (
		addr        string
		probeAddr   string
		gatewayName string
		gatewayNS   string
	)
	flag.StringVar(&addr, "listen", "127.0.0.1:9080", "address the router listens on (Tor connects here)")
	flag.StringVar(&probeAddr, "probe-addr", ":8081", "address the /healthz probe listener binds to")
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
	probeSrv := &http.Server{
		Addr:              probeAddr,
		Handler:           healthzHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = probeSrv.Shutdown(shutdownCtx)
	}()

	go func() {
		slog.Info("router probe listening", "addr", probeAddr)
		if err := probeSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("probe listener exited with error", "err", err)
		}
	}()

	slog.Info("router listening", "addr", addr, "gateway", gatewayName, "namespace", gatewayNS)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("router exited with error", "err", err)
		os.Exit(1)
	}
}
