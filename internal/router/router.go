/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package router implements the in-pod HTTP router that bridges between Tor's
// HiddenServicePort and in-cluster backend Services described by HTTPRoutes.
//
// The package is split into two layers so the matching logic is testable
// without a running Kubernetes cluster:
//
//   - The match/rewrite logic operates on a typed RouteTable value and is
//     pure (no informers, no network).
//   - The Config -> http.Handler constructor wires informers to that table.
package router

import (
	"context"
	"errors"
	"net/http"
)

// Config carries the wiring inputs the sidecar needs at startup.
type Config struct {
	GatewayName      string
	GatewayNamespace string
}

// New returns the HTTP handler that serves traffic coming from Tor.
//
// TODO: implement HTTPRoute informer + backendRef-aware reverse proxy.
// Tracked under the v1 implementation plan; this stub exists so the
// command binary compiles and the package surface is wired.
func New(ctx context.Context, cfg Config) (http.Handler, error) {
	if cfg.GatewayName == "" || cfg.GatewayNamespace == "" {
		return nil, errors.New("router: Config.GatewayName and Config.GatewayNamespace are required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "tor-gateway router: no HTTPRoute matched (stub)", http.StatusNotImplemented)
	})
	return mux, nil
}
