/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Command obrefresh is the sidecar that runs alongside the onionbalance
// frontend daemon. It watches the headless Service for backend Tor instances
// belonging to a Gateway, rewrites the onionbalance config.yaml on change,
// and SIGHUPs the onionbalance process.
//
// Splitting this out of the operator keeps the operator's blast radius small
// (it never needs cluster-wide pod read) and keeps the onionbalance pod
// self-sufficient.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chimbosonic/tor-gateway/internal/onionbalance"
)

func main() {
	var (
		gatewayName string
		gatewayNS   string
		configPath  string
		pidPath     string
		interval    time.Duration
	)
	flag.StringVar(&gatewayName, "gateway", "", "name of the Gateway this refresher serves")
	flag.StringVar(&gatewayNS, "namespace", "", "namespace of the Gateway this refresher serves")
	flag.StringVar(&configPath, "config", "/etc/onionbalance/config.yaml",
		"path to write the rendered onionbalance config")
	flag.StringVar(&pidPath, "pidfile", "/run/onionbalance/onionbalance.pid",
		"pidfile of the onionbalance daemon to SIGHUP")
	flag.DurationVar(&interval, "interval", 30*time.Second,
		"minimum interval between rewrites")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if gatewayName == "" || gatewayNS == "" {
		slog.Error("--gateway and --namespace are required")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	r, err := onionbalance.NewRefresher(ctx, onionbalance.RefresherConfig{
		GatewayName:      gatewayName,
		GatewayNamespace: gatewayNS,
		ConfigPath:       configPath,
		PIDFile:          pidPath,
		Interval:         interval,
	})
	if err != nil {
		slog.Error("refresher init failed", "err", err)
		os.Exit(1)
	}

	if err := r.Run(ctx); err != nil {
		slog.Error("refresher exited with error", "err", err)
		os.Exit(1)
	}
}
