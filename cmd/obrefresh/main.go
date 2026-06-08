/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Command obrefresh is the sidecar that runs alongside the onionbalance
// frontend daemon. It watches backend Secrets labelled
// torgateway.io/gateway=<gw>,torgateway.io/role=backend in the Gateway's
// namespace, rewrites the onionbalance config.yaml on change, and SIGHUPs
// the onionbalance process.
//
// Splitting this out of the operator keeps the operator's blast radius small
// (it never needs cluster-wide pod read) and keeps the onionbalance pod
// self-sufficient.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chimbosonic/tor-gateway/internal/onionbalance"
	"github.com/chimbosonic/tor-gateway/internal/tor"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// healthcheckFile is the well-known path the refresher writes after each
// successful rebuild and the --healthcheck flag reads to determine liveness.
const healthcheckFile = "/run/obrefresh/last-success"

func main() {
	var (
		gatewayName   string
		gatewayNS     string
		gatewayUID    string
		configPath    string
		pidPath       string
		interval      time.Duration
		masterAddr    string
		masterKeyPath string
		healthcheck   bool
	)
	flag.StringVar(&gatewayName, "gateway", "", "name of the Gateway this refresher serves")
	flag.StringVar(&gatewayNS, "namespace", "", "namespace of the Gateway this refresher serves")
	flag.StringVar(&gatewayUID, "gateway-uid", "", "Gateway.metadata.uid; used to label-filter backend Secrets")
	flag.StringVar(&configPath, "config", "/etc/onionbalance/config.yaml",
		"path to write the rendered onionbalance config")
	flag.StringVar(&pidPath, "pidfile", "/run/onionbalance/onionbalance.pid",
		"pidfile of the onionbalance daemon to SIGHUP")
	flag.DurationVar(&interval, "interval", 30*time.Second,
		"minimum interval between rewrites")
	flag.StringVar(&masterAddr, "master-address", "",
		"the master .onion address (with or without the .onion suffix)")
	flag.StringVar(&masterKeyPath, "master-key-path", "/etc/onionbalance/keys/hs_ed25519_secret_key",
		"in-pod path where the master ed25519 secret key is mounted")
	flag.BoolVar(&healthcheck, "healthcheck", false,
		"exit 0 if the last refresh succeeded within 2× --interval, else exit 1")
	flag.Parse()

	if healthcheck {
		runHealthcheck(interval)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if gatewayName == "" || gatewayNS == "" {
		slog.Error("--gateway and --namespace are required")
		os.Exit(2)
	}
	if gatewayUID == "" {
		slog.Error("--gateway-uid is required")
		os.Exit(2)
	}
	if masterAddr == "" {
		slog.Error("--master-address is required")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("rest.InClusterConfig", "err", err)
		os.Exit(1)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		slog.Error("kubernetes.NewForConfig", "err", err)
		os.Exit(1)
	}

	// Normalise: ensure the .onion suffix is present before parsing.
	if !strings.HasSuffix(masterAddr, ".onion") {
		masterAddr += ".onion"
	}
	master, err := tor.ParseAddress(masterAddr)
	if err != nil {
		slog.Error("parse master-address", "value", masterAddr, "err", err)
		os.Exit(2)
	}

	r, err := onionbalance.NewRefresher(ctx, onionbalance.RefresherConfig{
		GatewayName:      gatewayName,
		GatewayNamespace: gatewayNS,
		MasterKeyPath:    masterKeyPath,
		ConfigPath:       configPath,
		PIDFile:          pidPath,
		Interval:         interval,
		Master:           master,
		OwnerUID:         gatewayUID,
		Client:           client,
		HealthcheckFile:  healthcheckFile,
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

// runHealthcheck exits 0 if the healthcheck file was written within 2×interval
// of now, and exits 1 otherwise (file missing, unreadable, or stale).
func runHealthcheck(interval time.Duration) {
	info, err := os.Stat(healthcheckFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: stat failed:", err)
		os.Exit(1)
	}
	age := time.Since(info.ModTime())
	window := 2 * interval
	if age > window {
		fmt.Fprintf(os.Stderr, "healthcheck: last success %v ago, window %v\n", age.Truncate(time.Second), window)
		os.Exit(1)
	}
}
