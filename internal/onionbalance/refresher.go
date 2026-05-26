/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package onionbalance implements support for HA Tor hidden services via
// the onionbalance daemon.
//
// Two concerns live here:
//
//   - Rendering an onionbalance config.yaml from the set of backend instance
//     onion addresses currently advertised by a Gateway's headless Service.
//   - The refresher loop that runs inside the frontend pod, watches that
//     Service, rewrites the config on change, and SIGHUPs onionbalance.
//
// The rendering logic is pure and unit-tested separately from the refresher.
package onionbalance

import (
	"context"
	"errors"
	"time"
)

// RefresherConfig configures a per-Gateway onionbalance refresher.
type RefresherConfig struct {
	GatewayName      string
	GatewayNamespace string
	ConfigPath       string
	PIDFile          string
	Interval         time.Duration
}

// Refresher watches backend instance addresses for a Gateway and keeps the
// onionbalance config.yaml + running daemon in sync.
type Refresher struct {
	cfg RefresherConfig
}

// NewRefresher constructs a Refresher.
//
// TODO: wire a Service / EndpointSlice informer scoped to the Gateway's
// backend StatefulSet and emit reload events.
func NewRefresher(ctx context.Context, cfg RefresherConfig) (*Refresher, error) {
	if cfg.GatewayName == "" || cfg.GatewayNamespace == "" {
		return nil, errors.New("onionbalance: RefresherConfig.GatewayName and RefresherConfig.GatewayNamespace are required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	return &Refresher{cfg: cfg}, nil
}

// Run blocks until ctx is cancelled.
func (r *Refresher) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
