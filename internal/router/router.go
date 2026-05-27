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
//   - The Config -> http.Handler constructor wires an HTTPRoute informer to
//     that table, rebuilding it whenever routes change.
package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Config carries the wiring inputs the sidecar needs at startup.
type Config struct {
	GatewayName      string
	GatewayNamespace string

	// RestConfig is the cluster connection. A nil value uses the ambient
	// in-cluster (or kubeconfig) config; tests inject an envtest config.
	RestConfig *rest.Config
	// Resolve maps a matched Backend to its upstream URL. A nil value uses
	// ClusterResolver (in-cluster Service DNS); tests inject a stub.
	Resolve BackendResolver
}

// New returns the HTTP handler that serves traffic coming from Tor. It builds
// an informer over the HTTPRoutes targeting cfg's Gateway and keeps the
// returned handler's RouteTable in sync with them for ctx's lifetime.
func New(ctx context.Context, cfg Config) (http.Handler, error) {
	if cfg.GatewayName == "" || cfg.GatewayNamespace == "" {
		return nil, errors.New("router: Config.GatewayName and Config.GatewayNamespace are required")
	}

	restCfg := cfg.RestConfig
	if restCfg == nil {
		var err error
		if restCfg, err = ctrl.GetConfig(); err != nil {
			return nil, fmt.Errorf("router: load cluster config: %w", err)
		}
	}

	resolve := cfg.Resolve
	if resolve == nil {
		resolve = ClusterResolver()
	}

	scheme := runtime.NewScheme()
	if err := gwv1.Install(scheme); err != nil {
		return nil, fmt.Errorf("router: install gateway-api scheme: %w", err)
	}

	c, err := cache.New(restCfg, cache.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("router: build cache: %w", err)
	}

	proxy := NewProxy(resolve)
	syncer := &routeSync{
		reader: c,
		gw:     types.NamespacedName{Name: cfg.GatewayName, Namespace: cfg.GatewayNamespace},
		proxy:  proxy,
	}

	informer, err := c.GetInformer(ctx, &gwv1.HTTPRoute{})
	if err != nil {
		return nil, fmt.Errorf("router: get HTTPRoute informer: %w", err)
	}
	rebuild := func() {
		if err := syncer.sync(ctx); err != nil {
			slog.Error("router: rebuild route table", "err", err)
		}
	}
	if _, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { rebuild() },
		UpdateFunc: func(any, any) { rebuild() },
		DeleteFunc: func(any) { rebuild() },
	}); err != nil {
		return nil, fmt.Errorf("router: register HTTPRoute handler: %w", err)
	}

	go func() {
		if err := c.Start(ctx); err != nil {
			slog.Error("router: informer cache stopped", "err", err)
		}
	}()
	if !c.WaitForCacheSync(ctx) {
		return nil, errors.New("router: informer cache failed to sync")
	}

	// Build an initial table so the handler serves a definite state (an empty
	// table 404s) even before the first informer event fires.
	if err := syncer.sync(ctx); err != nil {
		return nil, fmt.Errorf("router: initial route sync: %w", err)
	}

	return proxy, nil
}
