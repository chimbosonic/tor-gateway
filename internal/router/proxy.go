/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
)

// BackendResolver maps a matched Backend to the upstream URL to proxy to.
// Returns ok=false when the backend can't be resolved (e.g. the Service
// has no endpoints), which the proxy surfaces as 502.
type BackendResolver func(Backend) (*url.URL, bool)

// Proxy is the in-pod HTTP handler: it matches each request against the
// current RouteTable and reverse-proxies to the resolved backend. The
// table is swapped atomically so the informer can update routes while
// requests are in flight.
type Proxy struct {
	resolve BackendResolver
	table   atomic.Pointer[RouteTable]
}

// NewProxy builds a Proxy with the given backend resolver.
func NewProxy(resolve BackendResolver) *Proxy {
	return &Proxy{resolve: resolve}
}

// SetTable atomically swaps the active RouteTable (called by the informer
// when HTTPRoutes change).
func (p *Proxy) SetTable(t *RouteTable) {
	p.table.Store(t)
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	table := p.table.Load()
	if table == nil {
		http.Error(w, "no routes configured", http.StatusNotFound)
		return
	}
	backend, ok := table.Match(r)
	if !ok {
		http.Error(w, "no matching route", http.StatusNotFound)
		return
	}
	target, ok := p.resolve(backend)
	if !ok || target == nil {
		http.Error(w, "backend unavailable", http.StatusBadGateway)
		return
	}
	httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
}
