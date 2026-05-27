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

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// routeSync rebuilds the proxy's RouteTable from the HTTPRoutes currently in
// the cluster. The informer invokes sync whenever an HTTPRoute changes.
type routeSync struct {
	reader client.Reader
	gw     types.NamespacedName
	proxy  *Proxy
}

// sync lists every HTTPRoute, keeps those targeting gw, and atomically swaps
// the proxy's table to the freshly compiled rules.
func (s *routeSync) sync(ctx context.Context) error {
	var list gwv1.HTTPRouteList
	if err := s.reader.List(ctx, &list); err != nil {
		return err
	}
	s.proxy.SetTable(NewRouteTable(rulesForGateway(list.Items, s.gw)))
	return nil
}
