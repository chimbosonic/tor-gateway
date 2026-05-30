/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// resolveBackends walks every backendRef in `routes`, gates cross-namespace
// refs through ReferenceGrants in the backend's namespace, reads the
// Service, resolves the port → targetPort, and returns the deduped set of
// ResolvedBackend entries. Skipped (with INFO log) on:
//   - Backend Service missing (ResolvedRefs already surfaces BackendNotFound).
//   - Backend Service has no selector (ExternalName / headless).
//   - Cross-namespace backendRef with no matching ReferenceGrant.
func (r *GatewayReconciler) resolveBackends(
	ctx context.Context,
	gw *gwv1.Gateway,
	routes []gwv1.HTTPRoute,
) ([]ResolvedBackend, error) {
	logger := log.FromContext(ctx).WithValues("gateway", client.ObjectKeyFromObject(gw))

	type key struct{ ns, name string }
	seen := map[key]ResolvedBackend{}
	grantCache := map[string][]gwv1beta1.ReferenceGrant{}

	for ri := range routes {
		route := &routes[ri]
		for rri := range route.Spec.Rules {
			for _, ref := range route.Spec.Rules[rri].BackendRefs {
				ns := route.Namespace
				if ref.Namespace != nil {
					ns = string(*ref.Namespace)
				}
				name := string(ref.Name)
				port := int32(0)
				if ref.Port != nil {
					port = int32(*ref.Port)
				}

				if ns != route.Namespace {
					grants, err := r.grantsIn(ctx, ns, grantCache)
					if err != nil {
						return nil, err
					}
					allowed := Allows(grants,
						FromRef{Group: gwv1.GroupName, Kind: "HTTPRoute", Namespace: route.Namespace},
						ToRef{Group: "", Kind: "Service", Name: name},
					)
					// Silent: the HTTPRoute reconciler already surfaces this as
					// ResolvedRefs=RefNotPermitted (v0.3.0); no need to double-emit.
					if !allowed {
						continue
					}
				}

				svc := &corev1.Service{}
				if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, svc); err != nil {
					if apierrors.IsNotFound(err) {
						logger.Info("backend Service not found; skipping from NetworkPolicy",
							"backend", client.ObjectKey{Namespace: ns, Name: name})
						continue
					}
					return nil, fmt.Errorf("get Service %s/%s: %w", ns, name, err)
				}
				if len(svc.Spec.Selector) == 0 {
					logger.Info("backend Service has no selector; skipping from NetworkPolicy",
						"backend", client.ObjectKey{Namespace: ns, Name: name})
					continue
				}

				target, proto, ok := resolveTargetPort(svc, port)
				if !ok {
					logger.Info("backend Service does not expose port; skipping from NetworkPolicy",
						"backend", client.ObjectKey{Namespace: ns, Name: name}, "port", port)
					continue
				}

				seen[key{ns, name}] = ResolvedBackend{
					Namespace:   ns,
					PodSelector: copyLabels(svc.Spec.Selector),
					TargetPort:  target,
					Protocol:    proto,
				}
			}
		}
	}

	out := make([]ResolvedBackend, 0, len(seen))
	for _, b := range seen {
		out = append(out, b)
	}
	return out, nil
}

func (r *GatewayReconciler) grantsIn(
	ctx context.Context,
	ns string,
	cache map[string][]gwv1beta1.ReferenceGrant,
) ([]gwv1beta1.ReferenceGrant, error) {
	if v, ok := cache[ns]; ok {
		return v, nil
	}
	list := &gwv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, list, client.InNamespace(ns)); err != nil {
		return nil, fmt.Errorf("list ReferenceGrants in %s: %w", ns, err)
	}
	cache[ns] = list.Items
	return list.Items, nil
}

func resolveTargetPort(svc *corev1.Service, requested int32) (intstr.IntOrString, corev1.Protocol, bool) {
	for _, p := range svc.Spec.Ports {
		if p.Port != requested {
			continue
		}
		proto := p.Protocol
		if proto == "" {
			proto = corev1.ProtocolTCP
		}
		// TargetPort may be empty (Service defaults to Port); fall back.
		tp := p.TargetPort
		if tp.Type == intstr.Int && tp.IntValue() == 0 && tp.StrVal == "" {
			tp = intstr.FromInt(int(p.Port))
		}
		return tp, proto, true
	}
	return intstr.IntOrString{}, "", false
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
