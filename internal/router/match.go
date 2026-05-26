/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import "net/http"

// PathMatchType enumerates the HTTPRoute path match types we support.
type PathMatchType string

const (
	PathExact  PathMatchType = "Exact"
	PathPrefix PathMatchType = "PathPrefix"
)

// PathMatch is a single path match condition.
type PathMatch struct {
	Type  PathMatchType
	Value string
}

// Match is one HTTPRoute match condition.
type Match struct {
	Path PathMatch
}

// Backend is a resolved upstream Service target.
type Backend struct {
	Namespace string
	Name      string
	Port      int32
}

// Rule is one compiled HTTPRoute rule.
type Rule struct {
	Matches  []Match
	Backends []Backend
}

// RouteTable holds the compiled rules for a Gateway and matches requests
// against them. It is pure: no informers, no network.
type RouteTable struct {
	rules []Rule
}

// NewRouteTable builds a RouteTable from compiled rules.
func NewRouteTable(rules []Rule) *RouteTable {
	return &RouteTable{rules: rules}
}

// Match returns the chosen backend for req, or ok=false if nothing matched.
// When several matches apply it picks the most specific per the Gateway API
// precedence rules: an Exact path beats a PathPrefix, and among prefixes the
// longest value wins.
func (t *RouteTable) Match(req *http.Request) (Backend, bool) {
	var (
		best      Backend
		bestScore = -1
		found     bool
	)
	for _, rule := range t.rules {
		if len(rule.Backends) == 0 {
			continue
		}
		for _, m := range rule.Matches {
			if !pathMatches(m.Path, req.URL.Path) {
				continue
			}
			if s := pathScore(m.Path); s > bestScore {
				bestScore = s
				best = rule.Backends[0]
				found = true
			}
		}
	}
	return best, found
}

// pathScore ranks a matched path for precedence. Exact matches outrank any
// prefix; within a type, longer values outrank shorter ones. The exact tier
// is offset well above any realistic path length so it always wins.
func pathScore(p PathMatch) int {
	const exactTier = 1 << 16
	if p.Type == PathExact {
		return exactTier + len(p.Value)
	}
	return len(p.Value)
}

// pathMatches implements the Gateway API path match semantics. PathPrefix
// matches on whole path segments: "/api" matches "/api" and "/api/..." but
// not "/apiv2".
func pathMatches(p PathMatch, reqPath string) bool {
	switch p.Type {
	case PathExact:
		return reqPath == p.Value
	case PathPrefix:
		if reqPath == p.Value {
			return true
		}
		prefix := p.Value
		if prefix != "/" {
			prefix += "/"
		}
		return len(reqPath) >= len(prefix) && reqPath[:len(prefix)] == prefix
	default:
		return false
	}
}
