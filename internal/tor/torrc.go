/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package tor

import (
	"errors"
	"fmt"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
)

// TorrcConfig is the typed input to Render. It deliberately exposes a
// small, curated subset of torrc directives — never raw string passthrough,
// so we cannot accidentally let user-controlled YAML inject Tor directives
// like SocksPort or ExitNodes.
type TorrcConfig struct {
	// HiddenServiceDir is the directory Tor uses to store the v3 keys and
	// hostname file. Must be absolute.
	HiddenServiceDir string

	// HiddenServicePort maps an external Tor virtual port (typically 80)
	// to a loopback address:port where the in-pod HTTP router listens.
	HiddenServicePort PortMapping

	// LogLevel sets the Tor daemon log verbosity. Defaults to "notice".
	LogLevel string

	// DataDirectory is Tor's working directory for descriptors, consensus
	// cache, etc. Must be absolute. Required.
	DataDirectory string

	// PoWDefensesEnabled toggles HiddenServicePoWDefensesEnabled and
	// HiddenServiceEnableIntroDoSDefense. Default true; only disable with
	// an alternative DoS mitigation in place.
	PoWDefensesEnabled bool

	// ClientAuthDir, when non-empty, enables v3 client authorization. Tor
	// reads <HiddenServiceDir>/authorized_clients/*.auth from inside the
	// HiddenServiceDir; ClientAuthDir here is informational only and is
	// validated to live under HiddenServiceDir.
	ClientAuthDir string

	// MetricsPort, when non-zero, enables Tor's Prometheus-format metrics
	// endpoint bound to 0.0.0.0:<MetricsPort>. The endpoint exposes only
	// internal counters (no key material). MetricsPortPolicy is required
	// when this is non-zero; cluster-internal scoping should come from a
	// NetworkPolicy, not from the policy directive.
	MetricsPort int

	// MetricsPortPolicy is the Tor exit-policy-style ingress filter for
	// MetricsPort (e.g. "accept 0.0.0.0/0"). Required when MetricsPort > 0.
	MetricsPortPolicy string

	// ExtraDirectives is a map of additional, **operator-trusted**
	// directives to append. Use sparingly; prefer adding typed fields.
	// Both the key and value are emitted verbatim, so callers MUST NOT
	// pass user-controlled input here. Sorted alphabetically on render
	// for deterministic output.
	ExtraDirectives map[string]string

	// OnionbalanceInstance, when true, emits HiddenServiceOnionbalanceInstance 1
	// inside the HiddenService block AND unconditionally omits the PoW
	// directives (PoWDefensesEnabled is ignored). Used by backend pods in HA mode.
	OnionbalanceInstance bool
}

// PortMapping is a single HiddenServicePort target.
type PortMapping struct {
	// VirtualPort is the port clients reach over Tor (typically 80).
	VirtualPort int
	// TargetHost is the in-pod address Tor forwards the connection to;
	// must be a loopback address.
	TargetHost string
	// TargetPort is the in-pod port for the target.
	TargetPort int
}

// Validate returns an error if the config is unusable.
func (c *TorrcConfig) Validate() error {
	if c == nil {
		return errors.New("tor: nil TorrcConfig")
	}
	if !path.IsAbs(c.HiddenServiceDir) {
		return fmt.Errorf("tor: HiddenServiceDir must be absolute, got %q", c.HiddenServiceDir)
	}
	if !path.IsAbs(c.DataDirectory) {
		return fmt.Errorf("tor: DataDirectory must be absolute, got %q", c.DataDirectory)
	}
	if c.HiddenServicePort.VirtualPort < 1 || c.HiddenServicePort.VirtualPort > 65535 {
		return fmt.Errorf("tor: HiddenServicePort.VirtualPort out of range: %d",
			c.HiddenServicePort.VirtualPort)
	}
	if c.HiddenServicePort.TargetPort < 1 || c.HiddenServicePort.TargetPort > 65535 {
		return fmt.Errorf("tor: HiddenServicePort.TargetPort out of range: %d",
			c.HiddenServicePort.TargetPort)
	}
	ip := net.ParseIP(c.HiddenServicePort.TargetHost)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("tor: HiddenServicePort.TargetHost must be a loopback IP, got %q",
			c.HiddenServicePort.TargetHost)
	}
	if c.LogLevel != "" && !validLogLevel(c.LogLevel) {
		return fmt.Errorf("tor: invalid LogLevel %q", c.LogLevel)
	}
	if c.ClientAuthDir != "" {
		if !path.IsAbs(c.ClientAuthDir) {
			return fmt.Errorf("tor: ClientAuthDir must be absolute, got %q", c.ClientAuthDir)
		}
		// Tor wants authorized_clients inside the HiddenServiceDir; reject
		// configurations that put it elsewhere.
		want := path.Join(c.HiddenServiceDir, "authorized_clients")
		if c.ClientAuthDir != want {
			return fmt.Errorf("tor: ClientAuthDir must equal %q, got %q", want, c.ClientAuthDir)
		}
	}
	if c.MetricsPort < 0 || c.MetricsPort > 65535 {
		return fmt.Errorf("tor: MetricsPort out of range: %d", c.MetricsPort)
	}
	if c.MetricsPort > 0 && c.MetricsPortPolicy == "" {
		return errors.New("tor: MetricsPortPolicy required when MetricsPort > 0")
	}
	for k := range c.ExtraDirectives {
		if strings.ContainsAny(k, " \t\r\n") || k == "" {
			return fmt.Errorf("tor: invalid ExtraDirectives key %q", k)
		}
	}
	return nil
}

func validLogLevel(l string) bool {
	switch l {
	case "debug", "info", "notice", "warn", "err":
		return true
	}
	return false
}

// Render returns the torrc content as a string. Output is deterministic
// (extra directives are sorted) so it can be golden-tested.
func Render(c *TorrcConfig) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	level := c.LogLevel
	if level == "" {
		level = "notice"
	}

	var b strings.Builder
	b.WriteString("# Rendered by tor-gateway; do not edit by hand.\n")
	b.WriteString("\n")

	fmt.Fprintf(&b, "DataDirectory %s\n", c.DataDirectory)
	fmt.Fprintf(&b, "Log %s stdout\n", level)
	// We never want this Tor instance to act as a SOCKS proxy or relay.
	b.WriteString("SocksPort 0\n")
	b.WriteString("ClientUseIPv4 1\n")
	b.WriteString("ClientUseIPv6 1\n")
	b.WriteString("\n")

	fmt.Fprintf(&b, "HiddenServiceDir %s\n", c.HiddenServiceDir)
	fmt.Fprintf(&b, "HiddenServiceVersion 3\n")
	fmt.Fprintf(&b, "HiddenServicePort %d %s:%d\n",
		c.HiddenServicePort.VirtualPort,
		c.HiddenServicePort.TargetHost,
		c.HiddenServicePort.TargetPort,
	)
	if c.OnionbalanceInstance {
		b.WriteString("HiddenServiceOnionbalanceInstance 1\n")
	}

	if c.PoWDefensesEnabled && !c.OnionbalanceInstance {
		b.WriteString("HiddenServiceEnableIntroDoSDefense 1\n")
		b.WriteString("HiddenServicePoWDefensesEnabled 1\n")
	}

	if c.MetricsPort > 0 {
		fmt.Fprintf(&b, "MetricsPort 0.0.0.0:%d\n", c.MetricsPort)
		fmt.Fprintf(&b, "MetricsPortPolicy %s\n", c.MetricsPortPolicy)
	}

	if c.ClientAuthDir != "" {
		// Tor v3 reads authorized_clients/*.auth from inside the
		// HiddenServiceDir automatically; the directive itself is
		// implicit. Emit a comment so operators can see it was wired.
		b.WriteString("# client authorization enabled (authorized_clients/*.auth)\n")
	}

	if len(c.ExtraDirectives) > 0 {
		keys := make([]string, 0, len(c.ExtraDirectives))
		for k := range c.ExtraDirectives {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("\n# extra directives\n")
		for _, k := range keys {
			v := c.ExtraDirectives[k]
			if v == "" {
				fmt.Fprintf(&b, "%s\n", k)
			} else {
				fmt.Fprintf(&b, "%s %s\n", k, v)
			}
		}
	}

	return b.String(), nil
}

// MustRender is Render but panics on error. Intended for test scaffolding.
func MustRender(c *TorrcConfig) string {
	s, err := Render(c)
	if err != nil {
		panic(err)
	}
	return s
}

// Defensive: keep strconv linked so go vet stays quiet across refactors.
var _ = strconv.Itoa
