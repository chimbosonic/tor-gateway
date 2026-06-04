/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package tor

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// To regenerate the golden files after an intentional rendering change:
//
//	go test ./internal/tor -update-golden
//
// Inspect the diff in `internal/tor/testdata/torrc/` before committing.
var updateGolden = flag.Bool("update-golden", false, "update golden files instead of asserting")

func TestRender_GoldenFiles(t *testing.T) {
	cases := []struct {
		name string
		cfg  TorrcConfig
	}{
		{
			name: "minimal",
			cfg: TorrcConfig{
				HiddenServiceDir: "/var/lib/tor/hs",
				DataDirectory:    "/var/lib/tor/data",
				HiddenServicePort: PortMapping{
					VirtualPort: 80,
					TargetHost:  "127.0.0.1",
					TargetPort:  9080,
				},
				PoWDefensesEnabled: true,
			},
		},
		{
			name: "debug-level-no-pow",
			cfg: TorrcConfig{
				HiddenServiceDir: "/var/lib/tor/hs",
				DataDirectory:    "/var/lib/tor/data",
				LogLevel:         "debug",
				HiddenServicePort: PortMapping{
					VirtualPort: 80,
					TargetHost:  "127.0.0.1",
					TargetPort:  9080,
				},
				PoWDefensesEnabled: false,
			},
		},
		{
			name: "client-auth",
			cfg: TorrcConfig{
				HiddenServiceDir: "/var/lib/tor/hs",
				DataDirectory:    "/var/lib/tor/data",
				HiddenServicePort: PortMapping{
					VirtualPort: 80,
					TargetHost:  "127.0.0.1",
					TargetPort:  9080,
				},
				PoWDefensesEnabled: true,
				ClientAuthDir:      "/var/lib/tor/hs/authorized_clients",
			},
		},
		{
			name: "extra-directives",
			cfg: TorrcConfig{
				HiddenServiceDir: "/var/lib/tor/hs",
				DataDirectory:    "/var/lib/tor/data",
				HiddenServicePort: PortMapping{
					VirtualPort: 80,
					TargetHost:  "127.0.0.1",
					TargetPort:  9080,
				},
				PoWDefensesEnabled: true,
				// Sorted-output property: keys deliberately out of order
				// here.
				ExtraDirectives: map[string]string{
					"SafeLogging":                       "1",
					"HardwareAccel":                     "0",
					"HiddenServiceOnionbalanceInstance": "1",
				},
			},
		},
		{
			name: "with-metrics",
			cfg: TorrcConfig{
				HiddenServiceDir: "/var/lib/tor/hs",
				DataDirectory:    "/var/lib/tor/data",
				HiddenServicePort: PortMapping{
					VirtualPort: 80,
					TargetHost:  "127.0.0.1",
					TargetPort:  9080,
				},
				PoWDefensesEnabled: true,
				MetricsPort:        9035,
				MetricsPortPolicy:  "accept 0.0.0.0/0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Render(&tc.cfg)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			golden := filepath.Join("testdata", "torrc", tc.name+".golden")
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("wrote %s", golden)
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden %s: %v (run with -update-golden to create)", golden, err)
			}
			if string(want) != got {
				t.Fatalf("torrc mismatch for %s\n--- want\n%s\n--- got\n%s", tc.name, want, got)
			}
		})
	}
}

func TestValidate_RejectsBadInputs(t *testing.T) {
	good := func() *TorrcConfig {
		return &TorrcConfig{
			HiddenServiceDir: "/var/lib/tor/hs",
			DataDirectory:    "/var/lib/tor/data",
			HiddenServicePort: PortMapping{
				VirtualPort: 80,
				TargetHost:  "127.0.0.1",
				TargetPort:  9080,
			},
			PoWDefensesEnabled: true,
		}
	}

	cases := []struct {
		name   string
		mutate func(*TorrcConfig)
		want   string
	}{
		{"relative hs dir", func(c *TorrcConfig) { c.HiddenServiceDir = "hs" }, "must be absolute"},
		{"relative data dir", func(c *TorrcConfig) { c.DataDirectory = "data" }, "must be absolute"},
		{"port 0", func(c *TorrcConfig) { c.HiddenServicePort.VirtualPort = 0 }, "out of range"},
		{"port too big", func(c *TorrcConfig) { c.HiddenServicePort.TargetPort = 65536 }, "out of range"},
		{"non-loopback target", func(c *TorrcConfig) { c.HiddenServicePort.TargetHost = "10.0.0.1" }, "loopback"},
		{"unknown log level", func(c *TorrcConfig) { c.LogLevel = "trace" }, "invalid LogLevel"},
		{"client auth outside hs dir", func(c *TorrcConfig) { c.ClientAuthDir = "/elsewhere/authorized_clients" }, "ClientAuthDir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestRender_EmitsMetricsPort(t *testing.T) {
	cfg := TorrcConfig{
		HiddenServiceDir: "/var/lib/tor/hs",
		DataDirectory:    "/var/lib/tor/data",
		HiddenServicePort: PortMapping{
			VirtualPort: 80,
			TargetHost:  "127.0.0.1",
			TargetPort:  9080,
		},
		PoWDefensesEnabled: true,
		MetricsPort:        9035,
		MetricsPortPolicy:  "accept 0.0.0.0/0",
	}
	out, err := Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"MetricsPort 0.0.0.0:9035",
		"MetricsPortPolicy accept 0.0.0.0/0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered torrc missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestRender_OmitsMetricsPortWhenZero(t *testing.T) {
	cfg := TorrcConfig{
		HiddenServiceDir: "/var/lib/tor/hs",
		DataDirectory:    "/var/lib/tor/data",
		HiddenServicePort: PortMapping{
			VirtualPort: 80,
			TargetHost:  "127.0.0.1",
			TargetPort:  9080,
		},
		PoWDefensesEnabled: true,
	}
	out, err := Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "MetricsPort") {
		t.Errorf("MetricsPort emitted with zero value\n--- got ---\n%s", out)
	}
}

func TestValidate_RejectsMetricsPortWithoutPolicy(t *testing.T) {
	cfg := TorrcConfig{
		HiddenServiceDir: "/var/lib/tor/hs",
		DataDirectory:    "/var/lib/tor/data",
		HiddenServicePort: PortMapping{
			VirtualPort: 80,
			TargetHost:  "127.0.0.1",
			TargetPort:  9080,
		},
		MetricsPort: 9035,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate to reject MetricsPort without MetricsPortPolicy")
	}
}

func TestRenderBackendOnionbalanceInstance(t *testing.T) {
	cfg := TorrcConfig{
		LogLevel:         "notice",
		HiddenServiceDir: "/var/lib/tor/hs",
		DataDirectory:    "/var/lib/tor/data",
		HiddenServicePort: PortMapping{
			VirtualPort: 80,
			TargetHost:  "127.0.0.1",
			TargetPort:  9080,
		},
		PoWDefensesEnabled:   true, // intentionally true — backend variant MUST override
		OnionbalanceInstance: true,
	}
	out, err := Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "HiddenServiceOnionbalanceInstance 1") {
		t.Errorf("expected HiddenServiceOnionbalanceInstance 1 in output:\n%s", out)
	}
	for _, denied := range []string{"HiddenServicePoWDefensesEnabled", "HiddenServiceEnableIntroDoSDefense"} {
		if strings.Contains(out, denied) {
			t.Errorf("backend variant must omit %s; got:\n%s", denied, out)
		}
	}
}

func TestRenderNonBackendStillHonoursPoW(t *testing.T) {
	cfg := TorrcConfig{
		LogLevel:         "notice",
		HiddenServiceDir: "/var/lib/tor/hs",
		DataDirectory:    "/var/lib/tor/data",
		HiddenServicePort: PortMapping{
			VirtualPort: 80,
			TargetHost:  "127.0.0.1",
			TargetPort:  9080,
		},
		PoWDefensesEnabled: true,
	}
	out, err := Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "HiddenServicePoWDefensesEnabled 1") {
		t.Errorf("non-backend variant must still emit PoW directives:\n%s", out)
	}
}

func TestRender_TestingNetworkInclude_Empty(t *testing.T) {
	// When the field is empty, output MUST be byte-identical to what a
	// production render produces — regression guard against accidentally
	// leaking testing-mode bytes into production torrcs.
	cfg := TorrcConfig{
		LogLevel:         "notice",
		HiddenServiceDir: "/var/lib/tor/hs",
		DataDirectory:    "/var/lib/tor/data",
		HiddenServicePort: PortMapping{
			VirtualPort: 80,
			TargetHost:  "127.0.0.1",
			TargetPort:  9080,
		},
		// TestingNetworkInclude intentionally unset
	}
	out, err := Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, denied := range []string{"TestingTorNetwork", "%include", "ClientUseIPv6 0"} {
		if strings.Contains(out, denied) {
			t.Errorf("production render must not contain %q; got:\n%s", denied, out)
		}
	}
}

func TestRender_TestingNetworkInclude_Set(t *testing.T) {
	const fragment = "TestingTorNetwork 1\nClientUseIPv6 0\nDirAuthority test_authority orport=5000 v3ident=AAA 127.0.0.1:7000 BBB\n"
	cfg := TorrcConfig{
		LogLevel:         "notice",
		HiddenServiceDir: "/var/lib/tor/hs",
		DataDirectory:    "/var/lib/tor/data",
		HiddenServicePort: PortMapping{
			VirtualPort: 80,
			TargetHost:  "127.0.0.1",
			TargetPort:  9080,
		},
		TestingNetworkInclude: fragment,
	}
	out, err := Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, required := range []string{
		"TestingTorNetwork 1",
		"ClientUseIPv6 0",
		"DirAuthority test_authority",
	} {
		if !strings.Contains(out, required) {
			t.Errorf("expected %q in output:\n%s", required, out)
		}
	}
	// No %include directive — content is inlined verbatim.
	if strings.Contains(out, "%include") {
		t.Errorf("rendered torrc must not contain %%include (content is inlined); got:\n%s", out)
	}
	// The testing block MUST precede the HiddenService block — Tor parses
	// torrc top-down and TestingTorNetwork must be set before HS
	// directives so the relaxed timeouts apply during HS publication.
	testingIdx := strings.Index(out, "TestingTorNetwork 1")
	hsIdx := strings.Index(out, "HiddenServiceDir")
	if testingIdx < 0 || hsIdx < 0 || testingIdx >= hsIdx {
		t.Errorf("TestingTorNetwork must precede HiddenServiceDir; got testingIdx=%d hsIdx=%d\n%s",
			testingIdx, hsIdx, out)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && (indexOf(s, sub) >= 0)))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
