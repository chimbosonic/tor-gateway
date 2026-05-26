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
