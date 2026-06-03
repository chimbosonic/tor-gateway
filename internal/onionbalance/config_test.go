package onionbalance

import (
	"strings"
	"testing"

	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// addrs picks N deterministic v3 addresses for tests.
func addrs(t *testing.T, n int) []tor.OnionAddress {
	t.Helper()
	out := make([]tor.OnionAddress, n)
	for i := range n {
		kp, err := tor.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		out[i] = kp.OnionAddress()
	}
	return out
}

func TestRenderConfig(t *testing.T) {
	master := addrs(t, 1)[0]
	backends := addrs(t, 3)

	t.Run("happy", func(t *testing.T) {
		got, err := Render(master, backends, "/etc/onionbalance/keys/hs_ed25519_secret_key")
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		for _, b := range backends {
			if !strings.Contains(got, b.String()) {
				t.Errorf("rendered config missing backend %s:\n%s", b, got)
			}
		}
		if !strings.Contains(got, "/etc/onionbalance/keys/hs_ed25519_secret_key") {
			t.Errorf("rendered config missing key path:\n%s", got)
		}
		if !strings.Contains(got, "services:") {
			t.Errorf("rendered config missing services: top-level:\n%s", got)
		}
	})

	t.Run("zero backends", func(t *testing.T) {
		got, err := Render(master, nil, "/k")
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if !strings.Contains(got, "services:") || !strings.Contains(got, "instances: []") {
			t.Errorf("expected services + empty instances:\n%s", got)
		}
	})

	t.Run("deterministic ordering", func(t *testing.T) {
		a, err := Render(master, backends, "/k")
		if err != nil {
			t.Fatal(err)
		}
		b, err := Render(master, backends, "/k")
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Errorf("Render is not deterministic")
		}
	})
}
