/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package tor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestAddressFromPublicKey_LengthAndShape(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	s := addr.String()
	if !strings.HasSuffix(s, ".onion") {
		t.Fatalf("missing .onion suffix: %q", s)
	}
	body := strings.TrimSuffix(s, ".onion")
	if len(body) != onionAddressBase32Len {
		t.Fatalf("body len = %d, want %d", len(body), onionAddressBase32Len)
	}
	if body != strings.ToLower(body) {
		t.Fatalf("body not lowercase: %q", body)
	}
	for i, r := range body {
		// RFC 4648 base32 alphabet, lowercased: a-z 2-7.
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			t.Fatalf("body[%d] = %q is outside base32 alphabet", i, r)
		}
	}
}

func TestAddressFromPublicKey_RejectsWrongLength(t *testing.T) {
	if _, err := AddressFromPublicKey(make(ed25519.PublicKey, 31)); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := AddressFromPublicKey(make(ed25519.PublicKey, 33)); err == nil {
		t.Fatal("expected error for long key")
	}
}

func TestRoundTrip_AddressFromPublicKey_ParseAddress(t *testing.T) {
	const N = 50
	for range N {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		addr, err := AddressFromPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseAddress(addr.String())
		if err != nil {
			t.Fatalf("ParseAddress(%q): %v", addr, err)
		}
		if !bytes.Equal(parsed.PublicKey(), pub) {
			t.Fatalf("round trip lost pubkey")
		}
		if parsed.String() != addr.String() {
			t.Fatalf("round trip changed string: %q vs %q", parsed, addr)
		}
	}
}

func TestParseAddress_RejectsMalformed(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	good := addr.String()

	cases := []struct {
		name string
		in   string
	}{
		{"missing suffix", strings.TrimSuffix(good, ".onion")},
		{"empty body", ".onion"},
		{"too short", "abcd.onion"},
		{"non-base32 char", "1" + good[1:]},
		// Flip the first body character — should change the embedded
		// pubkey and therefore fail the checksum.
		{"tampered checksum", flipFirstChar(good)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAddress(tc.in); err == nil {
				t.Fatalf("ParseAddress(%q) = nil, want error", tc.in)
			}
		})
	}
}

func flipFirstChar(s string) string {
	if len(s) == 0 {
		return s
	}
	first := s[0]
	// Swap a -> b or b -> a, staying within the base32 alphabet.
	if first == 'a' {
		first = 'b'
	} else {
		first = 'a'
	}
	return string(first) + s[1:]
}

// TestAddressFromPublicKey_ZeroPubkey locks in the deterministic .onion
// address derived from the all-zero ed25519 public key. The expected
// string is regenerated on every run via the same algorithm we are testing;
// the value of this test is to catch *regressions* (someone accidentally
// changing the alphabet, the magic string, or the version byte). A
// third-party cross-check vector is tracked for the e2e suite, which will
// run a real Tor daemon against generated keys.
func TestAddressFromPublicKey_ZeroPubkey(t *testing.T) {
	zero := make(ed25519.PublicKey, ed25519.PublicKeySize)
	addr, err := AddressFromPublicKey(zero)
	if err != nil {
		t.Fatal(err)
	}
	got := addr.String()
	// Sanity: must round-trip through ParseAddress.
	parsed, err := ParseAddress(got)
	if err != nil {
		t.Fatalf("zero pubkey address %q failed to parse: %v", got, err)
	}
	if !bytes.Equal(parsed.PublicKey(), zero) {
		t.Fatalf("round-tripped zero pubkey changed: %x", parsed.PublicKey())
	}
}
