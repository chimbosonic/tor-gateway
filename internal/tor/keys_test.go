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

func TestGenerateKeyPair_Shape(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(kp.PublicKey()); got != ed25519.PublicKeySize {
		t.Fatalf("public key len = %d, want %d", got, ed25519.PublicKeySize)
	}
	if got := len(kp.SecretKeyFile()); got != SecretKeyFileSize {
		t.Fatalf("secret file len = %d, want %d", got, SecretKeyFileSize)
	}
	if got := len(kp.PublicKeyFile()); got != PublicKeyFileSize {
		t.Fatalf("public file len = %d, want %d", got, PublicKeyFileSize)
	}
}

func TestKeyFiles_HaveExpectedMagicHeaders(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	secret := kp.SecretKeyFile()
	if !bytes.HasPrefix(secret, []byte("== ed25519v1-secret: type0 ==")) {
		t.Fatalf("secret file does not start with secret magic; got % x", secret[:32])
	}
	for i := 29; i < 32; i++ {
		if secret[i] != 0 {
			t.Fatalf("secret file header[%d] = %#x, want 0 (NUL padding)", i, secret[i])
		}
	}

	public := kp.PublicKeyFile()
	if !bytes.HasPrefix(public, []byte("== ed25519v1-public: type0 ==")) {
		t.Fatalf("public file does not start with public magic; got % x", public[:32])
	}
	for i := 29; i < 32; i++ {
		if public[i] != 0 {
			t.Fatalf("public file header[%d] = %#x, want 0 (NUL padding)", i, public[i])
		}
	}
}

func TestExpandedSecretKey_HasClampedBits(t *testing.T) {
	const N = 25
	for range N {
		kp, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		body := kp.SecretKeyFile()[headerLen:]
		// Per RFC 8032: bottom 3 bits clear, top bit clear, second-from-top set.
		if body[0]&0x07 != 0 {
			t.Fatalf("scalar[0] = %#x has bottom 3 bits not cleared", body[0])
		}
		if body[31]&0x80 != 0 {
			t.Fatalf("scalar[31] = %#x has top bit set", body[31])
		}
		if body[31]&0x40 == 0 {
			t.Fatalf("scalar[31] = %#x missing second-from-top bit", body[31])
		}
	}
}

func TestHostname_MatchesOnionAddress(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := kp.OnionAddress().String() + "\n"
	got := string(kp.Hostname())
	if got != want {
		t.Fatalf("Hostname() = %q, want %q", got, want)
	}
	if !strings.HasSuffix(strings.TrimSpace(got), ".onion") {
		t.Fatalf("hostname does not end with .onion: %q", got)
	}
}

func TestParseFiles_RoundTrip(t *testing.T) {
	src, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseFiles(src.SecretKeyFile(), src.PublicKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.PublicKey(), src.PublicKey()) {
		t.Fatalf("public key changed across round trip")
	}
	if out.OnionAddress().String() != src.OnionAddress().String() {
		t.Fatalf("onion address changed across round trip: %s vs %s",
			out.OnionAddress(), src.OnionAddress())
	}
	if !bytes.Equal(out.SecretKeyFile(), src.SecretKeyFile()) {
		t.Fatalf("secret file changed across round trip")
	}
}

func TestParseSecretKey_RejectsBadInputs(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := kp.SecretKeyFile()

	t.Run("wrong length", func(t *testing.T) {
		if _, err := ParseSecretKey(good[:len(good)-1]); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("wrong magic", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[0] = 'X'
		if _, err := ParseSecretKey(bad); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("unclamped scalar", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		// Set bottom bit of the scalar; clamping requires it cleared.
		bad[headerLen] |= 0x01
		if _, err := ParseSecretKey(bad); err == nil {
			t.Fatal("expected error for unclamped scalar")
		}
	})
}

func TestParsePublicKey_RejectsBadInputs(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := kp.PublicKeyFile()

	if _, err := ParsePublicKey(good[:len(good)-1]); err == nil {
		t.Fatal("expected length error")
	}
	bad := append([]byte(nil), good...)
	bad[0] = 'X'
	if _, err := ParsePublicKey(bad); err == nil {
		t.Fatal("expected magic error")
	}
}
