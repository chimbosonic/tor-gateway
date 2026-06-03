/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package tor

import (
	"errors"
	"testing"
)

func TestValidateMasterKeySecret(t *testing.T) {
	good, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	t.Run("happy", func(t *testing.T) {
		kp, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_secret_key": good.SecretKeyFile(),
			"hs_ed25519_public_key": good.PublicKeyFile(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if kp.OnionAddress().String() != good.OnionAddress().String() {
			t.Fatalf("derived .onion mismatch: %s vs %s", kp.OnionAddress(), good.OnionAddress())
		}
	})

	t.Run("missing secret", func(t *testing.T) {
		_, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_public_key": good.PublicKeyFile(),
		})
		if !errors.Is(err, ErrMasterKeyMissingSecret) {
			t.Fatalf("want ErrMasterKeyMissingSecret, got %v", err)
		}
	})

	t.Run("missing public", func(t *testing.T) {
		_, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_secret_key": good.SecretKeyFile(),
		})
		if !errors.Is(err, ErrMasterKeyMissingPublic) {
			t.Fatalf("want ErrMasterKeyMissingPublic, got %v", err)
		}
	})

	t.Run("mismatched pair", func(t *testing.T) {
		other, _ := GenerateKeyPair(nil)
		_, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_secret_key": good.SecretKeyFile(),
			"hs_ed25519_public_key": other.PublicKeyFile(),
		})
		if !errors.Is(err, ErrMasterKeyMismatch) {
			t.Fatalf("want ErrMasterKeyMismatch, got %v", err)
		}
	})

	t.Run("malformed secret", func(t *testing.T) {
		_, err := ValidateMasterKeySecret(map[string][]byte{
			"hs_ed25519_secret_key": []byte("not a key"),
			"hs_ed25519_public_key": good.PublicKeyFile(),
		})
		if err == nil || errors.Is(err, ErrMasterKeyMissingSecret) || errors.Is(err, ErrMasterKeyMissingPublic) {
			t.Fatalf("want parse error, got %v", err)
		}
	})
}
