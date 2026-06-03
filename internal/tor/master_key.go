/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package tor

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// Errors returned by ValidateMasterKeySecret.
var (
	ErrMasterKeyMissingSecret = errors.New("master key Secret is missing hs_ed25519_secret_key")
	ErrMasterKeyMissingPublic = errors.New("master key Secret is missing hs_ed25519_public_key")
	ErrMasterKeyMismatch      = errors.New("hs_ed25519_secret_key and hs_ed25519_public_key do not form a pair")
)

// ValidateMasterKeySecret enforces the Secret-key map shape required by
// OnionBalancePolicy.masterKeySecretRef and returns the parsed KeyPair on
// success. The Secret MUST contain hs_ed25519_secret_key (64 bytes, Tor
// binary format) and hs_ed25519_public_key (32 bytes, Tor binary format)
// and the two MUST form a valid pair.
func ValidateMasterKeySecret(data map[string][]byte) (*KeyPair, error) {
	secretBytes, ok := data["hs_ed25519_secret_key"]
	if !ok || len(secretBytes) == 0 {
		return nil, ErrMasterKeyMissingSecret
	}
	publicBytes, ok := data["hs_ed25519_public_key"]
	if !ok || len(publicBytes) == 0 {
		return nil, ErrMasterKeyMissingPublic
	}

	kp, err := ParseFiles(secretBytes, publicBytes)
	if err != nil {
		return nil, fmt.Errorf("parse master key: %w", err)
	}

	// Derive the public key from the scalar (first 32 bytes of the expanded
	// secret key) and check it matches the supplied public key file.
	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(kp.expanded[:32])
	if err != nil {
		return nil, fmt.Errorf("master key scalar: %w", err)
	}
	derivedPoint := new(edwards25519.Point).ScalarBaseMult(scalar)
	derivedPub := derivedPoint.Bytes()

	suppliedPub := publicBytes[headerLen:]

	if subtle.ConstantTimeCompare(derivedPub, suppliedPub) != 1 {
		return nil, ErrMasterKeyMismatch
	}

	return kp, nil
}
