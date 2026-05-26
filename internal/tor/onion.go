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
	"crypto/sha3"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// v3 onion address derivation, per Tor rend-spec-v3 §6:
//
//   onion_address = base32(pubkey || checksum || version) + ".onion"
//   checksum      = SHA3-256(".onion checksum" || pubkey || version)[:2]
//   version       = 0x03
//
// The base32 alphabet is RFC 4648 lowercase, no padding.

const (
	onionAddressVersion byte = 0x03
	onionMagic               = ".onion checksum"
	onionSuffix              = ".onion"

	// onionAddressBodyLen is the byte length of (pubkey || checksum || version)
	// before base32 encoding.
	onionAddressBodyLen = ed25519.PublicKeySize + 2 + 1
	// onionAddressBase32Len is the base32-encoded length of an onion body
	// (56 chars). Multiplied out: ceil(35 * 8 / 5) == 56.
	onionAddressBase32Len = 56
)

var onionBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// OnionAddress is an immutable v3 hidden-service address backed by an
// ed25519 public key. Its zero value is invalid; construct via
// AddressFromPublicKey or ParseAddress.
type OnionAddress struct {
	pubKey ed25519.PublicKey
}

// AddressFromPublicKey derives a v3 .onion address from an ed25519 public
// key. Returns an error if the key length is wrong.
func AddressFromPublicKey(pub ed25519.PublicKey) (OnionAddress, error) {
	if len(pub) != ed25519.PublicKeySize {
		return OnionAddress{}, fmt.Errorf("tor: invalid ed25519 public key length %d (want %d)",
			len(pub), ed25519.PublicKeySize)
	}
	// Defensive copy so the caller mutating its slice cannot change our address.
	cp := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(cp, pub)
	return OnionAddress{pubKey: cp}, nil
}

// String returns the canonical "<56 chars>.onion" representation.
func (a OnionAddress) String() string {
	if len(a.pubKey) != ed25519.PublicKeySize {
		return ""
	}
	body := make([]byte, 0, onionAddressBodyLen)
	body = append(body, a.pubKey...)
	body = append(body, onionChecksum(a.pubKey)...)
	body = append(body, onionAddressVersion)
	return strings.ToLower(onionBase32.EncodeToString(body)) + onionSuffix
}

// PublicKey returns a defensive copy of the underlying ed25519 public key.
func (a OnionAddress) PublicKey() ed25519.PublicKey {
	cp := make(ed25519.PublicKey, len(a.pubKey))
	copy(cp, a.pubKey)
	return cp
}

func onionChecksum(pub ed25519.PublicKey) []byte {
	h := sha3.New256()
	_, _ = h.Write([]byte(onionMagic))
	_, _ = h.Write(pub)
	_, _ = h.Write([]byte{onionAddressVersion})
	sum := h.Sum(nil)
	return sum[:2]
}

// ParseAddress decodes and validates a "<56 chars>.onion" address. The
// returned OnionAddress carries the recovered ed25519 public key and is
// guaranteed to round-trip back to the same input via String().
func ParseAddress(addr string) (OnionAddress, error) {
	lower := strings.ToLower(strings.TrimSpace(addr))
	stripped := strings.TrimSuffix(lower, onionSuffix)
	if stripped == lower {
		return OnionAddress{}, errors.New("tor: address missing .onion suffix")
	}
	if len(stripped) != onionAddressBase32Len {
		return OnionAddress{}, fmt.Errorf("tor: address body has wrong length %d (want %d)",
			len(stripped), onionAddressBase32Len)
	}
	raw, err := onionBase32.DecodeString(strings.ToUpper(stripped))
	if err != nil {
		return OnionAddress{}, fmt.Errorf("tor: invalid base32 in address: %w", err)
	}
	if len(raw) != onionAddressBodyLen {
		return OnionAddress{}, fmt.Errorf("tor: decoded address has wrong length %d (want %d)",
			len(raw), onionAddressBodyLen)
	}
	if raw[34] != onionAddressVersion {
		return OnionAddress{}, fmt.Errorf("tor: address version byte is %#x (want %#x)",
			raw[34], onionAddressVersion)
	}
	pub := ed25519.PublicKey(raw[:ed25519.PublicKeySize])
	if !bytes.Equal(onionChecksum(pub), raw[32:34]) {
		return OnionAddress{}, errors.New("tor: address checksum mismatch")
	}
	cp := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(cp, pub)
	return OnionAddress{pubKey: cp}, nil
}
