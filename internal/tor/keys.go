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
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
)

// On-disk file format for v3 hidden services, per Tor's src/lib/crypt_ops.
//
// Each key file starts with a 32-byte ASCII magic header (the literal
// string below, NUL-padded to 32 bytes) followed by the key body:
//
//   hs_ed25519_secret_key : 32-byte header || 64-byte expanded secret key
//   hs_ed25519_public_key : 32-byte header || 32-byte public key
//
// Tor uses the *expanded* secret key form (output of SHA-512 with the
// standard bit clamping) rather than the 32-byte seed, because Tor never
// re-derives the scalar at runtime — it signs with the expanded form
// directly. Once we expand the seed, the seed itself is no longer needed.

const (
	tagSecret = "== ed25519v1-secret: type0 =="
	tagPublic = "== ed25519v1-public: type0 =="

	headerLen         = 32
	expandedSecretLen = 64

	// SecretKeyFileSize is the byte length of hs_ed25519_secret_key.
	SecretKeyFileSize = headerLen + expandedSecretLen
	// PublicKeyFileSize is the byte length of hs_ed25519_public_key.
	PublicKeyFileSize = headerLen + ed25519.PublicKeySize
)

// FileSecretKeyName, FilePublicKeyName, FileHostnameName are the canonical
// file names Tor expects inside a HiddenServiceDir.
const (
	FileSecretKeyName = "hs_ed25519_secret_key"
	FilePublicKeyName = "hs_ed25519_public_key"
	FileHostnameName  = "hostname"
)

// KeyPair is a v3 hidden-service key, held in the expanded form Tor uses
// on disk. Construct via GenerateKeyPair (fresh keys) or ParseSecretKey /
// ParsePublicKey (pre-existing keys mounted from a Secret).
//
// KeyPair is not safe to copy after construction; pass by pointer.
type KeyPair struct {
	publicKey ed25519.PublicKey
	// expanded is the 64-byte expanded secret key (clamped SHA-512 of the
	// seed). It is sensitive material; never log it.
	expanded []byte
}

// GenerateKeyPair generates a fresh ed25519 hidden-service keypair using
// the supplied entropy source.
func GenerateKeyPair(rand io.Reader) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, fmt.Errorf("tor: generate ed25519 key: %w", err)
	}
	// ed25519.PrivateKey is seed||pub. The seed is the first 32 bytes.
	seed := priv.Seed()
	expanded := expandSeed(seed)
	return &KeyPair{
		publicKey: append(ed25519.PublicKey(nil), pub...),
		expanded:  expanded,
	}, nil
}

// PublicKey returns a defensive copy of the ed25519 public key.
func (k *KeyPair) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), k.publicKey...)
}

// OnionAddress returns the derived v3 .onion address.
func (k *KeyPair) OnionAddress() OnionAddress {
	addr, _ := AddressFromPublicKey(k.publicKey)
	return addr
}

// Hostname returns the canonical "<56 chars>.onion\n" content that Tor
// writes to <HiddenServiceDir>/hostname. The trailing newline is part of
// Tor's on-disk format.
func (k *KeyPair) Hostname() []byte {
	return []byte(k.OnionAddress().String() + "\n")
}

// SecretKeyFile returns the 96-byte content of hs_ed25519_secret_key.
func (k *KeyPair) SecretKeyFile() []byte {
	out := make([]byte, 0, SecretKeyFileSize)
	out = append(out, header(tagSecret)...)
	out = append(out, k.expanded...)
	return out
}

// PublicKeyFile returns the 64-byte content of hs_ed25519_public_key.
func (k *KeyPair) PublicKeyFile() []byte {
	out := make([]byte, 0, PublicKeyFileSize)
	out = append(out, header(tagPublic)...)
	out = append(out, k.publicKey...)
	return out
}

// ParseSecretKey decodes the on-disk hs_ed25519_secret_key content and
// returns a partial KeyPair (no public key yet). Combine with the result
// of ParsePublicKey to get a full KeyPair, or use ParseFiles for both.
func ParseSecretKey(data []byte) (expanded []byte, err error) {
	if len(data) != SecretKeyFileSize {
		return nil, fmt.Errorf("tor: secret key file is %d bytes (want %d)",
			len(data), SecretKeyFileSize)
	}
	if !bytes.Equal(data[:headerLen], header(tagSecret)) {
		return nil, errors.New("tor: secret key file has wrong magic header")
	}
	body := data[headerLen:]
	if !looksClamped(body) {
		return nil, errors.New("tor: secret key scalar is not bit-clamped (file is malformed)")
	}
	return append([]byte(nil), body...), nil
}

// ParsePublicKey decodes the on-disk hs_ed25519_public_key content.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) != PublicKeyFileSize {
		return nil, fmt.Errorf("tor: public key file is %d bytes (want %d)",
			len(data), PublicKeyFileSize)
	}
	if !bytes.Equal(data[:headerLen], header(tagPublic)) {
		return nil, errors.New("tor: public key file has wrong magic header")
	}
	return append(ed25519.PublicKey(nil), data[headerLen:]...), nil
}

// ParseFiles decodes a matched pair of hs_ed25519_secret_key /
// hs_ed25519_public_key file contents into a KeyPair.
func ParseFiles(secret, public []byte) (*KeyPair, error) {
	expanded, err := ParseSecretKey(secret)
	if err != nil {
		return nil, err
	}
	pub, err := ParsePublicKey(public)
	if err != nil {
		return nil, err
	}
	return &KeyPair{publicKey: pub, expanded: expanded}, nil
}

// header returns the 32-byte magic header for the given tag.
func header(tag string) []byte {
	if len(tag) > headerLen {
		panic(fmt.Sprintf("tor: tag %q exceeds header length", tag))
	}
	out := make([]byte, headerLen)
	copy(out, tag)
	return out
}

// expandSeed converts a 32-byte ed25519 seed into the 64-byte expanded
// secret key Tor stores on disk: SHA-512(seed) with the standard ed25519
// scalar clamping (RFC 8032 §5.1.5).
func expandSeed(seed []byte) []byte {
	if len(seed) != ed25519.SeedSize {
		panic(fmt.Sprintf("tor: seed must be %d bytes", ed25519.SeedSize))
	}
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return h[:]
}

// looksClamped returns true if the first 32 bytes of body match the bit
// pattern of a clamped ed25519 scalar (bottom 3 bits clear, top bit clear,
// second-from-top bit set).
func looksClamped(body []byte) bool {
	if len(body) < expandedSecretLen {
		return false
	}
	return body[0]&0x07 == 0 && body[31]&0xC0 == 0x40
}
