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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Tor v3 client authorization on disk:
//
//   <HiddenServiceDir>/authorized_clients/<label>.auth
//
// Each file contains a single line:
//
//   descriptor:x25519:<base32-encoded x25519 public key>
//
// where the base32 string is the standard RFC 4648 alphabet (uppercase
// A-Z and 2-7), no padding, 52 characters long for a 32-byte key.

// AuthorizedClientsSubdir is the relative subdirectory inside a
// HiddenServiceDir that holds client-auth files.
const AuthorizedClientsSubdir = "authorized_clients"

// AuthFileSuffix is the filename suffix Tor expects on every client-auth
// entry.
const AuthFileSuffix = ".auth"

// clientLabelPattern restricts auth filenames to DNS-label-like strings so
// users cannot inject directory traversal via Secret keys.
var clientLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,62}[a-z0-9])?$`)

// pubkeyPattern matches a 52-character RFC 4648 base32-encoded x25519
// public key (the "after descriptor:x25519:" portion).
var pubkeyPattern = regexp.MustCompile(`^[A-Z2-7]{52}$`)

// WriteAuthorizedClients writes one <label>.auth file per entry of clients
// into outDir/authorized_clients/. outDir must already exist; the
// authorized_clients subdir is created if absent. Files are written with
// 0600 mode; the subdirectory with 0700.
//
// Returns an aggregate error listing every malformed entry. Invalid entries
// are SKIPPED rather than failing the whole write, so a single bad pubkey
// from one client does not lock the other clients out.
func WriteAuthorizedClients(outDir string, clients map[string]string) error {
	if outDir == "" {
		return errors.New("tor: WriteAuthorizedClients: outDir is required")
	}
	authDir := filepath.Join(outDir, AuthorizedClientsSubdir)
	if err := os.MkdirAll(authDir, AuthorizedClientsDirMode); err != nil {
		return fmt.Errorf("tor: create %s: %w", authDir, err)
	}
	// Tor reads files at startup; deterministic ordering helps reproducible
	// renders and keeps log messages readable.
	labels := make([]string, 0, len(clients))
	for l := range clients {
		labels = append(labels, l)
	}
	sort.Strings(labels)

	var rejected []string
	for _, label := range labels {
		raw := strings.TrimSpace(clients[label])
		if err := validateAuthEntry(label, raw); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", label, err))
			continue
		}
		content := []byte("descriptor:x25519:" + raw + "\n")
		path := filepath.Join(authDir, label+AuthFileSuffix)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return fmt.Errorf("tor: write %s: %w", path, err)
		}
	}
	if len(rejected) > 0 {
		return fmt.Errorf("tor: %d invalid client auth entries skipped: %s",
			len(rejected), strings.Join(rejected, "; "))
	}
	return nil
}

// LoadAuthorizedClientsFromDir reads a flat directory of files (typically a
// Kubernetes Secret volume) where each entry's name is a client label and
// its body is a base32 x25519 public key. The Secret-projection ".." files
// created by the kubelet are skipped.
func LoadAuthorizedClientsFromDir(srcDir string) (map[string]string, error) {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, fmt.Errorf("tor: read %s: %w", srcDir, err)
	}
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		// kubelet Secret-volume internal symlinks ("..data", "..2026_05_..").
		if strings.HasPrefix(name, "..") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if info.Mode().Type() != 0 && info.Mode().Type() != fs.ModeSymlink {
			// Skip non-regular entries (sockets, devices, sub-dirs).
			continue
		}
		body, err := os.ReadFile(filepath.Join(srcDir, name)) //nolint:gosec // srcDir is the well-known mount path supplied by the operator
		if err != nil {
			return nil, err
		}
		out[name] = strings.TrimSpace(string(body))
	}
	return out, nil
}

// validateAuthEntry returns an error if the label or pubkey is malformed.
// Empty pubkeys are rejected (clients with no key serve no purpose).
func validateAuthEntry(label, pubkey string) error {
	if !clientLabelPattern.MatchString(label) {
		return fmt.Errorf("invalid label %q (need DNS-label-like)", label)
	}
	// Pubkey is base32 uppercase no-pad; users sometimes paste in a
	// lowercased form, normalize before validating.
	upper := strings.ToUpper(pubkey)
	if !pubkeyPattern.MatchString(upper) {
		return fmt.Errorf("invalid x25519 pubkey (need 52-char RFC 4648 base32)")
	}
	return nil
}
