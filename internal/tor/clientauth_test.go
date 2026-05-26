/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package tor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validKey is a syntactically valid (but functionally meaningless) base32
// pubkey — 52 chars from the [A-Z2-7] alphabet.
const validKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// validKey2 — a distinct 52-char base32 string so we can assert per-client
// content separation.
const validKey2 = "N2NU7BSRL6YODZCYPN4CREB54TYLKGIE2KYOQWLFYC23ZJVCE5DQ"

func TestWriteAuthorizedClients_HappyPath(t *testing.T) {
	dir := t.TempDir()
	clients := map[string]string{
		"alice": validKey,
		"bob":   validKey2,
	}
	if err := WriteAuthorizedClients(dir, clients); err != nil {
		t.Fatal(err)
	}
	authDir := filepath.Join(dir, AuthorizedClientsSubdir)
	for label, want := range clients {
		path := filepath.Join(authDir, label+AuthFileSuffix)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		expected := "descriptor:x25519:" + want + "\n"
		if string(body) != expected {
			t.Fatalf("%s = %q, want %q", path, body, expected)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s perms = %o, want 0600", path, info.Mode().Perm())
		}
	}
	info, err := os.Stat(authDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != AuthorizedClientsDirMode {
		t.Fatalf("authorized_clients perms = %o, want %o",
			info.Mode().Perm(), AuthorizedClientsDirMode)
	}
}

func TestWriteAuthorizedClients_NormalizesLowercasePubkey(t *testing.T) {
	dir := t.TempDir()
	clients := map[string]string{"alice": strings.ToLower(validKey)}
	if err := WriteAuthorizedClients(dir, clients); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, AuthorizedClientsSubdir, "alice"+AuthFileSuffix))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), strings.ToLower(validKey)) {
		t.Fatalf("expected lowercase key preserved verbatim in file body; got %q", body)
	}
}

func TestWriteAuthorizedClients_SkipsInvalidEntries(t *testing.T) {
	dir := t.TempDir()
	clients := map[string]string{
		"alice":        validKey,
		"Bob":          validKey2,  // capital -> bad label
		"carol/../etc": validKey2,  // traversal -> bad label
		"dave":         "shortkey", // bad pubkey
		"eve":          "",         // empty
	}
	err := WriteAuthorizedClients(dir, clients)
	if err == nil {
		t.Fatal("expected aggregate error for invalid entries")
	}
	for _, want := range []string{"Bob", "carol/../etc", "dave", "eve"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing offender %q", err, want)
		}
	}
	// Valid entries should still be written.
	if _, statErr := os.Stat(filepath.Join(dir, AuthorizedClientsSubdir, "alice.auth")); statErr != nil {
		t.Fatalf("alice should have been written despite siblings being rejected: %v", statErr)
	}
	for _, bad := range []string{"Bob.auth", "carol.auth", "dave.auth", "eve.auth"} {
		if _, statErr := os.Stat(filepath.Join(dir, AuthorizedClientsSubdir, bad)); statErr == nil {
			t.Fatalf("rejected entry %q should not exist on disk", bad)
		}
	}
}

func TestWriteAuthorizedClients_NoEntries(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAuthorizedClients(dir, nil); err != nil {
		t.Fatal(err)
	}
	// The subdirectory should exist even with 0 entries so Tor's startup
	// permission check is happy.
	info, err := os.Stat(filepath.Join(dir, AuthorizedClientsSubdir))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("authorized_clients was created as a non-directory")
	}
}

func TestLoadAuthorizedClientsFromDir_HappyPathAndSkipDotDot(t *testing.T) {
	src := t.TempDir()
	mustWrite := func(name, body string) {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("alice", validKey)
	mustWrite("bob", validKey2+"\n") // trailing whitespace should be trimmed
	mustWrite("..data", "kubelet-internal")
	mustWrite("..2026_05", "another-kubelet-symlink")

	got, err := LoadAuthorizedClientsFromDir(src)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"alice": validKey,
		"bob":   validKey2,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d (got=%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestLoadAuthorizedClientsFromDir_MissingDir(t *testing.T) {
	if _, err := LoadAuthorizedClientsFromDir(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected error for missing dir")
	}
}
