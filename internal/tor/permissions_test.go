/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package tor

import (
	"crypto/rand"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildHSD creates a HiddenServiceDir-shaped tree with the given modes,
// populated with real key files so the inspector sees realistic content.
func buildHSD(t *testing.T, hsdMode, secretMode, pubMode, hostMode fs.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	hsd := filepath.Join(dir, "hs")
	if err := os.Mkdir(hsd, 0o700); err != nil {
		t.Fatal(err)
	}

	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mustWrite := func(name string, data []byte, mode fs.FileMode) {
		p := filepath.Join(hsd, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		// WriteFile applies umask; chmod explicitly to set exact bits.
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(FileSecretKeyName, kp.SecretKeyFile(), secretMode)
	mustWrite(FilePublicKeyName, kp.PublicKeyFile(), pubMode)
	mustWrite(FileHostnameName, kp.Hostname(), hostMode)

	// Apply the requested dir mode last so child writes succeed first.
	if err := os.Chmod(hsd, hsdMode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Restore 0700 so t.TempDir() cleanup can recurse.
		_ = os.Chmod(hsd, 0o700)
	})
	return hsd
}

func TestCheckPermissions_HappyPath(t *testing.T) {
	hsd := buildHSD(t, 0o700, 0o600, 0o644, 0o644)
	if err := CheckPermissions(hsd); err != nil {
		t.Fatalf("CheckPermissions(clean): %v", err)
	}
}

func TestCheckPermissions_FlagsLooseDir(t *testing.T) {
	hsd := buildHSD(t, 0o755, 0o600, 0o644, 0o644)
	err := CheckPermissions(hsd)
	if err == nil {
		t.Fatal("expected violation for 0755 HSD")
	}
	if !IsPermissionError(err) {
		t.Fatalf("error is not *PermissionError: %T", err)
	}
	if !strings.Contains(err.Error(), "HiddenServiceDir must be 0700") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckPermissions_FlagsLooseSecret(t *testing.T) {
	hsd := buildHSD(t, 0o700, 0o644, 0o644, 0o644)
	err := CheckPermissions(hsd)
	if err == nil {
		t.Fatal("expected violation for 0644 secret key")
	}
	if !strings.Contains(err.Error(), "hs_ed25519_secret_key must be 0600") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckPermissions_FlagsWorldWriteableFile(t *testing.T) {
	hsd := buildHSD(t, 0o700, 0o600, 0o646, 0o644)
	err := CheckPermissions(hsd)
	if err == nil {
		t.Fatal("expected violation for world-writable pub key")
	}
	if !strings.Contains(err.Error(), "at most 0644") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckPermissions_MissingDir(t *testing.T) {
	if err := CheckPermissions(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected error for missing dir")
	}
}

func TestFixPermissions_NormalizesAll(t *testing.T) {
	// Start broken in every way.
	hsd := buildHSD(t, 0o755, 0o644, 0o646, 0o646)
	if err := FixPermissions(hsd); err != nil {
		t.Fatalf("FixPermissions: %v", err)
	}
	if err := CheckPermissions(hsd); err != nil {
		t.Fatalf("after fix, CheckPermissions: %v", err)
	}
}

func TestCheckPermissions_AuthorizedClientsDir(t *testing.T) {
	hsd := buildHSD(t, 0o700, 0o600, 0o644, 0o644)
	authDir := filepath.Join(hsd, "authorized_clients")
	if err := os.Mkdir(authDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := CheckPermissions(hsd)
	if err == nil {
		t.Fatal("expected violation for 0755 authorized_clients")
	}
	if !strings.Contains(err.Error(), "authorized_clients must be 0700") {
		t.Fatalf("unexpected error: %v", err)
	}
}
