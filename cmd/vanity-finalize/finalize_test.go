package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadKeyFiles(t *testing.T) {
	workdir := t.TempDir()
	onionDir := filepath.Join(workdir, "abcde234.onion")
	if err := os.MkdirAll(onionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"hs_ed25519_secret_key": "secret-bytes",
		"hs_ed25519_public_key": "public-bytes",
		"hostname":              "abcde234.onion\n",
	}
	for name, body := range want {
		if err := os.WriteFile(filepath.Join(onionDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := readKeyFiles(workdir)
	if err != nil {
		t.Fatalf("readKeyFiles: %v", err)
	}
	for name, body := range want {
		if string(got[name]) != body {
			t.Errorf("%s = %q, want %q", name, got[name], body)
		}
	}
}

func TestReadKeyFilesNoOnionDir(t *testing.T) {
	if _, err := readKeyFiles(t.TempDir()); err == nil {
		t.Fatal("expected error when no .onion subdir exists")
	}
}
