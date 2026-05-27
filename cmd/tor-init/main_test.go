package main

import (
	"os"
	"path/filepath"
	"testing"
)

// makeSecretMount builds a directory tree mimicking a Kubernetes Secret mount:
// a timestamped data dir, a `..data` symlink to it, and each key exposed as a
// top-level symlink into `..data` (exactly how the kubelet projects Secrets).
func makeSecretMount(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "..2026_05_27_00_00_00.000000")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(dataDir, filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	for name := range files {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRun_CopiesSecretMountSkippingDataSymlink(t *testing.T) {
	want := map[string]string{
		"hs_ed25519_secret_key": "secret-key-bytes",
		"hs_ed25519_public_key": "public-key-bytes",
		"hostname":              "abc.onion\n",
	}
	src := makeSecretMount(t, want)
	dst := filepath.Join(t.TempDir(), "hs")

	if err := run(src, dst, ""); err != nil {
		t.Fatalf("run() returned error: %v", err)
	}

	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("reading copied %s: %v", name, err)
		}
		if string(got) != content {
			t.Fatalf("%s = %q, want %q", name, got, content)
		}
	}
	// The Secret mount's internal ..data symlink must NOT be copied.
	if _, err := os.Lstat(filepath.Join(dst, "..data")); !os.IsNotExist(err) {
		t.Fatalf("..data should not be copied into the HiddenServiceDir (err=%v)", err)
	}
}
