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

	if err := run(src, dst, "", "", ""); err != nil {
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

func TestWriteObConfig(t *testing.T) {
	t.Run("appends .onion suffix", func(t *testing.T) {
		d := t.TempDir()
		if err := writeObConfig(d, "abcd"); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(d, "ob_config"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "MasterOnionAddress abcd.onion\n" {
			t.Errorf("unexpected content: %q", got)
		}
	})
	t.Run("preserves .onion suffix when present", func(t *testing.T) {
		d := t.TempDir()
		if err := writeObConfig(d, "abcd.onion"); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(filepath.Join(d, "ob_config"))
		if string(got) != "MasterOnionAddress abcd.onion\n" {
			t.Errorf("unexpected content: %q", got)
		}
	})
	t.Run("file permissions are 0400", func(t *testing.T) {
		d := t.TempDir()
		if err := writeObConfig(d, "abcd"); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(filepath.Join(d, "ob_config"))
		if mode := st.Mode().Perm(); mode != 0o400 {
			t.Errorf("want 0400, got %#o", mode)
		}
	})
}

func TestCopyPerPodKeys(t *testing.T) {
	base := t.TempDir()
	hsDir := t.TempDir()
	idxDir := filepath.Join(base, "2")
	if err := os.MkdirAll(idxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(idxDir, "hs_ed25519_secret_key"), []byte("S"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(idxDir, "hs_ed25519_public_key"), []byte("P"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyPerPodKeys(base, "blog-backend-2", hsDir); err != nil {
		t.Fatalf("copyPerPodKeys: %v", err)
	}
	for name, want := range map[string]string{"hs_ed25519_secret_key": "S", "hs_ed25519_public_key": "P"} {
		got, _ := os.ReadFile(filepath.Join(hsDir, name))
		if string(got) != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

func TestCopyPerPodKeysRejectsBadPodName(t *testing.T) {
	if err := copyPerPodKeys(t.TempDir(), "noDash", t.TempDir()); err == nil {
		t.Error("expected error on pod name with no trailing -N")
	}
}
