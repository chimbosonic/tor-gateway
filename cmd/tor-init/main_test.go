package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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

	if err := run(context.Background(), src, dst, "", "", ""); err != nil {
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

func TestApiFetchSecret_WritesKeyFilesAndHostname(t *testing.T) {
	dst := t.TempDir()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "blog-backend-2-keys", Namespace: "default"},
		Data: map[string][]byte{
			"hs_ed25519_secret_key": []byte("SECRET-KEY-BYTES"),
			"hs_ed25519_public_key": []byte("PUBLIC-KEY-BYTES"),
			"hostname":              []byte("aaaaaaaaaaaaaaaaaaaaaaaa.onion\n"),
		},
	}
	cs := fake.NewSimpleClientset(secret)
	if err := fetchSecretToDir(context.Background(), cs, "default", "blog-backend-2-keys", dst); err != nil {
		t.Fatalf("fetchSecretToDir: %v", err)
	}
	for _, name := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key", "hostname"} {
		b, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(b) == 0 {
			t.Fatalf("%s empty", name)
		}
	}
}

func TestApiFetchSecret_BadFlagFormat(t *testing.T) {
	dst := t.TempDir()
	cs := fake.NewSimpleClientset()
	err := fetchSecretToDir(context.Background(), cs, "", "name", dst)
	if err == nil {
		t.Fatal("expected error for empty namespace")
	}
	if !strings.Contains(err.Error(), "namespace and name must be non-empty") {
		t.Fatalf("expected guard error, got: %v", err)
	}
}

func TestApiFetchSecret_NotFound(t *testing.T) {
	dst := t.TempDir()
	cs := fake.NewSimpleClientset() // no Secrets
	err := fetchSecretToDir(context.Background(), cs, "default", "missing", dst)
	if err == nil {
		t.Fatal("expected not-found error")
	}
	if !apierrors.IsNotFound(err) && !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found, got: %v", err)
	}
}
