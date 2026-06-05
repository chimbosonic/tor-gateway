/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Command tor-init is the init container that runs before tor in each
// per-Gateway pod. It copies the hidden-service key files from the
// read-only Secret mount into the writable HiddenServiceDir emptyDir,
// then applies the strict permissions tor requires before it will start.
//
// Keeping this in a dedicated binary (rather than a shell snippet) means
//   - distroless: no shell needed in the init image,
//   - the permission policy is enforced by the same code as the operator's
//     unit tests (internal/tor.FixPermissions), and
//   - the binary can be exhaustively tested without a Tor daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/chimbosonic/tor-gateway/internal/tor"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// fetchSecretToDir GETs the named Secret and writes each of its data
// entries as a file under dst, preserving the entry names verbatim.
func fetchSecretToDir(ctx context.Context, cs kubernetes.Interface, namespace, name, dst string) error {
	s, err := cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get secret %s/%s: %w", namespace, name, err)
	}
	if err := os.MkdirAll(dst, tor.HiddenServiceDirMode); err != nil {
		return err
	}
	for k, v := range s.Data {
		if err := os.WriteFile(filepath.Join(dst, k), v, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", k, err)
		}
	}
	return nil
}

func main() {
	var (
		src             string
		dst             string
		clientAuthSrc   string
		obMasterAddress string
		perPodKeysBase  string
		apiFetchSecret  string
	)
	flag.StringVar(&src, "src", "/etc/tor-keys", "directory containing the mounted key Secret")
	flag.StringVar(&dst, "dst", "/var/lib/tor/hs", "HiddenServiceDir to populate")
	flag.StringVar(&clientAuthSrc, "client-auth-src", "",
		"optional directory containing client-auth Secret entries; when set, "+
			"each non-dotfile entry is written as <label>.auth into "+
			"<dst>/authorized_clients/")
	flag.StringVar(&obMasterAddress, "ob-master-address", "",
		"if set, write <HSDir>/ob_config containing MasterOnionAddress <value>.onion (HA backend mode)")
	flag.StringVar(&perPodKeysBase, "per-pod-keys-base", "",
		"if set, copy hs_ed25519_*_key from <base>/<index>/ into HSDir; "+
			"<index> is the trailing -N of $POD_NAME (HA backend mode)")
	flag.StringVar(&apiFetchSecret, "api-fetch-secret", "",
		"if set (NAMESPACE/NAME), fetch the named Secret via the in-cluster API and "+
			"write its data entries into <dst>")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(context.Background(), src, dst, clientAuthSrc, perPodKeysBase, obMasterAddress, apiFetchSecret); err != nil {
		slog.Error("tor-init failed", "err", err)
		os.Exit(1)
	}
	slog.Info("tor-init ok", "src", src, "dst", dst,
		"client_auth", clientAuthSrc != "",
		"per_pod_keys", perPodKeysBase != "",
		"ob_master", obMasterAddress != "")
}

func run(ctx context.Context, src, dst, clientAuthSrc, perPodKeysBase, obMasterAddress, apiFetchSecret string) error {
	if err := os.MkdirAll(dst, tor.HiddenServiceDirMode); err != nil {
		return err
	}

	if apiFetchSecret != "" {
		parts := strings.SplitN(apiFetchSecret, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("--api-fetch-secret expects NAMESPACE/NAME, got %q", apiFetchSecret)
		}
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("in-cluster config: %w", err)
		}
		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return fmt.Errorf("kubernetes client: %w", err)
		}
		if err := fetchSecretToDir(ctx, cs, parts[0], parts[1], dst); err != nil {
			return fmt.Errorf("api-fetch: %w", err)
		}
		slog.Info("tor-init: api-fetched secret", "ref", apiFetchSecret)
	}

	if perPodKeysBase != "" {
		podName := os.Getenv("POD_NAME")
		if podName == "" {
			return fmt.Errorf("--per-pod-keys-base requires POD_NAME env var")
		}
		if err := copyPerPodKeys(perPodKeysBase, podName, dst); err != nil {
			return fmt.Errorf("per-pod-keys: %w", err)
		}
		slog.Info("tor-init: per-pod keys copied", "pod", podName, "base", perPodKeysBase)
	}

	// HA backends pass --src="" because --per-pod-keys-base supplies the
	// keys; in that case there's no Mode A key-Secret to walk.
	if src != "" {
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			srcPath := filepath.Join(src, entry.Name())
			// Secret/ConfigMap mounts expose a `..data` symlink to a timestamped
			// dir plus the timestamped dir itself; os.Stat follows symlinks, so
			// non-regular entries (those dirs) are skipped and only the projected
			// key files are copied.
			info, err := os.Stat(srcPath)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if err := copyFile(srcPath, filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
		}
	}

	// Optionally lay down client-auth files. Skipped silently when
	// clientAuthSrc is empty so the same init image works for both
	// standalone-public and client-auth-protected Gateways.
	if clientAuthSrc != "" {
		clients, err := tor.LoadAuthorizedClientsFromDir(clientAuthSrc)
		if err != nil {
			return err
		}
		if err := tor.WriteAuthorizedClients(dst, clients); err != nil {
			// WriteAuthorizedClients returns an aggregate error for
			// invalid entries but still writes the valid ones. Log and
			// continue so Tor starts with the partial set rather than
			// locking everyone out.
			slog.Warn("tor-init: some client-auth entries skipped", "err", err)
		}
	}

	if err := tor.FixPermissions(dst); err != nil {
		return err
	}

	if obMasterAddress != "" {
		if err := writeObConfig(dst, obMasterAddress); err != nil {
			return fmt.Errorf("ob_config: %w", err)
		}
		slog.Info("tor-init: ob_config written", "master", obMasterAddress)
	}

	return nil
}

func writeObConfig(hsDir, addr string) error {
	addr = strings.TrimSpace(addr)
	if !strings.HasSuffix(addr, ".onion") {
		addr += ".onion"
	}
	obConfigPath := filepath.Join(hsDir, "ob_config")
	return os.WriteFile(obConfigPath, []byte("MasterOnionAddress "+addr+"\n"), 0o400)
}

func copyPerPodKeys(base, podName, hsDir string) error {
	dash := strings.LastIndexByte(podName, '-')
	if dash < 0 {
		return fmt.Errorf("POD_NAME %q has no trailing -N", podName)
	}
	idx := podName[dash+1:]
	src := filepath.Join(base, idx)
	for _, name := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key"} {
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(hsDir, name), data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func copyFile(srcPath, dstPath string) error {
	in, err := os.Open(srcPath) //nolint:gosec // source path is the well-known Secret mount controlled by the operator
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
