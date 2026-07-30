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

// podOrdinal extracts the trailing -N suffix from a StatefulSet pod name.
// Returns an error if no trailing -N is present or if the ordinal is empty.
func podOrdinal(podName string) (string, error) {
	dash := strings.LastIndexByte(podName, '-')
	if dash < 0 || dash == len(podName)-1 {
		return "", fmt.Errorf("POD_NAME %q has no trailing -N", podName)
	}
	return podName[dash+1:], nil
}

// fetchSecretToDir GETs the named Secret and writes each of its data
// entries as a file under dst, preserving the entry names verbatim.
func fetchSecretToDir(ctx context.Context, cs kubernetes.Interface, namespace, name, dst string) error {
	if namespace == "" || name == "" {
		return fmt.Errorf("namespace and name must be non-empty, got %q/%q", namespace, name)
	}
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
		src                  string
		dst                  string
		clientAuthSrc        string
		obMasterAddress      string
		apiFetchSecret       string
		apiFetchSecretPrefix string
	)
	flag.StringVar(&src, "src", "/etc/tor-keys", "directory containing the mounted key Secret")
	flag.StringVar(&dst, "dst", "/var/lib/tor/hs", "HiddenServiceDir to populate")
	flag.StringVar(&clientAuthSrc, "client-auth-src", "",
		"optional directory containing client-auth Secret entries; when set, "+
			"each non-dotfile entry is written as <label>.auth into "+
			"<dst>/authorized_clients/")
	flag.StringVar(&obMasterAddress, "ob-master-address", "",
		"if set, write <HSDir>/ob_config containing MasterOnionAddress <value>.onion (HA backend mode)")
	flag.StringVar(&apiFetchSecret, "api-fetch-secret", "",
		"if set (NAMESPACE/NAME), fetch the named Secret via the in-cluster API and "+
			"write its data entries into <dst>")
	flag.StringVar(&apiFetchSecretPrefix, "api-fetch-secret-prefix", "",
		"if set, fetch <prefix><POD_ORDINAL>-keys from POD_NAMESPACE via the in-cluster API")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(
		context.Background(), src, dst, clientAuthSrc,
		obMasterAddress, apiFetchSecret, apiFetchSecretPrefix,
	); err != nil {
		slog.Error("tor-init failed", "err", err)
		os.Exit(1)
	}
	slog.Info("tor-init ok", "src", src, "dst", dst,
		"client_auth", clientAuthSrc != "",
		"ob_master", obMasterAddress != "")
}

func run(
	ctx context.Context,
	src, dst, clientAuthSrc, obMasterAddress, apiFetchSecret, apiFetchSecretPrefix string,
) error {
	if err := os.MkdirAll(dst, tor.HiddenServiceDirMode); err != nil {
		return err
	}

	if apiFetchSecret != "" {
		if err := runAPIFetch(ctx, apiFetchSecret, dst); err != nil {
			return err
		}
	}

	if apiFetchSecretPrefix != "" {
		if err := runAPIFetchPrefix(ctx, apiFetchSecretPrefix, dst); err != nil {
			return err
		}
	}

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

	// FixPermissions enforces tor's strict 0700 HiddenServiceDir requirement.
	// Only invoke it when this run is populating a tor HS dir — not for
	// pure --api-fetch-secret (master-fetch into onionbalance's keys
	// emptyDir, where the mount root is owned by root and a non-root init
	// container cannot chmod it).
	torHSDirMode := src != "" || apiFetchSecretPrefix != "" || obMasterAddress != "" || clientAuthSrc != ""
	if torHSDirMode {
		if err := tor.FixPermissions(dst); err != nil {
			return err
		}
	}

	if obMasterAddress != "" {
		if err := writeObConfig(dst, obMasterAddress); err != nil {
			return fmt.Errorf("ob_config: %w", err)
		}
		slog.Info("tor-init: ob_config written", "master", obMasterAddress)
	}

	return nil
}

func runAPIFetch(ctx context.Context, apiFetchSecret, dst string) error {
	parts := strings.SplitN(apiFetchSecret, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("--api-fetch-secret expects NAMESPACE/NAME, got %q", apiFetchSecret)
	}
	if err := apiFetchSecretToDir(ctx, parts[0], parts[1], dst); err != nil {
		return fmt.Errorf("api-fetch: %w", err)
	}
	slog.Info("tor-init: api-fetched secret", "ref", apiFetchSecret)
	return nil
}

func runAPIFetchPrefix(ctx context.Context, prefix, dst string) error {
	podName := os.Getenv("POD_NAME")
	podNamespace := os.Getenv("POD_NAMESPACE")
	if podName == "" || podNamespace == "" {
		return fmt.Errorf("--api-fetch-secret-prefix requires POD_NAME and POD_NAMESPACE env vars")
	}
	ord, err := podOrdinal(podName)
	if err != nil {
		return err
	}
	name := prefix + ord + "-keys"
	if err := apiFetchSecretToDir(ctx, podNamespace, name, dst); err != nil {
		return fmt.Errorf("api-fetch-prefix: %w", err)
	}
	slog.Info("tor-init: api-fetched per-pod secret", "name", name)
	return nil
}

func apiFetchSecretToDir(ctx context.Context, namespace, name, dst string) error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}
	return fetchSecretToDir(ctx, cs, namespace, name, dst)
}

func writeObConfig(hsDir, addr string) error {
	addr = strings.TrimSpace(addr)
	if !strings.HasSuffix(addr, ".onion") {
		addr += ".onion"
	}
	obConfigPath := filepath.Join(hsDir, "ob_config")
	return os.WriteFile(obConfigPath, []byte("MasterOnionAddress "+addr+"\n"), 0o400)
}

func copyFile(srcPath, dstPath string) error {
	// #nosec G304 -- source path is the well-known Secret mount controlled by the operator
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	// #nosec G304 -- destination is the HiddenServiceDir emptyDir owned by this pod
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
