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
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/chimbosonic/tor-gateway/internal/tor"
)

func main() {
	var (
		src           string
		dst           string
		clientAuthSrc string
	)
	flag.StringVar(&src, "src", "/etc/tor-keys", "directory containing the mounted key Secret")
	flag.StringVar(&dst, "dst", "/var/lib/tor/hs", "HiddenServiceDir to populate")
	flag.StringVar(&clientAuthSrc, "client-auth-src", "",
		"optional directory containing client-auth Secret entries; when set, "+
			"each non-dotfile entry is written as <label>.auth into "+
			"<dst>/authorized_clients/")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(src, dst, clientAuthSrc); err != nil {
		slog.Error("tor-init failed", "err", err)
		os.Exit(1)
	}
	slog.Info("tor-init ok", "src", src, "dst", dst, "client_auth", clientAuthSrc != "")
}

func run(src, dst, clientAuthSrc string) error {
	if err := os.MkdirAll(dst, tor.HiddenServiceDirMode); err != nil {
		return err
	}
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
	return tor.FixPermissions(dst)
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
