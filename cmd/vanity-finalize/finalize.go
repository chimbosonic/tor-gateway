/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// keyFiles are the hidden-service files mkp224o writes that we copy into the
// output Secret.
var keyFiles = []string{
	"hs_ed25519_secret_key",
	"hs_ed25519_public_key",
	"hostname",
}

// onionSubdir returns the single "<onion>.onion" directory mkp224o created
// under workdir (it writes each match into its own subdirectory).
func onionSubdir(workdir string) (string, error) {
	entries, err := os.ReadDir(workdir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".onion") {
			return filepath.Join(workdir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("vanity-finalize: no .onion subdirectory in %s", workdir)
}

// readKeyFiles reads the three hidden-service key files from mkp224o's output
// subdirectory under workdir.
func readKeyFiles(workdir string) (map[string][]byte, error) {
	dir, err := onionSubdir(workdir)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(keyFiles))
	for _, f := range keyFiles {
		// #nosec G304 -- dir is an .onion subdirectory of our own mkp224o workdir and f is from a fixed list
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, fmt.Errorf("vanity-finalize: read %s: %w", f, err)
		}
		out[f] = b
	}
	return out, nil
}
