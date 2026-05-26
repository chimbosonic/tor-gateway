/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package tor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HiddenServiceDir permission expectations enforced by Tor before it will
// start. The init container shipped by the operator MUST normalize these
// before handing control to the tor daemon.
const (
	HiddenServiceDirMode     fs.FileMode = 0o700
	SecretKeyMode            fs.FileMode = 0o600
	PublicKeyMaxMode         fs.FileMode = 0o644 // pub key + hostname may be world-readable
	AuthorizedClientsDirMode fs.FileMode = 0o700
)

// PermissionViolation is one offending path discovered by CheckPermissions.
type PermissionViolation struct {
	Path   string
	Got    fs.FileMode
	Want   fs.FileMode
	Reason string
}

// PermissionError aggregates all violations found in a single walk so the
// caller can fix them in one pass instead of error-by-error.
type PermissionError struct {
	Violations []PermissionViolation
}

func (e *PermissionError) Error() string {
	if e == nil || len(e.Violations) == 0 {
		return "tor: no permission violations"
	}
	parts := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		parts = append(parts, fmt.Sprintf("%s: got %o, want %o (%s)",
			v.Path, v.Got.Perm(), v.Want.Perm(), v.Reason))
	}
	return "tor: HiddenServiceDir permission violations: " + strings.Join(parts, "; ")
}

// CheckPermissions walks a HiddenServiceDir and verifies that every entry
// matches Tor's strict mode requirements. Returns nil if all entries are
// compliant; otherwise a *PermissionError listing every offender.
//
// The function does NOT mutate the filesystem; pair it with FixPermissions
// (the init-container path) to actually correct violations.
func CheckPermissions(hiddenServiceDir string) error {
	var violations []PermissionViolation

	root, err := os.Stat(hiddenServiceDir)
	if err != nil {
		return fmt.Errorf("tor: stat HiddenServiceDir: %w", err)
	}
	if !root.IsDir() {
		return fmt.Errorf("tor: %s is not a directory", hiddenServiceDir)
	}
	if root.Mode().Perm() != HiddenServiceDirMode {
		violations = append(violations, PermissionViolation{
			Path:   hiddenServiceDir,
			Got:    root.Mode(),
			Want:   HiddenServiceDirMode,
			Reason: "HiddenServiceDir must be 0700",
		})
	}

	err = filepath.WalkDir(hiddenServiceDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p == hiddenServiceDir {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir() && d.Name() == "authorized_clients":
			if info.Mode().Perm() != AuthorizedClientsDirMode {
				violations = append(violations, PermissionViolation{
					Path:   p,
					Got:    info.Mode(),
					Want:   AuthorizedClientsDirMode,
					Reason: "authorized_clients must be 0700",
				})
			}
		case !d.IsDir() && filepath.Base(p) == FileSecretKeyName:
			if info.Mode().Perm() != SecretKeyMode {
				violations = append(violations, PermissionViolation{
					Path:   p,
					Got:    info.Mode(),
					Want:   SecretKeyMode,
					Reason: "hs_ed25519_secret_key must be 0600",
				})
			}
		case !d.IsDir():
			// pub key, hostname, .auth files: cap at 0644.
			if info.Mode().Perm() & ^PublicKeyMaxMode != 0 {
				violations = append(violations, PermissionViolation{
					Path:   p,
					Got:    info.Mode(),
					Want:   PublicKeyMaxMode,
					Reason: "file mode must be at most 0644",
				})
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("tor: walk HiddenServiceDir: %w", err)
	}
	if len(violations) == 0 {
		return nil
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].Path < violations[j].Path })
	return &PermissionError{Violations: violations}
}

// IsPermissionError reports whether err (or any wrapped error) is a
// *PermissionError. Useful for fixing-then-retrying in the init container.
func IsPermissionError(err error) bool {
	var pe *PermissionError
	return errors.As(err, &pe)
}

// FixPermissions chmods every entry under hiddenServiceDir to match the
// expected modes. Used by the init container shipped with each Tor pod
// after mounting the key Secret.
func FixPermissions(hiddenServiceDir string) error {
	if err := os.Chmod(hiddenServiceDir, HiddenServiceDirMode); err != nil {
		return fmt.Errorf("tor: chmod HiddenServiceDir: %w", err)
	}
	return filepath.WalkDir(hiddenServiceDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p == hiddenServiceDir {
			return nil
		}
		switch {
		case d.IsDir() && d.Name() == "authorized_clients":
			return os.Chmod(p, AuthorizedClientsDirMode)
		case !d.IsDir() && filepath.Base(p) == FileSecretKeyName:
			return os.Chmod(p, SecretKeyMode)
		case !d.IsDir():
			info, err := d.Info()
			if err != nil {
				return err
			}
			if info.Mode().Perm() & ^PublicKeyMaxMode != 0 {
				return os.Chmod(p, info.Mode().Perm()&PublicKeyMaxMode)
			}
		}
		return nil
	})
}
