/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package tor contains Tor-specific helpers used by the operator:
//
//   - torrc rendering from a typed config struct (no string-template
//     escapes leaking into user input).
//   - ed25519 hidden-service key generation and on-disk permission
//     verification (Tor refuses to start with loose permissions).
//   - mkp224o Job dispatch and result harvest for vanity-prefix
//     addresses.
//
// Nothing in this package talks to the Kubernetes API; it produces and
// consumes plain values, so it can be exhaustively unit-tested.
package tor
