// Package security holds the daemon's hardening primitives: path
// allowlist, file mode/ownership checks, TLS config builder, and
// SHA-256 cert pinning. Stdlib only.
package security

import "errors"

// ErrInsecure wraps every security precondition failure. Any wrapping
// of this error must be treated as fatal — never fall back.
var ErrInsecure = errors.New("security precondition failed")
