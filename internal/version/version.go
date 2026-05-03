// Package version exposes build-time identification.
// Values are stamped via -ldflags -X (see Makefile).
package version

var (
	Version   = "unknown" // semver string, e.g. "v0.1.0" or "v0.1.0-12-gabcdef"
	Commit    = "unknown" // short git SHA
	BuildDate = "unknown" // RFC 3339
)
