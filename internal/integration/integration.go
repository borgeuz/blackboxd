// Package integration hosts end-to-end tests that wire every layer of
// the daemon together (sources → ring → batcher → publisher → spool).
// Concurrency, timing and failure-recovery paths that per-package
// tests can't reach in isolation live here.
package integration
