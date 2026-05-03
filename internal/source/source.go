// Package source implements log input adapters: file tailing with
// offset persistence and rotation detection, /dev/kmsg, and a
// systemd-journal subprocess wrapper.
//
// Each Source runs in its own goroutine and emits entries via the Emit
// callback. Sources never panic; recoverable errors are logged
// internally, fatal errors are wrapped in ErrFatal so the supervisor
// can decide not to restart them.
package source

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

type Source interface {
	Name() string
	Run(ctx context.Context, emit Emit) error
}

// Emit must be cheap and non-blocking in steady state. Back-pressure
// handling lives in the caller-provided closure (see MakeBoundedEmit).
type Emit func(*parser.LogEntry)

// MakeBoundedEmit wraps a sink channel in the spec's drop-with-counter
// contract: try once, then wait up to blockBudget, then drop and bump
// the counter.
func MakeBoundedEmit(sink chan<- *parser.LogEntry, blockBudget time.Duration, drops *atomic.Uint64) Emit {
	return func(e *parser.LogEntry) {
		if e == nil {
			return
		}
		select {
		case sink <- e:
			return
		default:
		}
		t := time.NewTimer(blockBudget)
		defer t.Stop()
		select {
		case sink <- e:
		case <-t.C:
			drops.Add(1)
		}
	}
}

// ErrFatal signals an unrecoverable condition. The supervisor must
// not restart a source that returns it.
var ErrFatal = errors.New("source: fatal")
