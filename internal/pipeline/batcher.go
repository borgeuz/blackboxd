package pipeline

import (
	"context"
	"log/slog"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// Flush is the callback invoked on every completed batch. Returning
// an error is logged but does not stop collection — a transient flush
// failure must not halt the daemon.
type Flush func(ctx context.Context, batch []*parser.LogEntry) error

type BatcherConfig struct {
	BatchSize     int
	BatchInterval time.Duration
	Flush         Flush
	Logger        *slog.Logger
}

// Batcher drains a RingBuffer and flushes batches when any of these
// fire first: BatchSize reached, BatchInterval elapsed, ctx cancelled,
// or ring closed.
type Batcher struct {
	ring *RingBuffer
	cfg  BatcherConfig
	log  *slog.Logger
}

func NewBatcher(ring *RingBuffer, cfg BatcherConfig) *Batcher {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchInterval <= 0 {
		cfg.BatchInterval = 5 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Batcher{ring: ring, cfg: cfg, log: cfg.Logger.With("component", "batcher")}
}

// Run blocks until ctx fires. The hot loop is a single select over
// four events so the interval timer is honoured regardless of how
// long any handler runs. A final flush on shutdown drains pending.
func (b *Batcher) Run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			b.log.Error("panic in batcher", "event_type", "security", "panic", r)
		}
	}()
	timer := time.NewTimer(b.cfg.BatchInterval)
	defer timer.Stop()

	pending := make([]*parser.LogEntry, 0, b.cfg.BatchSize)

	flush := func(reason string) {
		if len(pending) == 0 {
			return
		}
		batch := pending
		pending = make([]*parser.LogEntry, 0, b.cfg.BatchSize)

		fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if b.cfg.Flush == nil {
			b.log.Warn("no flush callback; dropping batch", "size", len(batch), "reason", reason)
			return
		}
		if err := b.cfg.Flush(fctx, batch); err != nil {
			b.log.Error("flush failed", "err", err, "size", len(batch))
		}
	}

	drain := func() {
		more := b.ring.PopBatch(b.cfg.BatchSize - len(pending))
		pending = append(pending, more...)
	}

	// Catch entries that landed before Run started.
	drain()
	if len(pending) >= b.cfg.BatchSize {
		flush("size")
		resetTimer(timer, b.cfg.BatchInterval)
	}

	for {
		select {
		case <-ctx.Done():
			drain()
			flush("ctx")
			return

		case <-b.ring.Closed():
			drain()
			flush("shutdown")
			return

		case <-timer.C:
			flush("interval")
			resetTimer(timer, b.cfg.BatchInterval)

		case <-b.ring.Notify():
			drain()
			if len(pending) >= b.cfg.BatchSize {
				flush("size")
				resetTimer(timer, b.cfg.BatchInterval)
			}
		}
	}
}

// resetTimer is the canonical drain-then-reset dance for time.Timer
// reuse — Go's stdlib does not provide a single SafeReset.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}
