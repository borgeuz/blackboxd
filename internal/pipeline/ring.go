// Package pipeline owns the in-memory ring buffer, batcher, JSONL+gzip
// serialiser and per-source rate limiter.
//
// The ring is bounded by both entry count and approximate byte size;
// overflow drops the OLDEST entries (an active incident's recent logs
// are more valuable than its early ones). Drop counts are tracked.
package pipeline

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// RingBuffer is a bounded FIFO with drop-oldest semantics. Multi-
// producer / single-consumer. A single mutex is enough at the spec's
// throughput target (tens of thousands of lines/sec).
//
// Notification model: a sync.Cond can't be cancelled via context, so
// we expose a notify channel with capacity 1. Push fires it
// non-blockingly; multiple pushes between reads coalesce into one
// signal, and the consumer must drain in a loop.
type RingBuffer struct {
	mu    sync.Mutex
	buf   []*parser.LogEntry
	head  int
	size  int
	bytes int

	maxEntries int
	maxBytes   int
	closed     bool
	closedC    chan struct{}
	notify     chan struct{}

	drops atomic.Uint64
}

// NewRingBuffer constructs a ring with the given caps. maxBytes <= 0
// disables the byte cap; maxEntries falls back to 10 000 if not set.
func NewRingBuffer(maxEntries, maxBytes int) *RingBuffer {
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	return &RingBuffer{
		buf:        make([]*parser.LogEntry, maxEntries),
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		closedC:    make(chan struct{}),
		notify:     make(chan struct{}, 1),
	}
}

// Push enqueues e, evicting the oldest entries (and incrementing
// Drops) until either the entry-count or byte cap is satisfied.
// Returns false if the ring is closed; producers should stop.
func (r *RingBuffer) Push(e *parser.LogEntry) bool {
	if e == nil {
		return true
	}
	cost := approxBytes(e)
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return false
	}

	for r.size+1 > r.maxEntries || (r.maxBytes > 0 && r.bytes+cost > r.maxBytes && r.size > 0) {
		old := r.buf[r.head]
		r.buf[r.head] = nil
		r.head = (r.head + 1) % r.maxEntries
		r.size--
		r.bytes -= approxBytes(old)
		r.drops.Add(1)
	}

	tail := (r.head + r.size) % r.maxEntries
	r.buf[tail] = e
	r.size++
	r.bytes += cost
	select {
	case r.notify <- struct{}{}:
	default:
	}
	return true
}

// TryPop returns the oldest entry without blocking. drained is true
// when the ring is closed AND empty so the caller can exit its loop.
func (r *RingBuffer) TryPop() (entry *parser.LogEntry, drained bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == 0 {
		return nil, r.closed
	}
	e := r.buf[r.head]
	r.buf[r.head] = nil
	r.head = (r.head + 1) % r.maxEntries
	r.size--
	r.bytes -= approxBytes(e)
	return e, false
}

// PopWait blocks until an entry is available, ctx fires, or the ring
// is closed and drained.
func (r *RingBuffer) PopWait(ctx context.Context) *parser.LogEntry {
	for {
		if e, drained := r.TryPop(); e != nil {
			return e
		} else if drained {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-r.closedC:
			if e, _ := r.TryPop(); e != nil {
				return e
			}
			return nil
		case <-r.notify:
		}
	}
}

// PopBatch returns up to maxN entries without blocking past what's
// immediately available.
func (r *RingBuffer) PopBatch(maxN int) []*parser.LogEntry {
	if maxN <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*parser.LogEntry, 0, maxN)
	for len(out) < maxN && r.size > 0 {
		e := r.buf[r.head]
		r.buf[r.head] = nil
		r.head = (r.head + 1) % r.maxEntries
		r.size--
		r.bytes -= approxBytes(e)
		out = append(out, e)
	}
	return out
}

// Close marks the ring closed. Buffered entries remain readable via
// TryPop / PopWait until drained.
func (r *RingBuffer) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.closedC)
	r.mu.Unlock()
}

// Len is a snapshot; may race with concurrent Push.
func (r *RingBuffer) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// Drops is the cumulative number of entries evicted for capacity.
func (r *RingBuffer) Drops() uint64 { return r.drops.Load() }

// Notify fires (non-blockingly) on every Push. Multiple pushes
// between reads coalesce; consumers must drain in a loop.
func (r *RingBuffer) Notify() <-chan struct{} { return r.notify }

// Closed closes when the ring is closed; usable in selects watching
// shutdown independently of context cancellation.
func (r *RingBuffer) Closed() <-chan struct{} { return r.closedC }

// approxBytes estimates an entry's footprint. Monotonicity matters
// more than precision — we just need a stable upper bound on memory.
func approxBytes(e *parser.LogEntry) int {
	if e == nil {
		return 0
	}
	n := 64 + len(e.Message) + len(e.Hostname) + len(e.Process) + len(e.Source)
	for k, v := range e.Fields {
		n += len(k) + len(v) + 8
	}
	return n
}
