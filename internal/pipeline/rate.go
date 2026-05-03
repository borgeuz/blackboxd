package pipeline

import (
	"sync"
	"time"
)

// RateLimiter is a per-source token bucket: each source name gets its
// own bucket so a chatty source can't starve the quiet ones.
//
// Inline implementation rather than golang.org/x/time/rate — keeps the
// dependency surface minimal and the daemon's expected rates are well
// below any regime where the difference matters.
type RateLimiter struct {
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter configures the per-source rate. burst <= 0 defaults
// to one second of tokens (i.e. burst == rate).
func NewRateLimiter(linesPerSec int, burst int) *RateLimiter {
	if linesPerSec <= 0 {
		linesPerSec = 10_000
	}
	if burst <= 0 {
		burst = linesPerSec
	}
	return &RateLimiter{
		rate:    float64(linesPerSec),
		burst:   float64(burst),
		buckets: map[string]*bucket{},
	}
}

// Allow consumes one token if available. Non-blocking by design: a
// rate-limited line must be dropped immediately so the source loop
// stays free.
func (r *RateLimiter) Allow(source string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[source]
	if !ok {
		b = &bucket{tokens: r.burst, last: now}
		r.buckets[source] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * r.rate
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
