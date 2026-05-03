package pipeline

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

func makeEntry(msg string) *parser.LogEntry {
	return &parser.LogEntry{
		Timestamp: time.Now(),
		Level:     parser.LevelInfo,
		Message:   msg,
		Source:    "test",
	}
}

func TestRingBuffer_FIFO(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(4, 0)
	for _, m := range []string{"a", "b", "c", "d"} {
		r.Push(makeEntry(m))
	}
	if r.Len() != 4 {
		t.Fatalf("Len = %d, want 4", r.Len())
	}
	if r.Drops() != 0 {
		t.Fatalf("Drops = %d", r.Drops())
	}
	for _, want := range []string{"a", "b", "c", "d"} {
		got, _ := r.TryPop()
		if got == nil {
			t.Fatalf("TryPop returned nil; want %q", want)
		}
		if got.Message != want {
			t.Errorf("TryPop = %q, want %q", got.Message, want)
		}
	}
}

func TestRingBuffer_DropsOldest(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(2, 0)
	r.Push(makeEntry("a"))
	r.Push(makeEntry("b"))
	r.Push(makeEntry("c"))
	r.Push(makeEntry("d"))

	if r.Drops() != 2 {
		t.Errorf("drops = %d, want 2", r.Drops())
	}
	if r.Len() != 2 {
		t.Fatalf("len = %d", r.Len())
	}
	first, _ := r.TryPop()
	second, _ := r.TryPop()
	if first.Message != "c" {
		t.Errorf("oldest survivor = %q, want c", first.Message)
	}
	if second.Message != "d" {
		t.Errorf("youngest survivor = %q, want d", second.Message)
	}
}

func TestRingBuffer_ByteCap(t *testing.T) {
	t.Parallel()
	// 64 bytes overhead + msg length is the approxBytes formula.
	// With maxBytes=200 we should hold ~2 small entries.
	r := NewRingBuffer(100, 200)
	r.Push(makeEntry("aaaa"))
	r.Push(makeEntry("bbbb"))
	r.Push(makeEntry("cccc"))
	if r.Drops() == 0 {
		t.Errorf("expected at least one drop under byte cap")
	}
}

func TestRingBuffer_CloseUnblocksConsumer(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(4, 0)
	done := make(chan struct{})
	go func() {
		got := r.PopWait(context.Background())
		if got != nil {
			t.Errorf("expected nil after close, got %+v", got)
		}
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	r.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PopWait did not unblock on Close")
	}
}

func TestRingBuffer_PopWaitContextCancel(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(4, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got := r.PopWait(ctx)
	if got != nil {
		t.Fatalf("got %+v, want nil from cancellation", got)
	}
}

func TestRingBuffer_PopBatch(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(8, 0)
	for _, m := range []string{"a", "b", "c", "d", "e"} {
		r.Push(makeEntry(m))
	}
	got := r.PopBatch(3)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i].Message != want {
			t.Errorf("[%d] = %q, want %q", i, got[i].Message, want)
		}
	}
	if r.Len() != 2 {
		t.Errorf("len after = %d, want 2", r.Len())
	}
}

func TestBatcher_FlushBySize(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(100, 0)

	var batches int32
	var got []*parser.LogEntry
	var mu sync.Mutex

	b := NewBatcher(r, BatcherConfig{
		BatchSize:     5,
		BatchInterval: time.Hour, // make sure we flush by size
		Flush: func(_ context.Context, batch []*parser.LogEntry) error {
			atomic.AddInt32(&batches, 1)
			mu.Lock()
			got = append(got, batch...)
			mu.Unlock()
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()

	for i := 0; i < 10; i++ {
		r.Push(makeEntry(string(rune('a' + i))))
	}

	// Wait for both batches.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&batches) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	r.Close()
	<-done

	if atomic.LoadInt32(&batches) < 2 {
		t.Fatalf("got %d batches, want >=2", atomic.LoadInt32(&batches))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 10 {
		t.Errorf("total entries flushed = %d, want 10", len(got))
	}
}

func TestBatcher_FlushByInterval(t *testing.T) {
	t.Parallel()
	r := NewRingBuffer(100, 0)

	flushed := make(chan int, 1)
	b := NewBatcher(r, BatcherConfig{
		BatchSize:     1000, // never reached
		BatchInterval: 100 * time.Millisecond,
		Flush: func(_ context.Context, batch []*parser.LogEntry) error {
			flushed <- len(batch)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	r.Push(makeEntry("x"))
	r.Push(makeEntry("y"))
	r.Push(makeEntry("z"))

	select {
	case n := <-flushed:
		if n < 1 {
			t.Errorf("flushed empty batch")
		}
	case <-time.After(time.Second):
		t.Fatal("interval flush did not fire")
	}
}

func TestRateLimiter_AllowsUpToRate(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(10, 10)
	now := time.Unix(0, 0)
	allowed := 0
	for i := 0; i < 20; i++ {
		if rl.Allow("src", now) {
			allowed++
		}
	}
	if allowed != 10 {
		t.Errorf("allowed = %d in burst window, want 10", allowed)
	}

	// Advance one second; should refill 10 tokens.
	now = now.Add(time.Second)
	allowed = 0
	for i := 0; i < 20; i++ {
		if rl.Allow("src", now) {
			allowed++
		}
	}
	if allowed != 10 {
		t.Errorf("allowed after refill = %d, want 10", allowed)
	}
}

func TestRateLimiter_PerSourceIndependence(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(5, 5)
	now := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		if !rl.Allow("a", now) {
			t.Fatalf("a should still have tokens at i=%d", i)
		}
	}
	if rl.Allow("a", now) {
		t.Fatal("a should be exhausted")
	}
	if !rl.Allow("b", now) {
		t.Fatal("b should be unaffected")
	}
}

func TestSerialize_RoundTrip(t *testing.T) {
	t.Parallel()
	in := []*parser.LogEntry{
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), Level: parser.LevelInfo, Message: "a", Source: "s"},
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 1, 0, time.UTC), Level: parser.LevelError, Message: "b", Source: "s"},
	}
	payload, err := SerializeBatchJSONLGzip(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeBatchJSONLGzip(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("decoded %d, want 2", len(out))
	}
	if out[0].Message != "a" || out[1].Message != "b" {
		t.Errorf("messages = %q,%q", out[0].Message, out[1].Message)
	}
	if out[0].Level != parser.LevelInfo || out[1].Level != parser.LevelError {
		t.Errorf("levels = %s,%s", out[0].Level, out[1].Level)
	}
}
