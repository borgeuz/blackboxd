package transport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubPub is a Publisher that records every payload and can be flipped
// between healthy / unhealthy at any time.
type stubPub struct {
	mu      sync.Mutex
	healthy atomic.Bool
	calls   [][]byte
}

func newStubPub(healthy bool) *stubPub {
	p := &stubPub{}
	p.healthy.Store(healthy)
	return p
}

func (s *stubPub) Publish(_ context.Context, _ string, payload []byte, _ byte, _ bool) error {
	if !s.healthy.Load() {
		return errors.New("stub: unhealthy")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := append([]byte(nil), payload...)
	s.calls = append(s.calls, cp)
	return nil
}

func (s *stubPub) Close(_ context.Context) error { return nil }

func (s *stubPub) snapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.calls))
	for i, p := range s.calls {
		out[i] = append([]byte(nil), p...)
	}
	return out
}

func TestSpool_AppendListRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sp, err := NewSpool(dir, 1024*1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{[]byte("a"), []byte("bb"), []byte("ccc")} {
		if err := sp.Append(body); err != nil {
			t.Fatal(err)
		}
		// Tiny wait so timestamp prefixes differ on fast machines.
		time.Sleep(2 * time.Millisecond)
	}

	files, err := sp.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d files, want 3", len(files))
	}
	// Verify chronological order corresponds to insertion order.
	for i, want := range []string{"a", "bb", "ccc"} {
		body, err := sp.Read(files[i])
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != want {
			t.Errorf("file[%d] = %q, want %q", i, body, want)
		}
	}
}

func TestSpool_Mode0600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sp, _ := NewSpool(dir, 1<<20, nil)
	if err := sp.Append([]byte("x")); err != nil {
		t.Fatal(err)
	}
	files, _ := sp.List()
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestSpool_FIFOEviction(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Cap at 4 bytes; each entry is 2 bytes, so 3 entries → 1 must be evicted.
	sp, _ := NewSpool(dir, 4, nil)
	if err := sp.Append([]byte("aa")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := sp.Append([]byte("bb")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := sp.Append([]byte("cc")); err != nil {
		t.Fatal(err)
	}
	if sp.Drops() == 0 {
		t.Errorf("expected at least one eviction")
	}

	files, _ := sp.List()
	// Survivors should be the youngest two ("bb", "cc") because FIFO
	// evicts oldest.
	gotBodies := make([]string, 0, len(files))
	for _, p := range files {
		b, _ := sp.Read(p)
		gotBodies = append(gotBodies, string(b))
	}
	if len(gotBodies) == 0 || gotBodies[len(gotBodies)-1] != "cc" {
		t.Errorf("youngest survivor = %v", gotBodies)
	}
}

func TestSpooledPublisher_FallbackOnFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sp, _ := NewSpool(dir, 1<<20, nil)
	upstream := newStubPub(false)

	pub := NewSpooledPublisher(SpooledPublisherConfig{
		Upstream:  upstream,
		Spool:     sp,
		LogsTopic: "test/logs",
		QoS:       1,
	})
	if err := pub.Publish(context.Background(), "test/logs", []byte("payload-1"), 1, false); err != nil {
		t.Fatal(err)
	}
	files, _ := sp.List()
	if len(files) != 1 {
		t.Fatalf("expected 1 spooled file, got %d", len(files))
	}
}

func TestSpooledPublisher_ReplayWhenHealthy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sp, _ := NewSpool(dir, 1<<20, nil)
	upstream := newStubPub(false)

	pub := NewSpooledPublisher(SpooledPublisherConfig{
		Upstream:  upstream,
		Spool:     sp,
		LogsTopic: "test/logs",
		QoS:       1,
	})

	// Spool 3 payloads.
	for i, body := range []string{"one", "two", "three"} {
		if err := pub.Publish(context.Background(), "test/logs", []byte(body), 1, false); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Become healthy and run the replay loop.
	upstream.healthy.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go pub.Run(ctx)

	// Wait until either everything is replayed or the context fires.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		files, _ := sp.List()
		if len(files) == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	files, _ := sp.List()
	if len(files) != 0 {
		t.Errorf("spool not drained: %d files left", len(files))
	}
	if got := len(upstream.snapshot()); got != 3 {
		t.Errorf("upstream got %d publishes, want 3", got)
	}
}

func TestSpooledPublisher_NoSpoolConfigured(t *testing.T) {
	t.Parallel()
	upstream := newStubPub(false)
	pub := NewSpooledPublisher(SpooledPublisherConfig{
		Upstream:  upstream,
		LogsTopic: "test/logs",
	})
	err := pub.Publish(context.Background(), "test/logs", []byte("x"), 1, false)
	if err == nil {
		t.Fatalf("expected error when no spool and upstream fails")
	}
}

func TestSpool_DirIs0700(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool-fresh")
	if _, err := NewSpool(dir, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 0700", info.Mode().Perm())
	}
}
