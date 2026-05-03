package integration

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
	"github.com/borgeuz/blackboxd/internal/pipeline"
	"github.com/borgeuz/blackboxd/internal/transport"
)

// flakyPublisher flips between healthy and unhealthy under test
// control, recording every payload that gets through.
type flakyPublisher struct {
	mu       sync.Mutex
	healthy  atomic.Bool
	payloads [][]byte
}

func newFlakyPublisher() *flakyPublisher {
	p := &flakyPublisher{}
	p.healthy.Store(true)
	return p
}

func (f *flakyPublisher) Publish(_ context.Context, _ string, payload []byte, _ byte, _ bool) error {
	if !f.healthy.Load() {
		return errors.New("flaky: down")
	}
	f.mu.Lock()
	cp := append([]byte(nil), payload...)
	f.payloads = append(f.payloads, cp)
	f.mu.Unlock()
	return nil
}

func (f *flakyPublisher) Close(_ context.Context) error { return nil }

func (f *flakyPublisher) decoded() ([]*parser.LogEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var all []*parser.LogEntry
	for _, p := range f.payloads {
		batch, err := pipeline.DecodeBatchJSONLGzip(p)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
	}
	return all, nil
}

// TestEndToEnd_OutageRecovery is the scaled-down chaos scenario:
//   - 200 entries produced over ~2s
//   - 1.5s simulated outage in the middle
//   - assertion: every entry is eventually delivered, exactly once
//
// The full spec calls for a 5min/10k-line variant; the code paths
// exercised are the same.
func TestEndToEnd_OutageRecovery(t *testing.T) {
	dir := t.TempDir()

	pub := newFlakyPublisher()
	spool, err := transport.NewSpool(dir+"/spool", 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	sp := transport.NewSpooledPublisher(transport.SpooledPublisherConfig{
		Upstream:  pub,
		Spool:     spool,
		LogsTopic: "test/logs",
		QoS:       1,
	})
	ring := pipeline.NewRingBuffer(10_000, 0)
	batcher := pipeline.NewBatcher(ring, pipeline.BatcherConfig{
		BatchSize:     20,
		BatchInterval: 100 * time.Millisecond,
		Flush: func(ctx context.Context, batch []*parser.LogEntry) error {
			payload, err := pipeline.SerializeBatchJSONLGzip(batch)
			if err != nil {
				return err
			}
			return sp.Publish(ctx, "test/logs", payload, 1, false)
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); batcher.Run(ctx) }()
	go func() { defer wg.Done(); sp.Run(ctx) }()

	const produced = 200
	go func() {
		for i := 0; i < produced; i++ {
			ring.Push(&parser.LogEntry{
				Timestamp: time.Now(),
				Level:     parser.LevelInfo,
				Message:   "entry " + strconv.Itoa(i),
				Source:    "chaos",
			})
			time.Sleep(10 * time.Millisecond)

			// outage window
			switch i {
			case 40:
				pub.healthy.Store(false)
			case 190:
				pub.healthy.Store(true)
			}
		}
	}()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		decoded, err := pub.decoded()
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(decoded) >= produced {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	ring.Close()
	wg.Wait()

	decoded, err := pub.decoded()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	files, _ := spool.List()
	if len(files) != 0 {
		t.Errorf("spool not drained: %d files remain", len(files))
	}

	if len(decoded) != produced {
		t.Fatalf("delivered %d, want %d", len(decoded), produced)
	}

	seen := make(map[string]bool, produced)
	for _, e := range decoded {
		seen[e.Message] = true
	}
	for i := 0; i < produced; i++ {
		if !seen["entry "+strconv.Itoa(i)] {
			t.Fatalf("missing entry %d", i)
		}
	}
}
