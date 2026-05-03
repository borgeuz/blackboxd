package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Spool is the on-disk fallback used when MQTT is unreachable. Each
// Append writes one batch to its own file. File names use a sortable
// monotonic prefix so directory iteration yields chronological order.
//
// Layout (mode 0600, fsync'd):
//
//	{spoolDir}/{unix_ns}-{seq}.jsonl.gz
//
// FIFO eviction kicks in when the total size exceeds maxBytes;
// evicted files bump the drops counter.
type Spool struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
	seq      uint64
	drops    atomic.Uint64
	log      *slog.Logger
}

// NewSpool creates dir if missing (mode 0700, idempotent).
func NewSpool(dir string, maxBytes int64, logger *slog.Logger) (*Spool, error) {
	if dir == "" {
		return nil, errors.New("spool: dir required")
	}
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024
	}
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool: mkdir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool: chmod %q: %w", dir, err)
	}
	return &Spool{dir: dir, maxBytes: maxBytes, log: logger.With("component", "spool")}, nil
}

// Append writes payload atomically: tmp + fsync + rename, then
// enforces the size cap.
func (s *Spool) Append(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	name := fmt.Sprintf("%020d-%010d.jsonl.gz", time.Now().UnixNano(), s.seq)
	final := filepath.Join(s.dir, name)
	tmp := final + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("spool open: %w", err)
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("spool write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("spool fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("spool close: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("spool rename: %w", err)
	}

	if err := s.evict(); err != nil {
		s.log.Warn("spool eviction failed", "err", err)
	}
	return nil
}

// List returns spool files in chronological order (oldest first).
func (s *Spool) List() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("spool list: %w", err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".tmp") || !strings.HasSuffix(n, ".jsonl.gz") {
			continue
		}
		paths = append(paths, filepath.Join(s.dir, n))
	}
	sort.Strings(paths)
	return paths, nil
}

func (s *Spool) Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Delete removes a spool file, typically after a successful replay.
func (s *Spool) Delete(path string) error {
	return os.Remove(path)
}

// Drops is the cumulative count of FIFO-evicted files.
func (s *Spool) Drops() uint64 { return s.drops.Load() }

// evict removes the oldest files until total size is under cap.
// Caller holds s.mu.
func (s *Spool) evict() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	type item struct {
		path string
		size int64
	}
	var items []item
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, item{path: filepath.Join(s.dir, e.Name()), size: info.Size()})
		total += info.Size()
	}
	if total <= s.maxBytes {
		return nil
	}
	sort.Slice(items, func(i, j int) bool {
		return filepath.Base(items[i].path) < filepath.Base(items[j].path)
	})
	for _, it := range items {
		if total <= s.maxBytes {
			break
		}
		if err := os.Remove(it.path); err != nil {
			s.log.Warn("spool evict remove failed", "path", it.path, "err", err)
			continue
		}
		s.drops.Add(1)
		total -= it.size
	}
	return nil
}

// SpooledPublisher wraps a Publisher with the disk-spool fallback. On
// publish failure the payload is spooled; a background Run goroutine
// replays files when the upstream is healthy again.
//
// Files are deleted only after a successful replay PUBACK, so a crash
// mid-replay leaves them for the next run (at-least-once across
// restarts). Live publishes and replay are serialised via liveBusy so
// neither starves the other.
type SpooledPublisher struct {
	upstream Publisher
	spool    *Spool
	log      *slog.Logger

	logsTopic string
	qos       byte

	liveBusy sync.Mutex
}

type SpooledPublisherConfig struct {
	Upstream  Publisher
	Spool     *Spool
	LogsTopic string
	QoS       byte
	Logger    *slog.Logger
}

// NewSpooledPublisher does NOT start the replay goroutine; call Run
// separately so the caller controls its lifecycle.
func NewSpooledPublisher(cfg SpooledPublisherConfig) *SpooledPublisher {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SpooledPublisher{
		upstream:  cfg.Upstream,
		spool:     cfg.Spool,
		logsTopic: cfg.LogsTopic,
		qos:       cfg.QoS,
		log:       cfg.Logger.With("component", "spooled_publisher"),
	}
}

// publishTimeout caps every upstream publish attempt so a hung broker
// can't lock the publisher (and the live/replay path that depends on it).
const publishTimeout = 30 * time.Second

// Publish tries upstream first; on failure spools to disk. Returns
// nil if either path succeeded; an error only when both fail (e.g.
// no spool configured).
func (s *SpooledPublisher) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	s.liveBusy.Lock()
	defer s.liveBusy.Unlock()

	pctx, cancel := context.WithTimeout(ctx, publishTimeout)
	err := s.upstream.Publish(pctx, topic, payload, qos, retain)
	cancel()
	if err == nil {
		return nil
	}
	s.log.Warn("upstream publish failed; spooling", "err", err, "size", len(payload))

	if s.spool == nil {
		return errors.New("spooled publisher: no spool configured and upstream failed")
	}
	if err := s.spool.Append(payload); err != nil {
		return fmt.Errorf("spool append: %w", err)
	}
	return nil
}

func (s *SpooledPublisher) Close(ctx context.Context) error {
	if s.upstream == nil {
		return nil
	}
	return s.upstream.Close(ctx)
}

// Run replays the spool every 2s while the upstream is healthy. It
// bails on the first publish failure each tick — a flaky broker
// would otherwise burn cycles re-spooling everything it just popped.
func (s *SpooledPublisher) Run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in spool replay", "event_type", "security", "panic", r)
		}
	}()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.replayOnce(ctx)
		}
	}
}

func (s *SpooledPublisher) replayOnce(ctx context.Context) {
	if s.spool == nil {
		return
	}
	files, err := s.spool.List()
	if err != nil {
		s.log.Warn("spool list failed", "err", err)
		return
	}
	for _, p := range files {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.liveBusy.Lock()
		body, err := s.spool.Read(p)
		if err != nil {
			s.liveBusy.Unlock()
			// File evicted between List and Read is the expected race
			// when Append fires during replay; log only real failures.
			if !os.IsNotExist(err) {
				s.log.Warn("spool read failed", "path", p, "err", err)
			}
			return
		}
		pctx, cancel := context.WithTimeout(ctx, publishTimeout)
		err = s.upstream.Publish(pctx, s.logsTopic, body, s.qos, false)
		cancel()
		if err != nil {
			s.liveBusy.Unlock()
			return
		}
		if err := s.spool.Delete(p); err != nil && !os.IsNotExist(err) {
			s.log.Warn("spool delete failed", "path", p, "err", err)
		}
		s.liveBusy.Unlock()
	}
}
