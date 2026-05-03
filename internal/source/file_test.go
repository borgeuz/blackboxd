package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// passthroughParser is a Parser that emits one entry per line with the
// raw text in Message — sufficient for source-level testing without
// roping in a real parser's expectations.
type passthroughParser struct{}

func (passthroughParser) Name() string { return "passthrough" }
func (passthroughParser) Parse(line string) (*parser.LogEntry, error) {
	if line == "" || line == "\n" {
		return nil, errors.New("empty")
	}
	return &parser.LogEntry{
		Timestamp: time.Now(),
		Level:     parser.LevelInfo,
		Message:   trimNewline(line),
		Source:    "passthrough",
	}, nil
}
func trimNewline(s string) string {
	if n := len(s); n > 0 && s[n-1] == '\n' {
		return s[:n-1]
	}
	return s
}

// collector records every emitted entry under a mutex.
type collector struct {
	mu      sync.Mutex
	entries []*parser.LogEntry
}

func (c *collector) emit(e *parser.LogEntry) {
	c.mu.Lock()
	c.entries = append(c.entries, e)
	c.mu.Unlock()
}

func (c *collector) snapshot() []*parser.LogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*parser.LogEntry, len(c.entries))
	copy(out, c.entries)
	return out
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func appendFile(t *testing.T, p, body string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("OpenFile append: %v", err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatalf("Write append: %v", err)
	}
	f.Close()
}

func TestFileSource_BasicTail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	writeFile(t, p, "alpha\nbeta\n")

	src, err := NewFileSource(FileSourceConfig{
		Name:          "test",
		Path:          p,
		Parser:        passthroughParser{},
		FromBeginning: true,
		PollInterval:  20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	col := &collector{}

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, col.emit) }()

	// Append after start to exercise the live tail.
	time.Sleep(80 * time.Millisecond)
	appendFile(t, p, "gamma\n")

	// Allow the tail loop to pick up new bytes.
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	got := col.snapshot()
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), msgs(got))
	}
	for i, w := range want {
		if got[i].Message != w {
			t.Errorf("entry %d: got %q, want %q", i, got[i].Message, w)
		}
	}
}

func TestFileSource_RefusesSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	writeFile(t, target, "x\n")
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	src, _ := NewFileSource(FileSourceConfig{
		Name:   "sym",
		Path:   link,
		Parser: passthroughParser{},
	})

	col := &collector{}
	err := src.Run(context.Background(), col.emit)
	if err == nil || !errors.Is(err, ErrFatal) {
		t.Fatalf("expected ErrFatal for symlink, got %v", err)
	}
}

func TestFileSource_FollowSymlinkOptIn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	writeFile(t, target, "via-symlink\n")
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	src, _ := NewFileSource(FileSourceConfig{
		Name:           "sym",
		Path:           link,
		Parser:         passthroughParser{},
		FollowSymlinks: true,
		FromBeginning:  true,
		PollInterval:   20 * time.Millisecond,
	})
	col := &collector{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = src.Run(ctx, col.emit)

	got := col.snapshot()
	if len(got) != 1 || got[0].Message != "via-symlink" {
		t.Fatalf("got %v", msgs(got))
	}
}

func TestFileSource_OffsetPersistence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "log.txt")
	writeFile(t, logPath, "a\nb\nc\n")

	store := NewOffsetStore(stateDir)

	// First run: start from beginning, capture all 3 lines.
	src, _ := NewFileSource(FileSourceConfig{
		Name:          "persist",
		Path:          logPath,
		Parser:        passthroughParser{},
		FromBeginning: true,
		PollInterval:  20 * time.Millisecond,
		SaveInterval:  20 * time.Millisecond,
		Offsets:       store,
	})
	col1 := &collector{}
	ctx1, cancel1 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_ = src.Run(ctx1, col1.emit)
	cancel1()
	if g := len(col1.snapshot()); g != 3 {
		t.Fatalf("first run got %d, want 3", g)
	}

	// Append more lines and start a fresh source. It should resume
	// from the persisted offset and emit only the new lines.
	appendFile(t, logPath, "d\ne\n")
	src2, _ := NewFileSource(FileSourceConfig{
		Name:         "persist",
		Path:         logPath,
		Parser:       passthroughParser{},
		PollInterval: 20 * time.Millisecond,
		SaveInterval: 20 * time.Millisecond,
		Offsets:      store,
	})
	col2 := &collector{}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_ = src2.Run(ctx2, col2.emit)
	cancel2()

	got := msgs(col2.snapshot())
	want := []string{"d", "e"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("resume got %v, want %v", got, want)
	}
}

func TestFileSource_RotationByInodeChange(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.txt")
	writeFile(t, logPath, "old1\nold2\n")

	src, _ := NewFileSource(FileSourceConfig{
		Name:          "rot",
		Path:          logPath,
		Parser:        passthroughParser{},
		FromBeginning: true,
		PollInterval:  20 * time.Millisecond,
	})

	col := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = src.Run(ctx, col.emit); close(done) }()

	// Wait for the first batch to land.
	time.Sleep(80 * time.Millisecond)

	// Simulate logrotate: rename then new file in place.
	rotated := filepath.Join(dir, "log.txt.1")
	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatal(err)
	}
	writeFile(t, logPath, "new1\nnew2\n")

	// Allow rotation detection + read.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	all := msgs(col.snapshot())
	hasNew1 := false
	for _, m := range all {
		if m == "new1" {
			hasNew1 = true
			break
		}
	}
	if !hasNew1 {
		t.Fatalf("rotation did not pick up new file: %v", all)
	}
}

func TestFileSource_TruncationResetsOffset(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.txt")
	writeFile(t, logPath, "old1\nold2\n")

	src, _ := NewFileSource(FileSourceConfig{
		Name:          "trunc",
		Path:          logPath,
		Parser:        passthroughParser{},
		FromBeginning: true,
		PollInterval:  20 * time.Millisecond,
	})

	col := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = src.Run(ctx, col.emit); close(done) }()

	time.Sleep(80 * time.Millisecond)

	// Truncate in place (same inode, smaller size).
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatal(err)
	}
	writeFile(t, logPath, "fresh\n") // overwrites with smaller content

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	all := msgs(col.snapshot())
	hasFresh := false
	for _, m := range all {
		if m == "fresh" {
			hasFresh = true
			break
		}
	}
	if !hasFresh {
		t.Fatalf("truncation did not pick up new content: %v", all)
	}
}

func TestExpandGlob(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"a.log", "b.log", "c.txt"} {
		writeFile(t, filepath.Join(dir, name), "")
	}

	matches, err := ExpandGlob(filepath.Join(dir, "*.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Errorf("got %d matches, want 2", len(matches))
	}

	single, err := ExpandGlob(filepath.Join(dir, "a.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 {
		t.Errorf("non-glob: got %d, want 1", len(single))
	}

	if _, err := ExpandGlob(filepath.Join(dir, "missing.log")); err == nil {
		t.Errorf("expected error for missing file")
	}
}

func TestMakeBoundedEmit_DropsWhenFull(t *testing.T) {
	t.Parallel()
	sink := make(chan *parser.LogEntry, 1)
	var drops atomic.Uint64
	emit := MakeBoundedEmit(sink, 10*time.Millisecond, &drops)

	// First entry fits.
	emit(&parser.LogEntry{Message: "a"})
	// Second entry has nowhere to go and the timer expires.
	emit(&parser.LogEntry{Message: "b"})
	if drops.Load() != 1 {
		t.Fatalf("drops = %d, want 1", drops.Load())
	}
}

func msgs(entries []*parser.LogEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Message
	}
	return out
}
