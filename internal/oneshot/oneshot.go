// Package oneshot implements `blackboxd dump`: a forensic export
// that reads from each requested source, merges them by Timestamp via
// k-way min-heap, and writes JSONL (optionally gzipped) to stdout or
// a file.
//
// Service-mode pieces (ring buffer, batcher, MQTT) are not used here.
// One-shot mode bypasses the TOML config so it works even when the
// daemon's normal config is broken or absent.
package oneshot

import (
	"bufio"
	"compress/gzip"
	"container/heap"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// Source returns the per-source entries already filtered. The
// returned slice should be sorted ascending by Timestamp; Merge
// re-sorts defensively so a misbehaving source can't break ordering.
type Source interface {
	Name() string
	Read(filter Filter) ([]*parser.LogEntry, error)
}

// Filter applied per-source before merge to avoid allocating entries
// only to discard them.
type Filter struct {
	Since time.Time // zero = no lower bound
	Until time.Time // zero = no upper bound
}

func (f Filter) Passes(ts time.Time) bool {
	if !f.Since.IsZero() && ts.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && ts.After(f.Until) {
		return false
	}
	return true
}

type MergeOptions struct {
	MaxLines int // 0 = no cap
	Filter   Filter
}

// Merge runs k-way merge over sources and writes JSONL to w. A source
// that fails to Read is logged to stderr and skipped — one broken
// source must not abort the whole dump.
func Merge(w io.Writer, sources []Source, opts MergeOptions) (int, error) {
	pq := make(mergeHeap, 0, len(sources))
	for _, s := range sources {
		entries, err := s.Read(opts.Filter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "blackboxd dump: source %q: %v\n", s.Name(), err)
			continue
		}
		sort.SliceStable(entries, func(i, j int) bool {
			return entries[i].Timestamp.Before(entries[j].Timestamp)
		})
		if len(entries) > 0 {
			pq = append(pq, &mergeCursor{entries: entries, idx: 0, name: s.Name()})
		}
	}
	heap.Init(&pq)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	written := 0
	for pq.Len() > 0 {
		if opts.MaxLines > 0 && written >= opts.MaxLines {
			break
		}
		head := pq[0]
		if err := enc.Encode(head.entries[head.idx]); err != nil {
			return written, fmt.Errorf("oneshot encode: %w", err)
		}
		written++
		head.idx++
		if head.idx >= len(head.entries) {
			heap.Pop(&pq)
		} else {
			heap.Fix(&pq, 0)
		}
	}
	return written, nil
}

// OpenOutput returns a writer for --output / --gzip. Stdout (path "" or "-")
// is returned bare; the caller must not close it. The returned Closer
// flushes any buffered/gzipped state and closes the file when used.
func OpenOutput(path string, useGzip bool) (io.Writer, io.Closer, error) {
	var underlying io.Writer
	var closers []io.Closer

	if path == "" || path == "-" {
		underlying = os.Stdout
	} else {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("oneshot output: %w", err)
		}
		underlying = f
		closers = append(closers, f)
	}

	if useGzip {
		gz := gzip.NewWriter(underlying)
		closers = append([]io.Closer{gz}, closers...)
		bw := bufio.NewWriter(gz)
		return bw, &writerCloser{flush: bw.Flush, closers: closers}, nil
	}
	bw := bufio.NewWriter(underlying)
	return bw, &writerCloser{flush: bw.Flush, closers: closers}, nil
}

type writerCloser struct {
	flush   func() error
	closers []io.Closer
}

func (w *writerCloser) Close() error {
	var first error
	if w.flush != nil {
		if err := w.flush(); err != nil {
			first = err
		}
	}
	for _, c := range w.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// min-heap on Timestamp -------------------------------------------------------

type mergeCursor struct {
	entries []*parser.LogEntry
	idx     int
	name    string
}

type mergeHeap []*mergeCursor

func (h mergeHeap) Len() int { return len(h) }
func (h mergeHeap) Less(i, j int) bool {
	return h[i].entries[h[i].idx].Timestamp.Before(h[j].entries[h[j].idx].Timestamp)
}
func (h mergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(x any)   { *h = append(*h, x.(*mergeCursor)) }
func (h *mergeHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}
