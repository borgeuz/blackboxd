package oneshot

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// stubSource is a Source that returns a pre-built slice. Used to
// exercise the merge math without spinning up real parsers.
type stubSource struct {
	name    string
	entries []*parser.LogEntry
}

func (s *stubSource) Name() string                              { return s.name }
func (s *stubSource) Read(_ Filter) ([]*parser.LogEntry, error) { return s.entries, nil }

func ent(ts time.Time, msg, src string) *parser.LogEntry {
	return &parser.LogEntry{Timestamp: ts, Level: parser.LevelInfo, Message: msg, Source: src}
}

func TestMerge_ChronologicalOrder(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	srcA := &stubSource{name: "A", entries: []*parser.LogEntry{
		ent(t0.Add(0*time.Second), "a1", "A"),
		ent(t0.Add(2*time.Second), "a2", "A"),
		ent(t0.Add(4*time.Second), "a3", "A"),
	}}
	srcB := &stubSource{name: "B", entries: []*parser.LogEntry{
		ent(t0.Add(1*time.Second), "b1", "B"),
		ent(t0.Add(3*time.Second), "b2", "B"),
	}}
	srcC := &stubSource{name: "C", entries: []*parser.LogEntry{
		ent(t0.Add(5*time.Second), "c1", "C"),
	}}

	var buf bytes.Buffer
	n, err := Merge(&buf, []Source{srcA, srcB, srcC}, MergeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Errorf("written = %d, want 6", n)
	}

	// Expected order: a1, b1, a2, b2, a3, c1
	wantMsgs := []string{"a1", "b1", "a2", "b2", "a3", "c1"}
	gotMsgs := decodeMsgs(t, buf.Bytes())
	if !equalStrings(gotMsgs, wantMsgs) {
		t.Errorf("order: got %v, want %v", gotMsgs, wantMsgs)
	}
}

func TestMerge_RespectsMaxLines(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	srcA := &stubSource{name: "A", entries: []*parser.LogEntry{
		ent(t0, "a1", "A"), ent(t0.Add(time.Second), "a2", "A"),
		ent(t0.Add(2*time.Second), "a3", "A"), ent(t0.Add(3*time.Second), "a4", "A"),
	}}
	var buf bytes.Buffer
	n, err := Merge(&buf, []Source{srcA}, MergeOptions{MaxLines: 2})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("got %d, want 2", n)
	}
}

func TestMerge_RespectsFilter(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	srcA := &stubSource{name: "A", entries: []*parser.LogEntry{
		ent(t0.Add(-2*time.Second), "before", "A"),
		ent(t0.Add(0*time.Second), "in", "A"),
		ent(t0.Add(10*time.Second), "after", "A"),
	}}

	// We pass the filter to Source.Read; stubSource ignores it. So
	// to exercise filtering we use a wrapping source.
	wrapped := &filteringSource{inner: srcA}

	var buf bytes.Buffer
	_, err := Merge(&buf, []Source{wrapped}, MergeOptions{
		Filter: Filter{Since: t0, Until: t0.Add(5 * time.Second)},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := decodeMsgs(t, buf.Bytes())
	if len(got) != 1 || got[0] != "in" {
		t.Errorf("got %v", got)
	}
}

type filteringSource struct{ inner Source }

func (f *filteringSource) Name() string { return f.inner.Name() }
func (f *filteringSource) Read(filter Filter) ([]*parser.LogEntry, error) {
	all, err := f.inner.Read(Filter{})
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, e := range all {
		if filter.Passes(e.Timestamp) {
			out = append(out, e)
		}
	}
	return out, nil
}

func TestOpenOutput_Stdout(t *testing.T) {
	t.Parallel()
	w, c, err := OpenOutput("", false)
	if err != nil {
		t.Fatal(err)
	}
	if w == nil {
		t.Fatal("nil writer")
	}
	// Closing must not be an error for stdout-backed output (the
	// underlying os.Stdout is not part of the closer chain).
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenOutput_GzipFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "out.jsonl.gz")
	w, c, err := OpenOutput(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, `{"x":1}`+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Verify gzip integrity.
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	body, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"x":1`) {
		t.Errorf("body = %q", body)
	}
}

func TestFileSource_Read_AppliesFilter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "in.log")
	body := strings.Join([]string{
		"<13>Jan  1 00:00:00 host svc: a",
		"<13>Jan  1 00:00:01 host svc: b",
		"<13>Jan  1 00:00:02 host svc: c",
		"",
	}, "\n")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	bsd, err := parser.NewSyslogBSD(parser.SyslogBSDConfig{DefaultYear: 2026, Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	fs := &FileSource{Label: "test", Path: p, Parser: bsd}

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := fs.Read(Filter{Since: t0.Add(time.Second), Until: t0.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Message != "b" {
		var msgs []string
		for _, e := range got {
			msgs = append(msgs, e.Message)
		}
		t.Errorf("got %v", msgs)
	}
}

func decodeMsgs(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	for _, line := range bytes.Split(bytes.TrimRight(body, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var e parser.LogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		out = append(out, e.Message)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
