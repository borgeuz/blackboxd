package oneshot

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/borgeuz/blackboxd/internal/parser"
	"github.com/borgeuz/blackboxd/internal/source"
)

// FileSource adapts a single file + parser into oneshot.Source. Reads
// the whole file at start; parse errors go to stderr, never to output.
type FileSource struct {
	Label  string
	Path   string
	Parser parser.Parser
}

func (f *FileSource) Name() string {
	if f.Label != "" {
		return f.Label
	}
	return f.Path
}

func (f *FileSource) Read(filter Filter) ([]*parser.LogEntry, error) {
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", f.Path, err)
	}
	defer fh.Close()

	br := bufio.NewReaderSize(fh, 64*1024)
	var entries []*parser.LogEntry
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			entry, perr := f.Parser.Parse(line)
			if perr != nil {
				fmt.Fprintf(os.Stderr, "blackboxd dump: %s: parse: %v\n", f.Name(), perr)
			} else if filter.Passes(entry.Timestamp) {
				entry.Source = f.Name()
				entry.SanitizeUTF8()
				entries = append(entries, entry)
			}
		}
		if err != nil {
			break
		}
	}
	return entries, nil
}

// JournalSource runs `journalctl -o export` once and parses the output.
// Since/Until pass through as --since/--until so the time filter is
// applied at the journal layer (cheaper than discarding entries here).
type JournalSource struct {
	Label    string
	Path     string
	Units    []string
	Priority int
	Since    string
	Until    string
	Parser   parser.Parser
}

func (j *JournalSource) Name() string {
	if j.Label != "" {
		return j.Label
	}
	return "journal"
}

func (j *JournalSource) Read(filter Filter) ([]*parser.LogEntry, error) {
	args := []string{"-o", "export", "--no-pager"}
	if j.Path != "" {
		args = append(args, "--directory", j.Path)
	}
	for _, u := range j.Units {
		args = append(args, "--unit", u)
	}
	if j.Priority > 0 {
		args = append(args, "--priority", fmt.Sprintf("%d", j.Priority))
	}
	if j.Since != "" {
		args = append(args, "--since", j.Since)
	}
	if j.Until != "" {
		args = append(args, "--until", j.Until)
	}
	out, err := captureCommand("journalctl", args)
	if err != nil {
		return nil, err
	}

	var entries []*parser.LogEntry
	for _, rec := range strings.Split(string(out), "\n\n") {
		rec = strings.TrimSpace(rec)
		if rec == "" {
			continue
		}
		entry, perr := j.Parser.Parse(rec)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "blackboxd dump: journal parse: %v\n", perr)
			continue
		}
		if !filter.Passes(entry.Timestamp) {
			continue
		}
		entry.Source = j.Name()
		entry.SanitizeUTF8()
		entries = append(entries, entry)
	}
	return entries, nil
}

// DmesgSource runs `dmesg --time-format=iso` and applies the filter
// in memory (dmesg has no native time filter).
type DmesgSource struct {
	Parser parser.Parser
}

func (d *DmesgSource) Name() string { return "dmesg" }

func (d *DmesgSource) Read(filter Filter) ([]*parser.LogEntry, error) {
	entries, err := source.RunDmesg(context.Background(), source.DmesgRunOptions{
		Parser: d.Parser,
	})
	if err != nil {
		return nil, err
	}
	if filter.Since.IsZero() && filter.Until.IsZero() {
		return entries, nil
	}
	out := entries[:0]
	for _, e := range entries {
		if filter.Passes(e.Timestamp) {
			out = append(out, e)
		}
	}
	return out, nil
}
