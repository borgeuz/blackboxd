// systemd journal "export" format.
//
// `journalctl -o export` emits each entry as a sequence of "KEY=value\n"
// lines terminated by a blank line. Binary fields use an 8-byte length
// prefix; v1 only handles text fields and skips binary ones. The
// source layer slices the stream on blank lines and feeds one record
// at a time to Parse.

package parser

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("journald", newJournald)
}

// JournaldConfig is empty in v1: the format is self-describing.
type JournaldConfig struct{}

type journald struct{}

func newJournald(_ map[string]any) (Parser, error) { return NewJournald(JournaldConfig{}) }

func NewJournald(_ JournaldConfig) (Parser, error) { return &journald{}, nil }

func (p *journald) Name() string { return "journald" }

func (p *journald) Parse(record string) (*LogEntry, error) {
	if record == "" {
		return nil, fmt.Errorf("journald: %w", ErrTruncatedLine)
	}

	entry := &LogEntry{Source: "journald"}
	fields := map[string]string{}

	for _, line := range strings.Split(record, "\n") {
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			// Bare key: start of a binary-encoded field. Drop it —
			// the source already split on '\n' so we have no length prefix.
			continue
		}
		assignJournaldField(entry, fields, line[:eq], line[eq+1:])
	}

	if entry.Message == "" && len(fields) == 0 {
		return nil, fmt.Errorf("journald: %w: no recognisable fields", ErrInvalidFormat)
	}
	if len(fields) > 0 {
		entry.Fields = fields
	}
	return entry, nil
}

// assignJournaldField routes recognised keys into LogEntry slots; the
// rest goes into Fields.
//
//	MESSAGE               → Message
//	PRIORITY (0..7)       → Level
//	_HOSTNAME             → Hostname
//	_PID                  → PID
//	SYSLOG_IDENTIFIER     → Process (preferred)
//	_COMM                 → Process (fallback)
//	SYSLOG_FACILITY       → Facility
//	__REALTIME_TIMESTAMP  → Timestamp (μs since epoch)
func assignJournaldField(e *LogEntry, fields map[string]string, key, val string) {
	switch key {
	case "MESSAGE":
		e.Message = val
	case "PRIORITY":
		if n, err := strconv.Atoi(val); err == nil && n >= 0 && n <= 7 {
			e.Level = severityToLevel(n)
		}
	case "_HOSTNAME":
		e.Hostname = val
	case "_PID":
		if n, err := strconv.Atoi(val); err == nil {
			e.PID = n
		}
	case "SYSLOG_IDENTIFIER":
		e.Process = val
	case "_COMM":
		if e.Process == "" {
			e.Process = val
		}
	case "SYSLOG_FACILITY":
		if n, err := strconv.Atoi(val); err == nil {
			e.Facility = n
		}
	case "__REALTIME_TIMESTAMP":
		if n, err := strconv.ParseInt(val, 10, 64); err == nil {
			e.Timestamp = time.Unix(n/1_000_000, (n%1_000_000)*1_000)
		}
	default:
		fields[key] = val
	}
}
