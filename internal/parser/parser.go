// Package parser defines the canonical LogEntry / Level / Parser
// types and hosts the per-format parser registry. Parsers are
// stateless after construction and safe for concurrent use.
package parser

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Level mirrors the eight RFC 5424 severities. Lower number = more severe.
type Level uint8

const (
	LevelEmergency Level = iota
	LevelAlert
	LevelCritical
	LevelError
	LevelWarning
	LevelNotice
	LevelInfo
	LevelDebug
)

// String returns the short name used by most log shippers. Out-of-range
// values map to "unknown" so corrupted entries still produce valid JSON.
func (l Level) String() string {
	switch l {
	case LevelEmergency:
		return "emerg"
	case LevelAlert:
		return "alert"
	case LevelCritical:
		return "crit"
	case LevelError:
		return "error"
	case LevelWarning:
		return "warn"
	case LevelNotice:
		return "notice"
	case LevelInfo:
		return "info"
	case LevelDebug:
		return "debug"
	default:
		return "unknown"
	}
}

// MarshalJSON emits the symbolic name. Default uint8 marshalling would
// produce a number; the wire contract is the name.
func (l Level) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 0, 12)
	buf = append(buf, '"')
	buf = append(buf, l.String()...)
	buf = append(buf, '"')
	return buf, nil
}

// UnmarshalJSON accepts the symbolic name or a numeric severity (0-7).
// Numeric form lets the cloud receiver replay legacy data.
func (l *Level) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("parser: empty Level JSON")
	}
	// Strip surrounding quotes only if both present and length permits.
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}
	switch string(b) {
	case "emerg", "0":
		*l = LevelEmergency
	case "alert", "1":
		*l = LevelAlert
	case "crit", "2":
		*l = LevelCritical
	case "error", "err", "3":
		*l = LevelError
	case "warn", "warning", "4":
		*l = LevelWarning
	case "notice", "5":
		*l = LevelNotice
	case "info", "6":
		*l = LevelInfo
	case "debug", "7":
		*l = LevelDebug
	default:
		return fmt.Errorf("parser: unknown level %q", string(b))
	}
	return nil
}

// LogEntry is the canonical wire shape. JSON tags are short to keep
// payload size down on slow embedded uplinks.
type LogEntry struct {
	Timestamp time.Time         `json:"ts"`
	Level     Level             `json:"level"`
	Facility  int               `json:"facility,omitempty"`
	Hostname  string            `json:"host,omitempty"`
	Process   string            `json:"proc,omitempty"`
	PID       int               `json:"pid,omitempty"`
	Message   string            `json:"msg"`
	Source    string            `json:"src"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// SanitizeUTF8 replaces invalid UTF-8 sequences in Message with U+FFFD
// so the entry JSON-marshals cleanly regardless of input source.
func (e *LogEntry) SanitizeUTF8() {
	if utf8.ValidString(e.Message) {
		return
	}
	e.Message = strings.ToValidUTF8(e.Message, "�")
}

// Parser parses one record at a time. Implementations are safe for
// concurrent use after construction. Multi-line handling lives in the
// source/pipeline layer.
type Parser interface {
	Name() string
	Parse(line string) (*LogEntry, error)
}

// Sentinel errors; wrap with fmt.Errorf("...: %w", ...) for context.
var (
	ErrInvalidFormat   = errors.New("invalid log format")
	ErrTruncatedLine   = errors.New("truncated log line")
	ErrInvalidPriority = errors.New("invalid priority")
)
