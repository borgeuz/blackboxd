// RFC 3164 (BSD) syslog.
//
//	<PRI>TIMESTAMP HOSTNAME TAG[PID]: MESSAGE
//
// PRI       = "<" 1*3DIGIT ">"
// TIMESTAMP = "Mmm _D HH:MM:SS"  (15 ASCII bytes, day space-padded)
// HOSTNAME  = single word
// TAG       = process name, optional "[" PID "]"
// ":" SP    = optional separator before MESSAGE
//
// RFC 3164 omits year and timezone — both are supplied at parser
// construction. Around year boundaries this is ambiguous; pin
// DefaultYear when post-mortem timestamps must be unambiguous.

package parser

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("syslog_bsd", newSyslogBSD)
}

const (
	syslogTimestampLayout = "Jan _2 15:04:05"
	syslogTimestampLen    = 15
)

type SyslogBSDConfig struct {
	// DefaultYear fills the year RFC 3164 omits. Zero ⇒ time.Now().Year() at construction.
	DefaultYear int `toml:"default_year"`

	// Timezone is an IANA name (e.g. "Europe/Rome", "UTC"). Empty ⇒ time.Local.
	Timezone string `toml:"timezone"`

	// Strict rejects deviations from the RFC. Default false: real-world
	// streams often deviate harmlessly.
	Strict bool `toml:"strict"`
}

type syslogBSD struct {
	defaultYear int
	loc         *time.Location
	strict      bool
}

func newSyslogBSD(raw map[string]any) (Parser, error) {
	var cfg SyslogBSDConfig
	if v, ok := raw["default_year"].(int); ok {
		cfg.DefaultYear = v
	} else if v, ok := raw["default_year"].(int64); ok {
		cfg.DefaultYear = int(v)
	}
	if v, ok := raw["timezone"].(string); ok {
		cfg.Timezone = v
	}
	if v, ok := raw["strict"].(bool); ok {
		cfg.Strict = v
	}
	return NewSyslogBSD(cfg)
}

// NewSyslogBSD is the typed constructor used by code-driven callers
// (one-shot CLI). Same parser the registry path produces.
func NewSyslogBSD(cfg SyslogBSDConfig) (Parser, error) {
	p := &syslogBSD{
		defaultYear: cfg.DefaultYear,
		loc:         time.Local,
		strict:      cfg.Strict,
	}
	if p.defaultYear == 0 {
		p.defaultYear = time.Now().Year()
	}
	if cfg.Timezone != "" {
		loc, err := time.LoadLocation(cfg.Timezone)
		if err != nil {
			return nil, fmt.Errorf("syslog_bsd: load timezone %q: %w", cfg.Timezone, err)
		}
		p.loc = loc
	}
	return p, nil
}

func (p *syslogBSD) Name() string { return "syslog_bsd" }

func (p *syslogBSD) Parse(line string) (*LogEntry, error) {
	line = trimTrailingNewline(line)
	if line == "" {
		return nil, fmt.Errorf("syslog_bsd: %w", ErrTruncatedLine)
	}

	rest, facility, severity, err := parsePriorityField(line)
	if err != nil {
		return nil, fmt.Errorf("syslog_bsd: priority: %w", err)
	}

	if len(rest) < syslogTimestampLen {
		return nil, fmt.Errorf("syslog_bsd: timestamp: %w", ErrTruncatedLine)
	}
	ts, err := time.ParseInLocation(syslogTimestampLayout, rest[:syslogTimestampLen], p.loc)
	if err != nil {
		return nil, fmt.Errorf("syslog_bsd: timestamp: %w: %v", ErrInvalidFormat, err)
	}
	ts = time.Date(p.defaultYear, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, p.loc)
	rest = rest[syslogTimestampLen:]

	if len(rest) == 0 || rest[0] != ' ' {
		return nil, fmt.Errorf("syslog_bsd: after timestamp: %w", ErrInvalidFormat)
	}
	rest = rest[1:]

	hostEnd := strings.IndexByte(rest, ' ')
	if hostEnd <= 0 {
		return nil, fmt.Errorf("syslog_bsd: hostname: %w", ErrInvalidFormat)
	}
	host := rest[:hostEnd]
	rest = rest[hostEnd+1:]

	tag, pid, msg := splitTagAndMessage(rest, p.strict)

	return &LogEntry{
		Timestamp: ts,
		Level:     severityToLevel(severity),
		Facility:  facility,
		Hostname:  host,
		Process:   tag,
		PID:       pid,
		Message:   msg,
		Source:    "syslog_bsd",
	}, nil
}

// splitTagAndMessage extracts TAG, optional PID and MESSAGE from
// "TAG[PID]: MESSAGE" (or "TAG MESSAGE" when the colon is missing).
// Malformed PID brackets degrade to pid=0 rather than failing the parse.
func splitTagAndMessage(s string, strict bool) (tag string, pid int, msg string) {
	end := strings.IndexAny(s, "[: ")
	if end == -1 {
		return s, 0, ""
	}
	tag = s[:end]
	rest := s[end:]

	if strings.HasPrefix(rest, "[") {
		closeIdx := strings.IndexByte(rest, ']')
		if closeIdx > 0 {
			if v, err := strconv.Atoi(rest[1:closeIdx]); err == nil && v >= 0 {
				pid = v
			} else if !strict {
				pid = 0
			}
			rest = rest[closeIdx+1:]
		}
	}
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimLeft(rest, " ")
	return tag, pid, rest
}
