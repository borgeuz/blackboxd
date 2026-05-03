// RFC 5424 syslog.
//
//	<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]
//
// VERSION = 1*3DIGIT (usually "1")
// TIMESTAMP = RFC 3339 with optional fractional seconds and TZ, or "-"
// HOSTNAME / APP-NAME / PROCID / MSGID = printable ASCII or "-"
// STRUCTURED-DATA = "-" | 1*"[" SD-ID *(SP SD-PARAM) "]"
// MSG = optional UTF-8 BOM then text
//
// Reference: https://datatracker.ietf.org/doc/html/rfc5424

package parser

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("syslog_rfc5424", newSyslogRFC5424)
}

// SyslogRFC5424Config is empty in v1: 5424 carries everything in-band.
// Reserved for future options (e.g. SD-field allowlist, BOM tolerance).
type SyslogRFC5424Config struct{}

type syslogRFC5424 struct{}

func newSyslogRFC5424(_ map[string]any) (Parser, error) {
	return NewSyslogRFC5424(SyslogRFC5424Config{})
}

func NewSyslogRFC5424(_ SyslogRFC5424Config) (Parser, error) { return &syslogRFC5424{}, nil }

func (p *syslogRFC5424) Name() string { return "syslog_rfc5424" }

func (p *syslogRFC5424) Parse(line string) (*LogEntry, error) {
	line = trimTrailingNewline(line)
	if line == "" {
		return nil, fmt.Errorf("syslog_rfc5424: %w", ErrTruncatedLine)
	}

	rest, facility, severity, err := parsePriorityField(line)
	if err != nil {
		return nil, fmt.Errorf("syslog_rfc5424: priority: %w", err)
	}

	rest, _, err = takeUntilSpace(rest) // VERSION
	if err != nil {
		return nil, fmt.Errorf("syslog_rfc5424: version: %w", err)
	}

	rest, tsField, err := takeUntilSpace(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog_rfc5424: timestamp: %w", err)
	}
	var ts time.Time
	if tsField != "-" {
		ts, err = time.Parse(time.RFC3339Nano, tsField)
		if err != nil {
			return nil, fmt.Errorf("syslog_rfc5424: timestamp: %w: %v", ErrInvalidFormat, err)
		}
	}

	rest, host, err := takeUntilSpace(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog_rfc5424: hostname: %w", err)
	}
	rest, app, err := takeUntilSpace(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog_rfc5424: app-name: %w", err)
	}
	rest, procid, err := takeUntilSpace(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog_rfc5424: procid: %w", err)
	}
	rest, _, err = takeUntilSpace(rest) // MSGID; captured, unused in LogEntry
	if err != nil {
		return nil, fmt.Errorf("syslog_rfc5424: msgid: %w", err)
	}

	rest, sd, err := readStructuredData(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog_rfc5424: structured-data: %w", err)
	}

	if strings.HasPrefix(rest, " ") {
		rest = rest[1:]
	}
	rest = strings.TrimPrefix(rest, "\xef\xbb\xbf") // optional UTF-8 BOM

	pid := 0
	if procid != "-" {
		// PROCID is free-form per RFC 5424 §6.2.6: a non-numeric value
		// is not a parse error.
		if v, err := strconv.Atoi(procid); err == nil {
			pid = v
		}
	}

	entry := &LogEntry{
		Timestamp: ts,
		Level:     severityToLevel(severity),
		Facility:  facility,
		Hostname:  nilIfDash(host),
		Process:   nilIfDash(app),
		PID:       pid,
		Message:   rest,
		Source:    "syslog_rfc5424",
	}
	if sd != "" && sd != "-" {
		entry.Fields = map[string]string{"structured_data": sd}
	}
	return entry, nil
}

// takeUntilSpace returns (rest after the space, token).
// "-" is the explicit nil sentinel; an empty field (two consecutive
// spaces) violates the grammar and is rejected.
func takeUntilSpace(s string) (rest, token string, err error) {
	idx := strings.IndexByte(s, ' ')
	if idx == -1 {
		if s == "" {
			return "", "", ErrTruncatedLine
		}
		return "", s, nil
	}
	if idx == 0 {
		return s, "", ErrInvalidFormat
	}
	return s[idx+1:], s[:idx], nil
}

// readStructuredData consumes either "-" or one or more "[...]" segments
// and returns them as raw text. Quoted strings with backslash-escaped
// characters are honoured. The inner key/value pairs are not decoded —
// the cloud side parses them when needed.
func readStructuredData(s string) (rest, sd string, err error) {
	if s == "" {
		return "", "", ErrTruncatedLine
	}
	if s[0] == '-' {
		return s[1:], "-", nil
	}
	if s[0] != '[' {
		return s, "", ErrInvalidFormat
	}
	i := 0
	for i < len(s) {
		if s[i] != '[' {
			break
		}
		j := i + 1
		inQuote := false
		for j < len(s) {
			c := s[j]
			if c == '\\' && j+1 < len(s) {
				j += 2
				continue
			}
			if c == '"' {
				inQuote = !inQuote
				j++
				continue
			}
			if !inQuote && c == ']' {
				break
			}
			j++
		}
		if j >= len(s) {
			return s, "", ErrInvalidFormat
		}
		i = j + 1
	}
	return s[i:], s[:i], nil
}

func nilIfDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
