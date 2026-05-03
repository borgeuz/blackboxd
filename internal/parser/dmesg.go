// dmesg text output. Two timestamp formats:
//   - legacy "[12345.678901] msg" — seconds since boot
//   - iso    "[2026-04-01T12:00:00,123456+0000] msg" — wall-clock,
//     produced by `dmesg --time-format=iso`
//
// Used by one-shot mode only; service mode reads /dev/kmsg directly.

package parser

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("dmesg", newDmesg)
}

// DmesgConfig pins the boot wall-clock for legacy format. ISO format
// is self-describing and ignores BootTime.
type DmesgConfig struct {
	BootTime time.Time
}

type dmesg struct {
	bootTime time.Time
}

func newDmesg(raw map[string]any) (Parser, error) {
	var cfg DmesgConfig
	if v, ok := raw["boot_time"].(string); ok && v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return nil, fmt.Errorf("dmesg: boot_time: %w", err)
		}
		cfg.BootTime = t
	}
	return NewDmesg(cfg)
}

func NewDmesg(cfg DmesgConfig) (Parser, error) {
	bt := cfg.BootTime
	if bt.IsZero() {
		bt = readBootTime()
	}
	return &dmesg{bootTime: bt}, nil
}

func (p *dmesg) Name() string { return "dmesg" }

// dmesgISOLayout uses a comma for the fractional separator and a
// no-colon timezone offset (matches `dmesg --time-format=iso` exactly).
const dmesgISOLayout = "2006-01-02T15:04:05,000000-0700"

func (p *dmesg) Parse(line string) (*LogEntry, error) {
	line = trimTrailingNewline(line)
	if line == "" {
		return nil, fmt.Errorf("dmesg: %w", ErrTruncatedLine)
	}
	if line[0] != '[' {
		return nil, fmt.Errorf("dmesg: %w: no leading '['", ErrInvalidFormat)
	}
	closeIdx := strings.IndexByte(line, ']')
	if closeIdx == -1 {
		return nil, fmt.Errorf("dmesg: %w: no closing ']'", ErrInvalidFormat)
	}
	tsField := line[1:closeIdx]
	rest := strings.TrimLeft(line[closeIdx+1:], " \t")

	ts, err := parseDmesgTimestamp(tsField, p.bootTime)
	if err != nil {
		return nil, fmt.Errorf("dmesg: timestamp: %w", err)
	}

	return &LogEntry{
		Timestamp: ts,
		Level:     LevelInfo, // dmesg strips priority by default
		Process:   "kernel",
		Message:   rest,
		Source:    "dmesg",
	}, nil
}

// parseDmesgTimestamp picks legacy vs ISO by presence of 'T'. Legacy
// format with zero bootTime returns zero time; the caller decides what
// to do with that.
func parseDmesgTimestamp(s string, bootTime time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, ErrInvalidFormat
	}
	if strings.IndexByte(s, 'T') > 0 {
		return time.Parse(dmesgISOLayout, s)
	}
	secs, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}
	// Reject NaN, infinity, and values that wouldn't fit in time.Duration.
	// time.Duration max is ~292 years.
	const maxSecs = float64(9_223_372_036) // ns max / 1e9, with margin
	if secs < 0 || secs != secs || secs > maxSecs {
		return time.Time{}, fmt.Errorf("%w: timestamp out of range", ErrInvalidFormat)
	}
	if bootTime.IsZero() {
		return time.Time{}, nil
	}
	return bootTime.Add(time.Duration(secs * float64(time.Second))), nil
}
