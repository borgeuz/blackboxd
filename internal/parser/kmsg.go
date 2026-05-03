// /dev/kmsg — kernel ring buffer.
//
// Format (Documentation/ABI/testing/dev-kmsg):
//
//	PRIORITY,SEQNUM,TIMESTAMP_USEC,FLAG[,SUBSYS[,...]];MSG\n
//	[ KEY=value\n ]*
//
// PRIORITY = facility * 8 + severity (0..191)
// SEQNUM = monotonic kernel sequence number
// TIMESTAMP_USEC = microseconds since boot
// FLAG = "c" (continuation) or "-"
// MSG = printable text up to the next newline
//
// Indented KEY=value continuation lines are not consumed here; the
// source layer joins or drops them.

package parser

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("kmsg", newKMsg)
}

// KMsgConfig pins the wall-clock anchor used to convert TIMESTAMP_USEC.
// When BootTime is zero the parser reads /proc/uptime at construction.
type KMsgConfig struct {
	BootTime time.Time
}

type kmsg struct {
	bootTime time.Time
}

func newKMsg(raw map[string]any) (Parser, error) {
	var cfg KMsgConfig
	if v, ok := raw["boot_time"].(string); ok && v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return nil, fmt.Errorf("kmsg: boot_time: %w", err)
		}
		cfg.BootTime = t
	}
	return NewKMsg(cfg)
}

func NewKMsg(cfg KMsgConfig) (Parser, error) {
	bt := cfg.BootTime
	if bt.IsZero() {
		bt = readBootTime()
	}
	return &kmsg{bootTime: bt}, nil
}

func (p *kmsg) Name() string { return "kmsg" }

func (p *kmsg) Parse(line string) (*LogEntry, error) {
	line = trimTrailingNewline(line)
	if line == "" {
		return nil, fmt.Errorf("kmsg: %w", ErrTruncatedLine)
	}

	semi := strings.IndexByte(line, ';')
	if semi == -1 {
		return nil, fmt.Errorf("kmsg: %w: missing ';'", ErrInvalidFormat)
	}
	header := line[:semi]
	msg := line[semi+1:]

	// Header has at least PRI,SEQ,USEC,FLAG.
	parts := strings.SplitN(header, ",", 5)
	if len(parts) < 4 {
		return nil, fmt.Errorf("kmsg: %w: header has %d fields", ErrInvalidFormat, len(parts))
	}

	pri, err := strconv.Atoi(parts[0])
	if err != nil || pri < 0 || pri > maxPriority {
		return nil, fmt.Errorf("kmsg: %w: bad priority %q", ErrInvalidPriority, parts[0])
	}

	usec, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || usec < 0 {
		return nil, fmt.Errorf("kmsg: %w: bad timestamp %q", ErrInvalidFormat, parts[2])
	}
	// Guard against int64 overflow when converting μs → ns. The kernel
	// uptime in microseconds maxes out around 9.2e18 (int64) before the
	// next multiplication wraps; clamp to ~292 years which is the
	// practical limit of time.Duration anyway.
	const maxUsec = int64(9_223_372_036_854_775) // ns / 1000
	if usec > maxUsec {
		return nil, fmt.Errorf("kmsg: %w: timestamp out of range", ErrInvalidFormat)
	}

	var ts time.Time
	if !p.bootTime.IsZero() {
		ts = p.bootTime.Add(time.Duration(usec) * time.Microsecond)
	}

	entry := &LogEntry{
		Timestamp: ts,
		Level:     severityToLevel(pri % 8),
		Facility:  pri / 8,
		Process:   "kernel",
		Message:   msg,
		Source:    "kmsg",
	}
	if parts[3] != "" && parts[3] != "-" {
		entry.Fields = map[string]string{"flag": parts[3], "seq": parts[1]}
	}
	return entry, nil
}

// readBootTime derives boot wall-clock from /proc/uptime. Returns zero
// on error; the parser then emits zero Timestamp and the source layer
// logs a warning.
func readBootTime() time.Time {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return time.Time{}
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(secs * float64(time.Second)))
}
