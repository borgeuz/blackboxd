package parser

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func mustBSD(t testing.TB, cfg SyslogBSDConfig) Parser {
	t.Helper()
	p, err := NewSyslogBSD(cfg)
	if err != nil {
		t.Fatalf("NewSyslogBSD: %v", err)
	}
	return p
}

func TestSyslogBSD_Parse(t *testing.T) {
	t.Parallel()
	p := mustBSD(t, SyslogBSDConfig{DefaultYear: 2026, Timezone: "UTC"})

	cases := []struct {
		name      string
		line      string
		wantHost  string
		wantProc  string
		wantPID   int
		wantLevel Level
		wantMsg   string
		wantErr   bool
	}{
		{
			name:      "classic-with-pid",
			line:      "<134>Jan  3 12:00:00 host1 sshd[1234]: Accepted password for root",
			wantHost:  "host1",
			wantProc:  "sshd",
			wantPID:   1234,
			wantLevel: LevelInfo, // 134 % 8 = 6
			wantMsg:   "Accepted password for root",
		},
		{
			name:      "no-pid",
			line:      "<13>Jan  3 12:00:00 host1 cron: starting daily job",
			wantHost:  "host1",
			wantProc:  "cron",
			wantLevel: LevelNotice,
			wantMsg:   "starting daily job",
		},
		{
			name:      "single-digit-day",
			line:      "<10>Feb  9 03:14:15 nucleo kernel: usb 1-1: high-speed USB device number 5",
			wantHost:  "nucleo",
			wantProc:  "kernel",
			wantLevel: LevelCritical,
			wantMsg:   "usb 1-1: high-speed USB device number 5",
		},
		{
			name:      "two-digit-day",
			line:      "<6>Mar 11 23:00:00 box service: hello",
			wantHost:  "box",
			wantProc:  "service",
			wantLevel: LevelInfo,
			wantMsg:   "hello",
		},
		{
			name:      "empty-message",
			line:      "<13>Apr  1 00:00:00 box service: ",
			wantHost:  "box",
			wantProc:  "service",
			wantLevel: LevelNotice,
			wantMsg:   "",
		},
		{
			name:      "no-colon",
			line:      "<13>Apr  1 00:00:00 box service stuff happens",
			wantHost:  "box",
			wantProc:  "service",
			wantLevel: LevelNotice,
			wantMsg:   "stuff happens",
		},
		{
			name:    "missing-priority",
			line:    "Jan  3 12:00:00 host sshd: hi",
			wantErr: true,
		},
		{
			name:    "priority-out-of-range",
			line:    "<999>Jan  3 12:00:00 host sshd: hi",
			wantErr: true,
		},
		{
			name:    "truncated-after-priority",
			line:    "<13>",
			wantErr: true,
		},
		{
			name:    "empty",
			line:    "",
			wantErr: true,
		},
		{
			name:      "trailing-crlf",
			line:      "<13>Apr  1 00:00:00 box service: hello\r\n",
			wantHost:  "box",
			wantProc:  "service",
			wantLevel: LevelNotice,
			wantMsg:   "hello",
		},
		{
			name:      "non-numeric-pid",
			line:      "<13>Apr  1 00:00:00 box service[abc]: hi",
			wantHost:  "box",
			wantProc:  "service",
			wantPID:   0,
			wantLevel: LevelNotice,
			wantMsg:   "hi",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := p.Parse(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got entry %+v", e)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.Hostname != tc.wantHost {
				t.Errorf("host = %q, want %q", e.Hostname, tc.wantHost)
			}
			if e.Process != tc.wantProc {
				t.Errorf("proc = %q, want %q", e.Process, tc.wantProc)
			}
			if e.PID != tc.wantPID {
				t.Errorf("pid = %d, want %d", e.PID, tc.wantPID)
			}
			if e.Level != tc.wantLevel {
				t.Errorf("level = %s, want %s", e.Level, tc.wantLevel)
			}
			if e.Message != tc.wantMsg {
				t.Errorf("msg = %q, want %q", e.Message, tc.wantMsg)
			}
			if e.Source != "syslog_bsd" {
				t.Errorf("src = %q, want syslog_bsd", e.Source)
			}
		})
	}
}

func TestSyslogBSD_TimestampYearAndZone(t *testing.T) {
	t.Parallel()
	p := mustBSD(t, SyslogBSDConfig{DefaultYear: 2025, Timezone: "UTC"})
	e, err := p.Parse("<13>Jul  4 13:00:00 host svc: independence day")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, time.July, 4, 13, 0, 0, 0, time.UTC)
	if !e.Timestamp.Equal(want) {
		t.Fatalf("ts = %s, want %s", e.Timestamp, want)
	}
}

func TestSyslogBSD_ErrorWraps(t *testing.T) {
	t.Parallel()
	p := mustBSD(t, SyslogBSDConfig{Timezone: "UTC"})
	_, err := p.Parse("nope")
	if !errors.Is(err, ErrInvalidFormat) && !errors.Is(err, ErrInvalidPriority) {
		t.Fatalf("expected ErrInvalidFormat or ErrInvalidPriority, got %v", err)
	}
}

func TestSyslogBSD_RegistryPath(t *testing.T) {
	t.Parallel()
	p, err := Build("syslog_bsd", map[string]any{"default_year": int64(2026), "timezone": "UTC"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := p.Parse("<13>Jan  3 12:00:00 host svc: x"); err != nil {
		t.Fatalf("Parse via registry: %v", err)
	}
}

func BenchmarkSyslogBSD_Parse(b *testing.B) {
	p := mustBSD(b, SyslogBSDConfig{DefaultYear: 2026, Timezone: "UTC"})
	line := "<134>Jan  3 12:00:00 host1 sshd[1234]: Accepted password for root from 192.0.2.1"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.Parse(line)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzSyslogBSD_Parse(f *testing.F) {
	p, err := NewSyslogBSD(SyslogBSDConfig{DefaultYear: 2026, Timezone: "UTC"})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"<134>Jan  3 12:00:00 host sshd[1]: hi",
		"<13>Apr  1 00:00:00 box service: ",
		"",
		"<>",
		strings.Repeat("A", 1024),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		// We assert only that Parse never panics. Returning an error
		// is acceptable; producing a LogEntry is acceptable. Either
		// outcome must be reachable without crashing the daemon.
		_, _ = p.Parse(line)
	})
}
