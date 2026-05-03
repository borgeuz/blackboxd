package parser

import (
	"strings"
	"testing"
	"time"
)

var kmsgBoot = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func mustKMsg(t testing.TB) Parser {
	t.Helper()
	p, err := NewKMsg(KMsgConfig{BootTime: kmsgBoot})
	if err != nil {
		t.Fatalf("NewKMsg: %v", err)
	}
	return p
}

func TestKMsg_Parse(t *testing.T) {
	t.Parallel()
	p := mustKMsg(t)

	cases := []struct {
		name      string
		line      string
		wantLevel Level
		wantFac   int
		wantMsg   string
		wantTS    time.Time
		wantErr   bool
	}{
		{
			name:      "info-no-flag",
			line:      "6,500,1234567,-;ACPI: power button [PWRB]",
			wantLevel: LevelInfo,
			wantFac:   0,
			wantMsg:   "ACPI: power button [PWRB]",
			wantTS:    kmsgBoot.Add(1234567 * time.Microsecond),
		},
		{
			name:      "warning-with-flag",
			line:      "4,12,7000,c;continuation marker",
			wantLevel: LevelWarning,
			wantFac:   0,
			wantMsg:   "continuation marker",
			wantTS:    kmsgBoot.Add(7000 * time.Microsecond),
		},
		{
			name:      "high-facility",
			line:      "13,7,5000000,-;daemon notice",
			wantLevel: LevelNotice,
			wantFac:   1,
			wantMsg:   "daemon notice",
			wantTS:    kmsgBoot.Add(5000000 * time.Microsecond),
		},
		{
			name:      "with-subsystem",
			line:      "6,9,9000,-,1234,ehci_hcd;event from subsys",
			wantLevel: LevelInfo,
			wantMsg:   "event from subsys",
			wantTS:    kmsgBoot.Add(9000 * time.Microsecond),
		},
		{
			name:      "empty-message",
			line:      "6,9,9000,-;",
			wantLevel: LevelInfo,
			wantMsg:   "",
			wantTS:    kmsgBoot.Add(9000 * time.Microsecond),
		},
		{name: "missing-semicolon", line: "6,9,9000,-", wantErr: true},
		{name: "truncated-header", line: "6,9;hi", wantErr: true},
		{name: "bad-priority", line: "abc,1,1,-;hi", wantErr: true},
		{name: "priority-out-of-range", line: "999,1,1,-;hi", wantErr: true},
		{name: "bad-timestamp", line: "6,1,nope,-;hi", wantErr: true},
		{name: "timestamp-overflow", line: "6,1,99999999999999999999,-;hi", wantErr: true},
		{name: "empty", line: "", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := p.Parse(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", e)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.Level != tc.wantLevel {
				t.Errorf("level = %s, want %s", e.Level, tc.wantLevel)
			}
			if e.Facility != tc.wantFac {
				t.Errorf("facility = %d, want %d", e.Facility, tc.wantFac)
			}
			if e.Message != tc.wantMsg {
				t.Errorf("msg = %q, want %q", e.Message, tc.wantMsg)
			}
			if !tc.wantTS.IsZero() && !e.Timestamp.Equal(tc.wantTS) {
				t.Errorf("ts = %s, want %s", e.Timestamp, tc.wantTS)
			}
			if e.Source != "kmsg" {
				t.Errorf("src = %q", e.Source)
			}
			if e.Process != "kernel" {
				t.Errorf("proc = %q, want kernel", e.Process)
			}
		})
	}
}

func BenchmarkKMsg_Parse(b *testing.B) {
	p := mustKMsg(b)
	line := "6,500,1234567890,-;ACPI: Power Button [PWRB] event observed"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.Parse(line)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzKMsg_Parse(f *testing.F) {
	p, err := NewKMsg(KMsgConfig{BootTime: kmsgBoot})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"6,500,1234567,-;hi",
		"4,12,7000,c;cont",
		"",
		";",
		strings.Repeat(",", 16),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = p.Parse(line)
	})
}
