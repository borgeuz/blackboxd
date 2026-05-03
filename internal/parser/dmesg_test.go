package parser

import (
	"strings"
	"testing"
	"time"
)

var dmesgBoot = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func mustDmesg(t testing.TB) Parser {
	t.Helper()
	p, err := NewDmesg(DmesgConfig{BootTime: dmesgBoot})
	if err != nil {
		t.Fatalf("NewDmesg: %v", err)
	}
	return p
}

func TestDmesg_Parse(t *testing.T) {
	t.Parallel()
	p := mustDmesg(t)

	cases := []struct {
		name    string
		line    string
		wantMsg string
		wantTS  time.Time
		wantErr bool
	}{
		{
			name:    "legacy-uptime",
			line:    "[    1.234567] usb 1-1: high-speed USB device",
			wantMsg: "usb 1-1: high-speed USB device",
			wantTS:  dmesgBoot.Add(1234567 * time.Microsecond),
		},
		{
			name:    "legacy-zero",
			line:    "[    0.000000] Linux version 6.1",
			wantMsg: "Linux version 6.1",
			wantTS:  dmesgBoot,
		},
		{
			name:    "legacy-large",
			line:    "[12345.678901] late event",
			wantMsg: "late event",
			wantTS:  dmesgBoot.Add(time.Duration(12345.678901 * float64(time.Second))),
		},
		{
			name:    "iso-format",
			line:    "[2026-04-01T12:00:00,123456+0000] hello iso",
			wantMsg: "hello iso",
			wantTS:  time.Date(2026, 4, 1, 12, 0, 0, 123456000, time.UTC),
		},
		{
			name:    "iso-format-with-offset",
			line:    "[2026-04-01T14:00:00,000000+0200] tz aware",
			wantMsg: "tz aware",
			wantTS:  time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:    "extra-whitespace",
			line:    "[    2.345678]   spaced",
			wantMsg: "spaced",
			wantTS:  dmesgBoot.Add(time.Duration(2.345678 * float64(time.Second))),
		},
		{name: "no-bracket", line: "no leading bracket", wantErr: true},
		{name: "unterminated-bracket", line: "[12.345 nope", wantErr: true},
		{name: "non-numeric-uptime", line: "[notanum] hello", wantErr: true},
		{name: "uptime-overflow", line: "[1e30] hello", wantErr: true},
		{name: "uptime-nan", line: "[NaN] hello", wantErr: true},
		{name: "empty", line: "", wantErr: true},
		{name: "empty-bracket", line: "[] hello", wantErr: true},
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
			if e.Message != tc.wantMsg {
				t.Errorf("msg = %q, want %q", e.Message, tc.wantMsg)
			}
			if !e.Timestamp.Equal(tc.wantTS) {
				t.Errorf("ts = %s, want %s", e.Timestamp, tc.wantTS)
			}
			if e.Source != "dmesg" {
				t.Errorf("src = %q", e.Source)
			}
		})
	}
}

func BenchmarkDmesg_Parse(b *testing.B) {
	p := mustDmesg(b)
	line := "[12345.678901] usb 1-1: new low-speed USB device number 5 using ehci-pci"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.Parse(line)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzDmesg_Parse(f *testing.F) {
	p, err := NewDmesg(DmesgConfig{BootTime: dmesgBoot})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"[1.234] hello",
		"[2026-04-01T12:00:00,123456+0000] iso",
		"[]",
		"",
		strings.Repeat("[", 32),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = p.Parse(line)
	})
}
