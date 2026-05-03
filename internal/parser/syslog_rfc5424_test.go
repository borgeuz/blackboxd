package parser

import (
	"strings"
	"testing"
	"time"
)

func mustRFC5424(t testing.TB) Parser {
	t.Helper()
	p, err := NewSyslogRFC5424(SyslogRFC5424Config{})
	if err != nil {
		t.Fatalf("NewSyslogRFC5424: %v", err)
	}
	return p
}

func TestSyslogRFC5424_Parse(t *testing.T) {
	t.Parallel()
	p := mustRFC5424(t)

	cases := []struct {
		name      string
		line      string
		wantHost  string
		wantApp   string
		wantPID   int
		wantLevel Level
		wantMsg   string
		wantSD    string
		wantErr   bool
	}{
		{
			name:      "rfc5424-example1",
			line:      `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8`,
			wantHost:  "mymachine.example.com",
			wantApp:   "su",
			wantPID:   0,
			wantLevel: LevelCritical,
			wantMsg:   "BOM'su root' failed for lonvick on /dev/pts/8",
		},
		{
			name:      "with-pid",
			line:      `<13>1 2026-05-01T12:00:00Z host svc 1234 - - hello world`,
			wantHost:  "host",
			wantApp:   "svc",
			wantPID:   1234,
			wantLevel: LevelNotice,
			wantMsg:   "hello world",
		},
		{
			name:      "structured-data-only",
			line:      `<165>1 2026-05-01T12:00:00.000003+02:00 mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="App"] An event`,
			wantHost:  "mymachine.example.com",
			wantApp:   "evntslog",
			wantLevel: LevelNotice,
			wantMsg:   "An event",
			wantSD:    `[exampleSDID@32473 iut="3" eventSource="App"]`,
		},
		{
			name:      "multiple-sd-blocks",
			line:      `<165>1 2026-05-01T12:00:00Z h app - - [a@1 k="v"][b@1 k="w"] msg`,
			wantHost:  "h",
			wantApp:   "app",
			wantLevel: LevelNotice,
			wantMsg:   "msg",
			wantSD:    `[a@1 k="v"][b@1 k="w"]`,
		},
		{
			name:      "all-nil-fields",
			line:      `<13>1 - - - - - - just a message`,
			wantLevel: LevelNotice,
			wantMsg:   "just a message",
		},
		{
			name:      "bom-stripped",
			line:      "<13>1 2026-05-01T12:00:00Z h app - - - \xef\xbb\xbfhello",
			wantHost:  "h",
			wantApp:   "app",
			wantLevel: LevelNotice,
			wantMsg:   "hello",
		},
		{
			name:      "empty-msg",
			line:      `<13>1 2026-05-01T12:00:00Z h app - - -`,
			wantHost:  "h",
			wantApp:   "app",
			wantLevel: LevelNotice,
			wantMsg:   "",
		},
		{
			name:    "missing-priority",
			line:    `1 - - - - - - msg`,
			wantErr: true,
		},
		{
			name:    "bad-timestamp",
			line:    `<13>1 not-a-timestamp h app - - msg`,
			wantErr: true,
		},
		{
			name:    "empty",
			line:    "",
			wantErr: true,
		},
		{
			name:    "unterminated-sd",
			line:    `<13>1 - - - - - [oops msg`,
			wantErr: true,
		},
		{
			name:      "escaped-quote-in-sd",
			line:      `<13>1 - h app - - [id@1 k="he said \"hi\""] msg`,
			wantHost:  "h",
			wantApp:   "app",
			wantLevel: LevelNotice,
			wantMsg:   "msg",
			wantSD:    `[id@1 k="he said \"hi\""]`,
		},
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
			if e.Hostname != tc.wantHost {
				t.Errorf("host = %q, want %q", e.Hostname, tc.wantHost)
			}
			if e.Process != tc.wantApp {
				t.Errorf("proc = %q, want %q", e.Process, tc.wantApp)
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
			if tc.wantSD != "" {
				if e.Fields["structured_data"] != tc.wantSD {
					t.Errorf("sd = %q, want %q", e.Fields["structured_data"], tc.wantSD)
				}
			}
		})
	}
}

func TestSyslogRFC5424_TimestampFormats(t *testing.T) {
	t.Parallel()
	p := mustRFC5424(t)

	for _, tc := range []struct {
		line string
		want time.Time
	}{
		{`<13>1 2026-05-01T12:00:00Z h - - - - msg`, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
		{`<13>1 2026-05-01T12:00:00.123456Z h - - - - msg`, time.Date(2026, 5, 1, 12, 0, 0, 123456000, time.UTC)},
	} {
		e, err := p.Parse(tc.line)
		if err != nil {
			t.Fatalf("%s: %v", tc.line, err)
		}
		if !e.Timestamp.Equal(tc.want) {
			t.Errorf("ts = %s, want %s", e.Timestamp, tc.want)
		}
	}
}

func BenchmarkSyslogRFC5424_Parse(b *testing.B) {
	p := mustRFC5424(b)
	line := `<165>1 2026-05-01T12:00:00.000003+02:00 host evntslog 1234 ID47 [exampleSDID@32473 iut="3" eventSource="App"] An event happened`

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.Parse(line)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzSyslogRFC5424_Parse(f *testing.F) {
	p, err := NewSyslogRFC5424(SyslogRFC5424Config{})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		`<13>1 2026-05-01T12:00:00Z h app - - msg`,
		`<165>1 - - - - - [a@1 k="v"] hi`,
		"",
		"<>",
		strings.Repeat("[", 64),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = p.Parse(line)
	})
}
