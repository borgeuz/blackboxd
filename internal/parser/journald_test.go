package parser

import (
	"strings"
	"testing"
	"time"
)

func mustJournald(t testing.TB) Parser {
	t.Helper()
	p, err := NewJournald(JournaldConfig{})
	if err != nil {
		t.Fatalf("NewJournald: %v", err)
	}
	return p
}

func TestJournald_Parse(t *testing.T) {
	t.Parallel()
	p := mustJournald(t)

	cases := []struct {
		name      string
		record    string
		wantHost  string
		wantProc  string
		wantPID   int
		wantLevel Level
		wantFac   int
		wantMsg   string
		wantTS    time.Time
		wantField map[string]string
		wantErr   bool
	}{
		{
			name: "minimal",
			record: "MESSAGE=hello world\n" +
				"PRIORITY=6\n" +
				"_HOSTNAME=host1\n" +
				"SYSLOG_IDENTIFIER=svc\n" +
				"_PID=1234\n" +
				"__REALTIME_TIMESTAMP=1714579200000000",
			wantHost:  "host1",
			wantProc:  "svc",
			wantPID:   1234,
			wantLevel: LevelInfo,
			wantMsg:   "hello world",
			wantTS:    time.Unix(1714579200, 0),
		},
		{
			name: "comm-fallback",
			record: "MESSAGE=hi\n" +
				"_COMM=fallbackproc\n" +
				"PRIORITY=4",
			wantProc:  "fallbackproc",
			wantLevel: LevelWarning,
			wantMsg:   "hi",
		},
		{
			name: "syslog-identifier-wins",
			record: "MESSAGE=hi\n" +
				"_COMM=cmd\n" +
				"SYSLOG_IDENTIFIER=identifier\n" +
				"PRIORITY=3",
			wantProc:  "identifier",
			wantLevel: LevelError,
			wantMsg:   "hi",
		},
		{
			name: "facility",
			record: "MESSAGE=hi\n" +
				"SYSLOG_FACILITY=3\n" +
				"PRIORITY=6",
			wantFac:   3,
			wantLevel: LevelInfo,
			wantMsg:   "hi",
		},
		{
			name: "extra-fields-collected",
			record: "MESSAGE=hi\n" +
				"_SYSTEMD_UNIT=foo.service\n" +
				"_BOOT_ID=abc",
			wantMsg: "hi",
			wantField: map[string]string{
				"_SYSTEMD_UNIT": "foo.service",
				"_BOOT_ID":      "abc",
			},
		},
		{
			name:    "blank",
			record:  "",
			wantErr: true,
		},
		{
			name:    "no-recognisable-fields",
			record:  "BARE=line",
			wantMsg: "",
			wantField: map[string]string{
				"BARE": "line",
			},
		},
		{
			name: "binary-field-bare-key-dropped",
			record: "MESSAGE=hi\n" +
				"BINARY\n" +
				"PRIORITY=6",
			wantMsg:   "hi",
			wantLevel: LevelInfo,
		},
		{
			name: "trailing-newline",
			record: "MESSAGE=hi\n" +
				"PRIORITY=6\n",
			wantMsg:   "hi",
			wantLevel: LevelInfo,
		},
		{
			name: "value-with-equals",
			record: "MESSAGE=foo=bar=baz\n" +
				"PRIORITY=6",
			wantMsg:   "foo=bar=baz",
			wantLevel: LevelInfo,
		},
		{
			name: "priority-out-of-range-ignored",
			record: "MESSAGE=hi\n" +
				"PRIORITY=99",
			wantMsg:   "hi",
			wantLevel: LevelEmergency, // default zero value, no severity assigned
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := p.Parse(tc.record)
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
			if e.Process != tc.wantProc {
				t.Errorf("proc = %q, want %q", e.Process, tc.wantProc)
			}
			if e.PID != tc.wantPID {
				t.Errorf("pid = %d, want %d", e.PID, tc.wantPID)
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
			for k, want := range tc.wantField {
				if got := e.Fields[k]; got != want {
					t.Errorf("Fields[%q] = %q, want %q", k, got, want)
				}
			}
			if e.Source != "journald" {
				t.Errorf("src = %q", e.Source)
			}
		})
	}
}

func BenchmarkJournald_Parse(b *testing.B) {
	p := mustJournald(b)
	rec := "MESSAGE=Started Daily Cleanup of Temporary Directories.\n" +
		"PRIORITY=6\n" +
		"_HOSTNAME=host\n" +
		"SYSLOG_IDENTIFIER=systemd\n" +
		"_PID=1\n" +
		"__REALTIME_TIMESTAMP=1714579200123456\n" +
		"_SYSTEMD_UNIT=systemd-tmpfiles-clean.service"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.Parse(rec)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzJournald_Parse(f *testing.F) {
	p, err := NewJournald(JournaldConfig{})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"MESSAGE=hi\nPRIORITY=6",
		"_HOSTNAME=h",
		"",
		"=",
		strings.Repeat("a=b\n", 16),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rec string) {
		_, _ = p.Parse(rec)
	})
}
