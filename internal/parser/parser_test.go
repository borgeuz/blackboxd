package parser

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLevel_String(t *testing.T) {
	t.Parallel()
	cases := map[Level]string{
		LevelEmergency: "emerg",
		LevelAlert:     "alert",
		LevelCritical:  "crit",
		LevelError:     "error",
		LevelWarning:   "warn",
		LevelNotice:    "notice",
		LevelInfo:      "info",
		LevelDebug:     "debug",
		Level(99):      "unknown",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestLevel_MarshalUnmarshal(t *testing.T) {
	t.Parallel()
	for _, l := range []Level{LevelEmergency, LevelError, LevelInfo, LevelDebug} {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatalf("marshal %v: %v", l, err)
		}
		var got Level
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if got != l {
			t.Errorf("round-trip: %v -> %s -> %v", l, b, got)
		}
	}
}

func TestLevel_Unmarshal_Numeric(t *testing.T) {
	t.Parallel()
	var l Level
	if err := json.Unmarshal([]byte(`"3"`), &l); err != nil {
		t.Fatalf("numeric unmarshal: %v", err)
	}
	if l != LevelError {
		t.Fatalf("3 -> %v, want LevelError", l)
	}
}

func TestLevel_Unmarshal_Unknown(t *testing.T) {
	t.Parallel()
	var l Level
	err := json.Unmarshal([]byte(`"chartreuse"`), &l)
	if err == nil {
		t.Fatalf("expected error for unknown level")
	}
}

// Regression: a single quote byte must not panic. UnmarshalJSON
// previously sliced b[1:0] when len(b)==1.
func TestLevel_Unmarshal_SingleQuoteNoPanic(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UnmarshalJSON panicked on single quote: %v", r)
		}
	}()
	var l Level
	if err := l.UnmarshalJSON([]byte(`"`)); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestLogEntry_MarshalJSON_OmitEmpty(t *testing.T) {
	t.Parallel()

	e := &LogEntry{
		Timestamp: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		Level:     LevelInfo,
		Message:   "hello",
		Source:    "test",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, banned := range []string{"facility", "host", "proc", "pid", "fields"} {
		if strings.Contains(s, `"`+banned+`"`) {
			t.Errorf("output contains %q despite omitempty: %s", banned, s)
		}
	}
	for _, required := range []string{`"ts"`, `"level":"info"`, `"msg":"hello"`, `"src":"test"`} {
		if !strings.Contains(s, required) {
			t.Errorf("output missing %q: %s", required, s)
		}
	}
}

func TestLogEntry_SanitizeUTF8(t *testing.T) {
	t.Parallel()

	bad := "before\xff\xfeafter"
	e := &LogEntry{Message: bad}
	e.SanitizeUTF8()
	if strings.Contains(e.Message, "\xff") || strings.Contains(e.Message, "\xfe") {
		t.Fatalf("invalid bytes survived sanitisation: %q", e.Message)
	}
	if !strings.Contains(e.Message, "before") || !strings.Contains(e.Message, "after") {
		t.Fatalf("valid neighbours dropped: %q", e.Message)
	}

	good := "ciao mondo — niente di strano"
	e2 := &LogEntry{Message: good}
	e2.SanitizeUTF8()
	if e2.Message != good {
		t.Fatalf("valid input mutated: %q", e2.Message)
	}
}
