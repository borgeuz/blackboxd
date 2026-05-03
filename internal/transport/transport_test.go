package transport

import (
	"strings"
	"testing"
)

func TestNewTopics(t *testing.T) {
	t.Parallel()
	tp, err := NewTopics("acme", "device-001")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(tp.Logs, "/logs") {
		t.Errorf("logs = %q", tp.Logs)
	}
	if !strings.Contains(tp.Status, "acme/device-001") {
		t.Errorf("status = %q", tp.Status)
	}
	if _, err := NewTopics("", "x"); err == nil {
		t.Errorf("expected error for empty tenant")
	}
}

func TestNormalizeBrokerURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"tls://broker.example:8883", false},
		{"ssl://broker.example:8883", false},
		{"mqtts://broker.example:8883", false},
		{"tcp://broker.example:1883", true},
		{"mqtt://broker.example:1883", true},
		{"http://broker.example", true},
		{"broker.example:8883", true}, // no scheme
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, err := normalizeBrokerURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
