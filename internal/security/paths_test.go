package security

import (
	"errors"
	"strings"
	"testing"
)

func TestCanonicalizePath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"empty", "", "", true},
		{"relative", "var/log/messages", "", true},
		{"traversal-absolute", "/var/log/../../etc/passwd", "/etc/passwd", false}, // collapsed by Clean to a different but absolute path
		{"traversal-relative", "../../etc/passwd", "", true},
		{"plain-absolute", "/var/log/messages", "/var/log/messages", false},
		{"redundant-slashes", "/var//log///messages", "/var/log/messages", false},
		{"trailing-slash", "/var/log/", "/var/log", false},
		{"dot", "/var/log/./messages", "/var/log/messages", false},
		{"root", "/", "/", false},
		{"just-dotdot", "..", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalizePath(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil; result=%q", got)
				}
				if !errors.Is(err, ErrInsecure) {
					t.Fatalf("error not wrapping ErrInsecure: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckUnderAllowlist(t *testing.T) {
	t.Parallel()

	prefixes := []string{"/var/log", "/var/lib/blackboxd", "/dev/kmsg"}

	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"exact-match-file", "/dev/kmsg", false},
		{"descendant", "/var/log/messages", false},
		{"deep-descendant", "/var/log/journal/system.journal", false},
		{"sibling-confusion", "/var/log2/messages", true},
		{"unrelated", "/etc/passwd", true},
		{"prefix-as-substring-trap", "/var/lib/blackboxdfake/data", true},
		{"empty-prefix-list", "/var/log/messages", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := prefixes
			if tc.name == "empty-prefix-list" {
				ps = nil
			}
			err := CheckUnderAllowlist(tc.in, ps)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrInsecure) {
					t.Fatalf("error not wrapping ErrInsecure: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePath_Combined(t *testing.T) {
	t.Parallel()

	cleaned, err := ValidatePath("/var/log//messages", DefaultAllowedPrefixes)
	if err != nil {
		t.Fatalf("ValidatePath: %v", err)
	}
	if cleaned != "/var/log/messages" {
		t.Fatalf("got %q, want /var/log/messages", cleaned)
	}

	if _, err := ValidatePath("/etc/passwd", DefaultAllowedPrefixes); err == nil {
		t.Fatalf("expected rejection of /etc/passwd")
	} else if !strings.Contains(err.Error(), "not under any allowed prefix") {
		t.Fatalf("unexpected error: %v", err)
	}
}
