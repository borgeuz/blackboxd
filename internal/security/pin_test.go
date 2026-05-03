package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestParsePin(t *testing.T) {
	t.Parallel()

	const valid = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"plain-hex", valid, false},
		{"upper-hex", strings.ToUpper(valid), false},
		{"colon-separated", insertColons(valid), false},
		{"with-whitespace", " " + valid + "\n", false},
		{"empty", "", true},
		{"too-short", strings.Repeat("ab", 10), true},
		{"non-hex", strings.Repeat("zz", 32), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePin(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got bytes %x", got)
				}
				if !errors.Is(err, ErrInsecure) {
					t.Fatalf("error not wrapping ErrInsecure: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != pinSize {
				t.Fatalf("len=%d, want %d", len(got), pinSize)
			}
		})
	}
}

func TestMatchPin(t *testing.T) {
	t.Parallel()

	raw := []byte("synthetic-cert-bytes")
	sum := sha256.Sum256(raw)
	cert := &x509.Certificate{Raw: raw}

	if !MatchPin(cert, sum[:]) {
		t.Fatalf("expected match against own fingerprint")
	}

	other := sha256.Sum256([]byte("different"))
	if MatchPin(cert, other[:]) {
		t.Fatalf("expected mismatch")
	}
}

// insertColons turns "aabbcc..." into "aa:bb:cc:...". Used to exercise
// the openssl-style fingerprint format.
func insertColons(hexStr string) string {
	// validate it's even length first
	if _, err := hex.DecodeString(hexStr); err != nil {
		panic(err)
	}
	var b strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}
