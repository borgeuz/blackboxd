package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

const pinSize = sha256.Size

// ParsePin accepts both "aabbcc..." and the openssl-style
// "aa:bb:cc:..." form. Whitespace and case are ignored.
func ParsePin(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: empty pin", ErrInsecure)
	}
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ':', ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
	clean = strings.ToLower(clean)

	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: pin not hex: %v", ErrInsecure, err)
	}
	if len(b) != pinSize {
		return nil, fmt.Errorf("%w: pin is %d bytes, want %d", ErrInsecure, len(b), pinSize)
	}
	return b, nil
}

// CertFingerprint returns SHA-256 of cert.Raw — same value as
// `openssl x509 -fingerprint -sha256 -noout`, minus the colons.
func CertFingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

// MatchPin compares fingerprints in constant time.
func MatchPin(cert *x509.Certificate, want []byte) bool {
	return subtle.ConstantTimeCompare(CertFingerprint(cert), want) == 1
}
