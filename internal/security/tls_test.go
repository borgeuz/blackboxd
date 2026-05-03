package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPKI is the artefact set returned by buildPKI: a CA + a leaf
// signed by it, plus the on-disk paths to PEM-encoded copies.
type testPKI struct {
	dir            string
	caCertPath     string
	leafCertPath   string
	leafKeyPath    string
	leafFingerprnt string // hex, no colons
}

// buildPKI generates a CA and a leaf cert in t.TempDir(), writes them
// to disk in the layout BuildClientTLS expects, and returns the paths
// plus the leaf's SHA-256 fingerprint.
//
// The certificates are minimal: ECDSA-P256, 1-day validity, no SANs.
// They are sufficient to exercise mTLS config construction but should
// never escape the test process.
func buildPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "blackboxd-test-CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "blackboxd-test-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}

	caCertPath := filepath.Join(dir, "ca.crt")
	writePEM(t, caCertPath, "CERTIFICATE", caDER, 0o644)

	leafCertPath := filepath.Join(dir, "leaf.crt")
	writePEM(t, leafCertPath, "CERTIFICATE", leafDER, 0o644)

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	leafKeyPath := filepath.Join(dir, "leaf.key")
	writePEM(t, leafKeyPath, "EC PRIVATE KEY", leafKeyDER, 0o600)

	leafParsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	fp := CertFingerprint(leafParsed)

	return testPKI{
		dir:            dir,
		caCertPath:     caCertPath,
		leafCertPath:   leafCertPath,
		leafKeyPath:    leafKeyPath,
		leafFingerprnt: hex.EncodeToString(fp),
	}
}

func writePEM(t *testing.T, path, blockType string, der []byte, mode os.FileMode) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemBytes, mode); err != nil {
		t.Fatalf("write PEM %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod PEM %s: %v", path, err)
	}
}

func TestBuildClientTLS_HappyPath(t *testing.T) {
	t.Parallel()
	pki := buildPKI(t)

	cfg, err := BuildClientTLS(TLSOptions{
		CACertPath:     pki.caCertPath,
		ClientCertPath: pki.leafCertPath,
		ClientKeyPath:  pki.leafKeyPath,
		ServerName:     "broker.example",
	})
	if err != nil {
		t.Fatalf("BuildClientTLS: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2 (%x)", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify must be false")
	}
	if cfg.RootCAs == nil {
		t.Fatalf("RootCAs must be non-nil (we never fall back to system store)")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(cfg.Certificates))
	}
	if cfg.ServerName != "broker.example" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if cfg.VerifyConnection != nil {
		t.Fatalf("VerifyConnection should be nil when no pin is configured")
	}
}

func TestBuildClientTLS_WithPin_Match(t *testing.T) {
	t.Parallel()
	pki := buildPKI(t)

	cfg, err := BuildClientTLS(TLSOptions{
		CACertPath:     pki.caCertPath,
		ClientCertPath: pki.leafCertPath,
		ClientKeyPath:  pki.leafKeyPath,
		BrokerCertPin:  pki.leafFingerprnt,
	})
	if err != nil {
		t.Fatalf("BuildClientTLS: %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatalf("VerifyConnection must be set when pin is configured")
	}

	// Simulate handshake: feed the leaf cert into the verifier.
	leafPEM, err := os.ReadFile(pki.leafCertPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if err := cfg.VerifyConnection(cs); err != nil {
		t.Fatalf("verifier rejected matching pin: %v", err)
	}
}

func TestBuildClientTLS_WithPin_Mismatch(t *testing.T) {
	t.Parallel()
	pki := buildPKI(t)

	// Use the leaf as our identity but pin a fingerprint that does
	// not match it (the CA's, in this case).
	caPEM, err := os.ReadFile(pki.caCertPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	wrongPin := hex.EncodeToString(CertFingerprint(caCert))

	cfg, err := BuildClientTLS(TLSOptions{
		CACertPath:     pki.caCertPath,
		ClientCertPath: pki.leafCertPath,
		ClientKeyPath:  pki.leafKeyPath,
		BrokerCertPin:  wrongPin,
	})
	if err != nil {
		t.Fatalf("BuildClientTLS: %v", err)
	}

	leafPEM, err := os.ReadFile(pki.leafCertPath)
	if err != nil {
		t.Fatal(err)
	}
	leafBlock, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

	err = cfg.VerifyConnection(cs)
	if err == nil {
		t.Fatalf("expected pin mismatch rejection")
	}
	if !errors.Is(err, ErrInsecure) {
		t.Fatalf("error not wrapping ErrInsecure: %v", err)
	}
}

func TestBuildClientTLS_MissingPaths(t *testing.T) {
	t.Parallel()
	if _, err := BuildClientTLS(TLSOptions{}); err == nil {
		t.Fatalf("expected error for empty options")
	}
}

func TestBuildClientTLS_BadCABundle(t *testing.T) {
	t.Parallel()
	pki := buildPKI(t)

	bad := filepath.Join(pki.dir, "garbage.crt")
	if err := os.WriteFile(bad, []byte("not a PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildClientTLS(TLSOptions{
		CACertPath:     bad,
		ClientCertPath: pki.leafCertPath,
		ClientKeyPath:  pki.leafKeyPath,
	}); err == nil {
		t.Fatalf("expected error for bogus CA bundle")
	}
}
