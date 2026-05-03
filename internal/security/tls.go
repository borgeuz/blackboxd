package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSOptions are the inputs to BuildClientTLS. CACertPath, ClientCertPath
// and ClientKeyPath are required. BrokerCertPin and ServerName are optional.
type TLSOptions struct {
	// CACertPath is the PEM bundle that validates the broker. The
	// system CA store is not consulted — concatenate it in here if needed.
	CACertPath string

	ClientCertPath string
	ClientKeyPath  string

	// BrokerCertPin, when set, must match the leaf SHA-256 at
	// handshake time regardless of CA validation. Hex, optional colons.
	BrokerCertPin string

	ServerName string // SNI; required for hostname validation
}

// BuildClientTLS returns an mTLS config: TLS 1.2+, only the configured
// CA in RootCAs, client cert presented, optional pin enforcement.
// InsecureSkipVerify is never set.
func BuildClientTLS(opt TLSOptions) (*tls.Config, error) {
	if opt.CACertPath == "" || opt.ClientCertPath == "" || opt.ClientKeyPath == "" {
		return nil, fmt.Errorf("%w: TLS paths incomplete (ca=%q cert=%q key=%q)",
			ErrInsecure, opt.CACertPath, opt.ClientCertPath, opt.ClientKeyPath)
	}

	caPEM, err := os.ReadFile(opt.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read CA bundle %q: %v", ErrInsecure, opt.CACertPath, err)
	}
	defer zero(caPEM)

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: CA bundle %q contains no valid certificates",
			ErrInsecure, opt.CACertPath)
	}

	certPEM, err := os.ReadFile(opt.ClientCertPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read client cert %q: %v", ErrInsecure, opt.ClientCertPath, err)
	}
	defer zero(certPEM)

	keyPEM, err := os.ReadFile(opt.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read client key %q: %v", ErrInsecure, opt.ClientKeyPath, err)
	}
	defer zero(keyPEM)

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: parse client cert/key: %v", ErrInsecure, err)
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   opt.ServerName,
	}

	if opt.BrokerCertPin != "" {
		pin, err := ParsePin(opt.BrokerCertPin)
		if err != nil {
			return nil, fmt.Errorf("parse broker pin: %w", err)
		}
		cfg.VerifyConnection = pinVerifier(pin)
	}

	return cfg, nil
}

// pinVerifier runs after the standard chain verification (since
// InsecureSkipVerify is off), so it acts in addition to — not instead
// of — CA validation.
func pinVerifier(want []byte) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("%w: peer presented no certificate", ErrInsecure)
		}
		if !MatchPin(cs.PeerCertificates[0], want) {
			return fmt.Errorf("%w: broker leaf cert fingerprint mismatch", ErrInsecure)
		}
		return nil
	}
}

// zero scrubs PEM buffers after parsing. The compiler does not
// optimise this out today because the slice escapes via the read.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
