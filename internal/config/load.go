package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/borgeuz/blackboxd/internal/parser"
	"github.com/borgeuz/blackboxd/internal/security"
)

// LoadOptions controls the strictness of Load.
type LoadOptions struct {
	// SkipFSChecks bypasses CheckConfigMode / CheckKeyMode /
	// CheckStateDirMode. Path canonicalisation and allowlist still run.
	// Used by tests that build a Config without on-disk fixtures.
	SkipFSChecks bool
}

// Load reads, parses and validates the config. The returned error
// either wraps security.ErrInsecure (refusal-to-start) or is a plain
// parse/validation error. Callers must os.Exit non-zero on error.
func Load(path string, opts LoadOptions) (*Config, error) {
	if !opts.SkipFSChecks {
		if err := security.CheckConfigMode(path); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	return Parse(data, opts)
}

// Parse decodes a TOML byte slice and validates the result. Lets tests
// embed configs as string literals.
func Parse(data []byte, opts LoadOptions) (*Config, error) {
	var c Config

	// Two passes: first into the typed Config, then into a generic map
	// to capture the per-parser free-form options block.
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		// Reject unknown top-level keys. Parser option subkeys live
		// under [parsers.NAME] and are routed manually below.
		var keys []string
		for _, k := range undecoded {
			if len(k) >= 2 && k[0] == "parsers" {
				continue
			}
			keys = append(keys, k.String())
		}
		if len(keys) > 0 {
			return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
		}
	}

	if err := decodeParserOptions(data, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	applyDefaults(&c)
	if err := c.Validate(opts); err != nil {
		return nil, err
	}
	return &c, nil
}

// decodeParserOptions makes a second pass with a generic map so each
// [parsers.NAME] block's free-form keys land in ParserConfig.Options.
// The strongly-typed pass alone would silently drop them.
func decodeParserOptions(data []byte, c *Config) error {
	var raw struct {
		Parsers map[string]map[string]any `toml:"parsers"`
	}
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return fmt.Errorf("decode parser options: %w", err)
	}
	if c.Parsers == nil {
		c.Parsers = map[string]ParserConfig{}
	}
	for name, opts := range raw.Parsers {
		// "type" is a typed field, not a factory option.
		t, _ := opts["type"].(string)
		delete(opts, "type")
		pc := c.Parsers[name]
		if pc.Type == "" {
			pc.Type = t
		}
		pc.Options = opts
		c.Parsers[name] = pc
	}
	return nil
}

// applyDefaults runs before Validate so the validator sees a fully
// populated struct, and tests can compare against the canonical defaults.
func applyDefaults(c *Config) {
	if c.Daemon.LogLevel == "" {
		c.Daemon.LogLevel = "info"
	}
	if c.Buffer.MaxEntries == 0 {
		c.Buffer.MaxEntries = 10_000
	}
	if c.Buffer.MaxBytes == 0 {
		c.Buffer.MaxBytes = 4 * 1024 * 1024
	}
	if c.Buffer.BatchSize == 0 {
		c.Buffer.BatchSize = 100
	}
	if c.Buffer.BatchInterval == 0 {
		c.Buffer.BatchInterval = Duration(5 * 1_000_000_000)
	}
	if c.Buffer.MaxLineBytes == 0 {
		c.Buffer.MaxLineBytes = 64 * 1024
	}
	if c.Spool.MaxSizeBytes == 0 {
		c.Spool.MaxSizeBytes = 100 * 1024 * 1024
	}
	if c.RateLimit.PerSourceLinesPerSec == 0 {
		c.RateLimit.PerSourceLinesPerSec = 10_000
	}
	if c.Shutdown.Timeout == 0 {
		c.Shutdown.Timeout = Duration(10 * 1_000_000_000)
	}
	if c.Transport.QoSLogs == 0 {
		c.Transport.QoSLogs = 1
	}
}

// Validate checks every cross-cutting invariant. First violation
// returns; callers must not continue past a non-nil error.
func (c *Config) Validate(opts LoadOptions) error {
	if !IDPattern.MatchString(c.Daemon.DeviceID) {
		return fmt.Errorf("%w: daemon.device_id %q invalid (allowed: %s)",
			security.ErrInsecure, c.Daemon.DeviceID, IDPattern)
	}
	if !IDPattern.MatchString(c.Daemon.Tenant) {
		return fmt.Errorf("%w: daemon.tenant %q invalid (allowed: %s)",
			security.ErrInsecure, c.Daemon.Tenant, IDPattern)
	}
	if !validLogLevel(c.Daemon.LogLevel) {
		return fmt.Errorf("config: daemon.log_level %q is not one of debug/info/warn/error", c.Daemon.LogLevel)
	}

	allow := c.allowlist()

	if c.Daemon.StateDir != "" {
		if _, err := security.ValidatePath(c.Daemon.StateDir, allow); err != nil {
			return fmt.Errorf("config: daemon.state_dir: %w", err)
		}
		if !opts.SkipFSChecks {
			if err := security.CheckStateDirMode(c.Daemon.StateDir); err != nil {
				return fmt.Errorf("config: daemon.state_dir: %w", err)
			}
		}
	}

	if err := validateParsers(c); err != nil {
		return err
	}
	if err := validateSources(c, allow); err != nil {
		return err
	}
	return validateTransport(c, opts)
}

func validLogLevel(s string) bool {
	switch s {
	case "debug", "info", "warn", "error":
		return true
	}
	return false
}

func validateParsers(c *Config) error {
	if len(c.Parsers) == 0 {
		return fmt.Errorf("config: at least one [parsers.*] block is required")
	}
	known := parser.RegisteredNames()
	knownSet := map[string]bool{}
	for _, n := range known {
		knownSet[n] = true
	}
	for name, p := range c.Parsers {
		if p.Type == "" {
			return fmt.Errorf("config: parsers.%s.type is required", name)
		}
		if !knownSet[p.Type] {
			return fmt.Errorf("config: parsers.%s.type %q unknown (known: %v)",
				name, p.Type, known)
		}
	}
	return nil
}

func validateSources(c *Config, allow []string) error {
	for name, s := range c.Sources {
		if _, ok := c.Parsers[s.Parser]; !ok {
			return fmt.Errorf("config: sources.%s.parser %q not defined in [parsers.*]", name, s.Parser)
		}
		switch s.Type {
		case "file", "journal":
			if s.Path == "" {
				return fmt.Errorf("config: sources.%s.path is required for type=%s", name, s.Type)
			}
			if _, err := security.ValidatePath(s.Path, allow); err != nil {
				return fmt.Errorf("config: sources.%s.path: %w", name, err)
			}
		case "kmsg":
			// /dev/kmsg is implicit; the allowlist covers it.
		case "dmesg":
			return fmt.Errorf("config: sources.%s.type=dmesg is not supported in service mode (use one-shot)", name)
		case "":
			return fmt.Errorf("config: sources.%s.type is required", name)
		default:
			return fmt.Errorf("config: sources.%s.type %q unknown", name, s.Type)
		}
	}
	return nil
}

func validateTransport(c *Config, opts LoadOptions) error {
	t := c.Transport
	if t.MQTTBroker == "" {
		return errors.New("config: transport.mqtt_broker is required")
	}
	if !strings.HasPrefix(t.MQTTBroker, "tls://") && !strings.HasPrefix(t.MQTTBroker, "ssl://") &&
		!strings.HasPrefix(t.MQTTBroker, "mqtts://") {
		return fmt.Errorf("%w: transport.mqtt_broker %q must use tls://, ssl:// or mqtts://",
			security.ErrInsecure, t.MQTTBroker)
	}
	if t.ClientCert == "" || t.ClientKey == "" || t.CACert == "" {
		return fmt.Errorf("%w: transport requires client_cert, client_key, and ca_cert",
			security.ErrInsecure)
	}
	for _, p := range []string{t.ClientCert, t.ClientKey, t.CACert} {
		if _, err := security.CanonicalizePath(p); err != nil {
			return fmt.Errorf("config: transport TLS path: %w", err)
		}
	}
	if t.QoSLogs > 2 || t.QoSHeartbeat > 2 {
		return fmt.Errorf("config: QoS values must be 0..2 (logs=%d heartbeat=%d)", t.QoSLogs, t.QoSHeartbeat)
	}

	if !opts.SkipFSChecks {
		if err := security.CheckKeyMode(t.ClientKey); err != nil {
			return fmt.Errorf("config: transport.client_key: %w", err)
		}
		// Cert and CA are public material — just verify they're regular
		// readable files. Malformed PEM is caught later by the TLS builder.
		for _, p := range []string{t.ClientCert, t.CACert} {
			info, err := os.Stat(p)
			if err != nil {
				return fmt.Errorf("config: stat %q: %w", p, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("config: %q is not a regular file", p)
			}
		}
	}

	if t.BrokerCertPin != "" {
		if _, err := security.ParsePin(t.BrokerCertPin); err != nil {
			return fmt.Errorf("config: transport.broker_cert_pin: %w", err)
		}
	}
	return nil
}
