// Package config decodes and validates the blackboxd TOML config.
// Parsing (bytes → struct) and validation (struct → safe-to-run) are
// kept separate so tests can drive Validate with hand-built Configs.
package config

import (
	"fmt"
	"regexp"
	"time"

	"github.com/borgeuz/blackboxd/internal/security"
)

// Config is the top-level schema. The example file at
// configs/blackboxd.example.toml mirrors it.
type Config struct {
	Daemon    DaemonConfig            `toml:"daemon"`
	Sources   map[string]SourceConfig `toml:"sources"`
	Parsers   map[string]ParserConfig `toml:"parsers"`
	Transport TransportConfig         `toml:"transport"`
	Buffer    BufferConfig            `toml:"buffer"`
	Spool     SpoolConfig             `toml:"spool"`
	RateLimit RateLimitConfig         `toml:"rate_limit"`
	Shutdown  ShutdownConfig          `toml:"shutdown"`

	// AllowedPathPrefixes overrides security.DefaultAllowedPrefixes
	// for source-path validation. Operators tweaking this should know
	// they are widening the daemon's filesystem reach.
	AllowedPathPrefixes []string `toml:"allowed_path_prefixes"`
}

// DaemonConfig holds process-level identity and operational knobs.
type DaemonConfig struct {
	// DeviceID identifies this device in the fleet (used in MQTT
	// topics). Required. Charset: [A-Za-z0-9_-], length 1..64.
	DeviceID string `toml:"device_id"`

	// Tenant is the customer/organisation namespace. Required, same
	// charset as DeviceID.
	Tenant string `toml:"tenant"`

	// StateDir holds offset files and the spool. Must exist as 0700
	// owned by the daemon user.
	StateDir string `toml:"state_dir"`

	// LogLevel for the daemon's own slog output: debug, info, warn,
	// error. Default "info".
	LogLevel string `toml:"log_level"`
}

// SourceConfig describes one log input. Fields are a union over all
// source types; only the ones relevant to Type are read.
type SourceConfig struct {
	// Type: "file", "kmsg", "journal". "dmesg" is one-shot only and
	// is rejected here.
	Type string `toml:"type"`

	// Parser is the [parsers.*] key whose factory output applies to
	// this source's lines.
	Parser string `toml:"parser"`

	// Path is required for type=file (single file or glob) and
	// type=journal (journal directory). Ignored for type=kmsg.
	Path string `toml:"path"`

	// FromBeginning ignores any persisted offset on every restart.
	FromBeginning bool `toml:"from_beginning"`

	// FollowRotation enables logrotate-style rotation handling for
	// type=file. Default true.
	FollowRotation bool `toml:"follow_rotation"`

	// FollowSymlinks must be set explicitly to allow opening a symlink.
	FollowSymlinks bool `toml:"follow_symlinks"`

	// Units restricts a journal source to specific systemd units.
	Units []string `toml:"units"`

	// MinPriority restricts a journal source to entries at or above
	// the given severity (0=emerg .. 7=debug). 0 = no filter.
	MinPriority int `toml:"min_priority"`
}

// ParserConfig identifies a registered factory and the free-form
// options the factory consumes.
type ParserConfig struct {
	Type    string         `toml:"type"`
	Options map[string]any `toml:"-"` // populated by the second decode pass
}

// TransportConfig holds the MQTT broker URL, mTLS materials and
// topic options.
type TransportConfig struct {
	// MQTTBroker, e.g. "tls://broker.example:8883". Plaintext schemes
	// (tcp://, mqtt://) are rejected at validation.
	MQTTBroker string `toml:"mqtt_broker"`

	// mTLS identity: client cert + private key.
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`

	// CACert is the PEM bundle that validates the broker.
	CACert string `toml:"ca_cert"`

	// BrokerCertPin, when set, asserts the broker leaf SHA-256
	// fingerprint at handshake time. Optional.
	BrokerCertPin string `toml:"broker_cert_pin"`

	QoSLogs      uint8 `toml:"qos_logs"`      // default 1
	QoSHeartbeat uint8 `toml:"qos_heartbeat"` // default 0

	// HeartbeatInterval, zero = disabled.
	HeartbeatInterval Duration `toml:"heartbeat_interval"`
}

// BufferConfig sizes the in-memory ring and batcher.
type BufferConfig struct {
	MaxEntries    int      `toml:"max_entries"`    // default 10_000
	MaxBytes      int      `toml:"max_bytes"`      // default 4 MiB
	BatchSize     int      `toml:"batch_size"`     // default 100
	BatchInterval Duration `toml:"batch_interval"` // default 5s
	MaxLineBytes  int      `toml:"max_line_bytes"` // default 64 KiB
}

// SpoolConfig sizes the on-disk fallback used when MQTT is down.
type SpoolConfig struct {
	MaxSizeBytes int64 `toml:"max_size_bytes"` // default 100 MiB
}

// RateLimitConfig caps lines/sec per source via a token bucket.
type RateLimitConfig struct {
	PerSourceLinesPerSec int `toml:"per_source_lines_per_sec"` // default 10_000
}

// ShutdownConfig caps graceful shutdown time.
type ShutdownConfig struct {
	Timeout Duration `toml:"timeout"` // default 10s
}

// Duration wraps time.Duration with a TOML text decoder so the value
// can be written as "5s", "100ms", etc.
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("config: parse duration %q: %w", string(text), err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) AsDuration() time.Duration { return time.Duration(d) }

// IDPattern: device_id and tenant must match. Letters, digits,
// underscore, hyphen; length 1..64.
var IDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (c *Config) allowlist() []string {
	if len(c.AllowedPathPrefixes) == 0 {
		return security.DefaultAllowedPrefixes
	}
	return c.AllowedPathPrefixes
}
