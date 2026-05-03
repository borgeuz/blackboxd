package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/borgeuz/blackboxd/internal/security"
)

// minimalValid returns a TOML body that decodes-and-validates with
// SkipFSChecks=true. It exercises every required block.
func minimalValid() string {
	return `
[daemon]
device_id = "device-001"
tenant = "acme"

[parsers.bsd]
type = "syslog_bsd"

[sources.system]
type = "file"
path = "/var/log/messages"
parser = "bsd"

[transport]
mqtt_broker = "tls://broker.example:8883"
client_cert = "/var/lib/blackboxd/cert.pem"
client_key  = "/var/lib/blackboxd/key.pem"
ca_cert     = "/var/lib/blackboxd/ca.pem"
heartbeat_interval = "30s"
`
}

func TestParse_Minimal(t *testing.T) {
	t.Parallel()
	c, err := Parse([]byte(minimalValid()), LoadOptions{SkipFSChecks: true})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Daemon.DeviceID != "device-001" {
		t.Errorf("device_id = %q", c.Daemon.DeviceID)
	}
	if c.Buffer.MaxEntries != 10_000 {
		t.Errorf("default max_entries = %d, want 10000", c.Buffer.MaxEntries)
	}
	if c.Spool.MaxSizeBytes != 100*1024*1024 {
		t.Errorf("default spool max = %d", c.Spool.MaxSizeBytes)
	}
	if c.Shutdown.Timeout.AsDuration().Seconds() != 10 {
		t.Errorf("default shutdown timeout = %s", c.Shutdown.Timeout.AsDuration())
	}
}

func TestParse_RejectsBadDeviceID(t *testing.T) {
	t.Parallel()
	body := strings.Replace(minimalValid(), `device_id = "device-001"`, `device_id = "bad/id"`, 1)
	_, err := Parse([]byte(body), LoadOptions{SkipFSChecks: true})
	if err == nil {
		t.Fatalf("expected validation error for bad device_id")
	}
	if !errors.Is(err, security.ErrInsecure) {
		t.Fatalf("expected ErrInsecure, got %v", err)
	}
}

func TestParse_RejectsPlaintextBroker(t *testing.T) {
	t.Parallel()
	body := strings.Replace(minimalValid(),
		`mqtt_broker = "tls://broker.example:8883"`,
		`mqtt_broker = "tcp://broker.example:1883"`, 1)
	_, err := Parse([]byte(body), LoadOptions{SkipFSChecks: true})
	if err == nil || !errors.Is(err, security.ErrInsecure) {
		t.Fatalf("expected ErrInsecure for plaintext broker, got %v", err)
	}
}

func TestParse_RejectsUnknownParserRef(t *testing.T) {
	t.Parallel()
	body := strings.Replace(minimalValid(), `parser = "bsd"`, `parser = "ghost"`, 1)
	_, err := Parse([]byte(body), LoadOptions{SkipFSChecks: true})
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("expected error referencing missing parser, got %v", err)
	}
}

func TestParse_RejectsUnknownParserType(t *testing.T) {
	t.Parallel()
	body := strings.Replace(minimalValid(), `type = "syslog_bsd"`, `type = "fictional"`, 1)
	_, err := Parse([]byte(body), LoadOptions{SkipFSChecks: true})
	if err == nil || !strings.Contains(err.Error(), "fictional") {
		t.Fatalf("expected error referencing unknown parser type, got %v", err)
	}
}

func TestParse_RejectsBadPath(t *testing.T) {
	t.Parallel()
	body := strings.Replace(minimalValid(), `/var/log/messages`, `/etc/passwd`, 1)
	_, err := Parse([]byte(body), LoadOptions{SkipFSChecks: true})
	if err == nil || !errors.Is(err, security.ErrInsecure) {
		t.Fatalf("expected allowlist rejection, got %v", err)
	}
}

func TestParse_DmesgInServiceMode(t *testing.T) {
	t.Parallel()
	body := strings.Replace(minimalValid(),
		`type = "file"
path = "/var/log/messages"
parser = "bsd"`,
		`type = "dmesg"
parser = "bsd"`, 1)
	_, err := Parse([]byte(body), LoadOptions{SkipFSChecks: true})
	if err == nil || !strings.Contains(err.Error(), "dmesg") {
		t.Fatalf("expected dmesg-in-service rejection, got %v", err)
	}
}

func TestParse_ParserOptionsRoundTrip(t *testing.T) {
	t.Parallel()
	body := minimalValid() + `
default_year = 2026
timezone = "UTC"
strict = true

[parsers.bsd]
`
	// The trailing [parsers.bsd] is a no-op; we want the option keys
	// to stick to the existing block above. Use explicit syntax instead.
	body = `
[daemon]
device_id = "device-001"
tenant = "acme"

[parsers.bsd]
type = "syslog_bsd"
default_year = 2026
timezone = "UTC"
strict = true

[sources.system]
type = "file"
path = "/var/log/messages"
parser = "bsd"

[transport]
mqtt_broker = "tls://broker.example:8883"
client_cert = "/var/lib/blackboxd/cert.pem"
client_key  = "/var/lib/blackboxd/key.pem"
ca_cert     = "/var/lib/blackboxd/ca.pem"
`
	c, err := Parse([]byte(body), LoadOptions{SkipFSChecks: true})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	opts := c.Parsers["bsd"].Options
	if opts["timezone"] != "UTC" {
		t.Errorf("opts[timezone] = %v", opts["timezone"])
	}
	if opts["default_year"] != int64(2026) {
		t.Errorf("opts[default_year] = %v (%T)", opts["default_year"], opts["default_year"])
	}
	if opts["strict"] != true {
		t.Errorf("opts[strict] = %v", opts["strict"])
	}
}

func TestLoad_RejectsWorldWritableConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "world-writable.toml")
	if err := os.WriteFile(p, []byte(minimalValid()), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p, LoadOptions{SkipFSChecks: false})
	if err == nil {
		t.Fatalf("expected refusal for world-writable config")
	}
	if !errors.Is(err, security.ErrInsecure) {
		t.Fatalf("expected ErrInsecure, got %v", err)
	}
}

func TestLoad_AcceptsRegularConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "ok.toml")
	if err := os.WriteFile(p, []byte(minimalValid()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	// We still skip FS checks for cert paths since the test fixtures
	// don't include them on disk.
	_, err := Load(p, LoadOptions{SkipFSChecks: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestDuration_Unmarshal(t *testing.T) {
	t.Parallel()
	var d Duration
	if err := d.UnmarshalText([]byte("250ms")); err != nil {
		t.Fatal(err)
	}
	if d.AsDuration().Milliseconds() != 250 {
		t.Errorf("got %s", d.AsDuration())
	}
	if err := d.UnmarshalText([]byte("not-a-duration")); err == nil {
		t.Fatalf("expected error")
	}
}
