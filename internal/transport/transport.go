// Package transport ships log batches over MQTT with mTLS, and
// provides the disk spool fallback (spool.go).
//
// Topic structure:
//
//	blackbox/v1/{tenant}/{device_id}/logs
//	blackbox/v1/{tenant}/{device_id}/status      (retained, LWT)
//	blackbox/v1/{tenant}/{device_id}/heartbeat
//	blackbox/v1/{tenant}/{device_id}/metrics
//
// The device publishes only; there is no Subscribe path. This
// eliminates the remote-code-execution surface entirely.
package transport

import (
	"context"
	"fmt"
)

// Publisher hides MQTT specifics from upper layers and lets tests
// substitute in-memory implementations.
type Publisher interface {
	// Publish blocks until acknowledged (QoS 1 = until PUBACK). The
	// caller decides whether to retry or spool on error.
	Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error

	// Close disconnects, flushing in-flight publishes within ctx.
	Close(ctx context.Context) error
}

// Topics is the per-device topic set derived from {tenant}/{device_id}.
type Topics struct {
	Logs      string
	Status    string
	Heartbeat string
	Metrics   string
}

func NewTopics(tenant, deviceID string) (Topics, error) {
	if tenant == "" || deviceID == "" {
		return Topics{}, fmt.Errorf("transport: tenant and device_id required")
	}
	base := fmt.Sprintf("blackbox/v1/%s/%s", tenant, deviceID)
	return Topics{
		Logs:      base + "/logs",
		Status:    base + "/status",
		Heartbeat: base + "/heartbeat",
		Metrics:   base + "/metrics",
	}, nil
}
