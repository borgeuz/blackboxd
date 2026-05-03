package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

// MQTTPublisherConfig drives NewMQTTPublisher. The TLS config is
// pre-built (see security.BuildClientTLS) so this layer doesn't deal
// with CA paths or pinning.
type MQTTPublisherConfig struct {
	BrokerURL string      // tls://host:port (or ssl://, mqtts://)
	TLSConfig *tls.Config // hardened mTLS config
	ClientID  string      // typically "{tenant}-{device_id}"

	StatusTopic    string
	OfflinePayload []byte // LWT, e.g. {"online":false}
	OnlinePayload  []byte // published on (re)connect, e.g. {"online":true}
	StatusQoS      byte
	StatusRetain   bool

	KeepAlive         time.Duration
	ConnectRetryDelay time.Duration
	ConnectTimeout    time.Duration

	Logger *slog.Logger
}

// MQTTPublisher wraps autopaho into the Publisher interface. autopaho
// handles reconnect, backoff and session management; we layer on the
// once-on-connect status publish and error wrapping.
type MQTTPublisher struct {
	cm  *autopaho.ConnectionManager
	cfg MQTTPublisherConfig
	log *slog.Logger
}

// NewMQTTPublisher returns once the initial connect attempt has been
// queued — the connect itself is asynchronous. Call AwaitConnection
// before publishing if the first publish must succeed synchronously.
func NewMQTTPublisher(ctx context.Context, cfg MQTTPublisherConfig) (*MQTTPublisher, error) {
	if cfg.BrokerURL == "" || cfg.TLSConfig == nil || cfg.ClientID == "" {
		return nil, errors.New("transport: broker URL, TLS config, and client ID required")
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = 30 * time.Second
	}
	// MQTT KeepAlive is uint16 seconds; clamp to its max to avoid silent truncation.
	if secs := cfg.KeepAlive.Seconds(); secs > 65535 {
		cfg.KeepAlive = 65535 * time.Second
	}
	if cfg.ConnectRetryDelay == 0 {
		cfg.ConnectRetryDelay = 10 * time.Second
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	u, err := normalizeBrokerURL(cfg.BrokerURL)
	if err != nil {
		return nil, err
	}

	pub := &MQTTPublisher{cfg: cfg, log: cfg.Logger.With("component", "mqtt")}

	pcfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{u},
		TlsCfg:                        cfg.TLSConfig,
		KeepAlive:                     uint16(cfg.KeepAlive.Seconds()),
		CleanStartOnInitialConnection: true,
		ConnectRetryDelay:             cfg.ConnectRetryDelay,
		ConnectTimeout:                cfg.ConnectTimeout,
		ClientConfig: paho.ClientConfig{
			ClientID: cfg.ClientID,
		},
		OnConnectionUp: func(cm *autopaho.ConnectionManager, _ *paho.Connack) {
			defer func() {
				if r := recover(); r != nil {
					pub.log.Error("panic in OnConnectionUp", "event_type", "security", "panic", r)
				}
			}()
			pub.log.Info("mqtt connected", "event_type", "security",
				"broker", cfg.BrokerURL)
			if cfg.StatusTopic != "" && len(cfg.OnlinePayload) > 0 {
				octx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				if _, err := cm.Publish(octx, &paho.Publish{
					Topic:   cfg.StatusTopic,
					Payload: cfg.OnlinePayload,
					QoS:     cfg.StatusQoS,
					Retain:  cfg.StatusRetain,
				}); err != nil {
					pub.log.Warn("status publish on connect failed", "err", err)
				}
			}
		},
		OnConnectError: func(err error) {
			pub.log.Warn("mqtt connect error", "event_type", "security", "err", err)
		},
	}

	if cfg.StatusTopic != "" && len(cfg.OfflinePayload) > 0 {
		pcfg.SetWillMessage(cfg.StatusTopic, cfg.OfflinePayload, cfg.StatusQoS, cfg.StatusRetain)
	}

	cm, err := autopaho.NewConnection(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("transport: autopaho.NewConnection: %w", err)
	}
	pub.cm = cm
	return pub, nil
}

func (p *MQTTPublisher) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	if p.cm == nil {
		return errors.New("transport: publisher not connected")
	}
	resp, err := p.cm.Publish(ctx, &paho.Publish{
		Topic:   topic,
		Payload: payload,
		QoS:     qos,
		Retain:  retain,
	})
	if err != nil {
		return fmt.Errorf("transport publish: %w", err)
	}
	if resp != nil && resp.ReasonCode >= 0x80 {
		// Properties is *PublishResponseProperties — may be nil for some
		// broker responses, especially QoS 0.
		var reason string
		if resp.Properties != nil {
			reason = resp.Properties.ReasonString
		}
		return fmt.Errorf("transport publish: broker reason 0x%02x %q", resp.ReasonCode, reason)
	}
	return nil
}

func (p *MQTTPublisher) Close(ctx context.Context) error {
	if p.cm == nil {
		return nil
	}
	return p.cm.Disconnect(ctx)
}

// AwaitConnection blocks until the autopaho client has a live session,
// or ctx fires.
func (p *MQTTPublisher) AwaitConnection(ctx context.Context) error {
	if p.cm == nil {
		return errors.New("transport: not initialised")
	}
	return p.cm.AwaitConnection(ctx)
}

// normalizeBrokerURL accepts tls/ssl/mqtts and rejects plaintext
// schemes. Defense in depth: config validation already rejects them,
// this is a second line.
func normalizeBrokerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("transport: parse broker URL %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "tls", "ssl", "mqtts":
		u.Scheme = "tls"
	case "":
		return nil, fmt.Errorf("transport: broker URL %q lacks scheme", raw)
	default:
		return nil, fmt.Errorf("transport: broker URL %q uses non-TLS scheme %q",
			raw, u.Scheme)
	}
	return u, nil
}
