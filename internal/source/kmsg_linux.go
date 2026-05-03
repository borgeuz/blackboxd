//go:build linux

package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

type KMsgSourceConfig struct {
	Name         string
	Parser       parser.Parser
	Path         string // default /dev/kmsg
	Logger       *slog.Logger
	PollInterval time.Duration

	// FromBeginning starts at the oldest record still in the ring.
	// Default: skip the historical buffer.
	FromBeginning bool
}

// KMsgSource reads /dev/kmsg one record at a time. Each read() returns
// exactly one record terminated by '\n' — the kernel guarantees this.
type KMsgSource struct {
	cfg KMsgSourceConfig
	log *slog.Logger
}

func NewKMsgSource(cfg KMsgSourceConfig) (*KMsgSource, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("kmsg source: Name required")
	}
	if cfg.Parser == nil {
		return nil, fmt.Errorf("kmsg source: Parser required")
	}
	if cfg.Path == "" {
		cfg.Path = "/dev/kmsg"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 200 * time.Millisecond
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &KMsgSource{cfg: cfg, log: cfg.Logger.With("source", cfg.Name, "path", cfg.Path)}, nil
}

func (s *KMsgSource) Name() string { return s.cfg.Name }

func (s *KMsgSource) Run(ctx context.Context, emit Emit) error {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in kmsg source", "event_type", "security", "panic", r)
		}
	}()
	// O_NONBLOCK so read returns EAGAIN at end of buffer instead of blocking.
	f, err := os.OpenFile(s.cfg.Path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("kmsg open: %w", err)
	}
	defer f.Close()

	if !s.cfg.FromBeginning {
		// SEEK_END on /dev/kmsg = "skip historical buffer". See kernel/printk.c.
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			s.log.Warn("kmsg seek-end failed; reading from beginning", "err", err)
		}
	}

	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := f.Read(buf)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, io.EOF) {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(s.cfg.PollInterval):
				}
				continue
			}
			// EPIPE = the kernel ring overran us. Resync on next read.
			if errors.Is(err, syscall.EPIPE) {
				s.log.Warn("kmsg ring overrun; resyncing")
				continue
			}
			return fmt.Errorf("kmsg read: %w", err)
		}
		if n == 0 {
			continue
		}

		entry, err := s.cfg.Parser.Parse(string(buf[:n]))
		if err != nil {
			s.log.Warn("kmsg parse failed", "err", err)
			continue
		}
		entry.Source = s.cfg.Name
		entry.SanitizeUTF8()
		emit(entry)
	}
}
