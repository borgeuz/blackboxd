//go:build !linux

// Placeholder for non-Linux builds (e.g. darwin development hosts).
// blackboxd is Linux-only in production; this stub keeps `go test`
// compiling on a maintainer's workstation.

package source

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

type KMsgSourceConfig struct {
	Name          string
	Parser        parser.Parser
	Path          string
	Logger        *slog.Logger
	PollInterval  time.Duration
	FromBeginning bool
}

type KMsgSource struct{ cfg KMsgSourceConfig }

// NewKMsgSource succeeds so config-load doesn't fail on non-Linux;
// only Run reports the platform mismatch.
func NewKMsgSource(cfg KMsgSourceConfig) (*KMsgSource, error) {
	return &KMsgSource{cfg: cfg}, nil
}

func (s *KMsgSource) Name() string { return s.cfg.Name }

func (s *KMsgSource) Run(_ context.Context, _ Emit) error {
	return errors.Join(ErrFatal, errors.New("kmsg source is supported only on linux"))
}
