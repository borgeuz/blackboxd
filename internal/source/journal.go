package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// JournalSourceConfig drives a `journalctl -o export -f` subprocess.
//
// The subprocess approach avoids linking libsystemd (which would need
// CGO) and avoids reimplementing the journal binary on-disk format.
// The cost is one extra process; on embedded hardware the start-up
// latency is in the milliseconds.
type JournalSourceConfig struct {
	Name          string
	Parser        parser.Parser
	Path          string   // optional --directory
	Units         []string // one --unit each
	MinPriority   int      // 0..7; 0 = no filter
	FromBeginning bool
	Logger        *slog.Logger

	// Binary lets tests override "journalctl".
	Binary string
}

type JournalSource struct {
	cfg JournalSourceConfig
	log *slog.Logger
}

func NewJournalSource(cfg JournalSourceConfig) (*JournalSource, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("journal source: Name required")
	}
	if cfg.Parser == nil {
		return nil, fmt.Errorf("journal source: Parser required")
	}
	if cfg.MinPriority < 0 || cfg.MinPriority > 7 {
		return nil, fmt.Errorf("journal source: MinPriority must be 0..7")
	}
	if cfg.Binary == "" {
		cfg.Binary = "journalctl"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &JournalSource{cfg: cfg, log: cfg.Logger.With("source", cfg.Name)}, nil
}

func (s *JournalSource) Name() string { return s.cfg.Name }

func (s *JournalSource) Run(ctx context.Context, emit Emit) error {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in journal source", "event_type", "security", "panic", r)
		}
	}()
	cmd := exec.CommandContext(ctx, s.cfg.Binary, s.argv()...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journal source: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("journal source: stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journal source: start: %w", err)
	}

	// journalctl warnings come on stderr; surface them but don't fail.
	go func() {
		b, _ := io.ReadAll(stderr)
		if len(b) > 0 {
			s.log.Warn("journalctl stderr", "data", strings.TrimSpace(string(b)))
		}
	}()

	if err := s.consume(ctx, stdout, emit); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	return cmd.Wait()
}

// consume slices stdout into export records (one record = lines up to
// the next blank line) and emits one entry per record.
func (s *JournalSource) consume(ctx context.Context, r io.Reader, emit Emit) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var buf strings.Builder
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("journal read: %w", err)
		}
		if line == "\n" {
			if buf.Len() > 0 {
				s.emitRecord(buf.String(), emit)
				buf.Reset()
			}
		} else if line != "" {
			buf.WriteString(line)
		}
		if err == io.EOF {
			if buf.Len() > 0 {
				s.emitRecord(buf.String(), emit)
			}
			return nil
		}
	}
}

func (s *JournalSource) emitRecord(rec string, emit Emit) {
	entry, err := s.cfg.Parser.Parse(rec)
	if err != nil {
		s.log.Warn("journal parse failed", "err", err)
		return
	}
	entry.Source = s.cfg.Name
	entry.SanitizeUTF8()
	emit(entry)
}

func (s *JournalSource) argv() []string {
	args := []string{"-o", "export"}
	if !s.cfg.FromBeginning {
		args = append(args, "-f")
	}
	if s.cfg.Path != "" {
		args = append(args, "--directory", s.cfg.Path)
	}
	for _, u := range s.cfg.Units {
		args = append(args, "--unit", u)
	}
	if s.cfg.MinPriority > 0 {
		args = append(args, "--priority", fmt.Sprintf("%d", s.cfg.MinPriority))
	}
	return args
}
