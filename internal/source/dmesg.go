package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// DmesgRunOptions configures the one-shot dmesg invocation. Used by
// `blackboxd dump --dmesg`; service mode uses /dev/kmsg directly.
type DmesgRunOptions struct {
	// Binary lets tests override "dmesg".
	Binary string
	// Args overrides the default "--kernel --time-format=iso".
	Args   []string
	Parser parser.Parser
	Logger *slog.Logger
}

// RunDmesg runs dmesg once and returns the parsed entries. The caller
// (one-shot mode) merges them with other sources.
func RunDmesg(ctx context.Context, opt DmesgRunOptions) ([]*parser.LogEntry, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "dmesg"
	}
	args := opt.Args
	if args == nil {
		args = []string{"--kernel", "--time-format=iso"}
	}
	if opt.Parser == nil {
		return nil, fmt.Errorf("dmesg: Parser required")
	}
	logger := opt.Logger
	if logger == nil {
		logger = slog.Default()
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("dmesg pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("dmesg start: %w", err)
	}

	var entries []*parser.LogEntry
	br := bufio.NewReaderSize(stdout, 64*1024)
	for {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, fmt.Errorf("dmesg read: %w", err)
		}
		if line != "" {
			entry, perr := opt.Parser.Parse(line)
			if perr != nil {
				logger.Warn("dmesg parse failed", "err", perr)
			} else {
				entry.Source = "dmesg"
				entry.SanitizeUTF8()
				entries = append(entries, entry)
			}
		}
		if err == io.EOF {
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		return entries, fmt.Errorf("dmesg exit: %w", err)
	}
	return entries, nil
}
