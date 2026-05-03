package source

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// FileSourceConfig configures the file tailer. Defaults are filled in
// by NewFileSource.
type FileSourceConfig struct {
	Name string

	// Path is the concrete file to tail. Globs are not expanded here;
	// the caller instantiates one FileSource per matched path.
	Path string

	Parser parser.Parser

	// FromBeginning ignores the persisted offset on startup.
	FromBeginning bool

	// FollowSymlinks must be set explicitly to allow opening a symlink.
	FollowSymlinks bool

	// MaxLineBytes is the line-length cap; longer lines are truncated
	// and tagged with Fields["truncated"]="true". Default 64 KiB.
	MaxLineBytes int

	// PollInterval is the wait between read attempts at EOF. Default 250ms.
	PollInterval time.Duration

	// Offsets, when non-nil, persists the read position so tailing
	// resumes across restarts.
	Offsets *OffsetStore

	// SaveInterval is how often the offset is flushed. Default 1s.
	SaveInterval time.Duration

	Logger *slog.Logger
}

// FileSource tails a single regular file. Rotation is detected by
// inode change at the configured path; truncation by a Size shrink.
type FileSource struct {
	cfg     FileSourceConfig
	log     *slog.Logger
	current *os.File
	curIno  uint64
	offset  int64
	reader  *bufio.Reader
}

// NewFileSource validates cfg and returns a source ready to Run. The
// file is opened by Run, not here, so a single bad config doesn't kill
// the whole daemon at startup.
func NewFileSource(cfg FileSourceConfig) (*FileSource, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("file source: Name is required")
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("file source: Path is required")
	}
	if cfg.Parser == nil {
		return nil, fmt.Errorf("file source: Parser is required")
	}
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = 64 * 1024
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 250 * time.Millisecond
	}
	if cfg.SaveInterval <= 0 {
		cfg.SaveInterval = time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &FileSource{cfg: cfg, log: cfg.Logger.With("source", cfg.Name, "path", cfg.Path)}, nil
}

func (s *FileSource) Name() string { return s.cfg.Name }

func (s *FileSource) Run(ctx context.Context, emit Emit) error {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in file source", "event_type", "security", "panic", r)
		}
	}()
	if err := s.openInitial(); err != nil {
		return err
	}
	defer func() {
		if s.current != nil {
			_ = s.current.Close()
		}
	}()

	saveTick := time.NewTicker(s.cfg.SaveInterval)
	defer saveTick.Stop()

	for {
		select {
		case <-ctx.Done():
			s.persistOffset()
			return nil
		default:
		}

		if err := s.drain(ctx, emit); err != nil {
			if errors.Is(err, context.Canceled) {
				s.persistOffset()
				return nil
			}
			s.log.Error("drain failed", "err", err)
		}

		if rotated, err := s.checkRotation(); err != nil {
			s.log.Error("rotation check failed", "err", err)
		} else if rotated {
			s.log.Info("rotation detected")
		}

		select {
		case <-ctx.Done():
			s.persistOffset()
			return nil
		case <-saveTick.C:
			s.persistOffset()
		case <-time.After(s.cfg.PollInterval):
		}
	}
}

// openInitial opens the file, seeks to the persisted offset (or EOF),
// and reconciles the persisted state with the current inode. Inode
// mismatch or persisted-offset > current-size both restart at 0.
func (s *FileSource) openInitial() error {
	if !s.cfg.FollowSymlinks {
		info, err := os.Lstat(s.cfg.Path)
		if err != nil {
			return fmt.Errorf("file source open: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: refusing to open symlink %q (set follow_symlinks=true to allow)",
				ErrFatal, s.cfg.Path)
		}
	}

	f, err := os.Open(s.cfg.Path)
	if err != nil {
		return fmt.Errorf("file source open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("file source stat: %w", err)
	}
	ino, _ := inodeOf(info)

	startOffset := info.Size() // tail from end by default
	if s.cfg.FromBeginning {
		startOffset = 0
	}
	if s.cfg.Offsets != nil && !s.cfg.FromBeginning {
		off, err := s.cfg.Offsets.Load(s.cfg.Name)
		if err != nil {
			s.log.Warn("offset load failed; tailing from EOF", "err", err)
		} else if off.Inode != 0 && off.Inode == ino && off.Offset <= info.Size() {
			startOffset = off.Offset
		} else if off.Inode != 0 {
			s.log.Info("inode mismatch or truncation; restarting from 0",
				"persisted_inode", off.Inode, "current_inode", ino)
			startOffset = 0
		}
	}

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		f.Close()
		return fmt.Errorf("file source seek: %w", err)
	}
	s.current = f
	s.curIno = ino
	s.offset = startOffset
	s.reader = bufio.NewReaderSize(f, s.cfg.MaxLineBytes)
	return nil
}

func (s *FileSource) drain(ctx context.Context, emit Emit) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := s.readLine()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		s.consumeLine(line, emit)
	}
}

// readLine returns one line, capped at MaxLineBytes. If the line
// exceeds the cap we keep the first MaxLineBytes bytes, drain the
// rest of the line, and append a synthetic '\n' so the parser sees a
// complete record. consumeLine sets the truncation flag.
//
// We use bufio.Reader.ReadSlice — it returns ErrBufferFull when the
// line exceeds the buffer, which is exactly the cap behaviour we want.
// The returned slice points into the bufio's internal buffer and must
// be copied before further reads.
func (s *FileSource) readLine() (string, error) {
	slice, err := s.reader.ReadSlice('\n')
	switch {
	case err == nil:
		s.offset += int64(len(slice))
		return string(slice), nil

	case errors.Is(err, bufio.ErrBufferFull):
		first := make([]byte, len(slice))
		copy(first, slice)
		s.offset += int64(len(first))
		drained, derr := s.discardThroughNewline(maxDiscardBytes)
		s.offset += drained
		if derr != nil && derr != io.EOF {
			return "", derr
		}
		return string(first) + "\n", nil

	case err == io.EOF && len(slice) > 0:
		// trailing line without final newline
		s.offset += int64(len(slice))
		return string(slice), nil

	case err == io.EOF:
		return "", io.EOF

	default:
		return "", err
	}
}

// maxDiscardBytes caps how far we'll skip looking for a newline when
// the current line exceeds MaxLineBytes. Without this an adversary
// (or a buggy producer) could feed an unbounded line and pin the source
// goroutine forever on the discard.
const maxDiscardBytes = 16 * 1024 * 1024 // 16 MiB

func (s *FileSource) discardThroughNewline(limit int64) (int64, error) {
	var n int64
	for n < limit {
		slice, err := s.reader.ReadSlice('\n')
		n += int64(len(slice))
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return n, err
	}
	s.log.Warn("oversized line discard cap reached; resyncing on next newline", "discarded_bytes", n)
	return n, nil
}

func (s *FileSource) consumeLine(raw string, emit Emit) {
	truncated := false
	if len(raw) > s.cfg.MaxLineBytes {
		raw = raw[:s.cfg.MaxLineBytes]
		truncated = true
	}
	e, err := s.cfg.Parser.Parse(raw)
	if err != nil {
		s.log.Warn("parse failed", "err", err)
		return
	}
	e.Source = s.cfg.Name
	e.SanitizeUTF8()
	if truncated {
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		e.Fields["truncated"] = "true"
	}
	emit(e)
}

// checkRotation reopens on inode change, seeks to 0 on truncation.
// A briefly-missing path (the rename phase of a logrotate cycle) is
// not an error — we just retry on the next tick.
func (s *FileSource) checkRotation() (bool, error) {
	if !s.cfg.FollowSymlinks {
		info, err := os.Lstat(s.cfg.Path)
		if err != nil {
			return false, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%w: path became a symlink", ErrFatal)
		}
	}
	info, err := os.Stat(s.cfg.Path)
	if err != nil {
		return false, nil
	}
	ino, _ := inodeOf(info)

	rotated := false
	if ino != s.curIno {
		// Closing without a final drain risks losing the tail of the
		// rotated file. Acceptable: rotated content is also in the
		// renamed sibling (e.g. messages.1) and rare in steady state.
		_ = s.current.Close()
		f, err := os.Open(s.cfg.Path)
		if err != nil {
			return false, err
		}
		s.current = f
		s.curIno = ino
		s.offset = 0
		s.reader = bufio.NewReaderSize(f, s.cfg.MaxLineBytes)
		rotated = true
	} else if info.Size() < s.offset {
		if _, err := s.current.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		s.offset = 0
		s.reader = bufio.NewReaderSize(s.current, s.cfg.MaxLineBytes)
		rotated = true
	}
	return rotated, nil
}

func (s *FileSource) persistOffset() {
	if s.cfg.Offsets == nil {
		return
	}
	if err := s.cfg.Offsets.Save(s.cfg.Name, Offset{
		Path:   s.cfg.Path,
		Offset: s.offset,
		Inode:  s.curIno,
	}); err != nil {
		s.log.Warn("offset save failed", "err", err)
	}
}

// inodeOf returns the unix inode. Falls back to (0, false) on
// platforms where Sys() is not *syscall.Stat_t.
func inodeOf(info os.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true
}

// ExpandGlob returns the matching paths for a glob pattern, or just
// the path itself if it exists and contains no metacharacters.
func ExpandGlob(pattern string) ([]string, error) {
	if !hasMeta(pattern) {
		if _, err := os.Stat(pattern); err != nil {
			return nil, err
		}
		return []string{pattern}, nil
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob %q: %w", pattern, err)
	}
	return matches, nil
}

func hasMeta(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*', '?', '[':
			return true
		}
	}
	return false
}
