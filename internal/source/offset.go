package source

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// OffsetStore persists per-source byte offsets so file tailing resumes
// across restarts (at-least-once). Format on disk:
//
//	{"path":"/var/log/messages","offset":123456,"inode":17}
//
// Inode is recorded so we can detect rotation: a different inode at the
// same path means the previous file was rotated out, and we restart at
// offset 0 of the new one.
type OffsetStore struct {
	dir string
}

// NewOffsetStore expects dir to exist with mode 0700; mkdir is the
// caller's responsibility.
func NewOffsetStore(dir string) *OffsetStore {
	return &OffsetStore{dir: dir}
}

type Offset struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
}

// Load returns a zero Offset (no error) when no record exists yet.
func (s *OffsetStore) Load(sourceName string) (Offset, error) {
	p := filepath.Join(s.dir, sourceName+".offset")
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Offset{}, nil
		}
		return Offset{}, fmt.Errorf("offset load %s: %w", p, err)
	}
	var off Offset
	if err := json.Unmarshal(b, &off); err != nil {
		return Offset{}, fmt.Errorf("offset parse %s: %w", p, err)
	}
	return off, nil
}

// Save writes atomically: temp + fsync + rename, mode 0600.
func (s *OffsetStore) Save(sourceName string, off Offset) error {
	final := filepath.Join(s.dir, sourceName+".offset")
	tmp := final + ".tmp"

	body, err := json.Marshal(off)
	if err != nil {
		return fmt.Errorf("offset marshal: %w", err)
	}

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("offset open tmp: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("offset write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("offset fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("offset close: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("offset rename: %w", err)
	}
	return nil
}
