package security

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

const (
	modeFileSensitive fs.FileMode = 0o600
	modeDirState      fs.FileMode = 0o700
)

// CheckConfigMode rejects group- or world-writable config files, plus
// any non-regular file (symlink, device, fifo). Group/world *read* is
// allowed: the config holds no secrets, only paths to secret files.
func CheckConfigMode(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: stat config %q: %v", ErrInsecure, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: config %q is not a regular file", ErrInsecure, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: config %q is group/world-writable (mode %o)",
			ErrInsecure, path, info.Mode().Perm())
	}
	return nil
}

// CheckKeyMode requires exactly 0600 and ownership by the current
// effective UID. Any group or world bit on a private key is fatal.
func CheckKeyMode(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: stat key %q: %v", ErrInsecure, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: key %q is not a regular file", ErrInsecure, path)
	}
	if info.Mode().Perm() != modeFileSensitive {
		return fmt.Errorf("%w: key %q has mode %o, want 0600",
			ErrInsecure, path, info.Mode().Perm())
	}
	return checkOwnedByCurrentUser(info, path)
}

// CheckStateDirMode requires a directory at 0700 owned by the current
// effective UID.
func CheckStateDirMode(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: stat state dir %q: %v", ErrInsecure, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: state dir %q is not a directory", ErrInsecure, path)
	}
	if info.Mode().Perm() != modeDirState {
		return fmt.Errorf("%w: state dir %q has mode %o, want 0700",
			ErrInsecure, path, info.Mode().Perm())
	}
	return checkOwnedByCurrentUser(info, path)
}

func checkOwnedByCurrentUser(info fs.FileInfo, path string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// blackboxd targets unix; refuse rather than silently pass on
		// platforms where ownership cannot be checked.
		return fmt.Errorf("%w: cannot determine owner of %q on this platform",
			ErrInsecure, path)
	}
	euid := uint32(os.Geteuid())
	if st.Uid != euid {
		return fmt.Errorf("%w: %q owned by uid %d, want %d",
			ErrInsecure, path, st.Uid, euid)
	}
	return nil
}
