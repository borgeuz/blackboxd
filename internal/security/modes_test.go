package security

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates path with the given mode and returns it.
// Helper for the tests below.
func writeFile(t *testing.T, dir, name string, mode fs.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), mode); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// os.WriteFile honours the umask, so re-chmod to be sure.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return p
}

func TestCheckConfigMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	cases := []struct {
		name    string
		mode    fs.FileMode
		wantErr bool
	}{
		{"0600-OK", 0o600, false},
		{"0640-OK", 0o640, false},
		{"0644-OK", 0o644, false},
		{"0664-rejected-group-write", 0o664, true},
		{"0666-rejected-world-write", 0o666, true},
		{"0620-rejected-group-write-only", 0o620, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, dir, tc.name+".toml", tc.mode)
			err := CheckConfigMode(p)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("mode %o: expected error, got nil", tc.mode)
				}
				if !errors.Is(err, ErrInsecure) {
					t.Fatalf("error not wrapping ErrInsecure: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("mode %o: unexpected error: %v", tc.mode, err)
			}
		})
	}

	t.Run("missing-file", func(t *testing.T) {
		err := CheckConfigMode(filepath.Join(dir, "nope.toml"))
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("symlink-rejected", func(t *testing.T) {
		target := writeFile(t, dir, "target.toml", 0o600)
		link := filepath.Join(dir, "link.toml")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		if err := CheckConfigMode(link); err == nil {
			t.Fatalf("expected symlink rejection")
		}
	})
}

func TestCheckKeyMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	cases := []struct {
		name    string
		mode    fs.FileMode
		wantErr bool
	}{
		{"0600-OK", 0o600, false},
		{"0400-rejected-readonly", 0o400, true},
		{"0640-rejected-group-read", 0o640, true},
		{"0644-rejected-world-read", 0o644, true},
		{"0660-rejected-group-write", 0o660, true},
		{"0700-rejected-exec", 0o700, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, dir, tc.name+".key", tc.mode)
			err := CheckKeyMode(p)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("mode %o: expected error, got nil", tc.mode)
				}
				if !errors.Is(err, ErrInsecure) {
					t.Fatalf("error not wrapping ErrInsecure: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("mode %o: unexpected error: %v", tc.mode, err)
			}
		})
	}
}

func TestCheckStateDirMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	good := filepath.Join(dir, "ok")
	if err := os.Mkdir(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckStateDirMode(good); err != nil {
		t.Fatalf("0700 dir: %v", err)
	}

	bad := filepath.Join(dir, "bad")
	if err := os.Mkdir(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckStateDirMode(bad); err == nil {
		t.Fatalf("0755 dir: expected error")
	}

	notDir := writeFile(t, dir, "regular", 0o700)
	if err := CheckStateDirMode(notDir); err == nil {
		t.Fatalf("regular file as state dir: expected error")
	}
}
