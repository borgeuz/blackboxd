package security

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DefaultAllowedPrefixes is the conservative default for source paths.
// Operators can override via [daemon].allowed_path_prefixes.
var DefaultAllowedPrefixes = []string{
	"/var/log",
	"/var/log/journal",
	"/var/lib/blackboxd",
	"/dev/kmsg",
	"/run/log/journal",
}

// CanonicalizePath returns Clean(p) and rejects relative or
// traversal-bearing inputs. It does not resolve symlinks; that is a
// per-source policy decision (see file source's FollowSymlinks).
func CanonicalizePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: empty path", ErrInsecure)
	}
	cleaned := filepath.Clean(p)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("%w: path %q is not absolute", ErrInsecure, p)
	}
	// Belt-and-braces: IsAbs already rejects "../foo", but we also
	// refuse a Clean output that retained ".." for any reason.
	for _, seg := range strings.Split(cleaned, string(filepath.Separator)) {
		if seg == ".." {
			return "", fmt.Errorf("%w: path %q contains traversal segments", ErrInsecure, p)
		}
	}
	return cleaned, nil
}

// CheckUnderAllowlist accepts cleaned if it equals a prefix or sits
// strictly under it. "/var/log" matches "/var/log/messages" but not
// "/var/log2/foo".
func CheckUnderAllowlist(cleaned string, prefixes []string) error {
	if len(prefixes) == 0 {
		return fmt.Errorf("%w: empty allowlist", ErrInsecure)
	}
	for _, raw := range prefixes {
		p := filepath.Clean(raw)
		if cleaned == p {
			return nil
		}
		if strings.HasPrefix(cleaned, p+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("%w: path %q is not under any allowed prefix", ErrInsecure, cleaned)
}

// ValidatePath = CanonicalizePath + CheckUnderAllowlist.
func ValidatePath(p string, prefixes []string) (string, error) {
	cleaned, err := CanonicalizePath(p)
	if err != nil {
		return "", err
	}
	if err := CheckUnderAllowlist(cleaned, prefixes); err != nil {
		return "", err
	}
	return cleaned, nil
}
