package oneshot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// captureCommand runs cmd and returns stdout, capping at 30s so a
// wedged journalctl can't block dump indefinitely. stderr surfaces in
// the error message for diagnostics.
func captureCommand(name string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w (stderr: %s)", name, args, err,
			io.LimitReader(&stderr, 1024))
	}
	return stdout.Bytes(), nil
}
