// Command blackboxd is the on-device log collection daemon for the
// Blackbox platform.
//
// Subcommands:
//
//	blackboxd                       service mode (default)
//	blackboxd dump   [flags]        one-shot forensic export
//	blackboxd validate <path>       validate config, exit 0/nonzero
//	blackboxd version               build info
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/borgeuz/blackboxd/internal/config"
	"github.com/borgeuz/blackboxd/internal/oneshot"
	"github.com/borgeuz/blackboxd/internal/version"
)

type exitCode int

const (
	exitOK             exitCode = 0
	exitUsage          exitCode = 2
	exitConfigInvalid  exitCode = 3
	exitRuntimeFailure exitCode = 4
)

func main() {
	os.Exit(int(dispatch(os.Args[1:])))
}

// dispatch is split out from main so tests can drive subcommand
// routing without spawning a process.
func dispatch(args []string) exitCode {
	if len(args) == 0 {
		return runService(args)
	}
	switch args[0] {
	case "dump":
		return runDump(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "version":
		return runVersion(args[1:])
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return exitOK
	default:
		// Anything else (e.g. --config=...) is service mode.
		return runService(args)
	}
}

func runService(args []string) exitCode {
	fs := newFlagSet("blackboxd")
	configPath := fs.String("config", "/etc/blackboxd/blackboxd.toml", "path to TOML config file")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	_ = ctx
	_ = configPath

	fmt.Fprintln(os.Stderr, "blackboxd: service mode runtime not yet wired")
	return exitRuntimeFailure
}

// runDump bypasses the TOML config: every option comes from a flag,
// and no daemon state directory is touched.
func runDump(args []string) exitCode {
	fs := newFlagSet("blackboxd dump")

	wantKmsg := fs.Bool("kmsg", false, "include /dev/kmsg (kernel ring buffer)")
	wantDmesg := fs.Bool("dmesg", false, "include dmesg output")
	wantJournal := fs.Bool("journal", false, "include systemd journal (full)")
	journalUnits := multiString(fs, "journal-unit", "filter journal to a unit (repeatable)")
	bsdFiles := multiString(fs, "syslog-bsd", "parse a file as RFC 3164 syslog (repeatable)")
	rfc5424Files := multiString(fs, "syslog-rfc5424", "parse a file as RFC 5424 syslog (repeatable)")
	since := fs.String("since", "", "lower time bound (duration like 1h, or RFC3339 timestamp)")
	until := fs.String("until", "", "upper time bound (RFC3339 timestamp)")
	output := fs.String("output", "", "output file path (default: stdout)")
	outputShort := fs.String("o", "", "shorthand for --output")
	useGzip := fs.Bool("gzip", false, "gzip-compress the output")
	maxLines := fs.Int("max-lines", 0, "cap total entries (0 = no cap)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	out := *output
	if out == "" {
		out = *outputShort
	}

	filter, err := buildOneshotFilter(*since, *until)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blackboxd dump: %v\n", err)
		return exitUsage
	}

	sources, err := buildOneshotSources(*wantKmsg, *wantDmesg, *wantJournal,
		*journalUnits, *bsdFiles, *rfc5424Files, filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blackboxd dump: %v\n", err)
		return exitUsage
	}
	if len(sources) == 0 {
		fmt.Fprintln(os.Stderr, "blackboxd dump: no sources selected (try --kmsg, --journal, --syslog-bsd PATH, ...)")
		return exitUsage
	}

	w, closer, err := oneshot.OpenOutput(out, *useGzip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blackboxd dump: %v\n", err)
		return exitRuntimeFailure
	}
	defer closer.Close()

	n, err := oneshot.Merge(w, sources, oneshot.MergeOptions{
		MaxLines: *maxLines,
		Filter:   filter,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "blackboxd dump: %v\n", err)
		return exitRuntimeFailure
	}
	fmt.Fprintf(os.Stderr, "blackboxd dump: wrote %d entries\n", n)
	return exitOK
}

// runValidate runs the same validation as daemon startup.
// --skip-fs-checks limits it to schema-only when the operator can't
// access the cert/state files.
func runValidate(args []string) exitCode {
	fs := newFlagSet("blackboxd validate")
	skipFS := fs.Bool("skip-fs-checks", false, "skip file mode/ownership checks; only validate schema")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: blackboxd validate [--skip-fs-checks] <config-path>")
		return exitUsage
	}
	path := fs.Arg(0)
	if _, err := config.Load(path, config.LoadOptions{SkipFSChecks: *skipFS}); err != nil {
		fmt.Fprintf(os.Stderr, "blackboxd validate: %v\n", err)
		return exitConfigInvalid
	}
	fmt.Fprintf(os.Stdout, "config %s OK\n", path)
	return exitOK
}

func runVersion(_ []string) exitCode {
	fmt.Printf("blackboxd %s (commit %s, built %s)\n",
		version.Version, version.Commit, version.BuildDate)
	return exitOK
}

func printUsage(w *os.File) {
	fmt.Fprintf(w, `blackboxd %s — Blackbox on-device log collection daemon

USAGE:
  blackboxd [--config PATH]                  service mode (long-running)
  blackboxd dump [flags]                     one-shot forensic export
  blackboxd validate <config-path>           validate config, exit 0/nonzero
  blackboxd version                          print build info
  blackboxd help                             this message

Run 'blackboxd dump -h' or 'blackboxd -h' for mode-specific flags.
`, version.Version)
}
