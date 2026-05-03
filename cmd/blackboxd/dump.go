package main

import (
	"fmt"
	"time"

	"github.com/borgeuz/blackboxd/internal/oneshot"
	"github.com/borgeuz/blackboxd/internal/parser"
)

// buildOneshotFilter accepts --since as either a Go duration ("1h")
// or an RFC3339 timestamp; --until is RFC3339 only.
func buildOneshotFilter(since, until string) (oneshot.Filter, error) {
	var f oneshot.Filter
	if since != "" {
		if d, err := time.ParseDuration(since); err == nil {
			f.Since = time.Now().Add(-d)
		} else if t, err := time.Parse(time.RFC3339, since); err == nil {
			f.Since = t
		} else {
			return f, fmt.Errorf("--since %q: not a duration or RFC3339 timestamp", since)
		}
	}
	if until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return f, fmt.Errorf("--until %q: %w", until, err)
		}
		f.Until = t
	}
	return f, nil
}

func buildOneshotSources(
	kmsg, dmesg, journal bool,
	journalUnits, bsdFiles, rfc5424Files []string,
	filter oneshot.Filter,
) ([]oneshot.Source, error) {
	var sources []oneshot.Source

	for _, p := range bsdFiles {
		bsd, err := parser.NewSyslogBSD(parser.SyslogBSDConfig{Timezone: "UTC"})
		if err != nil {
			return nil, fmt.Errorf("syslog_bsd parser: %w", err)
		}
		sources = append(sources, &oneshot.FileSource{
			Label:  "syslog_bsd:" + p,
			Path:   p,
			Parser: bsd,
		})
	}
	for _, p := range rfc5424Files {
		rp, err := parser.NewSyslogRFC5424(parser.SyslogRFC5424Config{})
		if err != nil {
			return nil, fmt.Errorf("syslog_rfc5424 parser: %w", err)
		}
		sources = append(sources, &oneshot.FileSource{
			Label:  "syslog_rfc5424:" + p,
			Path:   p,
			Parser: rp,
		})
	}

	if kmsg {
		kp, err := parser.NewKMsg(parser.KMsgConfig{})
		if err != nil {
			return nil, fmt.Errorf("kmsg parser: %w", err)
		}
		sources = append(sources, &oneshot.FileSource{
			Label:  "kmsg",
			Path:   "/dev/kmsg",
			Parser: kp,
		})
	}

	if dmesg {
		dp, err := parser.NewDmesg(parser.DmesgConfig{})
		if err != nil {
			return nil, fmt.Errorf("dmesg parser: %w", err)
		}
		sources = append(sources, &oneshot.DmesgSource{Parser: dp})
	}

	if journal || len(journalUnits) > 0 {
		jp, err := parser.NewJournald(parser.JournaldConfig{})
		if err != nil {
			return nil, fmt.Errorf("journald parser: %w", err)
		}
		js := &oneshot.JournalSource{
			Label:  "journal",
			Units:  journalUnits,
			Parser: jp,
		}
		if !filter.Since.IsZero() {
			js.Since = filter.Since.Format(time.RFC3339)
		}
		if !filter.Until.IsZero() {
			js.Until = filter.Until.Format(time.RFC3339)
		}
		sources = append(sources, js)
	}

	return sources, nil
}
