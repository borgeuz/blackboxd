# blackboxd

Lightweight, hardened embedded-Linux log collection daemon for the
Blackbox post-mortem debugging platform.

`blackboxd` runs on customer devices (down to 64 MB RAM, ARMv7), reads
configured log sources, parses them into a canonical JSONL format, and
ships them via mTLS-protected MQTT to a remote analysis backend. It
performs no analysis itself: all intelligence lives in the cloud.

## Architecture

```
┌─────────────┐     ┌──────────┐     ┌──────────────┐     ┌───────────┐
│   Sources   │ ──> │  Parsers │ ──> │ Ring Buffer  │ ──> │ Transport │
│ file/kmsg/  │     │ per-src  │     │ (in-memory)  │     │  (MQTT)   │
│ journal     │     │          │     │              │     │           │
└─────────────┘     └──────────┘     └──────────────┘     └───────────┘
                                            │                    │
                                            │ overflow / outage  │
                                            ▼                    ▼
                                     ┌──────────────┐     ┌───────────┐
                                     │  Disk Spool  │ <── │  Replay   │
                                     │  (JSONL gz)  │     │  Logic    │
                                     └──────────────┘     └───────────┘
```

The daemon ships pre-defined parsers for the five log formats most
common on embedded Linux:

| Parser           | Source format              | Reference        |
|------------------|----------------------------|------------------|
| `syslog_bsd`     | RFC 3164 BSD syslog        | RFC 3164         |
| `syslog_rfc5424` | RFC 5424 syslog            | RFC 5424         |
| `kmsg`           | `/dev/kmsg` records        | kernel ABI       |
| `dmesg`          | `dmesg` text (legacy/iso)  | util-linux       |
| `journald`       | `journalctl -o export`     | systemd          |

A registry pattern (`internal/parser/registry.go`) keeps adding a new
parser to a single-file change.

## Operating modes

### Service mode (default)
Long-running process, driven by a TOML config file (`/etc/blackboxd/blackboxd.toml`
by default). Tails configured sources, parses, batches, and ships
batches over MQTT. Reloads on `SIGHUP`; flushes in-flight data on
`SIGTERM`/`SIGINT`.

```sh
blackboxd                                 # default config path
blackboxd --config /path/to/conf.toml     # custom path
```

### One-shot mode (`dump`)
Forensic export. Bypasses the TOML config entirely; all options on the
command line. Reads requested sources, parses, merges chronologically
across sources via a min-heap k-way merge, and writes JSONL to stdout
or a file (optionally gzip-compressed).

```sh
blackboxd dump --kmsg --journal --since 1h --output crash.jsonl.gz --gzip
blackboxd dump --syslog-bsd /var/log/messages --syslog-rfc5424 /var/log/syslog
```

Flags:

| Flag                               | Meaning                                       |
|------------------------------------|-----------------------------------------------|
| `--kmsg`                           | include `/dev/kmsg`                           |
| `--dmesg`                          | include `dmesg` output (one-shot)             |
| `--journal`                        | include systemd journal (full)                |
| `--journal-unit UNIT`              | filter journal to a unit (repeatable)         |
| `--syslog-bsd PATH`                | parse PATH as RFC 3164 (repeatable)           |
| `--syslog-rfc5424 PATH`            | parse PATH as RFC 5424 (repeatable)           |
| `--since DURATION` / `--since RFC3339` | lower time bound (`1h`, `2026-05-01T00:00:00Z`) |
| `--until RFC3339`                  | upper time bound                              |
| `--output PATH` / `-o PATH`        | output file (default stdout)                  |
| `--gzip`                           | gzip the output                               |
| `--max-lines N`                    | cap total entries                             |

### Other subcommands

```sh
blackboxd validate /etc/blackboxd/blackboxd.toml   # exit 0/non-zero
blackboxd validate --skip-fs-checks <path>          # schema only
blackboxd version                                   # build info
```

## Security model

`blackboxd` is designed against an attacker who can inspect the
binary, tamper with config and certs, inject malicious data into log
sources, attempt MitM on the broker connection, and try to escalate
privileges from a compromised process. The daemon must remain
trustworthy under all of these.

Highlights — see `BLACKBOXD_PROMPT.md` § "Security Requirements" for
the full list:

- **mTLS is mandatory.** No plaintext fallback exists in the codebase.
  Plaintext MQTT URLs are rejected at config validation. `MinVersion`
  is TLS 1.2 (1.3 negotiated when both peers support).
  `InsecureSkipVerify` cannot be enabled by any flag, env var, or path.
  The CA bundle is loaded from the configured path; the system CA
  store is *not* consulted unless explicitly concatenated.
- **Optional cert pinning** by SHA-256 fingerprint
  (`broker_cert_pin`). When set, the connection aborts on mismatch
  regardless of CA validation.
- **Publish-only.** The daemon never subscribes to remote topics: no
  remote-code-execution surface. The MQTT session is publish-only from
  the device.
- **Path canonicalisation + allowlist.** Every path in the config is
  canonicalised and checked against an allowlist (default `/var/log`,
  `/var/log/journal`, `/var/lib/blackboxd`, `/dev/kmsg`,
  `/run/log/journal`). Symlinks are refused unless explicitly opted
  in per source.
- **File mode checks.** Refuses to start with a group/world-writable
  config; key files must be `0600` and owned by the daemon user; state
  directory must be `0700`.
- **Bounded resource usage.** Hard line-length cap (default 64 KiB,
  truncated lines flagged); ring buffer cap (default 4 MiB / 10 000
  entries); spool cap (default 100 MiB); per-source token bucket rate
  limit (default 10 000 lines/sec). Drops are counted and published
  in the metrics topic.
- **Hardened systemd unit** at `configs/blackboxd.service`:
  `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
  `SystemCallFilter`, `RestrictAddressFamilies`, etc.
- **Reproducible build.** `make reproducible-check` builds twice and
  asserts byte-identical output. `go mod verify` runs in `make test`.

## MQTT topic structure

```
blackbox/v1/{tenant}/{device_id}/logs        — batched log entries
blackbox/v1/{tenant}/{device_id}/status      — online/offline (retained, LWT)
blackbox/v1/{tenant}/{device_id}/heartbeat   — periodic liveness
blackbox/v1/{tenant}/{device_id}/metrics     — internal daemon metrics
```

The device only publishes. mTLS provides authentication and
authorisation; LWT publishes `{"online": false}` retained on `status`
when the connection drops abnormally.

## Build

Pure Go, `CGO_ENABLED=0`, statically linked, stripped, reproducible.
Cross-compiles for `linux/{amd64, arm64, armv7, armv6}` from a single
`make` invocation.

```sh
make build                  # host arch
make build-all              # all four target architectures (in dist/)
make test                   # unit tests with race detector + go mod verify
make bench                  # all benchmarks
make fuzz                   # run fuzz targets, default 30s each (FUZZ_DURATION=2m make fuzz)
make reproducible-check     # build twice, assert byte-identical
make vet                    # go vet
make fmt-check              # gofmt -s -l
```

The Makefile preserves the host's `GOOS` / `GOARCH` for tests so
running `make test` on a darwin maintenance host doesn't try to
execute a cross-compiled linux binary.

## Configuration

See `configs/blackboxd.example.toml` for a fully-annotated reference
config. The schema documents every supported field; any field not
listed there is not supported.

The `validate` subcommand performs the same validation the daemon
runs at startup, including filesystem checks (config mode, key mode,
state-dir ownership). Use `--skip-fs-checks` to limit it to schema
concerns when validating a config you don't own.

## Performance

Microbenchmarks on Apple M4 (typical of a developer machine; production
embedded ARMv7 hardware will be ~10–50× slower):

| Parser           | ns/op | B/op | allocs/op |
|------------------|-------|------|-----------|
| `syslog_bsd`     |   101 |  128 |         1 |
| `syslog_rfc5424` |   170 |  464 |         3 |
| `kmsg`           |    67 |  208 |         2 |
| `dmesg`          |    42 |  128 |         1 |
| `journald`       |   176 |  576 |         4 |

(Run via `make bench`. The 1-allocation entries are the canonical
LogEntry itself; everything else is parsed in place from the input
string without copies.)

## Project layout

```
blackboxd/
├── cmd/blackboxd/                # CLI entry point + subcommand dispatch
├── internal/
│   ├── config/                   # TOML schema + validation
│   ├── parser/                   # interface, LogEntry, registry, 5 parsers
│   ├── source/                   # file/kmsg/journal/dmesg readers
│   ├── pipeline/                 # ring buffer, batcher, rate limiter, JSONL+gzip
│   ├── transport/                # MQTT publisher (mTLS), spool fallback
│   ├── oneshot/                  # `dump` mode k-way merge
│   ├── security/                 # path/mode checks, TLS builder, pin verifier
│   ├── version/                  # build identification
│   └── integration/              # end-to-end & chaos tests
├── configs/
│   ├── blackboxd.example.toml    # annotated reference config
│   └── blackboxd.service         # hardened systemd unit
├── scripts/build-all.sh
├── Makefile
├── go.mod / go.sum
└── README.md
```

## Troubleshooting

- **`config refuses to load with "group/world-writable"`** — set the
  config to `0600` (or `0640` if it must be readable by an operator
  group).
- **`refusing to open symlink`** — set `follow_symlinks = true` on
  the offending `[sources.NAME]` block, or change the path to point
  at the regular file directly.
- **`path not under any allowed prefix`** — the path is outside the
  default allowlist. Either move the file, or add a prefix via
  `[daemon].allowed_path_prefixes`.
- **`daemon refuses to publish over plaintext`** — change the broker
  URL to `tls://` (or `ssl://`/`mqtts://`) and ensure mTLS materials
  are configured.
- **`kmsg source: supported only on linux`** — the daemon was built
  for / is running on a non-Linux host. The kmsg source is intentionally
  Linux-only; cross-platform development is supported via the file source.

## License

To be specified by the project owner.
