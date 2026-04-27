# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `internal/scan/logs` package: scans `journal`, `dmesg`, and `boot` log sources. Bucketed pattern aggregation (Normalize collapses PIDs / IPs / UUIDs / hex addresses / paths / numbers); high-priority rule findings for kernel panic, OOM kill, hardware error, kernel BUG, segfault, I/O error, filesystem error, auth failure, sudo-not-in-sudoers, audit failed. Sources `auth`, `kern`, `misc` parse but mark themselves NotRunYet inside the dispatcher.
- `--logs[=auth,boot,journal,dmesg,kern,misc]` switch now runs the real scan end-to-end. The `--journal` flag string is passed through to `journalctl`, with `--output=json` appended for stable parsing.
- Boot source falls back to `journalctl -b -p err` when `/var/log/boot.log` is missing or empty (common on journald-only modern Ubuntu).
- Dmesg source prefers `dmesg --kernel --ctime` and falls back to `/var/log/dmesg` when the kernel ring buffer is restricted.

### Added
- `internal/scan/services` package: scans systemd services on system and user buses via `systemctl --output=json` + `systemctl show`. Derives findings for failed, masked, load-error, missing-fragment, world-writable unit files, and high restart counts. Gracefully skips user scope when no session bus is reachable.
- `--services` switch now runs the real scan end-to-end (no longer "not yet implemented").

### Added
- Initial scaffold: Go module, Makefile with switchable test runner (go|gotestsum|gotestfmt|tparse), golangci-lint config.
- `internal/log` package wrapping `charmbracelet/log`, level driven by `--verbose`/`--debug`/`--quiet`.
- `internal/config` package: viper-backed loader for `~/.config/sysaudit/config.yaml`; CLI flags override config values.
- `internal/scan/procs` process scanner via `gopsutil/v4`; emits a typed `Summary` with derived `Findings`.
- `internal/claude` client wrapping `anthropic-sdk-go`; honors `--tokens`, `--analysis-level`, `--claude-verbosity`.
- `internal/report` renderers: colorful stdout via `lipgloss` and markdown to file.
- `cmd/sysaudit` cobra CLI: `--procs` runs the full pipeline; other subcommands (`--services`, `--users`/`--groups`, `--logs`, `--all`, `--programs`) accept flags but exit with "not yet implemented".
