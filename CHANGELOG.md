# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI (`.github/workflows/ci.yml`): runs gofmt verification, `go vet`, golangci-lint (pinned to v2.11.4 to match local), `make test` (race + single run), `make build`, and `make manpage` on every push to `main` and on every pull request. Concurrency-grouped so superseded runs are canceled. README has a status badge.

### Added
- `internal/scan/programs` package with sshd and nginx analyzers. Scans per-program configuration:
  - **sshd**: parses `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf` (first-occurrence-wins per OpenSSH semantics, Match blocks skipped). Findings: `PermitRootLogin yes` (critical), `PermitRootLogin without-password|prohibit-password` (notice), `PasswordAuthentication yes` (warning), `PermitEmptyPasswords yes` (critical), Protocol 1 (critical), `X11Forwarding yes` (notice), `PermitTunnel` non-no (notice), `LogLevel QUIET|FATAL|ERROR` (notice), `MaxAuthTries > 6` (notice). `sshd -t -f` is run as a syntax check; the unprivileged "no hostkeys available" failure is downgraded to a note instead of a false-positive finding.
  - **nginx**: skipped gracefully when nginx isn't on PATH. Otherwise runs `nginx -t` for syntax check and `nginx -T` for the effective config dump, then applies rules: `server_tokens on` (notice), `autoindex on` (warning), deprecated `ssl_protocols` (TLSv1/TLSv1.1/SSLv2/SSLv3) (error), and weak `ssl_ciphers` (RC4/DES/MD5/NULL) (error).
- `--programs[=LIST]` switch now runs the real scan end-to-end. With no value it runs every supported analyzer (`sshd,nginx`); with a comma-separated value it validates the names and runs that subset. `--all` includes programs.

### Added
- `make manpage` now renders `man/sysaudit.1` from `man/sysaudit.1.md` via `go run github.com/cpuguy83/go-md2man/v2` (pure Go, no pandoc required). The Markdown source was rewritten in go-md2man's expected conventions and updated to match the current flag set; the rendered `.1` is a build artifact (gitignored).

### Added
- `--logs` sources `auth`, `kern`, and `misc` are now implemented.
  - `auth` reads `/var/log/auth.log`; falls back to `journalctl SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 -p info` when the file is empty/missing (covers `auth` and `authpriv` syslog facilities).
  - `kern` reads `/var/log/kern.log`; falls back to `journalctl -k` (kernel transport) when the file is empty/missing.
  - `misc` walks `/var/log/` recursively, skipping compressed archives (gz/xz/zst/bz2/lz4/zip/7z), binary `.journal` files, the `journal/` and `private/` subdirectories, files already covered by other sources (auth.log/boot.log/dmesg/kern.log), rotated tails (`*.log.1`, `*.log.42`), per-file >5 MiB (read up to the cap and flag truncation), and honors a global per-walk line cap so the walk terminates promptly.
- Shared syslog line parser strips `MMM DD HH:MM:SS host ` (RFC 3164) and `<ISO-8601> host ` prefixes before bucketing/rule matching.

### Fixed
- The `kernel-bug` rule no longer fires on Xorg's lowercase `client bug:` debug wording (case-insensitive flag dropped; kernel oopses are always uppercase).
- The `hardware-error` rule's `EDAC` clause now requires an `\bEDAC\b` word boundary and a same-line gap of at most 80 chars to the trigger token, so debug payloads that quote package names containing the substring "edac" don't fire it.

### Added
- `internal/scan/users` package: parses `/etc/passwd`, `/etc/group`, and (best-effort) `/etc/shadow`. Findings: extra UID 0 users, UID/GID collisions, system accounts with login shells, members of privileged groups (`sudo`/`wheel`/`root`/`adm`/`docker`/`lxd`/`kvm`/`disk`, with the trivial `root`-in-`root` case suppressed), empty/locked password hashes, and loose mode/owner on the three system files. When `/etc/shadow` is unreadable, the scan continues and emits an info-severity finding so the user knows hash checks were skipped.
- `--users` and `--groups` switches now run the real scan end-to-end.

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
