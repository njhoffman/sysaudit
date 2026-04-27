# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Implemented scanners: `--procs` (gopsutil) and `--services` (systemctl JSON + show). Stubs that parse but emit "not yet implemented": `--users`/`--groups`, `--logs`, `--programs`, `--all`. The **Specification** section below remains the source of truth for what still needs to be built.

## Overview

`sysaudit` is a Go CLI for Linux (Ubuntu) that scans the system for errors and misconfigurations across processes, services, users/groups, and logs. It summarizes findings, sends the summary to Claude for analysis, and emits a report. Output is colorful when written to stdout and markdown when written to a file.

## Specification

### Global behavior & flags

- Use Claude to analyze scan results and generate the report.
- Stdout output is colorful; file output is markdown. An option saves the report to a file.
- Standard flags, each with a single-letter short form: `--help`, `--version`, `--verbose`, `--debug`, `--quiet`.
- Claude AI control flags (each with a single-letter short form) for token budget, verbosity, and analysis level.
- Configuration lives at `~/.config/sysaudit/config.yaml`. CLI flags override config values.
- Logging uses `github.com/charmbracelet/log` (not the stdlib `log` package, not `fmt.Print*` for diagnostic output).
- Maintain a manpage and `CHANGELOG.md`.
- Test output is switchable between `gotestsum`, `gotestfmt`, and `tparse`.
- Lint and tests must pass before any commit.

### Subcommand switches

- `--procs` — scan running processes and their properties; summarize, report, and analyze with Claude.
- `--services` — scan running user and system services and their properties; verify unit files are configured correctly; summarize, report, analyze.
- `--users` / `--groups` — scan users and groups and their properties; summarize, report, analyze.
- `--logs=...` — comma-separated list (e.g. `--logs=auth,journal,misc`):
  - `auth` — `/var/log/auth.log`
  - `boot` — `/var/log/boot.log`
  - `journal` — `journalctl`. A `--journal=` switch (and matching config option) lets the user pass through journalctl options. Default flags: `-p 4 -b -n 500 --no-pager`.
  - `dmesg` — `/var/log/dmesg`
  - `kern` — `/var/log/kern.log`
  - `misc` — `/var/log/*`
  - Default when `--logs` is given without a value: `boot,dmesg,journal`.
- `--programs=...` — list of program-specific configurations to analyze. Not yet implemented.
- `--all` — scan everything above.
- No subcommand specified — scan procs and services.

## Commands

- `make build` — build `bin/sysaudit`.
- `make lint` — run `golangci-lint`.
- `make test` — run unit tests with `-race -count=1`. Switch output renderer with `TEST_RUNNER`: `make test TEST_RUNNER=gotestsum|gotestfmt|tparse` (default `go`).
- `make test-one PKG_=./internal/config NAME=TestLoad_FromYAML` — run a single test.
- `make cover` — write `coverage.html`.
- `make manpage` — regenerate the manpage *(stub: hooks into a hidden `gen-manpage` cobra command, not yet wired)*.
- Pre-commit gate: `make lint && make test` must pass.

## Architecture

```
cmd/sysaudit/           # main entrypoint
cmd/sysaudit/cmd/       # cobra root: flag wiring, scan dispatch, render
internal/scan/          # shared types: Result, Finding, Severity
internal/scan/procs/    # gopsutil-backed process scanner (implemented)
internal/scan/services/ # systemctl JSON + show (implemented)
internal/scan/users/    # not yet implemented
internal/scan/logs/     # not yet implemented
internal/claude/        # anthropic-sdk-go wrapper; token/level/verbosity controls
internal/report/        # WriteStdout (lipgloss + glamour) and WriteMarkdown
internal/config/        # viper-backed loader; XDG_CONFIG_HOME aware
internal/log/           # charmbracelet/log wrapper, level from CLI flags
internal/version/       # ldflags-injected build info
```

Data flow: `cmd dispatches → scan/* produces *scan.Result → claude/* analyzes → report/* renders to stdout (colorful) or file (markdown)`.

Subcommand selection (in `cmd/sysaudit/cmd/root.go`): `--all` → everything; otherwise the union of explicit switches; otherwise the spec default `procs + services`. Unimplemented kinds are logged and skipped, not fatal — as long as at least one implemented scan ran.

## Conventions

- Logging: `github.com/charmbracelet/log`. Do not use the stdlib `log` package or `fmt.Print*` for diagnostic output.
- Config precedence: CLI flags override `~/.config/sysaudit/config.yaml`.
- Every flag has both a long form and a single-letter short form.
- When adding or changing a subcommand or flag, update the manpage and `CHANGELOG.md` in the same change.
