# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

The repository is pre-implementation: no Go code, `go.mod`, `Makefile`, manpage, or `CHANGELOG.md` exists yet. Everything below the **Specification** section describes *intended* commands and architecture derived from the spec, not facts on disk. Update those sections to reflect reality as code lands. The spec itself is the source of truth for what to build.

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

## Intended commands (not yet implemented)

These targets are derived from the spec. They do not exist on disk yet; treat them as the contract to honor when scaffolding the `Makefile`.

- `make build` — build the `sysaudit` binary.
- `make lint` — run the Go linter (e.g. `golangci-lint run`).
- `make test` — run unit and integration tests. Honor a variable to switch the runner between `gotestsum`, `gotestfmt`, and `tparse` (e.g. `make test TEST_RUNNER=tparse`).
- `make manpage` — regenerate the manpage.
- Single test (canonical Go form): `go test ./path/to/pkg -run TestName -v`. A `make test-one PKG=... NAME=...` wrapper may be added later.
- Pre-commit gate: `make lint && make test` must pass before any commit (per spec).

## Intended architecture (not yet implemented)

A planned package layout derived from the subcommand surface. Use this as the starting shape when scaffolding; deviate when the code reveals a better split.

```
cmd/sysaudit/           # CLI entrypoint, flag parsing, subcommand dispatch
internal/scan/
  procs/                # process scanner
  services/             # systemd unit scanner (system + user)
  users/                # users & groups scanner
  logs/                 # log scanners: auth, boot, journal, dmesg, kern, misc
internal/claude/        # Claude API client; token/verbosity/analysis-level controls
internal/report/        # stdout (colorful) and markdown renderers
internal/config/        # ~/.config/sysaudit/config.yaml loading + flag merge
internal/log/           # charmbracelet/log wiring (verbose/debug/quiet)
```

Intended data flow: `scan/* → summary struct → claude/* (analysis) → report/* (stdout | markdown)`.

## Conventions

- Logging: `github.com/charmbracelet/log`. Do not use the stdlib `log` package or `fmt.Print*` for diagnostic output.
- Config precedence: CLI flags override `~/.config/sysaudit/config.yaml`.
- Every flag has both a long form and a single-letter short form.
- When adding or changing a subcommand or flag, update the manpage and `CHANGELOG.md` in the same change.
