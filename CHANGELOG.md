# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial scaffold: Go module, Makefile with switchable test runner (go|gotestsum|gotestfmt|tparse), golangci-lint config.
- `internal/log` package wrapping `charmbracelet/log`, level driven by `--verbose`/`--debug`/`--quiet`.
- `internal/config` package: viper-backed loader for `~/.config/sysaudit/config.yaml`; CLI flags override config values.
- `internal/scan/procs` process scanner via `gopsutil/v4`; emits a typed `Summary` with derived `Findings`.
- `internal/claude` client wrapping `anthropic-sdk-go`; honors `--tokens`, `--analysis-level`, `--claude-verbosity`.
- `internal/report` renderers: colorful stdout via `lipgloss` and markdown to file.
- `cmd/sysaudit` cobra CLI: `--procs` runs the full pipeline; other subcommands (`--services`, `--users`/`--groups`, `--logs`, `--all`, `--programs`) accept flags but exit with "not yet implemented".
