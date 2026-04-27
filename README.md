# sysaudit

[![CI](https://github.com/njhoffman/sysaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/njhoffman/sysaudit/actions/workflows/ci.yml)

A Go CLI for Linux (Ubuntu) that scans the system across processes, services, users/groups, logs, and per-program configuration; bundles the findings into a structured digest; sends that digest to [Claude](https://www.anthropic.com/claude) for analysis; and writes a report.

Output is colorful when written to a terminal and Markdown when written to a file. Run `sysaudit --no-claude` to skip the Claude call entirely (useful for offline use or to avoid token spend during exploration).

## Quickstart

```sh
# Build the binary into ./bin/sysaudit
make build

# Default scan (procs + services), colorful output, with Claude analysis
export ANTHROPIC_API_KEY=sk-...
./bin/sysaudit

# Skip Claude
./bin/sysaudit --no-claude

# Full audit, write a Markdown report
./bin/sysaudit --all --output audit.md

# Targeted scans
./bin/sysaudit --procs --services --users
./bin/sysaudit --logs=auth,journal --journal="-p 3 -b -n 1000 --no-pager"
./bin/sysaudit --programs=sshd
```

## What it scans

| Switch                | Source                                              | Notable findings                                                                                       |
|-----------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `--procs` / `-p`      | `gopsutil`                                          | zombies, high CPU/memory/thread-count                                                                  |
| `--services` / `-s`   | `systemctl --output=json` + `systemctl show`        | failed/masked units, load errors, missing fragment, world-writable unit files, high restart counts    |
| `--users` / `-u`      | `/etc/passwd`, `/etc/group`, `/etc/shadow`          | extra UID 0, UID/GID collisions, system accounts with login shells, privileged-group membership, weak hashes, loose mode/owner |
| `--groups` / `-g`     | same scanner as `--users`                           | (alias)                                                                                                |
| `--logs` / `-L`       | `journalctl`, `dmesg`, `/var/log/{auth,boot,kern}.log`, `/var/log/*` | bucketed pattern aggregation; rule findings for kernel panic, OOM kill, hardware error, kernel BUG, segfault, I/O error, FS error, auth failure |
| `--programs` / `-P`   | per-program audits (`sshd`, `nginx`, `postgres`, `apache`, `docker`, `cron`) | hardening checklists per program; auto-skips when not installed                          |
| `--all` / `-a`        | every scanner above; `--logs` covers all 6 sources  |                                                                                                        |

`sysaudit` falls back gracefully when something isn't available: shadow not readable as a regular user, `/var/log/auth.log` empty on a journald-only host, kernel ring buffer restricted, nginx not installed, etc. Each falls back to the next-best source or surfaces a self-explanatory note rather than aborting the scan.

## Configuration

`sysaudit` reads `~/.config/sysaudit/config.yaml` (or `$XDG_CONFIG_HOME/sysaudit/config.yaml`) if present. CLI flags override config values.

```yaml
# ~/.config/sysaudit/config.yaml
journal: "-p 3 -b -n 1000 --no-pager"
claude:
  api_key: sk-...           # falls back to $ANTHROPIC_API_KEY when omitted
  model: claude-opus-4-7
  max_tokens: 8192
  analysis_level: deep      # summary | standard | deep
  verbosity: normal         # low | normal | high
```

## Output

- **stdout** (default): colored by severity (`CRITICAL`/`ERROR`/`WARNING`/`NOTICE`/`INFO`), with a per-scan summary block and the Claude analysis rendered as TTY-friendly Markdown via [`glamour`](https://github.com/charmbracelet/glamour). Honors `NO_COLOR`.
- **`--output FILE`**: stable Markdown — header, findings table, per-scan summary, Claude analysis verbatim. Suitable for archiving or piping into a follow-up tool.

## Development

```sh
make build              # builds bin/sysaudit
make lint               # golangci-lint
make test               # go test -race -count=1 ./... (default runner)
make test TEST_RUNNER=tparse        # pretty output via mfridman/tparse
make test TEST_RUNNER=gotestsum     # gotestsum output
make test TEST_RUNNER=gotestfmt     # gotesttools/gotestfmt output
make test-one PKG_=./internal/config NAME=TestLoad_FromYAML

make manpage            # renders man/sysaudit.1 from man/sysaudit.1.md
make cover              # writes coverage.html
```

Lint and tests must pass before any commit.

## Documentation

- **[`man/sysaudit.1.md`](man/sysaudit.1.md)** — full manpage source. `make manpage` renders the groff-formatted `.1` file.
- **[`CHANGELOG.md`](CHANGELOG.md)** — what changed, when, and why.
- **[`CLAUDE.md`](CLAUDE.md)** — guidance for Claude Code instances working in this repo (specification, package layout, conventions).
