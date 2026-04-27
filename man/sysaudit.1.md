# sysaudit(1)

## NAME

sysaudit - scan a Linux system for errors and misconfigurations and analyze the results with Claude.

## SYNOPSIS

`sysaudit` [global options] [subcommand flags]

## DESCRIPTION

`sysaudit` scans a running Linux system across processes, services, users/groups, and logs, summarizes the findings, sends the summary to Claude for analysis, and writes a report. Output is colorful when written to a terminal and markdown when written to a file.

If no subcommand flag is given, `sysaudit` scans processes and services.

## GLOBAL OPTIONS

`-h, --help`
:   Show help.

`-V, --version`
:   Print version information and exit.

`-v, --verbose`
:   Increase log verbosity.

`-d, --debug`
:   Enable debug logging.

`-q, --quiet`
:   Suppress non-error output.

`-o, --output FILE`
:   Write the report to FILE as markdown. Default: colorful output to stdout.

## CLAUDE OPTIONS

`-t, --tokens N`
:   Maximum tokens for Claude analysis.

`-l, --analysis-level LEVEL`
:   Analysis depth: `summary`, `standard` (default), `deep`.

`-V, --claude-verbosity LEVEL`
:   Verbosity of the Claude prompt and response: `low`, `normal`, `high`.

## SUBCOMMAND FLAGS

`-p, --procs`
:   Scan running processes.

`-s, --services`
:   Scan running user and system services.

`-u, --users`, `-g, --groups`
:   Scan users and groups.

`-L, --logs LIST`
:   Comma-separated list of logs to scan: `auth`, `boot`, `journal`, `dmesg`, `kern`, `misc`. Default: `boot,dmesg,journal`.

`-j, --journal FLAGS`
:   Pass-through flags for `journalctl`. Default: `-p 4 -b -n 500 --no-pager`.

`-P, --programs LIST`
:   Program-specific configurations to analyze. *(Not yet implemented.)*

`-a, --all`
:   Scan everything above.

## CONFIGURATION

`sysaudit` reads `~/.config/sysaudit/config.yaml` if present. CLI flags override config values.

The Claude API key is read from `$ANTHROPIC_API_KEY` (or `claude.api_key` in the config file).

## EXIT STATUS

`0`
:   Success.

`1`
:   Operational error.

`2`
:   Invalid usage.

## SEE ALSO

`journalctl`(1), `dmesg`(1), `systemctl`(1)
