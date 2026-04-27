sysaudit 1 "April 2026" "sysaudit Manual"
==========================================

# NAME

sysaudit \- scan a Linux system for errors and misconfigurations and analyze the results with Claude

# SYNOPSIS

**sysaudit** [_global options_] [_subcommand switches_]

# DESCRIPTION

**sysaudit** scans a running Linux system across processes, services, users/groups, and logs, summarizes the findings, sends the summary to Claude for analysis, and writes a report. Output is colorful when written to a terminal and Markdown when written to a file via **\-\-output**.

If no subcommand switch is given, **sysaudit** scans processes and services.

# GLOBAL OPTIONS

**\-h**, **\-\-help**
  Show help and exit.

**\-\-version**
  Print version information and exit.

**\-v**, **\-\-verbose**
  Increase log verbosity.

**\-d**, **\-\-debug**
  Enable debug logging.

**\-q**, **\-\-quiet**
  Suppress non-error output.

**\-o**, **\-\-output**=_FILE_
  Write the report to _FILE_ as Markdown. Default: colorful output to stdout.

# CLAUDE OPTIONS

**\-t**, **\-\-tokens**=_N_
  Maximum tokens for Claude analysis. Default: 4096.

**\-m**, **\-\-model**=_MODEL_
  Claude model identifier. Default: **claude-opus-4-7**.

**\-A**, **\-\-analysis-level**=_LEVEL_
  Analysis depth: _summary_, _standard_ (default), or _deep_.

**\-\-claude-verbosity**=_LEVEL_
  Verbosity of the Claude prompt and response: _low_, _normal_ (default), or _high_.

**\-\-no-claude**
  Skip Claude analysis; emit scan results only. Useful for offline use or to avoid token spend during exploration.

# SUBCOMMAND SWITCHES

**\-p**, **\-\-procs**
  Scan running processes (pid, name, user, command, CPU%, memory%, threads, status). Surfaces zombies, high-CPU/memory processes, and high thread counts.

**\-s**, **\-\-services**
  Scan running user and system systemd services. Surfaces failed, masked, load-error, missing-fragment, world-writable unit files, and high restart counts.

**\-u**, **\-\-users**
  Scan **/etc/passwd** and **/etc/shadow**. Surfaces extra UID 0 users, UID/GID collisions, system accounts with login shells, members of privileged groups, empty/locked password hashes, and loose mode/owner on the three system files.

**\-g**, **\-\-groups**
  Same scan as **\-\-users**; the spec exposes both flags but they share one scanner.

**\-L**, **\-\-logs**[=_LIST_]
  Scan logs. _LIST_ is a comma-separated subset of _auth_, _boot_, _journal_, _dmesg_, _kern_, _misc_. With no value, defaults to _boot,dmesg,journal_.

**\-j**, **\-\-journal**=_FLAGS_
  Pass-through flag string for **journalctl** when the _journal_ source runs. Default: **-p 4 -b -n 500 \-\-no-pager**. Whitespace-split; quoted values with spaces are not supported.

**\-P**, **\-\-programs**[=_LIST_]
  Program-specific configuration audit. _LIST_ is a comma-separated subset of _sshd_, _nginx_, _postgres_, _apache_, _docker_, _cron_. With no value, runs every analyzer; each gracefully skips when the program isn't installed or has no config on this host.

**\-a**, **\-\-all**
  Scan everything implemented above. Logs are scanned across all six sources. Stub kinds emit "not yet implemented" warnings but do not fail the run.

# CONFIGURATION

**sysaudit** reads **~/.config/sysaudit/config.yaml** if present (or **$XDG_CONFIG_HOME/sysaudit/config.yaml**). CLI flags override config values. Example:

    journal: "-p 3 -b -n 1000 --no-pager"
    logs:
      - boot
      - journal
    claude:
      model: claude-opus-4-7
      max_tokens: 8192
      analysis_level: deep
      verbosity: normal

The Claude API key is read from **$ANTHROPIC_API_KEY** (or **claude.api_key** in the config file).

# EXAMPLES

Scan procs and services with Claude analysis to stdout:

    sysaudit

Scan everything to a Markdown report file:

    sysaudit --all --output report.md

Procs only, no Claude (no API spend):

    sysaudit --procs --no-claude

Logs scan with custom journalctl flags:

    sysaudit --logs=journal --journal="-p 3 --since today"

Deep analysis of a failing system:

    sysaudit --all --analysis-level deep --tokens 8192 -o /tmp/audit.md

# EXIT STATUS

**0**
  Success.

**1**
  Operational error (scan failed, Claude error, etc.).

**2**
  Invalid usage (unknown flag, bad **\-\-logs** source name, etc.).

# FILES

**~/.config/sysaudit/config.yaml**
  Per-user configuration.

**/etc/passwd**, **/etc/group**, **/etc/shadow**
  Read by the **\-\-users** scanner. **/etc/shadow** is best-effort; if unreadable the scan continues with a note.

**/var/log/auth.log**, **/var/log/boot.log**, **/var/log/dmesg**, **/var/log/kern.log**, **/var/log/\***
  Read by the **\-\-logs** scanner. Each file source falls back to **journalctl** when the file is missing or empty.

# ENVIRONMENT

**ANTHROPIC_API_KEY**
  Claude API key. Falls back to **claude.api_key** in **config.yaml**.

**XDG_CONFIG_HOME**
  Overrides **~/.config** as the configuration directory root.

**NO_COLOR**
  Disables ANSI color in stdout output.

# SEE ALSO

**journalctl**(1), **systemctl**(1), **dmesg**(1), **last**(1), **shadow**(5)
