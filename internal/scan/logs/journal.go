package logs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// scanJournal runs journalctl with the user's passthrough flags plus a
// forced --output=json (last-wins) so we can parse reliably regardless of
// what format string the user supplied.
func scanJournal(ctx context.Context, opts Options) (SourceResult, error) {
	out := SourceResult{Source: SourceJournal}

	args := splitArgs(opts.JournalArgs)
	// Force JSON output for stable parsing. journalctl resolves the last
	// --output flag, so this overrides anything the user passed.
	args = append(args, "--output=json")

	path, err := exec.LookPath("journalctl")
	if err != nil {
		return out, fmt.Errorf("journalctl not found: %w", err)
	}
	// #nosec G204 -- args derived from a curated CLI/config string under
	// the user's own privilege; journalctl path is from LookPath.
	cmd := exec.CommandContext(ctx, path, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return out, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return out, err
	}

	entries := parseJournalJSON(stdout, opts.MaxLines)

	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out, fmt.Errorf("journalctl exited %d: %s",
				ee.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return out, err
	}

	out.LinesRead = len(entries)
	out.Buckets = TopBuckets(entries, opts.TopBuckets)
	out.Findings = ApplyRules(SourceJournal, entries)
	return out, nil
}

// journalRecord is the subset of journalctl --output=json fields we use.
type journalRecord struct {
	Realtime string `json:"__REALTIME_TIMESTAMP"`
	Hostname string `json:"_HOSTNAME"`
	Unit     string `json:"_SYSTEMD_UNIT"`
	PID      string `json:"_PID"`
	Message  any    `json:"MESSAGE"`
	Priority string `json:"PRIORITY"`
}

// parseJournalJSON reads one JSON object per line and stops once maxLines
// entries are accumulated.
func parseJournalJSON(r interface {
	Read(p []byte) (n int, err error)
}, maxLines int) []Entry {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	out := []Entry{}
	for scanner.Scan() {
		if maxLines > 0 && len(out) >= maxLines {
			continue // drain so journalctl doesn't block on a full pipe
		}
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec journalRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		msg := messageString(rec.Message)
		if msg == "" {
			continue
		}
		e := Entry{
			Source:    SourceJournal,
			Host:      rec.Hostname,
			Unit:      rec.Unit,
			PID:       rec.PID,
			Message:   msg,
			Timestamp: parseRealtime(rec.Realtime),
			Raw:       string(line),
		}
		out = append(out, e)
	}
	return out
}

// messageString flattens MESSAGE which can be a string OR a list of bytes
// (numeric array) when journald couldn't decode the payload as UTF-8.
func messageString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		buf := make([]byte, 0, len(t))
		for _, b := range t {
			n, ok := b.(float64)
			if !ok || n < 0 || n > 255 {
				continue
			}
			buf = append(buf, byte(n))
		}
		return string(buf)
	}
	return ""
}

// parseRealtime converts journald's __REALTIME_TIMESTAMP (microseconds
// since epoch, as a numeric string) to a Go time.
func parseRealtime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	usec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMicro(usec)
}

// splitArgs splits a passthrough flag string on whitespace. This is
// deliberately simple — quoted values with spaces are not supported; users
// who need that should set the flag list as a YAML array in the config.
// Returns nil for an empty/whitespace-only input so callers can tell "no
// args supplied" from "no parseable tokens".
func splitArgs(s string) []string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return nil
	}
	return f
}
