package logs

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// reSyslogPrefix matches a leading "MMM DD HH:MM:SS host " (RFC 3164) or
// "<ISO-8601> host " timestamp+host prefix. Stripping it leaves the
// program tag and message, which is what the bucketer/rules consume.
var reSyslogPrefix = regexp.MustCompile(
	`^(?:[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.+\-Z]+)\s+\S+\s+`,
)

// readSyslogFile parses a syslog-style log file (auth.log, kern.log, etc.).
// Each Entry has the timestamp+host prefix stripped from Message; the
// remaining text typically looks like "prog[pid]: ...". Empty lines and
// lines past maxLines are dropped.
func readSyslogFile(r io.Reader, src Source, maxLines int) []Entry {
	out := []Entry{}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		if maxLines > 0 && len(out) >= maxLines {
			break
		}
		raw := s.Text()
		msg := strings.TrimSpace(reSyslogPrefix.ReplaceAllString(raw, ""))
		if msg == "" {
			continue
		}
		out = append(out, Entry{Source: src, Message: msg, Raw: raw})
	}
	return out
}
