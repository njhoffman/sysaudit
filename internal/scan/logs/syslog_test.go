package logs

import (
	"strings"
	"testing"
)

func TestReadSyslogFile_StripsRFC3164Prefix(t *testing.T) {
	in := `Apr 27 05:32:26 charon sudo: pam_unix(sudo:auth): authentication failure
Apr 27 05:33:00 charon sshd[1234]: Failed password for root from 10.0.0.1 port 22
`
	got := readSyslogFile(strings.NewReader(in), SourceAuth, 0)
	if len(got) != 2 {
		t.Fatalf("got %d entries", len(got))
	}
	if got[0].Message != "sudo: pam_unix(sudo:auth): authentication failure" {
		t.Errorf("first: %q", got[0].Message)
	}
	if got[1].Message != "sshd[1234]: Failed password for root from 10.0.0.1 port 22" {
		t.Errorf("second: %q", got[1].Message)
	}
}

func TestReadSyslogFile_StripsISOPrefix(t *testing.T) {
	in := "2026-04-27T05:32:26-05:00 charon kernel: BUG: scheduling while atomic\n"
	got := readSyslogFile(strings.NewReader(in), SourceKern, 0)
	if len(got) != 1 || got[0].Message != "kernel: BUG: scheduling while atomic" {
		t.Errorf("got %+v", got)
	}
}

func TestReadSyslogFile_RespectsMaxLines(t *testing.T) {
	in := strings.Repeat("Apr 27 05:00:00 host prog: line\n", 10)
	got := readSyslogFile(strings.NewReader(in), SourceAuth, 3)
	if len(got) != 3 {
		t.Errorf("max-lines cap: got %d want 3", len(got))
	}
}

func TestReadSyslogFile_SkipsBlanks(t *testing.T) {
	in := "\n\nApr 27 05:00:00 host prog: real\n\n"
	got := readSyslogFile(strings.NewReader(in), SourceAuth, 0)
	if len(got) != 1 || got[0].Message != "prog: real" {
		t.Errorf("got %+v", got)
	}
}

func TestReadSyslogFile_HandlesMissingPrefix(t *testing.T) {
	// Lines without a recognizable prefix pass through verbatim — better
	// than dropping them, since at minimum the rule engine still runs.
	in := "no timestamp here just a message\n"
	got := readSyslogFile(strings.NewReader(in), SourceMisc, 0)
	if len(got) != 1 || got[0].Message != "no timestamp here just a message" {
		t.Errorf("got %+v", got)
	}
}
