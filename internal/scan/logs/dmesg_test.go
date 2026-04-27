package logs

import (
	"strings"
	"testing"
)

func TestParseDmesgLines_StripsCtimePrefix(t *testing.T) {
	in := []byte(`[Sun Apr 27 03:31:00 2026] kernel: Linux version 6.17.0
[Sun Apr 27 03:31:00 2026] Command line: BOOT_IMAGE=/boot/vmlinuz`)
	got := parseDmesgLines(in, 100)
	if len(got) != 2 {
		t.Fatalf("got %d entries", len(got))
	}
	if got[0].Message != "Linux version 6.17.0" {
		t.Errorf("first: %q", got[0].Message)
	}
	if got[1].Message != "Command line: BOOT_IMAGE=/boot/vmlinuz" {
		t.Errorf("second: %q", got[1].Message)
	}
}

func TestParseDmesgLines_StripsUptimePrefix(t *testing.T) {
	in := []byte(`[    4.212960] kernel: Linux version 6.17.0
[   12.345678] usb 1-1: new device`)
	got := parseDmesgLines(in, 100)
	if len(got) != 2 {
		t.Fatalf("got %d entries", len(got))
	}
	if got[0].Message != "Linux version 6.17.0" {
		t.Errorf("first: %q", got[0].Message)
	}
	if got[1].Message != "usb 1-1: new device" {
		t.Errorf("second: %q", got[1].Message)
	}
}

func TestParseDmesgLines_RespectsMaxLines(t *testing.T) {
	in := strings.Repeat("[    1.000000] x\n", 10)
	got := parseDmesgLines([]byte(in), 3)
	if len(got) != 3 {
		t.Errorf("max-lines cap: got %d want 3", len(got))
	}
}

func TestParseDmesgLines_SkipsBlanks(t *testing.T) {
	in := []byte("\n\n[    1.000000] real\n\n")
	got := parseDmesgLines(in, 100)
	if len(got) != 1 || got[0].Message != "real" {
		t.Errorf("got %+v", got)
	}
}
