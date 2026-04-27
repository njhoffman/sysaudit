package logs

import (
	"strings"
	"testing"
)

func TestParseJournalJSON_StringMessage(t *testing.T) {
	in := `{"__REALTIME_TIMESTAMP":"1714200000000000","_HOSTNAME":"h","_SYSTEMD_UNIT":"u.service","_PID":"123","MESSAGE":"hello","PRIORITY":"4"}` + "\n"
	got := parseJournalJSON(strings.NewReader(in), 100)
	if len(got) != 1 {
		t.Fatalf("got %d entries", len(got))
	}
	e := got[0]
	if e.Message != "hello" || e.Host != "h" || e.Unit != "u.service" || e.PID != "123" {
		t.Errorf("entry: %+v", e)
	}
	if e.Timestamp.IsZero() {
		t.Errorf("timestamp not parsed: %v", e.Timestamp)
	}
}

func TestParseJournalJSON_ByteArrayMessage(t *testing.T) {
	// journald emits MESSAGE as a numeric byte array when it can't decode
	// the payload as UTF-8. parseJournalJSON should still recover the text.
	in := `{"__REALTIME_TIMESTAMP":"1","MESSAGE":[104,101,108,108,111]}` + "\n"
	got := parseJournalJSON(strings.NewReader(in), 100)
	if len(got) != 1 || got[0].Message != "hello" {
		t.Errorf("byte-array decode: %+v", got)
	}
}

func TestParseJournalJSON_SkipsMalformed(t *testing.T) {
	in := `not json
{"MESSAGE":"good","__REALTIME_TIMESTAMP":"1"}
{broken
{"MESSAGE":"also good","__REALTIME_TIMESTAMP":"2"}
`
	got := parseJournalJSON(strings.NewReader(in), 100)
	if len(got) != 2 {
		t.Errorf("want 2 surviving entries, got %d: %+v", len(got), got)
	}
}

func TestParseJournalJSON_RespectsMaxLines(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString(`{"MESSAGE":"x","__REALTIME_TIMESTAMP":"1"}` + "\n")
	}
	got := parseJournalJSON(strings.NewReader(b.String()), 3)
	if len(got) != 3 {
		t.Errorf("max-lines cap: got %d want 3", len(got))
	}
}

func TestMessageString(t *testing.T) {
	if got := messageString("text"); got != "text" {
		t.Errorf("string passthrough: %q", got)
	}
	if got := messageString([]any{float64(72), float64(105)}); got != "Hi" {
		t.Errorf("byte array decode: %q", got)
	}
	if got := messageString(123); got != "" {
		t.Errorf("unsupported type: %q", got)
	}
}
