package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/sysaudit/internal/claude"
	"github.com/njhoffman/sysaudit/internal/scan"
)

func sampleReport() *Report {
	t0 := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	return &Report{
		GeneratedAt: t0,
		Hostname:    "testhost",
		Results: []*scan.Result{
			{
				Kind:       "procs",
				StartedAt:  t0,
				FinishedAt: t0.Add(150 * time.Millisecond),
				Summary: map[string]any{
					"total":     42,
					"by_status": map[string]int{"running": 30, "sleeping": 12},
				},
				Findings: []scan.Finding{
					{Severity: scan.SeverityWarning, Subject: "1 zombie process(es)", Detail: "stale-child(1234)"},
					{Severity: scan.SeverityNotice, Subject: "high CPU: yes(2) 90.0%", Detail: "user=root cmd=/bin/yes"},
				},
			},
		},
		Analysis: &claude.Analysis{
			Model:        "claude-opus-4-7",
			InputTokens:  1234,
			OutputTokens: 567,
			Text:         "## Summary\n\nLooks healthy aside from a stale child.",
		},
	}
}

func TestWriteMarkdown_StableShape(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	mustContain(t, out, "# sysaudit report")
	mustContain(t, out, "**Host:** testhost")
	mustContain(t, out, "**Model:** claude-opus-4-7")
	mustContain(t, out, "## Findings")
	mustContain(t, out, "| Severity | Kind | Subject | Detail |")
	mustContain(t, out, "1 zombie process(es)")
	mustContain(t, out, "## Scan summaries")
	mustContain(t, out, "### procs")
	mustContain(t, out, "## Claude analysis")
	mustContain(t, out, "Looks healthy aside from a stale child.")
}

func TestWriteMarkdown_NoFindings(t *testing.T) {
	r := sampleReport()
	r.Results[0].Findings = nil
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	mustContain(t, buf.String(), "_No findings._")
}

func TestWriteMarkdown_EscapesPipes(t *testing.T) {
	r := sampleReport()
	r.Results[0].Findings = []scan.Finding{
		{Severity: scan.SeverityInfo, Subject: "pipe | in subject", Detail: "newline\nin detail"},
	}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	mustContain(t, out, `pipe \| in subject`)
	if strings.Contains(out, "newline\nin detail") {
		t.Errorf("newline in detail not escaped: %q", out)
	}
}

func TestWriteStdout_NoError(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	if err := WriteStdout(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	mustContain(t, out, "sysaudit report")
	mustContain(t, out, "Findings")
	mustContain(t, out, "Scan summaries")
}

func TestSeverityRank(t *testing.T) {
	if severityRank(scan.SeverityCritical) <= severityRank(scan.SeverityWarning) {
		t.Errorf("critical should outrank warning")
	}
	if severityRank(scan.SeverityWarning) <= severityRank(scan.SeverityInfo) {
		t.Errorf("warning should outrank info")
	}
}

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("output missing %q\n--- output ---\n%s\n---", sub, s)
	}
}
