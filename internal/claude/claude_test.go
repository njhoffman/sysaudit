package claude

import (
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/sysaudit/internal/scan"
)

func TestNew_Validation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("expected error for missing model")
	}
	if _, err := New(Options{Model: "x"}); err == nil {
		t.Error("expected error for non-positive max_tokens")
	}
	if _, err := New(Options{Model: "x", MaxTokens: 1}); err != nil {
		t.Errorf("valid options should not error: %v", err)
	}
}

func TestNormalizeLevel(t *testing.T) {
	cases := map[string]string{
		"":         "standard",
		"summary":  "summary",
		"BRIEF":    "summary",
		"deep":     "deep",
		"detailed": "deep",
		"random":   "standard",
	}
	for in, want := range cases {
		if got := normalizeLevel(in); got != want {
			t.Errorf("normalizeLevel(%q) = %q want %q", in, got, want)
		}
	}
}

func TestNormalizeVerbosity(t *testing.T) {
	cases := map[string]string{
		"":        "normal",
		"low":     "low",
		"QUIET":   "low",
		"high":    "high",
		"verbose": "high",
	}
	for in, want := range cases {
		if got := normalizeVerbosity(in); got != want {
			t.Errorf("normalizeVerbosity(%q) = %q want %q", in, got, want)
		}
	}
}

func TestBuildPrompt_Empty(t *testing.T) {
	if _, err := buildPrompt(nil, "standard", "normal"); err == nil {
		t.Error("expected error for empty results")
	}
}

func TestBuildPrompt_IncludesKindsAndPayload(t *testing.T) {
	r := []*scan.Result{
		{
			Kind:       "procs",
			StartedAt:  time.Now(),
			FinishedAt: time.Now(),
			Summary:    map[string]any{"total": 7},
			Findings:   []scan.Finding{{Severity: scan.SeverityWarning, Subject: "x"}},
		},
	}
	out, err := buildPrompt(r, "deep", "high")
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"procs", "deep", "high", `"total": 7`} {
		if !strings.Contains(out, sub) {
			t.Errorf("buildPrompt output missing %q\n--- output ---\n%s\n---", sub, out)
		}
	}
}

func TestSystemPrompt_VariesByLevel(t *testing.T) {
	a := systemPrompt("summary")
	b := systemPrompt("standard")
	c := systemPrompt("deep")
	if a == b || b == c || a == c {
		t.Error("systemPrompt should differ across levels")
	}
}
