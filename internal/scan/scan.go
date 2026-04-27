// Package scan defines types shared by all scanners (procs, services, users, logs).
package scan

import "time"

// Severity ranks finding seriousness.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityNotice   Severity = "notice"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// Finding is a single derived anomaly produced by a scanner.
type Finding struct {
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject"`
	Detail   string   `json:"detail"`
}

// Result is the contract every scanner returns. Scanners describe the surface
// they cover via Kind (e.g. "procs", "services") and provide a digest plus a
// list of derived findings.
type Result struct {
	Kind       string         `json:"kind"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Summary    map[string]any `json:"summary"`
	Findings   []Finding      `json:"findings"`
}
