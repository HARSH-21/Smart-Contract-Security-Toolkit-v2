package audit

import "time"

// Severity levels for findings.
type Severity string

const (
	SeverityCritical      Severity = "Critical"
	SeverityHigh          Severity = "High"
	SeverityMedium        Severity = "Medium"
	SeverityLow           Severity = "Low"
	SeverityInformational Severity = "Informational"
)

// Finding is a single vulnerability or observation.
type Finding struct {
	Source      string   // which tool or detector produced this
	Type        string   // e.g. "Reentrancy", "Unchecked Call"
	Severity    Severity
	Description string
	Line        int    // 0 = unknown
	Snippet     string // relevant code snippet, if available
}

// ToolResult is the raw output from one external tool run.
type ToolResult struct {
	Name     string
	Output   string
	Err      error
	Duration time.Duration
	Skipped  bool
}
