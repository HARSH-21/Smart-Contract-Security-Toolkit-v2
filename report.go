package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Report aggregates everything produced during a run.
type Report struct {
	ContractPath string
	GeneratedAt  time.Time
	ToolResults  []ToolResult
	Findings     []Finding
}

// Write serialises the report to <outputDir>/report.md.
func (r *Report) Write(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	path := filepath.Join(outputDir, "report.md")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	w := func(format string, args ...any) {
		fmt.Fprintf(f, format, args...)
	}

	// ── Header ────────────────────────────────────────────────────────────────
	w("# Smart Contract Audit Report\n\n")
	w("> **Generated:** %s  \n", r.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	w("> **Contract:** `%s`  \n\n", r.ContractPath)
	w("---\n\n")

	// ── Executive Summary ─────────────────────────────────────────────────────
	counts := r.severityCounts()
	w("## Executive Summary\n\n")
	w("| Severity | Count |\n|----------|-------|\n")
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational} {
		w("| %s | %d |\n", sev, counts[sev])
	}
	w("\n")

	// ── Tool Results ──────────────────────────────────────────────────────────
	w("## Tool Outputs\n\n")
	for _, tr := range r.ToolResults {
		if tr.Skipped {
			w("### %s — ⏭ Skipped\n\n", tr.Name)
			continue
		}
		status := "✅"
		if tr.Err != nil {
			status = "⚠️"
		}
		w("### %s %s  _(%.1fs)_\n\n", tr.Name, status, tr.Duration.Seconds())
		if tr.Err != nil {
			w("> **Error:** %v\n\n", tr.Err)
		}
		if tr.Output != "" {
			out := tr.Output
			if len(out) > 2000 {
				out = out[:2000] + "\n... [truncated] ..."
			}
			w("```\n%s\n```\n\n", out)
		} else {
			w("_No output_\n\n")
		}
	}

	// ── Custom Findings ───────────────────────────────────────────────────────
	w("## Custom Exploit Detections\n\n")

	if len(r.Findings) == 0 {
		w("✅ No issues detected by custom detectors.\n\n")
	} else {
		sorted := r.sortedFindings()
		for _, f := range sorted {
			icon := severityIcon(f.Severity)
			w("### %s %s — %s\n\n", icon, f.Severity, f.Type)
			w("**Source:** %s  \n", f.Source)
			if f.Line > 0 {
				w("**Line:** %d  \n", f.Line)
			}
			w("\n%s\n\n", f.Description)
			if f.Snippet != "" {
				w("```solidity\n%s\n```\n\n", f.Snippet)
			}
			w("---\n\n")
		}
	}

	// ── Remediation Checklist ─────────────────────────────────────────────────
	w("## Remediation Checklist\n\n")
	for _, f := range r.sortedFindings() {
		w("- [ ] **%s** (%s): %s\n", f.Type, f.Severity, shortDescription(f.Description))
	}
	w("\n")

	fmt.Printf("✅  Report written → %s\n", path)
	return nil
}

// PrintSummary prints a compact terminal summary.
func (r *Report) PrintSummary() {
	counts := r.severityCounts()
	total := 0
	for _, c := range counts {
		total += c
	}

	fmt.Println("\n╔══════════════════════════════════════╗")
	fmt.Println("║        AUDIT SUMMARY                 ║")
	fmt.Println("╠══════════════════════════════════════╣")
	fmt.Printf("║  Contract : %-25s║\n", truncate(filepath.Base(r.ContractPath), 25))
	fmt.Printf("║  Findings : %-25d║\n", total)
	fmt.Println("╠══════════╦═══════════════════════════╣")
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		fmt.Printf("║  %-9s║ %s%-25s║\n", sev, severityIcon(sev)+" ", fmt.Sprintf("%d finding(s)", counts[sev]))
	}
	fmt.Println("╚══════════╩═══════════════════════════╝")

	// Tool timing
	fmt.Println("\n⏱  Tool timings:")
	for _, tr := range r.ToolResults {
		if tr.Skipped {
			fmt.Printf("   %-12s  skipped\n", tr.Name)
		} else {
			status := "✅"
			if tr.Err != nil {
				status = "⚠️"
			}
			fmt.Printf("   %-12s  %.2fs  %s\n", tr.Name, tr.Duration.Seconds(), status)
		}
	}
	fmt.Println()
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (r *Report) severityCounts() map[Severity]int {
	m := map[Severity]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

var severityOrder = map[Severity]int{
	SeverityCritical:      0,
	SeverityHigh:          1,
	SeverityMedium:        2,
	SeverityLow:           3,
	SeverityInformational: 4,
}

func (r *Report) sortedFindings() []Finding {
	cp := make([]Finding, len(r.Findings))
	copy(cp, r.Findings)
	sort.Slice(cp, func(i, j int) bool {
		oi := severityOrder[cp[i].Severity]
		oj := severityOrder[cp[j].Severity]
		return oi < oj
	})
	return cp
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🟢"
	default:
		return "🔵"
	}
}

func shortDescription(d string) string {
	if idx := strings.Index(d, "."); idx > 0 && idx < 80 {
		return d[:idx+1]
	}
	return truncate(d, 80)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
