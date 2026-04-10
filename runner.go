package audit

import (
	"fmt"
	"os"
	"sync"
	"time"

	"sc-audit/internal/cli"
)

// Runner is the top-level orchestrator.
type Runner struct {
	cfg cli.Config
}

func NewRunner(cfg cli.Config) *Runner {
	return &Runner{cfg: cfg}
}

// Run executes the full audit pipeline and returns any fatal error.
func (r *Runner) Run() error {
	fmt.Printf("\n🚀  Smart Contract Security Audit\n")
	fmt.Printf("    Contract : %s\n", r.cfg.ContractPath)
	fmt.Printf("    Workers  : %d\n", r.cfg.Workers)
	fmt.Printf("    Timeout  : %ds per tool\n\n", r.cfg.Timeout)

	// Read source once; share it.
	src, err := os.ReadFile(r.cfg.ContractPath)
	if err != nil {
		return fmt.Errorf("read contract: %w", err)
	}

	var (
		toolResults []ToolResult
		findings    []Finding
		wg          sync.WaitGroup
		mu          sync.Mutex
	)

	// Kick off external tools and custom detectors concurrently.
	wg.Add(2)

	go func() {
		defer wg.Done()
		fmt.Println("[*] Running external tools concurrently...")
		res := runTools(r.cfg, r.cfg.ContractPath)
		mu.Lock()
		toolResults = res
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		fmt.Println("[*] Running custom exploit detectors...")
		f := DetectExploits(string(src))
		mu.Lock()
		findings = f
		mu.Unlock()
	}()

	wg.Wait()

	report := &Report{
		ContractPath: r.cfg.ContractPath,
		GeneratedAt:  time.Now(),
		ToolResults:  toolResults,
		Findings:     findings,
	}

	report.PrintSummary()
	return report.Write(r.cfg.OutputDir)
}
