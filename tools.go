package audit

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"sc-audit/internal/cli"
)

// toolJob describes a single external tool invocation.
type toolJob struct {
	name    string
	args    []string
	skip    bool
	timeout time.Duration
}

// runTools executes all tool jobs concurrently, respecting the worker limit.
// It returns results in the order they finish.
func runTools(cfg cli.Config, contractPath string) []ToolResult {
	jobs := buildJobs(cfg, contractPath)

	sem := make(chan struct{}, cfg.Workers) // semaphore limits concurrency
	results := make([]ToolResult, len(jobs))
	var wg sync.WaitGroup

	for i, job := range jobs {
		wg.Add(1)
		go func(idx int, j toolJob) {
			defer wg.Done()

			if j.skip {
				results[idx] = ToolResult{Name: j.name, Skipped: true}
				return
			}

			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			results[idx] = execTool(j, cfg.Verbose)
		}(i, job)
	}

	wg.Wait()
	return results
}

// buildJobs constructs the list of tool invocations based on config.
func buildJobs(cfg cli.Config, path string) []toolJob {
	to := time.Duration(cfg.Timeout) * time.Second

	return []toolJob{
		{
			name:    "Slither",
			args:    []string{"slither", path},
			skip:    cfg.SkipSlither,
			timeout: to,
		},
		{
			name:    "Mythril",
			args:    []string{"myth", "analyze", path},
			skip:    cfg.SkipMythril,
			timeout: to,
		},
		{
			name:    "Manticore",
			args:    []string{"manticore", path},
			skip:    cfg.SkipManticore,
			timeout: to,
		},
		{
			name:    "Echidna",
			args:    []string{"echidna-test", path, "--config", "echidna.yaml"},
			skip:    cfg.SkipEchidna,
			timeout: to,
		},
		{
			name:    "Halmos",
			args:    []string{"halmos", "--contract-path", path},
			skip:    cfg.SkipHalmos,
			timeout: to,
		},
	}
}

// execTool runs a single external command with timeout, capturing output.
func execTool(job toolJob, verbose bool) ToolResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), job.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, job.args[0], job.args[1:]...)

	var buf bytes.Buffer
	if verbose {
		// tee output to both buffer and stdout
		cmd.Stdout = &prefixWriter{prefix: "[" + job.name + "] ", buf: &buf}
		cmd.Stderr = &prefixWriter{prefix: "[" + job.name + "] ", buf: &buf}
	} else {
		cmd.Stdout = &buf
		cmd.Stderr = &buf
	}

	err := cmd.Run()
	elapsed := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %v", job.timeout)
	}

	return ToolResult{
		Name:     job.name,
		Output:   buf.String(),
		Err:      err,
		Duration: elapsed,
	}
}

// prefixWriter writes bytes to an underlying buffer, prefixing each new line.
type prefixWriter struct {
	prefix  string
	buf     *bytes.Buffer
	newLine bool
}

func (pw *prefixWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if pw.newLine || pw.buf.Len() == 0 {
			pw.buf.WriteString(pw.prefix)
			pw.newLine = false
		}
		pw.buf.WriteByte(b)
		if b == '\n' {
			pw.newLine = true
		}
	}
	fmt.Print(string(p)) // also echo to stdout when verbose
	return len(p), nil
}
