package main

import (
	"fmt"
	"os"

	"sc-audit/internal/audit"
	"sc-audit/internal/cli"
)

func main() {
	cfg := cli.ParseArgs()

	if cfg.Help {
		cli.PrintHelp()
		os.Exit(0)
	}

	if cfg.ContractPath == "" {
		fmt.Fprintln(os.Stderr, "❌  No contract path provided.")
		cli.PrintHelp()
		os.Exit(1)
	}

	if _, err := os.Stat(cfg.ContractPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "❌  Contract file not found: %s\n", cfg.ContractPath)
		os.Exit(1)
	}

	runner := audit.NewRunner(cfg)
	if err := runner.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌  Audit failed: %v\n", err)
		os.Exit(1)
	}
}
