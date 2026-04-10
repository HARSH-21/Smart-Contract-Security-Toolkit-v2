package cli

import (
	"flag"
	"fmt"
)

// Config holds all parsed CLI options.
type Config struct {
	ContractPath string
	OutputDir    string
	Workers      int
	Timeout      int  // per-tool timeout in seconds
	SkipSlither  bool
	SkipMythril  bool
	SkipManticore bool
	SkipEchidna  bool
	SkipHalmos   bool
	Verbose      bool
	Help         bool
}

func ParseArgs() Config {
	cfg := Config{}

	flag.StringVar(&cfg.ContractPath, "contract", "", "Path to the Solidity contract (.sol)")
	flag.StringVar(&cfg.OutputDir, "out", "output", "Directory to write reports into")
	flag.IntVar(&cfg.Workers, "workers", 5, "Max concurrent tool workers")
	flag.IntVar(&cfg.Timeout, "timeout", 120, "Per-tool timeout in seconds")
	flag.BoolVar(&cfg.SkipSlither, "skip-slither", false, "Skip Slither static analysis")
	flag.BoolVar(&cfg.SkipMythril, "skip-mythril", false, "Skip Mythril symbolic execution")
	flag.BoolVar(&cfg.SkipManticore, "skip-manticore", false, "Skip Manticore symbolic execution")
	flag.BoolVar(&cfg.SkipEchidna, "skip-echidna", false, "Skip Echidna fuzzing")
	flag.BoolVar(&cfg.SkipHalmos, "skip-halmos", false, "Skip Halmos formal verification")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Print tool output to stdout as it arrives")
	flag.BoolVar(&cfg.Help, "help", false, "Print this help message")

	flag.Parse()

	// positional fallback: sc-audit <contract.sol>
	if cfg.ContractPath == "" && flag.NArg() > 0 {
		cfg.ContractPath = flag.Arg(0)
	}

	return cfg
}

func PrintHelp() {
	fmt.Println(`
sc-audit — Smart Contract Security Toolkit (Go edition)

USAGE
  sc-audit [options] <contract.sol>
  sc-audit --contract <contract.sol> [options]

OPTIONS`)
	flag.PrintDefaults()
	fmt.Println(`
EXAMPLES
  sc-audit contracts/Token.sol
  sc-audit --workers 8 --timeout 180 contracts/Vault.sol
  sc-audit --skip-manticore --skip-echidna contracts/Simple.sol
  sc-audit --verbose contracts/DEX.sol`)

}
