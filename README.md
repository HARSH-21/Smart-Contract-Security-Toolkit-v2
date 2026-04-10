# Smart-Contract-Security-Toolkit-v2
Smart contract security toolkit written in Go for better speed,Multi-threading,More custom Detectors and well optimized results.

## Installation

git clone <repo>
cd sc-audit-go
bash install.sh

Optional:
bash install.sh --skip-heavy

## What installer does

- Installs Go if missing
- Installs required tools using pipx
- Configures PATH
- Builds sc-audit binary

## Verify installation

sc-audit --help
slither --version
myth --version
halmos --version

If commands are not found:
source ~/.bashrc

## Usage

Basic:
sc-audit contracts/Vault.sol

Advanced:
sc-audit --contract contracts/Vault.sol --out output --workers 8 --timeout 180 --verbose

## Output

output/report.md

## Notes

- Tools are installed using pipx to avoid system conflicts
- Missing tools are skipped at runtime
