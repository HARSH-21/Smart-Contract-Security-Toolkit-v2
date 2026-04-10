#!/usr/bin/env bash
set -euo pipefail

SKIP_HEAVY=false
for arg in "$@"; do
  case $arg in
    --skip-heavy) SKIP_HEAVY=true ;;
  esac
done

has() { command -v "$1" &>/dev/null; }

echo "== sc-audit installer =="

if ! has python3; then
  echo "python3 not found. Install it first."
  exit 1
fi

if ! has pipx; then
  python3 -m pip install --user pipx
  python3 -m pipx ensurepath
fi

export PATH="$HOME/.local/bin:$PATH"

if ! grep -q '.local/bin' "$HOME/.bashrc" 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi

pipx install slither-analyzer --force || true
pipx install mythril --force || true
pipx install halmos --force || true

if [ "$SKIP_HEAVY" = false ]; then
  pipx install manticore --force || true
fi

if ! has echidna; then
  curl -fsSL https://github.com/crytic/echidna/releases/latest/download/echidna-Linux.zip -o /tmp/echidna.zip
  unzip -q /tmp/echidna.zip -d /tmp/echidna
  chmod +x /tmp/echidna/echidna
  sudo mv /tmp/echidna/echidna /usr/local/bin/
  rm -rf /tmp/echidna*
fi

if ! has go; then
  curl -fsSL https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -o /tmp/go.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
  export PATH="/usr/local/go/bin:$PATH"
  echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$HOME/.bashrc"
fi

go build -o sc-audit .

sudo mv sc-audit /usr/local/bin/sc-audit

echo "Installation complete"
echo "Run: source ~/.bashrc"
