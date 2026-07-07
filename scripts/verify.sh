#!/usr/bin/env bash
# Verification gate. Extended with Go build/vet once gateway code lands (M4).
set -euo pipefail
cd "$(dirname "$0")/.."
mapfile -t scripts < <(find . -name '*.sh' -not -path './.git/*')
shellcheck "${scripts[@]}"
if [ -f go.mod ]; then
  go vet ./...
  go build ./...
fi
echo "sshgw verify OK"
