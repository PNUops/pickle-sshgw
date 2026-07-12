#!/usr/bin/env bash
# Verification gate for the sshgw repo: shellcheck all scripts, and (once Go
# code is present) gofmt + vet + build + test the gateway daemons.
set -euo pipefail
cd "$(dirname "$0")/.."
mapfile -t scripts < <(find . -name '*.sh' -not -path './.git/*')
shellcheck "${scripts[@]}"
if [ -f go.mod ]; then
  unformatted=$(gofmt -l . || true)
  if [ -n "$unformatted" ]; then
    echo "gofmt needed on:" >&2
    echo "$unformatted" >&2
    exit 1
  fi
  go vet ./...
  go build ./...
  go test ./...
fi
echo "sshgw verify OK"
