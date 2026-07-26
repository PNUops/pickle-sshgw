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
# Publication hygiene: no documentation-repo references, no private-repo or vault
# references, no internal process tokens. Enforced here because two manual scrubs
# both missed real violations.
# shellcheck source=scripts/hygiene.sh
. scripts/hygiene.sh   # cwd is the repo root (set above)
hygiene_selftest
hygiene_check public

echo "sshgw verify OK"
