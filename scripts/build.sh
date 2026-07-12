#!/usr/bin/env bash
# Builds the two Pickle SSH gateway binaries into ./dist:
#   sshgw-proxyfront    — PROXY-required ingress shim (listens on the WG addr)
#   sshgw-route-plugin  — sshpiperd gRPC routing plugin (slug → pickle-api)
# The stock sshpiperd binary is installed separately by the LXC create script.
# CGO is disabled for a static, portable binary. Output is consumed by the
# infra deploy step (or copied into the sshgw LXC at /opt/pickle/sshgw/bin).
set -euo pipefail
cd "$(dirname "$0")/.."

out="${1:-dist}"
mkdir -p "$out"

export CGO_ENABLED=0
go build -trimpath -o "$out/sshgw-proxyfront" ./cmd/sshgw-proxyfront
go build -trimpath -o "$out/sshgw-route-plugin" ./cmd/sshgw-route-plugin

echo "built:"
ls -1 "$out"
