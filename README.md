# pickle-sshgw

SSH gateway for Pickle: routes `ssh <vmslug>@ssh.pickle.pnuops.com` to the
student's VM after authorizing against pickle-api. Off-campus reachability is an
AWS Lightsail relay: the campus opens an **outbound** WireGuard tunnel to it and
Lightsail's HAProxy (`mode tcp`, `send-proxy-v2`) forwards public `:22` →
tunnel → `sshgw:22` (the campus firewall blocks inbound, so a plain relay cannot
reach in). The host keeps `:8022` for admin SSH — no host SSH cutover. See
`docs/plan/05-ssh-access.md` and the internal routing contract in
`docs/api/internal.md` (pickle-docs repo).

## Components

Three processes run inside the `sshgw` LXC (172.30.1.30); the two custom Go
binaries are built from this repo, `sshpiperd` is the stock upstream binary.

1. **`sshgw-proxyfront`** (`cmd/sshgw-proxyfront`, `internal/proxyfront`) — the
   `:22` ingress shim, bound to the WireGuard interface address
   (`10.100.100.2:22`). It enforces the frozen contract's PROXY-protocol trust
   conditions (`docs/api/internal.md` Link 1): the listener runs in
   **PROXY-v2-REQUIRED** mode restricted to the WireGuard peer
   (`TrustProxyHeaderFromRanges`), so a connection that is headerless,
   carries a malformed header, or comes from a non-peer source is **dropped
   with no SSH bytes exchanged** — there is no fallback to the raw TCP source.
   It then re-emits a fresh PROXY v2 header carrying the recovered real client
   IP to loopback sshpiperd and splices the bytes.

   *Why a shim:* stock sshpiperd's `--allowed-proxy-addresses` only offers
   go-proxyproto's deprecated **lax** policy (header optional for the peer),
   which would serve a headerless connection raw — violating contract
   conditions #1/#3. The shim closes exactly that gap while keeping sshpiperd
   stock and upgradeable.

2. **`sshpiperd`** (stock, v1.5.4) on `127.0.0.1:2222`, launched with
   `--allowed-proxy-addresses 127.0.0.1/32` (lax is safe here — only the shim
   connects, and it always sends a header) and our routing plugin. It does the
   transparent SSH piping that keeps scp/sftp/VSCode Remote working.

3. **`sshgw-route-plugin`** (`cmd/sshgw-route-plugin`, `internal/gateway`,
   `internal/route`) — the sshpiperd gRPC plugin. Its `PasswordCallback` reads
   the SSH username as the VM slug and the real client IP from the connection,
   calls `POST /internal/sshgw/route` (Bearer `PICKLE_SSHGW_TOKEN`), and on
   success pipes to the VM as the returned user, **passing the typed password
   through** to the VM's own sshd (v1 shared-password model). Any denial or
   error refuses the session; with no token the plugin refuses to start
   (fail-closed).

Ingress path: `client → HAProxy(send-proxy-v2) → WireGuard → proxyfront:22
(REQUIRE, peer-only) → sshpiperd:2222(loopback) → plugin → VM:22`.

## Deployment

The `sshgw` LXC, WireGuard endpoint (`wg0` = 10.100.100.2/30), systemd units,
and peer-only nftables firewall are provisioned by
`infra/scripts/create-sshgw-lxc.sh` (infra repo). This repo builds the daemons:

```bash
scripts/setup-hooks.sh   # once: install git hooks
scripts/verify.sh        # shellcheck + gofmt + go vet/build/test
scripts/build.sh         # → dist/sshgw-proxyfront, dist/sshgw-route-plugin
```

Configuration (env / `/etc/pickle/sshgw.env`):

| Variable | Used by | Meaning |
|---|---|---|
| `PICKLE_SSHGW_API_BASE` | route-plugin | pickle-api base, e.g. `http://172.30.1.20:8080` |
| `PICKLE_SSHGW_TOKEN` | route-plugin | shared bearer token (required — fail-closed) |
| `SSHGW_PROXYFRONT_LISTEN` | proxyfront | ingress addr (default `10.100.100.2:22`) |
| `SSHGW_PROXYFRONT_UPSTREAM` | proxyfront | loopback sshpiperd (default `127.0.0.1:2222`) |
| `SSHGW_PROXYFRONT_PEER` | proxyfront | trusted WG peer CIDR (default `10.100.100.1/32`) |

Pinned versions: Go 1.26, `sshpiperd` v1.5.4, `go-proxyproto` v0.15.0.
