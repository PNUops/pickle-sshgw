# pickle-sshgw

SSH gateway for Pickle: routes `ssh <vmslug>@ssh.pickle.pnuops.com` to the
student's VM after authenticating against pickle-api. Based on sshpiper with a
custom authorization plugin (fallback: a small gliderlabs/ssh daemon).

sshpiperd listens on :22 inside the sshgw LXC and receives the PROXY protocol
header (real client IP preserved for audit). Off-campus reachability is provided
by an AWS Lightsail relay: the campus opens an outbound WireGuard tunnel to it and
Lightsail forwards public :22 → tunnel → sshgw:22 (the school firewall blocks
inbound, so a plain relay cannot reach in). The host keeps :8022 for admin SSH —
no host SSH cutover. See `docs/plan/05-ssh-access.md` and the internal routing
contract in `docs/api/internal.md` (pickle-docs repo).

Implementation lands in milestone M4. Until then this repo holds configuration
research and the deployment skeleton.

```bash
scripts/setup-hooks.sh   # once: install git hooks
scripts/verify.sh        # shellcheck (+ go vet/build once code exists)
```
