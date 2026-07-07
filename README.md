# pickle-sshgw

SSH gateway for Pickle: routes `ssh <vmslug>@ssh.pickle.pnuops.com -p 8022` to the
student's VM after authenticating against pickle-api. Based on sshpiper with a
custom authorization plugin (fallback: a small gliderlabs/ssh daemon).

Design: `docs/plan/05-ssh-access.md` in the `pickle-docs` repository.

Implementation lands in milestone M4. Until then this repo holds configuration
research and the deployment skeleton.

```bash
scripts/setup-hooks.sh   # once: install git hooks
scripts/verify.sh        # shellcheck (+ go vet/build once code exists)
```
