---
paths:
  - "tools/sandbox/**"
---

# Sandbox VM

```bash
# Sandbox VM egress: allow-list proxy on the Tart bridge
make sandbox-net-up              # start tools/sandbox/allowlist-proxy.py bound to bridge100 (run after the VM is up); log + pidfile under ~/sandbox
make sandbox-net-down            # stop it
make sandbox-net-status          # pid, listener, last 10 decisions; $(SANDBOX_SOFTNET_POLICY) is the `tart run` flag set that pairs with it
make sandbox-up [SESSION=name]   # clone the sealed golden image, boot it under the policy with ~/sandbox/exchange.git mounted, proxy up, guest checkout at this HEAD, ~/sandbox/credential.env copied onto the clone (tools/sandbox/session.sh)
make sandbox-ssh                 # shell into the session as `agent`
make sandbox-pull                # fetch the agent's refs/heads/sandbox/* branches from the exchange for review
make sandbox-run PROMPT=f [MODEL=id] [JSON=1]   # hand one task file to the agent inside the session (claude -p, permissions bypassed: the VM is the containment); the run is detached in the guest, the host polls for its exit; answer on stdout, kept under ~/sandbox/runs/. Default MODEL is claude-mythos-5-2 ($(SANDBOX_MODEL)); the guest's /model picker does not list it but the API serves it
make sandbox-fetch RUN=stamp     # collect a run whose wait was interrupted (host slept, Ctrl-C); safe to repeat
make sandbox-down                # poweroff from inside, delete the clone, stop the proxy; only the exchange survives
make sandbox-status              # VMs, current session, proxy, last decisions
make sandbox-image               # rebuild the sealed golden image from the stock base (tools/sandbox/image.sh + provision.sh); previous kept as cambios-golden-prev
make sandbox-check               # is the golden fresh? stamp = hash of rust-toolchain.toml, every Cargo.lock, provision.sh, Limine pin, base digest; sandbox-up refuses a stale one
make sandbox-image-schedule      # user launchd job: weekly rebuild (Mondays 06:00); sandbox-image-unschedule removes it
```
