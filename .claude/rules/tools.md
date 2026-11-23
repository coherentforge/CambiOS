---
paths:
  - "tools/sign-elf/**"
  - "tools/build-manifest/**"
  - "tools/gen-dev-piv-keys/**"
  - "tools/format-volume/**"
  - "tools/check-claude-staged-files.py"
  - "tools/check-preflight-discipline.py"
  - "tools/log-claude-edit.py"
  - "tools/check-edit-window.py"
  - ".githooks/**"
  - "user/key-store-service/**"
  - "user/fde-mount/**"
  - "user/libsys/src/vault.rs"
  - "manifest.toml"
---

# Hooks, host tools and signing

## Git hooks

What the hooks require of a commit is stated in the root [CLAUDE.md](../../CLAUDE.md) Commit Cadence, because it binds every Claude-authored commit whichever files it touches. The mechanics:

```bash
# Commit-msg hooks (Claude-authored commits only):
# 1. H1 (2026-04-23): `Staged files:` block must match `git diff --cached
#    --name-only`. Script: tools/check-claude-staged-files.py.
# 2. Sticky preflight (2026-04-25): rejects commits that stage a file
#    which was already dirty at the start of the current Claude session
#    AND was never preflighted. Catches the 6th-recurrence shape that H1
#    misses (within-file sweeps). Set `CLAUDE_PREFLIGHT_SESSION=<id>`
#    once per session to enable enforcement; warn-but-pass when unset.
#    Script: tools/check-preflight-discipline.py.
# Pre-push hook (Claude-authored commits only):
# 3. Edit-window gate (2026-04-25): rejects pushes whose Claude-authored
#    commits modify files no Claude session ever touched via Edit/Write/
#    NotebookEdit. Defense-in-depth on top of (2); catches anything that
#    bypassed commit-msg via `--no-verify`. Requires the PostToolUse hook
#    in .claude/settings.local.json (calls tools/log-claude-edit.py) plus
#    `CLAUDE_PREFLIGHT_SESSION`. Warn-but-pass without an edit log.
#    Checks only commits no remote-tracking ref already has.
#    One derived-file case is accepted (2026-11-22): a Cargo.lock that
#    cargo regenerated, when its sibling Cargo.toml changed in the same
#    commit and is in the edit log, and only path-package lines changed.
#    A `source =` / `checksum =` line (registry or git dependency) is
#    still refused. Each acceptance prints a NOTICE. Tests: make test-tools.
#    Scripts: tools/log-claude-edit.py + tools/check-edit-window.py.
# All run automatically when installed via `make install-hooks`.
```

## Standalone builds, dev-PIV builds, ELF signing

```bash
# Standalone builds
make fs-service                  # user/fs-service — separate crate, uses CARGO_ENCODED_RUSTFLAGS to override parent .cargo/config.toml
make sign-tool                   # tools/sign-elf — host-side tool, built for the detected host triple
make manifest                    # ADR-018: emit manifest.bin from manifest.toml via tools/build-manifest (`--arch x86_64 --profile default`; manifest-aarch64 / manifest-riscv64 for the other arches), sign with sign-elf. What the manifest governs: platform-gotchas.md, first entry. A dependant can name a role by endpoint (`depends_on_endpoints = [27]`); build-manifest resolves it to the one kept owner per arch/profile, so the wire blob is always plain name deps.
make init                        # user/init — PID 1 supervisor (init-aarch64 / init-riscv64 for other arches); host tests: `make host-test-user-init`
make gen-dev-piv-keys            # tools/gen-dev-piv-keys — derives dev Ed25519+X25519 keys from a persistent per-developer seed at tools/gen-dev-piv-keys/.dev-seed.bin (gitignored); writes dev_bootstrap_pubkey.bin (workspace root) + dev_slot_9c_seed.bin (workspace root, for sign-elf via SIGN_MODE=dev-piv) + user/key-store-service/dev_piv_secret.bin. Idempotent; required before any `--features dev-piv` build (kernel + key-store-service must both be built with this feature for SwPivBackend's pubkey to match the kernel-baked bootstrap pubkey).
make format-volume               # tools/format-volume — host tool that writes a fresh signed ADR-032 volume header to a raw disk image. Run as `$(make -s print-FORMAT_VOLUME) <disk-image>`. Requires gen-dev-piv-keys to have run first. The header pairs with the dev_bootstrap_pubkey.bin baked into the kernel under `--features dev-piv`; fde-mount reads + verifies + unwraps the master key at boot. Stream A A-v.e.

# Dev-PIV feature builds (Stream A; ADR-032 Migration Path step 2)
make kernel-dev-piv              # kernel built with --features dev-piv (replaces baked bootstrap pubkey with the dev one)
make key-store-service-dev-piv   # key-store-service built with --features dev-piv (loads SwPivBackend with the DPIV's slot-9C/9D keys)
make iso-dev-piv                 # Re-assembles the ISO with dev-piv kernel + key-store binaries (uses --assume-old + SIGN_MODE=dev-piv so sign-elf signs with the slot-9C seed the dev-piv kernel accepts)
make run-quiet-dev-piv           # Formats cambios-disk.img with a fresh signed FDE header + boots under iso-dev-piv. Stream A A-v.d end-to-end smoke test.
# Manual: cargo build --target x86_64-unknown-none --release --features dev-piv (kernel) + CARGO_ENCODED_RUSTFLAGS=... cargo build --release --features dev-piv inside user/key-store-service/

# ELF signing (produces ARCSIG trailer). The tool is built under its host triple; `make -s print-SIGN_ELF` prints the path.
$(make -s print-SIGN_ELF) <elf-file>                                    # YubiKey (default)
$(make -s print-SIGN_ELF) --seed <hex> <elf-file>                       # seed (CI/test)
$(make -s print-SIGN_ELF) --export-pubkey bootstrap_pubkey.bin          # one-time setup
$(make -s print-SIGN_ELF) --print-pubkey
```

## tools/sign-elf

- **`tools/sign-elf/`** — host-side Ed25519 ELF signer (YubiKey or seed), produces the ARCSIG trailer. Built for the host (`host-tuple` in its `.cargo/config.toml`).
