---
paths:
  - "tools/**"
  - ".githooks/**"
  - "user/key-store-service/**"
  - "user/fde-mount/**"
  - "manifest.toml"
---

# Hooks, host tools and signing

## Git hooks

What the commit-msg and pre-push hooks require of a commit (the `Staged files:` block, `CLAUDE_PREFLIGHT_SESSION`, the edit-window gate) is in the root [CLAUDE.md](../../CLAUDE.md) Quick Reference, above `make install-hooks`: it binds every Claude-authored commit, whichever files the commit touches, so it is read before any file here is opened. The scripts are `tools/check-claude-staged-files.py`, `tools/check-preflight-discipline.py`, `tools/log-claude-edit.py` and `tools/check-edit-window.py`; the hooks themselves are in `.githooks/`.

## Standalone builds, dev-PIV builds, ELF signing

```bash
# Standalone builds
make fs-service                  # user/fs-service — separate crate, uses CARGO_ENCODED_RUSTFLAGS to override parent .cargo/config.toml
make sign-tool                   # tools/sign-elf — host-side tool, built for the detected host triple
make manifest                    # ADR-018: emit manifest.bin from manifest.toml via tools/build-manifest (`--arch x86_64 --profile default`; manifest-aarch64 / manifest-riscv64 for the other arches), sign with sign-elf. The manifest is the ONLY spawn authority since step 9: services, on-demand apps (`lifetime = "on-demand"`), grants, reservations all live in manifest.toml. A dependant can name a role by endpoint (`depends_on_endpoints = [27]`); build-manifest resolves it to the one kept owner per arch/profile, so the wire blob is always plain name deps.
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
