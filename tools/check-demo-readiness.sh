#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
#
# check-demo-readiness.sh — audit a machine for the CambiOS demo workflow.
#
# Run on a fresh clone (e.g. mobile laptop before IIW) to get a punch list
# of what's missing before `make iso && make run-quiet` will reach
# `cambios>` and the HN-prep games will launch.
#
# Exit code: 0 if no FAILs, 1 otherwise. WARNs do not fail the run.
#
# Usage:
#   ./tools/check-demo-readiness.sh
#   ./tools/check-demo-readiness.sh --no-color    # plain text

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Color (TTY only, unless --no-color)
if [[ "${1:-}" == "--no-color" ]] || [[ ! -t 1 ]]; then
    GREEN="" YELLOW="" RED="" BOLD="" RESET=""
else
    GREEN=$'\033[32m' YELLOW=$'\033[33m' RED=$'\033[31m' BOLD=$'\033[1m' RESET=$'\033[0m'
fi

OK_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

section() { printf "\n${BOLD}%s${RESET}\n" "$1"; }
ok()      { printf "  [${GREEN} OK ${RESET}] %s\n" "$1"; OK_COUNT=$((OK_COUNT+1)); }
warn()    { printf "  [${YELLOW}WARN${RESET}] %s\n" "$1"; WARN_COUNT=$((WARN_COUNT+1)); }
fail()    { printf "  [${RED}FAIL${RESET}] %s\n" "$1"; FAIL_COUNT=$((FAIL_COUNT+1)); }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
section "Repo state"

if git rev-parse --git-dir >/dev/null 2>&1; then
    ok "inside a git repo ($(git rev-parse --abbrev-ref HEAD))"
else
    fail "not in a git repo — clone CambiOS first"
fi

if [[ -f rust-toolchain.toml ]]; then
    PINNED_CHANNEL=$(grep -E '^channel\s*=' rust-toolchain.toml | sed -E 's/.*"([^"]+)".*/\1/')
    ok "rust-toolchain.toml present (channel: $PINNED_CHANNEL)"
else
    fail "rust-toolchain.toml missing — wrong directory?"
    PINNED_CHANNEL=""
fi

# ---------------------------------------------------------------------------
section "Rust toolchain"

if have rustup; then
    ok "rustup present ($(rustup --version 2>/dev/null | head -1))"

    ACTIVE=$(rustup show active-toolchain 2>/dev/null | awk '{print $1}')
    if [[ -n "$PINNED_CHANNEL" && "$ACTIVE" == "$PINNED_CHANNEL"* ]]; then
        ok "active toolchain matches pin: $ACTIVE"
    elif [[ -n "$PINNED_CHANNEL" ]]; then
        warn "active toolchain $ACTIVE != pinned $PINNED_CHANNEL (rustup will fetch on first build)"
    fi

    INSTALLED_TARGETS=$(rustup target list --installed 2>/dev/null)
    for tgt in x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf x86_64-apple-darwin; do
        if grep -qx "$tgt" <<< "$INSTALLED_TARGETS"; then
            ok "target installed: $tgt"
        else
            fail "target missing: $tgt — rustup target add $tgt"
        fi
    done
else
    fail "rustup not on PATH — install from https://rustup.rs"
fi

if have cargo; then
    ok "cargo on PATH"
else
    fail "cargo not on PATH"
fi

# ---------------------------------------------------------------------------
section "QEMU"

for arch in x86_64 aarch64 riscv64; do
    if have "qemu-system-$arch"; then
        VER=$("qemu-system-$arch" --version 2>/dev/null | head -1 | sed -E 's/.*version ([^ ]+).*/\1/')
        ok "qemu-system-$arch present (v$VER)"
    else
        fail "qemu-system-$arch missing — brew install qemu"
    fi
done

# AArch64 GICv3 support: parse virt-machine options for the gic-version key.
# Don't actually launch QEMU here — `qemu-system-aarch64 -bios /dev/null` does
# not fail fast, it spins at 100% CPU forever.
if have qemu-system-aarch64; then
    if qemu-system-aarch64 -machine virt,help 2>&1 | grep -qi "gic-version"; then
        ok "qemu-system-aarch64 supports gic-version option"
    else
        fail "qemu-system-aarch64 lacks gic-version option — AArch64 demo will triple-fault on default GICv2"
    fi
fi

# ---------------------------------------------------------------------------
section "Boot media tools"

# mtools: AArch64 FAT image (mformat + mcopy)
for tool in mformat mcopy; do
    if have "$tool"; then
        ok "$tool present (mtools)"
    else
        fail "$tool missing — brew install mtools (AArch64 image build will fail)"
    fi
done

# xorriso: x86_64 ISO build
if have xorriso; then
    ok "xorriso present"
else
    fail "xorriso missing — brew install xorriso (x86_64 ISO build will fail)"
fi

# cc: needed to compile Limine's host helper (Makefile builds /tmp/limine/limine from C source)
if have cc; then
    ok "cc present (needed for Limine host tool)"
else
    fail "cc missing — install Xcode CLT: xcode-select --install"
fi

# make
if have make; then
    ok "make present"
else
    fail "make missing — install Xcode CLT: xcode-select --install"
fi

# ---------------------------------------------------------------------------
section "Signing chain"

SIGN_ELF="tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf"
if [[ -x "$SIGN_ELF" ]]; then
    ok "sign-elf built ($SIGN_ELF)"
else
    warn "sign-elf not built yet — run 'make sign-tool' (needed for ARCSIG signing)"
fi

if have gpg; then
    ok "gpg present"
    if gpg --list-secret-keys 2>/dev/null | grep -q '^sec'; then
        ok "gpg has at least one secret key (commit signing should work)"
    else
        warn "gpg has no secret keys — signed commits will fail"
    fi
else
    warn "gpg not on PATH — needed for signed commits (brew install gnupg)"
fi

# YubiKey: ykman is the canonical CLI; pcsc daemon must be reachable
if have ykman; then
    ok "ykman present"
    if ykman list 2>/dev/null | grep -qi yubikey; then
        COUNT=$(ykman list 2>/dev/null | grep -ci yubikey)
        ok "$COUNT YubiKey(s) detected"
    else
        warn "ykman runs but no YubiKey detected (insert before demo, or use --seed fallback)"
    fi
else
    warn "ykman not on PATH — install via 'brew install ykman' or use --seed fallback for sign-elf"
fi

# ---------------------------------------------------------------------------
section "Dev environment (nice-to-have)"

if have claude; then
    ok "claude CLI on PATH"
else
    warn "claude CLI not on PATH — live editing without it works, just slower"
fi

if [[ -f .mcp.json ]]; then
    ok ".mcp.json present (rust-analyzer MCP wired up)"
else
    warn ".mcp.json missing — rust-analyzer MCP tools won't load"
fi

HOOKS_PATH=$(git config --get core.hooksPath 2>/dev/null || echo "")
if [[ "$HOOKS_PATH" == ".githooks" ]]; then
    ok "git hooks installed (core.hooksPath = .githooks)"
else
    warn "git hooks not installed — run 'make install-hooks' (commit/push gates won't fire)"
fi

# ---------------------------------------------------------------------------
section "Smoke test (cheap)"

# `cargo check` on the kernel — fastest signal that the toolchain is fully wired up.
# Skip if any toolchain check failed — would only produce confusing duplicate errors.
if have cargo && have rustup && [[ "$FAIL_COUNT" -eq 0 ]]; then
    printf "  running: cargo check --target x86_64-unknown-none --lib (this takes ~30s on a cold cache)... "
    if cargo check --target x86_64-unknown-none --lib --quiet 2>/dev/null; then
        printf "${GREEN}ok${RESET}\n"
        OK_COUNT=$((OK_COUNT+1))
    else
        printf "${RED}failed${RESET}\n"
        fail "cargo check failed — re-run manually for the error: cargo check --target x86_64-unknown-none --lib"
    fi
else
    warn "skipped cargo check (earlier failures would mask the result)"
fi

# ---------------------------------------------------------------------------
printf "\n${BOLD}Summary:${RESET} ${GREEN}%d ok${RESET}, ${YELLOW}%d warn${RESET}, ${RED}%d fail${RESET}\n" \
    "$OK_COUNT" "$WARN_COUNT" "$FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    printf "\nDemo not ready — fix the FAILs above before relying on this machine.\n"
    exit 1
elif [[ "$WARN_COUNT" -gt 0 ]]; then
    printf "\nDemo can boot, but review the WARNs (signing / hooks / nice-to-haves).\n"
    exit 0
else
    printf "\nAll green. ${BOLD}make iso && make run-quiet${RESET} should reach cambios>.\n"
    exit 0
fi
