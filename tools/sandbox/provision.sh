#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
#
# Provision the sandbox golden image (stage G rung 3). Runs INSIDE the
# golden-build VM as `admin` (passwordless sudo), copied in and invoked over
# SSH by the host. The build VM has open internet (softnet, no block rules);
# the image it produces is only ever booted under SANDBOX_SOFTNET_POLICY.
#
# Phases are idempotent and individually invocable:
#   provision.sh packages | user | profile | rust | limine | claude | harden | stamp
#   provision.sh all            # every phase, in that order
#
# Inputs (environment):
#   EXCHANGE      bare repo path inside the guest (default /mnt/tart/exchange)
#   PROXY_PORT    host proxy port the guest profile points at (default 3128)
#   SANDBOX_PUBKEY  host public key to authorise for `agent` (default: admin's)
#   STAMP         opaque freshness stamp written to /etc/cambios-sandbox-stamp
#   CLAUDE_INSTALL_URL  installer script URL for the claude phase
#   CLAUDE_VERSION      "stable" or an exact version for the claude phase
set -euo pipefail

EXCHANGE="${EXCHANGE:-/mnt/tart/exchange}"
PROXY_PORT="${PROXY_PORT:-3128}"
STAMP="${STAMP:-unstamped}"
CLAUDE_INSTALL_URL="${CLAUDE_INSTALL_URL:-https://claude.ai/install.sh}"
# "stable" (about a week behind latest) or an exact version such as 2.1.89.
CLAUDE_VERSION="${CLAUDE_VERSION:-stable}"
AGENT=agent
AGENT_HOME=/home/$AGENT
REPO_DIR=$AGENT_HOME/cambios

log() { printf '\n=== [%s] %s ===\n' "$(date -u +%H:%M:%S)" "$*"; }

as_agent() { sudo -u "$AGENT" -H bash -lc "$*"; }

phase_packages() {
  log packages
  export DEBIAN_FRONTEND=noninteractive
  # The stock ghcr.io/cirruslabs/ubuntu image ships with dpkg interrupted
  # mid-configure and a half-upgraded linux-virtual metapackage (headers at
  # 147, image at 149); apt refuses to install anything until both are fixed.
  sudo dpkg --configure -a || true
  sudo apt-get update -q
  sudo apt-get -f install -y -q
  # Mirrors .github/workflows/boot-smoke.yml plus the aarch64/riscv64 QEMU
  # system emulators and mtools (FAT images) the Makefile uses on those arches.
  sudo apt-get install -y -q --no-install-recommends \
    qemu-system-x86 qemu-system-arm qemu-system-misc qemu-utils \
    xorriso mtools build-essential libpcsclite-dev pkg-config \
    git curl ca-certificates python3 openssh-server
  sudo apt-get clean
}

phase_user() {
  log user
  if ! id "$AGENT" >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash "$AGENT"
  fi
  # No password, no sudo: the agent reaches root only if the sandbox is broken.
  sudo passwd -l "$AGENT" >/dev/null
  sudo install -d -m 700 -o "$AGENT" -g "$AGENT" "$AGENT_HOME/.ssh"
  local pub="${SANDBOX_PUBKEY:-$(cat ~/.ssh/authorized_keys)}"
  echo "$pub" | sudo tee "$AGENT_HOME/.ssh/authorized_keys" >/dev/null
  sudo chown "$AGENT:$AGENT" "$AGENT_HOME/.ssh/authorized_keys"
  sudo chmod 600 "$AGENT_HOME/.ssh/authorized_keys"
}

phase_profile() {
  log profile
  # Login-shell environment for every user. The proxy address is the softnet
  # gateway, which changes per boot, so it is read from the default route at
  # login rather than baked in.
  sudo tee /etc/profile.d/cambios-sandbox.sh >/dev/null <<EOF
# CambiOS sandbox guest environment (tools/sandbox/provision.sh, phase profile)
# Zero telemetry; the proxy's deny log shows anything that still tries.
export DISABLE_TELEMETRY=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
# Linux host-tool target, seed signing, headless QEMU (same as CI).
export HOST_TARGET=aarch64-unknown-linux-gnu SIGN_MODE=seed QEMU_DISPLAY="-display none"
# The block below applies only to a SEALED image (provision.sh phase stamp
# writes the marker). The golden-image build VM has no marker and reaches the
# network directly; a session VM has it, and its only route out is the proxy
# on the softnet gateway, which changes per boot, so it is read from the
# default route at login rather than baked in.
if [ -e /etc/cambios-sandbox-sealed ]; then
  _gw=\$(ip -4 route show default 2>/dev/null | awk '{print \$3; exit}')
  if [ -n "\$_gw" ]; then
    export https_proxy="http://\${_gw}:${PROXY_PORT}" HTTPS_PROXY="http://\${_gw}:${PROXY_PORT}"
  fi
  unset _gw http_proxy HTTP_PROXY      # plain HTTP is never tunnelled
  export no_proxy=localhost,127.0.0.1 NO_PROXY=localhost,127.0.0.1
  # The guest has no DNS: the proxy resolves the CONNECT host.
  export CLAUDE_CODE_PROXY_RESOLVES_HOSTS=1
  # No updates of any kind, manual included. Not set during the build: the
  # native installer reads it and then refuses to install at all.
  export DISABLE_UPDATES=1
  # Offline builds: every crate was fetched when the image was built.
  export CARGO_NET_OFFLINE=true
fi
EOF
  sudo chmod 644 /etc/profile.d/cambios-sandbox.sh
  # Mount the Tart directory share at boot. `make sandbox-up` passes the
  # exchange repo as --dir=exchange:..., which then appears at
  # /mnt/tart/exchange. nofail: a VM started without --dir still boots.
  sudo mkdir -p /mnt/tart
  if ! grep -q 'com.apple.virtio-fs.automount' /etc/fstab; then
    echo 'com.apple.virtio-fs.automount /mnt/tart virtiofs defaults,nofail 0 0' | sudo tee -a /etc/fstab >/dev/null
  fi
}

phase_rust() {
  log rust
  if ! sudo -u "$AGENT" test -r "$EXCHANGE/HEAD"; then
    echo "agent cannot read $EXCHANGE; mirroring through admin"
    sudo rm -rf /srv/cambios-exchange.git
    sudo git clone --quiet --bare "$EXCHANGE" /srv/cambios-exchange.git
    sudo chown -R "$AGENT:$AGENT" /srv/cambios-exchange.git
    EXCHANGE=/srv/cambios-exchange.git
  fi
  # Checked as agent: /home/agent is mode 750, admin cannot look inside.
  if ! as_agent "test -d '$REPO_DIR/.git'"; then
    as_agent "git clone --quiet '$EXCHANGE' '$REPO_DIR'"
  else
    as_agent "cd '$REPO_DIR' && git fetch --quiet '$EXCHANGE' && git reset --quiet --hard FETCH_HEAD"
  fi
  if ! as_agent 'command -v rustup' >/dev/null 2>&1; then
    as_agent "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal"
  fi
  # rust-toolchain.toml pins the nightly and lists the targets; `rustup show`
  # installs both. clippy backs `make check-clippy`.
  as_agent "cd '$REPO_DIR' && rustup show >/dev/null && rustup component add clippy && rustc --version"
  # Outside the repo (no rust-toolchain.toml) rustup has nothing to pick;
  # make the pinned nightly the default so cargo works from any directory.
  as_agent "rustup default \$(cd '$REPO_DIR' && rustup show active-toolchain | cut -d' ' -f1)"
  # Pre-fetch every workspace so the image builds with CARGO_NET_OFFLINE=true.
  as_agent "cd '$REPO_DIR' && find . -name Cargo.lock -not -path '*/target/*' -print0 \
    | xargs -0 -n1 dirname | sort | while read -r d; do echo \"fetch: \$d\"; (cd \"\$d\" && cargo fetch --quiet); done"
}

phase_limine() {
  log limine
  # `make limine` clones the limine-binary branch into ~/.cache/cambios/limine
  # and compiles the host-side `limine` tool; both are needed offline by `make iso`.
  as_agent "cd '$REPO_DIR' && make limine"
}

phase_claude() {
  log claude
  # Native installer: symlink at ~/.local/bin/claude -> ~/.local/share/claude/versions/<v>.
  # Needs claude.ai (script) and downloads.claude.ai (binary) during the build phase.
  as_agent "curl -fsSL '$CLAUDE_INSTALL_URL' | bash -s '$CLAUDE_VERSION'"
  as_agent 'command -v claude && claude --version' || echo "claude not on PATH for login shells yet"
}

phase_harden() {
  log harden
  # Key-only SSH; admin keeps passwordless sudo but can no longer log in with
  # the stock image password.
  sudo passwd -l admin >/dev/null
  sudo tee /etc/ssh/sshd_config.d/90-cambios-sandbox.conf >/dev/null <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
  sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd
}

phase_stamp() {
  log stamp
  echo "$STAMP" | sudo tee /etc/cambios-sandbox-stamp >/dev/null
  sudo chmod 644 /etc/cambios-sandbox-stamp
  # Seal: from the next login on, the profile routes everything through the
  # proxy and cargo runs offline. Last phase of a build, by construction.
  sudo touch /etc/cambios-sandbox-sealed
}

main() {
  local phases=("$@")
  [ ${#phases[@]} -eq 0 ] && { echo "usage: provision.sh <phase...>|all" >&2; exit 2; }
  if [ "${phases[0]}" = all ]; then
    phases=(packages user profile rust limine claude harden stamp)
  fi
  for p in "${phases[@]}"; do
    case "$p" in
      packages|user|profile|rust|limine|claude|harden|stamp) "phase_$p" ;;
      *) echo "unknown phase: $p" >&2; exit 2 ;;
    esac
  done
  # Flush before the host stops the VM. `tart stop` right after the last
  # phase lost the final seconds of writes once (the seal marker and sshd
  # drop-in vanished; files written a minute earlier survived).
  sync
  log "done: ${phases[*]}"
}

main "$@"
