#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
#
# Golden-image build and freshness check for the agent sandbox (stage G
# rung 6). Host side.
#
#   image.sh build    stock base -> cambios-golden-build -> provision.sh all
#                     -> poweroff -> rotate (golden -> golden-prev) -> stamp
#   image.sh stamp    print the stamp the current inputs produce
#   image.sh check    compare that stamp with the one the golden was built
#                     from (~/sandbox/golden.stamp); exit 1 when stale
#
# The stamp is a hash over every input that changes what the image must
# contain offline: rust-toolchain.toml, every Cargo.lock, provision.sh, the
# Limine pin, and the stock image digest. Things resolved at build time
# (Claude Code's "stable" version, apt security updates) are recorded in the
# stamp file but not hashed; a weekly rebuild refreshes those.
#
# Environment (the Makefile passes these; defaults match it):
#   SANDBOX_HOME, SANDBOX_GOLDEN, REPO    as in session.sh
#   SANDBOX_BASE       cambios-base (clone of the stock OCI image)
#   SANDBOX_BUILD_CPU  8      SANDBOX_BUILD_MEM  16384 (MiB)
set -euo pipefail

SANDBOX_HOME="${SANDBOX_HOME:-$HOME/sandbox}"
BASE="${SANDBOX_BASE:-cambios-base}"
GOLDEN="${SANDBOX_GOLDEN:-cambios-golden}"
BUILD="$GOLDEN-build"
PREV="$GOLDEN-prev"
CPU="${SANDBOX_BUILD_CPU:-8}"
MEM="${SANDBOX_BUILD_MEM:-16384}"
REPO="${REPO:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
EXCHANGE="$SANDBOX_HOME/exchange.git"
KEY="$SANDBOX_HOME/id_sandbox"
STAMP_FILE="$SANDBOX_HOME/golden.stamp"
HERE="$(cd "$(dirname "$0")" && pwd)"
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
# TUNING: waits, same reasoning as session.sh.
BOOT_WAIT_S=120
STOP_WAIT_S=120

die() { echo "image.sh: $*" >&2; exit 1; }
log() { printf '=== %s\n' "$*"; }
vm_state() { tart list 2>/dev/null | awk -v n="$1" '$2 == n {print $NF}'; }
ssh_as() { local user=$1 ip=$2; shift 2; ssh "${SSH_OPTS[@]}" "$user@$ip" "$@"; }

wait_ssh() {
  local ip=$1 deadline=$((SECONDS + BOOT_WAIT_S))
  while ! nc -z -w 3 "$ip" 22 2>/dev/null; do
    [ $SECONDS -ge $deadline ] && die "sshd on $ip not reachable after ${BOOT_WAIT_S}s"
    sleep 2
  done
}

inputs() {
  (cd "$REPO" && {
    echo rust-toolchain.toml
    echo tools/sandbox/provision.sh
    find . -name Cargo.lock -not -path '*/target/*' | sed 's|^\./||' | sort
  })
}

stamp() {
  {
    (cd "$REPO" && inputs | xargs shasum -a 256)
    grep -E '^LIMINE_(BRANCH|REPO) ' "$REPO/Makefile"
    tart list 2>/dev/null | grep -oE 'ghcr.io/cirruslabs/ubuntu@sha256:[0-9a-f]+' | head -1
  } | shasum -a 256 | cut -c1-16
}

cmd_stamp() { stamp; }

cmd_check() {
  local want have
  want=$(stamp)
  have=$(head -1 "$STAMP_FILE" 2>/dev/null || echo none)
  if [ "$want" = "$have" ]; then
    echo "golden image fresh ($have; built $(sed -n 's/^built=//p' "$STAMP_FILE"))"
  else
    echo "golden image STALE: built from $have, inputs now hash to $want. Run: make sandbox-image" >&2
    [ "$have" = none ] && echo "(no $STAMP_FILE: the golden was built before the stamp existed, or never)" >&2
    return 1
  fi
}

cmd_build() {
  local s; s=$(stamp)
  [ "$(vm_state "$BASE")" = stopped ] || die "base image '$BASE' missing or running"
  [ -d "$EXCHANGE" ] || die "exchange repo $EXCHANGE missing"
  [ -r "$KEY" ] || die "host key $KEY missing (ssh-keygen -t ed25519 -N '' -f $KEY)"
  if [ -n "$(vm_state "$BUILD")" ]; then
    log "removing leftover $BUILD"
    [ "$(vm_state "$BUILD")" = running ] && tart stop "$BUILD"
    tart delete "$BUILD"
  fi

  log "exchange <- $REPO HEAD ($(git -C "$REPO" rev-parse --short HEAD))"
  git -C "$REPO" push --quiet --force "$EXCHANGE" HEAD:refs/heads/main

  log "clone $BASE -> $BUILD ($CPU vCPU, $MEM MiB)"
  tart clone "$BASE" "$BUILD"
  tart set "$BUILD" --cpu "$CPU" --memory "$MEM"

  log "boot with open network (the build is the trusted phase)"
  nohup tart run "$BUILD" --nested --no-graphics --net-softnet \
    --dir="exchange:$EXCHANGE:ro" > "$SANDBOX_HOME/image-build.log" 2>&1 &
  local ip
  ip=$(tart ip "$BUILD" --wait "$BOOT_WAIT_S")
  wait_ssh "$ip"
  log "guest up at $ip; installing host key (the only password login this image ever sees)"
  "$HERE/stock-ssh.exp" "$ip" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$(cat "$KEY.pub")' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" >/dev/null

  log "provision (stamp $s)"
  scp "${SSH_OPTS[@]}" -q "$HERE/provision.sh" "admin@$ip:/tmp/provision.sh"
  ssh_as admin "$ip" "chmod +x /tmp/provision.sh && STAMP=$s /tmp/provision.sh all" 2>&1 | tee "$SANDBOX_HOME/image-provision.log" | grep -E '^=== \[' || true
  grep -q 'done: packages' "$SANDBOX_HOME/image-provision.log" || die "provisioning did not finish; see $SANDBOX_HOME/image-provision.log"

  local claude_v rustc_v
  claude_v=$(ssh_as agent "$ip" 'bash -lc "claude --version"' 2>/dev/null | tail -1)
  rustc_v=$(ssh_as agent "$ip" 'bash -lc "rustc --version"' 2>/dev/null | tail -1)

  log "poweroff from inside"
  ssh_as admin "$ip" 'sync; (sleep 1; sudo systemctl poweroff) >/dev/null 2>&1 &' || true
  local deadline=$((SECONDS + STOP_WAIT_S))
  while [ "$(vm_state "$BUILD")" = running ]; do
    [ $SECONDS -ge $deadline ] && die "$BUILD still running after ${STOP_WAIT_S}s"
    sleep 3
  done

  log "rotate: $GOLDEN -> $PREV, $BUILD -> $GOLDEN"
  if [ -n "$(vm_state "$GOLDEN")" ]; then
    [ -n "$(vm_state "$PREV")" ] && tart delete "$PREV"
    tart rename "$GOLDEN" "$PREV"
  fi
  tart rename "$BUILD" "$GOLDEN"

  {
    echo "$s"
    echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "head=$(git -C "$REPO" rev-parse --short HEAD)"
    echo "claude=$claude_v"
    echo "rustc=$rustc_v"
    echo "inputs:"; inputs | sed 's/^/  /'
  } > "$STAMP_FILE"
  log "golden image ready: $GOLDEN (stamp $s); previous kept as $PREV"
}

case "${1:-}" in
  build) cmd_build ;;
  stamp) cmd_stamp ;;
  check) cmd_check ;;
  *) sed -n '5,24p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
