#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
#
# Sandbox session lifecycle (stage G rung 5). Host side. One session at a
# time: a throwaway clone of the sealed golden image, booted under the
# softnet default-deny policy with the exchange repo mounted, the allow-list
# proxy up, the host's HEAD fast-forwarded into the guest checkout, and the
# credential copied onto the clone's disk. `down` powers the guest off from
# inside, deletes the clone, stops the proxy. Nothing survives a session
# except branches the agent pushed into the exchange.
#
#   session.sh up [NAME]   start a session (NAME defaults to a timestamp)
#   session.sh down        end the current session
#   session.sh ssh [CMD]   shell into the current session as `agent`
#   session.sh pull        fetch refs/heads/sandbox/* from the exchange
#   session.sh status      VMs, current session, proxy, last decisions
#
# Environment (the Makefile passes these; defaults match it):
#   SANDBOX_HOME            ~/sandbox
#   SANDBOX_GOLDEN          cambios-golden
#   SANDBOX_PROXY_PORT      3128
#   SANDBOX_CREDENTIAL      $SANDBOX_HOME/credential.env (export ANTHROPIC_API_KEY=…
#                           or export CLAUDE_CODE_OAUTH_TOKEN=…; mode 600)
#   REPO                    the checkout whose HEAD seeds the session (default: cwd's)
set -euo pipefail

SANDBOX_HOME="${SANDBOX_HOME:-$HOME/sandbox}"
GOLDEN="${SANDBOX_GOLDEN:-cambios-golden}"
PROXY_PORT="${SANDBOX_PROXY_PORT:-3128}"
CREDENTIAL="${SANDBOX_CREDENTIAL:-$SANDBOX_HOME/credential.env}"
REPO="${REPO:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
EXCHANGE="$SANDBOX_HOME/exchange.git"
KEY="$SANDBOX_HOME/id_sandbox"
CURRENT="$SANDBOX_HOME/session.current"
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
# Mirrors SANDBOX_SOFTNET_POLICY in the Makefile: stateless default deny,
# SSH in from the host, one TCP port out to the host (the proxy).
POLICY=(--net-softnet-block=0.0.0.0/0 "--net-softnet-allow=in proto tcp @host port 22,out proto tcp @host port $PROXY_PORT")
# TUNING: how long to wait for DHCP and sshd after `tart run`. A cold clone
# of the golden image reaches sshd in ~10 s; 120 s is a dead VM, not a slow one.
BOOT_WAIT_S=120
# TUNING: how long an in-guest poweroff may take before `down` gives up.
STOP_WAIT_S=90

die() { echo "session.sh: $*" >&2; exit 1; }
log() { printf '=== %s\n' "$*"; }

current() { [ -r "$CURRENT" ] && cat "$CURRENT" || true; }
vm_state() { tart list 2>/dev/null | awk -v n="$1" '$2 == n {print $NF}'; }
vm_ip() { tart ip "$1" "${@:2}"; }
ssh_as() { local user=$1 ip=$2; shift 2; ssh "${SSH_OPTS[@]}" "$user@$ip" "$@"; }

wait_ssh() {
  local ip=$1 deadline=$((SECONDS + BOOT_WAIT_S))
  while ! nc -z -w 3 "$ip" 22 2>/dev/null; do
    [ $SECONDS -ge $deadline ] && die "sshd on $ip not reachable after ${BOOT_WAIT_S}s"
    sleep 2
  done
}

cmd_up() {
  local name="${1:-cambios-sess-$(date -u +%Y%m%d-%H%M%S)}"
  [ -n "$(current)" ] && die "session '$(current)' is already current; run 'down' first"
  [ "$(vm_state "$GOLDEN")" = stopped ] || die "golden image '$GOLDEN' missing or running"
  [ -d "$EXCHANGE" ] || die "exchange repo $EXCHANGE missing"
  [ -r "$KEY" ] || die "host key $KEY missing"
  mkdir -p "$SANDBOX_HOME"
  # Refuse a stale golden: its crate cache would not match the lockfiles and
  # offline builds inside would fail in confusing ways.
  if [ "${SANDBOX_ALLOW_STALE:-0}" != 1 ]; then
    "$(dirname "$0")/image.sh" check || die "golden image stale (SANDBOX_ALLOW_STALE=1 to override)"
  fi

  # The exchange's main mirrors the host's HEAD and nothing else writes it
  # (the agent pushes refs/heads/sandbox/*), so a rebased host history is a
  # legitimate non-fast-forward: force is the mirror semantics, not a loss.
  log "exchange <- $REPO HEAD ($(git -C "$REPO" rev-parse --short HEAD))"
  git -C "$REPO" push --quiet --force "$EXCHANGE" HEAD:refs/heads/main

  log "clone $GOLDEN -> $name"
  tart clone "$GOLDEN" "$name"
  echo "$name" > "$CURRENT"

  log "boot under default-deny policy, exchange mounted rw"
  nohup tart run "$name" --nested --no-graphics "${POLICY[@]}" \
    --dir="exchange:$EXCHANGE" > "$SANDBOX_HOME/$name.log" 2>&1 &
  echo $! > "$SANDBOX_HOME/session.pid"

  local ip
  ip=$(vm_ip "$name" --wait "$BOOT_WAIT_S")
  wait_ssh "$ip"
  log "guest up at $ip"

  log "proxy up"
  make -C "$REPO" --no-print-directory sandbox-net-up

  log "mount exchange share, fast-forward guest checkout"
  ssh_as admin "$ip" 'mountpoint -q /mnt/tart || { sudo mkdir -p /mnt/tart && sudo mount -t virtiofs com.apple.virtio-fs.automount /mnt/tart; }'
  ssh_as agent "$ip" 'cd ~/cambios && git fetch --quiet /mnt/tart/exchange main && git checkout --quiet -B main FETCH_HEAD && git log --oneline -1'

  if [ -r "$CREDENTIAL" ]; then
    log "credential -> agent (~/.cambios-sandbox-env, 600)"
    scp "${SSH_OPTS[@]}" -q "$CREDENTIAL" "agent@$ip:.cambios-sandbox-env"
    ssh_as agent "$ip" 'chmod 600 ~/.cambios-sandbox-env; grep -q cambios-sandbox-env ~/.profile || printf "\n[ -r ~/.cambios-sandbox-env ] && . ~/.cambios-sandbox-env\n" >> ~/.profile'
  else
    log "no credential file at $CREDENTIAL; claude will have nothing to authenticate with"
  fi

  log "session '$name' ready: make sandbox-ssh   (ssh ${SSH_OPTS[*]} agent@$ip)"
}

cmd_down() {
  local name; name=$(current)
  [ -n "$name" ] || die "no current session"
  local state; state=$(vm_state "$name")
  if [ "$state" = running ]; then
    local ip; ip=$(vm_ip "$name" 2>/dev/null || true)
    if [ -n "$ip" ]; then
      log "poweroff from inside"
      ssh_as admin "$ip" 'sync; (sleep 1; sudo systemctl poweroff) >/dev/null 2>&1 &' || true
      local deadline=$((SECONDS + STOP_WAIT_S))
      while [ "$(vm_state "$name")" = running ]; do
        [ $SECONDS -ge $deadline ] && { log "guest still running after ${STOP_WAIT_S}s; tart stop"; tart stop "$name"; break; }
        sleep 3
      done
    else
      tart stop "$name"
    fi
  fi
  log "delete $name"
  tart delete "$name"
  make -C "$REPO" --no-print-directory sandbox-net-down || true
  # Keep one boot log for post-mortems; the clone it belonged to is gone.
  mv -f "$SANDBOX_HOME/$name.log" "$SANDBOX_HOME/last-session.log" 2>/dev/null || true
  rm -f "$CURRENT" "$SANDBOX_HOME/session.pid"
  log "session '$name' gone; branches it pushed are in $EXCHANGE (make sandbox-pull)"
}

cmd_ssh() {
  local name; name=$(current)
  [ -n "$name" ] || die "no current session"
  local ip; ip=$(vm_ip "$name")
  exec ssh "${SSH_OPTS[@]}" -t "agent@$ip" "$@"
}

cmd_pull() {
  git -C "$REPO" fetch --quiet "$EXCHANGE" '+refs/heads/sandbox/*:refs/remotes/sandbox/*'
  log "sandbox branches:"
  git -C "$REPO" for-each-ref --format='  %(refname:short)  %(objectname:short)  %(subject)' refs/remotes/sandbox/
}

cmd_status() {
  log "VMs"; tart list 2>/dev/null | awk 'NR==1 || /cambios/'
  log "current session: $(current)"
  make -C "$REPO" --no-print-directory sandbox-net-status || true
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  down) cmd_down ;;
  ssh) shift; cmd_ssh "$@" ;;
  pull) cmd_pull ;;
  status) cmd_status ;;
  *) sed -n '5,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
