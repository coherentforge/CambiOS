#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
#
# Sandbox session lifecycle (stage G rung 5). Host side. One session at a
# time: a throwaway clone of the sealed golden image, booted under the
# softnet default-deny policy with the exchange repo mounted, the allow-list
# proxy up, the host's HEAD fast-forwarded into the guest checkout, and the
# credential copied onto the clone's disk. `down` powers the guest off from
# inside, deletes the clone, stops the proxy. Nothing of the guest survives a
# session except branches the agent pushed into the exchange; the host keeps
# the run transcripts under runs/ and one boot log for post-mortems.
#
#   session.sh up [NAME]   start a session (NAME defaults to a timestamp)
#   session.sh down        end the current session
#   session.sh ssh [CMD]   shell into the current session as `agent`
#   session.sh run [--model M] [--json] [FILE]
#                          hand one task (FILE or stdin) to the agent inside
#   session.sh fetch STAMP wait for / collect a run whose `run` was interrupted
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
# ServerAlive: a dead peer is noticed in about a minute. Without it the first
# detached-run wait sat on macOS's two-hour TCP keepalive (task 001).
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
          -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
# Mirrors SANDBOX_SOFTNET_POLICY in the Makefile: stateless default deny,
# SSH in from the host, one TCP port out to the host (the proxy).
POLICY=(--net-softnet-block=0.0.0.0/0 "--net-softnet-allow=in proto tcp @host port 22,out proto tcp @host port $PROXY_PORT")
# TUNING: how long to wait for DHCP and sshd after `tart run`. A cold clone
# of the golden image reaches sshd in ~10 s; 120 s is a dead VM, not a slow one.
BOOT_WAIT_S=120
# TUNING: how long an in-guest poweroff may take before `down` gives up.
STOP_WAIT_S=90
# TUNING: how often `run`/`fetch` ask the guest whether a detached run has
# finished. Each poll is one SSH connection; a review run takes minutes to
# hours, so 15 s costs nothing and keeps the answer prompt.
RUN_POLL_S=15

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
  # `checkout -- .` after the branch switch: the golden's `cargo fetch`
  # rewrote several Cargo.lock files, and the agent's first `git status`
  # should show a clean tree, not provisioning residue (task 001).
  ssh_as agent "$ip" 'cd ~/cambios && git fetch --quiet /mnt/tart/exchange main && git checkout --quiet -B main FETCH_HEAD && git checkout --quiet -- . && git log --oneline -1'

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
    # Poweroff from inside, then delete: `tart stop` on a live guest dropped
    # the last seconds of writes once (rung 3), and `tart delete` wants a
    # stopped VM. Order matters for both reasons.
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

# run [--model M] [--json] [PROMPT_FILE]: hand one task to the agent inside
# the current session and print its answer. The prompt (file or stdin) is
# copied to the guest as ~/runs/STAMP.prompt and `claude -p` runs DETACHED
# there (setsid, stdin/stdout/stderr/exit status all under ~/runs/STAMP.*);
# the host polls for the exit file over fresh SSH connections and copies the
# four files to $SANDBOX_HOME/runs/ when it appears. The VM is the
# containment, so the agent runs with permission prompts bypassed;
# everything it does stays on the clone, and code comes back only as
# refs/heads/sandbox/*.
#
# Why detached (task 001, 2026-11-18): the first design piped the prompt
# through one SSH session and tee'd stdout. The run hit the subscription's
# session limit six minutes in, claude went silent, macOS's two-hour TCP
# keepalive then declared the idle connection dead, sshd hung up on the
# process, and nothing of the run reached the host. A detached run survives
# the host sleeping, the SSH hop dying, and a wait interrupted with Ctrl-C:
# `fetch STAMP` collects it later.
#
# Why stream-json (task 002, 2026-11-19): with text or json output the .out
# file stays empty until the run ends, so a 20-minute run could be watched
# only through the guest's session transcript. stream-json writes one event
# per line as the run goes (each tool call, each message, then a final
# `result` event carrying the answer, turns, cost and modelUsage), so
# `tail -f ~/runs/STAMP.out` in the guest is the live view and the fetched
# file is the full record. fetch prints the result event's text. --json
# keeps the old single JSON object.
cmd_run() {
  local name; name=$(current)
  [ -n "$name" ] || die "no current session"
  local model="${SANDBOX_MODEL:-}" fmt=stream-json file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --model) model=$2; shift 2 ;;
      --json) fmt=json; shift ;;
      *) file=$1; shift ;;
    esac
  done
  local ip; ip=$(vm_ip "$name")
  local stamp; stamp=$(date -u +%Y%m%dT%H%M%SZ)
  local dir="$SANDBOX_HOME/runs"; mkdir -p "$dir"
  if [ -n "$file" ]; then cp "$file" "$dir/$stamp.prompt"; else cat > "$dir/$stamp.prompt"; fi
  local args="-p --output-format $fmt --permission-mode bypassPermissions"
  # claude -p refuses stream-json without --verbose.
  [ "$fmt" = stream-json ] && args="$args --verbose"
  [ -n "$model" ] && args="$args --model $model"
  log "run $stamp (model: ${model:-default}) -> $dir/$stamp.out"
  ssh_as agent "$ip" 'mkdir -p ~/runs'
  scp "${SSH_OPTS[@]}" -q "$dir/$stamp.prompt" "agent@$ip:runs/$stamp.prompt"
  # setsid + nohup + no inherited fds: the process must outlive this SSH
  # session. The exit file is written last, so its presence means the
  # output files are complete.
  ssh_as agent "$ip" "setsid nohup bash -lc 'cd ~/cambios && claude $args < ~/runs/$stamp.prompt > ~/runs/$stamp.out 2> ~/runs/$stamp.err; echo \$? > ~/runs/$stamp.exit' >/dev/null 2>&1 </dev/null &"
  cmd_fetch "$stamp"
}

# print_answer OUT: print a run's answer. A stream-json file (first line a
# JSON event of type "system") prints the text of its final `result` event
# plus a one-line summary on stderr; a stream with no result event (the run
# died mid-way) says so instead of dumping the events. Text and json output
# print as they are.
print_answer() {
  python3 -I - "$1" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8", errors="replace") as f:
    lines = f.read().splitlines()
def event(line):
    try:
        e = json.loads(line)
    except ValueError:
        return None
    return e if isinstance(e, dict) else None
first = event(lines[0]) if lines else None
if not first or first.get("type") != "system":
    sys.stdout.write("\n".join(lines) + ("\n" if lines else ""))
    sys.exit(0)
results = [e for e in map(event, lines) if e and e.get("type") == "result"]
if not results:
    print(f"[session] no result event: the run stopped after {len(lines)} events; "
          f"the event log is {path}", file=sys.stderr)
    sys.exit(0)
r = results[-1]
print(r.get("result", ""))
cost = r.get("total_cost_usd")
print(f"[session] {r.get('subtype', '?')}, {r.get('num_turns', '?')} turns, "
      f"{(r.get('duration_ms') or 0) / 60000:.1f} min"
      + (f", ${cost:.2f} at list" if isinstance(cost, (int, float)) else "")
      + f"; event log {path}", file=sys.stderr)
PY
}

# fetch STAMP: wait until the detached run STAMP has written its exit file,
# copy its files to $SANDBOX_HOME/runs/, print the answer, exit with the
# agent's status. Safe to interrupt and repeat. A poll that cannot reach the
# guest (host asleep, bridge gone) is not a verdict; two consecutive answers
# of "no claude process and no exit file" are.
cmd_fetch() {
  local stamp=${1:-}; [ -n "$stamp" ] || die "fetch: STAMP required"
  local name; name=$(current)
  [ -n "$name" ] || die "no current session"
  local dir="$SANDBOX_HOME/runs"; mkdir -p "$dir"
  local probe="if test -f ~/runs/$stamp.exit; then echo done; elif pgrep -u agent -x claude >/dev/null; then echo running; else echo dead; fi"
  local ip state dead=0
  log "waiting for $stamp (poll ${RUN_POLL_S}s; Ctrl-C and 'fetch $stamp' later is safe)"
  while true; do
    ip=$(vm_ip "$name" 2>/dev/null || true)
    state=$([ -n "$ip" ] && ssh_as agent "$ip" "$probe" 2>/dev/null || echo unreachable)
    case "$state" in
      done) break ;;
      dead) dead=$((dead + 1)); [ $dead -ge 2 ] && die "run $stamp: no claude process and no exit file on the guest" ;;
      *) dead=0 ;;
    esac
    sleep "$RUN_POLL_S"
  done
  scp "${SSH_OPTS[@]}" -q "agent@$ip:runs/$stamp.out" "agent@$ip:runs/$stamp.err" "agent@$ip:runs/$stamp.exit" "$dir/"
  print_answer "$dir/$stamp.out"
  local rc; rc=$(tr -dc 0-9 < "$dir/$stamp.exit")
  [ -s "$dir/$stamp.err" ] && log "stderr ($(wc -l < "$dir/$stamp.err" | tr -d ' ') lines) in $dir/$stamp.err"
  log "run $stamp exit ${rc:-?}"
  return "${rc:-1}"
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  down) cmd_down ;;
  ssh) shift; cmd_ssh "$@" ;;
  run) shift; cmd_run "$@" ;;
  fetch) shift; cmd_fetch "$@" ;;
  pull) cmd_pull ;;
  status) cmd_status ;;
  *) sed -n '5,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
