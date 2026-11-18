#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""CONNECT-only forward proxy with a hostname allow-list.

The hostname layer of the sandbox VM's egress control (stage G rung 2). Softnet
on the host enforces the address layer: the VM may open TCP to exactly one
host port, this proxy's. The proxy then permits a tunnel only to hostnames in
the allow-list file, on port 443, and logs every decision. It never performs
plain HTTP forwarding and never resolves a name on the VM's behalf other than
the one it is about to tunnel to.

Stdlib only. One thread per tunnel.

Usage:
  allowlist-proxy.py --allow FILE --log FILE [--port 3128]
                     (--bind ADDR | --iface bridge100 [--wait SECONDS])
                     [--pidfile FILE]

Allow-list file: one hostname per line, lowercase, exact match. Blank lines and
lines starting with '#' are ignored. The file is re-read on SIGHUP.
"""

import argparse
import datetime
import os
import select
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time

# TUNING: request head cap. A CONNECT line plus a few headers is well under 1 KiB;
# 8 KiB rejects anything that is not a CONNECT handshake without buffering it.
MAX_HEAD_BYTES = 8192
# TUNING: upstream connect timeout. The API is a CDN; 10 s is a dead link, not a slow one.
CONNECT_TIMEOUT_S = 10.0
# TUNING: a tunnel idle this long (no bytes either way) is torn down. Long enough
# for a streamed API response that is thinking; short enough to reclaim leaks.
IDLE_TIMEOUT_S = 600.0
# ARCHITECTURAL: the only upstream port the sandbox needs. HTTP is not tunnelled.
ALLOWED_PORT = 443
RELAY_CHUNK = 65536


class Policy:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._hosts = frozenset()
        self.reload()

    def reload(self):
        hosts = set()
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                hosts.add(line.lower().rstrip("."))
        with self._lock:
            self._hosts = frozenset(hosts)

    def allows(self, host):
        with self._lock:
            return host in self._hosts

    def snapshot(self):
        with self._lock:
            return sorted(self._hosts)


class Log:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._f = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, verdict, client, target, reason="", extra=""):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{ts} {verdict} client={client} target={target}"
        if reason:
            line += f" reason={reason}"
        if extra:
            line += f" {extra}"
        with self._lock:
            self._f.write(line + "\n")


class Handler(socketserver.BaseRequestHandler):
    def _reply(self, status, text):
        body = (text + "\n").encode()
        head = (
            f"HTTP/1.1 {status}\r\n"
            "Connection: close\r\n"
            "Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode()
        try:
            self.request.sendall(head + body)
        except OSError:
            pass

    def handle(self):
        client = f"{self.client_address[0]}:{self.client_address[1]}"
        log, policy = self.server.log, self.server.policy
        self.request.settimeout(CONNECT_TIMEOUT_S)

        head = b""
        while b"\r\n\r\n" not in head:
            try:
                chunk = self.request.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            head += chunk
            if len(head) > MAX_HEAD_BYTES:
                log.write("DENY", client, "-", "head-too-large")
                self._reply("400 Bad Request", "request head too large")
                return

        request_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = request_line.split(" ")
        if len(parts) != 3 or parts[0] != "CONNECT":
            log.write("DENY", client, request_line[:120], "not-connect")
            self._reply("405 Method Not Allowed", "CONNECT only")
            return

        target = parts[1]
        host, sep, port_s = target.rpartition(":")
        if not sep or not port_s.isdigit():
            log.write("DENY", client, target, "malformed-target")
            self._reply("400 Bad Request", "malformed target")
            return
        host = host.strip("[]").lower().rstrip(".")
        port = int(port_s)

        if port != ALLOWED_PORT:
            log.write("DENY", client, target, "port")
            self._reply("403 Forbidden", "port not allowed")
            return
        if not policy.allows(host):
            log.write("DENY", client, target, "host-not-allowed")
            self._reply("403 Forbidden", "host not in allow-list")
            return

        try:
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S)
        except OSError as e:
            log.write("DENY", client, target, f"upstream-connect:{e.__class__.__name__}")
            self._reply("502 Bad Gateway", "upstream connect failed")
            return

        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            upstream.close()
            return

        sent, received = self._relay(self.request, upstream)
        upstream.close()
        log.write("ALLOW", client, target, extra=f"up={sent} down={received}")

    @staticmethod
    def _relay(a, b):
        a.settimeout(None)
        b.settimeout(None)
        a_to_b = b_to_a = 0
        socks = [a, b]
        while True:
            readable, _, _ = select.select(socks, [], [], IDLE_TIMEOUT_S)
            if not readable:
                break
            closed = False
            for s in readable:
                try:
                    data = s.recv(RELAY_CHUNK)
                except OSError:
                    data = b""
                if not data:
                    closed = True
                    break
                dst = b if s is a else a
                try:
                    dst.sendall(data)
                except OSError:
                    closed = True
                    break
                if s is a:
                    a_to_b += len(data)
                else:
                    b_to_a += len(data)
            if closed:
                break
        return a_to_b, b_to_a


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, policy, log):
        self.policy = policy
        self.log = log
        super().__init__(addr, Handler)


def iface_addr(iface):
    """First IPv4 address on `iface`, or None.

    Parses ifconfig(8) rather than `ipconfig getifaddr`: the Tart/softnet bridge
    (bridge100) is not a SystemConfiguration service, so ipconfig reports nothing
    for it even while ifconfig shows the gateway address.
    """
    try:
        out = subprocess.run(["ifconfig", iface], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "inet":
            return parts[1]
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--allow", required=True, help="allow-list file")
    ap.add_argument("--log", required=True, help="decision log (appended)")
    ap.add_argument("--port", type=int, default=3128)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--bind", help="address to listen on")
    g.add_argument("--iface", help="listen on this interface's IPv4 address (e.g. bridge100)")
    ap.add_argument("--wait", type=float, default=60.0, help="seconds to wait for --iface to get an address")
    ap.add_argument("--pidfile")
    args = ap.parse_args()

    bind = args.bind
    if args.iface:
        deadline = time.monotonic() + args.wait
        while True:
            bind = iface_addr(args.iface)
            if bind:
                break
            if time.monotonic() >= deadline:
                print(f"allowlist-proxy: {args.iface} has no IPv4 address after {args.wait:.0f}s", file=sys.stderr)
                return 2
            time.sleep(0.5)

    policy = Policy(args.allow)
    log = Log(args.log)
    server = Server((bind, args.port), policy, log)

    def on_hup(signum, frame):
        try:
            policy.reload()
            log.write("INFO", "-", "-", "reload", extra=f"hosts={','.join(policy.snapshot())}")
        except OSError as e:
            log.write("INFO", "-", "-", f"reload-failed:{e.__class__.__name__}")

    def on_term(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGHUP, on_hup)
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    if args.pidfile:
        with open(args.pidfile, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))

    log.write("INFO", "-", f"{bind}:{args.port}", "start", extra=f"hosts={','.join(policy.snapshot())}")
    print(f"allowlist-proxy: listening on {bind}:{args.port}; allow={policy.snapshot()}", flush=True)
    try:
        server.serve_forever()
    finally:
        log.write("INFO", "-", f"{bind}:{args.port}", "stop")
        if args.pidfile:
            try:
                os.unlink(args.pidfile)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
