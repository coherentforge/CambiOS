#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca

"""Filtered QEMU wrapper.

Streams kernel + module output live, suppresses boot-time noise (memory map
dump, Limine banner, per-framebuffer enumeration), exits with a status code
reflecting what actually happened.

Exit codes:
  0 — success sentinel seen (default: ``cambios> ``)
  1 — kernel panic, CPU exception, or Limine bailout
  2 — no sentinel within --timeout, or QEMU exited before one

Usage:
  qemu-run-quiet.py [--timeout N] [--success STRING] -- <qemu-cmd...>
"""

import argparse
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque


FAILURE_PATTERNS = [
    re.compile(r"MICROKERNEL PANIC:"),
    re.compile(r"EXCEPTION:"),
    re.compile(r"Limine base revision not supported"),
]

# Before this sentinel fires, pre-kmain lines (Limine boot menu, module
# loading) are treated as noise. Failure patterns still take precedence.
KMAIN_SENTINEL = re.compile(r"=== CambiOS Microkernel")

NOISE_PATTERNS = [
    re.compile(r"^HHDM offset:"),
    re.compile(r"^Memory map: \d+ entries"),
    re.compile(r"^\s+\[\s*\d+\]"),
    re.compile(r"^Framebuffers:"),
    re.compile(r"^\s+framebuffer\s+\d+:"),
]

CONTEXT_BEFORE = 5
RING_SIZE = 50
MAX_POST_FAILURE_LINES = 100


def classify(line: str, success_re: re.Pattern) -> str:
    if success_re.search(line):
        return "success"
    if any(p.search(line) for p in FAILURE_PATTERNS):
        return "failure"
    if any(p.search(line) for p in NOISE_PATTERNS):
        return "noise"
    return "live"


def main() -> int:
    # argparse.REMAINDER has surprising precedence; splitting on literal `--`
    # is unambiguous and avoids its corner cases.
    try:
        sep = sys.argv.index("--")
    except ValueError:
        print("error: separate wrapper args from QEMU command with '--'", file=sys.stderr)
        return 3

    parser = argparse.ArgumentParser(prog="qemu-run-quiet.py")
    parser.add_argument("--timeout", type=int, default=60,
                        help="seconds before declaring a hang (default: 60)")
    parser.add_argument("--success", default="cambios> ",
                        help="success sentinel substring (default: 'cambios> ')")
    args = parser.parse_args(sys.argv[1:sep])
    qemu_cmd = sys.argv[sep + 1:]
    if not qemu_cmd:
        print("error: no QEMU command after '--'", file=sys.stderr)
        return 3

    # Force stdout to blocking mode. Some launching shells (notably the
    # Claude Code agent harness) inherit non-blocking stdout, which causes
    # `print(line)` to raise BlockingIOError mid-stream when the pipe
    # buffer fills. Make doesn't survive that — the script dies, returning
    # exit 1 from an uncaught exception, and the run looks like a failure
    # when QEMU was actually fine.
    try:
        os.set_blocking(sys.stdout.fileno(), True)
    except (OSError, AttributeError):
        pass

    success_re = re.compile(re.escape(args.success))
    start = time.monotonic()
    ring: deque[str] = deque(maxlen=RING_SIZE)
    saw_failure = False
    post_failure = 0
    kmain_seen = False

    proc = subprocess.Popen(
        qemu_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    # Daemon watchdog kills QEMU if the main loop hasn't already. Killing
    # closes the stdout pipe, which ends the `for raw in proc.stdout` loop.
    def watchdog() -> None:
        time.sleep(args.timeout)
        if proc.poll() is None:
            proc.kill()

    threading.Thread(target=watchdog, daemon=True).start()

    try:
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            ring.append(line)
            kind = classify(line, success_re)

            if KMAIN_SENTINEL.search(line):
                kmain_seen = True

            if kind == "success" and not saw_failure:
                elapsed = time.monotonic() - start
                print(line)
                print(f"✓ success sentinel reached in {elapsed:.1f}s")
                proc.kill()
                proc.wait()
                return 0

            if kind == "failure" and not saw_failure:
                saw_failure = True
                for c in list(ring)[-CONTEXT_BEFORE - 1:-1]:
                    print(c)
                print(line)
                continue

            if saw_failure:
                print(line)
                post_failure += 1
                if post_failure >= MAX_POST_FAILURE_LINES:
                    proc.kill()
                continue

            if not kmain_seen:
                continue

            if kind == "live":
                print(line)
    except KeyboardInterrupt:
        proc.kill()
        proc.wait()
        return 130

    proc.wait()
    elapsed = time.monotonic() - start

    if saw_failure:
        return 1

    print(f"✗ no success sentinel within {elapsed:.1f}s (timeout={args.timeout}s); last {len(ring)} lines:")
    for line in ring:
        print(line)
    return 2


if __name__ == "__main__":
    sys.exit(main())
