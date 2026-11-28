# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""Host tests for tools/qemu-run-quiet.py: which serial lines end a run as a
failure (exit 1).

The kernel's fault banners are scanned out of src/, so a new banner the
runner does not recognise fails here instead of turning a halted boot into a
timeout. Run with `make test-tools`. Stdlib only.
"""
import importlib.util
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_spec = importlib.util.spec_from_file_location("qemu_run_quiet", _HERE / "qemu-run-quiet.py")
qrq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qrq)

_NEVER = re.compile(r"\A(?!x)x")

# The `!!`-framed segment of a string literal in kernel source.
_BANNER = re.compile(r"!!+ [^\"\\]*?!!+")


def kernel_banners():
    found = []
    for path in sorted((_ROOT / "src").rglob("*.rs")):
        for m in _BANNER.finditer(path.read_text(encoding="utf-8")):
            found.append((path.relative_to(_ROOT), m.group(0)))
    return found


class Classify(unittest.TestCase):
    def test_every_kernel_banner_is_a_failure(self):
        banners = kernel_banners()
        # The aarch64 and riscv64 kernel-fault banners at least; an empty
        # scan would make the loop below vacuous.
        self.assertGreaterEqual(len(banners), 2, banners)
        for path, banner in banners:
            with self.subTest(path=str(path), banner=banner):
                self.assertEqual(qrq.classify(banner, _NEVER), "failure")

    def test_panic_and_exception_lines(self):
        for line in (
            "MICROKERNEL PANIC: PanicInfo { .. }",
            "EXCEPTION: invalid opcode in ring 0 (vector 6, error code 0x0)",
        ):
            with self.subTest(line=line):
                self.assertEqual(qrq.classify(line, _NEVER), "failure")

    def test_a_reaped_user_fault_is_not_a_failure(self):
        for line in (
            "  [Fault] U-mode scause=15 PageFault stval=0x10 sepc=0x400040",
            "  [Fault] pid=15 task=14 PageFault at 0x10 (pc=0x400040) — reaping",
            "[REGRESS] PASS trap-UD: a ring-3 ud2 (invalid opcode) reaps the program",
            "important!! not a banner",
        ):
            with self.subTest(line=line):
                self.assertEqual(qrq.classify(line, _NEVER), "live")


class HaltedKernel(unittest.TestCase):
    def test_a_silent_halt_after_a_banner_exits_1_without_waiting_out_the_timeout(self):
        # Stands in for QEMU: the kmain sentinel, a fault banner, then
        # silence, as a halted kernel gives.
        fake_qemu = (
            "import time; print('=== CambiOS Microkernel'); "
            "print('!! RISC-V S-MODE TRAP — KERNEL FAULT !!', flush=True); time.sleep(120)"
        )
        start = time.monotonic()
        result = subprocess.run(
            [sys.executable, str(_HERE / "qemu-run-quiet.py"), "--timeout", "120", "--",
             sys.executable, "-c", fake_qemu],
            capture_output=True, text=True, timeout=150,
        )
        elapsed = time.monotonic() - start
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertLess(elapsed, qrq.POST_FAILURE_GRACE_S + 20, result.stdout)


if __name__ == "__main__":
    unittest.main()
