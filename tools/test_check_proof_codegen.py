# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""Host tests for tools/check-proof-codegen.py: which proof crates a set
of staged paths selects.

Run with `make test-tools` (or `python3 -m unittest discover -s tools
-p 'test_*.py'`). Stdlib only.
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "check_proof_codegen", _HERE / "check-proof-codegen.py"
)
cpc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cpc)


class Parsing(unittest.TestCase):
    def test_path_attr(self):
        src = '//! uses `#[path]`\n#[path = "../../../src/syscalls/user_slice.rs"]\npub mod user_slice;\n'
        self.assertEqual(cpc.path_attrs(src), ["../../../src/syscalls/user_slice.rs"])

    def test_doc_mention_is_not_an_attribute(self):
        self.assertEqual(cpc.path_attrs('//! included via `#[path = "x.rs"]` here\n'), [])

    def test_path_deps(self):
        toml = '[dependencies]\ncambios-abi = { path = "../../cambios-abi" }\nkani = "0.1"\n'
        self.assertEqual(cpc.path_deps(toml), ["../../cambios-abi"])

    def test_lib_path_is_not_a_dependency(self):
        toml = '[lib]\npath = "src/lib.rs"\n\n[target.x86_64-unknown-none.dependencies]\nx = { path = "../x" }\n'
        self.assertEqual(cpc.path_deps(toml), ["../x"])


class Selection(unittest.TestCase):
    """A fake repository: one kernel file, one ABI crate, two proof crates."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "src/ipc").mkdir(parents=True)
        (root / "src/ipc/capability.rs").write_text("")
        (root / "src/other.rs").write_text("")
        (root / "cambios-abi/src").mkdir(parents=True)
        (root / "cambios-abi/src/lib.rs").write_text("")
        cap = root / "verification/capability-proofs"
        (cap / "src").mkdir(parents=True)
        (cap / "src/lib.rs").write_text('#[path = "../../../src/ipc/capability.rs"]\npub mod capability;\n')
        (cap / "Cargo.toml").write_text('[dependencies]\ncambios-abi = { path = "../../cambios-abi" }\n')
        buddy = root / "verification/buddy-proofs"
        (buddy / "src").mkdir(parents=True)
        (buddy / "src/lib.rs").write_text("")
        (buddy / "Cargo.toml").write_text("")
        self.root, self.cap, self.buddy = root, cap, buddy

    def tearDown(self):
        self.tmp.cleanup()

    def selected(self, staged):
        return [c.name for c in cpc.proof_crates(self.root / "verification")
                if cpc.touches(cpc.crate_inputs(c, self.root), staged)]

    def test_included_kernel_file(self):
        self.assertEqual(self.selected(["src/ipc/capability.rs"]), ["capability-proofs"])

    def test_path_dependency(self):
        self.assertEqual(self.selected(["cambios-abi/src/lib.rs"]), ["capability-proofs"])

    def test_own_files(self):
        self.assertEqual(self.selected(["verification/buddy-proofs/src/lib.rs"]), ["buddy-proofs"])

    def test_unrelated_kernel_file(self):
        self.assertEqual(self.selected(["src/other.rs", "Makefile"]), [])

    def test_prefix_is_a_directory_not_a_name_prefix(self):
        # cambios-abi/ must not select on cambios-abi-extra/...
        self.assertEqual(self.selected(["cambios-abi-extra/src/lib.rs"]), [])


if __name__ == "__main__":
    unittest.main()
