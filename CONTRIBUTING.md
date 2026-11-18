# Contributing to CambiOS

This file is the process contract: how a change gets from your machine to `main`, and what checks it on the way. It applies to people and to AI agents working for them. The technical contract (conventions, lock ordering, required reading per subsystem) is [CLAUDE.md](CLAUDE.md), and agents should read both.

Where this file and the repository disagree, the repository is right and this file has a bug. Please say so in a pull request.

## Before you write code

1. Read [CLAUDE.md](CLAUDE.md). Its Stop-and-Ask Gate lists the changes that need a conversation with the maintainer before the first edit.
2. Read the ADRs (architecture decision records, under [docs/adr/](docs/adr/)) for the subsystem you are touching. The Required Reading map in CLAUDE.md names them.
3. Check [STATUS.md](STATUS.md) for what is built and what is in progress.

## Setup

Supported hosts are macOS on Apple Silicon and x86_64 Linux. The pinned Rust toolchain, its targets and clippy install themselves from [rust-toolchain.toml](rust-toolchain.toml) the first time cargo runs in the tree.

```bash
make install-hooks    # once per clone: points git at the tracked hooks in .githooks/
make check-env        # what this machine has and lacks, and how to get it
```

`make check-env` separates what the checks need (it fails if any of that is missing) from what building and booting images needs and what proofs and fuzzing need.

Not proven on Linux: the QEMU (Quick Emulator) run targets that use UEFI firmware (`make run-aarch64`, `make run-uefi`, `make run-img-x86`), whose firmware lookup only knows where QEMU itself installs the images, and `make usb`, which calls a macOS disk tool. `make run-quiet` (x86_64, BIOS boot) runs on Linux nightly in CI (continuous integration).

## What checks a change

### On your machine

Run these before you push. The first three are the gate for any change to the kernel; the next two are the gate for the user crates.

```bash
make check-all        # the kernel builds for x86_64, aarch64 and riscv64
make test             # kernel unit tests
make check-clippy     # the unsafe-discipline lints, on all three architectures
make check-user       # every user crate builds for every architecture that lists it
make test-user        # host tests of the user, protocol and tool crates
```

The hooks run on their own once installed:

- **pre-commit** runs the lints: build lists agree (`check-lists`), every `unsafe` block has a `// SAFETY:` comment, no enforcement path defaults to allow, deleted paths stay deleted, and others. Each prints what it found and how to fix it.
- **commit-msg** requires a sign-off on every commit and, for agent-authored commits, a list of the staged files (both described under Commits).
- **pre-push** checks the provenance of commits written with Claude Code.

Never bypass a hook or signing (`--no-verify`, `--no-gpg-sign`). If a hook is wrong, fix the hook in its own commit.

### On the pull request

The workflows under [.github/workflows/](.github/workflows/) run on every pull request: the kernel build for three architectures, the kernel unit tests, clippy, the lints, and the Kani proof jobs (Kani is the model checker the proofs under `verification/` use). Branch protection on `main` names the checks that must pass before a merge. A nightly job boots x86_64 under QEMU to the shell.

CI does not yet build or test the user crates. Until it does, `make check-user` and `make test-user` on your machine are that check.

A pull request is judged by the checks as they stand on `main` when it is opened and updated. The history of the gates is the history of `.github/`, `.githooks/`, `tools/` and the `Makefile`.

### Review

[.github/CODEOWNERS](.github/CODEOWNERS) lists the paths that need the maintainer's review before a merge: the kernel (`src/`), the syscall ABI (application binary interface) crate, the ADRs, CLAUDE.md, and the gates themselves (`Makefile`, `tools/`, `.github/`). A change that touches those paths waits for that review however green its checks are.

## Commits

- **One topic per commit.** A commit is complete and passing on its own. Stage files by name; never `git add .` or `git commit -a`.
- **Subject line** `area: what is now true`. The body says what changed, why, what was left out, and how it was verified.
- **Sign off every commit**: `git commit -s`. The `Signed-off-by:` line certifies the [Developer Certificate of Origin](https://developercertificate.org): that you wrote the change or otherwise have the right to submit it under the project's license. The sign-off is yours even when an agent wrote the change; you are the one certifying where it came from. The commit-msg hook rejects a commit without it.
- **Sign your commits cryptographically if you can** (GPG or SSH). The maintainer's commits are signed. GitHub does not currently reject an unsigned commit on a pull request.
- **Agent-authored commits say so.** A commit an AI agent wrote, or co-wrote, carries a `Co-Authored-By:` trailer naming the agent. Such a commit must also carry a `Staged files:` block that lists exactly the files in the commit, one per line, indented; the commit-msg hook compares the block with the index and rejects a mismatch. The rule exists because agents working in parallel have swept each other's files into commits.

```
Staged files:
  user/example/src/main.rs
  manifest.toml

Co-Authored-By: <agent name> <noreply address>
Signed-off-by: Your Name <you@example.org>
```

## Rules that hold everywhere

CLAUDE.md is the full statement. The ones a lint enforces on every crate:

- Every new file starts with an SPDX (Software Package Data Exchange) license line and the copyright line, as CLAUDE.md § Critical Rules gives them.
- Every `unsafe { }` block has a `// SAFETY:` comment stating why the operation is sound.
- Enforcement fails closed. A path that cannot get an authorization decision denies. Code or a comment that describes a default-allow path fails `check-fail-open`.
- A deferral (`TODO`, "for now", "eventually") names an observable trigger on a `Revisit when:` line.
- No telemetry, analytics or phone-home behaviour, in any form.

Kernel code has more (typed errors and no panics, tagged numeric bounds, the lock hierarchy, no architecture-specific code in portable modules). Read CLAUDE.md before touching `src/`.

## Architectural decisions

A new architectural decision gets a new ADR: `make new-adr TITLE="..."`. Do not bury a decision in a code comment. Changing the body of an existing ADR needs the maintainer's agreement to the diff first; the superseded wording moves to a Divergence appendix in the same file.

## Adding a user crate

[docs/dev-notes/adding-a-user-crate.md](docs/dev-notes/adding-a-user-crate.md) is the walkthrough: the crate, the build lists, the workspace exclude list, the boot configuration, the manifest entry, host tests. `make check-lists` reports what is missing at each step.

## Paths

Tracked files do not cite a path that exists on one machine only: a home directory, a plan or notes folder outside the repository, a gitignored directory. If a document is worth citing, commit it under `docs/`.

## Boot-module signing during development

Every boot module is signed, and the kernel verifies the signature before it loads one. The default build signs with a development seed that is published in the Makefile (`SIGN_MODE=seed`), and the committed `bootstrap_pubkey.bin` is the public key derived from that seed. This lets anyone build and boot without hardware. It also means a default build's signatures prove nothing about who built it. Signing with a hardware key is a separate mode (`SIGN_MODE=yubikey`) that the maintainer uses.

## License and copyright

CambiOS is licensed under AGPL-3.0-or-later (the GNU Affero General Public License, [LICENSE](LICENSE)). Files under `user/libsys/` are licensed under MPL-2.0 (the Mozilla Public License, [user/libsys/LICENSE](user/libsys/LICENSE)) so that applications can link the system library without taking on the AGPL.

You keep the copyright in what you contribute. There is no contributor license agreement; the sign-off on each commit is the whole of the paperwork. New files carry the collective line `Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors`.
