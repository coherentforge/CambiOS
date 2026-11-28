<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors -->

# Reporting a security problem

This file says how to report a security problem in CambiOS and what happens when you do. The security *design* (what the kernel enforces, where, and why) is [docs/SECURITY.md](docs/SECURITY.md); the threat model is [docs/threat-model.md](docs/threat-model.md).

## Where CambiOS stands

CambiOS is pre-release. It boots under QEMU and on one bare-metal machine the maintainer owns; nobody runs it with data they would miss. There are no supported versions and no security releases yet. The known-finding backlog is public: the maintainers' own review documents are under [docs/dev-notes/](docs/dev-notes/) (`review-*.md`), and each open finding is a GitHub issue labelled `review-finding` with its severity. Before reporting, search the open issues: the problem may already be filed, and a comment on the existing issue is the most useful form of a duplicate report.

Because nothing is deployed, a finding is a bug report with a severity attached, not a coordinated disclosure. Report it the way that suits you.

## How to report

- **Privately**, if you would rather the maintainers see it first: [open a private vulnerability report](https://github.com/coherentforge/CambiOS/security/advisories/new) on GitHub. Only the maintainers can read it. Use this if your finding comes with a working exploit you would rather not post, or if you are unsure.
- **Publicly**, as an [issue](https://github.com/coherentforge/CambiOS/issues/new/choose) using the *Security finding* template, if the problem is of the kind already visible in the public backlog.

Either way, the useful contents are: the architecture (x86_64, aarch64, riscv64), the commit you tested, what you expected the kernel to refuse, what it did instead, and how you observed it (a probe source, a QEMU command line, a serial log). A reproduction that runs from ring 3 under `make run-quiet` is the best possible report; the maintainers turn such probes into stages of `user/regression-probe` so the fix stays fixed.

## What happens next

- You get an acknowledgement within seven days. A private report is answered in the advisory thread; a public one, on the issue.
- The maintainers confirm or refute the finding by tracing or under QEMU, assign a severity using the scale the `severity:` labels define, and say what the fix shape is. The fix lands on `main` with a regression stage where one is possible, and the finding is credited to you in the commit message unless you ask otherwise.
- A private report is opened up once the fix lands, or sooner if you and the maintainers agree.

There is no bounty. The project has no money to offer; what it offers is credit, a fast fix, and a say in the design conversation that follows.

## Out of scope

- Denial of service by an identified process against the system it runs on, beyond what the capability model says it may do. Resource quotas are planned work, not a security boundary today.
- Anything that needs the signing key, the policy service's identity, or physical access to the machine. Those are the trust roots.
- Problems in QEMU, Limine, OpenSBI or the Rust toolchain. Report those upstream; a link here is welcome.

## Keys and signing

Boot modules are signed. The default build signs with a development seed published in the Makefile, so a default build proves nothing about who built it; the maintainer's canonical builds sign with a hardware key. Neither key is a secret you can report a leak of: the development seed is public by design, and the hardware key never leaves the device.
