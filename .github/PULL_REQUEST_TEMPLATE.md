<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors -->

## What is now true

<!-- One topic per pull request. What changed, why, and what was deliberately left out. Name the issue or ADR it serves. -->

## Verification

<!-- What you ran and what it printed. The checks CONTRIBUTING.md names for your lane: -->
<!-- kernel: make check-all, make test, make check-clippy; user crates: make check-user, make test-user -->
<!-- a boot-visible change: make run-quiet exit code, or the arch's run target -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`); an agent-authored commit also carries its `Co-Authored-By:` trailer and a `Staged files:` block.
- [ ] New files start with the SPDX license line and the copyright line.
- [ ] Every new `unsafe` block has a `// SAFETY:` comment; every deferral has a `Revisit when:` trigger.
- [ ] A change under `src/` has read the subsystem's Required Reading (CLAUDE.md) and ran the Post-Change Review Protocol; STATUS.md and ASSUMPTIONS.md rows are updated where they apply.
- [ ] No ADR body was changed without the maintainer's agreement to the diff first.
