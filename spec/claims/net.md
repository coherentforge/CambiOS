<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 CambiOS contributors -->

# Claim ledger: CambiOS network stack

Rows classify evidence for the invariants in `spec/crates/net.md`. `proposed`
means no implementation or proof has run. A successful local proof does not
establish protocol conformance or hardware correctness.

| crate | id | class | harness | bound | status | gap |
|---|---|---|---|---|---|---|
| net | INV-net-001 | kani | - | MAX_LINK_MTU + 18 | proposed | no parser or harness exists |
| net | INV-net-002 | tests | - | packet vectors | proposed | no parser or test exists |
| net | INV-net-003 | tests | - | packet vectors | proposed | no parser or test exists |
| net | INV-net-004 | kani | - | 8 headers, 2048 bytes | proposed | no parser or harness exists |
| net | INV-net-005 | tests | - | neighbor table capacity | proposed | no neighbor service or test exists |
| net | INV-net-006 | tests | - | packet vectors | proposed | no UDP service or test exists |
| net | INV-net-007 | model | - | TCP transition table | proposed | no state model or conformance test exists |
| net | INV-net-008 | kani | - | u32 serial arithmetic | proposed | no arithmetic harness exists |
| net | INV-net-009 | tests | - | RFC 5961 vectors | proposed | no TCP service or test exists |
| net | INV-net-010 | model | - | configured timer range | proposed | no timer model or interoperability evidence exists |
| net | INV-net-011 | kani | - | every `NetLimits` field | proposed | no resource accounting code or harness exists |
| net | INV-net-012 | model | - | per-principal resource model | proposed | no isolation model exists |
| net | INV-net-013 | kani | - | input bytes up to MAX_LINK_MTU + 18 | proposed | no parser or harness exists |
| net | INV-net-014 | tests | - | capability operation matrix | proposed | no network IPC or test exists |
| net | INV-net-015 | tests | - | DNS vectors and TTL bounds | proposed | no resolver or test exists |
| net | INV-net-016 | tests | - | DHCP transaction vectors | proposed | no DHCP client or test exists |
| net | INV-net-017 | tests | - | diagnostic capture | proposed | no stats/log interface or test exists |
| net | INV-net-018 | kani | - | 64 fragments, 4 MiB | proposed | no reassembly model or harness exists |
| net | INV-net-019 | tests | - | capability operation matrix | proposed | no listener service or test exists |
| net | INV-net-020 | tests | - | IPv6 UDP vectors | proposed | no UDP service or test exists |
| net | INV-net-021 | tests | - | MAX_ROUTES entries, longest-prefix/metric/interface tie-break | proposed | no route table or test exists |
| net | INV-net-022 | tests | - | one DAD interval and address lifetime | proposed | no SLAAC service or test exists |


## Verification-route decision (draft)

Kani remains the planned Rust-side bounded checker for parsers, integer/serial arithmetic, and resource accounting. `proposed` means no harness exists. Lean is a candidate for the pure state-transition model, with Aeneas as a possible translator for a safe sequential Rust subset. A Lean theorem would establish only the stated property of that model under its axioms and imported lemmas; it would not establish RFC conformance or match the implementation unless a refinement relation is separately specified and checked. Unsafe device/IPC boundaries and concurrent behavior remain outside this candidate route. No Lean/Kani proof has been run for this specification.

| candidate | property | status | gap |
|---|---|---|---|
| lean + aeneas | TCP transition safety of a pure sequential model | proposed | no model, translation, refinement theorem, or proof exists |
| kani | Rust parser memory safety and bounded resource arithmetic | proposed | no networking crate or harness exists |
| vectors + interop | observable RFC-profile behavior | proposed | vectors are draft data; no replay harness or peer traces exist |
