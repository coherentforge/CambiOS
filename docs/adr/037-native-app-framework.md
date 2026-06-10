# ADR-037: Native App Framework: runtime, IPC stdlib, toolkit, service scaffolding

- **Status:** Proposed
- **Date:** 2026-06-10
- **Depends on:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives the stdlib wraps), [ADR-024](024-syscall-abi-crate.md) (`cambios-abi`)
- **Related:** [ADR-018](018-init-process-and-boot-manifest.md) (init + boot manifest — owns the manifest, signing, kernel reservation table; this ADR's authoring layer feeds its build tool), [ADR-004](004-cryptographic-integrity.md) (ARCSIG signing), [ADR-011](011-graphics-architecture-and-scaling.md) + [ADR-014](014-compositor-scanout-driver-protocol.md) (compositor/GUI the toolkit renders through), [ADR-012](012-input-architecture-and-device-classes.md) (input the event loop pumps), [ADR-006](006-policy-service.md) (policy-service — the first consumer), [ADR-008](008-boot-time-sized-object-tables.md) (tier sizing)
- **Supersedes:** N/A (extends `user/libsys` + `user/libgui`; replaces neither)

## Context

CambiOS has 23 userspace services / ~12,000 lines of Rust (STATUS.md) that repeat nearly-
identical boilerplate, because `libsys` (raw + safe syscall wrappers) and `libgui` (v0 drawing
primitives, no widgets) are minimal *substrates*, not a *framework*. Measured across the tree:

- entry-point ritual (`#![no_std]`/`#![no_main]`/`_start` → `register_endpoint` → `module_ready`): **23/23 services**
- identical panic handlers: **23/23**
- recv/dispatch/yield main loops: **22/22**
- hand-rolled message marshalling (`from_le_bytes`/manual slicing): **333 sites**
- independently-invented `u8` status-code sets: **11 services**
- duplicated per-service `link.ld` linker scripts: **24**

The goal (the prioritized direction): a substrate that lets us *build a lot more in userspace*
once it is real. That needs a stdlib, not more bespoke services. This is squarely the "push
cycles out of the kernel ring" principle: the framework lives entirely in userspace and
introduces **zero new kernel syscalls in any layer** (contrast [ADR-018](018-init-process-and-boot-manifest.md),
which adds `SYS_INSTALL_ENDPOINT_RESERVATIONS` + extends `SYS_SPAWN`; this ADR is the lower-risk,
kernel-ABI-neutral slice).

### Boilerplate tax — measured, not asserted

Rather than claim a speculative reduction multiple, the savings are measured against a concrete,
not-yet-written target: **`user/init`** (the PID-1 supervisor [ADR-018](018-init-process-and-boot-manifest.md)
introduces). Init is a textbook framework consumer — it parses a blob, runs a steady-state recv
loop, manages child lifecycle, and emits audit events. Because it does not exist yet, writing it
*twice* — once on raw `libsys` (what the project would do today) and once on this framework — gives
an honest line-delta with no strawman "raw" version. That delta is the ADR's success metric; the
23-service / 333-site figures above are the standing context that motivates the work.

## Decision

A **layered framework that extends `libsys`/`libgui`** (it does not replace them), entirely in
userspace. Four layers; the boundary with [ADR-018](018-init-process-and-boot-manifest.md) is
sharp (see "Relationship to ADR-018").

- **L0 — `libsys-rt` (runtime / crt0).** The startup ritual every service hand-rolls, collapsed
  into one place: a `#[service_main]` entry macro (a `macro_rules!` macro — no `syn`/`quote`, no
  proc-macro crate in the build graph) that emits `_start`, a default `#[panic_handler]` (log to
  serial + `sys::exit(1)`), and a feature-gated default `#[global_allocator]` (the proven
  `LockedHeap`-over-static-BSS pattern, opt-in for `alloc` consumers). Assembles `register_endpoint`
  / `module_ready` / `exit`.
- **L1 — `libipc` (IPC stdlib).** Turns the 333 marshalling sites into a typed surface: a `Message`
  wrapper (parses the 36-byte header once: `sender_principal` + `from_endpoint` + payload), a shared
  `ServiceError` + `Result` alias (replacing the 11 reinvented status sets), and a generic,
  **monomorphized** `ServiceLoop<H: Handler>` owning recv→dispatch→reply→yield. No `Box<dyn>` (honors
  the no-trait-objects-in-hot-paths rule). A `no_std`/no-serde `Encode`/`Decode` derive is **deferred**
  to the second real request/response struct (second-consumer discriminator).
- **L2 — `libui` (GUI toolkit).** The widget/layout/event tier `libgui` v0 deferred: an event loop
  wired to compositor input (`MsgTag::InputEvent`), a minimal widget set (Label, Button, container)
  over a Box/Flex layout pass, focus/z-order, decoration drawing — all rendering through the existing
  `Surface` API (CPU writes into the attached surface channel).
- **L3 — service scaffolding (authoring ergonomics).** **Not** a manifest or package format — the
  signed manifest, its wire format, signing, and kernel-side endpoint reservation are owned wholly by
  [ADR-018](018-init-process-and-boot-manifest.md). What remains genuinely L3 is the *authoring-side*
  layer above that contract: (a) **one canonical `link.ld`** replacing the 24 duplicated per-service
  linker scripts, and (b) a **service-crate template / scaffolding** (`Cargo.toml` + skeleton wired to
  consume L0-L2). These are build-side artifacts authors copy from, not code linked into apps or the
  kernel. L3 does not interpret or produce the manifest; it produces *services* that the ADR-018
  manifest then describes.

### MVP substrate (build this first)

**L0 + the L1 core trio: `Message` + `ServiceError`/`Result` + `ServiceLoop<Handler>`.** The smallest
slice that unlocks broad userspace building — it attacks the boilerplate *every* service pays. Zero
kernel syscalls, zero ABI changes — verification-neutral, cannot regress the kernel. Defer the
`Encode`/`Decode` derive, the endpoint-registry source artifact (below), and L2/L3 until the MVP has a
real consumer proving the `Handler` shape.

### First consumer (prove before greenfield)

Rewrite **`policy-service`** onto the MVP first ([ADR-006](006-policy-service.md)) — the canonical
`recv_verified` → parse fixed query → dispatch → reply → yield server, security-load-bearing, no
driver MMIO to muddy the `Handler` abstraction. **L2's** first consumer is chosen when L2 starts
(Phase 3), from: a rewrite of an existing GUI app (`hello-window` or a game) onto `libui`, or the
*webmin/drainer portal* — a userspace dashboard over the backlog-drainer runs (live runs, lane
queues, bot PRs + CI, one-click greenlight). The portal is a *candidate*, not yet a specified app;
L2 will not be designed until its consumer is real (the "second consumer in scope" discriminator).

### Phasing

0. **MVP:** `libsys-rt` + `libipc` core. No derive macro, no kernel changes. Prove by rewriting
   `policy-service`. Then validate against the `init`-written-twice measurement.
1. Rewrite a second + third service (one driver-shaped, one pure-server) to confirm `Handler` covers
   blocking, multi-endpoint (`try_recv_msg`), and reply patterns. Extract the `Encode`/`Decode` derive
   only when a real struct demands it.
2. **Endpoint-registry source artifact** + structured logging. A TOML- or Rust-defined registry of
   `(service → reserved endpoints)`, build-tool-validated for global uniqueness, that **`tools/build-manifest`
   ([ADR-018](018-init-process-and-boot-manifest.md) migration step 2) consumes as input.** The
   convergence direction is *determined*, not aspirational: this artifact is the single source the
   ADR-018 manifest is generated from — never a parallel authority or a runtime registry (ADR-018's
   kernel reservation table is one-shot, no runtime re-read). Can ship before or after ADR-018 lands,
   as long as `build-manifest` accepts it as input.
3. `libui`: event loop, widgets, layout, focus/z-order, decorations. Driven by its first real consumer.
4. L3 scaffolding: consolidate the 24 `link.ld` into one canonical script; ship the service-crate
   template. Pure userspace build hygiene; orderable anytime.

## Decided (these were the open questions; now settled)

1. **L0-L2 license — MPL-2.0.** Confirmed. `user/libsys` is already MPL-2.0 (everything else AGPL);
   L0-L2 are the same *linkable* ABI/stdlib surface, so the precedent holds — file-level copyleft that
   lets apps link the framework without themselves becoming MPL.
2. **L3 license — differs from L0-L2, permissive.** The linker script + service template are *copied
   from*, not *linked into* apps. Project-supplied scaffolding wants a permissive license (Apache-2.0
   or CC0) so authored services carry whatever license their author chooses, not the template's. Exact
   choice is a one-line follow-up when L3 lands; it is explicitly a different question from the L0-L2
   MPL decision.
3. **Scope — L0-L2 + L3-scaffolding here; manifest/signing/kernel-reservation to ADR-018.** Confirmed.

### Still open (minor)

- **Default allocator policy:** feature-gated `LockedHeap` over a const-sized static BSS arena (the
  `terminal-window` pattern) — confirm the arena-size convention and whether non-`alloc` services opt
  **out** or `alloc` services opt **in**. Resolvable at MVP implementation.

## Relationship to ADR-018 (the boundary)

[ADR-018](018-init-process-and-boot-manifest.md) and this ADR are complementary and non-overlapping:

| Concern | Owner |
|---|---|
| Signed manifest blob + wire format; `ARCSIG` signing of it | **ADR-018** |
| `SYS_INSTALL_ENDPOINT_RESERVATIONS`, kernel reservation table, `SYS_SPAWN` extension | **ADR-018** (kernel) |
| init / PID-1, restart/backoff, deletion of `BOOT_MODULE_ORDER`/`BootGate`/`SYS_MODULE_READY` | **ADR-018** |
| `tools/build-manifest` (consumes the registry below, emits the signed blob) | **ADR-018** (migration step 2) |
| Runtime/crt0 (L0), IPC stdlib (L1), GUI toolkit (L2), service scaffolding (L3) | **This ADR** (all userspace) |
| Endpoint-registry *source artifact* that build-manifest reads | **This ADR** (L1/Phase 2), feeding ADR-018 |

ADR-018 adds kernel surface and is the heavier, later, more verification-relevant slice. This ADR
adds none — it is kernel-ABI-neutral and can land in any order relative to ADR-018's steps 1-7, with
the single coupling that the Phase-2 registry targets `build-manifest` as its consumer.

## Consequences

**Enables:** new services as a `Handler` impl + entry macro; a real GUI app surface (L2); a single
linker script + crate template (L3) that makes a new service a copy-and-fill exercise; and an
endpoint-registry source that removes the cross-crate-`const` deconfliction problem at its root by
feeding ADR-018's manifest.

**Verification posture:** L0-L3 are **userspace and outside the kernel verification target** — the
same stance [ADR-018 § Verification Stance](018-init-process-and-boot-manifest.md) takes for `init`
("user-space and is not in the kernel verification target"). Correctness is enforced by review + host
tests, not Kani. The framework crates commit to the established `libgui` host-test bar (libgui ships
26 tests, libgui-proto 13, libinput-proto 8): thorough host tests for `Message` parsing, `ServiceError`
round-trips, and the `Handler`/`ServiceLoop` dispatch loop — mirroring ADR-018's "host-test the parser
thoroughly" precedent.

**Costs / risks:**
- *Speculative design* is the dominant risk: building L2/L3 before a real app needs them is the
  "second consumer" trap. Mitigation: MVP gated on the `policy-service` rewrite + the `init` measurement;
  L2/L3 do not start until a real consumer exists.
- *Verification:* `ServiceLoop<Handler>` must stay monomorphized (no `Box<dyn>`); the derive macro must
  stay `no_std`/no-serde or it drags `std` into the userspace TCB.
- *No kernel-regression risk:* this ADR touches no kernel ABI in any layer.

**Forecloses:** nothing in the kernel. The L0-L2 MPL choice shapes downstream app licensing; L3 is
permissive so it does not.

## Alternatives considered

- **One feature-gated meta-crate (`libos`)** instead of four crates. Rejected: separate crates keep
  verification/test targets small and match the existing per-crate pattern.
- **L3 as a manifest/package format (the original draft).** Rejected on review: the signed manifest,
  its format, signing, and kernel enforcement are entirely [ADR-018](018-init-process-and-boot-manifest.md)'s;
  duplicating them here would create two ADRs claiming one mechanism. L3 narrowed to authoring ergonomics.
- **A Phase-2 endpoint registry as an independent deconfliction authority.** Rejected: ADR-018's kernel
  reservation table is the single runtime authority (one-shot, no re-read). The registry is strictly a
  build-time *source* that generates the manifest — unidirectional.
- **`Box<dyn Handler>` dispatch** for ergonomics. Rejected: violates no-trait-objects-in-hot-paths;
  monomorphized `ServiceLoop<H>` gives the same ergonomics statically.
- **Keep hand-rolling per service.** Rejected: the measured duplication is the tax that makes "build
  more in userspace" slow.
