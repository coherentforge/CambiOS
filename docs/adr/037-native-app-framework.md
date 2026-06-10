# ADR-037: Native App Framework: runtime, IPC stdlib, toolkit, package layering

- **Status:** Proposed
- **Date:** 2026-06-10
- **Depends on:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives the stdlib wraps), [ADR-024](024-syscall-abi-crate.md) (`cambios-abi`)
- **Related:** [ADR-018](018-init-process-and-boot-manifest.md) (boot manifest — owns the L3 package layer), [ADR-004](004-cryptographic-integrity.md) (ARCSIG signing), [ADR-011](011-graphics-architecture-and-scaling.md) + [ADR-014](014-compositor-scanout-driver-protocol.md) (compositor/GUI the toolkit renders through), [ADR-012](012-input-architecture-and-device-classes.md) (input the event loop pumps), [ADR-006](006-policy-service.md) (policy-service — the first consumer), [ADR-008](008-boot-time-sized-object-tables.md) (tier sizing)
- **Supersedes:** N/A (extends `user/libsys` + `user/libgui`; replaces neither)

## Context

CambiOS has 23 userspace services / ~12,000 lines of Rust that repeat nearly-identical
boilerplate in ~10 areas, because `libsys` (raw + safe syscall wrappers) and `libgui`
(v0 drawing primitives, no widgets) are minimal *substrates*, not a *framework*. Measured
across the tree:

- entry-point ritual (`#![no_std]`/`#![no_main]`/`_start` → `register_endpoint` → `module_ready`): **23/23 services**
- identical panic handlers: **23/23**
- recv/dispatch/yield main loops: **22/22**
- hand-rolled message marshalling (`from_le_bytes`/manual slicing): **333 sites**
- independently-invented `u8` status-code sets: **11 services**
- duplicated per-service `link.ld` linker scripts: **24**

The goal (the prioritized v1 direction): a substrate that lets us *build a lot more in
userspace* once it is real. That needs a stdlib, not more bespoke services. The conservative
estimate is a 10-15x reduction in per-service ceremony (a new service drops from ~500 lines
of boilerplate to a `Handler` impl plus an entry macro).

This is squarely the "push cycles out of the kernel ring" principle: the framework lives
entirely in userspace and (for the runtime/stdlib/toolkit tiers) introduces **zero new
kernel syscalls** — it is pure assembly of primitives `libsys` already exposes.

## Decision

A **layered framework that extends `libsys`/`libgui`** (it does not replace them). Four layers:

- **L0 — `libsys-rt` (runtime / crt0).** The startup ritual every service hand-rolls,
  collapsed into one place: a `#[service_main]` entry macro that emits `_start`, a default
  `#[panic_handler]` (log to serial + `sys::exit(1)`), and a feature-gated default
  `#[global_allocator]` (the proven `LockedHeap`-over-static-BSS pattern, opt-in for `alloc`
  consumers). No new syscalls — assembles `register_endpoint` / `module_ready` / `exit`.
- **L1 — `libipc` (IPC stdlib).** Turns the 333 marshalling sites into a typed surface: a
  `Message` wrapper (parses the 36-byte header once: `sender_principal` + `from_endpoint` +
  payload), a shared `ServiceError` + `Result` alias (replacing the 11 reinvented status sets),
  and a generic, **monomorphized** `ServiceLoop<H: Handler>` owning recv→dispatch→reply→yield.
  No `Box<dyn>` (honors the no-trait-objects-in-hot-paths rule). A `no_std`/no-serde
  `Encode`/`Decode` derive is **deferred** to the second real request/response struct.
- **L2 — `libui` (GUI toolkit).** The widget/layout/event tier `libgui` v0 deferred: an event
  loop wired to compositor input (`MsgTag::InputEvent`), a minimal widget set (Label, Button,
  container) over a Box/Flex layout pass, focus/z-order, decoration drawing — all rendering
  through the existing `Surface` API (CPU writes into the attached surface channel). No new syscalls.
- **L3 — `cambios-pkg` (package / manifest).** A signed, declarative module unit (principal,
  reserved endpoints, granted capabilities, deps) + build tooling + one canonical `link.ld`
  template replacing the 24 duplicates. **This layer is ADR-018's territory** (the boot
  manifest + init/PID-1 + endpoint reservation table); see Open Decisions.

### MVP substrate (build this first)

**L0 + the L1 core trio: `Message` + `ServiceError`/`Result` + `ServiceLoop<Handler>`.**
This is the smallest slice that unlocks broad userspace building because it attacks the
boilerplate *every* service pays (entry, panic, recv-loop, header parsing, status codes). It
adds **zero kernel syscalls and zero ABI changes** — verification-neutral, cannot regress the
kernel. Defer the `Encode`/`Decode` derive, the shared endpoint registry, and L2/L3 until the
MVP has a real consumer proving the `Handler` shape (the "second consumer in scope" discriminator).

### First consumer (prove before greenfield)

Rewrite **`policy-service`** onto the MVP first ([ADR-006](006-policy-service.md)). It is the
canonical `recv_verified` → parse fixed query → dispatch → reply → yield server, it is
security-load-bearing (so getting `ServiceError`/`Result` right there matters), and it has no
driver MMIO/DMA to muddy the `Handler` abstraction. Only after an existing service validates
L0+L1 do we drive the toolkit (L2) with a real GUI consumer (the webmin/drainer portal is the
candidate) — toolkit shaped by a real app, not designed speculatively.

### Phasing

0. **MVP:** `libsys-rt` + `libipc` core (`Message`, `ServiceError`/`Result`, `ServiceLoop`). No
   derive macro, no kernel changes. Prove by rewriting `policy-service`.
1. Rewrite a second + third service (one driver-shaped, one pure-server) to validate the
   `Handler` trait covers blocking, multi-endpoint (`try_recv_msg`), and reply patterns. Extract
   the `Encode`/`Decode` derive only when a real struct demands it.
2. Shared endpoint + command-constant registry (build-time deconfliction) + structured logging.
   **Design it to converge with ADR-018's reservation table, not to be torn down by it** (sawtooth).
3. `libui`: event loop, Label/Button/container, Box/Flex layout, focus/z-order, decorations.
   Driven by the first GUI consumer.
4. `cambios-pkg` / ADR-018 manifest: signed manifest, build tool, canonical `link.ld`, init/PID-1,
   kernel endpoint-reservation table. Last, and the only kernel/boot-path-touching slice — so the
   userspace shape is settled before the kernel enforcement contract freezes.

## Open Decisions (require sign-off before this moves to Accepted)

1. **Framework license — MPL-2.0 vs AGPL-3.0-or-later.** `user/libsys` is already MPL-2.0
   (everything else AGPL). The framework crates are the same linkable ABI/stdlib surface, so by
   precedent they would be **MPL-2.0** — file-level copyleft (edits to framework files stay open)
   that lets an app *link* the framework without itself becoming MPL. AGPL on the framework would
   instead force every linking app to be AGPL. This is a values call: *apps free to choose their
   license (MPL, matching libsys)* vs *AGPL-all-the-way for everything on CambiOS*. **Default in
   this draft: MPL-2.0 for `libsys-rt`/`libipc`/`libui`, by libsys precedent — override to AGPL if
   the intent is whole-userspace copyleft.** This sets the SPDX header on every new framework file.
2. **ADR scope — L0-L2 here, hand L3 to ADR-018; vs one ADR for all four.** Recommended: this ADR
   owns L0-L2 (runtime/stdlib/toolkit) + the L2-Phase-2 endpoint-registry-as-compile-time-mirror,
   and **ADR-018 owns L3** (the signed manifest + init + reservation table), since it already does.
   Avoids two ADRs claiming the manifest.
3. **Default allocator policy.** Feature-gated `LockedHeap` over a const-sized static BSS arena
   (the `terminal-window` pattern): confirm the arena-size convention and whether non-`alloc`
   services opt **out** or `alloc` services opt **in**.

## Consequences

**Enables:** new services as a `Handler` impl + entry macro (10-15x less ceremony); a real GUI
app surface (L2) that the webmin portal and future apps consume; a signed package format (L3) that
becomes the static authority graph an offline check / the init process validates before boot — the
"AI watches/flags" anchor.

**Costs / risks:**
- *Speculative design* is the dominant risk: building L2/L3 before a real app needs them is the
  "second consumer" trap. Mitigation: the MVP is gated on a concrete `policy-service` rewrite, and
  L2/L3 do not start until L0+L1 are proven on a real service.
- *Sawtooth:* the Phase-2 endpoint registry must be designed to converge with ADR-018's reservation
  table, or it becomes scaffolding torn down when ADR-018 lands.
- *Verification:* `ServiceLoop<Handler>` must stay monomorphized (no `Box<dyn>`); the derive macro
  must stay `no_std`/no-serde or it drags `std` into the userspace TCB.
- *Kernel-regression risk is low until Phase 4* — L0-L2 touch no kernel ABI; the manifest/init slice
  is correctly sequenced last.

**Forecloses:** nothing in the kernel (L0-L2 are pure userspace). The license choice (Open Decision 1)
does shape what licenses downstream apps may carry.

## Alternatives considered

- **One feature-gated meta-crate (`libos`)** instead of four crates. Rejected (draft default):
  separate crates keep verification targets small and match the existing per-crate pattern; revisit
  if cross-crate churn becomes painful.
- **Keep hand-rolling per service.** Rejected: the measured 10-15x duplication is exactly the tax
  that makes "build more in userspace" slow; the framework is the accelerant.
- **`Box<dyn Handler>` dispatch** for ergonomics. Rejected: violates no-trait-objects-in-hot-paths;
  monomorphized `ServiceLoop<H>` gives the same ergonomics statically.
