# ADR-036: Typed MMIO Register Blocks for Device Drivers

- **Status:** Accepted
- **Date:** 2026-06-07
- **Depends on:** N/A
- **Related:** [ADR-013](013-riscv64-architecture-support.md) (riscv64 backend - PLIC is a migration target; per-arch driver parity), [ADR-021](021-typed-boot-error-propagation.md) (typed-not-stringly boot surface - same "encode the invariant" instinct)
- **Supersedes:** N/A (subsumes the dormant `src/arch/mmio.rs::MmioRegion` for *structured* device drivers; MmioRegion is retained as the untyped escape hatch - see Decision §6)

## Scope Boundary (read this first)

This ADR is about how the **structured MMIO device drivers** address their hardware registers. It converts register access from hand-rolled `unsafe fn` accessors over a `base + offset` into `#[repr(C)]` typed register blocks whose field layout *is* the asserted hardware register map.

| Concern | Owner |
|---|---|
| Register access for aarch64 GIC (distributor + per-CPU redistributor), riscv64 PLIC, x86_64 APIC | **This ADR (typed register blocks)** |
| The one-time "this base is a mapped MMIO region" obligation | **This ADR (construction-site `unsafe`)** + the boot mapping path (HHDM / `early_map_mmio`) |
| Non-MMIO `unsafe`: CSR/system-register asm, per-CPU init, syscall GPR reads, satp/TTBR0/CR3 switches, page-table fills | **Per-op `unsafe` discipline** (the clippy `#![deny]` sweep) - *not register access, untouched here* |
| Ad-hoc / one-shot MMIO probes (e.g. virtio-mmio discovery) | **`MmioRegion`** (untyped escape hatch, retained) |
| *Whether* a device is present / *which* base to map | Device discovery (DTB / ACPI / PCI enumeration) - unchanged |

If a piece of `unsafe` is not a device register access, this ADR does not touch it.

## Context

The MMIO device drivers each hand-roll private `unsafe fn` accessors over a stored base:

- aarch64 `src/arch/aarch64/gic.rs`: `gicd_read/write`, `gicr_read/write` (4 accessors, ~18 call sites).
- riscv64 `src/arch/riscv64/plic.rs`: `read32/write32` (2 accessors, ~13 call sites).
- x86_64 `src/arch/x86_64/apic.rs`: `apic_read/write` (+ `read_apic_id`, `write_eoi`).

The per-op `unsafe` discipline sweep (clippy `multiple_unsafe_ops_per_block` + `undocumented_unsafe_blocks`, now `#![deny]` and tri-arch CI-gated) made every one of those accesses an explicit `unsafe {}` + `// SAFETY:` at the call site. That is *honest* - every hardware touch is visible - but it leaves ~31 caller-side `unsafe` blocks and restates the "device is mapped" invariant across many SAFETY comments, while encoding **none** of the real invariants in types:

1. The device is mapped before any register access.
2. Only a real register is addressable (the accessors take a free `usize`/`u32` offset).
3. The access class is honored (nothing stops a read of a write-only register, or vice-versa).
4. Register values are typed (writes are magic-number `u32`s, not named fields).

The project's Formal Verification constraints (CLAUDE.md) call for exactly the opposite: *"Invariants encoded in types, not comments"* and *"unsafe minimized and isolated ... wrapped behind a safe abstraction boundary that can be audited"* - the boundary this ADR's cell primitive is built to become the verification target of.

Two pieces of the substrate already exist:

- `src/arch/mmio.rs::MmioRegion` encodes the **mapped** invariant (`unsafe` only at `new(base)`; `read32`/`write32` are safe). It is **dormant** - defined, exported via `pub mod mmio`, and used by no driver - and it is **offset-untyped** (register identity, access class, and value type are not encoded).
- `bitflags = "2.3"` is already a dependency, so register *value* types come at no new cost.

## Problem

Encode invariants (1)-(4) in types so the compiler enforces them, collapse the `unsafe` surface to one small auditable core plus one construction site per device, and do so **without silently dropping the spec-conformance obligation** - a wrong register offset must not become an invisible runtime MMIO corruption.

## Decision

### 1. `#[repr(C)]` register-block structs are the typed surface

Each device's register map is a `#[repr(C)]` struct whose field byte-offsets **are** the hardware register offsets. Access is always through a named typed field, never a computed offset. A compile-time assertion ties each field to its spec offset:

```rust
#[repr(C)]
struct GicdRegs {
    ctlr:       ReadWrite<u32, Ctlr>,        // 0x0000
    typer:      ReadOnly<u32>,               // 0x0004
    _reserved0: [u8; 0x080 - 0x008],
    igroupr:    [ReadWrite<u32>; 32],        // 0x0080
    // ...
}
const _: () = assert!(core::mem::offset_of!(GicdRegs, typer) == 0x0004);
const _: () = assert!(core::mem::offset_of!(GicdRegs, igroupr) == 0x0080);
```

The layout *is* the asserted spec. A field placed at the wrong offset is a compile error the moment its `offset_of!` assert disagrees with the named spec offset. This is the load-bearing decision: it is what makes "invariants in types" real for MMIO rather than a comment. (`core::mem::offset_of!`, including the nested-field form needed for the PLIC/GICR sub-structs, is confirmed available on the pinned `nightly-2026-02-07` and is already used in-tree for the riscv64 `PerCpu` layout asserts.)

### 2. A minimal hand-rolled volatile-cell primitive (no new dependency)

`ReadOnly<T>`, `WriteOnly<T>`, `ReadWrite<T, F = T>` - `#[repr(transparent)]` wrappers over an `UnsafeCell<T>`. Each provides exactly its access-class methods (`ReadOnly` has no `write`; `WriteOnly` has no `read`). The single `unsafe` op in the whole abstraction is each cell's `read_volatile` / `write_volatile`; it is the audit/verification target and is ~40 lines total. Lives in `src/arch/mmio.rs` beside `MmioRegion`.

Two properties of the cell are **binding requirements**, not stylistic choices:

- **`UnsafeCell` backing is mandatory for soundness.** MMIO registers mutate asynchronously under hardware (pending bits set themselves; the GIC claim register changes when read). A plain `#[repr(C)] struct { ctlr: u32 }` read through a shared `&regs` is **undefined behaviour** - the compiler may assume data behind `&T` is immutable and hoist or elide the read. `UnsafeCell<T>` opts out of that assumption; paired with `read_volatile`/`write_volatile` it makes shared-`&` register access sound. The cell is the soundness boundary, not a convenience wrapper.
- **`#[inline(always)]` + `#[repr(transparent)]` make the abstraction zero-cost.** With both, `regs.ctlr.write(v)` compiles to the *identical* single volatile store as today's `write_volatile((base + offset) as *mut u32, v)` (the field offset is a compile-time constant, exactly like the named offset const). Without inlining it degrades to a function call per register access - which matters on the hot interrupt paths (APIC `write_eoi` on every timer tick + device IRQ, GIC acknowledge/EOI, PLIC claim/complete). Zero-cost is **verified by disassembly** on those paths, not assumed.

- **Rejected: the `tock-registers` crate.** Capable and idiomatic, but it adds an external `unsafe` surface to audit and a macro layer; a ~40-line hand-rolled primitive is fully auditable, dependency-free, and verifiable in-tree - which the verification posture favors over reuse here.

### 3. Construction is the single `unsafe` boundary per device

A driver obtains its block once: `let regs = unsafe { &*(base as *const GicdRegs) };`. That one `unsafe` discharges "`base` is a valid, mapped MMIO region of at least `size_of::<GicdRegs>()` with device caching attributes" - the same obligation `MmioRegion::new` carries today. The **public** driver API (`init_distributor`, `enable_spi`, `init`/`enable_irq`, ...) stays `unsafe fn`, carrying the "caller ensures the device was discovered and mapped" obligation up to the boot path. Everything between - the register accesses - becomes safe.

### 4. Register values are typed via `bitflags`

Control/status registers carry a `bitflags` value type, so a write is `regs.ctlr.write(Ctlr::ARE | Ctlr::GRP1NS)` rather than `(1 << 4) | (1 << 1)`. Wrong-field / wrong-width writes become type errors.

### 5. Layout wrinkles, modeled explicitly

- **GICR per-CPU frames.** The redistributor is two 64 KiB frames per CPU at `base + cpu_id * 0x20000`. Modeled as a `#[repr(C)] struct GicrFrame { ... }` reached by an explicit, asserted stride index (`&gicr_frames[cpu_id]` or a `gicr(cpu_id) -> &GicrFrame` accessor). The per-CPU stride stays one visible indexing operation, not a hidden offset.
- **Byte/array registers** (GICD `IPRIORITYR`, `ISENABLER`): `[ReadWrite<u8>; N]` / `[ReadWrite<u32>; N]` arrays at the asserted offset; indexing is bounds-checked safe code.
- **PLIC sparse map** (`priority[1024]`, per-context enable-bit words, per-context threshold/claim): nested `#[repr(C)]` with explicit reserved padding, `offset_of!`-asserted. PLIC is the largest layout; GIC is the template that proves the pattern before PLIC is attempted.

### 6. `MmioRegion`'s fate

`MmioRegion` is retained as the **untyped escape hatch** for genuinely ad-hoc or one-shot MMIO (e.g. the virtio-mmio probe sweep) where a full typed block is not warranted. The structured drivers (GIC, PLIC, APIC) migrate to typed blocks. The dormant primitive thereby becomes load-bearing for the escape-hatch case; typed cells are the primary path.

## Consequences

**Positive**
- `unsafe` collapses from ~31 caller-side blocks to: the cell primitive (one `unsafe` per access-class method, ~40 lines total) + one construction site per device. The verifier audits the cell primitive once and reasons about typed field accesses everywhere else.
- Access-class and value errors become **compile** errors (read a WO register → no method; write a wrong bitflags → type error).
- Offset-correctness is **machine-checked** at compile time via `offset_of!` asserts: the layout is the asserted spec.
- Array-indexed registers (GICD `IPRIORITYR[i]`, PLIC `priority[src]`) gain bounds checks they lack today (raw `base + offset + i`): a small init-time cost for a real safety gain.
- **Memory barriers stay explicit.** Any `dsb`/`isb`/fence adjacent to an MMIO access remains a separate asm at the call site; the cell performs the access, ordering stays the caller's concern - unchanged from today's structure.

**Negative / honest**
- The spec-conformance obligation **relocates, it does not vanish.** A wrong *asserted* offset const is still writable - but it is centralized to one assert per register and caught at compile time the instant the assert disagrees with the field's computed position. This is strictly better than a free offset at every call site, not a free lunch.
- The GICv3 and PLIC register maps are exacting to model (reserved gaps, per-CPU frames, sparse arrays). The `offset_of!` asserts make getting them right a compile-time check rather than a boot-time mystery, but writing them is real work.
- **Sawtooth, named.** This supersedes the *caller-side* per-op `unsafe` MMIO blocks added to `gic.rs`/`plic.rs`/`apic.rs` during the clippy sweep. Those blocks were not wasted - they delivered the tri-arch `#![deny]` gate, which stands - but their MMIO call sites are rewritten here. The non-MMIO per-op `unsafe` (asm/CSR, percpu, syscall GPR, satp/TTBR0, page-table fills) is untouched.

## Alternatives Considered

- **An offset-free representation - there isn't one.** MMIO is offset-addressed by hardware; the GICv3 / PLIC / APIC specs *define* each register by byte offset, so the offsets exist in physical reality and must appear somewhere in the code. The realistic options differ only in *where* the offset lives and whether it is checked: struct layout + `offset_of!` asserts (this ADR - machine-checked); a `register_structs!`-style macro (each offset written once, reserved gaps + asserts generated - rejected with `tock-registers` for the dependency/macro-surface reason, though a minimal in-tree macro stays available as an escape hatch should PLIC's hand-written gaps prove unwieldy); or handle consts (option (b) - offsets present but unchecked). The typed approach's value is therefore *not* eliminating offsets; it is writing each offset **once** and **machine-checking** it, against the status quo where offsets are scattered, unchecked, across every call site.
- **(b) Typed handles over `MmioRegion`** - each register a `const CTLR: Reg<Ctlr, RW>` bundling offset + access + value, accessed `gicd.ctlr().write(...)`. Lighter, builds directly on the existing primitive, no `repr(C)` layout work. Rejected: the offset stays a hand-written const inside the handle, *not* machine-checked against a layout - a weaker "invariants in types." For the verification north star the asserted-layout form (§1) is the truer target, and since it is the endgame it is built directly (no `MmioRegion`-handle intermediate to later tear down).
- **Promote accessors to plain safe fns** (offset stays a runtime value) - collapses the call-site `unsafe` but encodes neither register identity nor access class nor value type. The weakest option; rejected.
- **Status quo: per-op `unsafe` at every MMIO call** (the clippy-sweep state) - honest and gated, but does not reach "invariants in types." This ADR supersedes it for the structured drivers.

## Verification Target

The whole MMIO unsafe surface reduces to two checkable things: (i) the volatile-cell primitive's `read_volatile`/`write_volatile` (a ~40-line core, the same shape across all three arches), and (ii) the `offset_of!` layout assertions, which are discharged by the compiler. A future formal-verification pass proves the cell primitive once; the register blocks need only their layout asserts to hold, which they do by construction or fail to compile.

## Sequencing

This ADR ratifies the pattern. Implementation lands as focused, tri-arch-gated, adversarially-verified commits:

1. The volatile-cell primitive in `src/arch/mmio.rs` (+ unit tests for access-class shape).
2. **aarch64 GIC** as the template - the richest layout (distributor + per-CPU redistributor + byte arrays). Proves the pattern under this ADR.
3. **riscv64 PLIC** - the largest sparse layout.
4. **x86_64 APIC**.

Each migration commit is verified under **QEMU boot-smoke** - the kernel boots to a shell with interrupts working - in addition to build + clippy + host-tests. This is non-negotiable for this ADR specifically: GIC / PLIC / APIC are the interrupt controllers, where a transposed register or value is a **silent hang** (no panic, no output) - the one failure class host-tests cannot catch. The `offset_of!` asserts and adversarial review catch layout and value errors at compile and review time; boot-smoke is the runtime backstop.

Each step's adversarial review focuses on the `offset_of!` asserts (spec conformance) and the cell primitive's volatile correctness. On the GIC template landing, this ADR flips to **Accepted**.
