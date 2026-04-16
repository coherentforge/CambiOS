# ADR-011: Graphics Architecture and Scaling Assumptions

- **Status:** Proposed
- **Date:** 2026-04-13
- **Depends on:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC Bulk Path — Channels), [ADR-007](007-capability-revocation-and-telemetry.md) (Revocation + Telemetry), [ADR-009](009-purpose-tiers-scope.md) (Deployment Tiers)
- **Related:** [CambiOS.md](../CambiOS.md) § "Graphics and windowing runs in user-space", [PHILOSOPHY.md](../PHILOSOPHY.md)
- **Supersedes:** N/A

## Problem

CambiOS had no graphics stack, and "no graphics stack" is a silent design decision until it isn't. Every numeric bound in the kernel was picked when the only foreseeable workloads were headless services: networking, file I/O, signed binary loading, the shell. The IPC channel primitive (ADR-005) was sized for "1080p framebuffer double-buffered" with "4K video" explicitly named as its replacement trigger. The frame allocator was sized for 2 GiB of RAM with a comment flagging bare-metal Dell 3630 (16 GiB) as a production blocker. The per-process heap was 1 MiB with udp-stack already noted as "feeling it." Per-process VMA slots were 64, noted as "5+ channels is on the edge." None of these bounds were wrong for the time they were set — they were correct for what we were building. But they were all set against a workload profile that the user has since clarified.

The target CambiOS must support is:

- **Multi-monitor:** 3+ external displays (MacBook-class workstation topology).
- **4K and up:** 3840×2160 minimum physical resolution per display, with headroom for 5K/8K panels.
- **120Hz refresh:** ≤8.3 ms frame budget, not the ≤16.7 ms budget a 60Hz design tolerates.
- **HDR and HiDPI (Retina-style backing-scale):** apps draw in *points*; system backs per-window surfaces at `logical × backing_scale` pixels (typically 2×). A "4K Retina" display at 2× backing scale = 8K backing store = 256 MiB at 64bpp HDR *per window surface*.
- **3D rendering:** explicit goal. Not gaming-focused, but CAD / simulation / scientific visualization workloads with real vertex buffers, textures, depth/stencil buffers, and render targets. A modest 3D app holds hundreds of MiB of graphics state.
- **Damage-tracked partial redraws:** hybrid compositor model. Per-output dirty regions, per-window damage rects, back-buffer-as-mirror pattern. Without this the per-frame compositor bandwidth for 3×4K@120Hz HDR is ~93 GB/s (infeasible); with it, typical-desktop working bandwidth is ~5 GB/s (comfortable).

The problem this ADR addresses is not "implement a graphics stack." Graphics implementation is out of scope for the v1 roadmap and will land in a future phase. The problem is: **several numeric bounds that current kernel decisions reference are wrong for the v1 endgame workload, and the cost of widening them *ahead of need* is low, while the cost of widening them *during* graphics bring-up is high** (every intermediate phase relies on them, retroactive compatibility flags proliferate, reviewers at the graphics-implementation stage have to re-litigate decisions that could have been resolved calmly in advance).

This ADR does two things: it documents the target graphics architecture so future maintainers know what the bounds are sized *for*, and it records which bounds were widened in the Phase GUI-0 prep pass.

## Design Target

### The graphics stack (userspace, layered over kernel primitives)

```
┌──────────────────────────────────────────────────────────────────┐
│ GUI application process (one per app)                            │
│  • libgui (widgets, text, layout)                                │
│  • libgfx (2D/3D rendering: software rasterizer → GPU backend)   │
│  • Surface pixels in a shared-memory channel with compositor     │
└──────────────────────────────────────────────────────────────────┘
                              ↕ channel (surface) + control IPC (window mgmt)
┌──────────────────────────────────────────────────────────────────┐
│ compositor (user/compositor) — owns per-output scanout           │
│  • Z-order, focus, damage tracking, input routing, HiDPI scaling │
│  • Pre-GPU: maps framebuffer directly (transitional)             │
│  • Post-GPU: writes into scanout channel owned by gpu-driver     │
└──────────────────────────────────────────────────────────────────┘
              ↕ channel (scanout)            ↕ channel/IPC (input)
┌──────────────────────────────────────┐  ┌────────────────────────┐
│ gpu-driver (virtio-gpu, then Intel)   │  │ input-drivers           │
│  • Maps GPU MMIO + IRQs               │  │  ps2-kbd (IRQ 1)        │
│  • Command submission, scanout        │  │  ps2-mouse (IRQ 12)     │
│  • Validates client commands          │  │  usb-hid (post-v1)      │
└──────────────────────────────────────┘  └────────────────────────┘
              ↕ MapMmio / AllocDma / WaitIrq           ↕ WaitIrq / PortIo
┌──────────────────────────────────────────────────────────────────┐
│ KERNEL — thin primitives only                                    │
│  • Channels (ADR-005), MapMmio, AllocDma, WaitIrq, capabilities  │
│  • No driver-specific code, no display logic                     │
└──────────────────────────────────────────────────────────────────┘
```

This matches the pattern already set by `user/virtio-net`, `user/fs-service`, `user/udp-stack`: hardware drivers and service logic live in userspace, the kernel provides generic primitives and capability enforcement. Graphics is not special — it is another service stack over the same substrate.

### Division of labor

| Component | Where | Responsibility |
|---|---|---|
| kernel | `src/` | Channel allocation, MMIO mapping, DMA allocation, IRQ waiting, capability enforcement. No graphics-specific code. |
| ps2-kbd / ps2-mouse | `user/ps2-*` (future) | Claim legacy IRQ, read PS/2 controller, emit key/mouse events via control IPC. Capability-gated legacy port access. |
| usb-hid | `user/usb-hid` (post-v1) | USB keyboard/mouse/tablet/pen. Replaces PS/2 once USB stack exists. |
| gpu-driver | `user/virtio-gpu`, later `user/intel-gpu` (post-v1) | Map GPU MMIO, manage GPU memory, submit command buffers, handle completion IRQs, own the scanout buffer. Per-driver per-GPU. |
| compositor | `user/compositor` (future) | Per-output scanout, Z-order, focus, input routing, HiDPI backing-scale, damage tracking. Initially owns framebuffer directly; post-GPU-driver delegates scanout via channel. |
| libgfx | `user/libgfx` (future, in-process library) | 2D and 3D rendering API. Software rasterizer first; GPU backend follows. App-facing API deferred (Vulkan-subset leaning, but see Open Questions). |
| libgui | `user/libgui` (future, in-process library) | Widget toolkit, layout, text rendering (bitmap fonts initially, TrueType post-v1). |

### Why user-space GPU driver

- Consistent with every other hardware driver CambiOS has already shipped (virtio-net, i219-net, fs-service backing). The kernel has no drivers; graphics does not break that.
- A GPU crash (bad command buffer, hang, firmware failure) should not kill the kernel. Isolated in a process, the gpu-driver can be restarted while the rest of the system keeps running.
- Enables AI-monitored driver behavior per the CambiOS vision (drivers are processes under the same observation and capability model as any other service, per ADR-007).
- GPU driver only needs existing primitives, scaled up: `MapMmio` (registers), `AllocDma` (command buffers, GPU-visible memory), `WaitIrq` (completion IRQs), channels (scanout, surfaces).

### Why compositor owns framebuffer initially (transitional)

Pre-GPU-driver, the Limine-provided linear framebuffer is the only display path. The compositor maps it directly (via a future `SYS_MAP_FRAMEBUFFER` syscall, capability-gated). Post-GPU-driver, the gpu-driver takes ownership and exposes a per-display scanout channel to the compositor — compositor writes composed frames into the scanout channel; gpu-driver programs the GPU to display them. The transitional syscall is retained for early bring-up and firmware/headless fallback.

This means some architectural churn when GPU driver lands. Acceptable because (a) the scanout-channel protocol is better designed when the gpu-driver is being written than speculated at now, and (b) the transitional state is itself useful during QEMU `-vga std` bring-up and any future firmware-only display path.

### Multi-monitor

Compositor state: `outputs: Vec<Output>` where each `Output` has `scanout_front: ChannelId`, `scanout_back: ChannelId`, `physical_resolution: (u32, u32)`, `backing_scale: f32`, `refresh_hz: u32`, `dirty_region: Region`. Windows can span outputs; composition happens per output with correct backing-scale and dirty-rect handling. Pre-GPU bring-up: if Limine reports multiple framebuffers, the compositor maps each with its own `SYS_MAP_FRAMEBUFFER` call (indexed). If only one display is active (QEMU default), multi-output code degenerates cleanly.

### HiDPI / Retina-style backing scale

Apps draw in points; libgfx abstracts backing scale. Each window has a backing store at `logical_size × backing_scale` pixels. Compositor scales during composition using libgfx. Kernel has no HiDPI concept — it just provides channels big enough to hold backing stores (hence the `MAX_CHANNEL_PAGES = 256 MiB` ceiling).

### Damage tracking

Clients send `FrameReady { damage: [Rect; N] }` (N ≤ 16; fallback to "full surface dirty" above that). Compositor maintains per-output dirty region (union of window damages touching each output). Per frame: re-composite only the dirty region into a persistent per-output back buffer (mirror of scanout), then copy only the dirty region into scanout. Scanout itself remains full-frame (hardware display engines scan the whole panel every refresh); what the damage tracking optimizes is *generation* cost, not scanout cost. Kernel role: none, beyond providing the per-output back-buffer memory budget.

## Decision

### Numeric bounds raised in Phase GUI-0 (this ADR's immediate action)

Eight SCAFFOLDING bounds are widened now, ahead of graphics implementation. All rationale is captured in [ASSUMPTIONS.md](../ASSUMPTIONS.md) rows for each; this table summarizes:

| Bound | Old | New | Rationale (full detail in ASSUMPTIONS.md) |
|---|---|---|---|
| `MAX_CHANNEL_PAGES` | 4096 (16 MiB) | 65536 (256 MiB) | A 4K Retina backing store at 64bpp HDR is 256 MiB per window surface. Multi-monitor uses multiple channels; single-channel ceiling accommodates one full-screen surface. |
| `MAX_CHANNELS` | 64 | 256 | Multi-monitor compositor estimate: 6 scanout + 30 window surfaces + 10 GPU channels + non-GUI services ≈ 60 active. 4× headroom per CLAUDE.md Convention 8. |
| `MAX_VMAS` (per process) | 64 | 256 | Compositor estimate: 50 VMA slots (3 framebuffers + 6 scanout channels + 30 window surfaces + GPU mappings + heap + stack). 4× headroom. |
| `MapMmio` per-call | 256 (1 MiB) | 16384 (64 MiB) | Single-display 4K framebuffer = 8192 pages (32 MiB); HDR doubles that. Multi-monitor uses multiple calls. |
| `AllocDma` per-call | 64 (256 KiB) | 32768 (128 MiB) | GPU command buffers and GPU-visible memory need physical contiguity well above virtio-net's envelope. GiB-class texture regions remain a future bump. |
| `SYS_ALLOCATE` per-call | 1 MiB | 64 MiB | Large general-purpose allocations (texture staging, software-renderer back buffers, font atlases). |
| `HEAP_SIZE` (per process) | 1 MiB | 4 MiB | udp-stack was already documented as feeling 1 MiB; GUI clients need widget trees, font atlases, software-rendered backing stores. 4 MiB is a modest bump across all boot modules. |
| `MAX_FRAMES` (frame allocator) | 524288 (2 GiB) | 4194304 (16 GiB) | Resolves pre-existing bare-metal blocker (Dell 3630 has 16 GiB RAM). Also gives graphics headroom for multi-GiB GPU textures and backing stores. Bitmap grows 64 KiB → 512 KiB in `.bss`. |

Plus two new ceiling tests (`test_create_at_max_pages_succeeds`, `test_allocate_contiguous_heap_sized_run`) so regressions fail fast.

No new syscalls, new capabilities, or new code paths are landed in this pass. The graphics stack itself is deferred.

### Deferred to later phases (documented here, not built in Phase GUI-0)

Captured for future-maintainer visibility:

- **New syscalls:** `SYS_MAP_FRAMEBUFFER` (#35), `SYS_SLEEP` (#36).
- **New capabilities:** `LegacyPortIo` (PS/2 port access whitelist), `MapFramebuffer` (compositor/gpu-driver only), `LargeChannel` (tier-gated large-channel allocations).
- **Limine pixel-format exposure:** kernel currently logs only `width × height @ addr` ([src/microkernel/main.rs:273](../../src/microkernel/main.rs#L273)); needs to also capture `bpp`, `pitch`, pixel format masks, and iterate the full framebuffer list (currently calls `.next()` once — single-display assumption).
- **libsys `wait_irq` wrapper:** kernel implements `SYS_WAIT_IRQ = 5` but there is no userspace wrapper.
- **`BlockReason::TimerWait` wire-up:** variant exists in [src/scheduler/task.rs:280](../../src/scheduler/task.rs#L280) but is currently dead code; `SYS_SLEEP` will use it.
- **Default tick rate bump (HZ_100 → HZ_1000):** 100 Hz is inadequate for 120Hz frame pacing. HZ_1000 is already defined in [src/scheduler/timer.rs](../../src/scheduler/timer.rs); flipping it touches every timing-sensitive subsystem (network timeouts, audit drain cadence, scheduler quanta). Deferred to a measurement pass during graphics bring-up.

### Phased implementation (future work)

Captured here to prevent the full plan file ([sorted-dazzling-widget.md](../../../../.claude/plans/sorted-dazzling-widget.md)) from being the only record:

1. **GUI-1 — First pixels.** Boot module maps framebuffer via `SYS_MAP_FRAMEBUFFER`, draws a gradient + embedded bitmap-font text. Validates kernel → framebuffer path end-to-end.
2. **GUI-2 — Input.** `user/ps2-kbd` and `user/ps2-mouse` with legacy-port-whitelist syscall capability. Demo evolves to keyboard echo + cursor sprite.
3. **GUI-3 — Compositor separation.** `user/compositor` takes framebuffer ownership. `user/libgui` with surface-channel protocol. First GUI client: hello-window with a button.
4. **GUI-4 — 2D polish + software 3D.** Per-rect damage tracking, software rasterizer, TrueType fonts.
5. **GUI-5 — GPU driver.** virtio-gpu first (QEMU, well-documented, simple ring-buffer protocol, no firmware), Intel UHD on Dell 3630 follows once virtio-gpu proves the gpu-driver/compositor/libgfx protocol.
6. **GUI-6 — Advanced (post-v1).** Vulkan-subset API, HDR, variable refresh, hardware-accelerated compositing, Wayland-style client protocol if interop matters.

## Rationale

### Why widen bounds now rather than during graphics bring-up

Each of the eight bounds is referenced from code that is *currently* under active development (channels, process lifecycle, per-CPU scheduler, syscall dispatcher). Several subsystems are within one or two refactors of needing to re-examine their sizing: the process table (ADR-008) just moved to boot-time-sized slots, and the reviewers of that change would have been in the best position to judge whether 256 or 64 VMAs is the right endgame number — but they were reviewing "current-workload-plus-growth," not "4K multi-monitor HDR 3D endgame." That framing has now been corrected; the bounds should move to match, while the people who set them in the first place remember why.

Widening now also avoids the trap of *silently exceeding* a scaffolding bound during intermediate work. If a Phase 3.4 service is the first to legitimately hold six simultaneous channels, it will fail at runtime when the seventh channel attach trips the old `MAX_CHANNELS = 64` — not a verifier's concern, but very much a "2 AM Dell bring-up" concern.

### Why not go further (e.g., 8K Retina, GiB-class AllocDma)

Two constraints bound the numbers:

1. **Convention 8 says "4× headroom over the v1 endgame estimate."** Going beyond that gambles memory budget on workloads that may never materialize. A 512 MiB `MAX_CHANNEL_PAGES` ceiling saves one future bump but costs real memory budget on tier-1 embedded deployments. The right answer for "sometimes we want bigger" is the deferred `LargeChannel` capability gated by tier policy, not a blanket ceiling that applies everywhere.

2. **Some bounds interact with algorithm complexity.** `AllocDma` above ~128 MiB starts to press on `allocate_contiguous`'s linear bitmap scan cost; the right fix is a smarter contiguity allocator, not a larger linear-scan ceiling. Similarly, `MAX_FRAMES` above 16 GiB should switch to a tiered/sparse bitmap structure. Both are out of scope for a bounds-only prep pass.

### Why compositor + libgfx abstract HiDPI rather than pushing it into the kernel

HiDPI is a presentation decision: "this window is 1024pt × 768pt; draw it at 2× backing store for this display." The kernel has no opinion on points vs pixels — it allocates bytes, maps regions, enforces capabilities. Pushing backing-scale awareness into the kernel would couple a display-layer concern to the kernel ABI (future DPI changes require kernel changes), violate the zero-trust pattern (the kernel doesn't need to know about points), and complicate verification (per-display scale factors become kernel state).

Compositor-side HiDPI is how every modern OS handles this (macOS, Windows, Wayland). CambiOS follows the same pattern: kernel allocates, compositor+libgfx present.

## Open Questions

### App-facing 3D API (OpenGL subset vs. Vulkan subset vs. CambiOS-native)

libgfx will expose some 3D API to applications. The choice is deferred until libgfx work begins because it does not affect any earlier phase — the wire protocol between libgfx and gpu-driver (likely modeled on virtio-gpu's command set initially) is the load-bearing decision; the app-facing API is a presentation layer that can be added later and even offered in multiple variants over the same wire protocol.

Recommendation lean: **Vulkan-subset**, because its explicitness (apps manage memory, submit command buffers, no hidden state) aligns with CambiOS's capability-explicit verification stance. Every Vulkan primitive maps cleanly: "device memory allocation" = `AllocDma`-backed channel; "command buffer" = a write into a command channel; "queue" = a capability granted by gpu-driver; "queue submit" = control IPC signal. But this is not settled; OpenGL-subset has the advantage of familiarity and broader reference implementations.

### Framebuffer ownership transition protocol

When gpu-driver lands (Phase GUI-5), ownership of the scanout buffer moves from compositor to gpu-driver. Two designs are viable: (a) sharp handoff — compositor releases `SYS_MAP_FRAMEBUFFER` mapping, gpu-driver claims it, compositor attaches to a new scanout channel; (b) gradual — compositor continues to work against a channel throughout, and the pre-GPU "direct framebuffer mapping" is implemented as a kernel-provided single-consumer channel that gpu-driver can later replace. Design (b) avoids code churn at the handoff but adds a kernel primitive in Phase GUI-1 that doesn't yet pay off. Recommendation: design (a), handle the churn once, at the point we're writing the gpu-driver and best understand what the scanout channel should look like.

### Tick rate measurement

Before flipping HZ_100 → HZ_1000, a measurement pass should quantify: overhead of 10× more timer interrupts across SMP, audit drain cadence stability, network-stack timeout behavior, scheduler quantum effects. The change is small (one constant), but its blast radius is every time-sensitive subsystem. Owner and trigger TBD during Phase GUI-3 (compositor separation, when 120Hz frame pacing first becomes observable).

## Divergence

### 2026-04-14 — Bootloader abstraction landed ahead of graphics work

A new concern surfaced after this ADR was drafted: the dependency on Limine
(a single-maintainer hobby/research bootloader) is acceptable for v1 but not
for the long-term "CambiOS distribution" horizon. Jason's planned response
is a CambiOS-native firmware/bootloader called **camBIOS** that replaces the
UEFI + Limine stack and addresses OEM boot quirks across architectures.

To avoid a kernel-wide refactor when camBIOS lands, a `BootInfo` abstraction
was added *before* the first graphics-phase consumer (`SYS_MAP_FRAMEBUFFER`)
was wired. Location: `src/boot/mod.rs` + `src/boot/limine.rs`. The kernel
now reads a kernel-owned `BootInfo` struct (memory map, framebuffer list
with full pixel format, RSDP, modules, HHDM offset) populated once at boot
by the active adapter. No `limine::*` types leak past the adapter.

Scope decisions:

- **In scope now:** pure-data boot information (memory map, framebuffers,
  RSDP, modules, HHDM offset). All consumers refactored.
- **Deferred to camBIOS time:** Limine's MP active-wake mechanism
  (`goto_address` semantics) is not abstracted. `ap_entry` still uses
  `limine::mp::Cpu` directly. Rationale: MP is a mechanism not pure data,
  and the right abstraction is easier to design when camBIOS exists.
- **Also deferred:** the one early `HHDM_REQUEST.get_response()` call in
  `kmain` (needed before serial is up on AArch64, which is needed before
  `println!` in `populate`). Single-line chicken-and-egg; not worth
  contorting the init order.

### 2026-04-14 — Phase GUI-0 chunk 1 landed (capabilities + SYS_MAP_FRAMEBUFFER + libsys wrappers)

Three of the five "deferred to later phases" items from the original
Decision section landed in the same commit as the bootloader abstraction,
while the other two remain deferred:

- **Landed:** `CapabilityKind::{LegacyPortIo, MapFramebuffer, LargeChannel}`
  (with grant/check/revoke + revoke-on-exit wiring); `SYS_MAP_FRAMEBUFFER`
  (#35) handler capability-gated on `MapFramebuffer`; `libsys::wait_irq`
  and `libsys::map_framebuffer` wrappers; Limine pixel-format + multi-
  display enumeration (captured into `BootInfo::framebuffers` with full
  bpp/pitch/mask fields).
- **Still deferred:** PS/2 legacy ISA port whitelist in `handle_port_io`
  (pending input-driver phase); `SYS_SLEEP` + `BlockReason::TimerWait`
  wire-up (scheduler ISR touch — should coincide with tick-rate review);
  default tick-rate bump HZ_100 → HZ_1000 (needs measurement pass).

All three new `CapabilityKind` variants are currently granted to nobody.
The first grant sites land with their respective consumers (compositor
boot module, ps2-kbd/ps2-mouse boot modules, tier-aware policy).
