# ADR-014: Compositor ↔ Scanout-Driver Protocol

- **Status:** Proposed
- **Date:** 2026-04-15
- **Depends on:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC channels), [ADR-011](011-graphics-architecture-and-scaling.md) (Graphics architecture)
- **Related:** [ADR-012](012-input-architecture-and-device-classes.md) (input flow into compositor; same modularity pattern, different transport).
- **Supersedes:** N/A

## Problem

ADR-011 specifies the layered graphics stack — compositor in the middle, gpu-driver below, clients above — and names the seam between compositor and gpu-driver as a "scanout channel per display." It does not specify the protocol crossing that seam: what messages flow, who allocates the scanout buffer, how display capabilities are advertised, what happens on hotplug or mode change, how fallback to a non-GPU backend works, how the compositor remains agnostic to which scanout backend is bound.

The pressure to specify it now is two-pronged. First, the compositor implementation is about to start (Phase GUI-3, this session). It will *talk* this protocol on day one whether or not the protocol is written down. If it isn't written down, the protocol is whatever the compositor's first IPC happens to look like, and the future virtio-gpu / Intel-UHD / Limine-FB backends will have to retrofit themselves to that accident. Second, the user is about to start a parallel build effort targeting real hardware (Dell Precision 3630, Intel UHD). For that effort to slot into the compositor without cross-contamination — without the compositor needing to know it's talking to Intel — the protocol has to exist as a contract before either side codes against the other.

This ADR writes the contract. The compositor will speak it; every scanout backend (`user/scanout-virtio-gpu`, `user/scanout-intel`, `user/scanout-limine`, future) will implement it. The compositor links no backend; the scanout-driver knows nothing about windows. The seam is the protocol.

## Module Boundary

The split, restated in load-bearing form:

```
┌────────────────────────────────────────────────────────────┐
│ user/compositor                                             │
│  Knows: client surfaces, window state, focus, z-order,     │
│         damage tracking, input routing, scanout protocol.  │
│  Doesn't know: framebuffer addresses, GPU registers,       │
│         hardware-specific buffer formats, vsync mechanics, │
│         which scanout backend is bound today.              │
└────────────────────────────────────────────────────────────┘
                          ↕ scanout protocol (this ADR)
┌────────────────────────────────────────────────────────────┐
│ user/scanout-<name>     One per backend. Examples:          │
│  • user/scanout-virtio-gpu  (QEMU, dev/CI)                  │
│  • user/scanout-intel       (Dell 3630, bare metal)         │
│  • user/scanout-limine      (linear-FB fallback)            │
│  Knows: hardware MMIO, GPU command submission, scanout     │
│         buffer alignment/tiling, vsync, hotplug, EDID,     │
│         scanout protocol.                                   │
│  Doesn't know: window state, clients, focus, damage policy,│
│         compositor's internal data structures.             │
└────────────────────────────────────────────────────────────┘
                          ↕ MapMmio / AllocDma / WaitIrq /
                            SYS_MAP_FRAMEBUFFER (fallback only)
┌────────────────────────────────────────────────────────────┐
│ KERNEL                                                      │
└────────────────────────────────────────────────────────────┘
```

The compositor links exactly zero backend code. Backend selection is a runtime probe. There is no `if cfg!(target = "intel") { ... }` in the compositor. Cross-contamination between modules is a bug, not a tradeoff.

## Decision

### Connection topology

- **At most one compositor process per system.** Singleton. Identified by Principal at boot (similar to `POLICY_SERVICE_PID` for the policy service).
- **At most one scanout-driver process per system.** The compositor pairs with exactly one. Multiple physical displays are surfaced by the same driver, not by multiple drivers. Multi-GPU topologies (integrated + discrete, dual-GPU workstation) are deferred to a future ADR — see Open Questions § "Two GPUs in one machine (multi-driver topology)" for the deferred design discussion. Until that ADR exists, the singleton-driver assumption is load-bearing for the protocol; revisit when a real multi-GPU target appears.
- **Pairing is at startup**, not per-frame. Driver registers; compositor binds; from then on the pair is fixed for the boot.
- **Both sides are signed boot modules** holding bound Principals. Pairing handshake verifies Principals against each other (driver's Principal is in compositor's trusted-driver list and vice versa) — concrete authority list lives in the policy service eventually; for v0 the trust list is compiled into both processes.

### Two transports per the ADR-005 control + bulk pattern

Following ADR-005:
1. **Control IPC** (256-byte messages, capability-checked, identity-stamped) for protocol messages: handshake, capability advertisement, frame-ready notifications, hotplug events, mode changes, frame-displayed acknowledgments. Low frequency (handshake once, hotplug rarely, frame-ready ~120/sec per display).
2. **Shared-memory channels** ([ADR-005 § Data Channels](005-ipc-primitives-control-and-bulk.md)) for scanout buffers themselves. One channel per active display. The bytes never go through the kernel after channel attach.

### Endpoints

- `SCANOUT_DRIVER_ENDPOINT` — fixed endpoint number (proposed `27`, first free after the ADR-005 channel syscalls). The active scanout-driver registers this endpoint at boot. The compositor sends control messages here.
- `COMPOSITOR_ENDPOINT` — fixed endpoint number (proposed `28`). The compositor registers this. The scanout-driver sends async events (hotplug, frame-displayed) here.

These join the existing well-known endpoint table (16 = fs-service, 17 = key-store, etc.). Both numbers documented in the ADR-005 sense — they are part of the OS interface, not internal to either service.

### Scanout buffer ownership

**The driver allocates, the compositor writes.** Reasoning: the driver knows hardware constraints (DMA alignment, GPU-visible memory, tile ordering for some GPUs, NO_CACHE attributes for linear FBs). The compositor knows nothing about hardware. Putting allocation on the driver keeps the compositor hardware-agnostic.

Mechanism:
1. On display connect (or at handshake for displays already connected), the driver creates a shared-memory channel (`SYS_CHANNEL_CREATE`) sized for that display's full scanout (`pitch × height` bytes), with `peer_principal = compositor's Principal`, `role = Producer-from-compositor's-perspective` — meaning the compositor side is RW, the driver side is RO. The driver gets the compositor-facing `ChannelId`.
2. Driver sends `ScanoutBufferAllocated { display_id, channel_id, geometry, format }` to compositor over control IPC.
3. Compositor attaches (`SYS_CHANNEL_ATTACH(channel_id)`) and writes pixels into the mapped region.

The scanout buffer is *single-buffered* in this protocol. The compositor's own back-buffer-as-mirror pattern (per ADR-011) lives entirely on the compositor side. The driver sees one buffer per display; what flows in is whatever the compositor put there at the moment of `FrameReady`. If a backend wants double-buffering for tear-free presentation, it does that internally (e.g., an Intel driver might allocate two scanout planes and flip between them; the compositor never sees that). This keeps the protocol minimal and simplifies fallback backends.

### Display capability advertisement

At handshake (and on hotplug), the driver enumerates displays and announces each:

```
struct DisplayInfo {              // packs into the 256-byte control IPC
    display_id: u32,              // stable per physical port for this boot
    state: DisplayState,          // Connected | Disconnected
    physical_geometry: Geometry,  // current mode: width, height, pitch, bpp
    backing_scale: u16,           // 1×=100, 2×=200, fractional×=125, etc.
    refresh_hz: u16,
    pixel_format: PixelFormat,    // XRGB8888 | BGRA8888 | ARGB2_10_10_10 (HDR) | ...
    capabilities: u32,            // bitfield: HDR_HDR10, VRR, partial_update, ...
    edid_hash: [u8; 32],          // Blake3 of full EDID, for identity/fingerprinting
}
```

Mode lists (alternative resolutions / refresh rates per display) are larger than 256 bytes and are queried *on demand* via a separate request (`QueryDisplayModes { display_id } → response carries mode count, then a paginated mode walk` — full design in implementation; the ADR commits to "modes are queryable, not pushed").

### Frame lifecycle

```
compositor                            scanout-driver
    |                                       |
    |--- write pixels into scanout ch ----->|  (no kernel involvement;
    |    (direct memory, MMU enforces)      |   see ADR-005)
    |                                       |
    |--- FrameReady{display, damage[]} ---->|  (control IPC, 256B)
    |                                       |
    |                                       | program hardware to scan/flip;
    |                                       | wait for vsync/completion IRQ
    |                                       |
    |<-- FrameDisplayed{display, time_ns} --|  (control IPC, 256B)
    |                                       |
```

`damage` is a small list of dirty rectangles (≤ 16 rects per message; if more, compositor sends "full surface dirty"). Drivers may use the damage list to optimize (partial scanout, region-of-interest copy) or ignore it (full-frame flip). Either is conformant — `damage` is a *hint*, not a constraint.

`FrameDisplayed` carries the wall-time of presentation in tick units (kernel `GetTime` units). Compositor uses this for animation timing and vsync alignment without needing direct hardware access.

The compositor SHOULD wait for `FrameDisplayed` on at least one display before sending the next `FrameReady` for the same display (back-pressure). Drivers MAY drop `FrameReady`s that arrive while a previous frame is still in flight (returns `FrameDropped { display, reason }` instead of acking) — compositor uses this signal to slow its render loop.

### Hotplug + mode change events

Driver-initiated, sent to `COMPOSITOR_ENDPOINT`:

- `DisplayConnected { display_id, info: DisplayInfo, scanout_channel_id }` — new display attached and a scanout buffer is already allocated and ready for compositor to attach. Compositor responds by `SYS_CHANNEL_ATTACH`-ing and beginning to render to it.
- `DisplayDisconnected { display_id }` — physical disconnect or driver-side teardown. Compositor stops rendering to it and detaches the channel. Driver closes the channel after the compositor detaches.
- `DisplayModeChanged { display_id, new_info: DisplayInfo, new_scanout_channel_id }` — user changed resolution, new HDR mode negotiated, etc. New buffer is allocated; compositor switches over and detaches the old.

Compositor-initiated, sent to `SCANOUT_DRIVER_ENDPOINT`:

- `RequestModeChange { display_id, requested_mode }` — user setting a new resolution from the OS UI. Driver responds with `DisplayModeChanged` (success) or `ModeRejected { reason }` (failure).

### Capability model

New `CapabilityKind` (lands when this protocol is implemented, not now):

- `ScanoutDriverRegister` — authorizes a process to claim the singleton scanout-driver role. Granted at boot to the compiled-in scanout driver service.
- `CompositorRegister` — authorizes a process to claim the singleton compositor role. Granted at boot to `user/compositor`.
- `MapFramebuffer` (already exists, ADR-011) — required by the *fallback* `scanout-limine` driver, not by the compositor.
- `MapMmio` / `AllocDma` / `WaitIrq` / `LegacyPortIo` — required by hardware-touching scanout drivers (virtio-gpu, intel) per their access needs. Compositor needs none of these.

The compositor's complete kernel-syscall surface is: `RegisterEndpoint`, `RecvMsg`/`Write` (IPC), `ChannelCreate`/`Attach`/`Close` (for client surface buffers), `Yield`, `GetTime`, `Print`. No hardware access, no MMIO, no DMA. **This is a load-bearing property — if the compositor ever needs `MapMmio` or `MapFramebuffer`, the modular boundary has been violated.**

### Trait abstraction in the compositor (userspace dyn dispatch)

The compositor's internal API for talking to whichever scanout-driver is bound:

```rust
trait ScanoutBackend {
    fn enumerate_displays(&self) -> &[DisplayInfo];
    fn attach_scanout(&mut self, display_id: u32) -> Result<ScanoutBuffer, ScanoutError>;
    fn submit_frame(&mut self, display_id: u32, damage: &[Rect]) -> Result<(), ScanoutError>;
    fn poll_event(&mut self) -> Option<ScanoutEvent>;
    fn request_mode(&mut self, display_id: u32, mode: Mode) -> Result<(), ScanoutError>;
}

// At compositor startup, after probing which scanout-driver registered:
let backend: Box<dyn ScanoutBackend> = match probe_scanout_backend()? {
    Backend::VirtioGpu => Box::new(VirtioGpuBackend::attach()?),
    Backend::Intel     => Box::new(IntelGpuBackend::attach()?),
    Backend::Limine    => Box::new(LimineFbBackend::attach()?),
};
```

The dyn dispatch is *intra-process*, in the compositor only. Each `Box<dyn ScanoutBackend>` is a thin wrapper over an IPC client to the scanout-driver service; the actual rendering work happens in the scanout-driver process. This is userspace dyn dispatch (Box<dyn> in user/compositor) — explicitly allowed under CLAUDE.md's verification stance because:

1. **Verification scope is the kernel, not userspace.** The "no trait objects in kernel hot paths" rule in CLAUDE.md applies to `src/`. User-space services are programs the kernel runs; they are subject to the capability model and audit, not formal verification.
2. **The cost is invisible.** A vtable indirect call is a few cycles. Each `submit_frame` call it dispatches is an IPC roundtrip (thousands of cycles) plus hardware programming (more). The dispatch overhead is rounding error.
3. **The choice is genuinely runtime.** Compositor probes hardware at startup and binds the right backend. Generic monomorphization would require shipping multiple compositor binaries or compile-time backend selection — neither acceptable when the dev environment includes QEMU, AArch64, and bare-metal Dell concurrently.

The scanout-driver service itself is monomorphic — it talks to one specific hardware family with concrete types throughout.

### Fallback rules + non-local-display backends

**No backend baked into the compositor.** If no scanout-driver registers within `SCANOUT_DRIVER_HANDSHAKE_TIMEOUT` (5 seconds at 100Hz tick) of compositor startup, the compositor logs an error and enters `Headless` mode — accepts client connections, composes to memory, never displays. This is a real mode (useful for screen sharing / capture without a local display) and the cleanest semantics for "no scanout available."

The Limine fallback is its own service: `user/scanout-limine`. It uses `SYS_MAP_FRAMEBUFFER` to map the linear framebuffer Limine provided, and copies compositor-written scanout buffer regions into it on `FrameReady`. No hardware, no DMA, no IRQs — just memory copies. Good for QEMU dev sessions and as a sanity backend when bringing up new hardware.

**Non-local-display backends fit the same protocol.** The compositor doesn't know what a "display" is physically — it talks to a scanout-driver advertising display geometries. Any service that can fulfill that contract is a valid backend:

- **Remote display (RDP/VNC/SPICE/Looking-Glass-style)** — `user/scanout-remote` would advertise virtual displays over the wire and ship pixels over a network channel rather than a local PCIe bus. Compositor sees ordinary displays; the wire is somebody else's problem. This means remote access lands as a backend, not as a special compositor mode — the modular boundary holds.
- **KVM switch / monitor lid close / display sleep** — these are hotplug events. When the user flips the KVM, the now-disconnected display becomes `DisplayDisconnected`; on the other side it becomes `DisplayConnected`. Lid close on a laptop is the same shape: a `DisplayDisconnected { display_id = lid_panel }` event from the driver. Compositor reacts identically to physical unplug. No protocol extension needed.
- **Headless server with on-demand attach** — boot in `Headless` mode, accept a remote-display backend connection later, suddenly the compositor has displays. Same `DisplayConnected` flow as a hotplug. The 5-second handshake timeout governs when `Headless` mode is *entered*, not whether the compositor can leave it later.

The pattern: any change in display availability — physical, virtual, remote, switched — is a `DisplayConnected` / `DisplayDisconnected` event from the active scanout-driver. The compositor has one event-handling code path for all of them.

What this protocol does *not* cover yet: display power state (active vs. DPMS-suspended vs. off-but-still-attached). For v0 we model power-off as disconnect + reconnect — coarse but works. A finer-grained `DisplayPowerState` event lands when a real workload demands it (laptop suspend/resume, energy-saving display blanking). Listed in Open Questions.

### Wire encoding

All control-IPC messages carry a 4-byte tag at offset 0 indicating message type, followed by a packed payload. Layouts are `#[repr(C)]` little-endian, designed to fit in 256 bytes with room for protocol evolution. Detailed binary layouts go in the implementation, not this ADR — the contract is "what messages exist and what they mean," not "what bit goes where" (which would calcify too early).

### Reserved bounds (lands with implementation, listed here for visibility)

- `MAX_DISPLAYS_PER_DRIVER` = 8 (matches `MAX_FRAMEBUFFERS` in [src/boot/mod.rs](src/boot/mod.rs))
- `MAX_DAMAGE_RECTS_PER_FRAME` = 16 (fits in 256-byte control message; above this the compositor sends "full surface dirty")
- `SCANOUT_DRIVER_HANDSHAKE_TIMEOUT` = 500 ticks (5 seconds at 100Hz tick) — after which compositor enters Headless mode.

All three will get full SCAFFOLDING tags + ASSUMPTIONS.md rows when they enter code.

## Rationale

**Why a separate ADR rather than appending to ADR-011.** ADR-011 specifies the *stack* (what processes exist, what each one's job is). This ADR specifies the *protocol* (the wire contract between two of those processes). Different lifetime — ADR-011's stack design is settled-ish; the protocol will evolve with each new backend. Better to keep the protocol's evolution in its own divergence record than to muddy ADR-011's settled design with iterative protocol notes.

**Why driver-allocates rather than compositor-allocates the scanout buffer.** Hardware constraints dominate: GPU memory may need to be DMA-aligned, tiled, in specific physical address ranges, marked uncacheable. The compositor knows none of that. Putting allocation on the driver keeps the compositor's syscall surface to the IPC + channel primitives — no `AllocDma`, no `MapMmio`. The driver is the only side that ever touches the hardware allocator.

**Why singleton driver + singleton compositor.** Two compositors fighting over input focus and z-order would be incoherent. Two scanout drivers competing for the same display would be a configuration bug. Singleton-by-Principal is the cleanest enforcement — only one process holds the registration capability — and matches the existing pattern (one policy service, one fs-service, one key-store).

**Why control IPC + shared-memory channels rather than one or the other.** ADR-005's pattern: the kernel mediates *policy* (capability checks per IPC send), not *bytes*. Frame data is bytes (megabytes per frame at 4K) — must not go through kernel-mediated copies. Frame metadata is policy (which display, what damage, when displayed) — small, structured, identity-stamped, capability-checked, exactly the control IPC's job. Splitting them is the same call ADR-005 already made for video; this ADR just applies the call.

**Why pixels never go through the kernel after channel attach.** This is the load-bearing performance property. A 4K @ 120Hz scanout is 32 MiB × 120 = 3.8 GiB/sec per display. Three displays = 11.5 GiB/sec. Kernel-mediated copies cannot scale to that. MMU-enforced shared memory does — at full memory bandwidth, with no per-byte kernel involvement. The capability check at channel-attach time is the single per-channel security decision; everything after is hardware-enforced.

**Why ride on the existing ADR-005 channels rather than invent new IPC primitives.** Channels already do exactly what we need: capability-gated, MMU-enforced shared memory between two named Principals, with role-based access (Producer/Consumer/Bidirectional). Inventing a "graphics channel" alongside the existing channel would be duplicate design surface for no benefit. The graphics use case is one of the workloads ADR-005's `MAX_CHANNEL_PAGES = 65536` (256 MiB) was sized for — see [ADR-011 § Numeric bounds raised](011-graphics-architecture-and-scaling.md).

## Phased implementation

| Phase | What lands | Prerequisites |
|---|---|---|
| **Scanout-0** (this ADR) | Protocol contract written. No code. | — |
| **Scanout-1** | `user/compositor` scaffold: process, libsys boot module, `ScanoutBackend` trait, no-op render loop, `Headless` mode reachable. No real backend. | This ADR. |
| **Scanout-2** | `user/scanout-limine` — simplest backend. Maps Limine framebuffer, copies compositor's scanout to it on `FrameReady`. Validates the protocol end-to-end *if* the `SYS_MAP_FRAMEBUFFER` stall (STATUS.md known issue) is fixed first. | Scanout-1; SYS_MAP_FRAMEBUFFER stall resolution. |
| **Scanout-3** | First GUI client: simple "hello-window" boot module that opens a window and draws a colored rectangle. End-to-end validation. | Scanout-2. |
| **Scanout-4** | `user/scanout-virtio-gpu` — first hardware-accelerated backend. Validates the protocol against a real (well, emulated) GPU. | Scanout-3 + virtio-gpu spec implementation work. |
| **Scanout-5** | `user/scanout-intel` — Dell 3630 bare metal target. The user's parallel build effort lands here; the compositor accepts it without modification because the protocol contract held. | Scanout-4 (architecture proven) + Intel UHD driver work (substantial). |

Scanout-1 is what the compositor scaffold lands now. The rest follow.

## Open Questions

### Two GPUs in one machine (multi-driver topology)

Future workstations may have an integrated GPU + discrete GPU, each driving different displays. Today's "one scanout-driver per system" rule rules this out. Options when the time comes: (a) Allow multiple scanout-driver registrations, each owning a disjoint display set, with the compositor multiplexing across them; (b) A "scanout-driver multiplexer" service that wraps multiple physical drivers behind one protocol endpoint. Lean toward (b) — keeps the compositor protocol unchanged. Out of scope until a real multi-GPU target appears.

### Per-display scanout vs. unified scanout

This ADR assumes one scanout buffer per display. An alternative ("unified scanout") would have a single virtual desktop scanout that the driver crops/distributes per display. Unified scanout is simpler for the compositor (one buffer to write) but constrains the driver (display geometries must align). Per-display is what every modern OS does; sticking with it.

### Color management / HDR pipeline

The protocol carries `pixel_format` and HDR capability bits, but doesn't specify color-space conversion responsibility. Compositor in linear-light? Driver in display color-space? Open until first HDR backend lands.

### Display power state (DPMS-equivalent)

v0 models display power as binary: connected = on, disconnected = off. Real systems have richer states — DPMS standby/suspend/off, laptop lid close (physical disconnect vs. logical sleep), variable-backlight, etc. A finer-grained `DisplayPowerState` event would let the compositor stop submitting frames to a sleeping display without losing the display's state and capabilities. Lands when a battery-life or laptop-suspend workload demands it.

### Surface forwarding for direct scanout

A future optimization: compositor tells driver "this client surface IS the scanout buffer for this display, no compositing needed" (e.g., fullscreen video, fullscreen game). Eliminates the compositor copy. Not in v0; design when a real workload demands it.

## Divergence

*(appended as implementation diverges from the plan)*
