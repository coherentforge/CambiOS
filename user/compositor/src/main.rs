// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS compositor — Phase Scanout-3 (ADR-011 § surface channel + ADR-014).
//!
//! What this binary does today:
//!
//! - Registers `COMPOSITOR_ENDPOINT = 28` — single endpoint shared by
//!   the scanout-driver (tag prefix 0x20xx) and clients (tag prefix
//!   0x30xx). Incoming messages are dispatched by tag high nibble.
//! - Performs the protocol handshake with the active scanout-driver:
//!   sends `RegisterCompositor` to `SCANOUT_DRIVER_ENDPOINT`, awaits
//!   `WelcomeCompositor` + `DisplayConnected`, attaches to the scanout
//!   channel, builds a `LimineFbBackend` (or falls back to
//!   `HeadlessBackend`).
//! - Paints a single throwaway "first-pixels" test frame: fills the
//!   scanout buffer with a known color, submits a `FrameReady`,
//!   awaits the `FrameDisplayed` ack. End-to-end validation of the
//!   back path.
//! - Enters the main dispatch loop:
//!     * `try_recv_msg` on ep28
//!     * peek tag direction: 0x2x → scanout-driver event (backend
//!       decodes), 0x3x → client request (windows::dispatch)
//!     * on client FrameReady, blit surface into scanout + forward
//!       `FrameReady` downstream to the scanout-driver
//!
//! What this binary explicitly does NOT do:
//!
//! - No hardware access. The compositor's complete kernel-syscall
//!   surface is `RegisterEndpoint`, `Print`, `Yield`, `RecvMsg`/`Write`,
//!   `Channel*`, `GetTime`. If any future change adds a hardware
//!   syscall here, the modular boundary from ADR-014 has been violated.
//! - No z-order, no focus, no input routing, no damage-tracked partial
//!   composition — those land in Scanout-4+. Scanout-3 is: one window,
//!   full-surface blit, prove the pipe.

#![no_std]
#![no_main]
#![deny(unsafe_code)]
// Phase Scanout-2: most of `scanout.rs` (full trait surface, wire-format
// re-exports) exists today as the protocol contract. Real consumers
// — `VirtioGpuBackend`, `IntelGpuBackend`, full client surface plumbing
// — land in Scanout-3+ and will exercise it. Until then unused
// re-exports trip dead-code warnings; muted here.
#![allow(dead_code)]

use core::sync::atomic::{AtomicU8, Ordering};

use cambios_libgui_proto::{encode_input_event, INPUT_EVENT_SIZE, COMPOSITOR_INPUT_ENDPOINT, MAX_WINDOWS};
use cambios_libinput_proto::{decode_event, DeviceClass};
use cambios_libsys as sys;
use cambios_libscanout::{
    decode_display_connected, encode_register_compositor, MsgTag,
    COMPOSITOR_ENDPOINT, SCANOUT_DRIVER_ENDPOINT,
};

mod scanout;
mod windows;
use scanout::{
    Backend, HeadlessBackend, LimineFbBackend, ScanoutBackend, ScanoutBuffer, ScanoutEvent,
};
use windows::{handle_client_payload, Window, WindowTable, WindowView};

/// Maximum IPC receive buffer size for the main dispatch loop.
/// Sized to hold the largest libgui-proto message (FrameReady with
/// 16 damage rects = 144 bytes) plus the 36-byte `recv_msg` header.
/// 320 bytes leaves room to grow.
const DISPATCH_BUFFER_BYTES: usize = 320;

/// Bytes the kernel prepends to a `recv_msg` / `try_recv_msg` result:
/// 32-byte sender_principal + 4-byte from_endpoint.
const RECV_HEADER_BYTES: usize = 36;

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[COMPOSITOR] Phase Scanout-2 (ADR-014)\r\n");

    if sys::register_endpoint(COMPOSITOR_ENDPOINT) < 0 {
        sys::log_error(b"COMPOSITOR", b"register_endpoint(28) failed");
        sys::exit(1);
    }
    sys::print(b"[COMPOSITOR] registered endpoint 28\r\n");

    // Register the dedicated input endpoint (ADR-012 Input-1). Every
    // input driver sends 96-byte raw InputEvents here; we forward to
    // the focused window. If registration fails we continue — no
    // graphics clients depend on input, so falling back to "input
    // silently unavailable" is a survivable degraded mode.
    if sys::register_endpoint(COMPOSITOR_INPUT_ENDPOINT) < 0 {
        sys::log_error(b"COMPOSITOR", b"register_endpoint(30) failed");
    } else {
        sys::print(b"[COMPOSITOR] registered endpoint 30 (input)\r\n");
    }

    // ADR-027 Phase 2 step 7: register the rendering limb as a
    // service cluster *before* the scanout handshake, so the
    // scanout-driver can call `cluster_join` when it receives our
    // `RegisterCompositor` message. Compositor is the natural
    // creator (see ADR-027 § Migration Path step 7 — compositor is
    // the coordinator role that detects cluster-fatal conditions).
    //
    // Manifest: 2 members in v1 — compositor + scanout.
    // virtio-input membership deferred — see register_rendering_limb_cluster.
    // Revisit when: virtio-input gains an inbound endpoint to receive cluster_id.
    // All three boot modules share the bootstrap Principal today
    // (Frame-A vestige); the manifest names them by role for
    // structural membership tracking.
    let cluster_id = match register_rendering_limb_cluster() {
        Some(id) => id,
        None => {
            sys::print(b"[COMPOSITOR] cluster_create failed; continuing without cluster\r\n");
            // 0 is a valid ClusterId (idx=0 gen=0). Use u64::MAX as
            // the "no cluster" sentinel in our wire field; the
            // scanout-driver's decode skips cluster_join when it
            // sees this value.
            u64::MAX
        }
    };

    // Boot-gate ordering: do the scanout handshake BEFORE calling
    // `module_ready()`. Downstream modules include hello-window
    // (Scanout-3), which immediately sends `CreateWindow` to ep28 —
    // if it arrives while we're blocked in `recv_verified` for
    // `WelcomeCompositor`, the handshake reads the client message
    // instead of the scanout-driver's reply and fails with
    // "expected WelcomeCompositor, got other tag". Serialising the
    // gate resolves the race; shell is a leaf that doesn't touch the
    // compositor so the ~1 handshake RTT delay is harmless.
    let mut backend = match handshake_with_scanout_driver(cluster_id) {
        Some(b) => {
            sys::print(b"[COMPOSITOR] backend bound: scanout-limine\r\n");
            b
        }
        None => {
            sys::print(b"[COMPOSITOR] handshake failed; falling back to headless\r\n");
            Backend::Headless(HeadlessBackend::new())
        }
    };

    // Note: the throwaway first-pixels cyan test that originally lived
    // here has been retired. terminal-window now claims the full
    // scanout (1024×768) on boot and submits a real client frame
    // immediately, so the end-to-end compositor → channel → driver
    // chain is exercised by production traffic — the cyan flash was
    // only ever visible briefly before terminal-window's first paint
    // and confused first-time HN viewers about what they were seeing.
    // [`run_first_pixels_test`] is preserved at the bottom of this file
    // for use as a manual diagnostic when adding a new scanout-driver
    // backend; not invoked from the boot path.
    let mut window_table = WindowTable::new();

    // Release the boot gate now. hello-window and any other clients
    // can start sending CreateWindow messages; the dispatch loop is
    // next.
    sys::module_ready();

    // Main dispatch loop. Drains scanout-driver events (FrameDisplayed
    // acks today, hotplug in future) *and* client requests
    // (CreateWindow, FrameReady, DestroyWindow) — both arrive on ep28,
    // distinguished by MsgTag high nibble.
    //
    // Scanout-3c: on client FrameReady we blit the surface into the
    // scanout buffer and forward FrameReady to the scanout-driver.
    // v0 is single-window, no z-order, no damage tracking — full
    // surface copy every frame.
    // Tracks whether the previous tick had at least one live window.
    // Edge from true -> false means the last client just exited (or
    // sent DestroyWindow), so we paint a blank scanout to clear the
    // stale frame the previous game left in the framebuffer. Without
    // this, the user sees the prior game's last drawn frame until the
    // next game submits its first FrameReady — bad demo experience.
    let mut had_windows = false;
    // T-7 Phase A: track the currently focused (window_id, owner_principal)
    // so we can emit an InputFocusChange audit event whenever the focus
    // moves. v0 focus is "first live window in the table" (see
    // pump_input_once); transitions happen on window create/destroy.
    let mut last_focus: Option<(u32, [u8; 32])> = None;
    loop {
        // Userspace half of ADR-007 Divergence 7 (tombstone-on-
        // revoke). When a client exits without an explicit
        // DestroyWindow, the kernel revokes its surface channel and
        // remaps our RO mapping to the kernel's tombstone zero page.
        // Reaping here drops the dead window from the table within
        // one main-loop iteration, so composite, focus, has-windows,
        // and input-routing all see a clean state. Bounded by
        // MAX_WINDOWS sys::channel_info calls per iteration — cheap
        // even at the v1 endgame ~30-window target.
        let _ = window_table.reap_dead_channels();

        let outcome = pump_dispatch_once(&mut backend, &mut window_table);
        if matches!(outcome, DispatchOutcome::ClientFrame(_)) {
            // Z-stack composition: any window's FrameReady triggers a
            // full back-to-front recomposition because a higher-layer
            // alpha-blended pixel may now show different content from
            // a lower layer through transparent regions. The trigger
            // window inside the variant is informational; the
            // composite_and_present call walks the table.
            composite_and_present(&mut backend, &window_table);
        }

        let has_windows = window_table.iter().next().is_some();
        if had_windows && !has_windows {
            composite_blank_and_present(&mut backend);
        }
        had_windows = has_windows;

        // T-7 Phase A: detect focus transitions and report them to the
        // audit ring. Focus tracks the front-most live window
        // (highest `z_order`) — same rule pump_input_once uses for
        // event routing. On transition, emit an InputFocusChange event
        // with the old and new (window_id, owner_principal) pair.
        // Initial focus is encoded as old_id=0; focus loss as
        // new_id=0 + zero principal.
        let current_focus = window_table
            .front()
            .map(|w| (w.window_id, w.owner_principal));
        if current_focus != last_focus {
            let (old_id, _old_principal) = match last_focus {
                Some((id, p)) => (id, p),
                None => (0, [0u8; 32]),
            };
            let (new_id, new_principal) = match current_focus {
                Some((id, p)) => (id, p),
                None => (0, [0u8; 32]),
            };
            let _ = sys::audit_emit_input_focus(new_id, old_id, &new_principal);
            last_focus = current_focus;
        }

        // Drain any pending input events. Each pump forwards one event
        // to the focused window; a single scheduler tick may carry
        // multiple key/pointer events, so drain in a tight inner loop
        // rather than one-per-yield.
        while pump_input_once(&window_table) {}
        sys::yield_now();
    }
}

// ============================================================================
// Input routing
// ============================================================================

/// Drain one input event from `COMPOSITOR_INPUT_ENDPOINT` (if any) and
/// forward it to the focused window. Returns `true` if an event was
/// dispatched, `false` if the endpoint was empty.
///
/// Focus model: events go to the **front-most** live window — the
/// one with the highest `z_order` (ties broken by table order). Back
/// layers (e.g. terminal-window's watermark canvas) never receive
/// input. Single-window apps land at z=0 and are still "the front"
/// trivially. Cross-client focus arbitration (last-clicked,
/// explicit focus API) lands with the first multi-window WM service.
fn pump_input_once(window_table: &WindowTable) -> bool {
    let mut buf = [0u8; RECV_HEADER_BYTES + INPUT_EVENT_SIZE];
    let n = sys::try_recv_msg(COMPOSITOR_INPUT_ENDPOINT, &mut buf);
    if n <= 0 {
        return false;
    }
    let total = n as usize;
    if total < RECV_HEADER_BYTES + INPUT_EVENT_SIZE {
        return true; // malformed; advance so we don't re-read
    }
    let event = match decode_event(&buf[RECV_HEADER_BYTES..RECV_HEADER_BYTES + INPUT_EVENT_SIZE])
    {
        Some(e) => e,
        None => return true,
    };

    // v0 input policy: forward Keyboard and Pointer events to the focused
    // window. Controller / Tablet / Touch / Sensor / Accessibility /
    // Generic dropped here for now — no consumer expects them and the
    // first one to surface should ship alongside per-class subscription.
    //
    // Pointer was originally dropped at this gate (mouse-jiggle generates
    // ~50 PointerMove/sec of traffic and the keyboard-only games shipping
    // at the time would have eaten that for nothing). `tree` is mouse-
    // driven and has been since shortly after, so the gate ran out of
    // utility — pointer events now flow through. terminal-window's
    // encoder (`encoder.rs`) already drops anything non-Keyboard at the
    // first check, so the IPC traffic is bounded by "events the active
    // window cares about" + a small constant for the editor. Real
    // per-window subscription (clients announce which device classes they
    // want) is still the right shape long-term; lands when a second
    // pointer-using app surfaces and the spam matters more than the
    // simplicity.
    match event.device_class {
        DeviceClass::Keyboard | DeviceClass::Pointer => {}
        _ => return true,
    }

    // Find the focused window's reply endpoint — the front-most
    // (highest z_order) live window.
    let target = match window_table.front() {
        Some(w) => w.client_endpoint,
        None => return true, // no window to route to; drop event
    };

    // Forward as a tagged libgui-proto InputEvent message.
    let mut send_buf = [0u8; 4 + INPUT_EVENT_SIZE];
    let m = match encode_input_event(&mut send_buf, &event) {
        Some(m) => m,
        None => return true,
    };
    let _ = sys::write(target, &send_buf[..m]);
    true
}

// ============================================================================
// Dispatch
// ============================================================================

/// One tick's worth of work from the central dispatch. Returned by
/// [`pump_dispatch_once`] so the caller decides what to do next
/// (composite, log, etc.) without pushing composition state down into
/// either protocol module.
#[derive(Clone, Copy, Debug)]
enum DispatchOutcome {
    Idle,
    ScanoutEvent(ScanoutEvent),
    /// Client submitted a FrameReady — this is the window whose
    /// surface should now be blitted into the scanout buffer.
    ClientFrame(WindowView),
}

/// Core dispatch tick: try to pull one message from `COMPOSITOR_ENDPOINT`
/// and route it by tag direction. Non-blocking.
fn pump_dispatch_once<B: ScanoutBackend>(
    backend: &mut B,
    window_table: &mut WindowTable,
) -> DispatchOutcome {
    let mut buf = [0u8; DISPATCH_BUFFER_BYTES];
    let n = sys::try_recv_msg(COMPOSITOR_ENDPOINT, &mut buf);
    if n <= 0 {
        return DispatchOutcome::Idle;
    }
    let total = n as usize;
    if total < RECV_HEADER_BYTES + 4 {
        return DispatchOutcome::Idle;
    }
    let mut sender_principal = [0u8; 32];
    sender_principal.copy_from_slice(&buf[0..32]);
    let from_endpoint = match buf[32..36].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return DispatchOutcome::Idle,
    };
    let payload = &buf[RECV_HEADER_BYTES..total];

    let tag_raw = match payload[0..4].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return DispatchOutcome::Idle,
    };
    // High nibble of the tag. Symmetric with libscanout's 0x10xx/0x20xx
    // and libgui-proto's 0x30xx/0x40xx.
    match tag_raw >> 12 {
        0x2 => match backend.handle_scanout_payload(payload) {
            Some(evt) => DispatchOutcome::ScanoutEvent(evt),
            None => DispatchOutcome::Idle,
        },
        0x3 => match handle_client_payload(payload, &sender_principal, from_endpoint, window_table) {
            Some(view) => DispatchOutcome::ClientFrame(view),
            None => DispatchOutcome::Idle,
        },
        _ => DispatchOutcome::Idle,
    }
}

// ============================================================================
// Composite + present
// ============================================================================

/// Blit a window's surface into the bound scanout buffer and forward
/// a `FrameReady` to the scanout-driver. v0 is:
///
/// - Single window, origin-aligned (blits to (0,0) in scanout).
/// - Full-surface copy (no damage tracking).
/// - Destination clipped to the intersection of window geometry and
///   scanout geometry; anything past the scanout edge is dropped.
/// - Pixel format is assumed compatible (XRGB8888 for both surface
///   and scanout). Format-mismatch swizzling lands once virtio-gpu /
///   Intel backends advertise alternate formats.
///
/// Only meaningful against a `Backend::Limine` backend today; headless
/// has no scanout buffer to blit to.
fn composite_and_present(backend: &mut Backend, window_table: &WindowTable) {
    let scanout = match backend {
        Backend::Limine(b) => b.scanout,
        Backend::Headless(_) => return,
    };

    // Snapshot every live window into a fixed-size array, then sort by
    // z_order ascending so we composite back-to-front. Insertion sort
    // is fine — MAX_WINDOWS is bounded and small (32 today), and the
    // common case is 1–2 windows.
    let mut sorted: [Option<&Window>; MAX_WINDOWS] = [None; MAX_WINDOWS];
    let mut count = 0usize;
    for w in window_table.iter() {
        if count < MAX_WINDOWS {
            sorted[count] = Some(w);
            count += 1;
        }
    }
    for i in 1..count {
        let mut j = i;
        while j > 0 {
            let lo = sorted[j - 1].unwrap().z_order;
            let hi = sorted[j].unwrap().z_order;
            if hi < lo {
                sorted.swap(j, j - 1);
                j -= 1;
            } else {
                break;
            }
        }
    }

    // Composite. The back-most window always overwrites (its pixels
    // become the scanout's base regardless of `alpha_blend`); higher
    // layers either overwrite (`alpha_blend=false`) or alpha-blend
    // (`alpha_blend=true`) on top of whatever's there.
    for (idx, slot) in sorted[..count].iter().enumerate() {
        let w = slot.expect("count tracks Some entries");
        let view = WindowView::from(w);
        if idx == 0 || !w.alpha_blend {
            blit_surface_to_scanout(&view, &scanout);
        } else {
            blend_surface_onto_scanout(&view, &scanout);
        }
    }

    if backend.submit_frame(scanout.display_id, &[]).is_err() {
        sys::print(b"[COMPOSITOR] submit_frame (client) failed\r\n");
        return;
    }
    // Print the first few client frames (proof-of-life during boot /
    // first launch), then go silent. A 60 fps game would otherwise
    // flood the serial console with hundreds of lines per second.
    static FRAME_LOG_BUDGET: AtomicU8 = AtomicU8::new(3);
    let prev = FRAME_LOG_BUDGET.fetch_update(
        Ordering::Relaxed,
        Ordering::Relaxed,
        |v| if v > 0 { Some(v - 1) } else { None },
    );
    if prev.is_ok() {
        sys::print(b"[COMPOSITOR] composited client frame\r\n");
    }
}

/// Blank the scanout buffer to black and present it. Called when the
/// last live client window goes away (DestroyWindow on the only
/// remaining window, or that client exits). Without this, the
/// framebuffer holds the previous game's last frame indefinitely, so
/// after Ctrl+Q the user sees a stale image until the next game runs.
///
/// XRGB8888 zero = black with the alpha-strip bit zeroed (matches the
/// compositor's pixel format invariant — same blit path as
/// composite_and_present, just with a synthetic all-zeros source).
fn composite_blank_and_present(backend: &mut Backend) {
    let scanout = match backend {
        Backend::Limine(b) => b.scanout,
        Backend::Headless(_) => return,
    };
    // SAFETY: scanout.vaddr was obtained from channel_attach on the
    // scanout channel (compositor peer, RW). Valid for
    // height × pitch bytes. Bounded write.
    let total_bytes =
        (scanout.geometry.height as usize) * (scanout.geometry.pitch as usize);
    #[allow(unsafe_code)]
    unsafe {
        core::ptr::write_bytes(scanout.vaddr as *mut u8, 0, total_bytes);
    }
    if backend.submit_frame(scanout.display_id, &[]).is_err() {
        sys::print(b"[COMPOSITOR] submit_frame (blank) failed\r\n");
        return;
    }
    sys::print(b"[COMPOSITOR] blanked scanout (last window gone)\r\n");
}

/// Alpha-blend a window surface (ARGB8888) over the scanout buffer at
/// origin (0, 0). Used for layered windows that opted into
/// `alpha_blend=true` at create time. Each surface pixel's high byte
/// is interpreted as alpha; alpha=0 leaves the scanout pixel
/// untouched, alpha=255 fully replaces, intermediate values blend.
///
/// The blend uses a /256 right-shift instead of /255 to avoid the
/// per-pixel divide; the precision loss (≤ 1 unit per channel) is
/// invisible. Alpha=0 is a fast-skip — common for layered windows
/// that are mostly transparent (e.g. terminal-window's front layer
/// where most cells are blank space → fully-transparent BG).
#[allow(unsafe_code)]
fn blend_surface_onto_scanout(view: &WindowView, scanout: &ScanoutBuffer) {
    let sw = view.width as usize;
    let sh = view.height as usize;
    let src_pitch_pixels = (view.pitch / 4) as usize;

    let dst_w = scanout.geometry.width as usize;
    let dst_h = scanout.geometry.height as usize;
    let dst_pitch_pixels = (scanout.geometry.pitch / 4) as usize;

    let copy_w = sw.min(dst_w);
    let copy_h = sh.min(dst_h);

    // SAFETY: same as `blit_surface_to_scanout` — both mappings are
    // owned by this process, the loop bounds are clamped to the
    // smaller of the two dimensions, and write_volatile prevents
    // re-ordering of shared-memory accesses. The arithmetic on each
    // pixel is u32-internal: u8 channels widened to u32, multiplied,
    // shifted; can't overflow.
    unsafe {
        let src_base = view.surface_vaddr as *const u32;
        let dst_base = scanout.vaddr as *mut u32;
        for y in 0..copy_h {
            let src_row = src_base.add(y * src_pitch_pixels);
            let dst_row = dst_base.add(y * dst_pitch_pixels);
            for x in 0..copy_w {
                let src = core::ptr::read_volatile(src_row.add(x));
                let alpha = (src >> 24) & 0xFF;
                if alpha == 0 {
                    continue;
                }
                if alpha == 0xFF {
                    core::ptr::write_volatile(dst_row.add(x), src & 0x00_FF_FF_FF);
                    continue;
                }
                let dst = core::ptr::read_volatile(dst_row.add(x));
                let inv = 255 - alpha;
                let sr = (src >> 16) & 0xFF;
                let sg = (src >> 8) & 0xFF;
                let sb = src & 0xFF;
                let dr = (dst >> 16) & 0xFF;
                let dg = (dst >> 8) & 0xFF;
                let db = dst & 0xFF;
                let or = (sr * alpha + dr * inv) >> 8;
                let og = (sg * alpha + dg * inv) >> 8;
                let ob = (sb * alpha + db * inv) >> 8;
                let out = (or << 16) | (og << 8) | ob;
                core::ptr::write_volatile(dst_row.add(x), out);
            }
        }
    }
}

/// Copy a window surface (XRGB8888, pitch bytes per row) into the
/// scanout buffer at origin (0, 0). Both mappings are owned by this
/// process via channel_attach, so direct pointer writes are safe; the
/// kernel enforced RW on the channel mapping at attach time. Used
/// for the back-most window (always) and for opaque higher layers
/// (`alpha_blend=false`).
fn blit_surface_to_scanout(view: &WindowView, scanout: &ScanoutBuffer) {
    let sw = view.width as usize;
    let sh = view.height as usize;
    let src_pitch_pixels = (view.pitch / 4) as usize;

    let dst_w = scanout.geometry.width as usize;
    let dst_h = scanout.geometry.height as usize;
    let dst_pitch_pixels = (scanout.geometry.pitch / 4) as usize;

    let copy_w = sw.min(dst_w);
    let copy_h = sh.min(dst_h);

    // SAFETY:
    // - `view.surface_vaddr` was obtained from `channel_create`
    //   (compositor is Consumer, maps RW). Valid for `pitch × height`
    //   bytes.
    // - `scanout.vaddr` was obtained from `channel_attach` on the
    //   scanout channel (compositor peer, maps RW). Valid for
    //   `pitch × height` bytes.
    // - Bounded loops: `copy_h ≤ dst_h ≤ scanout height`,
    //   `copy_w ≤ dst_w ≤ scanout width`, and src strides are the
    //   client's declared pitch/height — the compositor trusted the
    //   declared geometry when allocating the channel, and the kernel
    //   enforced the channel size bound.
    // - `write_volatile` is used because the source and destination
    //   are shared memory; the compiler must not re-order or elide.
    #[allow(unsafe_code)]
    unsafe {
        let src_base = view.surface_vaddr as *const u32;
        let dst_base = scanout.vaddr as *mut u32;
        for y in 0..copy_h {
            let src_row = src_base.add(y * src_pitch_pixels);
            let dst_row = dst_base.add(y * dst_pitch_pixels);
            for x in 0..copy_w {
                let pixel = core::ptr::read_volatile(src_row.add(x));
                core::ptr::write_volatile(dst_row.add(x), pixel);
            }
        }
    }
}

// ============================================================================
// Handshake
// ============================================================================

/// Try to pair with the active scanout-driver. Returns `Some(Backend)`
/// on success; `None` if any step of the protocol failed (driver not
/// listening, malformed reply, channel attach denied).
///
/// Today only the `LimineFbBackend` is built — when virtio-gpu / Intel
/// land, the `WelcomeCompositor` reply gains a backend-kind hint and
/// this function fans out by kind.
/// Build the rendering-limb manifest and register the cluster with
/// the kernel (ADR-027 § Migration Path step 7).
///
/// Returns the `ClusterId` (raw u64) on success. `None` on failure
/// — the caller falls back to a "no cluster" sentinel in the
/// `RegisterCompositor` wire payload, and the scanout-driver skips
/// `cluster_join` accordingly.
///
/// Manifest in v1: compositor + scanout, both bound to the bootstrap
/// Principal (all three rendering modules share it today — Frame-A
/// vestige).
//
// Deferred: include virtio-input as a third manifest member.
// Why: virtio-input has no inbound endpoint to receive cluster_id.
// Revisit when: virtio-input gains an inbound endpoint, OR a
//      different mechanism for cluster_id handoff lands (env var /
//      boot manifest field).
fn register_rendering_limb_cluster() -> Option<u64> {
    use sys::{ClusterMember, CLUSTER_POLICY_RENDERING_LIMB,
              CLUSTER_ROLE_COMPOSITOR, CLUSTER_ROLE_SCANOUT};

    let mut own_principal = [0u8; 32];
    if sys::get_principal(&mut own_principal) < 0 {
        sys::print(b"[COMPOSITOR] get_principal failed; cluster_create skipped\r\n");
        return None;
    }

    // All RenderingLimb members share the bootstrap Principal in v1
    // (per `src/microkernel/main.rs::register_process_capabilities`).
    // The manifest names them distinctly by role for structural
    // membership tracking; Principal-matching at join is currently
    // vacuous as a trust boundary (kernel re-checks at SYS_CLUSTER_JOIN
    // anyway, defense-in-depth).
    let manifest = [
        ClusterMember { principal: own_principal, role: CLUSTER_ROLE_COMPOSITOR },
        ClusterMember { principal: own_principal, role: CLUSTER_ROLE_SCANOUT },
    ];

    let rc = sys::cluster_create(CLUSTER_POLICY_RENDERING_LIMB, &manifest);
    if rc < 0 {
        sys::print(b"[COMPOSITOR] cluster_create returned negative rc\r\n");
        return None;
    }
    sys::print(b"[COMPOSITOR] rendering-limb cluster created\r\n");

    // Compositor itself joins as the Compositor role. Scanout joins
    // when it receives RegisterCompositor with the cluster_id below.
    let cluster_id = rc as u64;
    if sys::cluster_join(cluster_id, CLUSTER_ROLE_COMPOSITOR) < 0 {
        sys::print(b"[COMPOSITOR] self cluster_join failed\r\n");
        // Cluster exists but we couldn't join — return None so the
        // wire payload signals "no cluster" and scanout doesn't try
        // to join an asymmetric cluster either.
        return None;
    }
    Some(cluster_id)
}

fn handshake_with_scanout_driver(cluster_id: u64) -> Option<Backend> {
    // 1. Send RegisterCompositor (with cluster_id) to the driver's
    //    endpoint. The driver decodes the cluster_id and calls
    //    SYS_CLUSTER_JOIN itself — the cap-token-passing role of the
    //    pairwise handshake is unchanged in v1 (cluster_policy::
    //    caps_for_role is still a stub), so this is structural
    //    membership wiring on top of the existing protocol, not a
    //    replacement of it.
    let mut send_buf = [0u8; 16];
    let n = encode_register_compositor(&mut send_buf, cluster_id)?;
    let rc = sys::write(SCANOUT_DRIVER_ENDPOINT, &send_buf[..n]);
    if rc < 0 {
        sys::print(b"[COMPOSITOR] write to scanout-driver failed\r\n");
        return None;
    }
    sys::print(b"[COMPOSITOR] sent RegisterCompositor\r\n");

    // 2. Block-recv WelcomeCompositor. Boot-gate ordering guarantees
    //    the driver registered SCANOUT_DRIVER_ENDPOINT before we sent,
    //    so blocking is fine. Future runtime hotplug will need a
    //    timed handshake (SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS) —
    //    out of scope for v0.
    let mut welcome_buf = [0u8; 320];
    let welcome = sys::recv_verified(COMPOSITOR_ENDPOINT, &mut welcome_buf)?;
    if !is_tagged(welcome.payload(), MsgTag::WelcomeCompositor) {
        sys::print(b"[COMPOSITOR] expected WelcomeCompositor, got other tag\r\n");
        return None;
    }
    sys::print(b"[COMPOSITOR] received WelcomeCompositor\r\n");

    // 3. Block-recv DisplayConnected (driver sends it immediately
    //    after Welcome in the v0 protocol).
    let mut display_buf = [0u8; 320];
    let display_msg = sys::recv_verified(COMPOSITOR_ENDPOINT, &mut display_buf)?;
    let (info, channel_id) = decode_display_connected(display_msg.payload())?;
    sys::print(b"[COMPOSITOR] received DisplayConnected\r\n");

    // 4. Attach to the scanout channel. Driver created it with role =
    //    Consumer (creator reads); compositor as peer gets RW.
    let vaddr_or_err = sys::channel_attach(channel_id);
    if vaddr_or_err < 0 {
        sys::print(b"[COMPOSITOR] channel_attach failed\r\n");
        return None;
    }
    let vaddr = vaddr_or_err as u64;

    let scanout = ScanoutBuffer {
        display_id: info.display_id,
        geometry: info.geometry,
        format: info.format,
        vaddr,
        channel_id,
    };

    Some(Backend::Limine(LimineFbBackend::from_handshake(info, scanout)))
}

fn is_tagged(payload: &[u8], expected: MsgTag) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let Ok(bytes) = payload[0..4].try_into() else { return false };
    u32::from_le_bytes(bytes) == expected.as_u32()
}

// ============================================================================
// First-pixels test (Step 7 / Scanout-2 acceptance)
// ============================================================================

/// Fill the scanout buffer with a known color, submit FrameReady, wait
/// for FrameDisplayed. Single-shot validation of the entire compositor
/// → channel → scanout-driver memcpy → FB → ack chain.
///
/// Color is bright cyan (R=0x00, G=0xB0, B=0xFF) packed into XRGB8888
/// using shifts the Limine FB advertises (R<<16, G<<8, B<<0). Visual
/// verification requires a QEMU display backend (`-display gtk` or
/// VNC); the default `-display none` configuration validates the
/// memcpy + ack but doesn't show pixels.
#[allow(dead_code)] // diagnostic helper; no boot-path caller after the cyan-test retirement.
fn run_first_pixels_test(backend: &mut LimineFbBackend) {
    sys::print(b"[COMPOSITOR] painting test frame (cyan)\r\n");

    let scanout = backend.scanout;
    let pitch_pixels = (scanout.geometry.pitch / 4) as usize;
    let width = scanout.geometry.width as usize;
    let height = scanout.geometry.height as usize;

    // XRGB8888 with Limine's standard mask layout (R<<16, G<<8, B<<0).
    // cyan-ish pure — 0x00B0FF — chosen to be visibly non-default.
    let cyan: u32 = (0x00 << 16) | (0xB0 << 8) | 0xFF;

    // SAFETY:
    // - scanout.vaddr is the compositor's mapping of the scanout
    //   channel, returned by sys::channel_attach. Valid for
    //   `pitch * height` bytes of write access until channel_close
    //   (which we never call).
    // - We bound y < height and x < width, and pitch_pixels >= width
    //   (pitch is in bytes ≥ width * 4), so all writes stay within the
    //   mapped region.
    // - write_volatile prevents the compiler from eliding the writes
    //   (the channel is a different process's read-side; from this
    //   process's POV the compiler sees no observers and would
    //   otherwise dead-code the loop).
    #[allow(unsafe_code)]
    unsafe {
        let base = scanout.vaddr as *mut u32;
        for y in 0..height {
            let row = base.add(y * pitch_pixels);
            for x in 0..width {
                row.add(x).write_volatile(cyan);
            }
        }
    }

    sys::print(b"[COMPOSITOR] submitting FrameReady (full surface)\r\n");
    if backend.submit_frame(scanout.display_id, &[]).is_err() {
        sys::print(b"[COMPOSITOR] submit_frame failed\r\n");
        return;
    }

    // Wait for FrameDisplayed. ~1000 yields with no ack ≈ stall —
    // useful diagnostic, not a real timeout (real backpressure logic
    // lands with sustained rendering). We use a disposable
    // WindowTable here; the test runs before any clients exist, so
    // no client payloads are possible.
    let mut scratch_table = WindowTable::new();
    for _ in 0..1000 {
        if let DispatchOutcome::ScanoutEvent(ScanoutEvent::FrameDisplayed { .. }) =
            pump_dispatch_once(backend, &mut scratch_table)
        {
            sys::print(b"[COMPOSITOR] FrameDisplayed received -- first-pixels test PASSED\r\n");
            return;
        }
        sys::yield_now();
    }
    sys::print(b"[COMPOSITOR] FrameDisplayed timeout -- test INCONCLUSIVE\r\n");
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"COMPOSITOR", b"panic");
    sys::exit(255);
}
