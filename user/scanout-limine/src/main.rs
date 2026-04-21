// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! scanout-limine — Phase Scanout-2 fallback driver (ADR-014).
//!
//! Implements the compositor ↔ scanout-driver protocol against the
//! Limine linear framebuffer. Maps the FB via `SYS_MAP_FRAMEBUFFER`,
//! allocates a shared-memory scanout channel for the compositor to
//! write into, then on each `FrameReady` memcpy's the channel contents
//! into the FB and acks with `FrameDisplayed`.
//!
//! No hardware MMIO, no DMA, no IRQs — the FB is just memory once
//! mapped. This driver exists so the compositor's scanout protocol can
//! be exercised end-to-end before the GPU drivers (virtio-gpu, intel)
//! land in Scanout-4/5.
//!
//! Single display, single compositor, single scanout buffer. Mode
//! changes, hotplug, multi-monitor, partial-update via damage rects:
//! all out of scope for the fallback. A future Scanout-2.x can add
//! per-rect copy if it ever matters; today's full-FB memcpy is fast
//! enough at 4 MiB and trivially correct.
//!
//! Trust model: today the driver accepts the first `RegisterCompositor`
//! it receives and binds that sender's Principal as "the compositor".
//! Stricter trust gating (compositor Principal in a compiled-in trust
//! list) lands when the `CompositorRegister` capability does (deferred
//! per ADR-014).

#![no_std]
#![no_main]
#![deny(unsafe_code)]
// `dead_code` is allowed because libscanout re-exports a wider surface
// than this driver consumes today (encoders for messages we don't yet
// emit). They're API for future scanout backends.
#![allow(dead_code)]

use arcos_libsys as sys;
use arcos_libsys::{FramebufferDescriptor, VerifiedMessage};
use arcos_libscanout::{
    DisplayInfo, DisplayState, Geometry, MsgTag, PixelFormat,
    SCANOUT_DRIVER_ENDPOINT,
    decode_frame_ready_header, encode_display_connected, encode_frame_displayed,
    encode_welcome_compositor,
};

/// Per-driver state. Single-display, single-compositor.
struct DriverState {
    fb: FramebufferDescriptor,
    /// Compositor's Principal, captured from the first `RegisterCompositor`.
    /// Used as the peer principal for `channel_create` and to verify
    /// subsequent `FrameReady` messages came from the same compositor.
    compositor: Option<[u8; 32]>,
    /// Compositor's reply endpoint (where we send WelcomeCompositor /
    /// DisplayConnected / FrameDisplayed). Captured from the
    /// `from_endpoint` field of the verified RegisterCompositor.
    compositor_endpoint: u32,
    /// Scanout channel: kernel-allocated, peer = compositor.
    /// `vaddr` is the driver-side mapping (RO; we read from it on FrameReady).
    scanout: Option<ScanoutChannel>,
}

#[derive(Clone, Copy)]
struct ScanoutChannel {
    channel_id: u64,
    vaddr: u64,
    size_bytes: usize,
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[SCANOUT-LIMINE] starting\r\n");

    // Map the Limine framebuffer. The kernel grants the
    // `MapFramebuffer` capability to scanout-limine by name at
    // boot — see register_process_capabilities in src/microkernel/main.rs.
    let mut fb = FramebufferDescriptor::default();
    if let Err(rc) = sys::map_framebuffer(0, &mut fb) {
        print_int(b"[SCANOUT-LIMINE] map_framebuffer rc=", rc);
        sys::exit(1);
    }
    print_fb(&fb);

    if fb.bpp != 32 {
        // Limine FB is virtually always 32bpp on QEMU/UEFI; if not, refuse.
        print_int(b"[SCANOUT-LIMINE] unsupported bpp=", fb.bpp as i64);
        sys::exit(2);
    }

    if sys::register_endpoint(SCANOUT_DRIVER_ENDPOINT) < 0 {
        sys::log_error(b"SCANOUT-LIMINE", b"register_endpoint(27) failed");
        sys::exit(3);
    }
    sys::print(b"[SCANOUT-LIMINE] registered endpoint 27\r\n");

    // Release the boot gate. scanout-limine doesn't gate downstream
    // services; they should come up in parallel.
    sys::module_ready();

    let mut state = DriverState {
        fb,
        compositor: None,
        compositor_endpoint: 0,
        scanout: None,
    };

    // 36 (header) + 256 (max payload) + slack. Sized to MAX_USER_BUFFER + header.
    let mut buf = [0u8; 320];
    loop {
        if let Some(msg) = sys::recv_verified(SCANOUT_DRIVER_ENDPOINT, &mut buf) {
            handle_message(&mut state, &msg);
        }
        // recv_verified blocks; if we get None it's a malformed/anonymous
        // message and we just spin to wait for the next.
    }
}

fn handle_message(state: &mut DriverState, msg: &VerifiedMessage) {
    let payload = msg.payload();
    if payload.len() < 4 {
        return;
    }
    let Ok(tag_bytes) = payload[0..4].try_into() else { return };
    let tag_u32 = u32::from_le_bytes(tag_bytes);
    let Some(tag) = MsgTag::from_u32(tag_u32) else { return };

    match tag {
        MsgTag::RegisterCompositor => handle_register_compositor(state, msg),
        MsgTag::FrameReady => handle_frame_ready(state, msg),
        // ReleaseScanoutBuffer / RequestModeChange not supported by this
        // fallback today. A real backend (virtio-gpu, intel) implements
        // these; for the Limine FB they have no meaning beyond shutdown.
        _ => {}
    }
}

fn handle_register_compositor(state: &mut DriverState, msg: &VerifiedMessage) {
    if state.compositor.is_some() {
        sys::print(b"[SCANOUT-LIMINE] duplicate RegisterCompositor; ignoring\r\n");
        return;
    }

    let principal = *msg.sender().as_bytes();
    state.compositor = Some(principal);
    state.compositor_endpoint = msg.from_endpoint();
    sys::print(b"[SCANOUT-LIMINE] compositor registered\r\n");

    // Allocate the scanout channel sized for the framebuffer.
    let size_bytes = (state.fb.pitch as u64) * (state.fb.height as u64);
    let pages = size_bytes.div_ceil(4096) as u32;
    print_int(b"[SCANOUT-LIMINE] channel_create pages=", pages as i64);
    print_hex(b"[SCANOUT-LIMINE] peer_principal first u64=",
        u64::from_le_bytes(principal[0..8].try_into().unwrap_or([0; 8])));
    let mut channel_vaddr: u64 = 0;
    // role = 1 = Consumer (creator/driver reads, peer/compositor writes).
    let rc = sys::channel_create(pages, &principal, 1, &mut channel_vaddr);
    if rc < 0 {
        print_int(b"[SCANOUT-LIMINE] channel_create rc=", rc);
        return;
    }
    let channel_id = rc as u64;
    state.scanout = Some(ScanoutChannel {
        channel_id,
        vaddr: channel_vaddr,
        size_bytes: size_bytes as usize,
    });
    print_hex(b"[SCANOUT-LIMINE] scanout channel id=", channel_id);

    // Send WelcomeCompositor (capabilities = 0, no flags defined in v0).
    let mut reply = [0u8; 16];
    if let Some(n) = encode_welcome_compositor(&mut reply, 0) {
        sys::write(state.compositor_endpoint, &reply[..n]);
    }

    // Send DisplayConnected with the scanout channel id + DisplayInfo.
    let info = DisplayInfo {
        display_id: 0,
        state: DisplayState::Connected,
        geometry: Geometry {
            width: state.fb.width,
            height: state.fb.height,
            pitch: state.fb.pitch,
            bpp: state.fb.bpp,
        },
        backing_scale: 100,
        refresh_hz: 60, // Limine doesn't expose refresh; assume 60 Hz.
        format: PixelFormat::Xrgb8888,
        capabilities: 0,
        edid_hash: [0; 32], // Limine doesn't expose EDID.
    };
    let mut reply = [0u8; 128];
    if let Some(n) = encode_display_connected(&mut reply, &info, channel_id) {
        sys::write(state.compositor_endpoint, &reply[..n]);
        sys::print(b"[SCANOUT-LIMINE] DisplayConnected sent\r\n");
    }
}

fn handle_frame_ready(state: &mut DriverState, msg: &VerifiedMessage) {
    // Verify sender matches the registered compositor.
    let Some(expected) = state.compositor else {
        sys::print(b"[SCANOUT-LIMINE] FrameReady before RegisterCompositor; dropping\r\n");
        return;
    };
    if msg.sender().as_bytes() != &expected {
        sys::print(b"[SCANOUT-LIMINE] FrameReady from wrong sender; dropping\r\n");
        return;
    }

    let scanout = match state.scanout {
        Some(s) => s,
        None => {
            sys::print(b"[SCANOUT-LIMINE] FrameReady but no scanout channel; dropping\r\n");
            return;
        }
    };

    let Some((display_id, seq, _damage_count)) = decode_frame_ready_header(msg.payload()) else {
        sys::print(b"[SCANOUT-LIMINE] malformed FrameReady; dropping\r\n");
        return;
    };

    if display_id != 0 {
        // Single-display fallback; ignore mismatched display_id.
        return;
    }

    // For v0: full-frame memcpy from scanout channel → framebuffer.
    // Damage rects ignored (driver MAY ignore damage per ADR-014; the
    // hint exists for sophisticated drivers, not a fallback like this).
    //
    // SAFETY:
    // - scanout.vaddr is the driver-side mapping of the scanout channel,
    //   returned by sys::channel_create with role=Consumer. Valid for
    //   `scanout.size_bytes` bytes (pitch × height) of read access until
    //   the channel is closed (which we never do in this loop).
    // - state.fb.vaddr is the driver's framebuffer mapping, returned by
    //   sys::map_framebuffer. Valid for `pitch × height` bytes of write
    //   access (uncacheable MMIO flags) for the kernel's lifetime.
    // - Both regions are exactly `scanout.size_bytes` bytes (we sized
    //   the channel to match the framebuffer at RegisterCompositor time)
    //   so the copy stays within both mappings.
    // - The regions don't overlap (channel is RAM-backed user memory,
    //   FB is MMIO-mapped device memory).
    #[allow(unsafe_code)]
    unsafe {
        core::ptr::copy_nonoverlapping(
            scanout.vaddr as *const u8,
            state.fb.vaddr as *mut u8,
            scanout.size_bytes,
        );
    }

    // Ack with FrameDisplayed. present_time = "now" since the Limine
    // FB has no vsync/refresh — the bytes are visible the instant we
    // finish the memcpy.
    let mut reply = [0u8; 24];
    if let Some(n) = encode_frame_displayed(&mut reply, display_id, seq, sys::get_time()) {
        sys::write(state.compositor_endpoint, &reply[..n]);
    }
}

// ============================================================================
// Tiny serial-print helpers (no_std, no alloc, no format!)
// ============================================================================

fn print_int(prefix: &[u8], value: i64) {
    sys::print(prefix);
    if value < 0 {
        sys::print(b"-");
        print_u64_dec((-value) as u64);
    } else {
        print_u64_dec(value as u64);
    }
    sys::print(b"\r\n");
}

fn print_hex(prefix: &[u8], value: u64) {
    sys::print(prefix);
    sys::print(b"0x");
    let mut buf = [0u8; 16];
    let mut n = value;
    for i in 0..16 {
        let nibble = (n & 0xF) as u8;
        buf[15 - i] = if nibble < 10 { b'0' + nibble } else { b'a' + (nibble - 10) };
        n >>= 4;
    }
    sys::print(&buf);
    sys::print(b"\r\n");
}

fn print_u64_dec(mut n: u64) {
    if n == 0 {
        sys::print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut len = 0;
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut out = [0u8; 20];
    for i in 0..len {
        out[i] = buf[len - 1 - i];
    }
    sys::print(&out[..len]);
}

fn print_fb(fb: &FramebufferDescriptor) {
    sys::print(b"[SCANOUT-LIMINE] fb ");
    print_u64_dec(fb.width as u64);
    sys::print(b"x");
    print_u64_dec(fb.height as u64);
    sys::print(b" pitch=");
    print_u64_dec(fb.pitch as u64);
    sys::print(b" bpp=");
    print_u64_dec(fb.bpp as u64);
    sys::print(b"\r\n");
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"SCANOUT-LIMINE", b"panic");
    sys::exit(255);
}
