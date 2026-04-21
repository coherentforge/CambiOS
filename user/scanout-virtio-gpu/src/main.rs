// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! scanout-virtio-gpu — Phase Scanout-4.b driver (ADR-014).
//!
//! # Scope of 4.b
//!
//! Full implementation of the compositor ↔ scanout-driver protocol
//! against QEMU's virtio-gpu-pci emulation. End-to-end pipeline:
//!
//!   compositor → FrameReady over ep27
//!              → driver memcpys channel-backed buffer into a
//!                virtio-gpu-owned DMA region
//!              → TRANSFER_TO_HOST_2D + RESOURCE_FLUSH
//!              → device scans out → QEMU window displays
//!              → FrameDisplayed ack to compositor.
//!
//! # Frame-path overhead (double-copy)
//!
//! Backing memory for a virtio-gpu `RESOURCE_ATTACH_BACKING` must be
//! physically contiguous DMA-capable pages (kernel-side `alloc_dma`).
//! The compositor writes into a shared-memory channel (RAM pages
//! allocated by the kernel at channel_create time). Those two sets
//! of pages are distinct, so every FrameReady incurs one userspace
//! memcpy (channel → backing) followed by virtio-gpu's own copy
//! (TRANSFER_TO_HOST_2D inside the device model). At 4 MiB × 60 Hz
//! = 240 MB/s, the copy cost is invisible on QEMU.
//!
//! **Zero-copy replacement deferred to 4.c** with the observable
//! trigger: "compositor frametime exceeds memcpy budget" OR
//! "first real-hardware port where the copy cost matters." The fix
//! is a new kernel primitive — either a DMA-backed channel flag on
//! `SYS_CHANNEL_CREATE`, or a dedicated share-DMA-pages-with-Principal
//! syscall. Both are nontrivial; the two-copy path lets 4.b ship
//! without that design work.
//!
//! # Deliberately NOT in 4.b
//!
//! - Damage-rect-aware partial transfer (compositor still sends
//!   damage; driver logs and ignores — same shape scanout-limine
//!   used through Scanout-3).
//! - Multi-display support. Driver picks scanout 0, single display.
//! - Hotplug, EDID, mode change.
//! - aarch64 / riscv64 backends (QEMU virtio-gpu-pci is x86-centric;
//!   the syscall surface is arch-portable but `make check-all`
//!   only builds the kernel, not user crates).

#![no_std]
#![no_main]
#![deny(unsafe_code)]
// 4.b consumes a subset of the transport + gpu surface — e.g.,
// `device_cfg_vaddr` stays on `ModernTransport` for 4.c cursor-cmd
// code; `VIRTIO_GPU_CMD_RESOURCE_UNREF` / `GpuError::DmaAlloc` exist
// for teardown paths that land later. Crate-level `allow(dead_code)`
// keeps the API shape intact without per-item noise.
#![allow(dead_code)]

#[allow(unsafe_code)]
mod gpu;
#[allow(unsafe_code)]
mod transport;
#[allow(unsafe_code)]
mod virtqueue;

use arcos_libscanout::{DisplayInfo, DisplayState, Geometry, MsgTag, PixelFormat,
    SCANOUT_DRIVER_ENDPOINT,
    decode_frame_ready_header, encode_display_connected, encode_frame_displayed,
    encode_welcome_compositor};
use arcos_libsys as sys;
use arcos_libsys::VerifiedMessage;

use gpu::{
    VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, VIRTIO_GPU_MAX_SCANOUTS,
    build_resource_attach_backing_single, build_resource_create_2d,
    build_resource_flush, build_set_scanout, build_transfer_to_host_2d,
    submit_get_display_info, submit_nodata, CTRL_HDR_SIZE,
};
use transport::{ModernTransport, STATUS_ACKNOWLEDGE, STATUS_DRIVER,
    STATUS_DRIVER_OK, STATUS_FAILED, STATUS_FEATURES_OK, VIRTIO_F_VERSION_1};
use virtqueue::{DmaBuffer, ModernVirtQueue};

// ============================================================================
// PCI identifiers
// ============================================================================

const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_GPU_DEVICE_ID_MODERN: u16 = 0x1050;

/// Virtio-gpu resource ID for the single scanout's host-side resource.
/// Arbitrary non-zero value; we only own one.
const SCANOUT_RESOURCE_ID: u32 = 1;

/// Scanout we bind to (virtio-gpu allows 16; we use the first).
const SCANOUT_ID: u32 = 0;

/// Recv buffer must hold the `recv_verified` header (32 B principal +
/// 4 B from_endpoint) + the 256 B max control-IPC payload + slack.
const RECV_BUF_SIZE: usize = 320;

// ============================================================================
// Driver state
// ============================================================================

struct Setup {
    transport: ModernTransport,
    queue: ModernVirtQueue,
    notify_off: u16,
    width: u32,
    height: u32,
    /// Command / response DMA buffers reused across every command
    /// (submit-and-wait is synchronous; no pipelining).
    cmd_buf: DmaBuffer,
    resp_buf: DmaBuffer,
}

struct CompositorBinding {
    /// Principal that first registered — used to verify subsequent
    /// FrameReady messages come from the same compositor.
    principal: [u8; 32],
    /// Compositor's reply endpoint (where we send async events).
    reply_endpoint: u32,
    /// Backing store for the virtio-gpu resource — DMA-contiguous,
    /// physically addressable by the device, mapped into this
    /// process's address space.
    backing: DmaBuffer,
    /// Shared-memory channel with the compositor.
    channel_id: u64,
    /// Driver-side mapping of the channel (compositor writes here,
    /// driver reads from here on FrameReady).
    channel_vaddr: u64,
    /// Length in bytes of the scanout frame — matches both the backing
    /// buffer size and the channel mapping size.
    frame_bytes: usize,
}

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[SCANOUT-VGPU] starting (Phase Scanout-4.b)\r\n");

    let mut setup = match initialize_device() {
        Some(s) => s,
        None => {
            sys::print(b"[SCANOUT-VGPU] device init failed; entering passive idle\r\n");
            // Register the endpoint anyway so the compositor's
            // handshake timeout (not our own) governs the behavior.
            let _ = sys::register_endpoint(SCANOUT_DRIVER_ENDPOINT);
            sys::module_ready();
            idle_loop();
        }
    };

    // Register our endpoint. Release the boot gate so the compositor
    // (next in BOOT_MODULE_ORDER) can come up and send RegisterCompositor.
    if sys::register_endpoint(SCANOUT_DRIVER_ENDPOINT) < 0 {
        sys::print(b"[SCANOUT-VGPU] register_endpoint(27) failed\r\n");
        sys::module_ready();
        idle_loop();
    }
    sys::print(b"[SCANOUT-VGPU] registered endpoint 27\r\n");
    sys::module_ready();

    // Main control loop.
    let mut binding: Option<CompositorBinding> = None;
    let mut recv_buf = [0u8; RECV_BUF_SIZE];
    loop {
        if let Some(msg) = sys::recv_verified(SCANOUT_DRIVER_ENDPOINT, &mut recv_buf) {
            handle_message(&mut setup, &mut binding, &msg);
        }
        // recv_verified blocks; if we get None it's a malformed /
        // anonymous message and we spin for the next.
    }
}

/// Find the device, map its BAR, run the virtio 1.0 init handshake,
/// set up the controlq, and issue GET_DISPLAY_INFO to learn geometry.
/// Returns the fully-initialized transport + queue on success.
fn initialize_device() -> Option<Setup> {
    let device_index = match find_virtio_gpu() {
        Some(i) => i,
        None => {
            sys::print(b"[SCANOUT-VGPU] no virtio-gpu device found\r\n");
            return None;
        }
    };
    print_kv(b"[SCANOUT-VGPU] found device index=", device_index as u64);

    let caps = sys::virtio_modern_caps(device_index)?;
    if caps.present == 0 {
        sys::print(b"[SCANOUT-VGPU] device reported no virtio-modern caps\r\n");
        return None;
    }

    let (bar_phys, bar_size) = bar_phys_size(device_index, caps.common_cfg.bar)?;
    print_kv(b"[SCANOUT-VGPU] mapping BAR ", caps.common_cfg.bar as u64);

    let transport = match ModernTransport::new(&caps, bar_phys, bar_size) {
        Ok(t) => t,
        Err(e) => {
            print_init_err(e);
            return None;
        }
    };

    let (queue, notify_off) = init_virtio(&transport)?;

    let cmd_buf = DmaBuffer::new(1)?;
    let resp_buf = DmaBuffer::new(1)?;

    // Discover the display's geometry via GET_DISPLAY_INFO. Use the
    // first enabled scanout as our display.
    let mut info_buf = [0u8; CTRL_HDR_SIZE + VIRTIO_GPU_MAX_SCANOUTS * 24];
    let mut queue = queue;
    if let Err(e) = submit_get_display_info(&transport, &mut queue, notify_off,
        &cmd_buf, &resp_buf, &mut info_buf)
    {
        print_gpu_err(b"GET_DISPLAY_INFO", e);
        return None;
    }

    let (width, height) = match pick_first_enabled_scanout(&info_buf) {
        Some(wh) => wh,
        None => {
            sys::print(b"[SCANOUT-VGPU] no enabled scanout reported\r\n");
            return None;
        }
    };
    sys::print(b"[SCANOUT-VGPU] scanout 0: ");
    print_u64_dec(width as u64);
    sys::print(b"x");
    print_u64_dec(height as u64);
    sys::print(b"\r\n");

    Some(Setup {
        transport,
        queue,
        notify_off,
        width,
        height,
        cmd_buf,
        resp_buf,
    })
}

/// Run the virtio 1.0 init sequence (reset → ACK → DRIVER → features →
/// FEATURES_OK → queue setup → DRIVER_OK).
fn init_virtio(t: &ModernTransport) -> Option<(ModernVirtQueue, u16)> {
    t.reset();
    for _ in 0..32 {
        if t.status() == 0 {
            break;
        }
    }
    t.set_status_bit(STATUS_ACKNOWLEDGE);
    t.set_status_bit(STATUS_DRIVER);

    let device_features = t.device_features();
    if device_features & VIRTIO_F_VERSION_1 == 0 {
        sys::print(b"[SCANOUT-VGPU] device lacks VIRTIO_F_VERSION_1\r\n");
        t.set_status_bit(STATUS_FAILED);
        return None;
    }
    t.set_driver_features(VIRTIO_F_VERSION_1);

    t.set_status_bit(STATUS_FEATURES_OK);
    if t.status() & STATUS_FEATURES_OK == 0 {
        sys::print(b"[SCANOUT-VGPU] device rejected FEATURES_OK\r\n");
        t.set_status_bit(STATUS_FAILED);
        return None;
    }

    if t.num_queues() == 0 {
        sys::print(b"[SCANOUT-VGPU] device advertises 0 queues\r\n");
        t.set_status_bit(STATUS_FAILED);
        return None;
    }
    t.select_queue(gpu::VGPU_CONTROLQ);
    let device_qsize = t.queue_size();
    if device_qsize == 0 {
        sys::print(b"[SCANOUT-VGPU] controlq size 0\r\n");
        t.set_status_bit(STATUS_FAILED);
        return None;
    }
    t.set_queue_size(virtqueue::QUEUE_SIZE);

    let queue = match ModernVirtQueue::new() {
        Some(q) => q,
        None => {
            sys::print(b"[SCANOUT-VGPU] queue DMA alloc failed\r\n");
            t.set_status_bit(STATUS_FAILED);
            return None;
        }
    };
    let (desc, driver, device) = queue.ring_addrs();
    t.set_queue_addrs(desc, driver, device);
    let notify_off = t.queue_notify_off();
    t.enable_queue();

    t.set_status_bit(STATUS_DRIVER_OK);
    if t.status() & STATUS_FAILED != 0 {
        sys::print(b"[SCANOUT-VGPU] device set FAILED after DRIVER_OK\r\n");
        return None;
    }
    Some((queue, notify_off))
}

/// Walk the 16-entry display-info response and return the (width, height)
/// of the first scanout with `enabled != 0`.
fn pick_first_enabled_scanout(info: &[u8]) -> Option<(u32, u32)> {
    for i in 0..VIRTIO_GPU_MAX_SCANOUTS {
        let off = CTRL_HDR_SIZE + i * 24;
        if off + 24 > info.len() {
            break;
        }
        let w = u32::from_le_bytes([info[off + 8], info[off + 9],
            info[off + 10], info[off + 11]]);
        let h = u32::from_le_bytes([info[off + 12], info[off + 13],
            info[off + 14], info[off + 15]]);
        let enabled = u32::from_le_bytes([info[off + 16], info[off + 17],
            info[off + 18], info[off + 19]]);
        if enabled != 0 {
            return Some((w, h));
        }
    }
    None
}

// ============================================================================
// Message dispatch
// ============================================================================

fn handle_message(
    setup: &mut Setup,
    binding: &mut Option<CompositorBinding>,
    msg: &VerifiedMessage,
) {
    let payload = msg.payload();
    if payload.len() < 4 {
        return;
    }
    let Ok(tag_bytes) = payload[0..4].try_into() else { return };
    let tag_u32 = u32::from_le_bytes(tag_bytes);
    let Some(tag) = MsgTag::from_u32(tag_u32) else { return };

    match tag {
        MsgTag::RegisterCompositor => handle_register_compositor(setup, binding, msg),
        MsgTag::FrameReady => handle_frame_ready(setup, binding, msg),
        // ReleaseScanoutBuffer / RequestModeChange / cursor commands —
        // not supported in 4.b. compositor doesn't send them yet.
        _ => {}
    }
}

fn handle_register_compositor(
    setup: &mut Setup,
    binding: &mut Option<CompositorBinding>,
    msg: &VerifiedMessage,
) {
    if binding.is_some() {
        sys::print(b"[SCANOUT-VGPU] duplicate RegisterCompositor; ignoring\r\n");
        return;
    }

    let principal = *msg.sender().as_bytes();
    let reply_endpoint = msg.from_endpoint();

    // Compute scanout size. XRGB8888 = 4 bytes per pixel, pitch = width * 4.
    let pitch: u32 = setup.width * 4;
    let frame_bytes = (pitch as usize) * (setup.height as usize);
    let pages = frame_bytes.div_ceil(4096) as u32;

    // 1. Allocate DMA-contiguous backing memory.
    let backing = match DmaBuffer::new(pages) {
        Some(b) => b,
        None => {
            sys::print(b"[SCANOUT-VGPU] backing DMA alloc failed\r\n");
            return;
        }
    };
    print_kv(b"[SCANOUT-VGPU] backing pages=", pages as u64);

    // 2. RESOURCE_CREATE_2D.
    let mut cmd = [0u8; 64];
    let cmd_len = build_resource_create_2d(&mut cmd, SCANOUT_RESOURCE_ID,
        VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, setup.width, setup.height) as u32;
    setup.cmd_buf.write(&cmd[..cmd_len as usize]);
    if let Err(e) = submit_nodata(&setup.transport, &mut setup.queue, setup.notify_off,
        &setup.cmd_buf, cmd_len, &setup.resp_buf)
    {
        print_gpu_err(b"RESOURCE_CREATE_2D", e);
        return;
    }

    // 3. RESOURCE_ATTACH_BACKING.
    let mut cmd = [0u8; 64];
    let cmd_len = build_resource_attach_backing_single(&mut cmd,
        SCANOUT_RESOURCE_ID, backing.paddr, frame_bytes as u32) as u32;
    setup.cmd_buf.write(&cmd[..cmd_len as usize]);
    if let Err(e) = submit_nodata(&setup.transport, &mut setup.queue, setup.notify_off,
        &setup.cmd_buf, cmd_len, &setup.resp_buf)
    {
        print_gpu_err(b"RESOURCE_ATTACH_BACKING", e);
        return;
    }

    // 4. SET_SCANOUT — bind the resource to scanout 0.
    let mut cmd = [0u8; 64];
    let cmd_len = build_set_scanout(&mut cmd, SCANOUT_ID, SCANOUT_RESOURCE_ID,
        0, 0, setup.width, setup.height) as u32;
    setup.cmd_buf.write(&cmd[..cmd_len as usize]);
    if let Err(e) = submit_nodata(&setup.transport, &mut setup.queue, setup.notify_off,
        &setup.cmd_buf, cmd_len, &setup.resp_buf)
    {
        print_gpu_err(b"SET_SCANOUT", e);
        return;
    }
    sys::print(b"[SCANOUT-VGPU] virtio-gpu resource bound to scanout 0\r\n");

    // 5. Create the shared-memory channel. role = 1 = Consumer
    // (driver reads, compositor writes) — matches scanout-limine.
    let mut channel_vaddr: u64 = 0;
    let rc = sys::channel_create(pages, &principal, 1, &mut channel_vaddr);
    if rc < 0 {
        print_int(b"[SCANOUT-VGPU] channel_create rc=", rc);
        return;
    }
    let channel_id = rc as u64;

    *binding = Some(CompositorBinding {
        principal,
        reply_endpoint,
        backing,
        channel_id,
        channel_vaddr,
        frame_bytes,
    });
    print_hex(b"[SCANOUT-VGPU] scanout channel id=", channel_id);

    // 6. Send WelcomeCompositor + DisplayConnected.
    let mut reply = [0u8; 16];
    if let Some(n) = encode_welcome_compositor(&mut reply, 0) {
        sys::write(reply_endpoint, &reply[..n]);
    }

    let info = DisplayInfo {
        display_id: 0,
        state: DisplayState::Connected,
        geometry: Geometry {
            width: setup.width,
            height: setup.height,
            pitch,
            bpp: 32,
        },
        backing_scale: 100,
        refresh_hz: 60,
        format: PixelFormat::Xrgb8888,
        capabilities: 0,
        edid_hash: [0; 32],
    };
    let mut reply = [0u8; 128];
    if let Some(n) = encode_display_connected(&mut reply, &info, channel_id) {
        sys::write(reply_endpoint, &reply[..n]);
        sys::print(b"[SCANOUT-VGPU] DisplayConnected sent\r\n");
    }
}

fn handle_frame_ready(
    setup: &mut Setup,
    binding: &mut Option<CompositorBinding>,
    msg: &VerifiedMessage,
) {
    let b = match binding.as_ref() {
        Some(b) => b,
        None => {
            sys::print(b"[SCANOUT-VGPU] FrameReady before RegisterCompositor; dropping\r\n");
            return;
        }
    };
    if msg.sender().as_bytes() != &b.principal {
        sys::print(b"[SCANOUT-VGPU] FrameReady from wrong sender; dropping\r\n");
        return;
    }

    let Some((display_id, seq, _damage_count)) = decode_frame_ready_header(msg.payload()) else {
        sys::print(b"[SCANOUT-VGPU] malformed FrameReady; dropping\r\n");
        return;
    };
    if display_id != 0 {
        return; // single-display driver
    }

    // 1. Copy compositor's channel (RAM) → driver-owned backing (DMA).
    // SAFETY:
    // - channel_vaddr is the driver-side Consumer mapping of a channel
    //   whose size was set to exactly `frame_bytes` at channel_create.
    //   The kernel holds the mapping live until channel_close, which
    //   this driver never calls.
    // - backing.vaddr is our alloc_dma mapping of `backing.size` >=
    //   frame_bytes (we sized the alloc to exactly cover frame_bytes).
    // - Regions do not overlap (distinct kernel mappings).
    #[allow(unsafe_code)]
    unsafe {
        core::ptr::copy_nonoverlapping(
            b.channel_vaddr as *const u8,
            b.backing.vaddr as *mut u8,
            b.frame_bytes,
        );
    }

    // 2. TRANSFER_TO_HOST_2D — device copies backing → host resource.
    let mut cmd = [0u8; 64];
    let cmd_len = build_transfer_to_host_2d(&mut cmd, SCANOUT_RESOURCE_ID,
        0, 0, setup.width, setup.height, 0) as u32;
    setup.cmd_buf.write(&cmd[..cmd_len as usize]);
    if let Err(e) = submit_nodata(&setup.transport, &mut setup.queue, setup.notify_off,
        &setup.cmd_buf, cmd_len, &setup.resp_buf)
    {
        print_gpu_err(b"TRANSFER_TO_HOST_2D", e);
        return;
    }

    // 3. RESOURCE_FLUSH — make the resource visible on the scanout.
    let mut cmd = [0u8; 64];
    let cmd_len = build_resource_flush(&mut cmd, SCANOUT_RESOURCE_ID,
        0, 0, setup.width, setup.height) as u32;
    setup.cmd_buf.write(&cmd[..cmd_len as usize]);
    if let Err(e) = submit_nodata(&setup.transport, &mut setup.queue, setup.notify_off,
        &setup.cmd_buf, cmd_len, &setup.resp_buf)
    {
        print_gpu_err(b"RESOURCE_FLUSH", e);
        return;
    }

    // 4. Ack the compositor.
    let mut reply = [0u8; 24];
    if let Some(n) = encode_frame_displayed(&mut reply, display_id, seq, sys::get_time()) {
        sys::write(b.reply_endpoint, &reply[..n]);
    }
}

// ============================================================================
// PCI discovery helpers
// ============================================================================

fn find_virtio_gpu() -> Option<u32> {
    let mut buf = [0u8; 108];
    for i in 0..32u32 {
        let r = sys::device_info(i, &mut buf);
        if r < 0 {
            break;
        }
        let vendor = u16::from_le_bytes([buf[0], buf[1]]);
        let device = u16::from_le_bytes([buf[2], buf[3]]);
        if vendor == VIRTIO_VENDOR_ID && device == VIRTIO_GPU_DEVICE_ID_MODERN {
            return Some(i);
        }
    }
    None
}

fn bar_phys_size(device_index: u32, bar_index: u8) -> Option<(u64, u64)> {
    if bar_index >= 6 {
        return None;
    }
    let mut buf = [0u8; 108];
    let r = sys::device_info(device_index, &mut buf);
    if r < 0 {
        return None;
    }
    let off = 12 + (bar_index as usize) * 16;
    let addr = u64::from_le_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7],
    ]);
    let size = u32::from_le_bytes([
        buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11],
    ]);
    let is_io = buf[off + 12] != 0;
    if addr == 0 || size == 0 || is_io {
        return None;
    }
    Some((addr, size as u64))
}

fn idle_loop() -> ! {
    loop {
        sys::yield_now();
    }
}

// ============================================================================
// Tiny serial-print helpers (no_std, no alloc, no format!)
// ============================================================================

fn print_init_err(e: transport::InitError) {
    sys::print(b"[SCANOUT-VGPU] transport init failed: ");
    match e {
        transport::InitError::NotModernDevice =>
            sys::print(b"not a virtio-modern device\r\n"),
        transport::InitError::MissingCap =>
            sys::print(b"required cap missing\r\n"),
        transport::InitError::CapsSpanMultipleBars =>
            sys::print(b"caps span multiple BARs (unsupported in 4.b)\r\n"),
        transport::InitError::MapMmioFailed =>
            sys::print(b"sys::map_mmio failed\r\n"),
    }
}

fn print_gpu_err(cmd: &[u8], e: gpu::GpuError) {
    sys::print(b"[SCANOUT-VGPU] ");
    sys::print(cmd);
    sys::print(b" failed: ");
    match e {
        gpu::GpuError::Timeout => sys::print(b"timeout\r\n"),
        gpu::GpuError::DeviceError { resp_type } => {
            sys::print(b"resp_type=");
            print_hex_raw(resp_type as u64);
            sys::print(b"\r\n");
        }
        gpu::GpuError::DmaAlloc => sys::print(b"dma alloc\r\n"),
    }
}

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

fn print_kv(prefix: &[u8], v: u64) {
    sys::print(prefix);
    print_u64_dec(v);
    sys::print(b"\r\n");
}

fn print_hex(prefix: &[u8], v: u64) {
    sys::print(prefix);
    print_hex_raw(v);
    sys::print(b"\r\n");
}

fn print_hex_raw(v: u64) {
    sys::print(b"0x");
    let mut buf = [0u8; 16];
    let mut n = v;
    for i in 0..16 {
        let nib = (n & 0xF) as u8;
        buf[15 - i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        n >>= 4;
    }
    sys::print(&buf);
}

fn print_u64_dec(n: u64) {
    if n == 0 {
        sys::print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut m = n;
    let mut len = 0;
    while m > 0 {
        buf[len] = b'0' + (m % 10) as u8;
        m /= 10;
        len += 1;
    }
    let mut out = [0u8; 20];
    for i in 0..len {
        out[i] = buf[len - 1 - i];
    }
    sys::print(&out[..len]);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"SCANOUT-VGPU", b"panic");
    sys::exit(255);
}
