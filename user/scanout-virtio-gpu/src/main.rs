// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! scanout-virtio-gpu — Phase Scanout-4.a driver (ADR-014).
//!
//! # Scope of 4.a
//!
//! This phase brings the virtio-gpu transport up and proves it works
//! end-to-end against QEMU's virtio-gpu-pci emulation:
//!
//!   1. Find the virtio-gpu PCI device (vendor `0x1AF4`, device `0x1050`).
//!   2. Fetch its virtio-modern capability set via `SYS_VIRTIO_MODERN_CAPS`
//!      (kernel-parsed, ADR-020 `UserWriteSlice` boundary).
//!   3. Map the device's MMIO BAR and build a `ModernTransport` over it.
//!   4. Run the virtio init handshake (reset → ACK → DRIVER → feature
//!      negotiation with `VIRTIO_F_VERSION_1` → FEATURES_OK → queue
//!      setup → DRIVER_OK).
//!   5. Submit `VIRTIO_GPU_CMD_GET_DISPLAY_INFO` on the control queue,
//!      log every enabled scanout's rectangle to the serial console.
//!   6. Idle.
//!
//! # Deliberately NOT in 4.a
//!
//! - Registering `SCANOUT_DRIVER_ENDPOINT = 27`. Doing so would contend
//!   with `scanout-limine` (which takes ep27 at boot today). 4.b switches
//!   the boot manifest so only one scanout driver is present, then adds
//!   endpoint registration + the compositor-protocol frame lifecycle
//!   (`DisplayConnected`, `FrameReady` / `TRANSFER` / `FLUSH`,
//!   `FrameDisplayed`).
//! - Resource creation, scanout buffer attach, transfer/flush path.
//! - Hotplug, EDID, mode change.
//! - aarch64 / riscv64 builds (virtio-gpu-pci on QEMU is x86_64-centric
//!   on CambiOS today; mmio backend would need its own arch gate).
//!
//! # Coexistence with scanout-limine
//!
//! Both drivers are present in the boot manifest during 4.a. Neither
//! fights the other: scanout-limine owns ep27 and drives the compositor
//! path; scanout-virtio-gpu is diagnostic only, probes the hardware,
//! and idles. When 4.b lands we remove scanout-limine from the default
//! boot manifest (or gate it on "-vga std" presence) and scanout-virtio-gpu
//! becomes the real scanout driver.

#![no_std]
#![no_main]
#![deny(unsafe_code)]
// 4.a consumes only a subset of the transport surface (device_cfg /
// device_cfg_vaddr are unused until 4.b introduces virtio-gpu config
// reads). Allow dead code here so the transport's 4.b-facing API
// doesn't force per-field #[allow] noise.
#![allow(dead_code)]

#[allow(unsafe_code)]
mod transport;
#[allow(unsafe_code)]
mod virtqueue;

use arcos_libsys as sys;
use transport::{ModernTransport, STATUS_ACKNOWLEDGE, STATUS_DRIVER,
    STATUS_DRIVER_OK, STATUS_FAILED, STATUS_FEATURES_OK, VIRTIO_F_VERSION_1};
use virtqueue::{DmaBuffer, ModernVirtQueue, Segment};

// ============================================================================
// PCI identifiers + device-specific constants
// ============================================================================

const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_GPU_DEVICE_ID_MODERN: u16 = 0x1050;

/// Control queue index (virtio-gpu spec §5.7).
const VIRTIO_GPU_CONTROLQ: u16 = 0;

/// Command type for GET_DISPLAY_INFO (virtio-gpu spec §5.7.6.1).
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;

/// Successful response type for GET_DISPLAY_INFO.
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

/// Maximum scanouts a virtio-gpu device can report.
const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

/// Size of `virtio_gpu_ctrl_hdr` (virtio-gpu spec §5.7.4).
const CTRL_HDR_SIZE: usize = 24;

/// Size of one `virtio_gpu_display_one` entry in the response.
const DISPLAY_ONE_SIZE: usize = 24;

/// Total size of `virtio_gpu_resp_display_info`: header + 16 entries.
const DISPLAY_INFO_RESP_SIZE: usize = CTRL_HDR_SIZE
    + VIRTIO_GPU_MAX_SCANOUTS * DISPLAY_ONE_SIZE;

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[SCANOUT-VGPU] starting (Phase Scanout-4.a)\r\n");

    // Find the virtio-gpu device. Absence is non-fatal — log it and idle,
    // same shape as virtio-blk's "no device" path so the boot chain
    // continues cleanly.
    let device_index = match find_virtio_gpu() {
        Some(i) => i,
        None => {
            sys::print(b"[SCANOUT-VGPU] no virtio-gpu device found; idling\r\n");
            sys::module_ready();
            idle_loop();
        }
    };
    print_kv(b"[SCANOUT-VGPU] found device index=", device_index as u64);

    // Pull the kernel-parsed modern caps.
    let caps = match sys::virtio_modern_caps(device_index) {
        Some(c) => c,
        None => {
            sys::print(b"[SCANOUT-VGPU] virtio_modern_caps syscall failed\r\n");
            sys::module_ready();
            idle_loop();
        }
    };
    if caps.present == 0 {
        sys::print(b"[SCANOUT-VGPU] device reported no virtio-modern caps\r\n");
        sys::module_ready();
        idle_loop();
    }
    print_cap(b"[SCANOUT-VGPU] common_cfg ", caps.common_cfg.bar,
        caps.common_cfg.offset, caps.common_cfg.length);
    print_cap(b"[SCANOUT-VGPU] notify_cfg ", caps.notify_cfg.bar,
        caps.notify_cfg.offset, caps.notify_cfg.length);
    print_kv(b"[SCANOUT-VGPU] notify_off_multiplier=",
        caps.notify_off_multiplier as u64);
    print_cap(b"[SCANOUT-VGPU] isr_cfg ", caps.isr_cfg.bar,
        caps.isr_cfg.offset, caps.isr_cfg.length);
    print_cap(b"[SCANOUT-VGPU] device_cfg ", caps.device_cfg.bar,
        caps.device_cfg.offset, caps.device_cfg.length);

    // Look up the physical address + size of the BAR the caps reference.
    // `ModernTransport::new` already verified all four caps share a BAR,
    // but we need to pass the right BAR's phys+size — can only know
    // AFTER reading caps.
    let (bar_phys, bar_size) = match bar_phys_size(device_index, caps.common_cfg.bar) {
        Some(pair) => pair,
        None => {
            sys::print(b"[SCANOUT-VGPU] cap-referenced BAR not present on device\r\n");
            sys::module_ready();
            idle_loop();
        }
    };
    print_kv(b"[SCANOUT-VGPU] mapping BAR ", caps.common_cfg.bar as u64);
    print_hex(b"[SCANOUT-VGPU] bar_phys=", bar_phys);
    print_kv(b"[SCANOUT-VGPU] bar_size_bytes=", bar_size);

    // Build the transport, mapping the BAR.
    let transport = match ModernTransport::new(&caps, bar_phys, bar_size) {
        Ok(t) => t,
        Err(e) => {
            print_init_err(e);
            sys::module_ready();
            idle_loop();
        }
    };
    sys::print(b"[SCANOUT-VGPU] transport built, BAR mapped\r\n");

    // Run the virtio init handshake. `init_device` returns the (queue,
    // notify_off) pair on success so we can submit afterwards.
    let (mut queue, notify_off) = match init_device(&transport) {
        Some(pair) => pair,
        None => {
            sys::print(b"[SCANOUT-VGPU] device init failed\r\n");
            sys::module_ready();
            idle_loop();
        }
    };
    sys::print(b"[SCANOUT-VGPU] device DRIVER_OK; controlq ready\r\n");

    // Submit GET_DISPLAY_INFO and log the response.
    match query_display_info(&transport, &mut queue, notify_off) {
        Ok(()) => sys::print(b"[SCANOUT-VGPU] GET_DISPLAY_INFO complete\r\n"),
        Err(msg) => {
            sys::print(b"[SCANOUT-VGPU] GET_DISPLAY_INFO failed: ");
            sys::print(msg);
            sys::print(b"\r\n");
        }
    }

    // 4.a scope ends here — don't register SCANOUT_DRIVER_ENDPOINT.
    // Release the boot gate so downstream modules proceed.
    sys::print(b"[SCANOUT-VGPU] 4.a scope complete; idling\r\n");
    sys::module_ready();
    idle_loop();
}

/// Scan PCI devices for the virtio-gpu-pci device. Returns the device
/// index (into the kernel's device table) so that subsequent syscalls
/// (`SYS_VIRTIO_MODERN_CAPS`, `SYS_DEVICE_INFO`) can query the same
/// device.
///
/// The BAR to map is not chosen here — it is dictated by the caps
/// retrieved via `sys::virtio_modern_caps`, which names a BAR index.
/// Callers use [`bar_phys_size`] to resolve that BAR's physical
/// address and size.
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

/// Look up the physical address and size of BAR `bar_index` on the
/// device at `device_index`. Returns `None` if the BAR is unused,
/// is an I/O BAR (virtio modern uses MMIO only), or the device index
/// is invalid.
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

/// Run the virtio 1.0+ initialization sequence (spec §3.1). Returns
/// the set-up virtqueue + its per-queue notify offset on success.
fn init_device(t: &ModernTransport) -> Option<(ModernVirtQueue, u16)> {
    // 1. Reset.
    t.reset();
    // Spin briefly for the reset to take. QEMU is immediate; hardware
    // may take a few cycles. 32 iterations of a device-status read is
    // generous and bounded.
    for _ in 0..32 {
        if t.status() == 0 {
            break;
        }
    }

    // 2. ACKNOWLEDGE + DRIVER.
    t.set_status_bit(STATUS_ACKNOWLEDGE);
    t.set_status_bit(STATUS_DRIVER);

    // 3. Feature negotiation. For 4.a we need only VIRTIO_F_VERSION_1 —
    // virtio-gpu doesn't require any feature beyond that for
    // GET_DISPLAY_INFO. Bail if the device doesn't offer it.
    let device_features = t.device_features();
    if device_features & VIRTIO_F_VERSION_1 == 0 {
        sys::print(b"[SCANOUT-VGPU] device lacks VIRTIO_F_VERSION_1\r\n");
        t.set_status_bit(STATUS_FAILED);
        return None;
    }
    t.set_driver_features(VIRTIO_F_VERSION_1);

    // 3b. FEATURES_OK must stick — the device acknowledges it understood
    // our feature set. If the bit is clear after the write, renegotiation
    // is expected (we don't — just fail).
    t.set_status_bit(STATUS_FEATURES_OK);
    if t.status() & STATUS_FEATURES_OK == 0 {
        sys::print(b"[SCANOUT-VGPU] device rejected FEATURES_OK\r\n");
        t.set_status_bit(STATUS_FAILED);
        return None;
    }

    // 4. Queue 0 (controlq) setup.
    if t.num_queues() == 0 {
        sys::print(b"[SCANOUT-VGPU] device advertises 0 queues\r\n");
        t.set_status_bit(STATUS_FAILED);
        return None;
    }
    t.select_queue(VIRTIO_GPU_CONTROLQ);
    let device_qsize = t.queue_size();
    if device_qsize == 0 {
        sys::print(b"[SCANOUT-VGPU] controlq size 0\r\n");
        t.set_status_bit(STATUS_FAILED);
        return None;
    }
    // Clamp down to our fixed 16-entry queue (virtqueue::QUEUE_SIZE).
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

    // 5. DRIVER_OK.
    t.set_status_bit(STATUS_DRIVER_OK);
    if t.status() & STATUS_FAILED != 0 {
        sys::print(b"[SCANOUT-VGPU] device set FAILED after DRIVER_OK\r\n");
        return None;
    }

    Some((queue, notify_off))
}

/// Submit `VIRTIO_GPU_CMD_GET_DISPLAY_INFO` and log the scanouts.
fn query_display_info(
    t: &ModernTransport,
    queue: &mut ModernVirtQueue,
    notify_off: u16,
) -> Result<(), &'static [u8]> {
    // Command + response buffers (each under a page → 1 page DMA each).
    let cmd = DmaBuffer::new(1).ok_or(b"cmd DMA alloc failed" as &[u8])?;
    let rsp = DmaBuffer::new(1).ok_or(b"rsp DMA alloc failed" as &[u8])?;

    // Build virtio_gpu_ctrl_hdr: type=GET_DISPLAY_INFO, everything else 0.
    let mut hdr = [0u8; CTRL_HDR_SIZE];
    hdr[0..4].copy_from_slice(&VIRTIO_GPU_CMD_GET_DISPLAY_INFO.to_le_bytes());
    // flags, fence_id, ctx_id, ring_idx, padding — all zero.
    cmd.write(&hdr);

    // Submit (req = device-readable command, rsp = device-writable response).
    let _head = queue.submit_two(
        Segment { paddr: cmd.paddr, len: CTRL_HDR_SIZE as u32, device_writable: false },
        Segment { paddr: rsp.paddr, len: DISPLAY_INFO_RESP_SIZE as u32, device_writable: true },
    );
    t.notify(VIRTIO_GPU_CONTROLQ, notify_off);

    // Poll for completion with yields. QEMU handles synchronously most
    // of the time but may defer to its event loop; cap the wait at a
    // bounded iteration count.
    let mut done = false;
    for _ in 0..500 {
        if queue.poll_used().is_some() {
            done = true;
            break;
        }
        sys::yield_now();
    }
    if !done {
        return Err(b"no completion within 500 yields");
    }

    // Read the response.
    let mut resp_bytes = [0u8; DISPLAY_INFO_RESP_SIZE];
    rsp.read(&mut resp_bytes, DISPLAY_INFO_RESP_SIZE);

    let resp_type = u32::from_le_bytes([
        resp_bytes[0], resp_bytes[1], resp_bytes[2], resp_bytes[3],
    ]);
    if resp_type != VIRTIO_GPU_RESP_OK_DISPLAY_INFO {
        print_kv(b"[SCANOUT-VGPU] bad resp_type=", resp_type as u64);
        return Err(b"response type != OK_DISPLAY_INFO");
    }

    // Walk the 16 display entries. Each display_one = {x, y, w, h, enabled, flags}.
    let mut enabled_count = 0u32;
    for i in 0..VIRTIO_GPU_MAX_SCANOUTS {
        let off = CTRL_HDR_SIZE + i * DISPLAY_ONE_SIZE;
        let x = u32::from_le_bytes([
            resp_bytes[off], resp_bytes[off + 1],
            resp_bytes[off + 2], resp_bytes[off + 3],
        ]);
        let y = u32::from_le_bytes([
            resp_bytes[off + 4], resp_bytes[off + 5],
            resp_bytes[off + 6], resp_bytes[off + 7],
        ]);
        let w = u32::from_le_bytes([
            resp_bytes[off + 8], resp_bytes[off + 9],
            resp_bytes[off + 10], resp_bytes[off + 11],
        ]);
        let h = u32::from_le_bytes([
            resp_bytes[off + 12], resp_bytes[off + 13],
            resp_bytes[off + 14], resp_bytes[off + 15],
        ]);
        let enabled = u32::from_le_bytes([
            resp_bytes[off + 16], resp_bytes[off + 17],
            resp_bytes[off + 18], resp_bytes[off + 19],
        ]);
        if enabled != 0 {
            enabled_count += 1;
            sys::print(b"[SCANOUT-VGPU] scanout ");
            print_u64_dec(i as u64);
            sys::print(b": ");
            print_u64_dec(w as u64);
            sys::print(b"x");
            print_u64_dec(h as u64);
            sys::print(b" @ (");
            print_u64_dec(x as u64);
            sys::print(b",");
            print_u64_dec(y as u64);
            sys::print(b")\r\n");
        }
    }
    print_kv(b"[SCANOUT-VGPU] enabled scanouts: ", enabled_count as u64);
    Ok(())
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
            sys::print(b"caps span multiple BARs (unsupported in 4.a)\r\n"),
        transport::InitError::MapMmioFailed =>
            sys::print(b"sys::map_mmio failed\r\n"),
    }
}

fn print_kv(prefix: &[u8], v: u64) {
    sys::print(prefix);
    print_u64_dec(v);
    sys::print(b"\r\n");
}

fn print_hex(prefix: &[u8], v: u64) {
    sys::print(prefix);
    sys::print(b"0x");
    let mut buf = [0u8; 16];
    let mut n = v;
    for i in 0..16 {
        let nib = (n & 0xF) as u8;
        buf[15 - i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        n >>= 4;
    }
    sys::print(&buf);
    sys::print(b"\r\n");
}

fn print_cap(prefix: &[u8], bar: u8, offset: u32, length: u32) {
    sys::print(prefix);
    sys::print(b"bar=");
    print_u64_dec(bar as u64);
    sys::print(b" offset=");
    print_u64_dec(offset as u64);
    sys::print(b" length=");
    print_u64_dec(length as u64);
    sys::print(b"\r\n");
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
