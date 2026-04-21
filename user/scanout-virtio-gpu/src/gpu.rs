// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! virtio-gpu command layouts + submit-and-wait helper (virtio spec §5.7).
//!
//! Each command is built into a DMA-backed byte buffer, submitted on the
//! controlq as a two-descriptor chain (command + response), and the
//! 24-byte response header is inspected for success.
//!
//! 4.b commands:
//!
//! | Name                       | Type   | Request bytes | Response bytes |
//! |----------------------------|--------|---------------|----------------|
//! | GET_DISPLAY_INFO           | 0x0100 | 24            | 408            |
//! | RESOURCE_CREATE_2D         | 0x0101 | 40            | 24             |
//! | RESOURCE_ATTACH_BACKING    | 0x0106 | 32 + 16×N     | 24             |
//! | SET_SCANOUT                | 0x0103 | 48            | 24             |
//! | TRANSFER_TO_HOST_2D        | 0x0105 | 56            | 24             |
//! | RESOURCE_FLUSH             | 0x0104 | 48            | 24             |

use arcos_libsys as sys;

use crate::transport::ModernTransport;
use crate::virtqueue::{DmaBuffer, ModernVirtQueue, Segment};

// ============================================================================
// virtio-gpu control header (24 bytes — every command starts with this)
// ============================================================================

pub const CTRL_HDR_SIZE: usize = 24;

// ── Command types ──

pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

// ── Response types ──

pub const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

// ── Pixel formats (virtio spec §5.7.4) ──
//
// Compositor writes Xrgb8888 — bytes in memory are [B, G, R, X] per
// pixel, which matches virtio-gpu's B8G8R8X8_UNORM. Format 2 is the
// standard choice for modern virtio-gpu backends.

pub const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;

/// Maximum scanouts virtio-gpu can advertise.
pub const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

/// Write a virtio_gpu_ctrl_hdr into `buf[0..24]`. Non-fence commands
/// leave flags / fence_id / ctx_id / ring_idx all zero.
fn write_hdr(buf: &mut [u8], cmd_type: u32) {
    buf[0..4].copy_from_slice(&cmd_type.to_le_bytes());
    // 4..24 stays zero (flags, fence_id, ctx_id, ring_idx, padding).
    for b in buf[4..CTRL_HDR_SIZE].iter_mut() {
        *b = 0;
    }
}

// ============================================================================
// Command builders — return the number of bytes written to `buf`.
// ============================================================================

/// `GET_DISPLAY_INFO` — header only (24 B). Response is
/// `virtio_gpu_resp_display_info`: 24 B header + 16 × 24 B per-display
/// entries = 408 B total.
pub fn build_get_display_info(buf: &mut [u8]) -> usize {
    write_hdr(buf, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    CTRL_HDR_SIZE
}

/// `RESOURCE_CREATE_2D` — allocates a host-side 2D resource of
/// `(width, height, format)` and tags it with `resource_id`.
/// Layout: `[hdr:24][resource_id:4][format:4][width:4][height:4]` = 40 B.
pub fn build_resource_create_2d(
    buf: &mut [u8],
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
) -> usize {
    write_hdr(buf, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
    buf[24..28].copy_from_slice(&resource_id.to_le_bytes());
    buf[28..32].copy_from_slice(&format.to_le_bytes());
    buf[32..36].copy_from_slice(&width.to_le_bytes());
    buf[36..40].copy_from_slice(&height.to_le_bytes());
    40
}

/// `RESOURCE_ATTACH_BACKING` — attaches guest memory at `phys_addr`
/// (`length` bytes, physically contiguous so one mem_entry suffices)
/// as the backing store for `resource_id`.
/// Layout: `[hdr:24][resource_id:4][nr_entries:4][mem_entry:16]` = 48 B.
pub fn build_resource_attach_backing_single(
    buf: &mut [u8],
    resource_id: u32,
    phys_addr: u64,
    length: u32,
) -> usize {
    write_hdr(buf, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    buf[24..28].copy_from_slice(&resource_id.to_le_bytes());
    buf[28..32].copy_from_slice(&1u32.to_le_bytes()); // nr_entries
    // virtio_gpu_mem_entry: {addr:u64, length:u32, padding:u32}
    buf[32..40].copy_from_slice(&phys_addr.to_le_bytes());
    buf[40..44].copy_from_slice(&length.to_le_bytes());
    buf[44..48].copy_from_slice(&0u32.to_le_bytes()); // padding
    48
}

/// `SET_SCANOUT` — binds `resource_id` to `scanout_id` covering
/// rectangle `(x, y, w, h)`.
/// Layout: `[hdr:24][rect: x,y,w,h (4×4)][scanout_id:4][resource_id:4]` = 48 B.
pub fn build_set_scanout(
    buf: &mut [u8],
    scanout_id: u32,
    resource_id: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> usize {
    write_hdr(buf, VIRTIO_GPU_CMD_SET_SCANOUT);
    buf[24..28].copy_from_slice(&x.to_le_bytes());
    buf[28..32].copy_from_slice(&y.to_le_bytes());
    buf[32..36].copy_from_slice(&width.to_le_bytes());
    buf[36..40].copy_from_slice(&height.to_le_bytes());
    buf[40..44].copy_from_slice(&scanout_id.to_le_bytes());
    buf[44..48].copy_from_slice(&resource_id.to_le_bytes());
    48
}

/// `TRANSFER_TO_HOST_2D` — copies the backing region at `offset`
/// bytes (length inferred from rect × bpp) into the host resource.
/// Layout: `[hdr:24][rect:16][offset:8][resource_id:4][padding:4]` = 56 B.
pub fn build_transfer_to_host_2d(
    buf: &mut [u8],
    resource_id: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    offset: u64,
) -> usize {
    write_hdr(buf, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
    buf[24..28].copy_from_slice(&x.to_le_bytes());
    buf[28..32].copy_from_slice(&y.to_le_bytes());
    buf[32..36].copy_from_slice(&width.to_le_bytes());
    buf[36..40].copy_from_slice(&height.to_le_bytes());
    buf[40..48].copy_from_slice(&offset.to_le_bytes());
    buf[48..52].copy_from_slice(&resource_id.to_le_bytes());
    buf[52..56].copy_from_slice(&0u32.to_le_bytes()); // padding
    56
}

/// `RESOURCE_FLUSH` — notifies the device to scan out the rectangle
/// of `resource_id` — i.e., make it visible on its bound scanout.
/// Layout: `[hdr:24][rect:16][resource_id:4][padding:4]` = 48 B.
pub fn build_resource_flush(
    buf: &mut [u8],
    resource_id: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> usize {
    write_hdr(buf, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
    buf[24..28].copy_from_slice(&x.to_le_bytes());
    buf[28..32].copy_from_slice(&y.to_le_bytes());
    buf[32..36].copy_from_slice(&width.to_le_bytes());
    buf[36..40].copy_from_slice(&height.to_le_bytes());
    buf[40..44].copy_from_slice(&resource_id.to_le_bytes());
    buf[44..48].copy_from_slice(&0u32.to_le_bytes()); // padding
    48
}

// ============================================================================
// Submit-and-wait helper
// ============================================================================

/// Errors from a single command round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuError {
    /// Device never produced a used-ring entry within the yield budget.
    Timeout,
    /// Response type was in the error range (0x1200..) or otherwise
    /// not the expected success type.
    DeviceError { resp_type: u32 },
    /// DMA buffer alloc failed.
    DmaAlloc,
}

pub const VGPU_CONTROLQ: u16 = 0;

/// SCAFFOLDING: poll iteration budget for a single command completion.
/// Virtio-gpu handles commands synchronously in QEMU TCG (one tick),
/// but the cost of overshooting is milliseconds of wasted yields, not
/// correctness. 2000 yields @ 10ms/tick caps the wait at 20s which
/// is enough to survive a QEMU pause/resume without spurious timeout.
/// Replace when: a real-hardware backend shows a queue latency
/// distribution where 2000 yields is either wasteful (lower bound) or
/// insufficient (higher bound).
pub const COMMAND_WAIT_BUDGET: u32 = 2000;

/// Issue a command that expects a 24-byte no-data response. Returns
/// `Ok(())` iff the response header's type is `VIRTIO_GPU_RESP_OK_NODATA`.
/// `cmd_buf` and `cmd_len` describe the built command buffer;
/// `resp_buf` is the 24-byte response DMA buffer.
pub fn submit_nodata(
    transport: &ModernTransport,
    queue: &mut ModernVirtQueue,
    notify_off: u16,
    cmd_buf: &DmaBuffer,
    cmd_len: u32,
    resp_buf: &DmaBuffer,
) -> Result<(), GpuError> {
    queue.submit_two(
        Segment { paddr: cmd_buf.paddr, len: cmd_len, device_writable: false },
        Segment { paddr: resp_buf.paddr, len: CTRL_HDR_SIZE as u32, device_writable: true },
    );
    transport.notify(VGPU_CONTROLQ, notify_off);

    for _ in 0..COMMAND_WAIT_BUDGET {
        if queue.poll_used().is_some() {
            // Inspect response header type.
            let mut hdr = [0u8; CTRL_HDR_SIZE];
            resp_buf.read(&mut hdr, CTRL_HDR_SIZE);
            let resp_type = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
            if resp_type == VIRTIO_GPU_RESP_OK_NODATA {
                return Ok(());
            } else {
                return Err(GpuError::DeviceError { resp_type });
            }
        }
        sys::yield_now();
    }
    Err(GpuError::Timeout)
}

/// Issue GET_DISPLAY_INFO and copy the 408-byte response into `out`.
/// `out.len()` must be ≥ `CTRL_HDR_SIZE + VIRTIO_GPU_MAX_SCANOUTS * 24` = 408.
pub fn submit_get_display_info(
    transport: &ModernTransport,
    queue: &mut ModernVirtQueue,
    notify_off: u16,
    cmd_buf: &DmaBuffer,
    resp_buf: &DmaBuffer,
    out: &mut [u8],
) -> Result<(), GpuError> {
    const RESP_SIZE: usize = CTRL_HDR_SIZE + VIRTIO_GPU_MAX_SCANOUTS * 24; // 408
    if out.len() < RESP_SIZE {
        return Err(GpuError::DeviceError { resp_type: 0 });
    }

    let cmd_len = build_get_display_info(&mut [0u8; CTRL_HDR_SIZE]) as u32;
    // Re-build into the DMA buffer (build_get_display_info returned len
    // only as a check above — do the real write now).
    let mut tmp = [0u8; CTRL_HDR_SIZE];
    build_get_display_info(&mut tmp);
    cmd_buf.write(&tmp);

    queue.submit_two(
        Segment { paddr: cmd_buf.paddr, len: cmd_len, device_writable: false },
        Segment { paddr: resp_buf.paddr, len: RESP_SIZE as u32, device_writable: true },
    );
    transport.notify(VGPU_CONTROLQ, notify_off);

    for _ in 0..COMMAND_WAIT_BUDGET {
        if queue.poll_used().is_some() {
            resp_buf.read(out, RESP_SIZE);
            let resp_type = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
            if resp_type == VIRTIO_GPU_RESP_OK_DISPLAY_INFO {
                return Ok(());
            } else {
                return Err(GpuError::DeviceError { resp_type });
            }
        }
        sys::yield_now();
    }
    Err(GpuError::Timeout)
}
