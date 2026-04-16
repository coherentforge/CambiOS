// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Kernel-side virtio-blk adapter — implements `BlockDevice` by speaking to
//! the user-space `user/virtio-blk` driver over IPC.
//!
//! ## Protocol (mirrors `user/virtio-blk/src/main.rs`)
//!
//! The driver owns the virtio-blk PCI device and the DMA bounce buffers.
//! The kernel delegates every disk I/O by sending a small command message
//! on endpoint 26 (`BLK_KERNEL_CMD_ENDPOINT`). Bulk data flows through a
//! single 4-KiB DMA page that the driver allocates once (at HANDSHAKE) and
//! whose physical address it reports back to the kernel. The kernel
//! accesses that page via the HHDM (`paddr + hhdm_offset`); no syscall,
//! no page-table walk.
//!
//! Completion travels back on endpoint 25 (`BLK_KERNEL_RESP_ENDPOINT`).
//! The kernel uses the same block-task-then-yield pattern as the policy
//! service: block the calling task on `BlockReason::MessageWait(25)`,
//! `yield_save_and_switch`, and on wake dequeue the response.
//!
//! Handshake is performed **lazily** on the first `BlockDevice` call. Boot
//! cannot easily handshake because the user-space driver is not yet running
//! — by the time a `SYS_OBJ_*` syscall arrives, the driver is scheduled and
//! endpoint 26 is live.
//!
//! ## Lock ordering
//!
//! `VirtioBlkDevice` itself uses no internal lock. It is held behind the
//! global `VIRTIO_BLK_DEVICE` spinlock (position 10, below `OBJECT_STORE`).
//! Callers MUST NOT hold `OBJECT_STORE` across a call into this module —
//! the plan/execute decomposition in `DiskObjectStore` (Phase 4a.iii
//! Step 3) is the enforcement point.

use crate::fs::block::{Block, BlockDevice, BlockError, BLOCK_SIZE};
use crate::ipc::{EndpointId, Message};

/// Endpoint IDs — MUST match `user/virtio-blk/src/main.rs`.
const BLK_KERNEL_RESP_ENDPOINT: u32 = 25;
const BLK_KERNEL_CMD_ENDPOINT: u32 = 26;

/// Kernel-only commands on endpoint 26.
const KCMD_HANDSHAKE: u8 = 1;
const KCMD_READ_BLOCK: u8 = 2;
const KCMD_WRITE_BLOCK: u8 = 3;
const KCMD_FLUSH: u8 = 4;
const KCMD_CAPACITY: u8 = 5;

/// Response status values (match the driver's).
const STATUS_OK: u8 = 0;

/// Sector size in the virtio-blk wire protocol (always 512).
const VIRTIO_BLK_SECTOR_SIZE: u64 = 512;

/// SCAFFOLDING: upper bound on yield iterations spent waiting for a single
/// disk I/O completion before giving up.
/// Why: real NVMe/AHCI completes a single I/O in microseconds; 10 000
///      scheduler-quantum yields (≈100 s at 100 Hz) is far more headroom
///      than any healthy request could need, and short enough to fail
///      loudly rather than hang forever if the driver is dead.
/// Replace when: we move to interrupt-driven virtio-blk completion (would
///      remove the polling path entirely).
const MAX_WAIT_ITERATIONS: u32 = 10_000;

/// Kernel-side view of the user-space virtio-blk driver.
pub struct VirtioBlkDevice {
    driver_cmd_endpoint: u32,
    response_endpoint: u32,
    /// Physical address of the driver's shared DMA region. 0 until the
    /// handshake completes.
    shared_region_paddr: u64,
    /// Kernel virtual address for that region (paddr + hhdm_offset).
    shared_region_kvaddr: u64,
    /// Device capacity in 512-byte sectors (learned at handshake).
    capacity_sectors: u64,
    initialized: bool,
}

impl VirtioBlkDevice {
    /// Construct an uninitialized device. Handshake is deferred until the
    /// first `BlockDevice` call happens from a real task context.
    pub fn new() -> Self {
        Self {
            driver_cmd_endpoint: BLK_KERNEL_CMD_ENDPOINT,
            response_endpoint: BLK_KERNEL_RESP_ENDPOINT,
            shared_region_paddr: 0,
            shared_region_kvaddr: 0,
            capacity_sectors: 0,
            initialized: false,
        }
    }

    /// Current capacity in 4-KiB logical blocks. Returns 0 before the
    /// handshake has completed.
    pub fn capacity_blocks_cached(&self) -> u64 {
        self.capacity_sectors / (BLOCK_SIZE as u64 / VIRTIO_BLK_SECTOR_SIZE)
    }

    /// Send `payload` to the driver's kernel endpoint and poll the response
    /// endpoint until a reply arrives or the iteration cap is hit.
    ///
    /// The earlier design used `block_local_task(MessageWait(25))` + yield
    /// (mirroring the policy-router pattern), which requires a matching
    /// `wake_message_waiters(25)` on the send path. That wake — invoked
    /// from `handle_write`'s endpoint-25 intercept — empirically stalled
    /// the virtio-blk driver's own self-test virtqueue polling. Rather
    /// than chase the scheduler-level interaction, we poll with cooperative
    /// yields: simpler, no cross-path wake dependency, and the uncontended
    /// case is one yield round-trip longer at worst.
    ///
    /// Caller contract: must be invoked from a syscall kernel-mode path
    /// where a current task exists on this CPU. Returns `BlockError::NotReady`
    /// if no task context is available (boot-time calls would hit this).
    fn call(&self, payload: &[u8]) -> Result<([u8; 256], usize), BlockError> {
        if payload.is_empty() || payload.len() > 256 {
            return Err(BlockError::DeviceError);
        }

        // 1. Confirm we have a task context — yield_save_and_switch needs it.
        {
            let g = crate::local_scheduler().lock();
            if g.as_ref().and_then(|s| s.current_task()).is_none() {
                return Err(BlockError::NotReady);
            }
        }

        // 2. Build and send the request.
        let mut msg = Message::new(
            EndpointId(self.response_endpoint),
            EndpointId(self.driver_cmd_endpoint),
        );
        if msg.set_payload(payload).is_err() {
            return Err(BlockError::DeviceError);
        }
        if crate::SHARDED_IPC
            .send_message(EndpointId(self.driver_cmd_endpoint), msg)
            .is_err()
        {
            return Err(BlockError::DeviceError);
        }

        // 3. Wake any task blocked on the driver's command endpoint (the
        //    driver's service loop uses `recv_verified(24)` / `recv_msg(26)`
        //    which blocks on `MessageWait` when both queues are empty).
        {
            let cpu_count = crate::online_cpu_count();
            for i in 0..cpu_count {
                if let Some(mut g) = crate::PER_CPU_SCHEDULER[i].try_lock() {
                    if let Some(s) = g.as_mut() {
                        s.wake_message_waiters(self.driver_cmd_endpoint);
                    }
                }
            }
        }

        // 4. Poll the response endpoint with cooperative yields. Each yield
        //    hands the CPU back to the scheduler; when all other tasks
        //    yield/block too, the CPU reaches idle → hlt, which lets the
        //    QEMU-TCG event loop advance the virtio-blk request. Once the
        //    driver replies, the reply lands in `SHARDED_IPC.shard[25]`
        //    via the `handle_write` endpoint-25 intercept.
        for _ in 0..MAX_WAIT_ITERATIONS {
            if let Some(reply) = crate::SHARDED_IPC.recv_message(EndpointId(self.response_endpoint))
            {
                let mut out = [0u8; 256];
                let n = reply.payload_len;
                if n > out.len() {
                    return Err(BlockError::DeviceError);
                }
                out[..n].copy_from_slice(&reply.payload[..n]);
                return Ok((out, n));
            }
            // SAFETY: on kernel stack, no locks held.
            unsafe {
                crate::arch::yield_save_and_switch();
            }
        }
        Err(BlockError::NotReady)
    }

    fn ensure_handshake(&mut self) -> Result<(), BlockError> {
        if self.initialized {
            return Ok(());
        }

        // HANDSHAKE → learn the shared region paddr.
        let (resp, n) = self.call(&[KCMD_HANDSHAKE])?;
        if n < 9 || resp[0] != STATUS_OK {
            return Err(BlockError::DeviceError);
        }
        let mut pb = [0u8; 8];
        pb.copy_from_slice(&resp[1..9]);
        let paddr = u64::from_le_bytes(pb);
        self.shared_region_paddr = paddr;
        self.shared_region_kvaddr = paddr + crate::hhdm_offset();

        // CAPACITY → learn the device capacity in 512-byte sectors.
        let (resp, n) = self.call(&[KCMD_CAPACITY])?;
        if n < 9 || resp[0] != STATUS_OK {
            return Err(BlockError::DeviceError);
        }
        let mut cb = [0u8; 8];
        cb.copy_from_slice(&resp[1..9]);
        self.capacity_sectors = u64::from_le_bytes(cb);

        self.initialized = true;
        Ok(())
    }

    /// Copy `BLOCK_SIZE` bytes from the shared region (via HHDM) into `buf`.
    fn read_shared_region(&self, buf: &mut Block) {
        // SAFETY: `shared_region_kvaddr` is HHDM + paddr, valid as long as
        // `initialized == true`. The DMA region is BLOCK_SIZE bytes and
        // aliases the driver's bounce buffer — no other kernel code maps
        // this paddr. The copy is 4 KiB into a 4 KiB stack-like buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.shared_region_kvaddr as *const u8,
                buf.as_mut_ptr(),
                BLOCK_SIZE,
            );
        }
    }

    /// Copy `buf` into the shared region (via HHDM).
    fn write_shared_region(&self, buf: &Block) {
        // SAFETY: mirror of `read_shared_region`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                self.shared_region_kvaddr as *mut u8,
                BLOCK_SIZE,
            );
        }
    }
}

impl Default for VirtioBlkDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockDevice for VirtioBlkDevice {
    fn capacity_blocks(&self) -> u64 {
        self.capacity_blocks_cached()
    }

    fn read_block(&mut self, lba: u64, buf: &mut Block) -> Result<(), BlockError> {
        self.ensure_handshake()?;
        if lba >= self.capacity_blocks_cached() {
            return Err(BlockError::OutOfBounds);
        }
        let mut req = [0u8; 9];
        req[0] = KCMD_READ_BLOCK;
        req[1..9].copy_from_slice(&lba.to_le_bytes());
        let (resp, n) = self.call(&req)?;
        if n < 1 || resp[0] != STATUS_OK {
            return Err(BlockError::DeviceError);
        }
        self.read_shared_region(buf);
        Ok(())
    }

    fn write_block(&mut self, lba: u64, buf: &Block) -> Result<(), BlockError> {
        self.ensure_handshake()?;
        if lba >= self.capacity_blocks_cached() {
            return Err(BlockError::OutOfBounds);
        }
        self.write_shared_region(buf);
        let mut req = [0u8; 9];
        req[0] = KCMD_WRITE_BLOCK;
        req[1..9].copy_from_slice(&lba.to_le_bytes());
        let (resp, n) = self.call(&req)?;
        if n < 1 || resp[0] != STATUS_OK {
            return Err(BlockError::DeviceError);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.ensure_handshake()?;
        let (resp, n) = self.call(&[KCMD_FLUSH])?;
        if n < 1 || resp[0] != STATUS_OK {
            return Err(BlockError::DeviceError);
        }
        Ok(())
    }
}
