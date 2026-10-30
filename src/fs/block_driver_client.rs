// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kernel-side client of the block-driver IPC seam — implements
//! `BlockDevice` by speaking to whichever user-space block driver the
//! manifest profile spawned (virtio-blk under QEMU, nvme on the Dell,
//! ahci on SATA machines). The seam's bytes are `cambios-blk-proto`.
//!
//! ## Protocol
//!
//! The driver owns the PCI device and the DMA bounce buffers.
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
//! `BlockDriverClient` itself uses no internal lock. It is held behind the
//! global `BLOCK_DRIVER_CLIENT` spinlock (position 10, below `OBJECT_STORE`).
//! Callers MUST NOT hold `OBJECT_STORE` across a call into this module —
//! the plan/execute decomposition in `DiskObjectStore` is the enforcement
//! point.

use crate::fs::block::{Block, BlockDevice, BlockError, BLOCK_SIZE};
use crate::ipc::{EndpointId, Message};
use cambios_blk_proto::{
    BLK_KERNEL_CMD_ENDPOINT, BLK_KERNEL_RESP_ENDPOINT, KCMD_CAPACITY, KCMD_FLUSH,
    KCMD_HANDSHAKE, KCMD_READ_BLOCK, KCMD_WRITE_BLOCK, STATUS_OK,
};

/// Sector size on the wire (always 512; `cambios_blk_proto::SECTOR_SIZE`).
const VIRTIO_BLK_SECTOR_SIZE: u64 = cambios_blk_proto::SECTOR_SIZE as u64;

/// TUNING: wall-clock budget for one block request (command sent, reply
/// read) — 5 s at 100 Hz. A healthy device answers in microseconds to
/// milliseconds; QEMU's NVMe model completes asynchronously and under TCG
/// a round trip can take tens of ms. The wait is measured in ticks, not
/// yields: a `yield_save_and_switch` on an idle CPU returns in
/// microseconds, so the old "10 000 yields" budget (meant as ~100 s) was
/// ~10 ms in practice and expired under the first NVMe round trip that
/// did not complete synchronously (QEMU, 2026-10-30 — the same lesson
/// usb-host learned on the Dell).
const BLOCK_IO_TIMEOUT_TICKS: u64 = 500;

/// ARCHITECTURAL: the poll loop is finite even with a stuck clock; the
/// tick budget is what normally ends a wait. 10^7 polls is minutes on
/// any hardware.
const MAX_WAIT_ITERATIONS: u32 = 10_000_000;

/// Kernel-side view of the user-space virtio-blk driver.
pub struct BlockDriverClient {
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

impl BlockDriverClient {
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
        //    Plain-lock all-CPU wake — the prior try_lock loop could
        //    silently skip a contended scheduler, losing the wake (see
        //    wake_message_waiters_all_cpus). Syscall context, no lock held.
        crate::wake_message_waiters_all_cpus(self.driver_cmd_endpoint);

        // 4. Poll the response endpoint with cooperative yields, bounded by
        //    wall clock (`BLOCK_IO_TIMEOUT_TICKS`) with an iteration
        //    backstop. Each yield hands the CPU back to the scheduler; the
        //    driver (polling both ep24 and ep26 via SYS_TRY_RECV_MSG) picks
        //    up the command, sends the reply to ep25 via handle_write's
        //    intercept, and our next recv_message call finds it.
        let start_tick = crate::scheduler::Timer::get_ticks();
        let mut polls: u32 = 0;
        loop {
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
            polls += 1;
            if polls >= MAX_WAIT_ITERATIONS
                || crate::scheduler::Timer::get_ticks().wrapping_sub(start_tick) >= BLOCK_IO_TIMEOUT_TICKS
            {
                return Err(BlockError::NotReady);
            }
            // SAFETY: on kernel stack, no locks held.
            unsafe {
                crate::arch::yield_save_and_switch();
            }
        }
    }

    pub fn ensure_handshake(&mut self) -> Result<(), BlockError> {
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

impl Default for BlockDriverClient {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockDevice for BlockDriverClient {
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
