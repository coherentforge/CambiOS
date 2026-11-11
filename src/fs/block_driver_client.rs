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
//! The kernel polls that endpoint with cooperative yields (ADR-010
//! § Divergence 2).
//!
//! ## What the kernel trusts, and how it checks
//!
//! The kernel acts on these replies, so it trusts none of them by
//! endpoint:
//!
//! - **Who may reply.** `handle_write`'s endpoint-25 intercept accepts a
//!   write only from a process whose Principal is the manifest's
//!   reservation owner of endpoint 25 (the block-driver row, ADR-018), and
//!   stamps that Principal on the message. [`call`] checks the stamp again
//!   on receipt.
//! - **Which request a reply answers.** Every request carries a tag from
//!   this client's counter; a reply must echo it. A reply with another tag
//!   is a late answer to a request that already timed out and is dropped.
//!   The reply queue is drained before each send so a reply that arrived
//!   after its timeout cannot be taken for the next request's.
//! - **The shared page.** The handshake reply names a physical address.
//!   The kernel accepts it only if it is page-aligned and lies inside a
//!   DMA run the kernel itself handed the replying process through
//!   `SYS_ALLOC_DMA` (`ProcessTable::owns_dma_range`). Otherwise the kernel
//!   would copy disk blocks to and from an address of the driver's
//!   choosing — any RAM in the machine, through the direct map.
//!
//! The handshake is the constructor: a [`BlockDriverClient`] that exists
//! has a checked shared page and a known capacity. This also fixes where
//! the ownership check runs: [`connect`] takes `PROCESS_TABLE` and
//! `CAPABILITY_MANAGER` (lock positions 7 and 4, one at a time), so it
//! must run with no higher-numbered lock held; both callers build the
//! client before installing it under `OBJECT_STORE`.
//!
//! ## Lock ordering
//!
//! Once connected, the client uses no kernel lock but the IPC shard and
//! the local scheduler. Callers hold `OBJECT_STORE` (position 10) across
//! `read_block` / `write_block` / `flush`; that is the arrangement ADR-010
//! § Divergence 1 records as safe.

use crate::fs::block::{Block, BlockDevice, BlockError, BLOCK_SIZE};
use crate::ipc::{EndpointId, Message, Principal, ProcessId};
use cambios_blk_proto::{
    decode_kernel_reply, decode_u64_data, encode_kernel_request, encode_klba_request,
    BLK_KERNEL_CMD_ENDPOINT, BLK_KERNEL_RESP_ENDPOINT, KCMD_CAPACITY, KCMD_FLUSH, KCMD_HANDSHAKE,
    KCMD_READ_BLOCK, KCMD_WRITE_BLOCK, STATUS_OK,
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

/// A reply the kernel accepted: its status byte and the bytes after the
/// tag. Replies that fail the sender or tag check never become one.
struct Reply {
    status: u8,
    data: [u8; 256],
    data_len: usize,
}

impl Reply {
    fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

/// Kernel-side view of the user-space block driver. Exists only
/// connected: see [`BlockDriverClient::connect`].
pub struct BlockDriverClient {
    /// The Principal every reply must carry — the manifest's reservation
    /// owner of the reply endpoint, read once at connect.
    driver: Principal,
    /// Tag of the next request. One request is in flight at a time, so a
    /// reply is this request's iff its tag matches.
    next_tag: u32,
    /// Physical address of the driver's shared DMA page, checked at
    /// connect against the driver's `SYS_ALLOC_DMA` record.
    shared_region_paddr: u64,
    /// Kernel virtual address for that page (paddr + hhdm_offset).
    shared_region_kvaddr: u64,
    /// Device capacity in 512-byte sectors (learned at connect).
    capacity_sectors: u64,
}

impl BlockDriverClient {
    /// Connect to the block driver: handshake for the shared page, check
    /// the page is the driver's, learn the capacity.
    ///
    /// Caller contract: a syscall kernel-mode path with a current task on
    /// this CPU (the reply wait yields), and **no lock above position 4
    /// held** — this takes `PROCESS_TABLE` (7) and `CAPABILITY_MANAGER`
    /// (4), each alone. Returns `BlockError::NotReady` with no task
    /// context or when the driver does not answer within the budget,
    /// `BlockError::DeviceError` for a refused or unacceptable reply.
    pub fn connect() -> Result<Self, BlockError> {
        // The identity every reply must carry. No reservation means the
        // manifest named no block driver; there is nobody to talk to.
        let owner_aid =
            crate::ipc::endpoint_reservation::ENDPOINT_RESERVATIONS.owner(BLK_KERNEL_RESP_ENDPOINT)
                .ok_or(BlockError::NotReady)?;
        let driver = Principal::from_aid(owner_aid);

        let mut client = Self {
            driver,
            next_tag: 0,
            shared_region_paddr: 0,
            shared_region_kvaddr: 0,
            capacity_sectors: 0,
        };

        // HANDSHAKE → the shared page's physical address, from a sender
        // we then hold to owning it.
        let tag = client.take_tag();
        let (reply, sender_slot) = client.call(tag, &encode_kernel_request(KCMD_HANDSHAKE, tag))?;
        if reply.status != STATUS_OK {
            return Err(BlockError::DeviceError);
        }
        let paddr = decode_u64_data(reply.data()).ok_or(BlockError::DeviceError)?;
        client.check_shared_page(sender_slot, paddr)?;
        client.shared_region_paddr = paddr;
        client.shared_region_kvaddr = paddr + crate::hhdm_offset();

        // CAPACITY → device capacity in 512-byte sectors.
        let tag = client.take_tag();
        let (reply, _) = client.call(tag, &encode_kernel_request(KCMD_CAPACITY, tag))?;
        if reply.status != STATUS_OK {
            return Err(BlockError::DeviceError);
        }
        client.capacity_sectors = decode_u64_data(reply.data()).ok_or(BlockError::DeviceError)?;

        Ok(client)
    }

    /// Current capacity in 4-KiB logical blocks.
    pub fn capacity_blocks_cached(&self) -> u64 {
        self.capacity_sectors / (BLOCK_SIZE as u64 / VIRTIO_BLK_SECTOR_SIZE)
    }

    /// The tag for the next request. Each request takes a fresh one; the
    /// same value is encoded into the request and required of the reply.
    fn take_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        tag
    }

    /// Accept the handshake's physical address only as the sender's own
    /// DMA grant.
    ///
    /// `sender_slot` is the `from` the intercept stamped. Three
    /// self-contained lock-copy-unlocks, none nested: `PROCESS_TABLE` for
    /// the slot's full id (so a later lookup fails if the sender has
    /// exited), `CAPABILITY_MANAGER` to confirm that id is still bound to
    /// the driver's Principal (the slot could have been reused), then
    /// `PROCESS_TABLE` for the grant. Any gap is a refusal, recorded.
    fn check_shared_page(&self, sender_slot: u32, paddr: u64) -> Result<(), BlockError> {
        let accepted = paddr.is_multiple_of(BLOCK_SIZE as u64)
            && self.sender_process(sender_slot).is_some_and(|pid| {
                crate::PROCESS_TABLE
                    .lock()
                    .as_ref()
                    .is_some_and(|pt| pt.owns_dma_range(pid, paddr, BLOCK_SIZE as u64))
            });
        if accepted {
            return Ok(());
        }
        crate::println!(
            "  [blk] handshake refused: shared page {:#x} is not a DMA grant of the driver (slot {})",
            paddr, sender_slot
        );
        if let Some(pid) = self.sender_process(sender_slot) {
            crate::audit::emit(crate::audit::RawAuditEvent::capability_denied(
                pid,
                EndpointId(BLK_KERNEL_RESP_ENDPOINT),
                crate::audit::now(),
                0,
            ));
        }
        Err(BlockError::DeviceError)
    }

    /// The process at `slot`, if it is bound to the driver's Principal.
    fn sender_process(&self, slot: u32) -> Option<ProcessId> {
        let pid = crate::PROCESS_TABLE.lock().as_ref()?.occupant(slot)?;
        let bound = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            cap_guard
                .as_ref()
                .and_then(|cap_mgr| cap_mgr.get_principal(pid).ok())
                .is_some_and(|p| p.aid() == self.driver.aid())
        };
        bound.then_some(pid)
    }

    /// Send `request` (already carrying `tag`) to the driver's kernel
    /// endpoint and poll the reply endpoint for the reply that echoes
    /// `tag`. Returns the reply and the sender's process slot.
    ///
    /// Stale replies (wrong tag) and replies without the driver's stamp
    /// are dropped and the wait continues; the budget bounds the whole
    /// wait, not the wait per reply.
    ///
    /// The wait is poll-with-yield rather than block+wake: see ADR-010
    /// § Divergence 2 for why the wake from the intercept was removed.
    ///
    /// Caller contract: must be invoked from a syscall kernel-mode path
    /// where a current task exists on this CPU. Returns `BlockError::NotReady`
    /// if no task context is available (boot-time calls would hit this).
    fn call(&self, tag: u32, request: &[u8]) -> Result<(Reply, u32), BlockError> {
        if request.is_empty() || request.len() > 256 {
            return Err(BlockError::DeviceError);
        }

        // 1. Confirm we have a task context — yield_save_and_switch needs it.
        {
            let g = crate::local_scheduler().lock();
            if g.as_ref().and_then(|s| s.current_task()).is_none() {
                return Err(BlockError::NotReady);
            }
        }

        // 2. Nothing queued on the reply endpoint is this request's: the
        //    kernel is the only consumer and nothing is in flight.
        crate::SHARDED_IPC.clear_endpoint(EndpointId(BLK_KERNEL_RESP_ENDPOINT));

        // 3. Build and send the request.
        let mut msg = Message::new(
            EndpointId(BLK_KERNEL_RESP_ENDPOINT),
            EndpointId(BLK_KERNEL_CMD_ENDPOINT),
        );
        if msg.set_payload(request).is_err() {
            return Err(BlockError::DeviceError);
        }
        if crate::SHARDED_IPC
            .send_message(EndpointId(BLK_KERNEL_CMD_ENDPOINT), msg)
            .is_err()
        {
            return Err(BlockError::DeviceError);
        }

        // 4. Wake any task blocked on the driver's command endpoint (the
        //    driver's service loop uses `recv_verified(24)` / `recv_msg(26)`
        //    which blocks on `MessageWait` when both queues are empty).
        //    Plain-lock all-CPU wake — the prior try_lock loop could
        //    silently skip a contended scheduler, losing the wake (see
        //    wake_message_waiters_all_cpus). Syscall context, no lock held.
        crate::wake_message_waiters_all_cpus(BLK_KERNEL_CMD_ENDPOINT);

        // 5. Poll the reply endpoint with cooperative yields, bounded by
        //    wall clock (`BLOCK_IO_TIMEOUT_TICKS`) with an iteration
        //    backstop. Each yield hands the CPU back to the scheduler; the
        //    driver (polling both ep24 and ep26 via SYS_TRY_RECV_MSG) picks
        //    up the command, sends the reply to ep25 via handle_write's
        //    intercept, and our next recv_message call finds it.
        let start_tick = crate::scheduler::Timer::get_ticks();
        let mut polls: u32 = 0;
        loop {
            if let Some(reply) =
                crate::SHARDED_IPC.recv_message(EndpointId(BLK_KERNEL_RESP_ENDPOINT))
            {
                if let Some(accepted) = self.accept(&reply, tag) {
                    return Ok((accepted, reply.from.0));
                }
                // Not ours: a stale reply or an unstamped one. Keep waiting.
            }
            polls += 1;
            if polls >= MAX_WAIT_ITERATIONS
                || crate::scheduler::Timer::get_ticks().wrapping_sub(start_tick)
                    >= BLOCK_IO_TIMEOUT_TICKS
            {
                return Err(BlockError::NotReady);
            }
            // SAFETY: on kernel stack, no locks held.
            unsafe {
                crate::arch::yield_save_and_switch();
            }
        }
    }

    /// The reply if it carries the driver's stamp and answers `tag`.
    fn accept(&self, reply: &Message, tag: u32) -> Option<Reply> {
        let stamped = reply
            .sender_principal
            .as_ref()
            .is_some_and(|p| p.aid() == self.driver.aid());
        if !stamped {
            return None;
        }
        let n = reply.payload_len.min(reply.payload.len());
        let decoded = decode_kernel_reply(&reply.payload[..n])?;
        if decoded.tag != tag {
            return None;
        }
        let mut data = [0u8; 256];
        let data_len = decoded.data.len();
        data[..data_len].copy_from_slice(decoded.data);
        Some(Reply { status: decoded.status, data, data_len })
    }

    /// Copy `BLOCK_SIZE` bytes from the shared page (via HHDM) into `buf`.
    fn read_shared_region(&self, buf: &mut Block) {
        // SAFETY: `shared_region_kvaddr` is HHDM + `shared_region_paddr`,
        // and `connect` accepted that paddr only as a page-aligned address
        // inside a `SYS_ALLOC_DMA` run the kernel allocated to the block
        // driver: RAM, in the direct map, not kernel memory. The run is at
        // least BLOCK_SIZE from paddr, so the 4 KiB read stays inside it.
        // `buf` is a distinct 4 KiB kernel buffer, so the ranges do not
        // overlap. The frames stay allocated while the driver lives; see
        // the note on `write_shared_region` about a driver exit.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.shared_region_kvaddr as *const u8,
                buf.as_mut_ptr(),
                BLOCK_SIZE,
            );
        }
    }

    /// Copy `buf` into the shared page (via HHDM).
    fn write_shared_region(&self, buf: &Block) {
        // Deferred: a block-driver exit frees the shared frame while this
        // client, installed under OBJECT_STORE, keeps its address.
        // Revisit when: init restarts a block-driver row (ADR-019 restart
        // for the block seam).
        // Why: the next copy would land in whatever the frame allocator
        // hands out next, but re-checking ownership here would take
        // PROCESS_TABLE under OBJECT_STORE (an inversion); the check needs
        // a lock-free signal from the reaper. Today a driver exit also
        // leaves every request timing out, so the seam is unusable after
        // one either way.
        //
        // SAFETY: mirror of `read_shared_region`: the destination is the
        // checked DMA page, BLOCK_SIZE bytes of it; `buf` is a distinct
        // kernel buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                self.shared_region_kvaddr as *mut u8,
                BLOCK_SIZE,
            );
        }
    }

    /// One tagged status-only command (read / write / flush).
    fn command(&self, tag: u32, request: &[u8]) -> Result<(), BlockError> {
        let (reply, _) = self.call(tag, request)?;
        if reply.status != STATUS_OK {
            return Err(BlockError::DeviceError);
        }
        Ok(())
    }
}

impl BlockDevice for BlockDriverClient {
    fn capacity_blocks(&self) -> u64 {
        self.capacity_blocks_cached()
    }

    fn read_block(&mut self, lba: u64, buf: &mut Block) -> Result<(), BlockError> {
        if lba >= self.capacity_blocks_cached() {
            return Err(BlockError::OutOfBounds);
        }
        let tag = self.take_tag();
        self.command(tag, &encode_klba_request(KCMD_READ_BLOCK, tag, lba))?;
        self.read_shared_region(buf);
        Ok(())
    }

    fn write_block(&mut self, lba: u64, buf: &Block) -> Result<(), BlockError> {
        if lba >= self.capacity_blocks_cached() {
            return Err(BlockError::OutOfBounds);
        }
        self.write_shared_region(buf);
        let tag = self.take_tag();
        self.command(tag, &encode_klba_request(KCMD_WRITE_BLOCK, tag, lba))
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        let tag = self.take_tag();
        self.command(tag, &encode_kernel_request(KCMD_FLUSH, tag))
    }
}
