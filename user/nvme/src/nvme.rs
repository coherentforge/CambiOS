// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! NVMe controller: bring-up per NVMe 1.4 § 7.6.1, Identify, one I/O
//! queue pair, and 4 KiB block reads/writes with polled completions.
//!
//! Everything here is register and queue bookkeeping over the DMA pages
//! and the mapped BAR in `dma.rs`; no `unsafe` of its own. One command
//! is outstanding at a time (the kernel's block client is serial), so a
//! completion is matched by command ID and anything else is a fault.

use crate::dma::{DmaPage, Mmio};
use cambios_libsys::Deadline;

// ---------------------------------------------------------------------------
// Register map (NVMe 1.4 § 3.1) — HARDWARE
// ---------------------------------------------------------------------------

const REG_CAP: u64 = 0x00;
const REG_VS: u64 = 0x08;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1C;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;
/// HARDWARE: doorbell registers start at 0x1000; SQ y tail at
/// `0x1000 + (2y) * stride`, CQ y head at `0x1000 + (2y + 1) * stride`,
/// stride = `4 << CAP.DSTRD`.
const DOORBELL_BASE: u64 = 0x1000;

const CC_EN: u32 = 1 << 0;
/// CC.IOSQES = 6 (64-byte submission entries), CC.IOCQES = 4 (16-byte
/// completion entries); CSS = 0 (NVM command set), MPS = 0 (4 KiB), AMS = 0.
const CC_QUEUE_ENTRY_SIZES: u32 = (6 << 16) | (4 << 20);
const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;

const ADMIN_CREATE_IO_SQ: u8 = 0x01;
const ADMIN_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const NVM_FLUSH: u8 = 0x00;
const NVM_WRITE: u8 = 0x01;
const NVM_READ: u8 = 0x02;
const CNS_NAMESPACE: u32 = 0x00;
const CNS_CONTROLLER: u32 = 0x01;

const SQE_BYTES: usize = 64;
const CQE_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// TUNING: admin queue depth. Bring-up issues four admin commands, one at
/// a time; 16 entries (1 KiB of a 4 KiB page) is headroom, not a need.
const ADMIN_QUEUE_DEPTH: u16 = 16;
/// TUNING: I/O queue depth. The kernel's block client has one request in
/// flight, so depth trades nothing today; 32 entries (2 KiB SQ, 512 B CQ)
/// fit one page each and leave room for a future multi-request client.
const IO_QUEUE_DEPTH: u16 = 32;
/// TUNING: ticks a single command may take before the controller is
/// declared dead — 1 s at 100 Hz; a healthy NVMe completes in
/// microseconds. Enable/disable waits use CAP.TO instead.
const COMMAND_TIMEOUT_TICKS: u64 = 100;
/// SCAFFOLDING: the driver serves namespace 1 only.
/// Why: every consumer target (QEMU `-device nvme`, the Dell 3630's
///      drive) exposes exactly one namespace, and the block seam has one
///      capacity.
/// Replace when: a target drive reports more than one active namespace.
const NSID: u32 = 1;
/// HARDWARE: Identify data structures are 4096 bytes (NVMe 1.4 § 5.15.2) —
/// exactly one DMA page, which is why `_identify` is a single `DmaPage`.
const IDENTIFY_BYTES: usize = 4096;
const _: () = assert!(IDENTIFY_BYTES == DmaPage::SIZE);
/// HARDWARE: CAP.TO is in 500 ms units; at 100 Hz that is 50 ticks each.
const CAP_TO_UNIT_TICKS: u64 = 50;

/// What went wrong, for the boot log and the status byte on the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeError {
    /// A DMA page could not be allocated.
    Alloc,
    /// The controller never reached the requested ready state, or a
    /// command never completed, within its budget.
    Timeout,
    /// CSTS.CFS: the controller declared a fatal status.
    Fatal,
    /// The controller or namespace is shaped in a way this driver does
    /// not speak (no NVM command set, page size, LBA size).
    Unsupported,
    /// A completion carried a non-zero status field (SCT:SC in bits 14:0).
    Status(u16),
    /// A completion arrived for a command ID we did not issue.
    StrayCompletion,
}

/// A 64-byte submission queue entry under construction.
struct Command {
    dw: [u32; 16],
}

impl Command {
    fn new(opcode: u8, nsid: u32, cid: u16) -> Self {
        let mut dw = [0u32; 16];
        dw[0] = opcode as u32 | ((cid as u32) << 16);
        dw[1] = nsid;
        Command { dw }
    }
    fn prp1(mut self, paddr: u64) -> Self {
        self.dw[6] = paddr as u32;
        self.dw[7] = (paddr >> 32) as u32;
        self
    }
    fn cdw10(mut self, v: u32) -> Self {
        self.dw[10] = v;
        self
    }
    fn cdw11(mut self, v: u32) -> Self {
        self.dw[11] = v;
        self
    }
    fn cdw12(mut self, v: u32) -> Self {
        self.dw[12] = v;
        self
    }
}

/// One submission/completion queue pair, each in its own DMA page.
struct Queue {
    qid: u16,
    depth: u16,
    sq: DmaPage,
    cq: DmaPage,
    sq_tail: u16,
    cq_head: u16,
    /// Expected phase bit of the next valid completion; starts at 1 on
    /// zeroed memory and flips at every wrap.
    phase: bool,
    next_cid: u16,
}

impl Queue {
    fn new(qid: u16, depth: u16) -> Result<Self, NvmeError> {
        let sq = DmaPage::new().ok_or(NvmeError::Alloc)?;
        let cq = DmaPage::new().ok_or(NvmeError::Alloc)?;
        Ok(Queue { qid, depth, sq, cq, sq_tail: 0, cq_head: 0, phase: true, next_cid: 1 })
    }

    fn sq_doorbell(&self, stride: u64) -> u64 {
        DOORBELL_BASE + (2 * self.qid as u64) * stride
    }

    fn cq_doorbell(&self, stride: u64) -> u64 {
        DOORBELL_BASE + (2 * self.qid as u64 + 1) * stride
    }

    /// Write the entry at the tail, ring the doorbell, return the CID.
    fn submit(&mut self, regs: &Mmio, stride: u64, mut cmd: Command) -> u16 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        cmd.dw[0] = (cmd.dw[0] & 0xFFFF) | ((cid as u32) << 16);
        let base = self.sq_tail as usize * SQE_BYTES;
        for (i, dword) in cmd.dw.iter().enumerate() {
            self.sq.write_u32(base + i * 4, *dword);
        }
        self.sq_tail += 1;
        if self.sq_tail == self.depth {
            self.sq_tail = 0;
        }
        regs.write32(self.sq_doorbell(stride), self.sq_tail as u32);
        cid
    }

    /// Poll for the completion of `cid`. Returns completion dword 0.
    fn wait(&mut self, regs: &Mmio, stride: u64, cid: u16, budget_ticks: u64) -> Result<u32, NvmeError> {
        let mut deadline = Deadline::for_ticks(budget_ticks);
        loop {
            let entry = self.cq_head as usize * CQE_BYTES;
            let dw3 = self.cq.read_u32(entry + 12);
            let phase_bit = (dw3 >> 16) & 1 == 1;
            if phase_bit == self.phase {
                let dw0 = self.cq.read_u32(entry);
                let got_cid = (dw3 & 0xFFFF) as u16;
                let status = ((dw3 >> 17) & 0x7FFF) as u16;
                self.cq_head += 1;
                if self.cq_head == self.depth {
                    self.cq_head = 0;
                    self.phase = !self.phase;
                }
                regs.write32(self.cq_doorbell(stride), self.cq_head as u32);
                if got_cid != cid {
                    return Err(NvmeError::StrayCompletion);
                }
                return if status == 0 { Ok(dw0) } else { Err(NvmeError::Status(status)) };
            }
            if regs.read32(REG_CSTS) & CSTS_CFS != 0 {
                return Err(NvmeError::Fatal);
            }
            if !deadline.tick() {
                return Err(NvmeError::Timeout);
            }
            cambios_libsys::yield_now();
        }
    }
}

/// A brought-up controller with namespace 1 identified and one I/O
/// queue pair live.
pub struct Controller {
    regs: Mmio,
    stride: u64,
    admin: Queue,
    io: Queue,
    /// Identify buffer, kept for the controller's lifetime (4 KiB).
    _identify: DmaPage,
    /// Bytes per LBA (512 or 4096 — anything else is `Unsupported`).
    pub lba_bytes: u32,
    /// Namespace size in LBAs.
    pub nsze: u64,
    /// LBAs per 4 KiB kernel block.
    lbas_per_block: u64,
    /// Model number string (Identify Controller bytes 24..64), space padded.
    pub model: [u8; 40],
    /// Controller version register, for the boot log.
    pub version: u32,
    /// Set after a timeout or fatal status; every later request is
    /// refused with `STATUS_DEVICE_DEAD` rather than retried.
    pub dead: bool,
}

impl Controller {
    pub fn init(regs: Mmio) -> Result<Self, NvmeError> {
        let cap = regs.read64(REG_CAP);
        let mqes = ((cap & 0xFFFF) as u16).saturating_add(1);
        let to_ticks = (((cap >> 24) & 0xFF) as u64 + 1) * CAP_TO_UNIT_TICKS;
        let dstrd = ((cap >> 32) & 0xF) as u32;
        let stride = 4u64 << dstrd;
        let css = (cap >> 37) & 0xFF;
        let mpsmin = (cap >> 48) & 0xF;
        if css & 1 == 0 || mpsmin != 0 {
            // No NVM command set, or a minimum page larger than 4 KiB.
            return Err(NvmeError::Unsupported);
        }
        let version = regs.read32(REG_VS);

        // Step 1: make sure the controller is disabled before touching
        // the admin queue registers (firmware may have left it enabled).
        let cc = regs.read32(REG_CC);
        if cc & CC_EN != 0 {
            regs.write32(REG_CC, cc & !CC_EN);
        }
        wait_csts(&regs, CSTS_RDY, false, to_ticks)?;

        // Step 2: admin queues.
        let admin_depth = ADMIN_QUEUE_DEPTH.min(mqes).max(2);
        let admin = Queue::new(0, admin_depth)?;
        let aqa = ((admin_depth as u32 - 1) << 16) | (admin_depth as u32 - 1);
        regs.write32(REG_AQA, aqa);
        regs.write64(REG_ASQ, admin.sq.paddr);
        regs.write64(REG_ACQ, admin.cq.paddr);

        // Step 3: enable with the NVM command set, 4 KiB pages, and our
        // entry sizes; wait for RDY.
        regs.write32(REG_CC, CC_QUEUE_ENTRY_SIZES | CC_EN);
        wait_csts(&regs, CSTS_RDY, true, to_ticks)?;

        let identify = DmaPage::new().ok_or(NvmeError::Alloc)?;
        let mut this = Controller {
            regs,
            stride,
            admin,
            io: Queue::new(1, IO_QUEUE_DEPTH.min(mqes).max(2))?,
            _identify: identify,
            lba_bytes: 0,
            nsze: 0,
            lbas_per_block: 0,
            model: [b' '; 40],
            version,
            dead: false,
        };

        // Step 4: Identify Controller — model string for the log.
        this.admin_command(
            Command::new(ADMIN_IDENTIFY, 0, 0).prp1(this._identify.paddr).cdw10(CNS_CONTROLLER),
        )?;
        let mut model = [b' '; 40];
        this._identify.read(24, &mut model);
        this.model = model;

        // Step 5: Identify Namespace 1 — size and LBA format.
        this._identify.zero();
        this.admin_command(
            Command::new(ADMIN_IDENTIFY, NSID, 0).prp1(this._identify.paddr).cdw10(CNS_NAMESPACE),
        )?;
        let mut nsze = [0u8; 8];
        this._identify.read(0, &mut nsze);
        let nsze = u64::from_le_bytes(nsze);
        let mut flbas = [0u8; 1];
        this._identify.read(26, &mut flbas);
        let lbaf_index = (flbas[0] & 0x0F) as usize;
        let mut lbaf = [0u8; 4];
        this._identify.read(128 + lbaf_index * 4, &mut lbaf);
        let lbads = lbaf[2];
        if nsze == 0 || !(9..=12).contains(&lbads) {
            return Err(NvmeError::Unsupported);
        }
        let lba_bytes = 1u32 << lbads;
        if cambios_blk_proto::LOGICAL_BLOCK_SIZE as u32 % lba_bytes != 0 {
            return Err(NvmeError::Unsupported);
        }
        this.lba_bytes = lba_bytes;
        this.nsze = nsze;
        this.lbas_per_block = (cambios_blk_proto::LOGICAL_BLOCK_SIZE as u32 / lba_bytes) as u64;

        // Step 6: one I/O queue pair. CQ before SQ (the SQ names its CQ).
        let depth = this.io.depth as u32 - 1;
        this.admin_command(
            Command::new(ADMIN_CREATE_IO_CQ, 0, 0)
                .prp1(this.io.cq.paddr)
                .cdw10((depth << 16) | 1)
                .cdw11(1), // PC = 1, no interrupts
        )?;
        this.admin_command(
            Command::new(ADMIN_CREATE_IO_SQ, 0, 0)
                .prp1(this.io.sq.paddr)
                .cdw10((depth << 16) | 1)
                .cdw11((1 << 16) | 1), // CQID = 1, PC = 1
        )?;
        Ok(this)
    }

    fn admin_command(&mut self, cmd: Command) -> Result<u32, NvmeError> {
        let cid = self.admin.submit(&self.regs, self.stride, cmd);
        self.admin.wait(&self.regs, self.stride, cid, COMMAND_TIMEOUT_TICKS)
    }

    fn io_command(&mut self, cmd: Command) -> Result<(), NvmeError> {
        if self.dead {
            return Err(NvmeError::Fatal);
        }
        let cid = self.io.submit(&self.regs, self.stride, cmd);
        match self.io.wait(&self.regs, self.stride, cid, COMMAND_TIMEOUT_TICKS) {
            Ok(_) => Ok(()),
            Err(e) => {
                if matches!(e, NvmeError::Timeout | NvmeError::Fatal | NvmeError::StrayCompletion) {
                    self.dead = true;
                }
                Err(e)
            }
        }
    }

    /// Capacity in 512-byte sectors, the unit the seam reports.
    pub fn capacity_sectors(&self) -> u64 {
        self.nsze.saturating_mul((self.lba_bytes / cambios_blk_proto::SECTOR_SIZE as u32) as u64)
    }

    /// Number of 4 KiB kernel blocks in the namespace.
    pub fn capacity_blocks(&self) -> u64 {
        self.nsze / self.lbas_per_block
    }

    fn block_io(&mut self, opcode: u8, block: u64, page: &DmaPage) -> Result<(), NvmeError> {
        if block >= self.capacity_blocks() {
            return Err(NvmeError::Status(0x80)); // LBA out of range (SCT 0, SC 80h)
        }
        let slba = block * self.lbas_per_block;
        let nlb = (self.lbas_per_block - 1) as u32;
        self.io_command(
            Command::new(opcode, NSID, 0)
                .prp1(page.paddr)
                .cdw10(slba as u32)
                .cdw11((slba >> 32) as u32)
                .cdw12(nlb),
        )
    }

    /// Read kernel block `block` into `page`.
    pub fn read_block(&mut self, block: u64, page: &DmaPage) -> Result<(), NvmeError> {
        self.block_io(NVM_READ, block, page)
    }

    /// Write `page` to kernel block `block`.
    pub fn write_block(&mut self, block: u64, page: &DmaPage) -> Result<(), NvmeError> {
        self.block_io(NVM_WRITE, block, page)
    }

    pub fn flush(&mut self) -> Result<(), NvmeError> {
        self.io_command(Command::new(NVM_FLUSH, NSID, 0))
    }
}

/// Wait until `CSTS & bit` equals `set`, or the budget expires; a fatal
/// status short-circuits.
fn wait_csts(regs: &Mmio, bit: u32, set: bool, budget_ticks: u64) -> Result<(), NvmeError> {
    let mut deadline = Deadline::for_ticks(budget_ticks);
    loop {
        let csts = regs.read32(REG_CSTS);
        if csts == 0xFFFF_FFFF {
            return Err(NvmeError::Fatal); // register space not responding
        }
        if csts & CSTS_CFS != 0 {
            return Err(NvmeError::Fatal);
        }
        if (csts & bit != 0) == set {
            return Ok(());
        }
        if !deadline.tick() {
            return Err(NvmeError::Timeout);
        }
        cambios_libsys::yield_now();
    }
}
