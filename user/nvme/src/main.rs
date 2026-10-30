// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS NVMe block driver — the block-driver IPC seam over an NVMe
//! controller. Same bytes, endpoints and shared-page handshake as
//! virtio-blk (`cambios-blk-proto`); which driver an image boots is a
//! manifest profile decision (nvme on the Dell 3630 profiles, virtio-blk
//! under QEMU's default). Everything above the seam — the ObjectStore,
//! fs-service, `arcobj`, fde-mount — is unchanged.
//!
//! Controller bring-up, Identify and the queue pair live in `nvme.rs`;
//! DMA pages and MMIO access in `dma.rs`; discovery in `pci.rs`.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod dma;
mod nvme;
mod pci;

use cambios_blk_proto::{
    decode_lba_request, encode_u64_reply, BLK_ENDPOINT, BLK_KERNEL_CMD_ENDPOINT,
    BLK_KERNEL_RESP_ENDPOINT, CMD_FLUSH, CMD_GET_CAPACITY, CMD_GET_STATUS, CMD_READ_BLOCK,
    CMD_WRITE_BLOCK, KCMD_CAPACITY, KCMD_FLUSH, KCMD_HANDSHAKE, KCMD_READ_BLOCK,
    KCMD_WRITE_BLOCK, STATUS_DEVICE_DEAD, STATUS_ERROR, STATUS_NO_DEVICE, STATUS_OK,
    STATUS_UNIMPLEMENTED,
};
use cambios_libipc as ipc;
use cambios_libsys as sys;
use dma::{DmaPage, Mmio};
use nvme::{Controller, NvmeError};

/// HARDWARE: the doorbells for admin + one I/O queue end below 0x1020;
/// mapping at least two pages of BAR0 covers them whatever the BAR
/// size field says.
const MIN_BAR0_BYTES: u32 = 0x2000;

struct Driver {
    ctl: Controller,
    /// Kernel-shared data page, allocated at the first HANDSHAKE and
    /// reported by physical address; the kernel reaches it through the
    /// HHDM and the controller DMAs straight into it.
    shared: Option<DmaPage>,
}

impl Driver {
    fn ensure_shared(&mut self) -> Option<u64> {
        if self.shared.is_none() {
            self.shared = DmaPage::new();
        }
        self.shared.map(|p| p.paddr)
    }

    fn status_for(&self, e: NvmeError) -> u8 {
        if self.ctl.dead || matches!(e, NvmeError::Timeout | NvmeError::Fatal) {
            STATUS_DEVICE_DEAD
        } else {
            STATUS_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// Logging without an allocator
// ---------------------------------------------------------------------------

/// Bounds-checked line builder: every push clamps to the buffer, so a
/// long label can truncate a line but never index past it (the first
/// self-test print did exactly that, 2026-10-30).
struct Line {
    buf: [u8; 160],
    n: usize,
}

impl Line {
    fn new() -> Self {
        Line { buf: [0; 160], n: 0 }
    }
    fn push(&mut self, bytes: &[u8]) -> &mut Self {
        let take = core::cmp::min(bytes.len(), self.buf.len() - self.n);
        self.buf[self.n..self.n + take].copy_from_slice(&bytes[..take]);
        self.n += take;
        self
    }
    fn push_hex_u64(&mut self, v: u64) -> &mut Self {
        let mut tmp = [0u8; 18];
        tmp[0] = b'0';
        tmp[1] = b'x';
        for i in 0..16 {
            tmp[2 + i] = hex_nibble((v >> ((15 - i) * 4)) as u8);
        }
        self.push(&tmp)
    }
    fn push_hex_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        for &b in bytes {
            self.push(&[hex_nibble(b >> 4), hex_nibble(b)]);
        }
        self
    }
    fn push_dec(&mut self, mut v: u64) -> &mut Self {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(&tmp[i..])
    }
    fn print(&mut self) {
        self.push(b"\n");
        sys::print(&self.buf[..self.n]);
    }
}

fn hex_nibble(n: u8) -> u8 {
    match n & 0xF {
        0..=9 => b'0' + (n & 0xF),
        _ => b'a' + (n & 0xF) - 10,
    }
}

fn log_u64(label: &[u8], v: u64) {
    Line::new().push(label).push_hex_u64(v).print();
}

fn log_dec(label: &[u8], v: u64, suffix: &[u8]) {
    Line::new().push(label).push_dec(v).push(suffix).print();
}

fn log_err(stage: &[u8], e: NvmeError) {
    let what: &[u8] = match e {
        NvmeError::Alloc => b"DMA allocation failed",
        NvmeError::Timeout => b"timeout",
        NvmeError::Fatal => b"controller fatal status",
        NvmeError::Unsupported => b"unsupported controller/namespace shape",
        NvmeError::Status(_) => b"command status error",
        NvmeError::StrayCompletion => b"stray completion",
    };
    Line::new().push(b"[NVME] ERROR at ").push(stage).push(b": ").push(what).print();
    if let NvmeError::Status(code) = e {
        log_u64(b"[NVME]   status field ", code as u64);
    }
}

// ---------------------------------------------------------------------------
// IPC handlers
// ---------------------------------------------------------------------------

fn handle_kernel_cmd(driver: &mut Driver, payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_ERROR;
        return 1;
    }
    match payload[0] {
        KCMD_HANDSHAKE => match driver.ensure_shared() {
            Some(paddr) => encode_u64_reply(STATUS_OK, paddr, response),
            None => {
                response[0] = STATUS_ERROR;
                1
            }
        },
        KCMD_READ_BLOCK | KCMD_WRITE_BLOCK => {
            let Some(lba) = decode_lba_request(payload) else {
                response[0] = STATUS_ERROR;
                return 1;
            };
            let Some(page) = driver.shared else {
                response[0] = STATUS_ERROR; // no handshake yet
                return 1;
            };
            let result = if payload[0] == KCMD_READ_BLOCK {
                driver.ctl.read_block(lba, &page)
            } else {
                driver.ctl.write_block(lba, &page)
            };
            response[0] = match result {
                Ok(()) => STATUS_OK,
                Err(e) => {
                    log_err(if payload[0] == KCMD_READ_BLOCK { b"read" } else { b"write" }, e);
                    driver.status_for(e)
                }
            };
            1
        }
        KCMD_FLUSH => {
            response[0] = match driver.ctl.flush() {
                Ok(()) => STATUS_OK,
                Err(e) => {
                    log_err(b"flush", e);
                    driver.status_for(e)
                }
            };
            1
        }
        KCMD_CAPACITY => encode_u64_reply(STATUS_OK, driver.ctl.capacity_sectors(), response),
        _ => {
            response[0] = STATUS_ERROR;
            1
        }
    }
}

fn handle_user_cmd(driver: &mut Driver, cmd: u8, response: &mut [u8]) -> usize {
    match cmd {
        CMD_READ_BLOCK | CMD_WRITE_BLOCK => {
            response[0] = STATUS_UNIMPLEMENTED;
            1
        }
        CMD_FLUSH => {
            response[0] = match driver.ctl.flush() {
                Ok(()) => STATUS_OK,
                Err(e) => driver.status_for(e),
            };
            1
        }
        CMD_GET_CAPACITY => encode_u64_reply(STATUS_OK, driver.ctl.capacity_sectors(), response),
        CMD_GET_STATUS => {
            response[0] = STATUS_OK;
            response[1] = if driver.ctl.dead { 0 } else { 1 };
            2
        }
        _ => {
            response[0] = STATUS_ERROR;
            1
        }
    }
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

cambios_libsys_rt::service_main! {
    name: "NVME",
    main: run,
}

fn run() -> ! {
    // Step 1: find the controller. Absence is non-fatal — serve the seam
    // with NO_DEVICE so the kernel's store falls back to RAM cleanly.
    let dev = match pci::PciDeviceInfo::find_nvme() {
        Some(d) => d,
        None => {
            sys::print(b"[NVME] no NVMe controller found on this system\n");
            no_device_loop();
        }
    };
    log_u64(b"[NVME] controller at bus:dev.fn ", ((dev.bus as u64) << 16) | ((dev.device as u64) << 8) | dev.function as u64);
    log_u64(b"[NVME] vendor:device:prog-if ", ((dev.vendor_id as u64) << 24) | ((dev.device_id as u64) << 8) | dev.prog_if as u64);
    let bar0 = dev.bars[0];
    if bar0.is_io || bar0.addr == 0 {
        sys::print(b"[NVME] ERROR: BAR0 is not a memory BAR\n");
        no_device_loop();
    }
    let regs = match Mmio::map(bar0.addr, bar0.size.max(MIN_BAR0_BYTES)) {
        Some(m) => m,
        None => {
            sys::print(b"[NVME] ERROR: map_mmio failed for BAR0\n");
            no_device_loop();
        }
    };

    // Step 2: bring the controller up.
    let ctl = match Controller::init(regs) {
        Ok(c) => c,
        Err(e) => {
            log_err(b"init", e);
            no_device_loop();
        }
    };
    Line::new().push(b"[NVME] controller: ").push(&ctl.model).print();
    log_u64(b"[NVME] version register ", ctl.version as u64);
    log_dec(b"[NVME] namespace 1: ", ctl.nsze, b" LBAs");
    log_dec(b"[NVME] LBA size: ", ctl.lba_bytes as u64, b" bytes");
    log_dec(b"[NVME] capacity: ", ctl.capacity_sectors(), b" sectors (512 B)");

    let mut driver = Driver { ctl, shared: None };

    // Step 3: self-test — read block 0 into the shared page and show its
    // first bytes (the volume header's magic on a formatted disk).
    if let Some(paddr) = driver.ensure_shared() {
        let _ = paddr;
        let page = driver.shared.unwrap_or(DmaPage { vaddr: 0, paddr: 0 });
        match driver.ctl.read_block(0, &page) {
            Ok(()) => {
                let mut head = [0u8; 16];
                page.read(0, &mut head);
                Line::new().push(b"[NVME] self-test: block 0 head bytes ").push_hex_bytes(&head).print();
            }
            Err(e) => log_err(b"self-test read", e),
        }
    }

    // Step 4: register the seam and serve.
    sys::register_endpoint(BLK_ENDPOINT);
    sys::register_endpoint(BLK_KERNEL_CMD_ENDPOINT);
    sys::print(b"[NVME] ready on endpoint 24 (nvme)\n");
    sys::print(b"[NVME] ready on endpoint 26 (nvme / kernel)\n");
    cambios_libsys_rt::ready();

    let mut recv_buf = [0u8; ipc::RECV_BUF_SIZE];
    let mut kern_recv_buf = [0u8; ipc::RECV_BUF_SIZE];
    let mut resp_buf = [0u8; 256];
    // Dual-endpoint poll loop: both endpoints non-blocking, as in
    // virtio-blk — a blocking receive on one would park the task on that
    // endpoint's wait and miss the other.
    loop {
        let mut did_work = false;
        did_work |= ipc::poll_verified(BLK_ENDPOINT, &mut recv_buf, |msg| {
            let resp_len = handle_user_cmd(&mut driver, msg.payload()[0], &mut resp_buf);
            sys::write(msg.from_endpoint(), &resp_buf[..resp_len]);
        });
        did_work |= ipc::poll_raw(BLK_KERNEL_CMD_ENDPOINT, &mut kern_recv_buf, |msg| {
            let resp_len = handle_kernel_cmd(&mut driver, msg.payload(), &mut resp_buf);
            if resp_len > 0 {
                sys::write(BLK_KERNEL_RESP_ENDPOINT, &resp_buf[..resp_len]);
            }
        });
        if !did_work {
            sys::yield_now();
        }
    }
}

fn no_device_loop() -> ! {
    // Serve both endpoints with NO_DEVICE so the kernel's handshake fails
    // fast instead of waiting out its iteration cap; release init.
    sys::register_endpoint(BLK_ENDPOINT);
    sys::register_endpoint(BLK_KERNEL_CMD_ENDPOINT);
    cambios_libsys_rt::ready();
    let mut recv_buf = [0u8; ipc::RECV_BUF_SIZE];
    let mut kern_recv_buf = [0u8; ipc::RECV_BUF_SIZE];
    let resp = [STATUS_NO_DEVICE; 1];
    loop {
        let mut did_work = false;
        did_work |= ipc::poll_raw(BLK_ENDPOINT, &mut recv_buf, |msg| {
            sys::write(msg.from_endpoint(), &resp);
        });
        did_work |= ipc::poll_raw(BLK_KERNEL_CMD_ENDPOINT, &mut kern_recv_buf, |_msg| {
            sys::write(BLK_KERNEL_RESP_ENDPOINT, &resp);
        });
        if !did_work {
            sys::yield_now();
        }
    }
}
