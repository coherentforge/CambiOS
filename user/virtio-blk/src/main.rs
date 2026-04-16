// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS Virtio-Blk Driver — user-space block device driver
//!
//! Runs as a ring-3 process. Discovers the virtio-blk PCI device via the
//! `DeviceInfo` syscall, initializes the legacy virtio transport, sets up a
//! single request virtqueue with DMA bounce buffers, and exposes a minimal
//! IPC service for disk operations.
//!
//! ## Scope — Phase 4a.ii
//!
//! This phase brings the driver up and validates it with a boot self-test
//! (read LBA 0, log the first 16 bytes to serial). Three IPC commands are
//! implemented directly over the 256-byte control frame:
//!
//! - `GET_CAPACITY` — returns device size in 512-byte sectors.
//! - `FLUSH` — `VIRTIO_BLK_T_FLUSH` barrier.
//! - `GET_STATUS` — driver-live / device-alive probe.
//!
//! `READ_BLOCK` / `WRITE_BLOCK` carry 4 KiB of data per call, which does not
//! fit in one control frame. The protocol for that data transfer is a real
//! architectural decision (multi-frame IPC vs. channel-based bulk per ADR-005
//! vs. shared-map bounce buffer). Deferred to Phase 4a.iii when the kernel
//! adapter actually needs it, so the design gets made when the caller
//! exists. For 4a.ii those commands return `STATUS_UNIMPLEMENTED`.
//!
//! ## Hostile device model
//!
//! All values read from device memory are validated via `DeviceValue<T>`.
//! Protocol violations (bad indices, length overflows, bad status byte)
//! kill the device — no recovery attempted. Bounce buffers isolate the
//! driver's internal memory from device DMA.
//!
//! ## IPC protocols
//!
//! Two endpoints are served concurrently:
//!
//! **Endpoint 24 — user-facing (identity-verified via `recv_verified`).**
//!   Request:  [cmd:1][args...]
//!   Response: [status:1][data...]
//!   Commands:
//!     1 = READ_BLOCK   (stub — STATUS_UNIMPLEMENTED; owed to Phase 4a.iv)
//!     2 = WRITE_BLOCK  (stub — STATUS_UNIMPLEMENTED)
//!     3 = FLUSH:       [cmd:1]          → [status:1]
//!     4 = GET_CAPACITY [cmd:1]          → [status:1][sectors_512:8]
//!     5 = GET_STATUS   [cmd:1]          → [status:1][alive:1]
//!
//! **Endpoint 26 — kernel-only (raw `recv_msg`; replies to endpoint 25).**
//!   Kernel-origin messages carry `sender_principal = None`, which
//!   `recv_verified` rejects. Trust is conferred by endpoint choice: only
//!   the kernel speaks on 26, only the kernel receives on 25. See the
//!   `handle_kernel_cmd` comment for the protocol.
//!
//!   Status: 0=OK, 1=ERROR, 2=NO_DEVICE, 3=DEVICE_DEAD, 4=UNIMPLEMENTED

#![no_std]
#![no_main]
#![deny(unsafe_code)]

mod device;
mod pci;
mod transport;
#[allow(unsafe_code)]
mod virtqueue;

use arcos_libsys as sys;
use transport::LegacyTransport;
use virtqueue::{BounceBuffer, ChainSegment, VirtQueue};

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[BLK] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// IPC protocol
// ============================================================================

// Endpoint 22 is already claimed by the policy service (POLICY_QUERY_ENDPOINT);
// endpoint 23 is its response channel. Virtio-blk takes 24.
const BLK_ENDPOINT: u32 = 24;

// Kernel-only endpoints (Phase 4a.iii). The driver polls 26 in addition to 24;
// responses to kernel commands are sent to endpoint 25 which only the kernel
// receives on. Kernel-origin messages use raw `recv_msg` (not `recv_verified`)
// because the kernel itself does not stamp a sender Principal; the trust
// anchor here is endpoint choice, same pattern the policy service uses.
const BLK_KERNEL_RESP_ENDPOINT: u32 = 25;
const BLK_KERNEL_CMD_ENDPOINT: u32 = 26;

// User-facing commands on endpoint 24.
const CMD_READ_BLOCK: u8 = 1;
const CMD_WRITE_BLOCK: u8 = 2;
const CMD_FLUSH: u8 = 3;
const CMD_GET_CAPACITY: u8 = 4;
const CMD_GET_STATUS: u8 = 5;

// Kernel-only commands on endpoint 26 (Phase 4a.iii).
const KCMD_HANDSHAKE: u8 = 1;
const KCMD_READ_BLOCK: u8 = 2;
const KCMD_WRITE_BLOCK: u8 = 3;
const KCMD_FLUSH: u8 = 4;
const KCMD_CAPACITY: u8 = 5;

const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
const STATUS_NO_DEVICE: u8 = 2;
const STATUS_DEVICE_DEAD: u8 = 3;
const STATUS_UNIMPLEMENTED: u8 = 4;

// ============================================================================
// Virtio-blk constants (virtio spec §5.2)
// ============================================================================

/// Virtio-blk uses queue 0 (requestq).
const BLK_QUEUE: u16 = 0;

/// Virtio-blk request types (16-byte request header, `type` field). `T_OUT`
/// is used by the Phase 4a.iii kernel adapter's `write_block` path; retained
/// here so the wire protocol is documented in one place.
const VIRTIO_BLK_T_IN: u32 = 0;
#[allow(dead_code)]
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;

/// Virtio-blk status byte values (device writes these into the last
/// descriptor of each chain). We distinguish `S_OK` from everything else
/// today; the `IOERR`/`UNSUPP` distinction becomes useful once we report
/// richer error categories up the stack (ADR-010 defers this).
const VIRTIO_BLK_S_OK: u8 = 0;
#[allow(dead_code)]
const VIRTIO_BLK_S_IOERR: u8 = 1;
#[allow(dead_code)]
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Virtio-blk legacy sector size — always 512 regardless of the underlying
/// device's native block size. `capacity` in the device config is expressed
/// in 512-byte units.
const SECTOR_SIZE: usize = 512;

/// We always do 4 KiB-sized logical block I/O. Matches the on-disk format's
/// `BLOCK_SIZE` (ADR-010) and is a clean multiple of 512.
const LOGICAL_BLOCK_SIZE: usize = 4096;
const SECTORS_PER_LOGICAL_BLOCK: u64 = (LOGICAL_BLOCK_SIZE / SECTOR_SIZE) as u64;

// ============================================================================
// Driver state
// ============================================================================

struct BlkDriver {
    transport: LegacyTransport,
    /// Device size in 512-byte sectors.
    capacity_sectors: u64,
    /// Whether the device negotiated `VIRTIO_BLK_F_FLUSH`. If not, `FLUSH`
    /// requests are treated as no-ops (pre-1.0 virtio-blk had no flush op).
    has_flush: bool,
    queue: VirtQueue,
    /// Request header buffer (16 bytes used, page-allocated for alignment).
    req_hdr: BounceBuffer,
    /// Self-test data buffer — 4 KiB, holds the boot-time LBA-0 read.
    data_buf: BounceBuffer,
    /// Status byte — one page, we only use byte 0.
    status_buf: BounceBuffer,
    /// Kernel-shared DMA region (Phase 4a.iii). Lazily allocated on first
    /// `HANDSHAKE` from the kernel on endpoint 26. Single 4 KiB page the
    /// kernel can read/write via HHDM and the driver uses as the data
    /// segment for kernel-initiated block I/O.
    shared_region: Option<BounceBuffer>,
}

impl BlkDriver {
    fn init(io_base: u16) -> Option<Self> {
        let transport = LegacyTransport::new(io_base);

        // Step 1: reset.
        transport.reset();

        // Step 2: ACKNOWLEDGE + DRIVER.
        transport.set_status(transport::STATUS_ACKNOWLEDGE);
        transport.set_status(transport::STATUS_DRIVER);

        // Step 3: feature negotiation. We accept FLUSH if offered; we do not
        // enable RO (we need write support). Anything else is ignored — the
        // data-transfer contract only depends on the base virtio-blk
        // semantics.
        let device_features = transport.device_features();
        let mut accepted: u32 = 0;
        let has_flush = (device_features & transport::VIRTIO_BLK_F_FLUSH) != 0;
        if has_flush {
            accepted |= transport::VIRTIO_BLK_F_FLUSH;
        }
        transport.set_guest_features(accepted);

        // Step 3b: FEATURES_OK — not strictly required by legacy virtio 0.9.x,
        // but QEMU's transitional virtio-blk-pci appears to gate request
        // processing on it even when the driver talks via the legacy I/O
        // register region. Verify the device accepts the bit; FAILED in
        // response means the device rejects our feature set.
        transport.set_status(transport::STATUS_FEATURES_OK);
        if transport.status() & transport::STATUS_FEATURES_OK == 0 {
            sys::print(b"[BLK] ERROR: device rejected FEATURES_OK\n");
            return None;
        }

        // Step 4: set up queue 0 (requestq).
        //
        // Legacy virtio's queue_size register is read-only — the device
        // picks the size, and the driver MUST use exactly that size or
        // the ring offsets the two sides compute disagree and completions
        // never appear to arrive. Fail init (rather than silently clamp)
        // if the device asks for more than we support.
        transport.select_queue(BLK_QUEUE);
        let device_qsize = transport.queue_size();
        if device_qsize == 0 {
            sys::print(b"[BLK] ERROR: request queue size is 0\n");
            return None;
        }
        if device_qsize > virtqueue::MAX_QUEUE_SIZE {
            sys::print(b"[BLK] ERROR: device queue size exceeds MAX_QUEUE_SIZE\n");
            return None;
        }
        let queue = VirtQueue::new(device_qsize)?;
        transport.set_queue_pfn(queue.pfn());

        // Sanity: verify the device accepted our PFN.
        if transport.get_queue_pfn() != queue.pfn() {
            sys::print(b"[BLK] ERROR: device PFN mismatch\n");
            return None;
        }
        // Defensive: reselect queue 0 after the diagnostic read, so any
        // subsequent queue-register access operates on a known selection.
        transport.select_queue(BLK_QUEUE);

        // Step 5: DRIVER_OK.
        transport.set_status(transport::STATUS_DRIVER_OK);
        if transport.status() & transport::STATUS_FAILED != 0 {
            sys::print(b"[BLK] ERROR: device set FAILED status during init\n");
            return None;
        }

        // Step 6: read device capacity (sectors of 512 B).
        let capacity_sectors = transport.read_capacity_sectors();

        // Step 7: allocate bounce buffers for the request chain.
        let req_hdr = BounceBuffer::new()?;
        let data_buf = BounceBuffer::new()?;
        let status_buf = BounceBuffer::new()?;

        Some(BlkDriver {
            transport,
            capacity_sectors,
            has_flush,
            queue,
            req_hdr,
            data_buf,
            status_buf,
            shared_region: None,
        })
    }

    fn is_alive(&self) -> bool {
        !self.queue.is_dead()
            && (self.transport.status() & transport::STATUS_FAILED) == 0
    }

    /// Number of logical (4 KiB) blocks.
    fn capacity_logical_blocks(&self) -> u64 {
        self.capacity_sectors / SECTORS_PER_LOGICAL_BLOCK
    }

    /// Issue a request chain against an arbitrary data buffer and wait
    /// (cooperatively) for completion.
    ///
    /// The caller supplies `data_paddr`: for the self-test this points at
    /// `self.data_buf`; for kernel-initiated I/O (Phase 4a.iii) it points
    /// at `self.shared_region` so that results land where the kernel can
    /// read them directly via HHDM.
    ///
    /// Writes the 16-byte virtio-blk request header into `req_hdr` at
    /// offset 0, then posts a 3-descriptor chain: `[req_hdr (RO), data
    /// (RO for OUT / WO for IN), status_buf (WO)]`. Yields until the used
    /// ring reports completion, then reads the status byte.
    ///
    /// Returns the virtio-blk status byte (`VIRTIO_BLK_S_OK` on success) or
    /// `None` on queue-level failure.
    fn submit_and_wait(
        &mut self,
        req_type: u32,
        sector: u64,
        data_paddr: u64,
        data_len: u32,
        data_device_writable: bool,
    ) -> Option<u8> {
        if self.queue.is_dead() {
            return None;
        }

        // Build the 16-byte request header in req_hdr:
        //   [type:4][reserved:4][sector:8]
        self.req_hdr.zero();
        let hdr_bytes = {
            let mut buf = [0u8; 16];
            buf[0..4].copy_from_slice(&req_type.to_le_bytes());
            // reserved (bytes 4..8) stays zero.
            buf[8..16].copy_from_slice(&sector.to_le_bytes());
            buf
        };
        self.req_hdr.write(0, &hdr_bytes);

        // Pre-poison the status byte so we can tell "device didn't write"
        // apart from "device wrote OK".
        self.status_buf.write_u8(0, 0xFF);

        // Build the descriptor chain. Flush requests (data_len == 0) elide
        // the data segment entirely — the virtio spec says "zero-length
        // buffers are not allowed" and QEMU enforces this.
        let full_chain: [ChainSegment; 3];
        let short_chain: [ChainSegment; 2];
        let segments: &[ChainSegment] = if data_len == 0 {
            short_chain = [
                ChainSegment {
                    paddr: self.req_hdr.paddr,
                    len: 16,
                    device_writable: false,
                },
                ChainSegment {
                    paddr: self.status_buf.paddr,
                    len: 1,
                    device_writable: true,
                },
            ];
            &short_chain
        } else {
            full_chain = [
                ChainSegment {
                    paddr: self.req_hdr.paddr,
                    len: 16,
                    device_writable: false,
                },
                ChainSegment {
                    paddr: data_paddr,
                    len: data_len,
                    device_writable: data_device_writable,
                },
                ChainSegment {
                    paddr: self.status_buf.paddr,
                    len: 1,
                    device_writable: true,
                },
            ];
            &full_chain
        };

        let head = self.queue.push_chain(segments)?;
        if !self.transport.notify_queue(BLK_QUEUE) {
            return None;
        }

        // QEMU TCG may process the request synchronously on notify, or may
        // defer to its event loop (which runs when the guest idles). Poll
        // with yields; same pattern as the virtio-net TX path.
        for _ in 0..200 {
            if let Some((completed_head, _len)) = self.queue.pop_used() {
                if completed_head != head {
                    return None;
                }
                return self.status_buf.read_u8(0);
            }
            sys::yield_now();
        }
        None
    }

    /// Read one logical (4 KiB) block into `self.data_buf` (used by the
    /// boot self-test).
    fn read_block_selftest(&mut self, lba: u64) -> bool {
        if lba >= self.capacity_logical_blocks() {
            return false;
        }
        let sector = lba * SECTORS_PER_LOGICAL_BLOCK;
        let paddr = self.data_buf.paddr;
        match self.submit_and_wait(VIRTIO_BLK_T_IN, sector, paddr, LOGICAL_BLOCK_SIZE as u32, true) {
            Some(VIRTIO_BLK_S_OK) => true,
            _ => false,
        }
    }

    /// Flush. No-op if the device doesn't support `VIRTIO_BLK_F_FLUSH`.
    fn flush(&mut self) -> bool {
        if !self.has_flush {
            return true;
        }
        match self.submit_and_wait(VIRTIO_BLK_T_FLUSH, 0, 0, 0, false) {
            Some(VIRTIO_BLK_S_OK) => true,
            _ => false,
        }
    }

    // ------------------------------------------------------------------------
    // Kernel-shared-region I/O path (Phase 4a.iii)
    // ------------------------------------------------------------------------

    /// Allocate the kernel-shared DMA region if it hasn't been created yet,
    /// and return its physical address. Called by the HANDSHAKE handler.
    fn ensure_shared_region(&mut self) -> Option<u64> {
        if let Some(ref r) = self.shared_region {
            return Some(r.paddr);
        }
        let r = BounceBuffer::new()?;
        r.zero();
        let paddr = r.paddr;
        self.shared_region = Some(r);
        Some(paddr)
    }

    /// Read one logical (4 KiB) block into the kernel-shared region.
    fn read_block_shared(&mut self, lba: u64) -> bool {
        if lba >= self.capacity_logical_blocks() {
            return false;
        }
        let sr_paddr = match self.shared_region {
            Some(ref r) => r.paddr,
            None => return false,
        };
        let sector = lba * SECTORS_PER_LOGICAL_BLOCK;
        match self.submit_and_wait(VIRTIO_BLK_T_IN, sector, sr_paddr, LOGICAL_BLOCK_SIZE as u32, true) {
            Some(VIRTIO_BLK_S_OK) => true,
            _ => false,
        }
    }

    /// Write the 4 KiB already present in the kernel-shared region to the
    /// given LBA.
    fn write_block_shared(&mut self, lba: u64) -> bool {
        if lba >= self.capacity_logical_blocks() {
            return false;
        }
        let sr_paddr = match self.shared_region {
            Some(ref r) => r.paddr,
            None => return false,
        };
        let sector = lba * SECTORS_PER_LOGICAL_BLOCK;
        match self.submit_and_wait(VIRTIO_BLK_T_OUT, sector, sr_paddr, LOGICAL_BLOCK_SIZE as u32, false) {
            Some(VIRTIO_BLK_S_OK) => true,
            _ => false,
        }
    }
}

// ============================================================================
// Boot self-test: read LBA 0, print the first 16 bytes in hex.
// ============================================================================

fn hex_nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

fn log_u64(label: &[u8], v: u64) {
    sys::print(label);
    let mut buf = [b'0'; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> ((15 - i) * 4)) & 0xF) as u8;
        buf[2 + i] = hex_nibble(nib);
    }
    sys::print(&buf);
    sys::print(b"\n");
}

fn log_first_bytes(driver: &BlkDriver) {
    let mut head = [0u8; 16];
    let n = driver.data_buf.read(0, &mut head);
    sys::print(b"[BLK] LBA 0 head bytes: ");
    let mut hex = [0u8; 32];
    for i in 0..n {
        hex[i * 2] = hex_nibble(head[i] >> 4);
        hex[i * 2 + 1] = hex_nibble(head[i] & 0xF);
    }
    sys::print(&hex[..n * 2]);
    sys::print(b"\n");
}

fn run_self_test(driver: &mut BlkDriver) {
    log_u64(b"[BLK] capacity (sectors): ", driver.capacity_sectors);
    log_u64(b"[BLK] capacity (4 KiB blocks): ", driver.capacity_logical_blocks());

    if driver.capacity_logical_blocks() == 0 {
        sys::print(b"[BLK] self-test: device has no capacity, skipping\n");
        return;
    }

    driver.data_buf.zero();
    if driver.read_block_selftest(0) {
        sys::print(b"[BLK] self-test: read LBA 0 ... OK\n");
        log_first_bytes(driver);
    } else {
        sys::print(b"[BLK] self-test: read LBA 0 FAILED, status=");
        // submit_and_wait already returned — we can't read its status here
        // without re-issuing. Just flag the failure.
        sys::print(b"n/a\n");
    }

    if driver.has_flush {
        if driver.flush() {
            sys::print(b"[BLK] self-test: flush OK\n");
        } else {
            sys::print(b"[BLK] self-test: flush FAILED\n");
        }
    } else {
        sys::print(b"[BLK] self-test: device does not advertise FLUSH\n");
    }
}

// ============================================================================
// Request handlers
// ============================================================================

fn handle_get_capacity(driver: &BlkDriver, response: &mut [u8]) -> usize {
    response[0] = STATUS_OK;
    response[1..9].copy_from_slice(&driver.capacity_sectors.to_le_bytes());
    9
}

fn handle_flush(driver: &mut BlkDriver, response: &mut [u8]) -> usize {
    if !driver.is_alive() {
        response[0] = STATUS_DEVICE_DEAD;
        return 1;
    }
    if driver.flush() {
        response[0] = STATUS_OK;
    } else {
        response[0] = STATUS_ERROR;
    }
    1
}

fn handle_get_status(driver: &BlkDriver, response: &mut [u8]) -> usize {
    response[0] = STATUS_OK;
    response[1] = if driver.is_alive() { 1 } else { 0 };
    2
}

fn handle_unimplemented(response: &mut [u8]) -> usize {
    response[0] = STATUS_UNIMPLEMENTED;
    1
}

// ============================================================================
// Kernel command handler (endpoint 26, Phase 4a.iii)
//
// Payload layouts:
//   HANDSHAKE:   [cmd:1]                         response: [status:1][paddr:8]
//   READ_BLOCK:  [cmd:1][lba:8]                  response: [status:1]
//   WRITE_BLOCK: [cmd:1][lba:8]                  response: [status:1]
//   FLUSH:       [cmd:1]                         response: [status:1]
//   CAPACITY:    [cmd:1]                         response: [status:1][sectors:8]
// ============================================================================

fn handle_kernel_cmd(driver: &mut BlkDriver, payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_ERROR;
        return 1;
    }
    match payload[0] {
        KCMD_HANDSHAKE => match driver.ensure_shared_region() {
            Some(paddr) => {
                response[0] = STATUS_OK;
                response[1..9].copy_from_slice(&paddr.to_le_bytes());
                9
            }
            None => {
                response[0] = STATUS_ERROR;
                1
            }
        },
        KCMD_READ_BLOCK => {
            if payload.len() < 9 {
                response[0] = STATUS_ERROR;
                return 1;
            }
            let mut lba_bytes = [0u8; 8];
            lba_bytes.copy_from_slice(&payload[1..9]);
            let lba = u64::from_le_bytes(lba_bytes);
            response[0] = if driver.read_block_shared(lba) { STATUS_OK } else { STATUS_ERROR };
            1
        }
        KCMD_WRITE_BLOCK => {
            if payload.len() < 9 {
                response[0] = STATUS_ERROR;
                return 1;
            }
            let mut lba_bytes = [0u8; 8];
            lba_bytes.copy_from_slice(&payload[1..9]);
            let lba = u64::from_le_bytes(lba_bytes);
            response[0] = if driver.write_block_shared(lba) { STATUS_OK } else { STATUS_ERROR };
            1
        }
        KCMD_FLUSH => {
            response[0] = if driver.flush() { STATUS_OK } else { STATUS_ERROR };
            1
        }
        KCMD_CAPACITY => {
            response[0] = STATUS_OK;
            response[1..9].copy_from_slice(&driver.capacity_sectors.to_le_bytes());
            9
        }
        _ => {
            response[0] = STATUS_ERROR;
            1
        }
    }
}

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Step 1: find the virtio-blk device. Absence is non-fatal — the driver
    // still registers its endpoint and replies NO_DEVICE so upstream can
    // discover the situation cleanly.
    let dev = match pci::PciDeviceInfo::find_virtio_blk() {
        Some(d) => d,
        None => {
            sys::print(b"[BLK] no virtio-blk device found on this system\n");
            sys::register_endpoint(BLK_ENDPOINT);
            no_device_loop();
        }
    };

    // Step 2: locate the legacy I/O BAR (address < 64K).
    let mut io_base: u16 = 0;
    for b in 0..6 {
        let addr = dev.bars[b].addr;
        if addr != 0 && addr < 0x10000 {
            io_base = addr as u16;
            break;
        }
    }
    if io_base == 0 {
        sys::print(b"[BLK] ERROR: no I/O BAR on virtio-blk device\n");
        sys::register_endpoint(BLK_ENDPOINT);
        no_device_loop();
    }

    // Step 3: initialize.
    let mut driver = match BlkDriver::init(io_base) {
        Some(d) => d,
        None => {
            sys::print(b"[BLK] ERROR: device initialization failed\n");
            sys::register_endpoint(BLK_ENDPOINT);
            no_device_loop();
        }
    };

    // Step 4: boot self-test.
    run_self_test(&mut driver);

    // Step 5: register IPC endpoints and serve.
    sys::register_endpoint(BLK_ENDPOINT);
    sys::register_endpoint(BLK_KERNEL_CMD_ENDPOINT);
    sys::print(b"[BLK] ready on endpoint 24 (virtio-blk)\n");
    sys::print(b"[BLK] ready on endpoint 26 (virtio-blk / kernel)\n");
    sys::module_ready();

    let mut recv_buf = [0u8; 292];
    let mut resp_buf = [0u8; 256];
    let mut kern_recv_buf = [0u8; 292];

    // Dual-endpoint service loop. We MUST use try_recv_msg (non-blocking)
    // on both endpoints: a blocking recv on one would park the task on
    // MessageWait(that endpoint), and a wake targeting the other endpoint
    // would miss us. That's what caused the Phase 4b arcobj handshake
    // stall before SYS_TRY_RECV_MSG (37) landed.
    loop {
        let mut did_work = false;

        // Poll the user-facing endpoint (identity-required).
        let n = sys::try_recv_msg(BLK_ENDPOINT, &mut recv_buf);
        if n > 0 {
            let total = n as usize;
            if total >= 37 {
                // Reject anonymous senders on the user endpoint (mirrors
                // what recv_verified's check did previously).
                let mut principal_zero = true;
                for &b in &recv_buf[0..32] {
                    if b != 0 { principal_zero = false; break; }
                }
                if !principal_zero {
                    // payload[0] = cmd, payload[1..] = args
                    let cmd = recv_buf[36];
                    let from_ep = u32::from_le_bytes(recv_buf[32..36].try_into().unwrap());
                    let resp_len = match cmd {
                        CMD_READ_BLOCK | CMD_WRITE_BLOCK => handle_unimplemented(&mut resp_buf),
                        CMD_FLUSH => handle_flush(&mut driver, &mut resp_buf),
                        CMD_GET_CAPACITY => handle_get_capacity(&driver, &mut resp_buf),
                        CMD_GET_STATUS => handle_get_status(&driver, &mut resp_buf),
                        _ => {
                            resp_buf[0] = STATUS_ERROR;
                            1
                        }
                    };
                    sys::write(from_ep, &resp_buf[..resp_len]);
                }
            }
            did_work = true;
        }

        // Poll the kernel-facing endpoint (kernel is anonymous sender —
        // trust is by endpoint choice; nobody else registers ep26).
        let n = sys::try_recv_msg(BLK_KERNEL_CMD_ENDPOINT, &mut kern_recv_buf);
        if n > 0 {
            let total = n as usize;
            if total >= 37 {
                let payload = &kern_recv_buf[36..total];
                let resp_len = handle_kernel_cmd(&mut driver, payload, &mut resp_buf);
                if resp_len > 0 {
                    sys::write(BLK_KERNEL_RESP_ENDPOINT, &resp_buf[..resp_len]);
                }
            }
            did_work = true;
        }

        if !did_work {
            sys::yield_now();
        }
    }
}

fn no_device_loop() -> ! {
    // Also register the kernel endpoint so handshakes get a fast NO_DEVICE
    // response instead of timing out after ~100s. Signal boot-chain ready
    // so downstream modules are released.
    sys::register_endpoint(BLK_KERNEL_CMD_ENDPOINT);
    sys::module_ready();

    let mut recv_buf = [0u8; 256];
    let mut kern_recv_buf = [0u8; 292];
    let resp_buf = [STATUS_NO_DEVICE; 1];

    loop {
        let mut did_work = false;

        let n = sys::try_recv_msg(BLK_ENDPOINT, &mut recv_buf);
        if n > 0 && (n as usize) >= 37 {
            let from_ep = u32::from_le_bytes(recv_buf[32..36].try_into().unwrap());
            sys::write(from_ep, &resp_buf);
            did_work = true;
        }

        let n = sys::try_recv_msg(BLK_KERNEL_CMD_ENDPOINT, &mut kern_recv_buf);
        if n > 0 {
            sys::write(BLK_KERNEL_RESP_ENDPOINT, &resp_buf);
            did_work = true;
        }

        if !did_work {
            sys::yield_now();
        }
    }
}
