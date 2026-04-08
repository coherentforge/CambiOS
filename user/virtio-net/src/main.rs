// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! ArcOS Virtio-Net Driver — user-space network device driver
//!
//! Runs as a ring-3 process. Discovers the virtio-net PCI device via the
//! DeviceInfo syscall, initializes the legacy virtio transport, sets up
//! TX and RX virtqueues with DMA bounce buffers, and exposes a packet
//! send/receive interface over IPC.
//!
//! ## Hostile device model
//!
//! All values read from device memory are validated via `DeviceValue<T>`.
//! Protocol violations (bad indices, non-monotonic counters, length overflows)
//! kill the device — no recovery attempted. Bounce buffers isolate the driver's
//! internal memory from device DMA.
//!
//! ## IPC protocol (endpoint 20, 256-byte payload)
//!
//!   Request:  [cmd:1][data...]
//!   Response: [status:1][data...]
//!
//!   Commands:
//!     1 = SEND_PACKET: [cmd:1][packet:N]  → [status:1]
//!     2 = RECV_PACKET: [cmd:1]            → [status:1][packet:N]
//!     3 = GET_MAC:     [cmd:1]            → [status:1][mac:6]
//!     4 = GET_STATUS:  [cmd:1]            → [status:1][link_up:1]
//!
//!   Status: 0=OK, 1=ERROR, 2=NO_DATA, 3=NO_DEVICE

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
use virtqueue::{BounceBuffer, VirtQueue};

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[NET] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// IPC protocol
// ============================================================================

const NET_ENDPOINT: u32 = 20;

const CMD_SEND_PACKET: u8 = 1;
const CMD_RECV_PACKET: u8 = 2;
const CMD_GET_MAC: u8 = 3;
const CMD_GET_STATUS: u8 = 4;

const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
const STATUS_NO_DATA: u8 = 2;
const STATUS_NO_DEVICE: u8 = 3;

// ============================================================================
// Virtio-net constants
// ============================================================================

/// Virtio-net header (legacy format, 10 bytes). Prepended to every packet.
const VIRTIO_NET_HDR_SIZE: usize = 10;

/// Number of pre-posted RX bounce buffers.
const RX_RING_SIZE: usize = 16;

/// RX queue index in virtio-net (queue 0 = receiveq).
const RX_QUEUE: u16 = 0;
/// TX queue index in virtio-net (queue 1 = transmitq).
const TX_QUEUE_IDX: u16 = 1;

// ============================================================================
// Driver state
// ============================================================================

struct NetDriver {
    transport: LegacyTransport,
    mac: [u8; 6],
    rx_queue: VirtQueue,
    tx_queue: VirtQueue,
    /// Pre-allocated RX bounce buffers. Posted to the RX queue at init;
    /// recycled after each received packet.
    rx_bufs: [Option<BounceBuffer>; RX_RING_SIZE],
    /// Single TX bounce buffer (synchronous sends — one at a time).
    tx_buf: BounceBuffer,
}

impl NetDriver {
    fn init(io_base: u16) -> Option<Self> {
        let transport = LegacyTransport::new(io_base);

        // Step 1: Reset
        transport.reset();

        // Step 2: Acknowledge + Driver
        transport.set_status(transport::STATUS_ACKNOWLEDGE);
        transport.set_status(transport::STATUS_DRIVER);

        // Step 3: Negotiate features
        let device_features = transport.device_features();
        let mut accepted = 0u32;
        if device_features & transport::VIRTIO_NET_F_MAC != 0 {
            accepted |= transport::VIRTIO_NET_F_MAC;
        }
        transport.set_guest_features(accepted);

        // Step 4: Set up RX queue (queue 0)
        transport.select_queue(RX_QUEUE);
        let rx_qsize = transport.queue_size();
        if rx_qsize == 0 {
            sys::print(b"[NET] RX queue size is 0\n");
            return None;
        }
        // Use smaller of device's max and our max
        let rx_qsize = core::cmp::min(rx_qsize, virtqueue::MAX_QUEUE_SIZE);

        let rx_queue = VirtQueue::new(rx_qsize)?;
        transport.set_queue_pfn(rx_queue.pfn());
        sys::print(b"[NET] RX queue configured\n");

        // Step 5: Set up TX queue (queue 1)
        transport.select_queue(TX_QUEUE_IDX);
        let tx_qsize = transport.queue_size();
        if tx_qsize == 0 {
            sys::print(b"[NET] TX queue size is 0\n");
            return None;
        }
        let tx_qsize = core::cmp::min(tx_qsize, virtqueue::MAX_QUEUE_SIZE);

        let tx_queue = VirtQueue::new(tx_qsize)?;
        transport.set_queue_pfn(tx_queue.pfn());
        sys::print(b"[NET] TX queue configured\n");

        // Step 6: Mark DRIVER_OK
        transport.set_status(transport::STATUS_DRIVER_OK);

        if transport.status() & transport::STATUS_FAILED != 0 {
            sys::print(b"[NET] Device set FAILED status during init\n");
            return None;
        }

        // Read MAC address
        let mac = transport.read_mac();

        sys::print(b"[NET] Device initialized, MAC=");
        print_mac(&mac);
        sys::print(b"\n");

        // Step 7: Allocate TX bounce buffer
        let tx_buf = BounceBuffer::new()?;

        // Step 8: Allocate and post RX bounce buffers
        let rx_bufs: [Option<BounceBuffer>; RX_RING_SIZE] =
            core::array::from_fn(|_| None);

        let mut driver = NetDriver {
            transport,
            mac,
            rx_queue,
            tx_queue,
            rx_bufs,
            tx_buf,
        };

        // Post initial RX buffers
        driver.fill_rx_ring();

        Some(driver)
    }

    /// Post available RX bounce buffers to the RX queue.
    fn fill_rx_ring(&mut self) {
        for i in 0..RX_RING_SIZE {
            if self.rx_bufs[i].is_some() {
                continue; // Already has a buffer
            }
            let buf = match BounceBuffer::new() {
                Some(b) => b,
                None => break, // Out of DMA memory
            };
            buf.zero();

            // Post to RX queue — device writes into this buffer
            if self.rx_queue.push_buffer(
                buf.paddr,
                buf.vaddr,
                buf.size,
                true, // device-writable
            ).is_some() {
                self.rx_bufs[i] = Some(buf);
            } else {
                break; // Queue full
            }
        }

        // Notify device that RX buffers are available
        self.transport.notify_queue(RX_QUEUE);
    }

    /// Send a packet. Copies data to TX bounce buffer with virtio-net header,
    /// posts to TX queue, notifies device, and waits for completion.
    fn send_packet(&mut self, packet: &[u8]) -> bool {
        if self.tx_queue.is_dead() {
            return false;
        }

        let total_len = VIRTIO_NET_HDR_SIZE + packet.len();
        if total_len > self.tx_buf.size as usize {
            return false; // Packet too large
        }

        // Build virtio-net header (all zeros = no offload)
        self.tx_buf.zero();
        // Copy packet data after the header
        let dst = (self.tx_buf.vaddr + VIRTIO_NET_HDR_SIZE as u64) as *mut u8;
        // This write goes to the bounce buffer (driver memory), not device memory
        #[allow(unsafe_code)]
        unsafe {
            core::ptr::copy_nonoverlapping(packet.as_ptr(), dst, packet.len());
        }

        // Post to TX queue
        if self.tx_queue.push_buffer(
            self.tx_buf.paddr,
            self.tx_buf.vaddr,
            total_len as u32,
            false, // driver-readable (TX)
        ).is_none() {
            return false;
        }

        // Notify device
        self.transport.notify_queue(TX_QUEUE_IDX);

        // Poll for TX completion (synchronous — simple for now)
        for _ in 0..1000 {
            if let Some((_pending, _len)) = self.tx_queue.pop_used() {
                return true; // Sent successfully
            }
            // Spin briefly
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        false // Timed out
    }

    /// Poll for a received packet. Returns the number of payload bytes
    /// copied to `out`, or 0 if no packet available.
    fn recv_packet(&mut self, out: &mut [u8]) -> usize {
        if self.rx_queue.is_dead() {
            return 0;
        }

        if let Some((pending, validated_len)) = self.rx_queue.pop_used() {
            // validated_len includes the virtio-net header
            if validated_len as usize <= VIRTIO_NET_HDR_SIZE {
                // No actual payload — repost buffer
                self.recycle_rx_buffer(pending);
                return 0;
            }

            let payload_len = validated_len as usize - VIRTIO_NET_HDR_SIZE;
            let copy_len = core::cmp::min(payload_len, out.len());

            // Read payload from bounce buffer (skip virtio-net header)
            let src = (pending.vaddr + VIRTIO_NET_HDR_SIZE as u64) as *const u8;
            #[allow(unsafe_code)]
            unsafe {
                core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), copy_len);
            }

            // Recycle this buffer back to the RX ring
            self.recycle_rx_buffer(pending);

            copy_len
        } else {
            0
        }
    }

    /// Return a used RX bounce buffer to the ring for reuse.
    fn recycle_rx_buffer(&mut self, pending: virtqueue::PendingBuffer) {
        // Find the slot this buffer came from and repost it
        for i in 0..RX_RING_SIZE {
            if let Some(ref buf) = self.rx_bufs[i] {
                if buf.paddr == pending.paddr {
                    buf.zero();
                    self.rx_queue.push_buffer(
                        buf.paddr, buf.vaddr, buf.size, true,
                    );
                    self.transport.notify_queue(RX_QUEUE);
                    return;
                }
            }
        }
        // Buffer not found in our tracking — don't repost (defensive)
    }
}

fn print_mac(mac: &[u8; 6]) {
    let mut buf = [0u8; 17];
    for i in 0..6 {
        let hi = mac[i] >> 4;
        let lo = mac[i] & 0xF;
        buf[i * 3] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
        buf[i * 3 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
        if i < 5 { buf[i * 3 + 2] = b':'; }
    }
    sys::print(&buf);
}

// ============================================================================
// Request handlers
// ============================================================================

fn handle_get_mac(driver: &NetDriver, response: &mut [u8]) -> usize {
    response[0] = STATUS_OK;
    response[1..7].copy_from_slice(&driver.mac);
    7
}

fn handle_get_status(driver: &NetDriver, response: &mut [u8]) -> usize {
    let dead = driver.rx_queue.is_dead() || driver.tx_queue.is_dead();
    let hw_failed = driver.transport.status() & transport::STATUS_FAILED != 0;
    response[0] = STATUS_OK;
    response[1] = if dead || hw_failed { 0 } else { 1 };
    2
}

fn handle_send_packet(driver: &mut NetDriver, payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_ERROR;
        return 1;
    }
    if driver.send_packet(payload) {
        response[0] = STATUS_OK;
    } else {
        response[0] = STATUS_ERROR;
    }
    1
}

fn handle_recv_packet(driver: &mut NetDriver, response: &mut [u8]) -> usize {
    // Max packet payload in 256-byte IPC frame: 255 - 1 status byte = 254
    let max_payload = response.len() - 1;
    let n = driver.recv_packet(&mut response[1..1 + max_payload]);
    if n > 0 {
        response[0] = STATUS_OK;
        1 + n
    } else {
        response[0] = STATUS_NO_DATA;
        1
    }
}

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[NET] Virtio-net driver starting\n");

    // Step 1: Find the virtio-net PCI device
    let dev = match pci::PciDeviceInfo::find_virtio_net() {
        Some(d) => d,
        None => {
            sys::print(b"[NET] No virtio-net device found\n");
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
    };

    sys::print(b"[NET] Found virtio-net PCI device\n");

    // Step 2: Find the I/O BAR (BAR 0 for legacy virtio)
    // Try all BARs — the I/O BAR might not be BAR 0 on all configurations
    let mut io_base: u16 = 0;
    for b in 0..6 {
        if dev.bars[b].is_io && dev.bars[b].addr != 0 {
            io_base = dev.bars[b].addr as u16;
            break;
        }
    }
    if io_base == 0 {
        // Fallback: check if BAR0 looks like an I/O port (addr < 0x10000)
        if dev.bars[0].addr != 0 && dev.bars[0].addr < 0x10000 {
            sys::print(b"[NET] BAR 0 appears to be I/O (addr < 64K), using it\n");
            io_base = dev.bars[0].addr as u16;
        } else {
            sys::print(b"[NET] No I/O BAR found\n");
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
    }

    // Step 3: Initialize the virtio device + queues
    let mut driver = match NetDriver::init(io_base) {
        Some(d) => d,
        None => {
            sys::print(b"[NET] Device initialization failed\n");
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
    };

    // Step 4: Register IPC endpoint
    sys::register_endpoint(NET_ENDPOINT);
    sys::print(b"[NET] Endpoint 20 registered, entering service loop\n");

    // Step 5: Service loop
    let mut recv_buf = [0u8; 256];
    let mut resp_buf = [0u8; 256];

    loop {
        let n = sys::recv_msg(NET_ENDPOINT, &mut recv_buf);

        if n <= 0 {
            sys::yield_now();
            continue;
        }
        let total = n as usize;

        if total < 37 {
            continue;
        }

        let from_endpoint = u32::from_le_bytes([
            recv_buf[32], recv_buf[33], recv_buf[34], recv_buf[35],
        ]);
        let payload = &recv_buf[36..total];
        let cmd = payload[0];
        let cmd_data = &payload[1..];

        let resp_len = match cmd {
            CMD_SEND_PACKET => handle_send_packet(&mut driver, cmd_data, &mut resp_buf),
            CMD_RECV_PACKET => handle_recv_packet(&mut driver, &mut resp_buf),
            CMD_GET_MAC => handle_get_mac(&driver, &mut resp_buf),
            CMD_GET_STATUS => handle_get_status(&driver, &mut resp_buf),
            _ => {
                resp_buf[0] = STATUS_ERROR;
                1
            }
        };

        sys::write(from_endpoint, &resp_buf[..resp_len]);
    }
}

fn no_device_loop() -> ! {
    let mut recv_buf = [0u8; 256];
    let resp_buf = [STATUS_NO_DEVICE; 1];

    loop {
        let n = sys::recv_msg(NET_ENDPOINT, &mut recv_buf);
        if n <= 0 {
            sys::yield_now();
            continue;
        }
        let total = n as usize;
        if total >= 37 {
            let from_endpoint = u32::from_le_bytes([
                recv_buf[32], recv_buf[33], recv_buf[34], recv_buf[35],
            ]);
            sys::write(from_endpoint, &resp_buf);
        }
    }
}
