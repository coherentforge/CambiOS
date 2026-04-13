// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS Intel I219-LM Network Driver — user-space, MMIO-based.
//!
//! Targets the Intel I219-LM Ethernet controller integrated into 100/200/300
//! /400-series PCH chipsets (e.g., the Dell Precision 3630). Discovers the
//! device via the DeviceInfo PCI syscall, maps BAR0, initializes the MAC and
//! Lewisville PHY, sets up TX/RX descriptor rings backed by DMA bounce
//! buffers, and exposes packet send/receive over the same IPC protocol as
//! the virtio-net driver — so the UDP stack works unchanged.
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
//!
//! ## Bare-metal only
//!
//! QEMU's x86_64 and AArch64 virt machines do not emulate the I219-LM, so
//! this driver only finds a device on real hardware. On QEMU it logs
//! "No I219 device found" and enters a no-device loop, leaving endpoint 20
//! free for the virtio-net driver (which loads alongside it via Limine).

#![no_std]
#![no_main]
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod mmio;
mod pci;
#[allow(unsafe_code)]
mod phy;
mod regs;
#[allow(unsafe_code)]
mod ring;

use arcos_libsys as sys;
use mmio::{spin_delay, Mmio};
use regs::*;
use ring::{DmaBuf, Ring, BUF_SIZE, RING_SIZE};

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[I219] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// IPC protocol (matches virtio-net for UDP stack compatibility)
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
// Driver state
// ============================================================================

struct I219Driver {
    mmio: Mmio,
    mac: [u8; 6],
    tx_ring: Ring,
    rx_ring: Ring,
    /// Software's view of the next RX descriptor to inspect.
    /// Hardware advances RDH; we read descriptors at indices
    /// [rx_next, RDH) and recycle them.
    rx_next: u16,
}

impl I219Driver {
    fn init(bar0_phys: u64, bar0_size: u32) -> Option<Self> {
        // Step 1: Map BAR0 into our address space.
        let pages = (bar0_size + 4095) / 4096;
        // I219 BAR0 is typically 128 KB; cap mapping at 32 pages (128 KB)
        // since we only access registers up to 0x05500.
        let pages = core::cmp::min(pages, 32);
        let mmio = Mmio::map(bar0_phys, pages)?;

        // Step 2: Reset the device. Per the manual:
        //   1. Disable interrupts (IMC = ~0)
        //   2. Set CTRL.RST
        //   3. Wait ~1ms
        //   4. Disable interrupts again (cleared by reset)
        mmio.write32(REG_IMC, 0xFFFF_FFFF);
        mmio.set_bits32(REG_CTRL, CTRL_RST);
        spin_delay(50_000);
        mmio.write32(REG_IMC, 0xFFFF_FFFF);

        // Step 3: Read MAC from RAH/RAL (set by EEPROM at power-on).
        let ral = mmio.read32(REG_RAL0);
        let rah = mmio.read32(REG_RAH0);
        let mac: [u8; 6] = [
            (ral & 0xFF) as u8,
            ((ral >> 8) & 0xFF) as u8,
            ((ral >> 16) & 0xFF) as u8,
            ((ral >> 24) & 0xFF) as u8,
            (rah & 0xFF) as u8,
            ((rah >> 8) & 0xFF) as u8,
        ];

        // If the MAC reads as all zeros or all-ones, the EEPROM probably
        // hasn't loaded — bail out.
        if mac.iter().all(|&b| b == 0) || mac.iter().all(|&b| b == 0xFF) {
            sys::print(b"[I219] MAC read from EEPROM looks invalid\n");
            return None;
        }

        // Step 4: Re-write RAH with AV (Address Valid) bit set so the
        // device accepts unicast packets to our MAC.
        mmio.write32(REG_RAL0, ral);
        mmio.write32(REG_RAH0, (rah & 0xFFFF) | RAH_AV);

        // Step 5: Clear Multicast Table Array (no multicast filtering).
        for i in 0..MTA_ENTRIES {
            mmio.write32(REG_MTA_BASE + i * 4, 0);
        }

        // Step 6: Set up CTRL — Set Link Up + Auto-Speed Detect.
        // Don't force speed/duplex; let auto-negotiation handle it.
        let ctrl = mmio.read32(REG_CTRL);
        mmio.write32(REG_CTRL, ctrl | CTRL_SLU | CTRL_ASDE);

        // Step 7: Allocate descriptor rings.
        let tx_ring = Ring::alloc()?;
        let rx_ring = Ring::alloc()?;

        let mut driver = I219Driver {
            mmio,
            mac,
            tx_ring,
            rx_ring,
            rx_next: 0,
        };

        // Step 8: Initialize TX ring.
        driver.init_tx();

        // Step 9: Initialize RX ring (post all bounce buffers as available).
        driver.init_rx();

        sys::print(b"[I219] Device initialized, MAC=");
        print_mac(&driver.mac);
        sys::print(b"\n");

        Some(driver)
    }

    /// Configure TX descriptor ring base/length and enable transmitter.
    fn init_tx(&mut self) {
        let base = self.tx_ring.desc_paddr;
        self.mmio.write32(REG_TDBAL, (base & 0xFFFF_FFFF) as u32);
        self.mmio.write32(REG_TDBAH, (base >> 32) as u32);
        self.mmio.write32(REG_TDLEN, self.tx_ring.byte_size());
        self.mmio.write32(REG_TDH, 0);
        self.mmio.write32(REG_TDT, 0);

        // TIPG: standard IEEE 802.3 inter-packet gap (per Intel manual default).
        self.mmio.write32(REG_TIPG, 0x0060_200A);

        // Enable transmitter:
        //   EN | PSP (pad short packets) | CT=0x10 | COLD=0x40
        let tctl = TCTL_EN
            | TCTL_PSP
            | (0x10 << TCTL_CT_SHIFT)
            | (0x40 << TCTL_COLD_SHIFT);
        self.mmio.write32(REG_TCTL, tctl);
    }

    /// Configure RX descriptor ring base/length, post all bounce buffers,
    /// then enable the receiver.
    fn init_rx(&mut self) {
        // Pre-fill all descriptors with their bounce buffer addresses.
        for slot in 0..RING_SIZE {
            if let Some(buf) = self.rx_ring.buf(slot) {
                let paddr = buf.paddr;
                self.rx_ring.write_rx_desc(slot, RxDesc {
                    addr: paddr,
                    length: 0,
                    checksum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                });
            }
        }

        // Program the ring registers.
        let base = self.rx_ring.desc_paddr;
        self.mmio.write32(REG_RDBAL, (base & 0xFFFF_FFFF) as u32);
        self.mmio.write32(REG_RDBAH, (base >> 32) as u32);
        self.mmio.write32(REG_RDLEN, self.rx_ring.byte_size());
        self.mmio.write32(REG_RDH, 0);
        // Tail = ring size - 1: all slots are available to the device.
        self.mmio.write32(REG_RDT, (RING_SIZE - 1) as u32);

        // Enable receiver: EN | BAM (broadcast accept) | BSIZE=2048 | SECRC
        let rctl = RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC;
        self.mmio.write32(REG_RCTL, rctl);
    }

    /// Send a packet by writing to the next available TX descriptor.
    /// Polls for descriptor done; returns false on timeout.
    fn send_packet(&mut self, packet: &[u8]) -> bool {
        if packet.is_empty() || packet.len() > BUF_SIZE as usize {
            return false;
        }

        let slot = self.tx_ring.next as usize % RING_SIZE;

        // Copy packet into the bounce buffer for this slot.
        let buf = match self.tx_ring.buf(slot) {
            Some(b) => *b,
            None => return false,
        };
        let copied = buf.write(packet);
        if copied != packet.len() {
            return false;
        }

        // Build the descriptor.
        let desc = TxDesc {
            addr: buf.paddr,
            length: packet.len() as u16,
            cso: 0,
            cmd: TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS,
            status: 0,
            css: 0,
            special: 0,
        };
        self.tx_ring.write_tx_desc(slot, desc);

        // Advance tail to publish the descriptor.
        let new_tail = ((slot + 1) % RING_SIZE) as u32;
        self.mmio.write32(REG_TDT, new_tail);
        self.tx_ring.next = new_tail as u16;

        // Poll for the device to set STATUS.DD on this descriptor.
        for _ in 0..1_000_000 {
            let d = self.tx_ring.tx_desc(slot);
            if d.status & TX_STATUS_DD != 0 {
                return true;
            }
            spin_delay(10);
        }
        false
    }

    /// Poll for a received packet. Returns the number of bytes copied
    /// to `out`, or 0 if no packet is available.
    fn recv_packet(&mut self, out: &mut [u8]) -> usize {
        let slot = self.rx_next as usize % RING_SIZE;
        let desc = self.rx_ring.rx_desc(slot);

        if desc.status & RX_STATUS_DD == 0 {
            return 0; // Not yet received
        }

        // Validate length: must fit in our bounce buffer.
        let raw_len = desc.length as usize;
        if raw_len == 0 || raw_len > BUF_SIZE as usize {
            // Hostile or corrupt — recycle the slot and skip.
            self.recycle_rx_slot(slot);
            return 0;
        }

        // Errors? Drop the packet.
        if desc.errors != 0 {
            self.recycle_rx_slot(slot);
            return 0;
        }

        // Copy out of the bounce buffer.
        let copied = if let Some(buf) = self.rx_ring.buf(slot) {
            buf.read(out, raw_len)
        } else {
            0
        };

        self.recycle_rx_slot(slot);
        copied
    }

    /// Reset a descriptor's status and re-publish it as available.
    fn recycle_rx_slot(&mut self, slot: usize) {
        if let Some(buf) = self.rx_ring.buf(slot) {
            let paddr = buf.paddr;
            self.rx_ring.write_rx_desc(slot, RxDesc {
                addr: paddr,
                length: 0,
                checksum: 0,
                status: 0,
                errors: 0,
                special: 0,
            });
        }
        // Move tail forward to give the device this slot back.
        // RDT must trail RDH; setting RDT = (slot + 1) makes [old_RDT..slot]
        // available.
        let new_tail = (slot as u32) % (RING_SIZE as u32);
        self.mmio.write32(REG_RDT, new_tail);
        self.rx_next = ((slot + 1) % RING_SIZE) as u16;
    }

    /// Returns true if the link is currently up.
    fn link_up(&self) -> bool {
        self.mmio.read32(REG_STATUS) & STATUS_LU != 0
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

fn handle_get_mac(driver: &I219Driver, response: &mut [u8]) -> usize {
    response[0] = STATUS_OK;
    response[1..7].copy_from_slice(&driver.mac);
    7
}

fn handle_get_status(driver: &I219Driver, response: &mut [u8]) -> usize {
    response[0] = STATUS_OK;
    response[1] = if driver.link_up() { 1 } else { 0 };
    2
}

fn handle_send_packet(driver: &mut I219Driver, payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_ERROR;
        return 1;
    }
    response[0] = if driver.send_packet(payload) {
        STATUS_OK
    } else {
        STATUS_ERROR
    };
    1
}

fn handle_recv_packet(driver: &mut I219Driver, response: &mut [u8]) -> usize {
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
    sys::print(b"[I219] Intel I219-LM driver starting\n");

    // Step 1: Find the I219 PCI device.
    let dev = match pci::PciDeviceInfo::find_i219() {
        Some(d) => d,
        None => {
            sys::print(b"[I219] No I219-LM device found (expected on QEMU)\n");
            // Don't register the endpoint — virtio-net may take it.
            no_device_loop();
        }
    };

    sys::print(b"[I219] Found Intel Ethernet device\n");

    // Step 2: Locate BAR0 (MMIO).
    let bar0 = match dev.first_mmio_bar() {
        Some(b) => b,
        None => {
            sys::print(b"[I219] No MMIO BAR found\n");
            no_device_loop();
        }
    };

    // Step 3: Initialize the device.
    let mut driver = match I219Driver::init(bar0.addr, bar0.size) {
        Some(d) => d,
        None => {
            sys::print(b"[I219] Device initialization failed\n");
            no_device_loop();
        }
    };

    // Step 4: Wait for link (best-effort, doesn't block init).
    if phy::wait_for_link(&driver.mmio, 200) {
        sys::print(b"[I219] Link is up\n");
    } else {
        sys::print(b"[I219] Link is down (no cable?)\n");
    }

    // Step 5: Register IPC endpoint and enter service loop.
    sys::register_endpoint(NET_ENDPOINT);
    sys::print(b"[I219] Endpoint 20 registered, entering service loop\n");

    let mut recv_buf = [0u8; 256];
    let mut resp_buf = [0u8; 256];

    loop {
        let msg = match sys::recv_verified(NET_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };

        let (cmd, cmd_data) = match msg.command() {
            Some(pair) => pair,
            None => continue,
        };

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

        sys::write(msg.from_endpoint(), &resp_buf[..resp_len]);
    }
}

/// Idle loop when no device is found.
///
/// Unlike virtio-net, the I219 driver does NOT register the endpoint
/// in this case — it leaves endpoint 20 free for the virtio-net driver
/// (which is what runs on QEMU). On bare-metal hardware, virtio-net
/// won't find a device and the endpoint will be ours.
fn no_device_loop() -> ! {
    loop {
        sys::yield_now();
    }
}
