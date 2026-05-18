// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS USB Host Driver — Stream B, substage B-i.
//!
//! Userspace xHCI bring-up skeleton. Discovers an xHCI controller via the
//! `DeviceInfo` syscall (PCI class=0x0C, subclass=0x03, prog_if=0x30), maps
//! its MMIO BAR, parses the capability register block per xHCI 1.2 § 5.3,
//! logs the result, and idles on endpoint 31.
//!
//! ## Scope — B-i
//!
//! Capability discovery only. The crate does NOT yet touch operational
//! registers (HCRESET / Run-Stop), command/event rings, or any port.
//! Those land in B-ii.
//!
//! On platforms where no xHCI controller is discovered (e.g. aarch64 /
//! riscv64 QEMU without `-device qemu-xhci`), the driver logs a single
//! line and idles cleanly so the boot gate still releases the next module.
//!
//! ## IPC protocol
//!
//! Endpoint 31 is registered but accepts no commands at B-i. Incoming
//! messages are read and dropped (B-i validation does not exercise IPC).
//! Command surface lands at B-iii / B-v as the stack grows.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

mod pci;
#[allow(unsafe_code)]
mod xhci;

use cambios_libsys as sys;

const USB_HOST_ENDPOINT: u32 = 31;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[USB-HOST] PANIC!\n");
    sys::exit(1);
}

// ---------------------------------------------------------------------------
// Diagnostic logging
// ---------------------------------------------------------------------------

fn hex_nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

fn log_hex64(label: &[u8], v: u64) {
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

fn log_dec(label: &[u8], v: u32) {
    sys::print(label);
    let mut buf = [b'0'; 10];
    let mut i = 9usize;
    let mut n = v;
    if n == 0 {
        sys::print(b"0\n");
        return;
    }
    while n > 0 && i < buf.len() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if i == 0 { break; }
        i -= 1;
    }
    sys::print(&buf[i + 1..]);
    sys::print(b"\n");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Step 1: locate the xHCI controller via PCI class/subclass/prog_if.
    let dev = match pci::PciDeviceInfo::find_xhci() {
        Some(d) => d,
        None => {
            sys::print(b"[USB-HOST] no xHCI controller found, idling on ep 31\n");
            sys::register_endpoint(USB_HOST_ENDPOINT);
            sys::module_ready();
            idle_loop();
        }
    };

    // Step 2: locate the MMIO BAR. xHCI is required to expose its register
    // file via a memory BAR (xHCI 1.2 § 5.2.1); we pick the first non-zero
    // memory BAR found.
    let mut mmio_paddr: u64 = 0;
    let mut mmio_size: u32 = 0;
    for b in 0..6 {
        let bar = dev.bars[b];
        if bar.addr != 0 && !bar.is_io {
            mmio_paddr = bar.addr;
            mmio_size = bar.size;
            break;
        }
    }
    if mmio_paddr == 0 {
        sys::print(b"[USB-HOST] ERROR: xHCI found but no MMIO BAR, idling\n");
        sys::register_endpoint(USB_HOST_ENDPOINT);
        sys::module_ready();
        idle_loop();
    }

    // Step 3: map the BAR. xHCI register file spans capability + operational
    // + runtime + doorbell regions; map the full BAR up front so later
    // substages (B-ii operational, B-iii doorbell) don't need to re-map.
    sys::print(b"[USB-HOST] xhci detected\n");
    log_hex64(b"[USB-HOST]   MMIO paddr = ", mmio_paddr);
    log_hex64(b"[USB-HOST]   MMIO size  = ", mmio_size as u64);
    let pages = ((mmio_size as u64 + 0xFFF) / 0x1000).max(1) as u32;
    let mapped = sys::map_mmio(mmio_paddr, pages);
    if mapped < 0 {
        log_dec(b"[USB-HOST] ERROR: map_mmio failed with rc=-", (-mapped) as u32);
        sys::print(b"[USB-HOST] idling on ep 31\n");
        sys::register_endpoint(USB_HOST_ENDPOINT);
        sys::module_ready();
        idle_loop();
    }
    let mmio_vaddr = mapped as u64;
    log_hex64(b"[USB-HOST]   MMIO vaddr = ", mmio_vaddr);

    // Step 4: parse capability registers (xHCI 1.2 § 5.3).
    let caps = xhci::parse_capabilities(mmio_vaddr);

    // Step 5: log the cap-register dump.
    log_dec(b"[USB-HOST]   HCIVERSION = ", caps.hci_version as u32);
    log_dec(b"[USB-HOST]   CapLength  = ", caps.cap_length as u32);
    log_dec(b"[USB-HOST]   MaxSlots   = ", caps.max_slots as u32);
    log_dec(b"[USB-HOST]   MaxIntrs   = ", caps.max_intrs as u32);
    log_dec(b"[USB-HOST]   MaxPorts   = ", caps.max_ports as u32);
    log_dec(b"[USB-HOST]   AC64       = ", caps.ac64 as u32);
    log_hex64(b"[USB-HOST]   DBOFF      = ", caps.doorbell_offset as u64);
    log_hex64(b"[USB-HOST]   RTSOFF     = ", caps.runtime_offset as u64);

    // Step 6: register IPC endpoint and release boot gate.
    sys::register_endpoint(USB_HOST_ENDPOINT);
    sys::print(b"[USB-HOST] ready on endpoint 31\n");
    sys::module_ready();

    idle_loop();
}

fn idle_loop() -> ! {
    // B-i has no IPC command surface yet. Drain any incoming message and
    // sleep; commands arrive at B-iii / B-v.
    let mut recv_buf = [0u8; 256];
    loop {
        let n = sys::try_recv_msg(USB_HOST_ENDPOINT, &mut recv_buf);
        if n <= 0 {
            sys::yield_now();
        }
    }
}
