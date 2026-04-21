// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! 8259 PIC (Programmable Interrupt Controller) driver
//!
//! Remaps hardware IRQs from default vectors (0-15, which conflict with
//! CPU exceptions) to vectors 32-47. Provides EOI signaling.
//!
//! In a production system, this would be replaced by APIC for SMP support.
//! The legacy PIC is sufficient for single-core boot and early development.

use x86_64::instructions::port::Port;

/// Master PIC I/O ports
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;

/// Slave PIC I/O ports
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// ICW1: Initialization command word 1
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01; // ICW4 needed

/// ICW4: 8086 mode
const ICW4_8086: u8 = 0x01;

/// End-of-interrupt command
const PIC_EOI: u8 = 0x20;

/// Vector offset for master PIC (IRQ 0-7 → vectors 32-39)
pub const PIC1_OFFSET: u8 = 32;

/// Vector offset for slave PIC (IRQ 8-15 → vectors 40-47)
pub const PIC2_OFFSET: u8 = 40;

/// Timer interrupt vector (IRQ 0 remapped)
pub const TIMER_VECTOR: u8 = PIC1_OFFSET; // Vector 32

/// Initialize and remap both PICs
///
/// Remaps IRQ 0-7 to vectors 32-39 and IRQ 8-15 to vectors 40-47.
/// After init, only the timer IRQ (IRQ 0) is unmasked; all others are masked.
///
/// # Safety
/// Must be called exactly once during boot, before enabling interrupts.
pub unsafe fn init() {
    let mut pic1_cmd = Port::<u8>::new(PIC1_COMMAND);
    let mut pic1_data = Port::<u8>::new(PIC1_DATA);
    let mut pic2_cmd = Port::<u8>::new(PIC2_COMMAND);
    let mut pic2_data = Port::<u8>::new(PIC2_DATA);

    // Save current masks
    // SAFETY: Reading from PIC data port is a standard x86 I/O operation.
    let mask1: u8 = unsafe { pic1_data.read() };
    // SAFETY: Same — reading slave PIC data port.
    let mask2: u8 = unsafe { pic2_data.read() };

    // ICW1: Start initialization sequence (cascade mode, ICW4 needed)
    // SAFETY: Writing PIC command byte is a standard ICW1 operation.
    unsafe { pic1_cmd.write(ICW1_INIT | ICW1_ICW4) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };
    // SAFETY: Writing slave PIC command byte.
    unsafe { pic2_cmd.write(ICW1_INIT | ICW1_ICW4) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };

    // ICW2: Set vector offsets
    // SAFETY: ICW2 — setting master PIC vector offset.
    unsafe { pic1_data.write(PIC1_OFFSET) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };
    // SAFETY: ICW2 — setting slave PIC vector offset.
    unsafe { pic2_data.write(PIC2_OFFSET) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };

    // ICW3: Tell PICs about each other
    // SAFETY: ICW3 — master: slave PIC at IRQ2.
    unsafe { pic1_data.write(4) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };
    // SAFETY: ICW3 — slave: cascade identity.
    unsafe { pic2_data.write(2) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };

    // ICW4: 8086 mode
    // SAFETY: ICW4 — master 8086 mode.
    unsafe { pic1_data.write(ICW4_8086) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };
    // SAFETY: ICW4 — slave 8086 mode.
    unsafe { pic2_data.write(ICW4_8086) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };

    // Mask all IRQs except IRQ 0 (timer) on master
    // SAFETY: Writing mask register.
    unsafe { pic1_data.write(0xFE) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };
    // Mask all IRQs on slave
    // SAFETY: Writing slave mask register.
    unsafe { pic2_data.write(0xFF) };
    // SAFETY: I/O delay via port 0x80 — standard x86 ~1µs wait.
    unsafe { io_wait() };

    let _ = (mask1, mask2); // Acknowledge saved masks (not restored)
}

/// Send End-of-Interrupt to the PIC(s)
///
/// Must be called at the end of every hardware interrupt handler.
/// For IRQs 8-15 (slave PIC), EOI must be sent to both PICs.
///
/// # Safety
/// Must be called from an interrupt handler context for a valid IRQ.
pub unsafe fn send_eoi(irq: u8) {
    let mut pic1_cmd = Port::<u8>::new(PIC1_COMMAND);

    if irq >= 8 {
        let mut pic2_cmd = Port::<u8>::new(PIC2_COMMAND);
        // SAFETY: Writing PIC_EOI to slave PIC command port.
        unsafe { pic2_cmd.write(PIC_EOI) };
    }
    // SAFETY: Writing PIC_EOI to master PIC command port.
    unsafe { pic1_cmd.write(PIC_EOI) };
}

/// Small I/O delay (needed between PIC commands)
#[inline(always)]
unsafe fn io_wait() {
    // SAFETY: Port 0x80 is the POST diagnostic port, commonly used as a ~1µs
    // I/O delay. Writing 0 has no effect on modern hardware.
    unsafe {
        let mut port = Port::<u8>::new(0x80);
        port.write(0);
    }
}
