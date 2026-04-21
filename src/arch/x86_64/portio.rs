// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! x86 port-mapped I/O wrappers
//!
//! Safe wrappers around `in`/`out` instructions. All legacy port I/O in the
//! kernel (PIC, PIT, APIC calibration, POST delays) should use these instead
//! of inline assembly directly.
//!
//! # Safety model
//! Port I/O is inherently privileged (ring 0). The unsafe boundary is at
//! `Port::new()` — the caller guarantees the port number is valid and that
//! accessing it is appropriate in the current boot state. Once constructed,
//! reads and writes are safe.

/// An 8-bit I/O port.
#[derive(Clone, Copy)]
pub struct Port8 {
    port: u16,
}

impl Port8 {
    /// Create a handle to an 8-bit I/O port.
    ///
    /// # Safety
    /// `port` must be a valid x86 I/O port number. The caller must ensure
    /// that accessing this port is appropriate (e.g., the device exists and
    /// is in the expected state).
    #[inline]
    pub const unsafe fn new(port: u16) -> Self {
        Self { port }
    }

    /// Read a byte from this port.
    #[inline]
    pub fn read(&self) -> u8 {
        let value: u8;
        // SAFETY: Port was validated at construction time.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") self.port,
                out("al") value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    /// Write a byte to this port.
    #[inline]
    pub fn write(&self, value: u8) {
        // SAFETY: Port was validated at construction time.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.port,
                in("al") value,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    /// Return the port number.
    #[inline]
    pub const fn number(&self) -> u16 {
        self.port
    }
}

/// An 16-bit I/O port.
#[derive(Clone, Copy)]
pub struct Port16 {
    port: u16,
}

impl Port16 {
    /// Create a handle to a 16-bit I/O port.
    ///
    /// # Safety
    /// Same as `Port8::new`.
    #[inline]
    pub const unsafe fn new(port: u16) -> Self {
        Self { port }
    }

    /// Read a 16-bit word from this port.
    #[inline]
    pub fn read(&self) -> u16 {
        let value: u16;
        // SAFETY: Port was validated at construction time.
        unsafe {
            core::arch::asm!(
                "in ax, dx",
                in("dx") self.port,
                out("ax") value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    /// Write a 16-bit word to this port.
    #[inline]
    pub fn write(&self, value: u16) {
        // SAFETY: Port was validated at construction time.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") self.port,
                in("ax") value,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

/// Short I/O delay (~1 µs) via a write to POST diagnostic port 0x80.
///
/// Standard technique for I/O-speed delays on x86. Port 0x80 is universally
/// available and writing to it has no side effects beyond the bus cycle delay.
#[inline]
pub fn io_wait() {
    // SAFETY: Port 0x80 is the standard POST diagnostic port, always safe to write.
    let post_port = unsafe { Port8::new(0x80) };
    post_port.write(0);
}
