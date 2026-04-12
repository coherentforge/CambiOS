// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! I/O subsystem for bootloader communication
//!
//! Provides abstractions for serial port communication and display output.
//! Designed to interface with both hardware and emulators (QEMU).
//!
//! - **x86_64**: Uses uart_16550 crate (port-mapped I/O at 0x3F8 / COM1)
//! - **AArch64**: Uses PL011 UART (MMIO at 0x0900_0000 on QEMU `virt`)
//!
//! In both cases, SERIAL1 is protected by a spinlock for multicore safety.

use core::fmt;
#[cfg(target_arch = "x86_64")]
use uart_16550::SerialPort;
use crate::Spinlock;

// ============================================================================
// x86_64: uart_16550 (port I/O)
// ============================================================================

/// Global serial port, spinlock-protected for multicore safety.
///
/// Initialized once during boot via `init()`. All subsequent access
/// (print!, println!) goes through `lock()`.
#[cfg(target_arch = "x86_64")]
static SERIAL1: Spinlock<Option<SerialPort>> = Spinlock::new(None);

// ============================================================================
// AArch64: PL011 UART (MMIO)
// ============================================================================

/// PL011 UART driver for AArch64.
///
/// Uses memory-mapped I/O to the PL011 peripheral (standard on QEMU `virt`
/// and many ARM SoCs). The base address is configured at init time.
#[cfg(target_arch = "aarch64")]
pub struct Pl011 {
    base: usize,
}

#[cfg(target_arch = "aarch64")]
impl Pl011 {
    /// PL011 register offsets
    const UARTDR: usize = 0x000;   // Data register
    const UARTFR: usize = 0x018;   // Flag register
    const UARTFR_TXFF: u32 = 1 << 5; // TX FIFO full

    /// Create a new PL011 driver at the given MMIO base address.
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Write a single byte, blocking until the TX FIFO has space.
    pub fn send(&mut self, byte: u8) {
        // SAFETY: base points to the PL011 MMIO region.
        // We read the flag register to check TX FIFO full, then write
        // the data register. Both are volatile MMIO accesses.
        unsafe {
            let fr = self.base + Self::UARTFR;
            // Spin until TX FIFO not full
            while core::ptr::read_volatile(fr as *const u32) & Self::UARTFR_TXFF != 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile((self.base + Self::UARTDR) as *mut u32, byte as u32);
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl fmt::Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}

/// QEMU `virt` machine PL011 physical base address.
/// At init time this is translated through the HHDM offset to get the
/// kernel-accessible virtual address.
#[cfg(target_arch = "aarch64")]
const PL011_PHYS_BASE: u64 = 0x0900_0000;

/// Global PL011 serial port, spinlock-protected for multicore safety.
#[cfg(target_arch = "aarch64")]
static SERIAL1: Spinlock<Option<Pl011>> = Spinlock::new(None);

/// Initialize the I/O subsystem
///
/// # Safety
/// Must be called exactly once during boot before any `print!` / `println!` calls.
pub unsafe fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        let mut guard = SERIAL1.lock();
        // SAFETY: 0x3F8 is the standard COM1 I/O port address.
        // Called once during single-core boot.
        let mut port = unsafe { SerialPort::new(0x3f8) };
        port.init();
        *guard = Some(port);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mut guard = SERIAL1.lock();
        // SAFETY: PL011_PHYS_BASE is the standard UART0 physical MMIO address
        // on QEMU virt. We add the HHDM offset (set before io::init) to get
        // the kernel-accessible virtual address. Called once during single-core boot.
        let hhdm = crate::hhdm_offset();
        let virt_base = (PL011_PHYS_BASE + hhdm) as usize;
        *guard = Some(Pl011::new(virt_base));
    }
}

/// Print to serial output
pub fn print(args: fmt::Arguments) {
    use core::fmt::Write;
    let mut guard = SERIAL1.lock();
    if let Some(serial) = guard.as_mut() {
        let _ = write!(serial, "{}", args);
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::io::print(format_args!($($arg)*))
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        $crate::io::print(format_args!("{}\n", format_args!($($arg)*)))
    }};
}

/// Read a single byte from the serial console, if one is available.
///
/// Returns `Some(byte)` if data was waiting, `None` otherwise.
/// Used by the ConsoleRead syscall for polling-mode serial input.
pub fn read_byte() -> Option<u8> {
    #[cfg(target_arch = "x86_64")]
    {
        // Hold SERIAL1 lock to ensure init has completed, but we read
        // COM1 registers directly (uart_16550 doesn't expose a try-receive).
        let mut guard = SERIAL1.lock();
        let _serial = guard.as_mut()?;

        use x86_64::instructions::port::Port;
        let base = 0x3F8u16;
        // SAFETY: Reading Line Status Register (base+5) is a side-effect-free read
        // on a valid x86 I/O port. The serial port was initialized at boot.
        let lsr: u8 = unsafe { Port::new(base + 5).read() };
        if lsr & 0x01 != 0 {
            // SAFETY: Data Register (base+0) read — byte is available per LSR check above.
            let data: u8 = unsafe { Port::new(base).read() };
            Some(data)
        } else {
            None
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mut guard = SERIAL1.lock();
        let serial = guard.as_mut()?;

        // PL011: check UARTFR.RXFE (bit 4). If clear, data is available.
        // SAFETY: base points to the PL011 MMIO region, initialized at boot.
        unsafe {
            let fr = core::ptr::read_volatile((serial.base + Pl011::UARTFR) as *const u32);
            const UARTFR_RXFE: u32 = 1 << 4; // RX FIFO empty
            if fr & UARTFR_RXFE == 0 {
                let data = core::ptr::read_volatile((serial.base + Pl011::UARTDR) as *const u32);
                Some(data as u8)
            } else {
                None
            }
        }
    }
}

/// Interface trait for verification and integration testing
pub trait OutputWriter {
    fn write_byte(&mut self, byte: u8);
    fn write_str(&mut self, s: &str);
}

#[cfg(target_arch = "x86_64")]
impl OutputWriter for SerialPort {
    fn write_byte(&mut self, byte: u8) {
        self.send(byte);
    }

    fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            self.send(byte);
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl OutputWriter for Pl011 {
    fn write_byte(&mut self, byte: u8) {
        self.send(byte);
    }

    fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            self.send(byte);
        }
    }
}
