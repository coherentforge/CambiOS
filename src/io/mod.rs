//! I/O subsystem for bootloader communication
//!
//! Provides abstractions for serial port communication and display output.
//! Designed to interface with both hardware and emulators (QEMU).
//!
//! SERIAL1 is protected by a spinlock for multicore safety.

use core::fmt;
#[cfg(target_arch = "x86_64")]
use uart_16550::SerialPort;
use crate::Spinlock;

/// Global serial port, spinlock-protected for multicore safety.
///
/// Initialized once during boot via `init()`. All subsequent access
/// (print!, println!) goes through `lock()`.
#[cfg(target_arch = "x86_64")]
static SERIAL1: Spinlock<Option<SerialPort>> = Spinlock::new(None);

/// Initialize the I/O subsystem
///
/// # Safety
/// Must be called exactly once during boot before any `print!` / `println!` calls.
pub unsafe fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        let mut guard = SERIAL1.lock();
        let mut port = SerialPort::new(0x3f8);
        // SAFETY: 0x3F8 is the standard COM1 I/O port address.
        // Called once during single-core boot.
        port.init();
        *guard = Some(port);
    }
}

/// Print to serial output
pub fn print(args: fmt::Arguments) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::fmt::Write;
        let mut guard = SERIAL1.lock();
        if let Some(serial) = guard.as_mut() {
            let _ = write!(serial, "{}", args);
        }
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
