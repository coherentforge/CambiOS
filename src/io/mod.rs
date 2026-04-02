//! I/O subsystem for bootloader communication
//!
//! Provides abstractions for serial port communication and display output.
//! Designed to interface with both hardware and emulators (QEMU).

use core::fmt;
use uart_16550::SerialPort;

static mut SERIAL1: Option<SerialPort> = None;

/// Initialize the I/O subsystem
pub unsafe fn init() {
    SERIAL1 = Some(SerialPort::new(0x3f8));
    if let Some(serial) = (*(&raw mut SERIAL1)).as_mut() {
        serial.init();
    }
}

/// Print to serial output
pub fn print(args: fmt::Arguments) {
    use core::fmt::Write;
    
    unsafe {
        if let Some(serial) = (*(&raw mut SERIAL1)).as_mut() {
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
