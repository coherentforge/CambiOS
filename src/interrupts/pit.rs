//! 8253/8254 PIT (Programmable Interval Timer) driver
//!
//! Configures the PIT Channel 0 to generate periodic timer interrupts
//! at the requested frequency. Connected to IRQ 0 (PIC master).
//!
//! The PIT has a base frequency of 1,193,182 Hz and uses a 16-bit divisor,
//! giving a range of ~18.2 Hz (divisor 65535) to 1,193,182 Hz (divisor 1).

use x86_64::instructions::port::Port;

/// PIT I/O ports
const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

/// PIT base frequency in Hz
const PIT_BASE_FREQUENCY: u32 = 1_193_182;

/// PIT command byte: Channel 0, lobyte/hibyte, rate generator (mode 2)
const PIT_CMD_CHANNEL0_RATE: u8 = 0x34; // 0b00_11_010_0

/// Initialize PIT Channel 0 at the given frequency
///
/// Configures the PIT in rate generator mode (mode 2) for periodic interrupts.
/// The actual frequency may differ slightly due to integer division.
///
/// # Arguments
/// * `frequency_hz` - Desired interrupt frequency (18-1193182 Hz)
///
/// # Returns
/// The actual divisor used (for verification)
///
/// # Safety
/// Must be called after PIC init and before enabling interrupts.
pub unsafe fn init(frequency_hz: u32) -> u16 {
    // SAFETY for all Port I/O in this function:
    // Called once during boot with interrupts disabled. Ports 0x40 (Channel 0 data)
    // and 0x43 (command) are the standard 8254 PIT I/O addresses.
    // The command byte 0x34 selects Channel 0, lobyte/hibyte access, rate generator mode.

    // Calculate divisor (clamped to u16 range)
    let divisor = if frequency_hz == 0 {
        65535u16 // Minimum frequency (~18.2 Hz)
    } else {
        let raw = PIT_BASE_FREQUENCY / frequency_hz;
        if raw > 65535 {
            65535u16
        } else if raw < 1 {
            1u16
        } else {
            raw as u16
        }
    };

    let mut cmd_port = Port::<u8>::new(PIT_COMMAND);
    let mut data_port = Port::<u8>::new(PIT_CHANNEL0);

    // Send command: Channel 0, lobyte/hibyte, rate generator
    cmd_port.write(PIT_CMD_CHANNEL0_RATE);

    // Send divisor (low byte first, then high byte)
    data_port.write((divisor & 0xFF) as u8);
    data_port.write((divisor >> 8) as u8);

    divisor
}
