// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS interactive shell
//!
//! A minimal command-line shell over the serial console. Supports built-in
//! commands and spawning boot module ELFs by name.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libsys as sys;

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Let other boot modules finish their startup output before we
    // take over the serial console with the interactive prompt.
    for _ in 0..500 {
        sys::yield_now();
    }

    sys::print(b"\r\n");
    sys::print(b"CambiOS Shell v0.1\r\n");
    sys::print(b"Type 'help' for available commands.\r\n");

    loop {
        sys::print(b"arcos> ");

        let mut line_buf = [0u8; 128];
        let len = read_line(&mut line_buf);

        if len == 0 {
            continue;
        }

        let line = &line_buf[..len];
        dispatch_command(line);
    }
}

// ============================================================================
// Line reader (polling serial input)
// ============================================================================

fn read_line(buf: &mut [u8]) -> usize {
    let mut pos = 0;
    let mut byte_buf = [0u8; 1];

    loop {
        let n = sys::console_read(&mut byte_buf);
        if n <= 0 {
            sys::yield_now();
            continue;
        }

        let ch = byte_buf[0];

        match ch {
            // Enter (CR or LF) — submit line
            b'\r' | b'\n' => {
                sys::print(b"\r\n");
                return pos;
            }
            // Backspace (DEL or BS)
            0x7F | 0x08 => {
                if pos > 0 {
                    pos -= 1;
                    // Erase character on terminal: backspace, space, backspace
                    sys::print(b"\x08 \x08");
                }
            }
            // Ctrl-C — abandon line
            0x03 => {
                sys::print(b"^C\r\n");
                return 0;
            }
            // Printable characters
            0x20..=0x7E => {
                if pos < buf.len() {
                    buf[pos] = ch;
                    pos += 1;
                    // Echo the character
                    sys::print(&[ch]);
                }
            }
            // Ignore other control characters
            _ => {}
        }
    }
}

// ============================================================================
// Command dispatch
// ============================================================================

fn dispatch_command(line: &[u8]) {
    // Trim leading/trailing whitespace
    let trimmed = trim(line);
    if trimmed.is_empty() {
        return;
    }

    // Split into command and arguments at first space
    let (cmd, args) = split_first_space(trimmed);

    match cmd {
        b"help" => cmd_help(),
        b"echo" => cmd_echo(args),
        b"time" => cmd_time(),
        b"pid" => cmd_pid(),
        b"clear" => cmd_clear(),
        b"exit" => sys::exit(0),
        _ => cmd_spawn(cmd),
    }
}

// ============================================================================
// Built-in commands
// ============================================================================

fn cmd_help() {
    sys::print(b"Built-in commands:\r\n");
    sys::print(b"  help   - Show this help\r\n");
    sys::print(b"  echo   - Print text\r\n");
    sys::print(b"  time   - Show system ticks\r\n");
    sys::print(b"  pid    - Show shell process ID\r\n");
    sys::print(b"  clear  - Clear screen\r\n");
    sys::print(b"  exit   - Exit shell\r\n");
    sys::print(b"\r\nExternal commands (boot modules):\r\n");
    sys::print(b"  hello, key-store-service, fs-service, ...\r\n");
}

fn cmd_echo(args: &[u8]) {
    sys::print(args);
    sys::print(b"\r\n");
}

fn cmd_time() {
    let ticks = sys::get_time();
    // Print as decimal — no format! macro available in no_std without alloc
    sys::print(b"System ticks: ");
    print_u64(ticks);
    sys::print(b"\r\n");
}

fn cmd_pid() {
    let pid = sys::get_pid();
    sys::print(b"Shell PID: ");
    print_u64(pid as u64);
    sys::print(b"\r\n");
}

fn cmd_clear() {
    // ANSI escape: clear screen + move cursor to top-left
    sys::print(b"\x1b[2J\x1b[H");
}

// ============================================================================
// External command (spawn boot module)
// ============================================================================

fn cmd_spawn(name: &[u8]) {
    let result = sys::spawn(name);
    if result < 0 {
        sys::print(b"Unknown command: ");
        sys::print(name);
        sys::print(b"\r\n");
        return;
    }

    let task_id = result as u32;
    let exit_code = sys::wait_task(task_id);

    // Print exit info
    sys::print(b"[");
    sys::print(name);
    sys::print(b" exited with code ");
    print_u64(exit_code as u64);
    sys::print(b"]\r\n");
}

// ============================================================================
// Utility functions
// ============================================================================

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| b != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&b| b != b' ').map_or(start, |i| i + 1);
    if start >= end { &[] } else { &s[start..end] }
}

fn split_first_space(s: &[u8]) -> (&[u8], &[u8]) {
    match s.iter().position(|&b| b == b' ') {
        Some(i) => {
            let args = &s[i + 1..];
            let args = trim(args);
            (&s[..i], args)
        }
        None => (s, &[]),
    }
}

/// Print a u64 as decimal to the serial console.
fn print_u64(mut val: u64) {
    if val == 0 {
        sys::print(b"0");
        return;
    }
    let mut buf = [0u8; 20]; // max digits for u64
    let mut pos = buf.len();
    while val > 0 {
        pos -= 1;
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    sys::print(&buf[pos..]);
}

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"\r\n!!! SHELL PANIC !!!\r\n");
    sys::exit(1);
}
