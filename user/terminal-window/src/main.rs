// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! `terminal-window` — GUI-hosted shell terminal entry point.
//!
//! Opens a libgui window, runs a libterm-driven REPL, dispatches a
//! handful of builtin commands. v1 minimum: prove the input + render
//! loop works end-to-end in QEMU. `/play` (game spawning with the
//! close-before-spawn / reopen-after pattern) and the full shell
//! command set integrate in subsequent commits.

#![no_std]
#![no_main]

extern crate alloc;

use arcos_libsys as sys;
use arcos_libterm::line_editor::{LineEditor, LineResult};
use arcos_libterm::Terminal;
use arcos_terminal_window::gui_backend::GuiBackend;
use linked_list_allocator::LockedHeap;

// ============================================================================
// Userspace heap
// ============================================================================
//
// SCAFFOLDING: 64 KiB static heap. The LineEditor needs alloc for its
// `VecDeque<Vec<u8>>` history; sizing for 64 entries × ~80 bytes ≈ 5 KiB
// peak, with headroom for any other transient allocations the shell
// command path drops on the floor.
// Why: lets the GUI terminal use libterm without refactoring libterm
// to be allocation-free.
// Replace when: the kernel exposes a syscall-mapped per-process heap,
// or libterm gains a no-alloc feature.
const HEAP_SIZE: usize = 64 * 1024;
static mut HEAP_AREA: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// ============================================================================
// Configuration
// ============================================================================

/// terminal-window's reply endpoint. Picked from the empty 0..15 range
/// so it never collides with any boot-module service or game.
const TERMINAL_WINDOW_ENDPOINT: u32 = 14;

/// Window dimensions. 640×240 lines up exactly with 80×30 cells at
/// 8×8 glyphs — no wasted pixels and matches the grid's geometry.
const WINDOW_WIDTH: u32 = 640;
const WINDOW_HEIGHT: u32 = 240;

const PROMPT: &[u8] = b"cambios> ";

const BANNER: &[u8] =
    b"CambiOS terminal v0\r\ntype `help` for commands.\r\n\r\n";

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[terminal-window] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// Entry point
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[terminal-window] starting\n");

    // Initialize the userspace heap before any alloc-using code runs.
    // SAFETY: HEAP_AREA is a static byte buffer with `'static` lifetime.
    // We hand its full extent to the allocator exactly once at startup;
    // no other code reads or writes HEAP_AREA directly.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(HEAP_AREA) as *mut u8;
        ALLOCATOR.lock().init(ptr, HEAP_SIZE);
    }

    let backend = match GuiBackend::open(WINDOW_WIDTH, WINDOW_HEIGHT, TERMINAL_WINDOW_ENDPOINT) {
        Ok(b) => b,
        Err(_) => {
            sys::print(b"[terminal-window] failed to open compositor window\n");
            sys::exit(1);
        }
    };

    sys::print(b"[terminal-window] window open\n");
    sys::module_ready();

    let mut terminal = Terminal::new(backend);
    let mut editor = LineEditor::new(64);

    // Initial banner.
    terminal.write(BANNER);
    // Force a render of the banner before the first read_line so users
    // see the welcome text immediately, not after their first keystroke.
    terminal.backend_mut().render_if_dirty();

    // REPL.
    loop {
        let line = match editor.read_line(&mut terminal, PROMPT) {
            LineResult::Ok(buf) => buf,
            LineResult::Interrupt => continue,
            LineResult::Eof => {
                terminal.write(b"bye\r\n");
                terminal.backend_mut().render_if_dirty();
                sys::exit(0);
            }
        };

        if !line.is_empty() {
            editor.push_history(&line);
        }

        dispatch_command(&mut terminal, &line);

        // Make sure post-command output is visible.
        terminal.backend_mut().render_if_dirty();
    }
}

// ============================================================================
// Command dispatch
// ============================================================================

fn dispatch_command(terminal: &mut Terminal<GuiBackend>, line: &[u8]) {
    let trimmed = trim_ascii(line);
    if trimmed.is_empty() {
        return;
    }
    let (cmd, rest) = split_first_space(trimmed);
    match cmd {
        b"help" => cmd_help(terminal),
        b"echo" => cmd_echo(terminal, rest),
        b"clear" => cmd_clear(terminal),
        b"version" => cmd_version(terminal),
        b"pid" => cmd_pid(terminal),
        b"exit" => {
            terminal.write(b"bye\r\n");
            terminal.backend_mut().render_if_dirty();
            sys::exit(0);
        }
        _ => {
            terminal.write(b"unknown command: ");
            terminal.write(cmd);
            terminal.write(b"\r\n");
        }
    }
}

fn cmd_help(t: &mut Terminal<GuiBackend>) {
    t.write(b"available commands:\r\n");
    t.write(b"  help        list commands\r\n");
    t.write(b"  echo <msg>  print msg\r\n");
    t.write(b"  clear       clear screen\r\n");
    t.write(b"  version     show CambiOS version\r\n");
    t.write(b"  pid         show this task's pid\r\n");
    t.write(b"  exit        leave the terminal\r\n");
}

fn cmd_echo(t: &mut Terminal<GuiBackend>, args: &[u8]) {
    t.write(args);
    t.write(b"\r\n");
}

fn cmd_clear(t: &mut Terminal<GuiBackend>) {
    // libterm output convention: ESC [ 2 J clears, ESC [ H homes.
    t.write(b"\x1b[2J\x1b[H");
}

fn cmd_version(t: &mut Terminal<GuiBackend>) {
    t.write(b"CambiOS v1 - terminal-window v0 (Phase: Scanout-3 single-window)\r\n");
}

fn cmd_pid(t: &mut Terminal<GuiBackend>) {
    let pid = sys::get_pid();
    let mut buf = [0u8; 16];
    let n = format_u32(&mut buf, pid);
    t.write(b"pid: ");
    t.write(&buf[..n]);
    t.write(b"\r\n");
}

// ============================================================================
// Tiny string helpers (no_std, no alloc)
// ============================================================================

fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    let mut end = s.len();
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

fn split_first_space(s: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < s.len() && s[i] != b' ' && s[i] != b'\t' {
        i += 1;
    }
    if i == s.len() {
        return (s, &[]);
    }
    let cmd = &s[..i];
    let mut j = i;
    while j < s.len() && (s[j] == b' ' || s[j] == b'\t') {
        j += 1;
    }
    (cmd, &s[j..])
}

fn format_u32(buf: &mut [u8], mut n: u32) -> usize {
    if n == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
            return 1;
        }
        return 0;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while n > 0 && len < tmp.len() {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut out = 0;
    while out < len && out < buf.len() {
        buf[out] = tmp[len - 1 - out];
        out += 1;
    }
    out
}

