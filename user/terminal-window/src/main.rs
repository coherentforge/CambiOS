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

use cambios_libsys as sys;
use cambios_libterm::line_editor::{LineEditor, LineResult};
use cambios_libterm::Terminal;
use cambios_style::format;
use cambios_terminal_window::gui_backend::GuiBackend;
use core::fmt::Write;
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

/// Window dimensions. 1024×768 lines up exactly with the 128×96 cell
/// grid (`grid::COLS` × `grid::VISIBLE_ROWS`) at 8×8 glyphs — no wasted
/// pixels — and exactly matches the QEMU virtio-vga default scanout, so
/// the compositor blits the whole framebuffer and nothing of the prior
/// frame's contents (e.g. the boot-time cyan test fill) survives around
/// the edges. Replace when the scanout dimensions are queryable through
/// libgui at CreateWindow time, or when window decorations / tiling
/// give us a deliberate sub-scanout region.
const WINDOW_WIDTH: u32 = 1024;
const WINDOW_HEIGHT: u32 = 768;

/// Stack buffer for the rendered prompt. The fully-styled
/// `cambios@<short-did>:HH:MM> ` form runs ~70 bytes once ANSI escapes
/// are factored in; 128 leaves comfortable slack.
const PROMPT_BUF_SIZE: usize = 128;

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
        let mut prompt_buf = [0u8; PROMPT_BUF_SIZE];
        let prompt = render_prompt(&mut prompt_buf);
        let line = match editor.read_line(&mut terminal, prompt) {
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
        b"play" => cmd_play(terminal, rest),
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
    t.write(b"  play <game> launch a game (`play` alone lists them)\r\n");
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
// `play` — close → spawn → wait → reopen window-lifecycle wrapper
// ============================================================================
//
// The serial shell's `cmd_play` ([user/shell/src/main.rs::cmd_play]) is the
// reference implementation; this version layers GUI window choreography on
// top so the spawned game becomes the compositor's "first live window" and
// receives input directly:
//
//   write "launching: <name>..." → render → close window → sys::spawn
//     → sys::wait_task → reopen window → invalidate_all → REPL repaints
//
// The allowlist is duplicated from the kernel's spawn-only set
// ([src/microkernel/main.rs]); kernel rejects unknowns regardless. The
// userspace allowlist exists to print a readable error before any
// close/spawn happens, instead of surfacing a numeric kernel rc.

const KNOWN_GAMES: &[&[u8]] = &[b"tree", b"worm", b"pong", b"super-sprouty-o"];

fn is_known_game(name: &[u8]) -> bool {
    KNOWN_GAMES.iter().any(|g| *g == name)
}

fn cmd_play(t: &mut Terminal<GuiBackend>, args: &[u8]) {
    let name = trim_ascii(args);
    if name.is_empty() {
        t.write(b"usage: play <game>\r\n");
        t.write(b"games: tree, worm, pong, super-sprouty-o\r\n");
        return;
    }
    if !is_known_game(name) {
        t.write(b"unknown game: ");
        t.write(name);
        t.write(b"\r\ntry: tree, worm, pong, super-sprouty-o\r\n");
        return;
    }

    // Plain-text loader cue. Splash / title-card / wipe theatrics layer
    // on top in a follow-up — see project_play_arcade_loader memory.
    t.write(b"launching: ");
    t.write(name);
    t.write(b"...\r\n");
    t.backend_mut().render_if_dirty();

    // Surrender the window so the spawned game becomes "first live
    // window" and receives input directly.
    t.backend_mut().close();

    let tid = sys::spawn(name);
    if tid < 0 {
        // Spawn failed before the game ran — re-attach and report.
        // Keep the terminal alive; the user can try a different game.
        if t.backend_mut().reopen().is_err() {
            sys::print(b"[terminal-window] reopen failed after spawn error\n");
            sys::exit(1);
        }
        t.backend_mut().invalidate_all();
        t.write(b"spawn failed: rc=");
        let mut buf = [0u8; 16];
        let n = format_i64(&mut buf, tid);
        t.write(&buf[..n]);
        t.write(b"\r\n");
        return;
    }

    let _exit = sys::wait_task(tid as u32);

    // Game's done — re-attach our window. If reopen fails the GUI is
    // dead and the terminal can't draw; clean exit beats a zombie.
    if t.backend_mut().reopen().is_err() {
        sys::print(b"[terminal-window] reopen failed after game exit\n");
        sys::exit(1);
    }
    t.backend_mut().invalidate_all();
    // REPL loop's render_if_dirty repaints; next read_line re-prompts.
}

// ============================================================================
// Prompt rendering — identity- and time-aware (ADR-022)
// ============================================================================

/// Render the styled prompt into `buf`, return the populated slice.
///
/// Pulls the caller's bound Principal via `sys::get_principal` and the
/// current Unix-seconds wall clock via `sys::get_wallclock`. The
/// `cambios_style::format::prompt` helper renders the full
/// `cambios@<short-did>:HH:MM> ` shape, dropping segments out when
/// their inputs are unavailable (anonymous principal, unset wallclock).
fn render_prompt(buf: &mut [u8]) -> &[u8] {
    let mut principal = [0u8; 32];
    let _ = sys::get_principal(&mut principal);
    let wall = sys::get_wallclock();

    let mut writer = StackWriter::new(buf);
    let _ = write!(writer, "{}", format::prompt(&principal, wall));
    writer.into_slice()
}

/// Tiny `core::fmt::Write` adapter over a borrowed `&mut [u8]`. Used
/// so `write!` macros can drive the styled-prompt rendering without
/// allocation. Truncates on overflow rather than panicking.
struct StackWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> StackWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn into_slice(self) -> &'a [u8] {
        &self.buf[..self.pos]
    }
}

impl<'a> core::fmt::Write for StackWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let space = self.buf.len().saturating_sub(self.pos);
        let n = bytes.len().min(space);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        if n < bytes.len() {
            Err(core::fmt::Error)
        } else {
            Ok(())
        }
    }
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

/// Format a possibly-negative i64 as ASCII decimal with a leading minus
/// for negatives. Used by `cmd_play` to render kernel `rc` codes (which
/// are signed) when `sys::spawn` reports a failure.
fn format_i64(buf: &mut [u8], n: i64) -> usize {
    if n >= 0 {
        return format_u32(buf, n as u32);
    }
    if buf.is_empty() {
        return 0;
    }
    buf[0] = b'-';
    1 + format_u32(&mut buf[1..], (-n) as u32)
}

