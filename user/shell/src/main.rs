// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

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

/// Shell's own IPC endpoint — used to receive replies from services
/// (fs-service, eventually key-store etc.). Not in use until `arcobj` is
/// invoked, but registered at startup so the first call doesn't have to
/// race endpoint setup.
const SHELL_ENDPOINT: u32 = 18;

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::register_endpoint(SHELL_ENDPOINT);

    sys::print(b"[Shell] ready on endpoint 18\n");
    sys::module_ready();

    sys::print(b"\r\n");
    sys::print(b"CambiOS Shell v0.1\r\n");
    sys::print(b"Type 'help' for available commands.\r\n");

    loop {
        sys::print(b"cambios> ");

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
        b"arcobj" => cmd_arcobj(args),
        b"did-key" | b"didkey" => cmd_did_key(args),
        b"play" => cmd_play(args),
        b"exit" => sys::exit(0),
        _ => cmd_spawn(cmd),
    }
}

// ============================================================================
// Built-in commands
// ============================================================================

fn cmd_help() {
    sys::print(b"Built-in commands:\r\n");
    sys::print(b"  help    - Show this help\r\n");
    sys::print(b"  echo    - Print text\r\n");
    sys::print(b"  time    - Show system ticks\r\n");
    sys::print(b"  pid     - Show shell process ID\r\n");
    sys::print(b"  clear   - Clear screen\r\n");
    sys::print(b"  arcobj  - CambiObject store operations (put/get/list/delete)\r\n");
    sys::print(b"  did-key - Render this process's Principal as did:key, or encode/decode one\r\n");
    sys::print(b"  play    - Launch a game; `play` alone lists available games\r\n");
    sys::print(b"  exit    - Exit shell\r\n");
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
// `did-key` — render / encode / decode Principals as did:key
//
// Modes:
//   did-key                   this process's Principal as did:key
//   did-key <64-hex>          encode a raw Ed25519 pubkey as did:key
//   did-key did:key:z6Mk...   decode a did:key into raw hex bytes
//
// This is the userspace half of identity.md Phase 4: CambiOS Principals
// expressed in the W3C DID Core vocabulary, without changing how the
// kernel enforces them.
// ============================================================================

fn cmd_did_key(args: &[u8]) {
    let trimmed = trim(args);

    if trimmed.is_empty() {
        // Self mode.
        let mut pk = [0u8; 32];
        let n = sys::get_principal(&mut pk);
        if n != 32 {
            sys::print(b"did-key: failed to read this process's Principal\r\n");
            return;
        }
        if pk == [0u8; 32] {
            sys::print(b"did-key: this process has no bound Principal (anonymous)\r\n");
            return;
        }
        let rendered = sys::did_key_encode(&pk);
        sys::print(rendered.as_bytes());
        sys::print(b"\r\n");
        return;
    }

    // Decode mode: input looks like did:key:z...
    if trimmed.starts_with(b"did:key:") {
        match sys::did_key_decode(trimmed) {
            Some(bytes) => {
                print_hex32(&bytes);
                sys::print(b"\r\n");
            }
            None => sys::print(b"did-key: not a valid Ed25519 did:key\r\n"),
        }
        return;
    }

    // Encode mode: input is 64 hex chars (raw pubkey).
    let mut pk = [0u8; 32];
    if !parse_hex32(trimmed, &mut pk) {
        sys::print(b"did-key: argument must be 64 hex chars OR a did:key:z... string\r\n");
        return;
    }
    let rendered = sys::did_key_encode(&pk);
    sys::print(rendered.as_bytes());
    sys::print(b"\r\n");
}

// ============================================================================
// `play` — curated game launcher
//
// Thin wrapper over `cmd_spawn` that enforces an allowlist of first-party
// games. Unknown names print a readable error rather than falling through
// to the generic "Unknown command" path. `play` alone lists the games so
// the shell self-documents.
//
// When a new game lands (e.g. super-sprouty-o), add it to GAMES in the
// same commit that registers it as a boot module.
// ============================================================================

const GAMES: &[&[u8]] = &[b"tree", b"worm", b"pong", b"super-sprouty-o"];

fn cmd_play(args: &[u8]) {
    let name = trim(args);
    if name.is_empty() {
        sys::print(b"Available games:\r\n");
        for game in GAMES {
            sys::print(b"  ");
            sys::print(game);
            sys::print(b"\r\n");
        }
        return;
    }
    if !GAMES.iter().any(|g| *g == name) {
        sys::print(b"play: unknown game '");
        sys::print(name);
        sys::print(b"'. Run `play` for the list.\r\n");
        return;
    }
    cmd_spawn(name);
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
// `arcobj` — CambiObject store CLI
//
// Sub-commands:
//   arcobj put <text>           store bytes, print the 32-byte content hash
//   arcobj get <hex-hash>       fetch an object's content by hash
//   arcobj list                 list all stored hashes (up to 7 per reply)
//   arcobj delete <hex-hash>    delete an object (must be its owner)
//
// Talks to fs-service on FS_ENDPOINT (16). Uses SHELL_ENDPOINT (18) as
// the return address. Payload caps at the 256-byte IPC control frame —
// content up to ~240 bytes for a single put/get roundtrip.
// ============================================================================

const FS_ENDPOINT: u32 = 16;
const FS_CMD_PUT: u8 = 1;
const FS_CMD_GET: u8 = 2;
const FS_CMD_DELETE: u8 = 3;
const FS_CMD_LIST: u8 = 4;

const FS_STATUS_OK: u8 = 0;
const FS_STATUS_NOT_FOUND: u8 = 1;
const FS_STATUS_FULL: u8 = 2;
const FS_STATUS_DENIED: u8 = 3;
const FS_STATUS_INVALID: u8 = 4;

fn cmd_arcobj(args: &[u8]) {
    let (sub, rest) = split_first_space(args);
    match sub {
        b"put" => arcobj_put(rest),
        b"get" => arcobj_get(rest),
        b"list" => arcobj_list(),
        b"delete" | b"del" | b"rm" => arcobj_delete(rest),
        b"" => arcobj_usage(),
        _ => {
            sys::print(b"arcobj: unknown subcommand '");
            sys::print(sub);
            sys::print(b"'\r\n");
            arcobj_usage();
        }
    }
}

fn arcobj_usage() {
    sys::print(b"Usage: arcobj <put|get|list|delete> [args]\r\n");
    sys::print(b"  arcobj put <text>          store bytes, print hash\r\n");
    sys::print(b"  arcobj get <hex-hash>      retrieve by hash\r\n");
    sys::print(b"  arcobj list                list all hashes\r\n");
    sys::print(b"  arcobj delete <hex-hash>   delete by hash\r\n");
}

fn arcobj_put(content: &[u8]) {
    if content.is_empty() {
        sys::print(b"arcobj put: missing content\r\n");
        return;
    }
    if content.len() > 254 {
        sys::print(b"arcobj put: content exceeds 254-byte limit\r\n");
        return;
    }

    let mut req = [0u8; 256];
    req[0] = FS_CMD_PUT;
    req[1..1 + content.len()].copy_from_slice(content);
    let req_len = 1 + content.len();

    let reply = match fs_call(&req[..req_len]) {
        Some(r) => r,
        None => return,
    };
    let (status, payload) = reply.split();

    match status {
        FS_STATUS_OK => {
            if payload.len() < 32 {
                sys::print(b"arcobj put: short OK reply\r\n");
                return;
            }
            sys::print(b"stored: ");
            print_hex32(&payload[..32]);
            sys::print(b"\r\n");
        }
        FS_STATUS_FULL => sys::print(b"arcobj put: store full\r\n"),
        FS_STATUS_DENIED => sys::print(b"arcobj put: denied (key-store unavailable)\r\n"),
        FS_STATUS_INVALID => sys::print(b"arcobj put: invalid request\r\n"),
        _ => print_unknown_status("put", status),
    }
}

fn arcobj_get(hex: &[u8]) {
    let mut hash = [0u8; 32];
    if !parse_hex32(hex, &mut hash) {
        sys::print(b"arcobj get: argument must be a 64-character hex hash\r\n");
        return;
    }

    let mut req = [0u8; 256];
    req[0] = FS_CMD_GET;
    req[1..33].copy_from_slice(&hash);

    let reply = match fs_call(&req[..33]) {
        Some(r) => r,
        None => return,
    };
    let (status, payload) = reply.split();

    match status {
        FS_STATUS_OK => {
            sys::print(b"content (");
            print_u64(payload.len() as u64);
            sys::print(b" bytes):\r\n");
            sys::print(payload);
            sys::print(b"\r\n");
        }
        FS_STATUS_NOT_FOUND => sys::print(b"arcobj get: not found\r\n"),
        FS_STATUS_DENIED => sys::print(b"arcobj get: denied (signature verification failed)\r\n"),
        FS_STATUS_INVALID => sys::print(b"arcobj get: invalid request\r\n"),
        _ => print_unknown_status("get", status),
    }
}

fn arcobj_list() {
    let req = [FS_CMD_LIST];
    let reply = match fs_call(&req) {
        Some(r) => r,
        None => return,
    };
    let (status, payload) = reply.split();

    if status != FS_STATUS_OK {
        print_unknown_status("list", status);
        return;
    }
    if payload.is_empty() {
        sys::print(b"arcobj list: short OK reply\r\n");
        return;
    }
    let count = payload[0] as usize;
    let hashes = &payload[1..];
    if hashes.len() < count * 32 {
        sys::print(b"arcobj list: truncated reply\r\n");
        return;
    }
    sys::print(b"objects (");
    print_u64(count as u64);
    sys::print(b"):\r\n");
    for i in 0..count {
        sys::print(b"  ");
        print_hex32(&hashes[i * 32..(i + 1) * 32]);
        sys::print(b"\r\n");
    }
    if count == 0 {
        sys::print(b"  (none)\r\n");
    }
}

fn arcobj_delete(hex: &[u8]) {
    let mut hash = [0u8; 32];
    if !parse_hex32(hex, &mut hash) {
        sys::print(b"arcobj delete: argument must be a 64-character hex hash\r\n");
        return;
    }

    let mut req = [0u8; 256];
    req[0] = FS_CMD_DELETE;
    req[1..33].copy_from_slice(&hash);

    let reply = match fs_call(&req[..33]) {
        Some(r) => r,
        None => return,
    };
    let (status, _) = reply.split();

    match status {
        FS_STATUS_OK => sys::print(b"deleted\r\n"),
        FS_STATUS_NOT_FOUND => sys::print(b"arcobj delete: not found\r\n"),
        FS_STATUS_DENIED => sys::print(b"arcobj delete: denied (not the owner)\r\n"),
        FS_STATUS_INVALID => sys::print(b"arcobj delete: invalid request\r\n"),
        _ => print_unknown_status("delete", status),
    }
}

fn print_unknown_status(op: &str, status: u8) {
    sys::print(b"arcobj ");
    sys::print(op.as_bytes());
    sys::print(b": unexpected status ");
    print_u64(status as u64);
    sys::print(b"\r\n");
}

/// Owned copy of an fs-service reply. The IPC payload is separated from
/// the 36-byte principal + from-endpoint header.
struct FsReply {
    buf: [u8; 256],
    len: usize,
}

impl FsReply {
    fn split(&self) -> (u8, &[u8]) {
        if self.len == 0 {
            return (FS_STATUS_INVALID, &[]);
        }
        (self.buf[0], &self.buf[1..self.len])
    }
}

/// Send a request to fs-service (endpoint 16) and poll the shell's own
/// endpoint (18) for the verified reply. Returns `None` on transport
/// failure or timeout.
fn fs_call(req: &[u8]) -> Option<FsReply> {
    if sys::write(FS_ENDPOINT, req) < 0 {
        sys::print(b"arcobj: fs-service unreachable\r\n");
        return None;
    }

    // Poll with yields. fs-service may itself block on key-store (for PUT)
    // or on the disk-backed ObjectStore — iteration bound is generous.
    let mut recv_buf = [0u8; 292];
    for _ in 0..400 {
        if let Some(msg) = sys::recv_verified(SHELL_ENDPOINT, &mut recv_buf) {
            let payload = msg.payload();
            let mut out = FsReply {
                buf: [0u8; 256],
                len: 0,
            };
            let n = core::cmp::min(payload.len(), out.buf.len());
            out.buf[..n].copy_from_slice(&payload[..n]);
            out.len = n;
            return Some(out);
        }
        sys::yield_now();
    }
    sys::print(b"arcobj: timed out waiting for fs-service reply\r\n");
    None
}

// ============================================================================
// Hex encode/decode (32-byte fixed width)
// ============================================================================

fn print_hex32(bytes: &[u8]) {
    let n = core::cmp::min(bytes.len(), 32);
    let mut buf = [0u8; 64];
    for i in 0..n {
        let hi = bytes[i] >> 4;
        let lo = bytes[i] & 0xF;
        buf[i * 2] = hex_nibble(hi);
        buf[i * 2 + 1] = hex_nibble(lo);
    }
    sys::print(&buf[..n * 2]);
}

fn hex_nibble(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

/// Parse a 64-char hex string into a 32-byte array. Accepts lowercase or
/// uppercase; any other character (including whitespace) is a parse error.
fn parse_hex32(input: &[u8], out: &mut [u8; 32]) -> bool {
    if input.len() != 64 {
        return false;
    }
    for i in 0..32 {
        let hi = match parse_hex_digit(input[i * 2]) {
            Some(v) => v,
            None => return false,
        };
        let lo = match parse_hex_digit(input[i * 2 + 1]) {
            Some(v) => v,
            None => return false,
        };
        out[i] = (hi << 4) | lo;
    }
    true
}

fn parse_hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
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
