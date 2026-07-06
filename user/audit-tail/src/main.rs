// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! audit-tail — kernel audit ring consumer (commit 3 of audit-consumer-cap).
//!
//! Holds `CapabilityKind::AuditConsumer` (granted by name in
//! `load_boot_modules`); calls `SYS_AUDIT_ATTACH` to map the kernel's
//! audit ring read-only into this process; loops reading events as the
//! kernel produces them; resolves each event's `subject_pid` to a
//! `did:key:z6Mk…` via `SYS_GET_PROCESS_PRINCIPAL`; prints a one-line
//! summary per event to the serial console.
//!
//! This is the structural counterpart to ADR-007's audit channel —
//! kernel produces, signed user-space module consumes, principal
//! resolution stays out of the 64-byte event format.

#![no_std]
#![no_main]

use cambios_abi::audit::AuditEventKind;
use cambios_libsys as sys;
use cambios_style::{format as fmt_style, style};
use core::fmt::Write;

/// Ring header magic ("ARCAUDIT" little-endian, see `src/audit/drain.rs`).
const RING_HEADER_MAGIC: u64 = 0x5449_4455_4143_5241;

/// Header size at the start of the mapped ring region.
const RING_HEADER_SIZE: usize = 64;

/// Per-event size (one cache line; matches `RAW_AUDIT_EVENT_SIZE`).
const EVENT_SIZE: usize = 64;

/// Maximum events drained per polling pass before yielding. Keeps the
/// audit-tail task cooperative with other userspace work.
const READ_BATCH: usize = 32;

cambios_libsys_rt::service_main! {
    name: "AUDIT-TAIL",
    main: run,
}

fn run() -> ! {
    sys::print(b"[AUDIT-TAIL] starting\r\n");

    // Release the boot gate immediately — audit-tail is a leaf consumer.
    // Calling module_ready before audit_attach means a failure to attach
    // doesn't park the rest of the boot chain.
    sys::module_ready();

    let vaddr = sys::audit_attach();
    if vaddr < 0 {
        print_int(b"[AUDIT-TAIL] audit_attach rc=", vaddr);
        sys::exit(1);
    }
    let ring_base = vaddr as usize;
    let header_ptr = ring_base as *const u8;

    let magic = read_u64(header_ptr, 0);
    if magic != RING_HEADER_MAGIC {
        print_hex64_msg(b"[AUDIT-TAIL] bad ring magic: ", magic);
        sys::exit(2);
    }

    let capacity = read_u64(header_ptr, 16) as u32;
    if capacity == 0 {
        sys::print(b"[AUDIT-TAIL] capacity=0 - ring not initialized\r\n");
        sys::exit(3);
    }
    print_int(b"[AUDIT-TAIL] attached, capacity=", capacity as i64);

    let mut consumed: u64 = 0;
    loop {
        let total_produced = read_u64(header_ptr, 24);
        let mut drained = 0;
        while consumed < total_produced && drained < READ_BATCH {
            // Slot index in the event array; ring wraps at capacity.
            let slot = (consumed % capacity as u64) as usize;
            let event_base = ring_base + RING_HEADER_SIZE + slot * EVENT_SIZE;
            print_event(event_base);
            consumed = consumed.wrapping_add(1);
            drained += 1;
        }
        sys::yield_now();
    }
}

/// Format and print one event from the ring.
///
/// Layout (per `RawAuditEvent` in `src/audit/mod.rs`):
///   [0]      kind: u8 (AuditEventKind discriminant; names via cambios-abi)
///   [1]      flags: u8 (bit 0 sampled, bits 1-3 AuditClass)
///   [16..24] subject_pid: u64 (raw ProcessId)
fn print_event(event_base: usize) {
    let p = event_base as *const u8;
    // SAFETY: event_base lies within the ring region (slot < capacity)
    // and the ring is mapped RO and at least 64 bytes per event.
    let kind = unsafe { p.read_volatile() };
    let subject_pid = read_u64(p, 16);

    // Compose the styled line into a stack buffer in three segments:
    //
    //   <dim "[AUDIT-TAIL]"> <emph kind> <dim "pid=">N <dim "as"> <principal did>
    //
    // The dim treatment on the bracketed prefix and the `pid=` /
    // `as` glue keeps the eye on the two semantic anchors: the
    // event kind (what happened) and the principal (who).
    let mut buf = [0u8; 192];
    let mut w = StackWriter::new(&mut buf);

    // Canonical `domain.action` name from the shared taxonomy (cambios-abi).
    // Unknown discriminants (a newer kernel than this consumer) render as
    // "unknown" rather than guessing.
    let kind_name = AuditEventKind::from_u8(kind)
        .map(|k| k.name())
        .unwrap_or("unknown");
    let _ = write!(
        w,
        "{} {} {}",
        style::dim("[AUDIT-TAIL]"),
        style::emphasis(kind_name),
        style::dim("pid="),
    );
    let mut pid_buf = [0u8; 20];
    let pid_str = u64_to_decimal(&mut pid_buf, subject_pid);
    let _ = write!(w, "{}", pid_str);

    // subject_pid == 0 is the kernel-context sentinel (BinaryLoaded /
    // BinaryRejected / AuditDropped). No principal to resolve.
    if subject_pid != 0 {
        let mut pk = [0u8; 32];
        let rc = sys::get_process_principal(subject_pid, &mut pk);
        if rc == 32 {
            let short = fmt_style::principal_short(&pk);
            let _ = write!(
                w,
                " {} {}",
                style::dim("as"),
                style::principal(short.as_str()),
            );
        } else {
            // Principal unresolved — render in a low-key dim so it
            // doesn't compete with the rest of the line.
            let _ = write!(w, " {}", style::dim("(principal unresolved)"));
        }
    }
    let _ = write!(w, "\r\n");

    sys::print(w.into_slice());
}

/// Format a u64 into the buffer as ASCII decimal; return the populated
/// slice as `&str`. Bounded to 20 chars (max u64).
fn u64_to_decimal(buf: &mut [u8; 20], mut n: u64) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap_or("0");
    }
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while n > 0 && len < tmp.len() {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    core::str::from_utf8(&buf[..len]).unwrap_or("?")
}

/// Stack `core::fmt::Write` adapter used so the styled audit line is
/// composed without allocation. Truncates on overflow rather than
/// panicking — the buffer is sized for the worst case at the call
/// site.
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

fn read_u64(base: *const u8, offset: usize) -> u64 {
    // SAFETY: caller is reading from the kernel-mapped ring header
    // (offsets 0..64) or an event slot (offsets 0..64 within the slot).
    // All call sites pass offsets that stay within those bounds.
    unsafe {
        let ptr = base.add(offset) as *const u64;
        ptr.read_volatile()
    }
}

fn print_int(prefix: &[u8], n: i64) {
    sys::print(prefix);
    if n < 0 {
        sys::print(b"-");
        print_u64_dec((-n) as u64);
    } else {
        print_u64_dec(n as u64);
    }
    sys::print(b"\r\n");
}

fn print_hex64_msg(prefix: &[u8], n: u64) {
    sys::print(prefix);
    sys::print(b"0x");
    let mut buf = [0u8; 16];
    let mut v = n;
    for i in 0..16 {
        let nibble = (v & 0xF) as u8;
        buf[15 - i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        v >>= 4;
    }
    sys::print(&buf);
    sys::print(b"\r\n");
}

fn print_u64_dec(mut n: u64) {
    if n == 0 {
        sys::print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut len = 0;
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut out = [0u8; 20];
    for i in 0..len {
        out[i] = buf[len - 1 - i];
    }
    sys::print(&out[..len]);
}

