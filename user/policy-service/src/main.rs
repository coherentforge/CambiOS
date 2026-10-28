// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Policy Service — user-space authorization decisions (ADR-006)
//!
//! Receives syscall policy queries from the kernel on endpoint 22,
//! answers them from the boot manifest's per-entry syscall sets, and
//! sends Allow/Deny decisions back on endpoint 23.
//!
//! The kernel maps the signed, verified manifest blob read-only at
//! `MANIFEST_USER_VADDR` before this process runs — the same contract
//! init boots under. Each entry's `syscalls` bitmap is keyed by the
//! entry's derived AID: the Principal the kernel binds at spawn and
//! stamps into every query. One signed artifact, two readers — the
//! enforcement table cannot drift from the spawn table.
//!
//! Fail closed: a Principal the manifest does not name is denied; a
//! syscall outside an entry's set is denied. The first denial per
//! (entry, syscall) is printed so a missing profile line is read off
//! the console, not inferred from a stall.
//!
//! IPC protocol (256-byte payload):
//!   Query (kernel → policy-service):
//!     IPC header: [sender_principal:32][from_endpoint:4]
//!     Payload:    [query_id:8][caller_pid:4][syscall_num:4][caller_principal:32]
//!   Response (policy-service → kernel):
//!     [query_id:8][decision:1]   (0 = Allow, 1 = Deny)

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use cambios_libipc as ipc;
use cambios_libipc::MessageExt;
use cambios_libsys as sys;
use cambios_libsys::SyscallNumber;
use cambios_manifest::{
    payload_extent, syscall_mask_allows, Manifest, HEADER_LEN, MANIFEST_USER_VADDR,
    MAX_MANIFEST_ENTRIES, SYSCALL_MASK_WORDS,
};

// ============================================================================
// Constants
// ============================================================================

/// IPC endpoint where the kernel sends policy queries.
const POLICY_QUERY_ENDPOINT: u32 = 22;

/// IPC endpoint where the kernel intercepts our responses.
const POLICY_RESP_ENDPOINT: u32 = 23;

/// ARCHITECTURAL: one row per manifest entry plus init, whose syscall
/// set lives in the manifest header rather than in an entry.
const MAX_PROFILES: usize = MAX_MANIFEST_ENTRIES + 1;

// ============================================================================
// Profile table — the manifest's syscall sets, keyed by AID
// ============================================================================

/// One manifest row's enforcement view.
#[derive(Clone, Copy)]
struct Profile {
    /// The AID the kernel binds to this entry's process at spawn.
    aid: [u8; 32],
    /// The syscall set the signed manifest grants it.
    syscalls: [u64; SYSCALL_MASK_WORDS],
    /// Syscalls already reported denied for this entry — one console
    /// line per (entry, syscall), so a retry loop cannot flood it.
    reported: [u64; SYSCALL_MASK_WORDS],
    /// Module name, for the denial line. Borrowed from the mapped blob,
    /// which outlives the process.
    name: &'static str,
}

struct PolicyTable {
    rows: [Option<Profile>; MAX_PROFILES],
    len: usize,
    /// Syscalls already reported denied for Principals the manifest
    /// does not name (same flood guard as `Profile::reported`).
    unknown_reported: [u64; SYSCALL_MASK_WORDS],
}

/// Outcome of one query, with what the console should say about it.
enum Decision {
    Allow,
    /// Denied; `report` is true the first time this (entry, syscall)
    /// pair is seen.
    Deny { report: bool, name: Option<&'static str> },
}

impl PolicyTable {
    /// Read the kernel-mapped manifest and build the AID → syscall-set
    /// table. Mirrors init's parse: size the slice from the header,
    /// never read past the mapped extent.
    #[allow(unsafe_code)] // the two raw slices below are the mapping contract; nothing else here is unsafe
    fn from_manifest() -> Result<Self, &'static [u8]> {
        // SAFETY: the kernel maps at least the header at
        // MANIFEST_USER_VADDR, read-only, for the life of this process
        // (the same ADR-018 § 6 contract init boots under; the spawn
        // path maps it for policy-service by name). HEADER_LEN bytes
        // from it form one mapped object, and u8 has no validity
        // invariants.
        let header: &'static [u8] =
            unsafe { core::slice::from_raw_parts(MANIFEST_USER_VADDR as *const u8, HEADER_LEN) };
        let extent = payload_extent(header)
            .ok_or(b"[POLICY] manifest header invalid at MANIFEST_USER_VADDR\n" as &[u8])?;
        // SAFETY: `extent` came from payload_extent, which caps it at
        // MANIFEST_MAX_BYTES and derives it from the header the kernel
        // validated when it transcribed this blob; the kernel maps the
        // whole blob, so [vaddr, vaddr + extent) is mapped, read-only,
        // and outlives this process's use of it.
        let blob: &'static [u8] =
            unsafe { core::slice::from_raw_parts(MANIFEST_USER_VADDR as *const u8, extent) };
        let m = Manifest::parse(blob)
            .map_err(|_| b"[POLICY] manifest re-parse failed (kernel/policy parser skew?)\n" as &[u8])?;

        let mut table = PolicyTable {
            rows: [None; MAX_PROFILES],
            len: 0,
            unknown_reported: [0; SYSCALL_MASK_WORDS],
        };
        table.push(Profile {
            aid: m.init_aid(),
            syscalls: m.init_syscalls(),
            reported: [0; SYSCALL_MASK_WORDS],
            name: "init",
        })?;
        let mut i = 0;
        while let Some(e) = m.entry(i) {
            table.push(Profile {
                aid: e.principal(),
                syscalls: e.syscalls(),
                reported: [0; SYSCALL_MASK_WORDS],
                name: e.module_name(),
            })?;
            i += 1;
        }
        Ok(table)
    }

    fn push(&mut self, p: Profile) -> Result<(), &'static [u8]> {
        if self.len >= MAX_PROFILES {
            return Err(b"[POLICY] manifest has more entries than MAX_PROFILES\n");
        }
        self.rows[self.len] = Some(p);
        self.len += 1;
        Ok(())
    }

    /// Decide one query. Linear scan: the kernel caches answers per
    /// CPU, so this runs on cache misses only.
    fn decide(&mut self, principal: &[u8], syscall_num: u32) -> Decision {
        for row in self.rows.iter_mut().take(self.len) {
            let Some(p) = row else { continue };
            if p.aid[..] != principal[..] {
                continue;
            }
            if syscall_mask_allows(&p.syscalls, syscall_num) {
                return Decision::Allow;
            }
            let report = !syscall_mask_allows(&p.reported, syscall_num);
            if report {
                mask_set(&mut p.reported, syscall_num);
            }
            return Decision::Deny { report, name: Some(p.name) };
        }
        let report = !syscall_mask_allows(&self.unknown_reported, syscall_num);
        if report {
            mask_set(&mut self.unknown_reported, syscall_num);
        }
        Decision::Deny { report, name: None }
    }
}

/// Set bit `num` in a syscall mask (out-of-range numbers are ignored —
/// they can never be allowed either).
fn mask_set(mask: &mut [u64; SYSCALL_MASK_WORDS], num: u32) {
    let word = (num / 64) as usize;
    if word < SYSCALL_MASK_WORDS {
        mask[word] |= 1u64 << (num % 64);
    }
}

// ============================================================================
// Console line for a first denial
// ============================================================================

/// Fixed-capacity line builder: no heap, no formatting machinery.
struct Line {
    buf: [u8; 192],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Line { buf: [0; 192], len: 0 }
    }
    fn push(&mut self, s: &[u8]) {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
    fn push_dec(&mut self, mut v: u32) {
        let mut tmp = [0u8; 10];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(&tmp[i..]);
    }
    fn print(&self) {
        sys::print(&self.buf[..self.len]);
    }
}

fn report_denial(name: Option<&str>, caller_pid: u32, syscall_num: u32) {
    let mut line = Line::new();
    line.push(b"[POLICY] deny: ");
    match name {
        Some(n) => {
            line.push(n.as_bytes());
            line.push(b" (pid ");
            line.push_dec(caller_pid);
            line.push(b") may not ");
        }
        None => {
            line.push(b"unknown principal (pid ");
            line.push_dec(caller_pid);
            line.push(b") asked for ");
        }
    }
    match SyscallNumber::from_u64(syscall_num as u64) {
        Some(sc) => line.push(sc.name().as_bytes()),
        None => {
            line.push(b"syscall ");
            line.push_dec(syscall_num);
        }
    }
    if name.is_some() {
        line.push(b" - add it to the entry's manifest `syscalls`");
    }
    line.push(b"\n");
    line.print();
}

// ============================================================================
// Entry point — the ritual (_start, endpoint registration, readiness
// ping, panic handler) is emitted by `service_main!` (ADR-037 L0).
// ============================================================================

cambios_libsys_rt::service_main! {
    name: "POLICY",
    endpoint: POLICY_QUERY_ENDPOINT,
    main: service_loop,
}

/// Build the table from the mapped manifest, then serve queries.
/// `service_main!` has already registered the query endpoint and pinged
/// init ready; `ServiceLoop` owns recv → dispatch → yield (ADR-037 L1).
fn service_loop() -> ! {
    let table = match PolicyTable::from_manifest() {
        Ok(t) => t,
        Err(why) => {
            // No table means no decisions: exit rather than guess. Init's
            // restart budget surfaces it; the kernel denies meanwhile.
            sys::print(why);
            sys::exit(1)
        }
    };
    let mut line = Line::new();
    line.push(b"[POLICY] ready on endpoint 22; ");
    line.push_dec(table.len as u32);
    line.push(b" syscall profiles from the manifest\n");
    line.print();
    ipc::ServiceLoop::new(POLICY_QUERY_ENDPOINT, PolicyHandler { table }).run()
}

/// Per-query dispatch: parse the fixed query, decide, reply.
struct PolicyHandler {
    table: PolicyTable,
}

impl ipc::Handler for PolicyHandler {
    fn handle(&mut self, msg: &ipc::VerifiedMessage<'_>) -> ipc::Result<()> {
        // Query payload: [query_id:8][caller_pid:4][syscall_num:4][caller_principal:32]
        let mut r = msg.reader();
        let query_id = r.u64()?;
        let caller_pid = r.u32()?;
        let syscall_num = r.u32()?;
        let caller_principal = r.take(32)?;

        let allowed = match self.table.decide(caller_principal, syscall_num) {
            Decision::Allow => true,
            Decision::Deny { report, name } => {
                if report {
                    report_denial(name, caller_pid, syscall_num);
                }
                false
            }
        };

        // Response: [query_id:8][decision:1] (0 = Allow, 1 = Deny)
        let mut resp = [0u8; 9];
        let mut w = ipc::Writer::new(&mut resp);
        w.put_u64(query_id)?;
        w.put_u8(if allowed { 0 } else { 1 })?;

        // The kernel intercepts writes to the policy response endpoint.
        sys::write(POLICY_RESP_ENDPOINT, &resp);
        Ok(())
    }
}
