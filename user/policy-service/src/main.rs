// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Policy Service — user-space authorization decisions (Phase 3.4)
//!
//! Receives syscall policy queries from the kernel on endpoint 22,
//! evaluates against per-process syscall profiles, and sends Allow/Deny
//! decisions back on endpoint 23.
//!
//! Phase 3.4b: per-process syscall allowlists keyed on ProcessId slot.
//! Boot modules are loaded in deterministic order from limine.conf; the
//! slot assignments below must match that order. When the init-process
//! boot manifest lands, this hardcoded table is replaced by a signed
//! per-service profile config.
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

use cambios_libsys as sys;
use cambios_libsys::SyscallNumber;

// ============================================================================
// Panic handler (required for no_std)
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[POLICY] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// Constants
// ============================================================================

/// IPC endpoint where the kernel sends policy queries.
const POLICY_QUERY_ENDPOINT: u32 = 22;

/// IPC endpoint where the kernel intercepts our responses.
const POLICY_RESP_ENDPOINT: u32 = 23;

/// Minimum payload size for a valid query.
/// IPC header (36 bytes) + query payload (48 bytes) = 84 bytes total.
const MIN_QUERY_SIZE: usize = 36 + 48;

// Syscall numbers come from `cambios-libsys::SyscallNumber` (re-exported from
// the standalone `cambios-abi` crate so kernel + userspace share one source
// of truth). Profiles below use the enum directly; `fn profile()` casts
// each variant to its `repr(u64)` discriminant for the bitmap shift.

// ============================================================================
// Syscall profiles (bitmap of allowed syscall numbers)
// ============================================================================

/// A syscall profile is a u64 bitmap — bit N is set if syscall number N
/// is allowed. Fits the current syscall surface (max 42) in a single
/// word. O(1) check. Outgrowing 64 means rethinking the
/// representation; the kernel's `SyscallNumber` enum is the source of
/// truth for the high-water mark.
type Profile = u64;

/// Build a profile by OR-ing together syscall bits.
const fn profile(syscalls: &[SyscallNumber]) -> Profile {
    let mut bits: u64 = 0;
    let mut i = 0;
    while i < syscalls.len() {
        bits |= 1u64 << (syscalls[i] as u64);
        i += 1;
    }
    bits
}

/// Default profile — common syscalls every identified process may use.
/// Covers panic (Exit), cooperation (Yield), identity (GetPid, GetPrincipal,
/// GetTime), diagnostic output (Print), and the boot-chain release call
/// (ModuleReady). Nothing that touches shared state or hardware.
const DEFAULT_PROFILE: Profile = profile(&[
    SyscallNumber::Exit, SyscallNumber::Yield, SyscallNumber::GetPid, SyscallNumber::GetTime, SyscallNumber::Print, SyscallNumber::GetPrincipal,
    SyscallNumber::ModuleReady,
]);

/// Hello test module — minimal profile (print and exit). Removed from
/// boot chain in Phase 4b; can still be spawned via `spawn hello`.
#[allow(dead_code)]
const HELLO_PROFILE: Profile = DEFAULT_PROFILE;

/// Key-store service — claims bootstrap key, signs object puts over IPC.
const KEY_STORE_PROFILE: Profile = DEFAULT_PROFILE
    | profile(&[
        SyscallNumber::Write, SyscallNumber::RegisterEndpoint, SyscallNumber::RecvMsg,
        SyscallNumber::ClaimBootstrapKey, SyscallNumber::BindPrincipal,
    ]);

/// FS service — ObjectStore gateway.
const FS_SERVICE_PROFILE: Profile = DEFAULT_PROFILE
    | profile(&[
        SyscallNumber::Write, SyscallNumber::RegisterEndpoint, SyscallNumber::RecvMsg,
        SyscallNumber::ObjPut, SyscallNumber::ObjGet, SyscallNumber::ObjDelete, SyscallNumber::ObjList, SyscallNumber::ObjPutSigned,
    ]);

/// Network driver (virtio-net / i219-net) — hardware I/O, DMA, IRQs.
const NET_DRIVER_PROFILE: Profile = DEFAULT_PROFILE
    | profile(&[
        SyscallNumber::Write, SyscallNumber::RegisterEndpoint, SyscallNumber::RecvMsg,
        SyscallNumber::WaitIrq, SyscallNumber::MapMmio, SyscallNumber::AllocDma, SyscallNumber::DeviceInfo, SyscallNumber::PortIo,
    ]);

/// Block driver (virtio-blk) — same shape as the NIC drivers today:
/// PCI discovery via DeviceInfo, legacy I/O-BAR programming via PortIo,
/// DMA allocation via AllocDma. No MMIO or IRQ wait path yet (polled).
/// Needs SyscallNumber::TryRecvMsg because virtio-blk listens on two endpoints
/// (user ep24, kernel ep26) and must poll both non-blockingly.
const BLK_DRIVER_PROFILE: Profile = DEFAULT_PROFILE
    | profile(&[
        SyscallNumber::Write, SyscallNumber::RegisterEndpoint, SyscallNumber::RecvMsg, SyscallNumber::TryRecvMsg,
        SyscallNumber::DeviceInfo, SyscallNumber::AllocDma, SyscallNumber::PortIo,
    ]);

/// UDP stack — network protocol service over IPC.
const UDP_STACK_PROFILE: Profile = DEFAULT_PROFILE
    | profile(&[SyscallNumber::Write, SyscallNumber::RegisterEndpoint, SyscallNumber::RecvMsg]);

/// Shell — user interface, can spawn children and drain audit ring.
const SHELL_PROFILE: Profile = DEFAULT_PROFILE
    | profile(&[
        SyscallNumber::Write, SyscallNumber::RegisterEndpoint, SyscallNumber::RecvMsg,
        SyscallNumber::ConsoleRead, SyscallNumber::Spawn, SyscallNumber::WaitTask,
        SyscallNumber::AuditAttach, SyscallNumber::AuditInfo,
    ]);

// ============================================================================
// ProcessId slot → profile mapping
// ============================================================================
//
// SCAFFOLDING: hardcoded by boot-order slot. The assignments below must match
// limine.conf's module_path order. Slots 0-2 are kernel processes (never
// queried). Slot 4 (policy-service) is bypassed by the kernel, so its entry
// here is defensive-only.
//
// Replace when: the init-process boot manifest lands (planned post-v1).
// At that point this table becomes a signed config file loaded at boot,
// keyed on Principal + module name rather than fragile slot numbers.

const SLOT_UNUSED: Profile = 0;

/// Profile lookup table, indexed by ProcessId slot.
/// Out-of-range slots get DEFAULT_PROFILE (conservative: only safe syscalls).
///
/// Slot order matches limine.conf module ordering (see Divergence of
/// ADR-002-adjacent boot sequencing). Network drivers (virtio-net,
/// i219-net, udp-stack) are currently disabled — their profiles are
/// kept here for when they return.
const SLOT_PROFILES: [Profile; 16] = [
    SLOT_UNUSED,          //  0: kernel idle
    SLOT_UNUSED,          //  1: kernel process 1
    SLOT_UNUSED,          //  2: kernel process 2
    SLOT_UNUSED,          //  3: policy-service (bypassed in kernel)
    KEY_STORE_PROFILE,    //  4: key-store-service
    FS_SERVICE_PROFILE,   //  5: fs-service
    BLK_DRIVER_PROFILE,   //  6: virtio-blk
    NET_DRIVER_PROFILE,   //  7: virtio-net
    UDP_STACK_PROFILE,    //  8: udp-stack
    DEFAULT_PROFILE,      //  9+: scanout-virtio-gpu / compositor / virtio-input
    DEFAULT_PROFILE,      // 10    / worm / shell — GUI modules and shell
    DEFAULT_PROFILE,      // 11    run under DEFAULT today (policy allowlist
    DEFAULT_PROFILE,      // 12    pending; the slot-based mapping is
    DEFAULT_PROFILE,      // 13    SCAFFOLDING until the init-process manifest
    DEFAULT_PROFILE,      // 14    lands — see the table's docblock).
    DEFAULT_PROFILE,      // 15
];

// Silence "unused" warnings for profiles kept for re-enabling drivers later.
#[allow(dead_code)]
const _SHELL_PROFILE_KEPT: Profile = SHELL_PROFILE;
// Note: the previous `_SYS_MAP_FRAMEBUFFER_KEPT` hack existed to keep the
// `SyscallNumber::MapFramebuffer` const referenced. After the migration to
// `SyscallNumber`, unused enum variants don't generate dead-code warnings
// (only unused consts do), so the hack is no longer needed.

/// Return the syscall profile for a given process slot.
fn profile_for(caller_pid: u32) -> Profile {
    let slot = caller_pid as usize;
    if slot < SLOT_PROFILES.len() {
        let p = SLOT_PROFILES[slot];
        if p == SLOT_UNUSED {
            // Slot reserved for kernel or bypassed — be conservative.
            DEFAULT_PROFILE
        } else {
            p
        }
    } else {
        // Out-of-range (unknown spawned process) — conservative default.
        DEFAULT_PROFILE
    }
}

/// Check if `syscall_num` is allowed under `profile`.
fn is_allowed(profile: Profile, syscall_num: u32) -> bool {
    if syscall_num >= 64 {
        return false; // out of bitmap range
    }
    (profile & (1u64 << syscall_num)) != 0
}

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Register our query endpoint
    sys::register_endpoint(POLICY_QUERY_ENDPOINT);

    sys::print(b"[POLICY] ready on endpoint 22\n");
    sys::module_ready();

    // Service loop: recv_verified rejects anonymous senders.
    let mut recv_buf = [0u8; 256];

    loop {
        let msg = match sys::recv_verified(POLICY_QUERY_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };

        // Query payload must be at least 48 bytes (query_id + pid + syscall + principal)
        let payload = msg.payload();
        if payload.len() < 48 {
            continue;
        }

        // Extract query fields
        let query_id_bytes: [u8; 8] = match payload[0..8].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let caller_pid_bytes: [u8; 4] = match payload[8..12].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let syscall_bytes: [u8; 4] = match payload[12..16].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let caller_pid = u32::from_le_bytes(caller_pid_bytes);
        let syscall_num = u32::from_le_bytes(syscall_bytes);

        // Profile lookup + check
        let profile = profile_for(caller_pid);
        let allowed = is_allowed(profile, syscall_num);

        // Build response: [query_id:8][decision:1]
        let mut resp = [0u8; 9];
        resp[0..8].copy_from_slice(&query_id_bytes);
        resp[8] = if allowed { 0 } else { 1 };

        // Send response to the policy response endpoint (kernel intercepts this)
        sys::write(POLICY_RESP_ENDPOINT, &resp);
    }
}

// Suppress unused warning for MIN_QUERY_SIZE (kept as documentation of the protocol).
#[allow(dead_code)]
const _MIN_QUERY_SIZE: usize = MIN_QUERY_SIZE;
