// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Syscall definitions and numbers
//!
//! Defines the syscall ABI and interfaces that userspace drivers use
//! to request kernel services.

pub mod dispatcher;
pub mod user_slice;
pub mod userspace;

#[cfg(fuzzing)]
pub mod fuzz_fixture;

pub use user_slice::{UserReadSlice, UserWriteSlice};



/// Syscall numbers - must match userspace convention
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    /// exit(code: i32) -> !
    /// Terminate the calling process
    Exit = 0,

    /// write(endpoint: u32, buffer: *const u8, len: usize) -> isize
    /// Send data through an endpoint
    Write = 1,

    /// read(endpoint: u32, buffer: *mut u8, len: usize) -> isize
    /// Receive data from an endpoint
    Read = 2,

    /// allocate(size: usize, flags: u32) -> *mut u8
    /// Allocate memory for this process
    Allocate = 3,

    /// free(ptr: *mut u8, size: usize) -> i32
    /// Free previously allocated memory
    Free = 4,

    /// wait_irq(irq_number: u32) -> i32
    /// Wait for a specific interrupt to fire
    WaitIrq = 5,

    /// register_endpoint(endpoint_id: u32, flags: u32) -> i32
    /// Register a message endpoint
    RegisterEndpoint = 6,

    /// yield_cpu() -> i32
    /// Voluntarily yield to scheduler
    Yield = 7,

    /// get_pid() -> u32
    /// Get current process ID
    GetPid = 8,

    /// get_time() -> u64
    /// Get current system time (ticks)
    GetTime = 9,

    /// print(buffer: *const u8, len: usize) -> isize
    /// Print a string to the kernel serial console (for debugging)
    Print = 10,

    /// bind_principal(process_id: u32, pubkey_ptr: *const u8, pubkey_len: u32) -> i32
    /// Bind a cryptographic Principal to a process. Restricted to the bootstrap
    /// Principal (identity service). pubkey_len must be 32.
    BindPrincipal = 11,

    /// get_principal(out_buf: *mut u8, buf_len: u32) -> i32
    /// Read the calling process's bound Principal (32-byte public key).
    /// Returns 32 on success, or error if no Principal is bound.
    GetPrincipal = 12,

    /// recv_msg(endpoint: u32, buf: *mut u8, buf_len: usize) -> isize
    /// Receive an IPC message with sender identity.
    /// Writes to buf: [sender_principal:32][from_endpoint:4][payload:N]
    /// Returns total bytes written (>= 36), 0 if no message, or negative error.
    RecvMsg = 13,

    /// obj_put(content_ptr: *const u8, content_len: usize, out_hash: *mut u8) -> isize
    /// Store an CambiObject. Author/owner = caller's Principal.
    /// Writes 32-byte content hash to out_hash. Returns 0 or negative error.
    ObjPut = 14,

    /// obj_get(hash_ptr: *const u8, out_buf: *mut u8, out_buf_len: usize) -> isize
    /// Retrieve object content by hash. Returns bytes written or negative error.
    ObjGet = 15,

    /// obj_delete(hash_ptr: *const u8) -> isize
    /// Delete an object. Only the owner can delete. Returns 0 or negative error.
    ObjDelete = 16,

    /// obj_list(out_buf: *mut u8, out_buf_len: usize) -> isize
    /// List object hashes. Writes packed 32-byte hashes. Returns count of objects.
    ObjList = 17,

    /// claim_bootstrap_key(out_sk_ptr: *mut u8) -> isize
    /// One-shot: writes the 64-byte bootstrap Ed25519 secret key to the caller's
    /// buffer and zeroes the kernel's copy. Restricted to bootstrap Principal.
    /// Returns 64 on success, negative error if already claimed or unauthorized.
    ClaimBootstrapKey = 18,

    /// obj_put_signed(content_ptr: *const u8, content_len: usize, sig_ptr: *const u8, out_hash: *mut u8) -> isize
    /// Store a pre-signed CambiObject. Kernel verifies the Ed25519 signature
    /// against the caller's Principal before storing. Returns 0 or negative error.
    ObjPutSigned = 19,

    /// map_mmio(phys_addr: u64, num_pages: u32) -> u64
    /// Map device MMIO into the calling process's address space with uncacheable
    /// attributes. Returns user-space virtual address, or negative error.
    /// Kernel validates the physical address is not in RAM regions.
    MapMmio = 20,

    /// alloc_dma(num_pages: u32, flags: u32) -> (vaddr: u64, paddr: u64)
    /// Allocate physically contiguous DMA-capable pages with guard pages on
    /// both sides. Returns user vaddr in the return value, writes paddr to
    /// the u64 pointed to by arg3. Flags reserved for future IOMMU hints.
    AllocDma = 21,

    /// device_info(index: u32, out_buf: *mut u8, buf_len: u32) -> i32
    /// Query PCI device info by index. Writes a fixed-format device descriptor
    /// to out_buf. Returns 0 on success, negative error if index out of range.
    DeviceInfo = 22,

    /// port_io(port: u16, value: u32, flags: u32) -> u32
    /// Read or write an x86 I/O port. The kernel validates the port is within
    /// a PCI device's I/O BAR range.
    /// flags bit 0: direction (0=read, 1=write)
    /// flags bits 2:1: width (0=byte, 1=word, 2=dword)
    /// Returns: read value (for reads), 0 (for writes), or negative error.
    PortIo = 23,

    /// console_read(buf: *mut u8, max_len: usize) -> isize
    /// Read bytes from the serial console into buf. Returns the number of
    /// bytes read (0 if no data available). Non-blocking (polling mode).
    ConsoleRead = 24,

    /// spawn(name_ptr: *const u8, name_len: usize) -> isize
    /// Spawn a boot module by name. Returns the new task ID on success,
    /// or negative error. The spawned task's parent is the caller.
    Spawn = 25,

    /// wait_task(child_task_id: u32) -> isize
    /// Block until the specified child task exits. Returns the child's
    /// exit code. Only the parent (spawner) can wait on a child.
    WaitTask = 26,

    /// revoke_capability(target_process_id: u32, endpoint_id: u32) -> i32
    /// Revoke a capability held by another process on a given endpoint.
    /// Per ADR-007 §"Who can revoke", Phase 3.1 restricts this to the bootstrap
    /// Principal; other authority paths (original grantor, holder of `revoke`
    /// right, policy service) land in Phase 3.4.
    ///
    /// Args are `(target_process_id, endpoint_id)` in Phase 3.1 for simplicity.
    /// Phase 3.2d refactors this to a single `CapabilityHandle` once channels
    /// force a system-wide capability registry into existence.
    ///
    /// Returns 0 on success, negative error code on failure.
    RevokeCapability = 27,

    /// channel_create(size_pages: u32, peer_principal_ptr: *const u8, role: u32,
    ///                out_vaddr_ptr: *mut u64) -> i64
    /// Create a shared-memory channel with `size_pages` pages. The peer's
    /// 32-byte Principal is read from `peer_principal_ptr`. `role` selects
    /// Producer(0)/Consumer(1)/Bidirectional(2). The creator's mapping
    /// virtual address is written to `out_vaddr_ptr`. Returns the ChannelId
    /// (>= 0) on success, or a negative error code.
    /// Requires `CreateChannel` system capability.
    ChannelCreate = 28,

    /// channel_attach(channel_id: u64) -> i64
    /// Attach to an existing channel as the named peer. Kernel verifies
    /// the caller's Principal matches the peer_principal specified at
    /// create time. Returns the user-space virtual address of the shared
    /// region on success, or a negative error code.
    ChannelAttach = 29,

    /// channel_close(channel_id: u64) -> i32
    /// Close a channel. Unmaps the shared region from both processes,
    /// issues TLB shootdown, and frees the physical pages. Only the
    /// creator or peer may call this. Returns 0 on success.
    ChannelClose = 30,

    /// channel_revoke(channel_id: u64) -> i32
    /// Force-close a channel from a third party (bootstrap/policy
    /// authority). Same teardown as close but no caller-identity check.
    /// Returns 0 on success.
    ChannelRevoke = 31,

    /// channel_info(channel_id: u64, out_buf: *mut u8, buf_len: u32) -> i32
    /// Read channel metadata (size, state, principals, byte counters)
    /// into a user buffer. Returns 0 on success.
    ChannelInfo = 32,

    /// audit_attach() -> i64
    /// Attach as the audit ring consumer. Maps the kernel's audit ring
    /// pages read-only into the caller's address space. Returns the
    /// user-space virtual address on success.
    /// Restricted to bootstrap Principal (Phase 3.3).
    AuditAttach = 33,

    /// audit_info(out_buf: *mut u8, buf_len: u32) -> i32
    /// Read audit ring statistics (total produced, total dropped,
    /// capacity, consumer attached, per-CPU staging occupancy) into
    /// a user buffer. Any process may call.
    AuditInfo = 34,

    /// map_framebuffer(index: u32, out_desc: *mut u8, desc_len: u32) -> i32
    /// Map a Limine-reported framebuffer (selected by zero-based
    /// `index`) into the calling process and write a 32-byte
    /// `FramebufferDescriptor` to `out_desc`:
    ///   { vaddr: u64, width: u32, height: u32, pitch: u32, bpp: u16,
    ///     red_size: u8, red_shift: u8,
    ///     green_size: u8, green_shift: u8,
    ///     blue_size: u8, blue_shift: u8, _reserved: u8 }
    /// Returns 0 on success.
    /// Capability-gated: requires `CapabilityKind::MapFramebuffer`.
    /// Phase GUI-0 ([ADR-011](docs/adr/011-graphics-architecture-and-scaling.md)).
    MapFramebuffer = 35,
    /// SYS_MODULE_READY (36): signal that this boot module has finished
    /// initialization. The kernel's boot-release chain advances: the next
    /// module in `BOOT_MODULE_ORDER` (if any) is unblocked from
    /// `BlockReason::BootGate` so it can run its own `_start`.
    /// No arguments, no return payload (returns 0).
    /// Intentionally identity-exempt — boot modules can call this before
    /// the rest of the trusted-service chain is up (e.g., key-store
    /// isn't needed for signing a no-op call).
    ModuleReady = 36,
    /// SYS_TRY_RECV_MSG (37): non-blocking variant of RecvMsg. Returns 0
    /// immediately if no message is queued, instead of parking the task
    /// on `MessageWait(endpoint)`. Required for services that must poll
    /// multiple endpoints (e.g., virtio-blk: ep24 user, ep26 kernel) —
    /// blocking recv on one endpoint would miss wakes on the other.
    /// Arg layout matches RecvMsg: arg1=endpoint, arg2=user_buf, arg3=buf_len.
    /// Returns: bytes received (>=36 for header + payload) or 0 if empty.
    TryRecvMsg = 37,

    /// SYS_VIRTIO_MODERN_CAPS (38): return the kernel-parsed virtio-modern
    /// PCI capabilities for a given device index (virtio spec §4.1.4).
    /// Needed by modern virtio-pci drivers (virtio-gpu, future virtio
    /// devices) to discover the (BAR, offset) locations of the common,
    /// notify, ISR, and device-specific config regions without touching
    /// PCI configuration space themselves.
    ///
    /// Args: arg1 = device_index (u32), arg2 = out_buf (user ptr),
    ///       arg3 = buf_len (usize; must equal
    ///              `size_of::<pci::VirtioModernCaps>()` = 64).
    ///
    /// Writes a 64-byte `VirtioModernCaps` structure to `out_buf`.
    /// `caps.present == 0` means the device is not a virtio-modern
    /// device (caller must check before using the cap fields).
    /// Returns 0 on success, negative error on invalid index / buffer.
    ///
    /// Identity-required but not capability-gated: same privacy class
    /// as `DeviceInfo` (information-disclosure only; no MMIO mapping,
    /// no config-space writes). Built on ADR-020 `UserWriteSlice` from
    /// day one.
    VirtioModernCaps = 38,

    // 39 SetWallclock and 40 GetWallclock are reserved by ADR-022
    // (wall-clock time + path to decentralized time). The handlers
    // are not yet implemented; numbers held to keep the ABI stable
    // when the implementation lands.

    /// SYS_AUDIT_EMIT_INPUT_FOCUS (41): compositor reports a window-focus
    /// transition into the kernel audit ring (T-7 Phase A,
    /// docs/threat-model.md). Lets the audit consumer observe focus
    /// changes — including initial focus and focus loss — so a
    /// focus-hijack attack ("malicious app spawned before key-store
    /// passphrase prompt") leaves a trail.
    ///
    /// Args: arg1 = new_window_id (u32), arg2 = old_window_id (u32; 0
    ///       if no prior focus), arg3 = user vaddr of 32-byte new owner
    ///       Principal (zero bytes when focus was lost).
    ///
    /// Capability-gated on `CapabilityKind::EmitInputAudit`. Granted to
    /// all spawned boot modules today (parallel CreateProcess /
    /// CreateChannel pattern); narrows to compositor-only when an
    /// identity-aware grant flow lands.
    ///
    /// Returns 0 on success, `PermissionDenied` without the capability,
    /// `InvalidArg` on a bad user pointer.
    AuditEmitInputFocus = 41,

    /// SYS_GET_PROCESS_PRINCIPAL (42): resolve a `ProcessId` to its bound
    /// 32-byte Principal. Lets an audit consumer render `subject_pid`
    /// fields from `RawAuditEvent` as `did:key:z6Mk…` without widening
    /// the 64-byte event format.
    ///
    /// Args: arg1 = target ProcessId raw (u64; encodes slot + generation
    ///       per ADR-008), arg2 = out_buf (user ptr to 32-byte buffer),
    ///       arg3 = buf_len (must equal 32).
    ///
    /// Capability-gated on `CapabilityKind::AuditConsumer`. Same gating
    /// posture as `SYS_AUDIT_ATTACH`: if you can read events you can
    /// resolve the principals they reference. Future `ProcessIntrospect`
    /// cap may decouple if a non-audit consumer (GUI window-owner
    /// labeling, win-compat) needs principal lookup without ring access.
    ///
    /// Lookup chain: live process table first (`CapabilityManager::
    /// get_principal`), falls back to a recent-exits ring on the process
    /// table for principals of processes that have already exited but
    /// whose `subject_pid` may still be referenced by buffered events.
    ///
    /// Returns 32 on success (bytes written), `PermissionDenied` without
    /// the capability, or `InvalidArg` on bad user pointer / buf_len /
    /// unknown target (no principal bound to the live process and no
    /// matching entry in the recent-exits ring).
    GetProcessPrincipal = 42,
}

impl SyscallNumber {
    /// Returns `true` for syscalls that require the caller to have a bound,
    /// non-zero Principal. Unidentified processes may only use the exempt
    /// set: Exit, Yield, GetPid, GetTime, Print, GetPrincipal.
    ///
    /// This is the kernel-side half of the "identity is load-bearing" invariant.
    /// The userspace half is `recv_verified()` in libsys, which rejects
    /// anonymous IPC senders. Together they ensure a stripped-security kernel
    /// fork cannot run the standard userspace ecosystem.
    pub const fn requires_identity(&self) -> bool {
        matches!(self,
            Self::Write | Self::Read | Self::RecvMsg | Self::TryRecvMsg |
            Self::Allocate | Self::Free |
            Self::RegisterEndpoint |
            Self::WaitIrq | Self::MapMmio | Self::AllocDma |
            Self::DeviceInfo | Self::PortIo |
            Self::ObjPut | Self::ObjGet | Self::ObjDelete |
            Self::ObjList | Self::ObjPutSigned |
            Self::BindPrincipal | Self::ClaimBootstrapKey |
            Self::Spawn | Self::WaitTask |
            Self::ConsoleRead |
            Self::RevokeCapability |
            Self::ChannelCreate | Self::ChannelAttach |
            Self::ChannelClose | Self::ChannelRevoke | Self::ChannelInfo |
            Self::AuditAttach | Self::AuditInfo |
            Self::MapFramebuffer |
            Self::VirtioModernCaps |
            Self::AuditEmitInputFocus |
            Self::GetProcessPrincipal
        )
    }

    /// Convert u64 to syscall number
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(Self::Exit),
            1 => Some(Self::Write),
            2 => Some(Self::Read),
            3 => Some(Self::Allocate),
            4 => Some(Self::Free),
            5 => Some(Self::WaitIrq),
            6 => Some(Self::RegisterEndpoint),
            7 => Some(Self::Yield),
            8 => Some(Self::GetPid),
            9 => Some(Self::GetTime),
            10 => Some(Self::Print),
            11 => Some(Self::BindPrincipal),
            12 => Some(Self::GetPrincipal),
            13 => Some(Self::RecvMsg),
            14 => Some(Self::ObjPut),
            15 => Some(Self::ObjGet),
            16 => Some(Self::ObjDelete),
            17 => Some(Self::ObjList),
            18 => Some(Self::ClaimBootstrapKey),
            19 => Some(Self::ObjPutSigned),
            20 => Some(Self::MapMmio),
            21 => Some(Self::AllocDma),
            22 => Some(Self::DeviceInfo),
            23 => Some(Self::PortIo),
            24 => Some(Self::ConsoleRead),
            25 => Some(Self::Spawn),
            26 => Some(Self::WaitTask),
            27 => Some(Self::RevokeCapability),
            28 => Some(Self::ChannelCreate),
            29 => Some(Self::ChannelAttach),
            30 => Some(Self::ChannelClose),
            31 => Some(Self::ChannelRevoke),
            32 => Some(Self::ChannelInfo),
            33 => Some(Self::AuditAttach),
            34 => Some(Self::AuditInfo),
            35 => Some(Self::MapFramebuffer),
            36 => Some(Self::ModuleReady),
            37 => Some(Self::TryRecvMsg),
            38 => Some(Self::VirtioModernCaps),
            // 39 SetWallclock + 40 GetWallclock reserved by ADR-022;
            // not yet wired through dispatch.
            41 => Some(Self::AuditEmitInputFocus),
            42 => Some(Self::GetProcessPrincipal),
            _ => None,
        }
    }
}

/// Arguments passed via registers on x86-64
/// 
/// x86-64 System V ABI syscall convention:
/// - RAX: syscall number (input), return value (output)
/// - RDI: first argument (typically fd or endpoint)
/// - RSI: second argument (typically buffer/pointer)
/// - RDX: third argument (typically size/count)
/// - RCX: fourth argument
/// - R8:  fifth argument
/// - R9:  sixth argument
/// - RBX, RBP, R12-R15: must be preserved by syscall handler
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    pub arg1: u64,  // rdi
    pub arg2: u64,  // rsi
    pub arg3: u64,  // rdx
    pub arg4: u64,  // rcx
    pub arg5: u64,  // r8
    pub arg6: u64,  // r9
}

impl SyscallArgs {
    /// Create syscall arguments from register values
    pub fn new(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> Self {
        SyscallArgs {
            arg1, arg2, arg3, arg4, arg5, arg6,
        }
    }

    /// Get first argument as u32
    pub fn arg1_u32(&self) -> u32 {
        self.arg1 as u32
    }

    /// Get second argument as u32
    pub fn arg2_u32(&self) -> u32 {
        self.arg2 as u32
    }

    /// Get first argument as pointer
    pub fn arg1_ptr<T>(&self) -> *const T {
        self.arg1 as *const T
    }

    /// Get first argument as mutable pointer
    pub fn arg1_mut_ptr<T>(&self) -> *mut T {
        self.arg1 as *mut T
    }

    /// Get second argument as pointer
    pub fn arg2_ptr<T>(&self) -> *const T {
        self.arg2 as *const T
    }

    /// Get second argument as mutable pointer
    pub fn arg2_mut_ptr<T>(&self) -> *mut T {
        self.arg2 as *mut T
    }

    /// Get argument as usize (common for sizes)
    pub fn arg_usize(&self, n: usize) -> usize {
        match n {
            1 => self.arg1 as usize,
            2 => self.arg2 as usize,
            3 => self.arg3 as usize,
            4 => self.arg4 as usize,
            5 => self.arg5 as usize,
            6 => self.arg6 as usize,
            _ => 0,
        }
    }
}

/// Syscall error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SyscallError {
    /// Operation succeeded (0)
    Success = 0,
    
    /// Invalid argument
    InvalidArg = -1,
    
    /// Permission denied
    PermissionDenied = -2,
    
    /// Out of memory
    OutOfMemory = -3,
    
    /// Endpoint not found
    EndpointNotFound = -4,
    
    /// Operation would block
    WouldBlock = -5,
    
    /// Interrupted by signal (future)
    Interrupted = -6,
    
    /// Unknown syscall
    Enosys = -38,
}

impl SyscallError {
    /// Convert to signed integer for return value
    pub fn as_i64(&self) -> i64 {
        *self as i32 as i64
    }
}

/// Result type for syscall implementations
pub type SyscallResult = Result<u64, SyscallError>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::SyscallNumber;

    /// The exempt set: syscalls that do NOT require identity.
    /// These are the only operations an unidentified process can perform.
    const EXEMPT: &[SyscallNumber] = &[
        SyscallNumber::Exit,
        SyscallNumber::Yield,
        SyscallNumber::GetPid,
        SyscallNumber::GetTime,
        SyscallNumber::Print,
        SyscallNumber::GetPrincipal,
        // `ModuleReady` is called by every boot module at the end of its
        // own init, including modules that run before the key-store /
        // identity infrastructure is fully up. Making it identity-gated
        // would create a bootstrap circular dependency.
        SyscallNumber::ModuleReady,
    ];

    #[test]
    fn exempt_syscalls_do_not_require_identity() {
        for &num in EXEMPT {
            assert!(
                !num.requires_identity(),
                "{:?} should be exempt from identity requirement",
                num,
            );
        }
    }

    #[test]
    fn identity_required_syscalls_are_gated() {
        // Every syscall NOT in the exempt set must require identity.
        let all = [
            SyscallNumber::Exit, SyscallNumber::Write, SyscallNumber::Read,
            SyscallNumber::Allocate, SyscallNumber::Free, SyscallNumber::WaitIrq,
            SyscallNumber::RegisterEndpoint, SyscallNumber::Yield,
            SyscallNumber::GetPid, SyscallNumber::GetTime, SyscallNumber::Print,
            SyscallNumber::BindPrincipal, SyscallNumber::GetPrincipal,
            SyscallNumber::RecvMsg, SyscallNumber::ObjPut, SyscallNumber::ObjGet,
            SyscallNumber::ObjDelete, SyscallNumber::ObjList,
            SyscallNumber::ClaimBootstrapKey, SyscallNumber::ObjPutSigned,
            SyscallNumber::MapMmio, SyscallNumber::AllocDma,
            SyscallNumber::DeviceInfo, SyscallNumber::PortIo,
            SyscallNumber::ConsoleRead, SyscallNumber::Spawn,
            SyscallNumber::WaitTask, SyscallNumber::RevokeCapability,
            SyscallNumber::ChannelCreate, SyscallNumber::ChannelAttach,
            SyscallNumber::ChannelClose, SyscallNumber::ChannelRevoke,
            SyscallNumber::ChannelInfo, SyscallNumber::AuditAttach,
            SyscallNumber::AuditInfo,
            SyscallNumber::MapFramebuffer, SyscallNumber::ModuleReady,
            SyscallNumber::TryRecvMsg, SyscallNumber::VirtioModernCaps,
            SyscallNumber::AuditEmitInputFocus,
            SyscallNumber::GetProcessPrincipal,
        ];

        for &num in &all {
            let is_exempt = EXEMPT.contains(&num);
            assert_eq!(
                num.requires_identity(),
                !is_exempt,
                "{:?}: requires_identity()={} but exempt={}",
                num,
                num.requires_identity(),
                is_exempt,
            );
        }
    }

    #[test]
    fn exempt_set_is_minimal() {
        // The exempt set must be exactly 7 syscalls (Exit, Yield, GetPid,
        // GetTime, Print, GetPrincipal, ModuleReady). If this test fails,
        // someone added a new exempt syscall — that requires justification.
        assert_eq!(EXEMPT.len(), 7, "exempt set size changed — review required");
    }

    #[test]
    fn all_syscall_numbers_covered() {
        // Verify from_u64 round-trips for all defined values, ensuring
        // no gap in the requires_identity() match. ADR-022 reserves
        // 39 (SetWallclock) and 40 (GetWallclock) but they are not yet
        // wired through dispatch, so from_u64 returns None for them
        // today; assert that explicitly so this test catches the day
        // they land but isn't broken until then.
        for i in 0..=38u64 {
            let num = SyscallNumber::from_u64(i);
            assert!(num.is_some(), "from_u64({}) returned None", i);
            let _ = num.unwrap().requires_identity();
        }
        assert!(SyscallNumber::from_u64(39).is_none(), "ADR-022 SetWallclock not yet wired");
        assert!(SyscallNumber::from_u64(40).is_none(), "ADR-022 GetWallclock not yet wired");
        let aef = SyscallNumber::from_u64(41);
        assert_eq!(aef, Some(SyscallNumber::AuditEmitInputFocus));
        let _ = aef.unwrap().requires_identity();
        let gpp = SyscallNumber::from_u64(42);
        assert_eq!(gpp, Some(SyscallNumber::GetProcessPrincipal));
        let _ = gpp.unwrap().requires_identity();
    }
}
