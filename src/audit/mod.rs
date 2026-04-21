// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kernel audit event infrastructure (Phase 3.3, ADR-007).
//!
//! Provides an internal observability surface for the policy service and
//! AI watcher. Events are emitted from syscall handlers and the loader
//! into per-CPU staging buffers, then drained to a global audit ring
//! that user-space consumers read.
//!
//! # Architecture
//!
//! ```text
//!  syscall handler ──► emit() ──► PER_CPU_AUDIT_BUFFER[cpu] ──► drain_tick() ──► AuditRing
//!                                   (lock-free SPSC)              (BSP ISR)      (consumer reads)
//! ```
//!
//! This is **not** external telemetry. CambiOS is telemetry-free to the outside
//! world. This is kernel→userspace event streaming for security observability.

pub mod buffer;
pub mod drain;

use crate::ipc::{EndpointId, ProcessId};

/// Audit event kind discriminant.
///
/// Each variant maps 1:1 to an event type from ADR-007 § "What gets logged".
/// The `repr(u8)` is the wire format written into `RawAuditEvent.data[0]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditEventKind {
    /// After a successful `RegisterEndpoint` or capability delegation.
    CapabilityGranted = 0,
    /// After a successful `revoke()` or `revoke_all_for_process()`.
    CapabilityRevoked = 1,
    /// When a capability check returns `PermissionDenied`.
    CapabilityDenied = 2,
    /// After successful IPC send (sampled, not every send).
    IpcSend = 3,
    /// After successful IPC recv (sampled).
    IpcRecv = 4,
    /// After `SYS_CHANNEL_CREATE` succeeds.
    ChannelCreated = 5,
    /// After `SYS_CHANNEL_ATTACH` succeeds.
    ChannelAttached = 6,
    /// After channel close (any path).
    ChannelClosed = 7,
    /// When the interceptor / policy service denies a syscall.
    SyscallDenied = 8,
    /// After `BinaryVerifier::verify()` succeeds.
    BinaryLoaded = 9,
    /// After `BinaryVerifier::verify()` fails.
    BinaryRejected = 10,
    /// After process creation.
    ProcessCreated = 11,
    /// After process exit.
    ProcessTerminated = 12,
    /// When the policy service is consulted (sampled).
    PolicyQuery = 13,
    /// Reserved for future AI watcher anomaly flagging.
    AnomalyHook = 14,
    /// Synthetic: reports accumulated drops from a staging buffer.
    AuditDropped = 15,
}

/// ARCHITECTURAL: size of one serialized audit event in bytes.
///
/// Matches ADR-007's "~64 bytes average" target. One x86_64 cache line.
/// The flat layout avoids serialization overhead and is memcpy-safe.
pub const RAW_AUDIT_EVENT_SIZE: usize = 64;

/// Fixed-size serialized audit event.
///
/// This is the unit stored in both per-CPU staging buffers and the global
/// audit ring. The flat byte layout avoids serialization overhead, is
/// `Copy`-safe (no destructors), and is directly readable by user-space
/// consumers through a read-only mapping.
///
/// # Wire format
///
/// ```text
/// [0]      event_kind: u8          (AuditEventKind discriminant)
/// [1]      flags: u8               (bit 0: sampled; bits 1-7: reserved)
/// [2..4]   reserved: [u8; 2]
/// [4..8]   sequence: u32           (per-CPU monotonic, wraps)
/// [8..16]  timestamp: u64          (Timer::get_ticks())
/// [16..24] subject_pid: u64        (ProcessId raw, or 0 for kernel)
/// [24..32] object_id: u64          (EndpointId, ChannelId, or secondary PID)
/// [32..40] arg0: u64               (event-specific)
/// [40..48] arg1: u64               (event-specific)
/// [48..56] arg2: u64               (event-specific)
/// [56..64] arg3: u64               (event-specific)
/// ```
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RawAuditEvent {
    pub data: [u8; RAW_AUDIT_EVENT_SIZE],
}

impl RawAuditEvent {
    /// All-zero event (used for array initialization in tests and drain buffers).
    pub const ZERO: Self = Self { data: [0u8; RAW_AUDIT_EVENT_SIZE] };

    // ── Field accessors ──

    /// The event kind discriminant (byte 0).
    #[inline]
    pub fn kind(&self) -> u8 {
        self.data[0]
    }

    /// The flags byte (byte 1).
    #[inline]
    pub fn flags(&self) -> u8 {
        self.data[1]
    }

    /// The per-CPU sequence number (bytes 4..8).
    #[inline]
    pub fn sequence(&self) -> u32 {
        u32::from_le_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    /// The timestamp in ticks (bytes 8..16).
    #[inline]
    pub fn timestamp(&self) -> u64 {
        u64::from_le_bytes(self.data[8..16].try_into().unwrap())
    }

    /// The subject ProcessId raw value (bytes 16..24).
    #[inline]
    pub fn subject_pid(&self) -> u64 {
        u64::from_le_bytes(self.data[16..24].try_into().unwrap())
    }

    /// The object identifier (bytes 24..32).
    #[inline]
    pub fn object_id(&self) -> u64 {
        u64::from_le_bytes(self.data[24..32].try_into().unwrap())
    }

    /// Event-specific argument 0 (bytes 32..40).
    #[inline]
    pub fn arg0(&self) -> u64 {
        u64::from_le_bytes(self.data[32..40].try_into().unwrap())
    }

    // ── Typed builder constructors ──
    //
    // Each builder produces a fully populated 64-byte event. The caller
    // supplies domain-typed arguments; the builder encodes them into the
    // flat wire format. `emit()` is the only consumer of these builders.

    /// Build the common header bytes shared by all event types.
    #[allow(clippy::too_many_arguments)]
    fn build(
        kind: AuditEventKind,
        flags: u8,
        sequence: u32,
        timestamp: u64,
        subject_pid: u64,
        object_id: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
    ) -> Self {
        let mut data = [0u8; RAW_AUDIT_EVENT_SIZE];
        data[0] = kind as u8;
        data[1] = flags;
        // data[2..4] reserved
        data[4..8].copy_from_slice(&sequence.to_le_bytes());
        data[8..16].copy_from_slice(&timestamp.to_le_bytes());
        data[16..24].copy_from_slice(&subject_pid.to_le_bytes());
        data[24..32].copy_from_slice(&object_id.to_le_bytes());
        data[32..40].copy_from_slice(&arg0.to_le_bytes());
        data[40..48].copy_from_slice(&arg1.to_le_bytes());
        data[48..56].copy_from_slice(&arg2.to_le_bytes());
        data[56..64].copy_from_slice(&arg3.to_le_bytes());
        Self { data }
    }

    /// `CAPABILITY_GRANTED`: after RegisterEndpoint or delegation.
    ///
    /// - `subject_pid`: the grantor
    /// - `object_id`: endpoint id
    /// - `arg0`: grantee ProcessId raw
    /// - `arg1`: rights bitmap
    pub fn capability_granted(
        grantor: ProcessId,
        grantee: ProcessId,
        endpoint: EndpointId,
        rights: u32,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::CapabilityGranted,
            0,
            sequence,
            timestamp,
            grantor.as_raw(),
            endpoint.0 as u64,
            grantee.as_raw(),
            rights as u64,
            0,
            0,
        )
    }

    /// `CAPABILITY_REVOKED`: after successful revoke.
    ///
    /// - `subject_pid`: the revoker
    /// - `object_id`: endpoint id
    /// - `arg0`: holder ProcessId raw
    pub fn capability_revoked(
        revoker: ProcessId,
        holder: ProcessId,
        endpoint: EndpointId,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::CapabilityRevoked,
            0,
            sequence,
            timestamp,
            revoker.as_raw(),
            endpoint.0 as u64,
            holder.as_raw(),
            0,
            0,
            0,
        )
    }

    /// `CAPABILITY_DENIED`: after capability check fails.
    ///
    /// - `subject_pid`: the caller that was denied
    /// - `object_id`: endpoint they tried to access
    pub fn capability_denied(
        caller: ProcessId,
        endpoint: EndpointId,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::CapabilityDenied,
            0,
            sequence,
            timestamp,
            caller.as_raw(),
            endpoint.0 as u64,
            0,
            0,
            0,
            0,
        )
    }

    /// `IPC_SEND`: after successful IPC send (sampled).
    ///
    /// - `subject_pid`: the sender
    /// - `object_id`: endpoint id
    /// - `arg0`: payload length
    pub fn ipc_send(
        sender: ProcessId,
        endpoint: EndpointId,
        payload_len: usize,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::IpcSend,
            FLAG_SAMPLED,
            sequence,
            timestamp,
            sender.as_raw(),
            endpoint.0 as u64,
            payload_len as u64,
            0,
            0,
            0,
        )
    }

    /// `IPC_RECV`: after successful IPC recv (sampled).
    ///
    /// - `subject_pid`: the receiver
    /// - `object_id`: endpoint id
    /// - `arg0`: payload length
    pub fn ipc_recv(
        receiver: ProcessId,
        endpoint: EndpointId,
        payload_len: usize,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::IpcRecv,
            FLAG_SAMPLED,
            sequence,
            timestamp,
            receiver.as_raw(),
            endpoint.0 as u64,
            payload_len as u64,
            0,
            0,
            0,
        )
    }

    /// `CHANNEL_CREATED`: after SYS_CHANNEL_CREATE.
    ///
    /// - `subject_pid`: the creator
    /// - `object_id`: channel id
    /// - `arg0`: size in pages
    pub fn channel_created(
        creator: ProcessId,
        channel_id: u64,
        size_pages: u32,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::ChannelCreated,
            0,
            sequence,
            timestamp,
            creator.as_raw(),
            channel_id,
            size_pages as u64,
            0,
            0,
            0,
        )
    }

    /// `CHANNEL_ATTACHED`: after SYS_CHANNEL_ATTACH.
    ///
    /// - `subject_pid`: the attacher
    /// - `object_id`: channel id
    pub fn channel_attached(
        attacher: ProcessId,
        channel_id: u64,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::ChannelAttached,
            0,
            sequence,
            timestamp,
            attacher.as_raw(),
            channel_id,
            0,
            0,
            0,
            0,
        )
    }

    /// `CHANNEL_CLOSED`: after channel close (any path).
    ///
    /// - `subject_pid`: the closer
    /// - `object_id`: channel id
    /// - `arg0`: bytes transferred estimate
    /// - `arg1`: lifetime in ticks
    pub fn channel_closed(
        closer: ProcessId,
        channel_id: u64,
        bytes_transferred: u64,
        lifetime_ticks: u64,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::ChannelClosed,
            0,
            sequence,
            timestamp,
            closer.as_raw(),
            channel_id,
            bytes_transferred,
            lifetime_ticks,
            0,
            0,
        )
    }

    /// `SYSCALL_DENIED`: when the interceptor denies a syscall.
    ///
    /// - `subject_pid`: the caller that was denied
    /// - `arg0`: syscall number
    pub fn syscall_denied(
        caller: ProcessId,
        syscall_number: u64,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::SyscallDenied,
            0,
            sequence,
            timestamp,
            caller.as_raw(),
            0,
            syscall_number,
            0,
            0,
            0,
        )
    }

    /// `BINARY_LOADED`: after BinaryVerifier succeeds.
    ///
    /// - `subject_pid`: 0 (kernel context)
    /// - `arg0`: binary size
    /// - `arg1..arg3`: first 24 bytes of the content hash
    pub fn binary_loaded(
        binary_size: usize,
        hash_prefix: [u8; 24],
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        let arg1 = u64::from_le_bytes(hash_prefix[0..8].try_into().unwrap());
        let arg2 = u64::from_le_bytes(hash_prefix[8..16].try_into().unwrap());
        let arg3 = u64::from_le_bytes(hash_prefix[16..24].try_into().unwrap());
        Self::build(
            AuditEventKind::BinaryLoaded,
            0,
            sequence,
            timestamp,
            0, // kernel context
            0,
            binary_size as u64,
            arg1,
            arg2,
            arg3,
        )
    }

    /// `BINARY_REJECTED`: after BinaryVerifier fails.
    ///
    /// - `arg0`: rejection reason code
    pub fn binary_rejected(
        reason: u64,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::BinaryRejected,
            0,
            sequence,
            timestamp,
            0, // kernel context
            0,
            reason,
            0,
            0,
            0,
        )
    }

    /// `PROCESS_CREATED`: after process creation.
    ///
    /// - `subject_pid`: the new process
    /// - `object_id`: parent ProcessId raw
    pub fn process_created(
        pid: ProcessId,
        parent: ProcessId,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::ProcessCreated,
            0,
            sequence,
            timestamp,
            pid.as_raw(),
            parent.as_raw(),
            0,
            0,
            0,
            0,
        )
    }

    /// `PROCESS_TERMINATED`: after process exit.
    ///
    /// - `subject_pid`: the exiting process
    /// - `arg0`: exit code
    /// - `arg1`: runtime ticks
    pub fn process_terminated(
        pid: ProcessId,
        exit_code: i32,
        runtime_ticks: u64,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::ProcessTerminated,
            0,
            sequence,
            timestamp,
            pid.as_raw(),
            0,
            exit_code as u64,
            runtime_ticks,
            0,
            0,
        )
    }

    /// `POLICY_QUERY`: when the policy service is consulted (sampled).
    ///
    /// - `subject_pid`: the process being queried about
    /// - `arg0`: syscall number
    /// - `arg1`: 0 = denied, 1 = allowed
    pub fn policy_query(
        subject: ProcessId,
        syscall_number: u64,
        allowed: bool,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::PolicyQuery,
            FLAG_SAMPLED,
            sequence,
            timestamp,
            subject.as_raw(),
            0,
            syscall_number,
            if allowed { 1 } else { 0 },
            0,
            0,
        )
    }

    /// `AUDIT_DROPPED`: synthetic event reporting accumulated drops.
    ///
    /// - `arg0`: number of events dropped
    /// - `arg1`: CPU id that dropped them
    pub fn audit_dropped(
        dropped_count: u64,
        cpu_id: u32,
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self::build(
            AuditEventKind::AuditDropped,
            0,
            sequence,
            timestamp,
            0, // kernel context
            0,
            dropped_count,
            cpu_id as u64,
            0,
            0,
        )
    }
}

/// Flag: this event was generated via sampling (not every occurrence).
pub const FLAG_SAMPLED: u8 = 0x01;

/// TUNING: IPC send/recv audit sampling rate. Emit 1 event per N operations.
///
/// At typical IPC rates (~1000 msg/sec), 1-in-100 sampling produces ~10
/// events/sec — well within the staging buffer capacity and informative
/// enough for pattern detection.
///
/// Replace when: policy service can dynamically adjust sampling rate via
/// a control IPC message (Phase 3.4+).
pub const AUDIT_IPC_SAMPLE_RATE: u32 = 100;

/// Emit an audit event to the current CPU's staging buffer.
///
/// This is the hot-path entry point. It reads the current CPU ID, writes
/// the event to `PER_CPU_AUDIT_BUFFER[cpu_id]`, and returns immediately.
///
/// If the staging buffer is full, the event is dropped and the per-CPU
/// drop counter is incremented. The kernel never blocks on audit.
///
/// # Performance
///
/// Target: <100ns. One atomic load (tail), one 64-byte write, one atomic
/// store (head). No lock, no CAS, no syscall.
#[inline(always)]
pub fn emit(event: RawAuditEvent) {
    #[cfg(all(not(any(test, fuzzing)), target_arch = "x86_64"))]
    {
        // SAFETY: Read GS base raw — if null, per-CPU data is not yet
        // initialized (early boot, before init_bsp). Drop the event silently.
        // This can happen when audit::emit() is inlined into load_elf_process(),
        // which runs during scheduler_init() — before init_hardware_interrupts()
        // calls init_bsp() to set GS base.
        let gs_base: u64;
        // SAFETY: rdmsr of IA32_GS_BASE (0xC0000101) is always safe at ring 0.
        // rdmsr returns result in EDX:EAX.
        unsafe {
            let lo: u32;
            let hi: u32;
            core::arch::asm!(
                "rdmsr",
                in("ecx") 0xC000_0101u32,
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack),
            );
            gs_base = ((hi as u64) << 32) | (lo as u64);
        }
        if gs_base != 0 {
            // SAFETY: GS base is valid (non-null), per-CPU data initialized.
            let cpu_id = unsafe { crate::arch::x86_64::percpu::current_cpu_id() } as usize;
            crate::PER_CPU_AUDIT_BUFFER[cpu_id].push(event);
        }
        // else: early boot, silently drop
    }

    #[cfg(all(not(any(test, fuzzing)), target_arch = "aarch64"))]
    {
        // SAFETY: Read TPIDR_EL1 raw — if null, per-CPU data is not yet
        // initialized (early boot, before init_bsp). Drop the event silently.
        // This can happen when audit::emit() is inlined into load_elf_process(),
        // which runs during scheduler_init() — before the AArch64 hardware
        // init block that calls init_bsp() to set TPIDR_EL1.
        let tpidr: u64;
        // SAFETY: mrs is a read-only register access, always safe at EL1.
        unsafe { core::arch::asm!("mrs {}, tpidr_el1", out(reg) tpidr, options(nostack, nomem)) };
        if tpidr != 0 {
            // SAFETY: TPIDR_EL1 is valid (non-null), per-CPU data initialized.
            let cpu_id = unsafe { crate::arch::aarch64::percpu::current_percpu().cpu_id() } as usize;
            crate::PER_CPU_AUDIT_BUFFER[cpu_id].push(event);
        }
        // else: early boot, silently drop
    }

    // Under test/fuzzing, emit is a no-op — there is no per-CPU hardware.
    // Also a no-op on riscv64 until the audit per-CPU staging is wired
    // through the RISC-V backend (post-R-5 work — see ADR-013).
    #[cfg(any(test, fuzzing, target_arch = "riscv64"))]
    {
        let _ = event;
    }
}

/// Convenience: get the current timestamp for audit events.
///
/// Wraps `Timer::get_ticks()` so callers don't need to import the scheduler.
#[inline]
pub fn now() -> u64 {
    crate::scheduler::Timer::get_ticks()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{EndpointId, ProcessId};

    #[test]
    fn event_kind_discriminants() {
        assert_eq!(AuditEventKind::CapabilityGranted as u8, 0);
        assert_eq!(AuditEventKind::AuditDropped as u8, 15);
        assert_eq!(AuditEventKind::ProcessTerminated as u8, 12);
    }

    #[test]
    fn raw_event_size() {
        assert_eq!(core::mem::size_of::<RawAuditEvent>(), RAW_AUDIT_EVENT_SIZE);
        assert_eq!(RAW_AUDIT_EVENT_SIZE, 64);
    }

    #[test]
    fn zero_event_is_all_zeroes() {
        let e = RawAuditEvent::ZERO;
        assert!(e.data.iter().all(|&b| b == 0));
    }

    #[test]
    fn capability_granted_builder() {
        let grantor = ProcessId::new(1, 0);
        let grantee = ProcessId::new(2, 0);
        let endpoint = EndpointId(16);
        let e = RawAuditEvent::capability_granted(grantor, grantee, endpoint, 0x03, 1000, 42);

        assert_eq!(e.kind(), AuditEventKind::CapabilityGranted as u8);
        assert_eq!(e.flags(), 0);
        assert_eq!(e.sequence(), 42);
        assert_eq!(e.timestamp(), 1000);
        assert_eq!(e.subject_pid(), grantor.as_raw());
        assert_eq!(e.object_id(), 16);
        assert_eq!(e.arg0(), grantee.as_raw());
    }

    #[test]
    fn capability_revoked_builder() {
        let revoker = ProcessId::new(0, 1);
        let holder = ProcessId::new(3, 0);
        let endpoint = EndpointId(8);
        let e = RawAuditEvent::capability_revoked(revoker, holder, endpoint, 500, 7);

        assert_eq!(e.kind(), AuditEventKind::CapabilityRevoked as u8);
        assert_eq!(e.subject_pid(), revoker.as_raw());
        assert_eq!(e.arg0(), holder.as_raw());
        assert_eq!(e.object_id(), 8);
        assert_eq!(e.timestamp(), 500);
    }

    #[test]
    fn capability_denied_builder() {
        let caller = ProcessId::new(5, 2);
        let endpoint = EndpointId(99);
        let e = RawAuditEvent::capability_denied(caller, endpoint, 777, 0);

        assert_eq!(e.kind(), AuditEventKind::CapabilityDenied as u8);
        assert_eq!(e.subject_pid(), caller.as_raw());
        assert_eq!(e.object_id(), 99);
    }

    #[test]
    fn ipc_send_has_sampled_flag() {
        let sender = ProcessId::new(1, 0);
        let e = RawAuditEvent::ipc_send(sender, EndpointId(10), 256, 100, 1);

        assert_eq!(e.kind(), AuditEventKind::IpcSend as u8);
        assert_eq!(e.flags() & FLAG_SAMPLED, FLAG_SAMPLED);
        assert_eq!(e.arg0(), 256); // payload_len
    }

    #[test]
    fn ipc_recv_has_sampled_flag() {
        let receiver = ProcessId::new(2, 0);
        let e = RawAuditEvent::ipc_recv(receiver, EndpointId(10), 128, 200, 2);

        assert_eq!(e.kind(), AuditEventKind::IpcRecv as u8);
        assert_eq!(e.flags() & FLAG_SAMPLED, FLAG_SAMPLED);
    }

    #[test]
    fn channel_created_builder() {
        let creator = ProcessId::new(1, 0);
        let e = RawAuditEvent::channel_created(creator, 0x0001_0005, 4, 300, 3);

        assert_eq!(e.kind(), AuditEventKind::ChannelCreated as u8);
        assert_eq!(e.object_id(), 0x0001_0005); // channel_id
        assert_eq!(e.arg0(), 4); // size_pages
    }

    #[test]
    fn channel_closed_builder() {
        let closer = ProcessId::new(1, 0);
        let e = RawAuditEvent::channel_closed(closer, 0x0001_0005, 65536, 1000, 400, 4);

        assert_eq!(e.kind(), AuditEventKind::ChannelClosed as u8);
        assert_eq!(e.arg0(), 65536); // bytes_transferred
        assert_eq!(u64::from_le_bytes(e.data[40..48].try_into().unwrap()), 1000); // lifetime
    }

    #[test]
    fn syscall_denied_builder() {
        let caller = ProcessId::new(3, 0);
        let e = RawAuditEvent::syscall_denied(caller, 25, 500, 5);

        assert_eq!(e.kind(), AuditEventKind::SyscallDenied as u8);
        assert_eq!(e.arg0(), 25); // syscall number (Spawn)
    }

    #[test]
    fn process_created_builder() {
        let pid = ProcessId::new(4, 0);
        let parent = ProcessId::new(1, 0);
        let e = RawAuditEvent::process_created(pid, parent, 600, 6);

        assert_eq!(e.kind(), AuditEventKind::ProcessCreated as u8);
        assert_eq!(e.subject_pid(), pid.as_raw());
        assert_eq!(e.object_id(), parent.as_raw());
    }

    #[test]
    fn process_terminated_builder() {
        let pid = ProcessId::new(4, 0);
        let e = RawAuditEvent::process_terminated(pid, -1, 50000, 700, 7);

        assert_eq!(e.kind(), AuditEventKind::ProcessTerminated as u8);
        assert_eq!(e.subject_pid(), pid.as_raw());
        // exit_code is -1, stored as u64 (two's complement)
        assert_eq!(e.arg0(), (-1i32) as u64);
    }

    #[test]
    fn binary_loaded_builder() {
        let hash = [0xABu8; 24];
        let e = RawAuditEvent::binary_loaded(4096, hash, 800, 8);

        assert_eq!(e.kind(), AuditEventKind::BinaryLoaded as u8);
        assert_eq!(e.subject_pid(), 0); // kernel context
        assert_eq!(e.arg0(), 4096); // binary size
    }

    #[test]
    fn binary_rejected_builder() {
        let e = RawAuditEvent::binary_rejected(2, 900, 9);

        assert_eq!(e.kind(), AuditEventKind::BinaryRejected as u8);
        assert_eq!(e.arg0(), 2); // reason code
    }

    #[test]
    fn policy_query_builder() {
        let subject = ProcessId::new(3, 0);
        let e = RawAuditEvent::policy_query(subject, 1, true, 1000, 10);

        assert_eq!(e.kind(), AuditEventKind::PolicyQuery as u8);
        assert_eq!(e.flags() & FLAG_SAMPLED, FLAG_SAMPLED);
        assert_eq!(e.arg0(), 1); // syscall number
        assert_eq!(u64::from_le_bytes(e.data[40..48].try_into().unwrap()), 1); // allowed
    }

    #[test]
    fn audit_dropped_builder() {
        let e = RawAuditEvent::audit_dropped(42, 3, 1100, 11);

        assert_eq!(e.kind(), AuditEventKind::AuditDropped as u8);
        assert_eq!(e.arg0(), 42); // dropped count
        assert_eq!(u64::from_le_bytes(e.data[40..48].try_into().unwrap()), 3); // cpu id
    }

    #[test]
    fn timestamp_round_trips() {
        let ts: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let e = RawAuditEvent::capability_denied(ProcessId::new(0, 0), EndpointId(0), ts, 0);
        assert_eq!(e.timestamp(), ts);
    }

    #[test]
    fn sequence_round_trips() {
        let seq: u32 = 0xFFFF_FFFE;
        let e = RawAuditEvent::capability_denied(ProcessId::new(0, 0), EndpointId(0), 0, seq);
        assert_eq!(e.sequence(), seq);
    }
}
