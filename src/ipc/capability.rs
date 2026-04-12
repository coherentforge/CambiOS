// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Capability-based security manager
//!
//! Enforces fine-grained access control for IPC operations.
//! Each process holds capabilities that grant rights to communicate with endpoints.

use crate::ipc::{ProcessId, EndpointId, CapabilityRights, Principal};
extern crate alloc;
use alloc::boxed::Box;
use core::fmt;

/// Errors from capability operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    ProcessNotFound,
    EndpointNotFound,
    AccessDenied,
    CapabilityFull,
    InvalidOperation,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ProcessNotFound => write!(f, "Process not found"),
            Self::EndpointNotFound => write!(f, "Endpoint not found"),
            Self::AccessDenied => write!(f, "Access denied"),
            Self::CapabilityFull => write!(f, "Process capability table full"),
            Self::InvalidOperation => write!(f, "Invalid capability operation"),
        }
    }
}

/// A single capability grant: rights to an endpoint
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    /// Target endpoint
    pub endpoint: EndpointId,
    /// Rights granted
    pub rights: CapabilityRights,
}

/// Capability table for a single process.
///
/// SCAFFOLDING: 32 capabilities per process.
/// Why: bounded set for verification; cache-line-friendly linear scan. Originally
///      chosen to match `MAX_PROCESSES` and `MAX_ENDPOINTS` (a process can
///      typically hold capabilities for ~half the system's endpoints). As of
///      Wave 2a, `MAX_PROCESSES` is runtime-computed (`config::num_slots()`),
///      but this per-process cap is still a fixed compile-time 32.
/// Replace when: Phase 3 work hits this — the policy service holds one capability
///      per service it mediates, the audit consumer holds one per producer.
///      32 will get tight fast. See ASSUMPTIONS.md.
#[derive(Debug, Clone, Copy)]
pub struct ProcessCapabilities {
    /// Process ID
    pub process_id: ProcessId,
    /// Capabilities held by this process
    capabilities: [Option<Capability>; 32],
    /// Number of active capabilities
    count: u8,
    /// Cryptographic identity bound to this process.
    /// Set via BindPrincipal syscall. Once bound, cannot be rebound without
    /// explicit unbind (prevents identity theft).
    principal: Option<Principal>,
}

impl ProcessCapabilities {
    /// Create a new empty capability table
    pub fn new(process_id: ProcessId) -> Self {
        ProcessCapabilities {
            process_id,
            capabilities: [None; 32],
            count: 0,
            principal: None,
        }
    }

    /// Grant a capability to this process
    pub fn grant(&mut self, endpoint: EndpointId, rights: CapabilityRights) -> Result<(), CapabilityError> {
        if self.count >= 32 {
            return Err(CapabilityError::CapabilityFull);
        }

        // Check if already has this endpoint (invariant: no duplicates in 0..count)
        for i in 0..self.count as usize {
            if let Some(cap) = self.capabilities[i] {
                if cap.endpoint == endpoint {
                    // Update existing
                    self.capabilities[i] = Some(Capability { endpoint, rights });
                    return Ok(());
                }
            }
        }

        // Add new capability (relies on invariant: no Some exists beyond count)
        self.capabilities[self.count as usize] = Some(Capability { endpoint, rights });
        self.count += 1;
        Ok(())
    }

    /// Revoke a capability
    pub fn revoke(&mut self, endpoint: EndpointId) -> Result<(), CapabilityError> {
        for i in 0..self.count as usize {
            if let Some(cap) = self.capabilities[i] {
                if cap.endpoint == endpoint {
                    // Swap with last element and decrement (order doesn't matter for linear search)
                    if i != (self.count as usize - 1) {
                        self.capabilities[i] = self.capabilities[(self.count - 1) as usize];
                    }
                    self.capabilities[(self.count - 1) as usize] = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(CapabilityError::EndpointNotFound)
    }

    /// Check if process has specific rights to an endpoint
    pub fn verify_access(&self, endpoint: EndpointId, required: CapabilityRights) -> Result<(), CapabilityError> {
        for i in 0..self.count as usize {
            if let Some(cap) = self.capabilities[i] {
                if cap.endpoint == endpoint {
                    // Check all required rights are present
                    if required.send && !cap.rights.send {
                        return Err(CapabilityError::AccessDenied);
                    }
                    if required.receive && !cap.rights.receive {
                        return Err(CapabilityError::AccessDenied);
                    }
                    if required.delegate && !cap.rights.delegate {
                        return Err(CapabilityError::AccessDenied);
                    }
                    if required.revoke && !cap.rights.revoke {
                        return Err(CapabilityError::AccessDenied);
                    }
                    return Ok(());
                }
            }
        }
        Err(CapabilityError::AccessDenied)
    }

    /// Check if this process can delegate rights to an endpoint
    /// (used internally by CapabilityManager)
    fn can_delegate(&self, endpoint: EndpointId, requested_rights: CapabilityRights) -> Result<(), CapabilityError> {
        // Verify we have delegate right
        self.verify_access(endpoint, CapabilityRights {
            send: false,
            receive: false,
            delegate: true,
            revoke: false,
        })?;

        // Can't delegate more rights than we have
        for i in 0..self.count as usize {
            if let Some(cap) = self.capabilities[i] {
                if cap.endpoint == endpoint {
                    // Check delegating <= owned
                    if requested_rights.send && !cap.rights.send {
                        return Err(CapabilityError::InvalidOperation);
                    }
                    if requested_rights.receive && !cap.rights.receive {
                        return Err(CapabilityError::InvalidOperation);
                    }
                    if requested_rights.delegate && !cap.rights.delegate {
                        return Err(CapabilityError::InvalidOperation);
                    }
                    if requested_rights.revoke && !cap.rights.revoke {
                        return Err(CapabilityError::InvalidOperation);
                    }
                    return Ok(());
                }
            }
        }
        Err(CapabilityError::EndpointNotFound)
    }

    /// Get capability for an endpoint (read-only)
    pub fn get(&self, endpoint: EndpointId) -> Option<Capability> {
        for i in 0..self.count as usize {
            if let Some(cap) = self.capabilities[i] {
                if cap.endpoint == endpoint {
                    return Some(cap);
                }
            }
        }
        None
    }

    /// List all capabilities held by this process
    pub fn list(&self) -> &[Option<Capability>; 32] {
        &self.capabilities
    }

    /// Count of active capabilities
    pub fn capability_count(&self) -> u8 {
        self.count
    }
}

/// Global capability manager for the system
///
/// Tracks capabilities for all processes. Central policy enforcement point.
///
/// Wave 2a: slot storage is a `&'static mut [Option<ProcessCapabilities>]`
/// slice backed by the kernel object table region (see
/// `memory::object_table::init`). The slice length equals
/// `config::num_slots()`, computed at boot from the active tier policy.
pub struct CapabilityManager {
    /// Capability tables for processes (process ID maps to index)
    process_caps: &'static mut [Option<ProcessCapabilities>],
    /// Number of active processes with capabilities
    process_count: u16,
}

impl CapabilityManager {
    /// Construct a capability manager backed by an already-initialized
    /// slice from the kernel object table region.
    ///
    /// The slice must have every slot pre-initialized to `None`
    /// (which `object_table::init` guarantees). The returned
    /// `Box<Self>` header lives on the kernel heap; the slot storage
    /// lives in the object table region.
    pub fn from_object_slice(
        process_caps: &'static mut [Option<ProcessCapabilities>],
    ) -> Option<Box<Self>> {
        Some(Box::new(CapabilityManager {
            process_caps,
            process_count: 0,
        }))
    }

    /// Number of slots in the capability table (equal to `config::num_slots()`).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.process_caps.len()
    }

    /// Test-only constructor that allocates a host-side `Vec` of the
    /// given size and leaks it into a `'static` slice. Only usable in
    /// host unit tests; the kernel path always goes through
    /// [`from_object_slice`].
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Box<Self> {
        Self::new_for_test_with_capacity(32)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_capacity(num_slots: usize) -> Box<Self> {
        let mut v: alloc::vec::Vec<Option<ProcessCapabilities>> =
            alloc::vec::Vec::with_capacity(num_slots);
        for _ in 0..num_slots {
            v.push(None);
        }
        let boxed: Box<[Option<ProcessCapabilities>]> = v.into_boxed_slice();
        let slice: &'static mut [Option<ProcessCapabilities>] = Box::leak(boxed);
        Box::new(CapabilityManager {
            process_caps: slice,
            process_count: 0,
        })
    }

    /// Register a new process in the capability system
    pub fn register_process(&mut self, process_id: ProcessId) -> Result<(), CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        if self.process_caps[process_id.0 as usize].is_some() {
            return Err(CapabilityError::InvalidOperation); // Already registered
        }

        self.process_caps[process_id.0 as usize] = Some(ProcessCapabilities::new(process_id));
        self.process_count += 1;
        Ok(())
    }

    /// Unregister a process (revoke all its capabilities)
    pub fn unregister_process(&mut self, process_id: ProcessId) -> Result<(), CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        if self.process_caps[process_id.0 as usize].is_some() {
            self.process_caps[process_id.0 as usize] = None;
            self.process_count -= 1;
            Ok(())
        } else {
            Err(CapabilityError::ProcessNotFound)
        }
    }

    /// Grant a capability to a process
    pub fn grant_capability(
        &mut self,
        process_id: ProcessId,
        endpoint: EndpointId,
        rights: CapabilityRights,
    ) -> Result<(), CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        if let Some(caps) = &mut self.process_caps[process_id.0 as usize] {
            caps.grant(endpoint, rights)
        } else {
            Err(CapabilityError::ProcessNotFound)
        }
    }

    /// Verify a process has access to an endpoint
    pub fn verify_access(
        &self,
        process_id: ProcessId,
        endpoint: EndpointId,
        rights: CapabilityRights,
    ) -> Result<(), CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        if let Some(caps) = &self.process_caps[process_id.0 as usize] {
            caps.verify_access(endpoint, rights)
        } else {
            Err(CapabilityError::ProcessNotFound)
        }
    }

    /// Revoke a capability
    pub fn revoke_capability(
        &mut self,
        process_id: ProcessId,
        endpoint: EndpointId,
    ) -> Result<(), CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        if let Some(caps) = &mut self.process_caps[process_id.0 as usize] {
            caps.revoke(endpoint)
        } else {
            Err(CapabilityError::ProcessNotFound)
        }
    }

    /// Get process capability table
    pub fn get_capabilities(&self, process_id: ProcessId) -> Result<&ProcessCapabilities, CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        self.process_caps[process_id.0 as usize]
            .as_ref()
            .ok_or(CapabilityError::ProcessNotFound)
    }

    /// Get mutable reference to process capabilities
    pub fn get_capabilities_mut(&mut self, process_id: ProcessId) -> Result<&mut ProcessCapabilities, CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        self.process_caps[process_id.0 as usize]
            .as_mut()
            .ok_or(CapabilityError::ProcessNotFound)
    }

    /// Count of registered processes
    pub fn process_count(&self) -> u16 {
        self.process_count
    }

    /// Bind a Principal (cryptographic identity) to a process.
    ///
    /// Once bound, the Principal cannot be rebound without explicit unbind.
    /// This prevents identity theft — a process cannot assume another's identity.
    pub fn bind_principal(
        &mut self,
        process_id: ProcessId,
        principal: Principal,
    ) -> Result<(), CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        let caps = self.process_caps[process_id.0 as usize]
            .as_mut()
            .ok_or(CapabilityError::ProcessNotFound)?;

        if caps.principal.is_some() {
            return Err(CapabilityError::InvalidOperation); // Already bound
        }

        caps.principal = Some(principal);
        Ok(())
    }

    /// Get the Principal bound to a process.
    pub fn get_principal(
        &self,
        process_id: ProcessId,
    ) -> Result<Principal, CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        let caps = self.process_caps[process_id.0 as usize]
            .as_ref()
            .ok_or(CapabilityError::ProcessNotFound)?;

        caps.principal.ok_or(CapabilityError::ProcessNotFound)
    }

    /// Delegate a capability to another process.
    ///
    /// Pipeline: interceptor check → capability validation → grant.
    ///
    /// The source process must have the delegate right for the endpoint,
    /// and can only delegate rights it owns. The target process must be registered.
    ///
    /// # Example
    /// Process A has send/receive/delegate on endpoint E.
    /// Process A can delegate (send/receive) on E to Process B.
    /// Process A cannot delegate delegate right (only owned rights transfer).
    pub fn delegate_capability(
        &mut self,
        source_pid: ProcessId,
        target_pid: ProcessId,
        endpoint: EndpointId,
        rights: CapabilityRights,
    ) -> Result<(), CapabilityError> {
        self.delegate_capability_with_interceptor(source_pid, target_pid, endpoint, rights, None)
    }

    /// Delegate with optional interceptor check (defense-in-depth).
    pub fn delegate_capability_with_interceptor(
        &mut self,
        source_pid: ProcessId,
        target_pid: ProcessId,
        endpoint: EndpointId,
        rights: CapabilityRights,
        interceptor: Option<&dyn crate::ipc::interceptor::IpcInterceptor>,
    ) -> Result<(), CapabilityError> {
        if source_pid.0 as usize >= self.process_caps.len()
            || target_pid.0 as usize >= self.process_caps.len()
        {
            return Err(CapabilityError::InvalidOperation);
        }

        if source_pid == target_pid {
            return Err(CapabilityError::InvalidOperation); // Can't delegate to self
        }

        // Layer 1: Interceptor check (before any capability validation)
        if let Some(interceptor) = interceptor {
            use crate::ipc::interceptor::InterceptDecision;
            if let InterceptDecision::Deny(_) =
                interceptor.on_delegate(source_pid, target_pid, endpoint, rights)
            {
                return Err(CapabilityError::AccessDenied);
            }
        }

        // Layer 2: Validate the delegation is allowed (scoped to drop reference)
        {
            let source_caps = self.process_caps[source_pid.0 as usize]
                .as_ref()
                .ok_or(CapabilityError::ProcessNotFound)?;
            source_caps.can_delegate(endpoint, rights)?;
        }

        // Then grant to target (in a separate scope after source reference is dropped)
        let target_caps = self.process_caps[target_pid.0 as usize]
            .as_mut()
            .ok_or(CapabilityError::ProcessNotFound)?;
        target_caps.grant(endpoint, rights)?;

        Ok(())
    }

    /// Revoke a capability held by `holder` on `endpoint`, authorized by
    /// `revoker_principal`.
    ///
    /// This is the ADR-007 revocation primitive — the authority-checked
    /// counterpart to the low-level [`revoke_capability`] table mutation.
    ///
    /// The `bootstrap` parameter is the current bootstrap Principal, loaded
    /// by the caller from [`crate::BOOTSTRAP_PRINCIPAL`]. Passing it in (rather
    /// than having this method read the global) keeps the method testable in
    /// unit tests without depending on shared mutable global state, and
    /// matches the pattern of the existing `handle_claim_bootstrap_key`
    /// dispatcher which also loads the bootstrap once at the syscall boundary.
    ///
    /// After a successful return:
    /// - The capability is removed from the holder's [`ProcessCapabilities`] table.
    /// - The holder's next attempt to use the capability will fail the
    ///   standard [`verify_access`] check with [`CapabilityError::AccessDenied`],
    ///   which is the current v0 signal. (Active control-IPC notification is
    ///   deferred — see "Wave 4" stub below.)
    ///
    /// # Authority — v0 (Wave 1)
    ///
    /// Only the bootstrap Principal can revoke. This matches the existing
    /// pattern for `SyscallNumber::BindPrincipal` and
    /// `SyscallNumber::ClaimBootstrapKey`. ADR-007 §"Who can revoke" specifies
    /// three authority paths (original grantor, holder of `revoke` right,
    /// bootstrap/policy service); the other two land in Wave 4 when the policy
    /// service exists as the mediator.
    ///
    /// # Stubbed behavior (documented, not workarounds)
    ///
    /// The following ADR-007 §"How revocation interacts with channels" steps
    /// are intentionally stubbed in Wave 1 because their prerequisites do not
    /// exist yet. Each is marked in-code so a future maintainer cannot miss
    /// them when the prerequisite lands.
    ///
    /// - **Wave 2 (channels).** If the capability kind is a channel role,
    ///   unmap the shared pages from the holder's address space and issue a
    ///   TLB shootdown via `crate::arch::tlb::shootdown_range`. No channel
    ///   kind exists in Wave 1 — all capabilities are endpoint rights.
    /// - **Wave 3 (audit telemetry).** Emit an
    ///   `audit::Event::CapabilityRevoked { revoker, holder, endpoint, … }`
    ///   record to the per-CPU audit staging buffer. No audit subsystem
    ///   exists in Wave 1.
    /// - **Wave 4 (policy service).** Invalidate the per-CPU policy decision
    ///   cache for the `(holder, endpoint)` key via an IPI broadcast, and
    ///   send a control-IPC `CapabilityRevoked` notification to the holder
    ///   via the kernel-initiated send primitive. Neither the cache nor
    ///   the kernel-initiated send primitive exist in Wave 1.
    ///
    /// Wave 1 honors the "atomic, immediate, structural" properties of
    /// ADR-007 §"What revocation means" — the capability is gone the moment
    /// this method returns. The *active notification* property is the part
    /// that is stubbed; the holder learns of the revocation via its next
    /// failed [`verify_access`] call.
    pub fn revoke(
        &mut self,
        holder: ProcessId,
        endpoint: EndpointId,
        revoker_principal: Principal,
        bootstrap: Principal,
    ) -> Result<(), CapabilityError> {
        // Authority check — v0 (Wave 1): bootstrap Principal only.
        // TODO Wave 4: also accept the original grantor and any holder of the
        // `revoke` right on `endpoint`, per ADR-007 §"Who can revoke".
        if revoker_principal != bootstrap {
            return Err(CapabilityError::AccessDenied);
        }

        if holder.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        // Perform the table mutation. The existing per-process revoke() is
        // the low-level helper — it enforces the table invariants and returns
        // EndpointNotFound if the capability is already gone (idempotent
        // failure, not success).
        let caps = self.process_caps[holder.0 as usize]
            .as_mut()
            .ok_or(CapabilityError::ProcessNotFound)?;
        caps.revoke(endpoint)?;

        // TODO Wave 2: if the capability kind is a channel role, unmap the
        // shared pages from the holder's address space and issue a TLB
        // shootdown via crate::arch::tlb::shootdown_range(). Channels do not
        // exist yet — all capabilities are endpoint rights in Wave 1.
        //
        // TODO Wave 3: crate::audit::emit(Event::CapabilityRevoked {
        //     revoker: revoker_principal,
        //     holder,
        //     endpoint,
        //     timestamp: crate::scheduler::Timer::get_ticks(),
        // });
        //
        // TODO Wave 4: invalidate the per-CPU policy decision cache for
        // (holder, endpoint) via an IPI broadcast, then send a kernel-
        // originated control IPC notification to the holder using
        // kernel_send() + Principal::KERNEL. See ADR-006 §"Caching" and
        // ADR-007 §"How revocation interacts with channels" (step 10).

        Ok(())
    }

    /// Revoke every capability held by `process_id`.
    ///
    /// This is the process-exit cleanup path referenced in ADR-007 §"What
    /// this gives us" — it is called from [`handle_exit`] to ensure stale
    /// capabilities don't accumulate in the capability table after a process
    /// terminates.
    ///
    /// Unlike [`revoke`], this method performs **no per-capability authority
    /// check**: the process is already terminating, and the kernel is the
    /// sole caller. It is crate-internal and must not be exposed via syscall.
    ///
    /// Returns the number of capabilities that were removed.
    ///
    /// # Stubbed behavior
    ///
    /// Same Wave 2/3/4 stubs as [`revoke`], applied per-capability during
    /// iteration. Wave 3 (audit telemetry) will emit one
    /// `CapabilityRevoked` event per removed capability (or a single
    /// batched `ProcessTerminated` event that carries the count — that's a
    /// telemetry-design choice for Wave 3 to make).
    ///
    /// Note: this removes capabilities from the process's table but does not
    /// unregister the process itself. The caller should call
    /// [`unregister_process`] separately to drop the table entry when the
    /// process is fully cleaned up.
    pub fn revoke_all_for_process(
        &mut self,
        process_id: ProcessId,
    ) -> Result<usize, CapabilityError> {
        if process_id.0 as usize >= self.process_caps.len() {
            return Err(CapabilityError::InvalidOperation);
        }

        let caps = self.process_caps[process_id.0 as usize]
            .as_mut()
            .ok_or(CapabilityError::ProcessNotFound)?;

        let count = caps.capability_count() as usize;

        // Clear the table in place. We iterate defensively rather than
        // assuming the invariant "all Somes are in 0..count" — the per-process
        // grant/revoke methods maintain that invariant, but clear-all should
        // be robust against any future layout change.
        //
        // TODO Wave 3: emit an audit event per removed capability (or a single
        // batched ProcessTerminated event for the count).
        for slot in caps.capabilities.iter_mut() {
            *slot = None;
        }
        caps.count = 0;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_capabilities() {
        let mut caps = ProcessCapabilities::new(ProcessId(1));

        // Grant send/receive on endpoint 0
        let rights = CapabilityRights {
            send: true,
            receive: true,
            delegate: false,
            revoke: false,
        };
        caps.grant(EndpointId(0), rights).unwrap();

        // Verify access
        caps.verify_access(EndpointId(0), rights).unwrap();

        // Should fail with delegate
        assert!(caps.verify_access(EndpointId(0), CapabilityRights {
            send: false,
            receive: false,
            delegate: true,
            revoke: false,
        }).is_err());
    }

    #[test]
    fn test_capability_manager() {
        let mut mgr = CapabilityManager::new_for_test();

        let proc_id = ProcessId(1);
        let endpoint = EndpointId(10);

        // Register process
        mgr.register_process(proc_id).unwrap();

        // Grant capability
        let rights = CapabilityRights {
            send: true,
            receive: true,
            delegate: true,
            revoke: false,
        };
        mgr.grant_capability(proc_id, endpoint, rights).unwrap();

        // Verify access
        mgr.verify_access(proc_id, endpoint, CapabilityRights {
            send: true,
            receive: false,
            delegate: false,
            revoke: false,
        }).unwrap();

        // Revoke
        mgr.revoke_capability(proc_id, endpoint).unwrap();

        // Should fail now
        assert!(mgr.verify_access(proc_id, endpoint, CapabilityRights {
            send: true,
            receive: false,
            delegate: false,
            revoke: false,
        }).is_err());
    }

    #[test]
    fn test_delegation() {
        let mut mgr = CapabilityManager::new_for_test();

        let proc_a = ProcessId(1);
        let proc_b = ProcessId(2);
        let endpoint = EndpointId(10);

        // Register both processes
        mgr.register_process(proc_a).unwrap();
        mgr.register_process(proc_b).unwrap();

        // Grant A full rights including delegate
        let full_rights = CapabilityRights {
            send: true,
            receive: true,
            delegate: true,
            revoke: false,
        };
        mgr.grant_capability(proc_a, endpoint, full_rights).unwrap();

        // A delegates (send/receive only) to B
        let delegated_rights = CapabilityRights {
            send: true,
            receive: true,
            delegate: false,
            revoke: false,
        };
        mgr.delegate_capability(proc_a, proc_b, endpoint, delegated_rights).unwrap();

        // B now has send/receive on endpoint
        mgr.verify_access(proc_b, endpoint, delegated_rights).unwrap();

        // B should NOT have delegate right
        assert!(mgr.verify_access(proc_b, endpoint, CapabilityRights {
            send: false,
            receive: false,
            delegate: true,
            revoke: false,
        }).is_err());
    }

    #[test]
    fn test_delegation_requires_delegate_right() {
        let mut mgr = CapabilityManager::new_for_test();

        let proc_a = ProcessId(1);
        let proc_b = ProcessId(2);
        let endpoint = EndpointId(10);

        mgr.register_process(proc_a).unwrap();
        mgr.register_process(proc_b).unwrap();

        // Grant A only send/receive (no delegate right)
        let limited_rights = CapabilityRights {
            send: true,
            receive: true,
            delegate: false,
            revoke: false,
        };
        mgr.grant_capability(proc_a, endpoint, limited_rights).unwrap();

        // A cannot delegate (no delegate right)
        assert!(mgr.delegate_capability(proc_a, proc_b, endpoint, limited_rights).is_err());
    }

    #[test]
    fn test_delegation_cannot_escalate_rights() {
        let mut mgr = CapabilityManager::new_for_test();

        let proc_a = ProcessId(1);
        let proc_b = ProcessId(2);
        let endpoint = EndpointId(10);

        mgr.register_process(proc_a).unwrap();
        mgr.register_process(proc_b).unwrap();

        // Grant A only send (no receive, but has delegate)
        let limited_rights = CapabilityRights {
            send: true,
            receive: false,
            delegate: true,
            revoke: false,
        };
        mgr.grant_capability(proc_a, endpoint, limited_rights).unwrap();

        // A cannot delegate receive right (doesn't own it)
        assert!(mgr.delegate_capability(
            proc_a,
            proc_b,
            endpoint,
            CapabilityRights {
                send: true,
                receive: true,
                delegate: false,
                revoke: false,
            }
        ).is_err());
    }

    #[test]
    fn test_capability_limit() {
        let mut caps = ProcessCapabilities::new(ProcessId(1));

        // Grant 32 capabilities (the limit)
        for i in 0..32 {
            let rights = CapabilityRights {
                send: true,
                receive: false,
                delegate: false,
                revoke: false,
            };
            caps.grant(EndpointId(i), rights).unwrap();
        }

        // 33rd capability should fail
        assert!(caps.grant(
            EndpointId(32),
            CapabilityRights {
                send: true,
                receive: false,
                delegate: false,
                revoke: false,
            }
        ).is_err());
    }

    // ========================================================================
    // Principal binding tests
    // ========================================================================

    #[test]
    fn test_bind_and_get_principal() {
        let mut mgr = CapabilityManager::new_for_test();
        let proc_id = ProcessId(1);
        let principal = Principal::from_public_key([0xAA; 32]);

        mgr.register_process(proc_id).unwrap();
        mgr.bind_principal(proc_id, principal).unwrap();

        let retrieved = mgr.get_principal(proc_id).unwrap();
        assert_eq!(retrieved, principal);
    }

    #[test]
    fn test_bind_principal_rejects_double_bind() {
        let mut mgr = CapabilityManager::new_for_test();
        let proc_id = ProcessId(1);
        let p1 = Principal::from_public_key([0xAA; 32]);
        let p2 = Principal::from_public_key([0xBB; 32]);

        mgr.register_process(proc_id).unwrap();
        mgr.bind_principal(proc_id, p1).unwrap();

        // Second bind should fail — prevents identity theft
        assert!(mgr.bind_principal(proc_id, p2).is_err());

        // Original Principal is preserved
        assert_eq!(mgr.get_principal(proc_id).unwrap(), p1);
    }

    #[test]
    fn test_get_principal_unregistered_process() {
        let mgr = CapabilityManager::new_for_test();
        assert!(mgr.get_principal(ProcessId(99)).is_err());
    }

    #[test]
    fn test_get_principal_no_principal_bound() {
        let mut mgr = CapabilityManager::new_for_test();
        let proc_id = ProcessId(1);
        mgr.register_process(proc_id).unwrap();

        // Registered but no Principal bound yet
        assert!(mgr.get_principal(proc_id).is_err());
    }

    #[test]
    fn test_bind_principal_unregistered_process() {
        let mut mgr = CapabilityManager::new_for_test();
        let principal = Principal::from_public_key([0xAA; 32]);

        // Not registered — should fail
        assert!(mgr.bind_principal(ProcessId(99), principal).is_err());
    }

    // ========================================================================
    // Wave 1 revocation tests — CapabilityManager::revoke() and
    // revoke_all_for_process(). See ADR-007 for the design.
    // ========================================================================

    /// Helper: a holder process with one granted endpoint capability and a
    /// distinct "attacker" principal, plus a known bootstrap Principal to pass
    /// to `revoke()`. Returns (manager, holder_pid, endpoint, bootstrap).
    fn revoke_test_fixture() -> (Box<CapabilityManager>, ProcessId, EndpointId, Principal) {
        let mut mgr = CapabilityManager::new_for_test();
        let holder = ProcessId(1);
        let endpoint = EndpointId(10);
        let bootstrap = Principal::from_public_key([0xAA; 32]);

        mgr.register_process(holder).unwrap();
        mgr.grant_capability(
            holder,
            endpoint,
            CapabilityRights {
                send: true,
                receive: true,
                delegate: false,
                revoke: false,
            },
        )
        .unwrap();

        (mgr, holder, endpoint, bootstrap)
    }

    #[test]
    fn test_revoke_by_bootstrap_succeeds() {
        let (mut mgr, holder, endpoint, bootstrap) = revoke_test_fixture();

        // Bootstrap revokes the capability.
        mgr.revoke(holder, endpoint, bootstrap, bootstrap).unwrap();

        // Holder's next verify_access fails.
        let check = CapabilityRights {
            send: true,
            receive: false,
            delegate: false,
            revoke: false,
        };
        assert_eq!(
            mgr.verify_access(holder, endpoint, check),
            Err(CapabilityError::AccessDenied)
        );
    }

    #[test]
    fn test_revoke_by_non_bootstrap_rejected() {
        let (mut mgr, holder, endpoint, bootstrap) = revoke_test_fixture();
        let attacker = Principal::from_public_key([0xBB; 32]);

        // Attacker tries to revoke — rejected.
        assert_eq!(
            mgr.revoke(holder, endpoint, attacker, bootstrap),
            Err(CapabilityError::AccessDenied)
        );

        // Capability is still present.
        mgr.verify_access(
            holder,
            endpoint,
            CapabilityRights {
                send: true,
                receive: true,
                delegate: false,
                revoke: false,
            },
        )
        .unwrap();
    }

    #[test]
    fn test_revoke_nonexistent_endpoint_returns_endpoint_not_found() {
        let (mut mgr, holder, _endpoint, bootstrap) = revoke_test_fixture();
        let other = EndpointId(99);

        assert_eq!(
            mgr.revoke(holder, other, bootstrap, bootstrap),
            Err(CapabilityError::EndpointNotFound)
        );
    }

    #[test]
    fn test_revoke_unregistered_process_returns_process_not_found() {
        let (mut mgr, _holder, endpoint, bootstrap) = revoke_test_fixture();
        // In-range ProcessId but not registered (fixture only registers PID 1).
        let ghost = ProcessId(5);

        assert_eq!(
            mgr.revoke(ghost, endpoint, bootstrap, bootstrap),
            Err(CapabilityError::ProcessNotFound)
        );
    }

    #[test]
    fn test_revoke_out_of_range_pid_returns_invalid_operation() {
        let (mut mgr, _holder, endpoint, bootstrap) = revoke_test_fixture();
        // Beyond the manager's capacity — distinct code path from ProcessNotFound.
        let out_of_range = ProcessId(mgr.capacity() as u32);

        assert_eq!(
            mgr.revoke(out_of_range, endpoint, bootstrap, bootstrap),
            Err(CapabilityError::InvalidOperation)
        );
    }

    #[test]
    fn test_revoke_is_idempotent_failure() {
        let (mut mgr, holder, endpoint, bootstrap) = revoke_test_fixture();

        // First revoke succeeds.
        mgr.revoke(holder, endpoint, bootstrap, bootstrap).unwrap();

        // Second revoke returns EndpointNotFound — the capability is gone,
        // there is nothing to revoke. Intentional failure, not silent success.
        assert_eq!(
            mgr.revoke(holder, endpoint, bootstrap, bootstrap),
            Err(CapabilityError::EndpointNotFound)
        );
    }

    #[test]
    fn test_revoke_all_for_process_returns_count() {
        let mut mgr = CapabilityManager::new_for_test();
        let proc_id = ProcessId(1);
        mgr.register_process(proc_id).unwrap();

        // Grant 5 capabilities.
        for i in 0..5u32 {
            mgr.grant_capability(
                proc_id,
                EndpointId(i),
                CapabilityRights {
                    send: true,
                    receive: false,
                    delegate: false,
                    revoke: false,
                },
            )
            .unwrap();
        }

        // Reclaim them all.
        let count = mgr.revoke_all_for_process(proc_id).unwrap();
        assert_eq!(count, 5);

        // Every capability is gone.
        for i in 0..5u32 {
            assert_eq!(
                mgr.verify_access(
                    proc_id,
                    EndpointId(i),
                    CapabilityRights {
                        send: true,
                        receive: false,
                        delegate: false,
                        revoke: false,
                    }
                ),
                Err(CapabilityError::AccessDenied)
            );
        }

        // And the process entry is still registered (revoke_all is scoped to
        // caps, not the table entry — unregister_process is the separate path).
        assert!(mgr.get_capabilities(proc_id).is_ok());
    }

    #[test]
    fn test_revoke_all_for_process_empty_table_returns_zero() {
        let mut mgr = CapabilityManager::new_for_test();
        let proc_id = ProcessId(1);
        mgr.register_process(proc_id).unwrap();

        // Registered but no capabilities granted.
        assert_eq!(mgr.revoke_all_for_process(proc_id).unwrap(), 0);
    }

    #[test]
    fn test_revoke_all_for_process_unregistered_returns_error() {
        let mut mgr = CapabilityManager::new_for_test();
        // In-range but not registered.
        assert_eq!(
            mgr.revoke_all_for_process(ProcessId(5)),
            Err(CapabilityError::ProcessNotFound)
        );
    }

    #[test]
    fn test_revoke_all_for_process_out_of_range_returns_invalid_operation() {
        let mut mgr = CapabilityManager::new_for_test();
        assert_eq!(
            mgr.revoke_all_for_process(ProcessId(mgr.capacity() as u32)),
            Err(CapabilityError::InvalidOperation)
        );
    }

    #[test]
    fn test_revoke_all_for_process_preserves_other_processes() {
        let mut mgr = CapabilityManager::new_for_test();
        let victim = ProcessId(1);
        let bystander = ProcessId(2);
        let endpoint = EndpointId(10);
        let rights = CapabilityRights {
            send: true,
            receive: true,
            delegate: false,
            revoke: false,
        };

        mgr.register_process(victim).unwrap();
        mgr.register_process(bystander).unwrap();
        mgr.grant_capability(victim, endpoint, rights).unwrap();
        mgr.grant_capability(bystander, endpoint, rights).unwrap();

        // Reclaim victim's caps.
        mgr.revoke_all_for_process(victim).unwrap();

        // Bystander's capability is untouched.
        mgr.verify_access(bystander, endpoint, rights).unwrap();
    }
}
