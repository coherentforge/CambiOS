//! Capability-based security manager
//!
//! Enforces fine-grained access control for IPC operations.
//! Each process holds capabilities that grant rights to communicate with endpoints.

use crate::ipc::{ProcessId, EndpointId, CapabilityRights};
use crate::process::MAX_PROCESSES;
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

/// Capability table for a single process
/// 
/// Each process can hold up to 32 capabilities (endpoint access rights).
/// Designed for verification: bounded set, explicit tracking.
#[derive(Debug, Clone, Copy)]
pub struct ProcessCapabilities {
    /// Process ID
    pub process_id: ProcessId,
    /// Capabilities held by this process
    capabilities: [Option<Capability>; 32],
    /// Number of active capabilities
    count: u8,
}

impl ProcessCapabilities {
    /// Create a new empty capability table
    pub fn new(process_id: ProcessId) -> Self {
        ProcessCapabilities {
            process_id,
            capabilities: [None; 32],
            count: 0,
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
/// Memory footprint: 32 processes × 32 capabilities × ~16 bytes per Capability ≈ 16KB
/// Heap-allocated at boot via CapabilityManager::new_boxed().
pub struct CapabilityManager {
    /// Capability tables for processes (process ID maps to index)
    process_caps: [Option<ProcessCapabilities>; MAX_PROCESSES],
    /// Number of active processes with capabilities
    process_count: u16,
}

impl CapabilityManager {
    /// Create new capability manager
    pub const fn new() -> Self {
        CapabilityManager {
            process_caps: [None; MAX_PROCESSES],
            process_count: 0,
        }
    }

    /// Create a new capability manager directly on the heap.
    pub fn new_boxed() -> Box<Self> {
        use alloc::alloc::{alloc, Layout};
        let layout = Layout::new::<Self>();
        // SAFETY: layout is non-zero-sized (CapabilityManager contains arrays).
        let ptr = unsafe { alloc(layout) as *mut Self };
        if ptr.is_null() {
            panic!("Failed to allocate CapabilityManager");
        }
        // SAFETY: Cannot use alloc_zeroed because Option<ProcessCapabilities> may
        // use niche optimization (bool fields), so all-zeros might not be None.
        // Instead we write each field explicitly. ptr is valid and aligned per
        // alloc's contract. We write all fields before constructing the Box.
        unsafe {
            core::ptr::addr_of_mut!((*ptr).process_caps)
                .write([None; MAX_PROCESSES]);
            core::ptr::addr_of_mut!((*ptr).process_count).write(0u16);
            Box::from_raw(ptr)
        }
    }

    /// Register a new process in the capability system
    pub fn register_process(&mut self, process_id: ProcessId) -> Result<(), CapabilityError> {
        if process_id.0 >= MAX_PROCESSES as u32 {
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
        if process_id.0 >= MAX_PROCESSES as u32 {
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
        if process_id.0 >= MAX_PROCESSES as u32 {
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
        if process_id.0 >= MAX_PROCESSES as u32 {
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
        if process_id.0 >= MAX_PROCESSES as u32 {
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
        if process_id.0 >= MAX_PROCESSES as u32 {
            return Err(CapabilityError::InvalidOperation);
        }

        self.process_caps[process_id.0 as usize]
            .as_ref()
            .ok_or(CapabilityError::ProcessNotFound)
    }

    /// Get mutable reference to process capabilities
    pub fn get_capabilities_mut(&mut self, process_id: ProcessId) -> Result<&mut ProcessCapabilities, CapabilityError> {
        if process_id.0 >= MAX_PROCESSES as u32 {
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
        if source_pid.0 >= MAX_PROCESSES as u32 || target_pid.0 >= MAX_PROCESSES as u32 {
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
        };
        caps.grant(EndpointId(0), rights).unwrap();

        // Verify access
        caps.verify_access(EndpointId(0), rights).unwrap();

        // Should fail with delegate
        assert!(caps.verify_access(EndpointId(0), CapabilityRights {
            send: false,
            receive: false,
            delegate: true,
        }).is_err());
    }

    #[test]
    fn test_capability_manager() {
        let mut mgr = CapabilityManager::new();

        let proc_id = ProcessId(1);
        let endpoint = EndpointId(10);

        // Register process
        mgr.register_process(proc_id).unwrap();

        // Grant capability
        let rights = CapabilityRights {
            send: true,
            receive: true,
            delegate: true,
        };
        mgr.grant_capability(proc_id, endpoint, rights).unwrap();

        // Verify access
        mgr.verify_access(proc_id, endpoint, CapabilityRights {
            send: true,
            receive: false,
            delegate: false,
        }).unwrap();

        // Revoke
        mgr.revoke_capability(proc_id, endpoint).unwrap();

        // Should fail now
        assert!(mgr.verify_access(proc_id, endpoint, CapabilityRights {
            send: true,
            receive: false,
            delegate: false,
        }).is_err());
    }

    #[test]
    fn test_delegation() {
        let mut mgr = CapabilityManager::new();

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
        };
        mgr.grant_capability(proc_a, endpoint, full_rights).unwrap();

        // A delegates (send/receive only) to B
        let delegated_rights = CapabilityRights {
            send: true,
            receive: true,
            delegate: false,
        };
        mgr.delegate_capability(proc_a, proc_b, endpoint, delegated_rights).unwrap();

        // B now has send/receive on endpoint
        mgr.verify_access(proc_b, endpoint, delegated_rights).unwrap();

        // B should NOT have delegate right
        assert!(mgr.verify_access(proc_b, endpoint, CapabilityRights {
            send: false,
            receive: false,
            delegate: true,
        }).is_err());
    }

    #[test]
    fn test_delegation_requires_delegate_right() {
        let mut mgr = CapabilityManager::new();

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
        };
        mgr.grant_capability(proc_a, endpoint, limited_rights).unwrap();

        // A cannot delegate (no delegate right)
        assert!(mgr.delegate_capability(proc_a, proc_b, endpoint, limited_rights).is_err());
    }

    #[test]
    fn test_delegation_cannot_escalate_rights() {
        let mut mgr = CapabilityManager::new();

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
            }
        ).is_err());
    }
}
