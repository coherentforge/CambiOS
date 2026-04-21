// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Zero-Trust IPC Interceptor
//!
//! Policy enforcement layer that sits between capability checks and actual IPC
//! operations. Provides defense-in-depth: even if a process holds a valid
//! capability, the interceptor can deny operations based on runtime policy
//! (payload validation, endpoint bounds, delegation rules, syscall filtering).
//!
//! Design mirrors the `BinaryVerifier` trait in the loader — trait-based
//! abstraction with a `DefaultInterceptor` that enforces baseline policies.

use crate::ipc::{EndpointId, ProcessId, Message, MAX_ENDPOINTS};
use crate::syscalls::SyscallNumber;
use crate::ipc::CapabilityRights;
use core::fmt;

// ============================================================================
// Intercept decisions
// ============================================================================

/// Result of an interception check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptDecision {
    /// Operation is allowed to proceed
    Allow,
    /// Operation is denied with a reason
    Deny(DenyReason),
}

/// Reason an IPC operation was denied by the interceptor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Payload length exceeds maximum or is invalid
    InvalidPayload,
    /// Target endpoint ID is out of bounds
    EndpointOutOfBounds,
    /// Process attempted to send to itself
    SelfSend,
    /// Process attempted to delegate to itself
    SelfDelegation,
    /// Delegation would grant rights the source doesn't hold
    DelegationEscalation,
    /// Syscall not permitted for this process
    SyscallNotPermitted,
    /// Operation denied by custom policy
    PolicyViolation,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidPayload => write!(f, "Invalid payload"),
            Self::EndpointOutOfBounds => write!(f, "Endpoint out of bounds"),
            Self::SelfSend => write!(f, "Self-send denied"),
            Self::SelfDelegation => write!(f, "Self-delegation denied"),
            Self::DelegationEscalation => write!(f, "Delegation escalation denied"),
            Self::SyscallNotPermitted => write!(f, "Syscall not permitted"),
            Self::PolicyViolation => write!(f, "Policy violation"),
        }
    }
}

// ============================================================================
// Interceptor trait
// ============================================================================

/// Zero-trust IPC interceptor trait.
///
/// Called at key points in the IPC path to enforce runtime security policies.
/// Each hook receives enough context to make a policy decision and returns
/// `Allow` or `Deny(reason)`.
///
/// Hook call sites (defense-in-depth — AFTER capability checks):
/// - `on_send`: before message enqueue (async) or deposit (sync)
/// - `on_recv`: before message dequeue / pickup
/// - `on_delegate`: before capability delegation between processes
/// - `on_syscall`: before syscall dispatch (pre-handler filter)
pub trait IpcInterceptor: Send + Sync {
    /// Called before a message is sent (async or sync).
    ///
    /// Receives the sender process, target endpoint, and the message.
    fn on_send(
        &self,
        sender: ProcessId,
        endpoint: EndpointId,
        msg: &Message,
    ) -> InterceptDecision;

    /// Called before a message is received.
    ///
    /// Receives the receiver process and the endpoint being read.
    fn on_recv(
        &self,
        receiver: ProcessId,
        endpoint: EndpointId,
    ) -> InterceptDecision;

    /// Called before a capability delegation.
    ///
    /// Receives source and target process IDs, endpoint, and the rights
    /// being delegated.
    fn on_delegate(
        &self,
        source: ProcessId,
        target: ProcessId,
        endpoint: EndpointId,
        rights: CapabilityRights,
    ) -> InterceptDecision;

    /// Called before a syscall is dispatched.
    ///
    /// Receives the calling process and the syscall number. Can be used
    /// to enforce per-process syscall allowlists.
    fn on_syscall(
        &self,
        caller: ProcessId,
        syscall: SyscallNumber,
    ) -> InterceptDecision;
}

// ============================================================================
// Default interceptor
// ============================================================================

/// Default zero-trust interceptor enforcing baseline security policies.
///
/// Policies:
/// 1. **Payload validation**: message payload_len <= 256 and consistent
/// 2. **Endpoint bounds**: target endpoint < MAX_ENDPOINTS
/// 3. **No self-send**: process cannot send IPC to its own endpoint ID
/// 4. **No self-delegation**: process cannot delegate capabilities to itself
/// 5. **Syscall allowlist**: all defined syscalls permitted (extensible)
pub struct DefaultInterceptor {
    /// Maximum allowed payload size (bytes)
    pub max_payload: usize,
}

impl Default for DefaultInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultInterceptor {
    pub fn new() -> Self {
        Self {
            max_payload: 256,
        }
    }
}

// ============================================================================
// IpcInterceptorBackend — enum-dispatch shim for kernel-side interceptor
// ============================================================================
//
// The trait above is the *specification* — what every backend must implement.
// `IpcInterceptorBackend` is the *impl shim* used at the kernel-side
// `IpcManager.interceptor` and `ShardedIpcManager.interceptor` fields. It
// exists to satisfy CLAUDE.md's Formal Verification rule against `dyn`
// dispatch on kernel hot paths (interceptor runs on every IPC send/recv
// and every syscall pre-dispatch). See ADR-002 § Divergence for the full
// decision rationale (and the reconciliation with ADR-006's reframe of
// runtime extensibility into the userspace policy-service).
//
// In-kernel impl set is closed-world by construction:
//   - Default: permissive baseline (current).
//   - PolicyService: thin upcall client (future, when ADR-006 lands).
// Adding a new variant = one new arm in each of the 4 trait methods.

/// Enum-dispatch shim for `IpcInterceptor` backends installed at the
/// `IpcManager.interceptor` and `ShardedIpcManager.interceptor` fields.
/// See module-level note above and ADR-002 § Divergence.
pub enum IpcInterceptorBackend {
    /// Permissive baseline interceptor — endpoint bounds, payload size,
    /// no self-send, all syscalls allowed.
    Default(DefaultInterceptor),
    // Future: PolicyService(PolicyServiceInterceptor) — lands when ADR-006's
    // userspace policy-service IPC path is built. Until then, this enum has
    // exactly one variant.
}

impl IpcInterceptor for IpcInterceptorBackend {
    fn on_send(
        &self,
        sender: ProcessId,
        endpoint: EndpointId,
        msg: &Message,
    ) -> InterceptDecision {
        match self {
            Self::Default(i) => i.on_send(sender, endpoint, msg),
        }
    }

    fn on_recv(
        &self,
        receiver: ProcessId,
        endpoint: EndpointId,
    ) -> InterceptDecision {
        match self {
            Self::Default(i) => i.on_recv(receiver, endpoint),
        }
    }

    fn on_delegate(
        &self,
        source: ProcessId,
        target: ProcessId,
        endpoint: EndpointId,
        rights: CapabilityRights,
    ) -> InterceptDecision {
        match self {
            Self::Default(i) => i.on_delegate(source, target, endpoint, rights),
        }
    }

    fn on_syscall(
        &self,
        caller: ProcessId,
        syscall: SyscallNumber,
    ) -> InterceptDecision {
        match self {
            Self::Default(i) => i.on_syscall(caller, syscall),
        }
    }
}

impl IpcInterceptor for DefaultInterceptor {
    fn on_send(
        &self,
        sender: ProcessId,
        endpoint: EndpointId,
        msg: &Message,
    ) -> InterceptDecision {
        // 1. Endpoint bounds check
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return InterceptDecision::Deny(DenyReason::EndpointOutOfBounds);
        }

        // 2. Payload validation
        if msg.payload_len > self.max_payload {
            return InterceptDecision::Deny(DenyReason::InvalidPayload);
        }

        // 3. No self-send (sender endpoint == target endpoint from same process)
        if msg.from.0 == endpoint.0 && sender.slot() == endpoint.0 {
            return InterceptDecision::Deny(DenyReason::SelfSend);
        }

        InterceptDecision::Allow
    }

    fn on_recv(
        &self,
        _receiver: ProcessId,
        endpoint: EndpointId,
    ) -> InterceptDecision {
        // Endpoint bounds check
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return InterceptDecision::Deny(DenyReason::EndpointOutOfBounds);
        }

        InterceptDecision::Allow
    }

    fn on_delegate(
        &self,
        source: ProcessId,
        target: ProcessId,
        endpoint: EndpointId,
        _rights: CapabilityRights,
    ) -> InterceptDecision {
        // Endpoint bounds
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return InterceptDecision::Deny(DenyReason::EndpointOutOfBounds);
        }

        // No self-delegation
        if source == target {
            return InterceptDecision::Deny(DenyReason::SelfDelegation);
        }

        InterceptDecision::Allow
    }

    fn on_syscall(
        &self,
        _caller: ProcessId,
        _syscall: SyscallNumber,
    ) -> InterceptDecision {
        // Default: all defined syscalls are permitted.
        // Extended interceptors can enforce per-process allowlists.
        InterceptDecision::Allow
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(from: u32, to: u32, payload_len: usize) -> Message {
        let mut msg = Message::new(EndpointId(from), EndpointId(to));
        msg.payload_len = payload_len;
        msg
    }

    // --- DefaultInterceptor send tests ---

    #[test]
    fn test_send_allows_valid_message() {
        let interceptor = DefaultInterceptor::new();
        let msg = make_msg(0, 5, 100);
        assert_eq!(
            interceptor.on_send(ProcessId::new(0, 0), EndpointId(5), &msg),
            InterceptDecision::Allow,
        );
    }

    #[test]
    fn test_send_denies_endpoint_out_of_bounds() {
        let interceptor = DefaultInterceptor::new();
        let msg = make_msg(0, 99, 10);
        assert_eq!(
            interceptor.on_send(ProcessId::new(0, 0), EndpointId(99), &msg),
            InterceptDecision::Deny(DenyReason::EndpointOutOfBounds),
        );
    }

    #[test]
    fn test_send_denies_oversized_payload() {
        let interceptor = DefaultInterceptor::new();
        let msg = make_msg(0, 5, 300);
        assert_eq!(
            interceptor.on_send(ProcessId::new(0, 0), EndpointId(5), &msg),
            InterceptDecision::Deny(DenyReason::InvalidPayload),
        );
    }

    #[test]
    fn test_send_denies_self_send() {
        let interceptor = DefaultInterceptor::new();
        // Process 3 sending from endpoint 3 to endpoint 3
        let msg = make_msg(3, 3, 10);
        assert_eq!(
            interceptor.on_send(ProcessId::new(3, 0), EndpointId(3), &msg),
            InterceptDecision::Deny(DenyReason::SelfSend),
        );
    }

    #[test]
    fn test_send_allows_zero_payload() {
        let interceptor = DefaultInterceptor::new();
        let msg = make_msg(0, 5, 0);
        assert_eq!(
            interceptor.on_send(ProcessId::new(0, 0), EndpointId(5), &msg),
            InterceptDecision::Allow,
        );
    }

    #[test]
    fn test_send_allows_max_payload() {
        let interceptor = DefaultInterceptor::new();
        let msg = make_msg(0, 5, 256);
        assert_eq!(
            interceptor.on_send(ProcessId::new(0, 0), EndpointId(5), &msg),
            InterceptDecision::Allow,
        );
    }

    // --- DefaultInterceptor recv tests ---

    #[test]
    fn test_recv_allows_valid_endpoint() {
        let interceptor = DefaultInterceptor::new();
        assert_eq!(
            interceptor.on_recv(ProcessId::new(1, 0), EndpointId(5)),
            InterceptDecision::Allow,
        );
    }

    #[test]
    fn test_recv_denies_endpoint_out_of_bounds() {
        let interceptor = DefaultInterceptor::new();
        assert_eq!(
            interceptor.on_recv(ProcessId::new(1, 0), EndpointId(50)),
            InterceptDecision::Deny(DenyReason::EndpointOutOfBounds),
        );
    }

    // --- DefaultInterceptor delegate tests ---

    #[test]
    fn test_delegate_allows_valid() {
        let interceptor = DefaultInterceptor::new();
        assert_eq!(
            interceptor.on_delegate(
                ProcessId::new(1, 0), ProcessId::new(2, 0), EndpointId(5),
                CapabilityRights::SEND_ONLY,
            ),
            InterceptDecision::Allow,
        );
    }

    #[test]
    fn test_delegate_denies_self_delegation() {
        let interceptor = DefaultInterceptor::new();
        assert_eq!(
            interceptor.on_delegate(
                ProcessId::new(1, 0), ProcessId::new(1, 0), EndpointId(5),
                CapabilityRights::SEND_ONLY,
            ),
            InterceptDecision::Deny(DenyReason::SelfDelegation),
        );
    }

    #[test]
    fn test_delegate_denies_endpoint_out_of_bounds() {
        let interceptor = DefaultInterceptor::new();
        assert_eq!(
            interceptor.on_delegate(
                ProcessId::new(1, 0), ProcessId::new(2, 0), EndpointId(100),
                CapabilityRights::FULL,
            ),
            InterceptDecision::Deny(DenyReason::EndpointOutOfBounds),
        );
    }

    // --- DefaultInterceptor syscall tests ---

    #[test]
    fn test_syscall_allows_all_by_default() {
        let interceptor = DefaultInterceptor::new();
        assert_eq!(
            interceptor.on_syscall(ProcessId::new(1, 0), SyscallNumber::Write),
            InterceptDecision::Allow,
        );
        assert_eq!(
            interceptor.on_syscall(ProcessId::new(1, 0), SyscallNumber::GetPid),
            InterceptDecision::Allow,
        );
    }

    // --- Custom interceptor test ---

    #[test]
    fn test_custom_interceptor_deny_all_sends() {
        struct DenyAllSends;
        impl IpcInterceptor for DenyAllSends {
            fn on_send(&self, _: ProcessId, _: EndpointId, _: &Message) -> InterceptDecision {
                InterceptDecision::Deny(DenyReason::PolicyViolation)
            }
            fn on_recv(&self, _: ProcessId, _: EndpointId) -> InterceptDecision {
                InterceptDecision::Allow
            }
            fn on_delegate(&self, _: ProcessId, _: ProcessId, _: EndpointId, _: CapabilityRights) -> InterceptDecision {
                InterceptDecision::Allow
            }
            fn on_syscall(&self, _: ProcessId, _: SyscallNumber) -> InterceptDecision {
                InterceptDecision::Allow
            }
        }

        let interceptor = DenyAllSends;
        let msg = make_msg(0, 5, 10);
        assert_eq!(
            interceptor.on_send(ProcessId::new(0, 0), EndpointId(5), &msg),
            InterceptDecision::Deny(DenyReason::PolicyViolation),
        );
    }
}
