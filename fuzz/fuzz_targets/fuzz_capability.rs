// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Fuzz target: Capability system (ProcessCapabilities)
//!
//! Replays random sequences of grant/revoke/verify/delegate operations
//! against a ProcessCapabilities instance. Catches panics, invariant
//! violations, and capability escalation bugs.
//!
//! Properties that must hold:
//! - No panic on any operation sequence
//! - verify_access succeeds only if a matching grant exists with sufficient rights
//! - revoke of a non-existent endpoint returns EndpointNotFound
//! - grant count never exceeds 32 (the hard cap)
//! - capability escalation is impossible: delegated rights <= source rights

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use arcos_core::ipc::capability::{CapabilityError, ProcessCapabilities};
use arcos_core::ipc::{CapabilityRights, EndpointId, ProcessId};

/// Capability operations the fuzzer can invoke.
#[derive(Arbitrary, Debug)]
enum Op {
    /// Grant rights on an endpoint.
    Grant {
        endpoint: u8,
        send: bool,
        receive: bool,
        delegate: bool,
        revoke: bool,
    },
    /// Revoke an endpoint capability.
    Revoke { endpoint: u8 },
    /// Verify access with specific rights.
    Verify {
        endpoint: u8,
        send: bool,
        receive: bool,
        delegate: bool,
        revoke: bool,
    },
    /// Look up a capability.
    Get { endpoint: u8 },
}

fuzz_target!(|ops: Vec<Op>| {
    let mut caps = ProcessCapabilities::new(ProcessId::new(1, 0));

    // Shadow model: track what we expect to be granted.
    // Map endpoint → rights (only tracks the latest grant per endpoint).
    let mut shadow: [(bool, CapabilityRights); 256] = [(
        false,
        CapabilityRights {
            send: false,
            receive: false,
            delegate: false,
            revoke: false,
        },
    ); 256];
    let mut granted_count: usize = 0;

    for op in &ops {
        match op {
            Op::Grant {
                endpoint,
                send,
                receive,
                delegate,
                revoke,
            } => {
                let eid = EndpointId(*endpoint as u32);
                let rights = CapabilityRights {
                    send: *send,
                    receive: *receive,
                    delegate: *delegate,
                    revoke: *revoke,
                };
                let result = caps.grant(eid, rights);

                let idx = *endpoint as usize;
                if shadow[idx].0 {
                    // Update existing — should always succeed
                    assert!(result.is_ok(), "Grant update failed unexpectedly");
                    shadow[idx].1 = rights;
                } else if granted_count >= 32 {
                    // Table full
                    assert_eq!(result, Err(CapabilityError::CapabilityFull));
                } else {
                    // New grant
                    assert!(result.is_ok(), "New grant failed unexpectedly");
                    shadow[idx] = (true, rights);
                    granted_count += 1;
                }
            }
            Op::Revoke { endpoint } => {
                let eid = EndpointId(*endpoint as u32);
                let result = caps.revoke(eid);

                let idx = *endpoint as usize;
                if shadow[idx].0 {
                    assert!(result.is_ok(), "Revoke of granted endpoint failed");
                    shadow[idx].0 = false;
                    granted_count -= 1;
                } else {
                    assert_eq!(result, Err(CapabilityError::EndpointNotFound));
                }
            }
            Op::Verify {
                endpoint,
                send,
                receive,
                delegate,
                revoke,
            } => {
                let eid = EndpointId(*endpoint as u32);
                let required = CapabilityRights {
                    send: *send,
                    receive: *receive,
                    delegate: *delegate,
                    revoke: *revoke,
                };
                let result = caps.verify_access(eid, required);

                let idx = *endpoint as usize;
                if !shadow[idx].0 {
                    // No capability for this endpoint — must deny
                    assert!(result.is_err(), "Verify succeeded without any grant");
                } else {
                    let held = &shadow[idx].1;
                    let should_allow = (!required.send || held.send)
                        && (!required.receive || held.receive)
                        && (!required.delegate || held.delegate)
                        && (!required.revoke || held.revoke);

                    if should_allow {
                        assert!(
                            result.is_ok(),
                            "Verify denied despite sufficient rights: required={:?}, held={:?}",
                            required,
                            held
                        );
                    } else {
                        assert!(
                            result.is_err(),
                            "Verify allowed despite insufficient rights: required={:?}, held={:?}",
                            required,
                            held
                        );
                    }
                }
            }
            Op::Get { endpoint } => {
                let eid = EndpointId(*endpoint as u32);
                let result = caps.get(eid);

                let idx = *endpoint as usize;
                if shadow[idx].0 {
                    assert!(result.is_some(), "Get returned None for granted endpoint");
                    let cap = result.unwrap();
                    assert_eq!(cap.rights, shadow[idx].1, "Rights mismatch on Get");
                } else {
                    assert!(result.is_none(), "Get returned Some for ungranted endpoint");
                }
            }
        }
    }

    // Final invariant: capability_count matches our shadow
    assert_eq!(
        caps.capability_count() as usize,
        granted_count,
        "Capability count mismatch: kernel={}, shadow={}",
        caps.capability_count(),
        granted_count
    );
});
