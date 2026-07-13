// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The supervisor engine: a pure state machine over the manifest's
//! service entries. No syscalls, no allocation, no manifest borrows —
//! [`SupervisorEngine::new`] copies the identities and dependency
//! edges it needs into fixed arrays, so the engine is self-contained
//! and host-testable, and the shell's loop is three lines:
//! [`next_action`], perform the syscall, [`on_event`].
//!
//! Sequencing implements ADR-018 § 4 exactly: one spawn in flight at
//! a time, blocking on the spawned service's readiness ping before
//! any dependent (or successor) spawns — like-for-like with the
//! `BOOT_MODULE_ORDER` gate semantics it replaces at cutover.
//! Readiness is matched by the kernel-stamped sender AID against the
//! entry AID, never by anything the payload claims.
//!
//! No allocator, by policy (ADR-018 migration step 6): every bound
//! here is a wire-format bound. Revisit only if init ever needs a
//! dependency that pulls `alloc` — the userspace heap pattern is a
//! mechanical retrofit, not a redesign.
//!
//! [`next_action`]: SupervisorEngine::next_action
//! [`on_event`]: SupervisorEngine::on_event

use cambios_manifest::{Manifest, DEPS_MAX, MAX_MANIFEST_ENTRIES};

/// Engine capacity — the wire format's entry bound; the manifest is
/// the only input, so its bounds are the engine's bounds.
pub const MAX_SERVICES: usize = MAX_MANIFEST_ENTRIES;

/// Lifecycle state of one manifest entry. Explicit machine,
/// exhaustively matched everywhere (house verification discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Not yet spawned; deps may or may not be satisfied.
    NotSpawned,
    /// `SYS_SPAWN` succeeded; awaiting the service's readiness ping.
    /// `task` is the kernel task handle (slot, generation) the spawn
    /// returned — held for the step-10 restart machinery, which waits
    /// on exactly this handle.
    Spawned { task: u64 },
    /// Readiness ping received from the entry's AID.
    Ready,
    /// `SYS_SPAWN` itself failed.
    SpawnFailed,
    /// Never spawned: a transitive dependency is `SpawnFailed` or
    /// `DepFailed`, so this entry's turn can never come.
    DepFailed,
}

/// What the shell should do next. Exactly one of these is pending at
/// any time (sequential supervision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Call `SYS_SPAWN` for entry `idx`, then report
    /// [`Event::SpawnSucceeded`] or [`Event::SpawnFailed`].
    Spawn { idx: u16 },
    /// Block on init's endpoint for a readiness ping, then report
    /// [`Event::ReadyPing`].
    AwaitReady { idx: u16 },
    /// Every entry is terminal; supervision of the boot wave is over.
    Done,
}

/// What the world reported back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    SpawnSucceeded { idx: u16, task: u64 },
    SpawnFailed { idx: u16 },
    /// A verified message arrived on init's endpoint; `sender_aid` is
    /// the kernel-stamped Principal AID of the sender.
    ReadyPing { sender_aid: [u8; 32] },
}

/// Engine rejections. Construction errors are defensive re-checks of
/// invariants `Manifest::parse` + `topo_order` already established —
/// the engine's own soundness must not depend on its caller. Event
/// errors are anomalies for the shell to log; the machine state is
/// unchanged when one is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    /// More entries than `MAX_SERVICES` (unreachable off the parser).
    TooManyEntries,
    /// `order` is not a permutation of `0..entry_count`.
    BadOrder,
    /// A `depends_on` name matches no entry (unreachable after
    /// `topo_order`, which validates the same edges).
    UnknownDependency,
    /// Event names an index out of range.
    BadIndex,
    /// Event does not apply to the entry's current state (duplicate
    /// ready ping, spawn report for an already-settled entry, ...).
    UnexpectedEvent,
    /// Ready ping whose sender AID matches no entry. Worth a loud log
    /// at the shell: something unexpected holds send access to init's
    /// endpoint.
    UnknownSender,
}

/// Outcome counts for the boot wave, for init's summary line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Summary {
    pub ready: u16,
    pub spawn_failed: u16,
    pub dep_failed: u16,
    pub pending: u16,
}

/// Pure supervisor over the manifest's entries. ~10 KiB of fixed
/// arrays — lives on the shell's stack (user stacks are 64 KiB; the
/// shell is otherwise shallow).
pub struct SupervisorEngine {
    count: u16,
    /// Spawn order (indices into the entry arrays), dependencies
    /// first — `topo_order`'s output, validated as a permutation.
    order: [u16; MAX_SERVICES],
    state: [ServiceState; MAX_SERVICES],
    /// Entry AIDs, for readiness-ping correlation.
    aid: [[u8; 32]; MAX_SERVICES],
    /// Resolved dependency edges (entry index → dep entry indices).
    deps: [[u16; DEPS_MAX]; MAX_SERVICES],
    dep_len: [u8; MAX_SERVICES],
}

impl SupervisorEngine {
    /// Build the engine from a parsed manifest and its topological
    /// order (`cambios_manifest::topo_order` output). Copies AIDs and
    /// resolves dependency names to indices; after this the manifest
    /// is needed only by the shell (for `SYS_SPAWN` module names).
    pub fn new(m: &Manifest<'_>, order: &[u16]) -> Result<SupervisorEngine, EngineError> {
        let count = m.entry_count() as usize;
        if count > MAX_SERVICES {
            return Err(EngineError::TooManyEntries);
        }

        // `order` must be a permutation of 0..count.
        if order.len() != count {
            return Err(EngineError::BadOrder);
        }
        let mut seen = [false; MAX_SERVICES];
        for &idx in order {
            let i = idx as usize;
            if i >= count || seen[i] {
                return Err(EngineError::BadOrder);
            }
            seen[i] = true;
        }

        let mut eng = SupervisorEngine {
            count: count as u16,
            order: [0; MAX_SERVICES],
            state: [ServiceState::NotSpawned; MAX_SERVICES],
            aid: [[0; 32]; MAX_SERVICES],
            deps: [[0; DEPS_MAX]; MAX_SERVICES],
            dep_len: [0; MAX_SERVICES],
        };
        eng.order[..count].copy_from_slice(order);

        for i in 0..count {
            let entry = match m.entry(i as usize) {
                Some(e) => e,
                None => continue, // unreachable: i < entry_count
            };
            eng.aid[i] = entry.principal();
            let n_deps = entry.depends_on_len();
            for j in 0..n_deps {
                let name = entry.depends_on(j).ok_or(EngineError::UnknownDependency)?;
                let dep_idx = Self::find_by_name(m, name)?;
                eng.deps[i][j] = dep_idx;
                eng.dep_len[i] = (j + 1) as u8;
            }
        }
        Ok(eng)
    }

    /// Resolve a dependency name to its entry index (bounded linear
    /// scan; the same shape `topo_order` uses internally).
    fn find_by_name(m: &Manifest<'_>, name: &str) -> Result<u16, EngineError> {
        for k in 0..m.entry_count() {
            if let Some(e) = m.entry(k) {
                if e.module_name() == name {
                    return Ok(k as u16);
                }
            }
        }
        Err(EngineError::UnknownDependency)
    }

    /// The next thing to do. Walks the topo order for the first
    /// non-terminal entry: an in-flight spawn blocks everything
    /// (sequential per ADR-018 § 4); otherwise the entry is
    /// `NotSpawned` and — by the topo order plus the `DepFailed`
    /// cascade in [`Self::on_event`] — all its dependencies are
    /// `Ready`, so it spawns.
    pub fn next_action(&self) -> Action {
        for &idx in &self.order[..self.count as usize] {
            match self.state[idx as usize] {
                ServiceState::Spawned { .. } => return Action::AwaitReady { idx },
                ServiceState::NotSpawned => return Action::Spawn { idx },
                ServiceState::Ready | ServiceState::SpawnFailed | ServiceState::DepFailed => {}
            }
        }
        Action::Done
    }

    /// Feed back what happened. On `Err` the machine is unchanged.
    pub fn on_event(&mut self, ev: Event) -> Result<(), EngineError> {
        match ev {
            Event::SpawnSucceeded { idx, task } => {
                let s = self.state_mut(idx)?;
                match *s {
                    ServiceState::NotSpawned => {
                        *s = ServiceState::Spawned { task };
                        Ok(())
                    }
                    _ => Err(EngineError::UnexpectedEvent),
                }
            }
            Event::SpawnFailed { idx } => {
                let s = self.state_mut(idx)?;
                match *s {
                    ServiceState::NotSpawned => {
                        *s = ServiceState::SpawnFailed;
                        self.cascade_dep_failures();
                        Ok(())
                    }
                    _ => Err(EngineError::UnexpectedEvent),
                }
            }
            Event::ReadyPing { sender_aid } => {
                let idx = self
                    .find_by_aid(&sender_aid)
                    .ok_or(EngineError::UnknownSender)?;
                let s = &mut self.state[idx as usize];
                match *s {
                    ServiceState::Spawned { .. } => {
                        *s = ServiceState::Ready;
                        Ok(())
                    }
                    _ => Err(EngineError::UnexpectedEvent),
                }
            }
        }
    }

    /// Mark every `NotSpawned` entry with a failed (or transitively
    /// failed) dependency as `DepFailed`. Fixpoint over at most
    /// `count` passes — each productive pass settles at least one
    /// entry, so the loop bound is static (bounded-iteration rule).
    fn cascade_dep_failures(&mut self) {
        for _ in 0..self.count {
            let mut changed = false;
            for i in 0..self.count as usize {
                if self.state[i] != ServiceState::NotSpawned {
                    continue;
                }
                let failed_dep = self.deps[i][..self.dep_len[i] as usize].iter().any(|&d| {
                    matches!(
                        self.state[d as usize],
                        ServiceState::SpawnFailed | ServiceState::DepFailed
                    )
                });
                if failed_dep {
                    self.state[i] = ServiceState::DepFailed;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn state_mut(&mut self, idx: u16) -> Result<&mut ServiceState, EngineError> {
        if idx >= self.count {
            return Err(EngineError::BadIndex);
        }
        Ok(&mut self.state[idx as usize])
    }

    fn find_by_aid(&self, aid: &[u8; 32]) -> Option<u16> {
        (0..self.count as usize)
            .find(|&i| &self.aid[i] == aid)
            .map(|i| i as u16)
    }

    /// Current state of entry `idx` (shell logging / tests).
    pub fn state(&self, idx: u16) -> Option<ServiceState> {
        (idx < self.count).then(|| self.state[idx as usize])
    }

    /// Outcome counts across all entries.
    pub fn summary(&self) -> Summary {
        let mut s = Summary::default();
        for i in 0..self.count as usize {
            match self.state[i] {
                ServiceState::Ready => s.ready += 1,
                ServiceState::SpawnFailed => s.spawn_failed += 1,
                ServiceState::DepFailed => s.dep_failed += 1,
                ServiceState::NotSpawned | ServiceState::Spawned { .. } => s.pending += 1,
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cambios_manifest::{
        emit_manifest, emitted_size, topo_order, EntryDef, ServiceLifetime,
    };

    fn aid(tag: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = tag;
        a
    }

    /// Emit a manifest from (name, aid_tag, deps) triples and hand
    /// back (blob, topo order).
    fn build(entries: &[(&str, u8, &[&str])]) -> (Vec<u8>, Vec<u16>) {
        let defs: Vec<EntryDef> = entries
            .iter()
            .map(|&(name, tag, deps)| EntryDef {
                module_name: name,
                principal: aid(tag),
                reserved_endpoints: &[],
                grants: &[],
                lifetime: ServiceLifetime::OneShot,
                depends_on: deps,
            })
            .collect();
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        let m = Manifest::parse(&buf).unwrap();
        let mut order = vec![0u16; entries.len()];
        let n = topo_order(&m, &mut order).unwrap();
        order.truncate(n);
        (buf, order)
    }

    /// Drive the engine to completion with every spawn succeeding and
    /// every service pinging ready; returns the spawn sequence.
    fn run_happy(eng: &mut SupervisorEngine) -> Vec<u16> {
        let mut spawned = Vec::new();
        let mut task = 100u64;
        loop {
            match eng.next_action() {
                Action::Spawn { idx } => {
                    spawned.push(idx);
                    eng.on_event(Event::SpawnSucceeded { idx, task }).unwrap();
                    task += 1;
                }
                Action::AwaitReady { idx } => {
                    let a = eng.aid[idx as usize];
                    eng.on_event(Event::ReadyPing { sender_aid: a }).unwrap();
                }
                Action::Done => return spawned,
            }
        }
    }

    #[test]
    fn linear_chain_spawns_in_dependency_order() {
        let (blob, order) = build(&[
            ("c", 3, &["b"]),
            ("a", 1, &[]),
            ("b", 2, &["a"]),
        ]);
        let m = Manifest::parse(&blob).unwrap();
        let mut eng = SupervisorEngine::new(&m, &order).unwrap();

        // Sequential discipline: after a spawn, the ONLY action is
        // awaiting that service's readiness.
        let first = eng.next_action();
        let Action::Spawn { idx: a_idx } = first else { panic!("expected spawn") };
        eng.on_event(Event::SpawnSucceeded { idx: a_idx, task: 7 }).unwrap();
        assert_eq!(eng.next_action(), Action::AwaitReady { idx: a_idx });

        let spawned = run_happy(&mut eng);
        // run_happy continues from b: full order is a, b, c.
        let mut full = vec![a_idx];
        full.extend(spawned);
        let names: Vec<&str> = full
            .iter()
            .map(|&i| m.entry(i as usize).unwrap().module_name())
            .collect();
        assert_eq!(names, ["a", "b", "c"]);
        assert_eq!(eng.summary(), Summary { ready: 3, ..Default::default() });
    }

    #[test]
    fn diamond_respects_dependencies() {
        let (blob, order) = build(&[
            ("d", 4, &["b", "c"]),
            ("b", 2, &["a"]),
            ("c", 3, &["a"]),
            ("a", 1, &[]),
        ]);
        let m = Manifest::parse(&blob).unwrap();
        let mut eng = SupervisorEngine::new(&m, &order).unwrap();
        let spawned = run_happy(&mut eng);
        let pos = |name: &str| {
            spawned
                .iter()
                .position(|&i| m.entry(i as usize).unwrap().module_name() == name)
                .unwrap()
        };
        assert!(pos("a") < pos("b"));
        assert!(pos("a") < pos("c"));
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
        assert_eq!(eng.summary().ready, 4);
    }

    #[test]
    fn spawn_failure_cascades_but_independent_services_continue() {
        // a fails; b and c (transitively) depend on it; e is
        // independent and must still come up.
        let (blob, order) = build(&[
            ("a", 1, &[]),
            ("b", 2, &["a"]),
            ("c", 3, &["b"]),
            ("e", 5, &[]),
        ]);
        let m = Manifest::parse(&blob).unwrap();
        let mut eng = SupervisorEngine::new(&m, &order).unwrap();

        let a_idx = 0u16;
        let e_idx = 3u16;
        loop {
            match eng.next_action() {
                Action::Spawn { idx } if idx == a_idx => {
                    eng.on_event(Event::SpawnFailed { idx }).unwrap();
                }
                Action::Spawn { idx } => {
                    assert_eq!(idx, e_idx, "only the independent entry may spawn");
                    eng.on_event(Event::SpawnSucceeded { idx, task: 9 }).unwrap();
                }
                Action::AwaitReady { idx } => {
                    let a = eng.aid[idx as usize];
                    eng.on_event(Event::ReadyPing { sender_aid: a }).unwrap();
                }
                Action::Done => break,
            }
        }
        assert_eq!(eng.state(0), Some(ServiceState::SpawnFailed));
        assert_eq!(eng.state(1), Some(ServiceState::DepFailed));
        assert_eq!(eng.state(2), Some(ServiceState::DepFailed));
        assert_eq!(eng.state(3), Some(ServiceState::Ready));
        assert_eq!(
            eng.summary(),
            Summary { ready: 1, spawn_failed: 1, dep_failed: 2, pending: 0 }
        );
    }

    #[test]
    fn ready_ping_anomalies_are_typed_and_state_preserving() {
        let (blob, order) = build(&[("a", 1, &[]), ("b", 2, &["a"])]);
        let m = Manifest::parse(&blob).unwrap();
        let mut eng = SupervisorEngine::new(&m, &order).unwrap();

        // Ping before anything spawned: sender known, state wrong.
        assert_eq!(
            eng.on_event(Event::ReadyPing { sender_aid: aid(1) }),
            Err(EngineError::UnexpectedEvent)
        );
        // Unknown sender.
        assert_eq!(
            eng.on_event(Event::ReadyPing { sender_aid: aid(99) }),
            Err(EngineError::UnknownSender)
        );

        let Action::Spawn { idx } = eng.next_action() else { panic!() };
        eng.on_event(Event::SpawnSucceeded { idx, task: 1 }).unwrap();
        eng.on_event(Event::ReadyPing { sender_aid: aid(1) }).unwrap();
        // Duplicate ping.
        assert_eq!(
            eng.on_event(Event::ReadyPing { sender_aid: aid(1) }),
            Err(EngineError::UnexpectedEvent)
        );
        // Machine unchanged by the rejections: b spawns next.
        assert_eq!(eng.next_action(), Action::Spawn { idx: 1 });
    }

    #[test]
    fn construction_rejects_corrupt_order() {
        let (blob, order) = build(&[("a", 1, &[]), ("b", 2, &[])]);
        let m = Manifest::parse(&blob).unwrap();

        assert!(SupervisorEngine::new(&m, &order).is_ok());
        // Wrong length.
        assert_eq!(
            SupervisorEngine::new(&m, &order[..1]).map(|_| ()),
            Err(EngineError::BadOrder)
        );
        // Duplicate index.
        assert_eq!(
            SupervisorEngine::new(&m, &[0, 0]).map(|_| ()),
            Err(EngineError::BadOrder)
        );
        // Out-of-range index.
        assert_eq!(
            SupervisorEngine::new(&m, &[0, 7]).map(|_| ()),
            Err(EngineError::BadOrder)
        );
    }

    #[test]
    fn empty_manifest_is_immediately_done() {
        let mut buf = vec![0u8; emitted_size(&[]).unwrap()];
        emit_manifest(aid(0xEE), 1, &[], &mut buf).unwrap();
        let m = Manifest::parse(&buf).unwrap();
        let eng = SupervisorEngine::new(&m, &[]).unwrap();
        assert_eq!(eng.next_action(), Action::Done);
        assert_eq!(eng.summary(), Summary::default());
    }

    #[test]
    fn spawn_report_anomalies_are_typed() {
        let (blob, order) = build(&[("a", 1, &[])]);
        let m = Manifest::parse(&blob).unwrap();
        let mut eng = SupervisorEngine::new(&m, &order).unwrap();

        assert_eq!(
            eng.on_event(Event::SpawnSucceeded { idx: 5, task: 1 }),
            Err(EngineError::BadIndex)
        );
        eng.on_event(Event::SpawnSucceeded { idx: 0, task: 1 }).unwrap();
        // Double spawn report.
        assert_eq!(
            eng.on_event(Event::SpawnSucceeded { idx: 0, task: 2 }),
            Err(EngineError::UnexpectedEvent)
        );
        assert_eq!(
            eng.on_event(Event::SpawnFailed { idx: 0 }),
            Err(EngineError::UnexpectedEvent)
        );
    }
}
