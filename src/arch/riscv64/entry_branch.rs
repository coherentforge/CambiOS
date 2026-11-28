// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors

//! The riscv64 trap vector's entry-branch check (ADR-040 § 9), as pure
//! logic over two integers.
//!
//! `_riscv_trap_vector` decides which branch to take from `sscratch`
//! (0: the kernel was running; otherwise this hart's `PerCpu`, so the
//! trap came from U-mode) and passes the branch it took to the Rust
//! handler. The hardware records the same fact in `sstatus.SPP`. The two
//! disagree only when the `sscratch` invariant broke: a trap taken in
//! S-mode while `sscratch` was not 0, or one from U-mode while it was.
//! Then the frame was built from the wrong per-CPU anchor and nothing in
//! it is trusted; the handler halts with a typed report before any
//! dispatch.
//!
//! This module has no dependency on the riscv64 backend, so the host
//! test build compiles it on every architecture (`src/arch/mod.rs`
//! declares it under `any(target_arch = "riscv64", test)`): the check is
//! exercised by `make test`, which no riscv64 host runs. The pattern,
//! pure logic in its own file and declared for the host test build, is
//! how a non-host backend's decisions get host tests.

/// Which branch of `_riscv_trap_vector` built a frame. The vector passes
/// it in `a3` (0 or 1), chosen by its `sscratch` test; the hardware
/// records the same fact independently in `sstatus.SPP` (ADR-040 § 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryBranch {
    /// `sscratch` was 0: the trap was taken while the kernel ran.
    Supervisor,
    /// `sscratch` held this hart's `PerCpu`: the trap came from U-mode.
    User,
}

impl EntryBranch {
    /// Decode the vector's `a3`. `None` for any value it never passes.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Supervisor),
            1 => Some(Self::User),
            _ => None,
        }
    }

    /// The mode `sstatus.SPP` says the trap was taken from.
    pub const fn from_sstatus(sstatus: u64) -> Self {
        if sstatus & SSTATUS_SPP == 0 {
            Self::User
        } else {
            Self::Supervisor
        }
    }
}

/// HARDWARE: `sstatus.SPP`, bit 8: the privilege mode a trap was taken
/// from, 0 = U-mode, 1 = S-mode (riscv-privileged, "Supervisor Status
/// Register").
pub const SSTATUS_SPP: u64 = 1 << 8;

/// The vector's branch and `sstatus.SPP` disagree. `branch` is what the
/// vector reported (`None`: a value it never passes), `origin` what SPP
/// says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mismatch {
    pub branch: Option<EntryBranch>,
    pub origin: EntryBranch,
}

/// The branch the vector chose must be the one the frame's captured
/// `sstatus.SPP` names (ADR-040 § 9). `raw` is the vector's `a3`,
/// `sstatus` the value saved in the frame at entry, not the live CSR.
pub const fn check(raw: u64, sstatus: u64) -> Result<(), Mismatch> {
    let origin = EntryBranch::from_sstatus(sstatus);
    match EntryBranch::from_raw(raw) {
        Some(branch) if matches!((branch, origin),
            (EntryBranch::Supervisor, EntryBranch::Supervisor)
            | (EntryBranch::User, EntryBranch::User)) => Ok(()),
        branch => Err(Mismatch { branch, origin }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An sstatus value as a trap from S-mode leaves it: SPP set, SIE
    /// clear (the hardware clears SIE on entry), SPIE carrying the
    /// pre-trap SIE.
    const FROM_S: u64 = SSTATUS_SPP | (1 << 5);
    /// From U-mode: SPP clear, SPIE set (U-mode runs with SIE = 1).
    const FROM_U: u64 = 1 << 5;

    #[test]
    fn agreeing_branches_pass() {
        assert_eq!(check(0, FROM_S), Ok(()));
        assert_eq!(check(1, FROM_U), Ok(()));
    }

    #[test]
    fn supervisor_branch_for_a_user_trap_is_the_stale_anchor_case() {
        // sscratch was 0 while U-mode ran: the vector built the frame on
        // the program's stack pointer.
        assert_eq!(
            check(0, FROM_U),
            Err(Mismatch { branch: Some(EntryBranch::Supervisor), origin: EntryBranch::User })
        );
    }

    #[test]
    fn user_branch_for_a_supervisor_trap_is_the_m2_case() {
        // sscratch was non-zero while the kernel ran: the vector took the
        // user branch with that value as tp (the 2026-11-24 finding).
        assert_eq!(
            check(1, FROM_S),
            Err(Mismatch { branch: Some(EntryBranch::User), origin: EntryBranch::Supervisor })
        );
    }

    #[test]
    fn a_value_the_vector_never_passes_is_a_mismatch() {
        assert_eq!(
            check(2, FROM_S),
            Err(Mismatch { branch: None, origin: EntryBranch::Supervisor })
        );
        assert_eq!(
            check(u64::MAX, FROM_U),
            Err(Mismatch { branch: None, origin: EntryBranch::User })
        );
    }

    #[test]
    fn only_spp_decides_the_origin() {
        // Every other sstatus bit set, SPP clear: still U-mode.
        assert_eq!(EntryBranch::from_sstatus(!SSTATUS_SPP), EntryBranch::User);
        assert_eq!(EntryBranch::from_sstatus(SSTATUS_SPP), EntryBranch::Supervisor);
    }
}
