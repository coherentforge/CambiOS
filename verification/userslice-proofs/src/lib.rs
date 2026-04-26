// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kani proof harnesses for the kernel's typed user-buffer slices
//! (`UserReadSlice` / `UserWriteSlice`, ADR-020,
//! `src/syscalls/user_slice.rs`).
//!
//! Proves the cheap-validation contract at the syscall boundary:
//! every invocation of `UserReadSlice::validate` / `UserWriteSlice::validate`
//! either rejects with `SyscallError::InvalidArg` or returns a slice
//! whose `(addr, len)` lie inside the canonical user range and whose
//! arithmetic does not overflow. These are the structural invariants
//! that handler-side `read_into` / `write_from` rely on at copy time.
//!
//! The proven module (`src/syscalls/user_slice.rs`) is included via
//! `#[path]` — no fork, no copy. The kernel file contains:
//!
//! ```text
//! use super::SyscallError;
//! use super::dispatcher::SyscallContext;
//! ```
//!
//! Including the file at this crate's root makes `super::` resolve to
//! `crate::*`, so this crate provides crate-root stubs for
//! `SyscallError` and `dispatcher::SyscallContext`. Same pattern as
//! capability-proofs's `crate::ipc::*` stubs, adapted for the
//! `super::`-style imports.
//!
//! The page-walk helpers further down `user_slice.rs`
//! (`read_user_buffer` / `write_user_buffer`) reference
//! `crate::hhdm_offset` and `crate::memory::paging::*`. Those are
//! stubbed with type-compatible no-op implementations: the proofs
//! only exercise `validate()` and never call the helpers, so the
//! stubs never run.
//!
//! Run with `cargo kani` from this directory.

extern crate alloc;

// ============================================================================
// Crate-root stubs — these resolve `super::*` references inside the
// included `user_slice.rs`.
// ============================================================================

/// Mirror of `crate::syscalls::SyscallError`. user_slice.rs only constructs
/// the `InvalidArg` variant; that is the only variant the stub needs to
/// expose for the include to type-check.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SyscallError {
    InvalidArg = -1,
}

pub mod dispatcher {
    //! Stand-in for `crate::syscalls::dispatcher::SyscallContext`.
    //! `validate()` reads only `ctx.cr3`; the rest of the kernel's
    //! struct is omitted.

    pub struct SyscallContext {
        pub cr3: u64,
    }
}

// ============================================================================
// Stubs for kernel-side names that `user_slice.rs` references in function
// bodies. The proofs only exercise `validate()`; these are never called.
// ============================================================================

/// Stub for `crate::hhdm_offset()`. Real kernel returns the Limine HHDM
/// base; the proven path never calls this so any value is fine.
pub fn hhdm_offset() -> u64 {
    0
}

pub mod memory {
    /// Stub mirroring the kernel's `crate::memory::paging` module.
    /// The kernel ships two implementations (one per cfg-arch); both
    /// expose `page_table_from_cr3` and `translate`, but with different
    /// return types (`OffsetPageTable<'static>` on x86_64,
    /// `PageTableRef` on others). For the proof crate the return type
    /// is irrelevant — `validate()` never calls these functions, and
    /// the only call sites (in `read_user_buffer` / `write_user_buffer`)
    /// only do `let pt = ...; translate(&pt, vaddr)`. A unit-struct
    /// `OffsetPageTable<'a>` satisfies both call sites on any arch.
    pub mod paging {
        /// Arch-agnostic stub. Named to match the x86_64 kernel-side
        /// type for symmetry; the only requirement is that
        /// `translate(&Self, _) -> Option<u64>` type-checks.
        pub struct OffsetPageTable<'a> {
            _phantom: core::marker::PhantomData<&'a ()>,
        }

        /// # Safety
        /// Stub — never called from proven paths. Real kernel walks PML4.
        pub unsafe fn page_table_from_cr3(_pml4_phys: u64) -> OffsetPageTable<'static> {
            OffsetPageTable {
                _phantom: core::marker::PhantomData,
            }
        }

        /// Stub. Always returns `None`; the proven path never calls this.
        pub fn translate(_pt: &OffsetPageTable, _virt_addr: u64) -> Option<u64> {
            None
        }
    }
}

// ============================================================================
// Proven kernel source. `super::*` references inside this module resolve
// to the crate-root stubs above.
// ============================================================================

#[path = "../../../src/syscalls/user_slice.rs"]
pub mod user_slice;

// ============================================================================
// Kani proofs
// ============================================================================

#[cfg(kani)]
mod proofs {
    use super::dispatcher::SyscallContext;
    use super::user_slice::{UserReadSlice, UserWriteSlice};
    use super::SyscallError;

    // user_slice.rs makes `MAX_USER_BUFFER` and `USER_SPACE_END`
    // `pub(super)`, which from this crate means the values are visible
    // only within `crate::user_slice`. We re-state them here at the
    // values the kernel uses; if either drifts in the kernel, the
    // proofs catch the inconsistency at the next run.
    //
    // `USER_SPACE_END` is arch-conditional in the kernel
    // (`src/syscalls/user_slice.rs:64-68`). The proof crate is
    // built under whatever toolchain Kani picked (typically
    // aarch64-apple-darwin on Apple Silicon hosts), so the proof
    // constant must follow the same `cfg` to match the kernel's
    // active value at proof-build time.
    const MAX_USER_BUFFER: usize = 4096;

    #[cfg(target_arch = "x86_64")]
    const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
    #[cfg(not(target_arch = "x86_64"))]
    const USER_SPACE_END: u64 = 0x0001_0000_0000_0000;

    fn any_ctx() -> SyscallContext {
        SyscallContext { cr3: kani::any() }
    }

    // ========================================================================
    // Tier R — `UserReadSlice::validate` invariants
    // ========================================================================

    /// U1.1 — Zero length validates unconditionally.
    ///
    /// For any cr3 (kernel or user) and any address (canonical or not),
    /// `validate(ctx, addr, 0)` returns `Ok`. The kernel's contract is
    /// "zero-length reads are no-ops"; this is the base case.
    #[kani::proof]
    fn proof_read_zero_len_always_ok() {
        let ctx = any_ctx();
        let addr: u64 = kani::any();
        let result = UserReadSlice::validate(&ctx, addr, 0);
        assert!(result.is_ok());
    }

    /// U1.2 — Non-zero length with kernel-task `cr3 == 0` is rejected.
    ///
    /// Captures the kernel-task carve-out: kernel tasks have no user
    /// address space, so any user-pointer copy is meaningless and must
    /// fail at the cheap-check stage.
    #[kani::proof]
    fn proof_read_kernel_cr3_with_nonzero_len_rejects() {
        let ctx = SyscallContext { cr3: 0 };
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > 0);

        let result = UserReadSlice::validate(&ctx, addr, len);
        assert_eq!(result.err(), Some(SyscallError::InvalidArg));
    }

    /// U1.3 — Length above `MAX_USER_BUFFER` (4 KiB) is rejected.
    ///
    /// The 4 KiB cap bounds the per-page-walk work in
    /// `copy_from_user_pages`. Any value above it is rejected before
    /// any page walk is attempted.
    #[kani::proof]
    fn proof_read_len_over_max_buffer_rejects() {
        let ctx = SyscallContext { cr3: kani::any() };
        kani::assume(ctx.cr3 != 0); // isolate the len check from the cr3 check
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > MAX_USER_BUFFER);

        let result = UserReadSlice::validate(&ctx, addr, len);
        assert_eq!(result.err(), Some(SyscallError::InvalidArg));
    }

    /// U1.4 — Address arithmetic that overflows `u64::MAX` is rejected.
    ///
    /// `addr.checked_add(len)` returning `None` must produce
    /// `Err(InvalidArg)`. Without this, a downstream page walk would
    /// silently wrap and read past `u64::MAX` — undefined.
    #[kani::proof]
    fn proof_read_addr_plus_len_overflow_rejects() {
        let ctx = SyscallContext { cr3: kani::any() };
        kani::assume(ctx.cr3 != 0);
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > 0 && len <= MAX_USER_BUFFER);
        // Force overflow: addr + len > u64::MAX.
        kani::assume(addr > u64::MAX - len as u64);

        let result = UserReadSlice::validate(&ctx, addr, len);
        assert_eq!(result.err(), Some(SyscallError::InvalidArg));
    }

    /// U1.5 — Address at or beyond the canonical user-space end is
    /// rejected.
    ///
    /// `addr >= USER_SPACE_END` covers both kernel-half addresses
    /// (above 0x0000_8000_0000_0000) and the boundary itself. Either
    /// case must reject before any walk attempts to dereference.
    #[kani::proof]
    fn proof_read_addr_at_or_above_userspace_end_rejects() {
        let ctx = SyscallContext { cr3: kani::any() };
        kani::assume(ctx.cr3 != 0);
        let addr: u64 = kani::any();
        kani::assume(addr >= USER_SPACE_END);
        let len: usize = kani::any();
        kani::assume(len > 0 && len <= MAX_USER_BUFFER);
        // Avoid overflow path so this proof exercises *only* the
        // address bound.
        kani::assume(addr <= u64::MAX - len as u64);

        let result = UserReadSlice::validate(&ctx, addr, len);
        assert_eq!(result.err(), Some(SyscallError::InvalidArg));
    }

    /// U1.6 — Inputs satisfying every invariant succeed and round-trip
    /// the input length.
    ///
    /// The complement of U1.2..U1.5: cr3 != 0, len in (0, MAX_USER_BUFFER],
    /// addr canonical, no overflow, end at or below USER_SPACE_END.
    /// `validate` must return `Ok(slice)` where `slice.len() == len`.
    #[kani::proof]
    fn proof_read_within_bounds_succeeds_preserves_len() {
        let ctx = SyscallContext { cr3: kani::any() };
        kani::assume(ctx.cr3 != 0);
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > 0 && len <= MAX_USER_BUFFER);
        kani::assume(addr < USER_SPACE_END);
        // No overflow.
        kani::assume(addr <= u64::MAX - len as u64);
        // Buffer fits inside user space.
        kani::assume(addr + (len as u64) <= USER_SPACE_END);

        let result = UserReadSlice::validate(&ctx, addr, len);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), len);
    }

    // ========================================================================
    // Tier W — `UserWriteSlice::validate` invariants
    //
    // Twin proofs of U1.x. UserWriteSlice::validate's body duplicates
    // UserReadSlice::validate's; these proofs witness that the
    // duplication is faithful, not just structurally similar.
    // ========================================================================

    /// U2.1 — Twin of U1.1.
    #[kani::proof]
    fn proof_write_zero_len_always_ok() {
        let ctx = any_ctx();
        let addr: u64 = kani::any();
        let result = UserWriteSlice::validate(&ctx, addr, 0);
        assert!(result.is_ok());
    }

    /// U2.2 — Twin of U1.2.
    #[kani::proof]
    fn proof_write_kernel_cr3_with_nonzero_len_rejects() {
        let ctx = SyscallContext { cr3: 0 };
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > 0);

        let result = UserWriteSlice::validate(&ctx, addr, len);
        assert_eq!(result.err(), Some(SyscallError::InvalidArg));
    }

    /// U2.3 — Twin of U1.3.
    #[kani::proof]
    fn proof_write_len_over_max_buffer_rejects() {
        let ctx = SyscallContext { cr3: kani::any() };
        kani::assume(ctx.cr3 != 0);
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > MAX_USER_BUFFER);

        let result = UserWriteSlice::validate(&ctx, addr, len);
        assert_eq!(result.err(), Some(SyscallError::InvalidArg));
    }

    /// U2.4 — Twin of U1.4.
    #[kani::proof]
    fn proof_write_addr_plus_len_overflow_rejects() {
        let ctx = SyscallContext { cr3: kani::any() };
        kani::assume(ctx.cr3 != 0);
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > 0 && len <= MAX_USER_BUFFER);
        kani::assume(addr > u64::MAX - len as u64);

        let result = UserWriteSlice::validate(&ctx, addr, len);
        assert_eq!(result.err(), Some(SyscallError::InvalidArg));
    }

    /// U2.5 — Twin of U1.5.
    #[kani::proof]
    fn proof_write_addr_at_or_above_userspace_end_rejects() {
        let ctx = SyscallContext { cr3: kani::any() };
        kani::assume(ctx.cr3 != 0);
        let addr: u64 = kani::any();
        kani::assume(addr >= USER_SPACE_END);
        let len: usize = kani::any();
        kani::assume(len > 0 && len <= MAX_USER_BUFFER);
        kani::assume(addr <= u64::MAX - len as u64);

        let result = UserWriteSlice::validate(&ctx, addr, len);
        assert_eq!(result.err(), Some(SyscallError::InvalidArg));
    }

    /// U2.6 — Twin of U1.6.
    #[kani::proof]
    fn proof_write_within_bounds_succeeds_preserves_len() {
        let ctx = SyscallContext { cr3: kani::any() };
        kani::assume(ctx.cr3 != 0);
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > 0 && len <= MAX_USER_BUFFER);
        kani::assume(addr < USER_SPACE_END);
        kani::assume(addr <= u64::MAX - len as u64);
        kani::assume(addr + (len as u64) <= USER_SPACE_END);

        let result = UserWriteSlice::validate(&ctx, addr, len);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), len);
    }
}
