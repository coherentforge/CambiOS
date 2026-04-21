// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Typed user-buffer slices for syscall-boundary validation.
//!
//! Implements the types decided in [ADR-020](../../../docs/adr/020-typed-user-buffer-slices-at-syscall-boundary.md).
//! `UserReadSlice<'ctx>` and `UserWriteSlice<'ctx>` replace the raw
//! `(user_addr: u64, len: usize)` pair that flows through syscall
//! handlers today. A slice is a unitary typed value carrying:
//!
//! - A borrow of the current [`SyscallContext`] (lifetime-bound, so
//!   the slice cannot escape the handler),
//! - An already-validated address,
//! - An already-validated length,
//! - Its direction (read-only or write-only at the type level).
//!
//! Validation shape per ADR-020:
//! - **At construction (`::validate`)**: cheap checks — non-zero
//!   `cr3` for non-empty buffers, length within `MAX_USER_BUFFER`,
//!   address within the canonical user-space range, no overflow.
//! - **At use (`read_into` / `write_from`)**: per-page translate
//!   via the existing page-walk helpers. Can still fail if a page
//!   is unmapped at the moment of copy.
//!
//! # Phase 020.A (this commit)
//!
//! The types are **adapters over the existing `read_user_buffer` /
//! `write_user_buffer` helpers**. No syscall handlers migrate in
//! this phase — new code may adopt the types from day one, existing
//! handlers stay as-is. Handler migration lands in phase 020.B.
//!
//! The existing helpers repeat the cheap validation internally, so
//! `validate` → `read_into` performs the checks twice until phase
//! 020.C demotes the helpers to a private detail of this module.
//! The redundancy is acknowledged and temporary.

use super::SyscallError;
use super::dispatcher::{
    SyscallContext, MAX_USER_BUFFER, USER_SPACE_END,
    read_user_buffer, write_user_buffer,
};

/// Validated user-provided buffer that the kernel will **read**.
///
/// Construct via [`UserReadSlice::validate`]. Consume via
/// [`UserReadSlice::read_into`]. The lifetime `'ctx` ties the slice
/// to its [`SyscallContext`] borrow, so a slice cannot outlive the
/// syscall handler it was produced in.
pub struct UserReadSlice<'ctx> {
    ctx: &'ctx SyscallContext,
    addr: u64,
    len: usize,
}

/// Validated user-provided buffer that the kernel will **write**.
///
/// Construct via [`UserWriteSlice::validate`]. Consume via
/// [`UserWriteSlice::write_from`]. The lifetime `'ctx` ties the
/// slice to its [`SyscallContext`] borrow; a slice cannot outlive
/// the syscall handler.
pub struct UserWriteSlice<'ctx> {
    ctx: &'ctx SyscallContext,
    addr: u64,
    len: usize,
}

impl<'ctx> UserReadSlice<'ctx> {
    /// Validate an `(addr, len)` pair against the caller's syscall context.
    ///
    /// Returns `Err(SyscallError::InvalidArg)` if any cheap check fails:
    /// - Non-zero length with a kernel-task `cr3` (no user address space).
    /// - Length greater than [`MAX_USER_BUFFER`].
    /// - Address at or beyond the canonical user-space end.
    /// - Address + length overflows, or crosses the user-space end.
    ///
    /// Does not page-walk. A read may still fail later if a page in
    /// the range is unmapped at copy time.
    ///
    /// Zero-length slices validate unconditionally and read as no-ops —
    /// this matches the existing `read_user_buffer` short-circuit.
    pub fn validate(
        ctx: &'ctx SyscallContext,
        addr: u64,
        len: usize,
    ) -> Result<Self, SyscallError> {
        if len == 0 {
            return Ok(Self { ctx, addr, len });
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }
        if len > MAX_USER_BUFFER {
            return Err(SyscallError::InvalidArg);
        }
        let end = addr
            .checked_add(len as u64)
            .ok_or(SyscallError::InvalidArg)?;
        if addr >= USER_SPACE_END || end > USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        Ok(Self { ctx, addr, len })
    }

    /// Validated length of the user buffer, in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True iff the slice has zero length.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copy the user buffer into `dst`. `dst.len()` must equal
    /// [`Self::len`] exactly.
    ///
    /// Returns `Ok(())` on success. Returns `Err(SyscallError::InvalidArg)`
    /// on length mismatch or if any page in the user range is unmapped
    /// at copy time.
    pub fn read_into(&self, dst: &mut [u8]) -> Result<(), SyscallError> {
        if dst.len() != self.len {
            return Err(SyscallError::InvalidArg);
        }
        if self.len == 0 {
            return Ok(());
        }
        read_user_buffer(self.ctx.cr3, self.addr, self.len, dst).map(|_| ())
    }
}

impl<'ctx> UserWriteSlice<'ctx> {
    /// Validate an `(addr, len)` pair against the caller's syscall context.
    ///
    /// Same cheap checks as [`UserReadSlice::validate`]. Does not
    /// check that the target pages are mapped writable — that's a
    /// per-page concern verified at copy time.
    pub fn validate(
        ctx: &'ctx SyscallContext,
        addr: u64,
        len: usize,
    ) -> Result<Self, SyscallError> {
        if len == 0 {
            return Ok(Self { ctx, addr, len });
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }
        if len > MAX_USER_BUFFER {
            return Err(SyscallError::InvalidArg);
        }
        let end = addr
            .checked_add(len as u64)
            .ok_or(SyscallError::InvalidArg)?;
        if addr >= USER_SPACE_END || end > USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        Ok(Self { ctx, addr, len })
    }

    /// Validated length of the user buffer, in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True iff the slice has zero length.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copy `src` into the user buffer. `src.len()` must equal
    /// [`Self::len`] exactly.
    ///
    /// Returns `Ok(())` on success. Returns `Err(SyscallError::InvalidArg)`
    /// on length mismatch or if any page in the user range is unmapped
    /// (or not writable) at copy time.
    pub fn write_from(&self, src: &[u8]) -> Result<(), SyscallError> {
        if src.len() != self.len {
            return Err(SyscallError::InvalidArg);
        }
        if self.len == 0 {
            return Ok(());
        }
        write_user_buffer(self.ctx.cr3, self.addr, src).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{Principal, ProcessId};
    use crate::scheduler::TaskId;

    /// Build a synthetic SyscallContext for tests. `cr3` controls
    /// whether the context represents a user-space task (`cr3 != 0`)
    /// or a kernel task (`cr3 == 0`).
    fn test_ctx(cr3: u64) -> SyscallContext {
        SyscallContext {
            process_id: ProcessId::new(1, 0),
            task_id: TaskId(1),
            cr3,
            caller_principal: Some(Principal::from_public_key([0u8; 32])),
        }
    }

    // ── UserReadSlice::validate ──

    #[test]
    fn read_validate_zero_length_ok_regardless_of_address() {
        let ctx = test_ctx(0x1000);
        assert!(UserReadSlice::validate(&ctx, 0x400000, 0).is_ok());
        // Zero length short-circuits before address check.
        assert!(UserReadSlice::validate(&ctx, USER_SPACE_END, 0).is_ok());
        assert!(UserReadSlice::validate(&ctx, u64::MAX, 0).is_ok());
    }

    #[test]
    fn read_validate_zero_length_ok_even_with_kernel_cr3() {
        let ctx = test_ctx(0);
        assert!(UserReadSlice::validate(&ctx, 0x400000, 0).is_ok());
    }

    #[test]
    fn read_validate_nonzero_length_with_kernel_cr3_err() {
        let ctx = test_ctx(0);
        assert!(UserReadSlice::validate(&ctx, 0x400000, 1).is_err());
    }

    #[test]
    fn read_validate_len_at_max_ok() {
        let ctx = test_ctx(0x1000);
        assert!(UserReadSlice::validate(&ctx, 0x400000, MAX_USER_BUFFER).is_ok());
    }

    #[test]
    fn read_validate_len_over_max_err() {
        let ctx = test_ctx(0x1000);
        assert!(UserReadSlice::validate(&ctx, 0x400000, MAX_USER_BUFFER + 1).is_err());
    }

    #[test]
    fn read_validate_addr_at_userspace_end_err() {
        let ctx = test_ctx(0x1000);
        assert!(UserReadSlice::validate(&ctx, USER_SPACE_END, 1).is_err());
    }

    #[test]
    fn read_validate_addr_beyond_userspace_end_err() {
        let ctx = test_ctx(0x1000);
        assert!(UserReadSlice::validate(&ctx, USER_SPACE_END + 0x1000, 1).is_err());
    }

    #[test]
    fn read_validate_addr_plus_len_overflows_err() {
        let ctx = test_ctx(0x1000);
        assert!(UserReadSlice::validate(&ctx, u64::MAX - 10, 20).is_err());
    }

    #[test]
    fn read_validate_addr_plus_len_crosses_userspace_end_err() {
        let ctx = test_ctx(0x1000);
        // addr + len straddles USER_SPACE_END.
        let addr = USER_SPACE_END - 10;
        assert!(UserReadSlice::validate(&ctx, addr, 20).is_err());
    }

    #[test]
    fn read_validate_preserves_addr_and_len() {
        let ctx = test_ctx(0x1000);
        let s = UserReadSlice::validate(&ctx, 0x400000, 42).unwrap();
        assert_eq!(s.len(), 42);
        assert!(!s.is_empty());
    }

    #[test]
    fn read_validate_zero_is_empty() {
        let ctx = test_ctx(0x1000);
        let s = UserReadSlice::validate(&ctx, 0x400000, 0).unwrap();
        assert!(s.is_empty());
    }

    // ── UserReadSlice::read_into (length checks — live cr3 page-walk
    //     is covered by the existing read_user_buffer tests) ──

    #[test]
    fn read_into_dst_len_mismatch_err() {
        let ctx = test_ctx(0x1000);
        let s = UserReadSlice::validate(&ctx, 0x400000, 16).unwrap();
        let mut dst = [0u8; 8];
        assert!(s.read_into(&mut dst).is_err());
    }

    #[test]
    fn read_into_dst_too_large_err() {
        let ctx = test_ctx(0x1000);
        let s = UserReadSlice::validate(&ctx, 0x400000, 16).unwrap();
        let mut dst = [0u8; 32];
        assert!(s.read_into(&mut dst).is_err());
    }

    #[test]
    fn read_into_zero_length_ok() {
        let ctx = test_ctx(0x1000);
        let s = UserReadSlice::validate(&ctx, 0x400000, 0).unwrap();
        let mut dst: [u8; 0] = [];
        assert!(s.read_into(&mut dst).is_ok());
    }

    // ── UserWriteSlice::validate ──

    #[test]
    fn write_validate_zero_length_ok_regardless_of_address() {
        let ctx = test_ctx(0x1000);
        assert!(UserWriteSlice::validate(&ctx, 0x400000, 0).is_ok());
        assert!(UserWriteSlice::validate(&ctx, u64::MAX, 0).is_ok());
    }

    #[test]
    fn write_validate_zero_length_ok_even_with_kernel_cr3() {
        let ctx = test_ctx(0);
        assert!(UserWriteSlice::validate(&ctx, 0x400000, 0).is_ok());
    }

    #[test]
    fn write_validate_nonzero_length_with_kernel_cr3_err() {
        let ctx = test_ctx(0);
        assert!(UserWriteSlice::validate(&ctx, 0x400000, 1).is_err());
    }

    #[test]
    fn write_validate_len_over_max_err() {
        let ctx = test_ctx(0x1000);
        assert!(UserWriteSlice::validate(&ctx, 0x400000, MAX_USER_BUFFER + 1).is_err());
    }

    #[test]
    fn write_validate_addr_at_userspace_end_err() {
        let ctx = test_ctx(0x1000);
        assert!(UserWriteSlice::validate(&ctx, USER_SPACE_END, 1).is_err());
    }

    #[test]
    fn write_validate_addr_plus_len_overflows_err() {
        let ctx = test_ctx(0x1000);
        assert!(UserWriteSlice::validate(&ctx, u64::MAX - 10, 20).is_err());
    }

    #[test]
    fn write_validate_preserves_len() {
        let ctx = test_ctx(0x1000);
        let s = UserWriteSlice::validate(&ctx, 0x400000, 100).unwrap();
        assert_eq!(s.len(), 100);
    }

    // ── UserWriteSlice::write_from length checks ──

    #[test]
    fn write_from_src_len_mismatch_err() {
        let ctx = test_ctx(0x1000);
        let s = UserWriteSlice::validate(&ctx, 0x400000, 16).unwrap();
        let src = [0u8; 8];
        assert!(s.write_from(&src).is_err());
    }

    #[test]
    fn write_from_src_too_large_err() {
        let ctx = test_ctx(0x1000);
        let s = UserWriteSlice::validate(&ctx, 0x400000, 16).unwrap();
        let src = [0u8; 32];
        assert!(s.write_from(&src).is_err());
    }

    #[test]
    fn write_from_zero_length_ok() {
        let ctx = test_ctx(0x1000);
        let s = UserWriteSlice::validate(&ctx, 0x400000, 0).unwrap();
        let src: [u8; 0] = [];
        assert!(s.write_from(&src).is_ok());
    }
}
