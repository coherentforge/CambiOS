// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Typed user-buffer slices for syscall-boundary validation.
//!
//! Implements the types decided in [ADR-020](../../../docs/adr/020-typed-user-buffer-slices-at-syscall-boundary.md).
//! `UserReadSlice<'ctx>` and `UserWriteSlice<'ctx>` replace the raw
//! `(user_addr: u64, len: usize)` pair that flows through syscall
//! handlers. A slice is a unitary typed value carrying:
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
//! - **At use (`read_into` / `write_from`)**: per-page page-table
//!   walk via the module-private `read_user_buffer` /
//!   `write_user_buffer` helpers below. Can still fail if a page
//!   is unmapped at the moment of copy.
//!
//! # Phase 020.C (this commit)
//!
//! The underlying `read_user_buffer` / `write_user_buffer` helpers
//! that were `pub(super)` shims in dispatcher.rs during Phases B.x
//! have moved here as module-private functions. Handler code in
//! sibling modules (dispatcher.rs) can no longer call them
//! directly — the typed slices are the only reachable path for
//! user-pointer validation. Constants `MAX_USER_BUFFER` and
//! `USER_SPACE_END` remain `pub(super)` because a few handlers
//! still use them as pre-validate guards (redundant-but-cheap
//! defense-in-depth alongside `UserSlice::validate`).
//!
//! Phase 020.D adds compile-fail tests asserting the lifetime and
//! direction invariants.

use super::SyscallError;
use super::dispatcher::SyscallContext;

// ============================================================================
// Bounds — shared with sibling modules via pub(super).
// ============================================================================

/// SCAFFOLDING: maximum user buffer size for a single syscall (4 KiB).
/// Why: bounds `copy_from_user_pages` / `copy_to_user_pages`; safety
///      net against accidentally mapping huge ranges through the
///      page-table-walk helpers.
/// Replace when: a user-space service needs to read or write > 4 KiB
///      in one syscall and gets a confusing failure at exactly the
///      boundary. Channels (ADR-005) are the long-term answer for
///      bulk data; until then this needs to grow on demand. See
///      docs/ASSUMPTIONS.md.
pub(super) const MAX_USER_BUFFER: usize = 4096;

/// HARDWARE: canonical user-space address ceiling.
/// x86_64: lower-half canonical addresses end at bit 47
/// (Intel SDM Vol 3 §3.3.7.1).
/// AArch64 / RISC-V: TTBR0 / Sv48 cover 0..2^48 with T0SZ=16;
/// the 0x0001_0000_0000_0000 value uses the full 48-bit range.
#[cfg(target_arch = "x86_64")]
pub(super) const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
/// HARDWARE: see `USER_SPACE_END` above — 48-bit VA variant.
#[cfg(not(target_arch = "x86_64"))]
pub(super) const USER_SPACE_END: u64 = 0x0001_0000_0000_0000;

// ============================================================================
// Private page-walk helpers
// ============================================================================
//
// The page-traversal logic (bounds, page-boundary chunking, partial-failure
// handling) is in `copy_from_user_pages` / `copy_to_user_pages` — generic
// over a `translate` closure (vaddr → phys) and a `read_phys` / `write_phys`
// closure (phys, slice → copy). This shape lets host tests exercise the
// traversal without touching `crate::memory::paging` or HHDM.
//
// `read_user_buffer` / `write_user_buffer` wire the closures to the live
// page-table walk + HHDM deref. Both are module-private after Phase 020.C:
// the typed slices above are the only reachable path.

/// Generic copy from a user-space virtual range into a kernel buffer.
///
/// `translate(vaddr) -> Option<phys>` returns the full physical address
/// (page-base + offset) for `vaddr`, or `None` if unmapped.
/// `read_phys(phys, dst)` copies `dst.len()` bytes starting at `phys`
/// into `dst`. The caller guarantees `dst.len()` does not cross a page
/// boundary.
fn copy_from_user_pages<T, R>(
    translate: T,
    read_phys: R,
    user_addr: u64,
    len: usize,
    dst: &mut [u8],
) -> Result<usize, SyscallError>
where
    T: Fn(u64) -> Option<u64>,
    R: Fn(u64, &mut [u8]),
{
    if len == 0 {
        return Ok(0);
    }
    if len > dst.len() || len > MAX_USER_BUFFER {
        return Err(SyscallError::InvalidArg);
    }
    if user_addr >= USER_SPACE_END || user_addr.checked_add(len as u64).is_none() {
        return Err(SyscallError::InvalidArg);
    }
    if user_addr + len as u64 > USER_SPACE_END {
        return Err(SyscallError::InvalidArg);
    }

    let mut copied = 0usize;
    while copied < len {
        let vaddr = user_addr + copied as u64;
        let page_offset = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(len - copied, 4096 - page_offset);

        match translate(vaddr) {
            Some(phys) => {
                read_phys(phys, &mut dst[copied..copied + chunk]);
                copied += chunk;
            }
            None => return Err(SyscallError::InvalidArg),
        }
    }

    Ok(copied)
}

/// Generic copy from a kernel buffer into a user-space virtual range.
/// Mirror of `copy_from_user_pages`; `write_phys(phys, src)` writes `src`
/// at `phys`. Caller guarantees no-cross-page-boundary on `src.len()`.
fn copy_to_user_pages<T, W>(
    translate: T,
    write_phys: W,
    user_addr: u64,
    src: &[u8],
) -> Result<usize, SyscallError>
where
    T: Fn(u64) -> Option<u64>,
    W: Fn(u64, &[u8]),
{
    let len = src.len();
    if len == 0 {
        return Ok(0);
    }
    if len > MAX_USER_BUFFER {
        return Err(SyscallError::InvalidArg);
    }
    if user_addr >= USER_SPACE_END || user_addr.checked_add(len as u64).is_none() {
        return Err(SyscallError::InvalidArg);
    }
    if user_addr + len as u64 > USER_SPACE_END {
        return Err(SyscallError::InvalidArg);
    }

    let mut written = 0usize;
    while written < len {
        let vaddr = user_addr + written as u64;
        let page_offset = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(len - written, 4096 - page_offset);

        match translate(vaddr) {
            Some(phys) => {
                write_phys(phys, &src[written..written + chunk]);
                written += chunk;
            }
            None => return Err(SyscallError::InvalidArg),
        }
    }

    Ok(written)
}

/// Read bytes from a user-space virtual address into a kernel buffer.
///
/// Module-private production wrapper: walks the process page table (CR3)
/// to translate each page the buffer spans, then reads via HHDM.
/// Returns the number of bytes copied. `cr3 == 0` yields a translator
/// that always returns `None`, so the first byte fails with `InvalidArg`.
///
/// # Safety contract
/// `cr3` must be a valid page-table root physical address for the calling
/// process (PML4 on x86_64, L0 on AArch64) or 0. Called only from
/// `UserReadSlice::read_into` which has already validated `(addr, len)`.
fn read_user_buffer(
    cr3: u64,
    user_addr: u64,
    len: usize,
    dst: &mut [u8],
) -> Result<usize, SyscallError> {
    let hhdm = crate::hhdm_offset();
    copy_from_user_pages(
        |vaddr| {
            if cr3 == 0 {
                return None;
            }
            // SAFETY: cr3 is the process's page-table root.
            // page_table_from_cr3 builds a temporary OffsetPageTable via HHDM;
            // translate performs a read-only walk.
            unsafe {
                let pt = crate::memory::paging::page_table_from_cr3(cr3);
                crate::memory::paging::translate(&pt, vaddr)
            }
        },
        |phys, dst_chunk| {
            // SAFETY: phys is from a successful page-table walk (page is mapped).
            // hhdm + phys is a valid kernel virtual address. dst_chunk.len() is
            // bounded by the chunk math in copy_from_user_pages — never crosses
            // a page boundary.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (phys + hhdm) as *const u8,
                    dst_chunk.as_mut_ptr(),
                    dst_chunk.len(),
                );
            }
        },
        user_addr,
        len,
        dst,
    )
}

/// Write bytes from a kernel buffer into a user-space virtual address.
///
/// Module-private production wrapper. Mirror of `read_user_buffer`.
/// Target pages must be mapped writable in the process address space
/// (caller's responsibility via VMA tracker / page-table flags).
fn write_user_buffer(cr3: u64, user_addr: u64, src: &[u8]) -> Result<usize, SyscallError> {
    let hhdm = crate::hhdm_offset();
    copy_to_user_pages(
        |vaddr| {
            if cr3 == 0 {
                return None;
            }
            // SAFETY: same as read_user_buffer — cr3 is valid; walk is read-only.
            unsafe {
                let pt = crate::memory::paging::page_table_from_cr3(cr3);
                crate::memory::paging::translate(&pt, vaddr)
            }
        },
        |phys, src_chunk| {
            // SAFETY: phys is mapped; hhdm + phys is kernel-writable; the page
            // must be RW (caller guarantees via VMA tracker / page-table flags).
            // src_chunk.len() does not cross a page boundary.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src_chunk.as_ptr(),
                    (phys + hhdm) as *mut u8,
                    src_chunk.len(),
                );
            }
        },
        user_addr,
        src,
    )
}

// ============================================================================
// Typed slices
// ============================================================================

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
    /// Zero-length slices validate unconditionally and read as no-ops.
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

    // ── UserReadSlice::read_into (length checks) ──

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

    // ========================================================================
    // Phase 020.C relocations: early-exit guards for the underlying helpers,
    // moved here from dispatcher.rs when read_user_buffer / write_user_buffer
    // became module-private. These cover paths that fire before any page-
    // table walk is attempted.
    // ========================================================================

    // ---- read_user_buffer early-exit guards --------------------------------

    #[test]
    fn read_user_buffer_len_zero_short_circuits() {
        // cr3=0 would normally fail; len=0 returns Ok(0) first.
        let mut dst = [0u8; 16];
        assert_eq!(read_user_buffer(0, 0x1000, 0, &mut dst), Ok(0));
    }

    #[test]
    fn read_user_buffer_len_exceeds_dst_capacity_invalid() {
        let mut dst = [0u8; 16];
        assert_eq!(
            read_user_buffer(0xDEAD_0000, 0x1000, 17, &mut dst),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn read_user_buffer_len_exceeds_max_buffer_invalid() {
        let mut dst = [0u8; MAX_USER_BUFFER + 16];
        assert_eq!(
            read_user_buffer(0xDEAD_0000, 0x1000, MAX_USER_BUFFER + 1, &mut dst),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn read_user_buffer_addr_at_userspace_end_invalid() {
        let mut dst = [0u8; 16];
        assert_eq!(
            read_user_buffer(0xDEAD_0000, USER_SPACE_END, 1, &mut dst),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn read_user_buffer_addr_overflow_invalid() {
        let mut dst = [0u8; 16];
        // user_addr + len wraps past u64::MAX.
        assert_eq!(
            read_user_buffer(0xDEAD_0000, u64::MAX, 16, &mut dst),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn read_user_buffer_addr_crosses_userspace_end_invalid() {
        let mut dst = [0u8; 16];
        // start sits below USER_SPACE_END but [start, start+len) crosses it.
        let start = USER_SPACE_END - 8;
        assert_eq!(
            read_user_buffer(0xDEAD_0000, start, 16, &mut dst),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn read_user_buffer_cr3_zero_with_nonzero_len_invalid() {
        let mut dst = [0u8; 16];
        // All upstream guards pass; cr3=0 is the failure.
        assert_eq!(
            read_user_buffer(0, 0x1000, 16, &mut dst),
            Err(SyscallError::InvalidArg),
        );
    }

    // ---- write_user_buffer early-exit guards -------------------------------

    #[test]
    fn write_user_buffer_len_zero_short_circuits() {
        let src: [u8; 0] = [];
        assert_eq!(write_user_buffer(0, 0x1000, &src), Ok(0));
    }

    #[test]
    fn write_user_buffer_len_exceeds_max_buffer_invalid() {
        let src = [0u8; MAX_USER_BUFFER + 1];
        assert_eq!(
            write_user_buffer(0xDEAD_0000, 0x1000, &src),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn write_user_buffer_addr_at_userspace_end_invalid() {
        let src = [0u8; 1];
        assert_eq!(
            write_user_buffer(0xDEAD_0000, USER_SPACE_END, &src),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn write_user_buffer_addr_overflow_invalid() {
        let src = [0u8; 16];
        assert_eq!(
            write_user_buffer(0xDEAD_0000, u64::MAX, &src),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn write_user_buffer_addr_crosses_userspace_end_invalid() {
        let src = [0u8; 16];
        let start = USER_SPACE_END - 8;
        assert_eq!(
            write_user_buffer(0xDEAD_0000, start, &src),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn write_user_buffer_cr3_zero_with_nonzero_len_invalid() {
        let src = [0u8; 16];
        assert_eq!(
            write_user_buffer(0, 0x1000, &src),
            Err(SyscallError::InvalidArg),
        );
    }

    // ========================================================================
    // Multi-page traversal — copy_from_user_pages / copy_to_user_pages
    //
    // Drives page-boundary chunking, partial-failure handling, and translate-
    // call accounting inside the generic workers. A `FakeSpace` backs both
    // the translator and the read/write_phys closures, using identity
    // translation (vaddr == phys) so test reasoning matches the assertions:
    // "writes at vaddr 0x1500" lands at "page 0x1000 offset 0x500".
    // Relocated from dispatcher.rs in Phase 020.C.
    // ========================================================================

    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Test fixture: a page table where mapped pages live in a HashMap and
    /// translate uses identity (returns the same vaddr as phys). RefCell
    /// is required because write_phys needs interior mutability while the
    /// closure is borrowed for the call.
    struct FakeSpace {
        pages: RefCell<HashMap<u64, [u8; 4096]>>,
        translate_calls: RefCell<Vec<u64>>,
    }

    impl FakeSpace {
        fn new() -> Self {
            FakeSpace {
                pages: RefCell::new(HashMap::new()),
                translate_calls: RefCell::new(Vec::new()),
            }
        }

        fn map(&self, page_base: u64, fill: impl Fn(usize) -> u8) {
            assert_eq!(page_base & 0xFFF, 0, "page_base must be 4 KiB aligned");
            let mut p = [0u8; 4096];
            for (i, slot) in p.iter_mut().enumerate() {
                *slot = fill(i);
            }
            self.pages.borrow_mut().insert(page_base, p);
        }

        fn page(&self, page_base: u64) -> [u8; 4096] {
            *self.pages.borrow().get(&page_base).expect("page not mapped")
        }

        fn translate_count(&self) -> usize {
            self.translate_calls.borrow().len()
        }

        fn translator(&self) -> impl Fn(u64) -> Option<u64> + '_ {
            |v: u64| {
                self.translate_calls.borrow_mut().push(v);
                let base = v & !0xFFF;
                if self.pages.borrow().contains_key(&base) {
                    Some(v)
                } else {
                    None
                }
            }
        }

        fn reader(&self) -> impl Fn(u64, &mut [u8]) + '_ {
            |phys: u64, dst: &mut [u8]| {
                let base = phys & !0xFFF;
                let off = (phys & 0xFFF) as usize;
                let pages = self.pages.borrow();
                let page = pages.get(&base).expect("read_phys: page not mapped");
                dst.copy_from_slice(&page[off..off + dst.len()]);
            }
        }

        fn writer(&self) -> impl Fn(u64, &[u8]) + '_ {
            |phys: u64, src: &[u8]| {
                let base = phys & !0xFFF;
                let off = (phys & 0xFFF) as usize;
                let mut pages = self.pages.borrow_mut();
                let page = pages.get_mut(&base).expect("write_phys: page not mapped");
                page[off..off + src.len()].copy_from_slice(src);
            }
        }
    }

    // ---- copy_from_user_pages: single-page reads ---------------------------

    #[test]
    fn copy_from_pages_single_page_full_read() {
        let space = FakeSpace::new();
        space.map(0x1000, |i| (i & 0xFF) as u8);

        let mut dst = [0u8; 4096];
        let result = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1000, 4096, &mut dst,
        );
        assert_eq!(result, Ok(4096));
        for i in 0..4096 {
            assert_eq!(dst[i], (i & 0xFF) as u8, "byte {} mismatch", i);
        }
    }

    #[test]
    fn copy_from_pages_single_page_with_offset() {
        let space = FakeSpace::new();
        space.map(0x1000, |i| (i & 0xFF) as u8);

        let mut dst = [0u8; 256];
        // Read 256 bytes starting at vaddr 0x1500 → page offset 0x500..0x600.
        let result = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1500, 256, &mut dst,
        );
        assert_eq!(result, Ok(256));
        for i in 0..256 {
            assert_eq!(dst[i], ((0x500 + i) & 0xFF) as u8);
        }
    }

    // ---- copy_from_user_pages: multi-page boundary crossing ----------------

    #[test]
    fn copy_from_pages_two_pages_at_boundary() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0xAA);
        space.map(0x2000, |_| 0xBB);

        let mut dst = [0u8; 512];
        // Start 256 bytes from end of page 0x1000 → 256 bytes there + 256 in page 0x2000.
        let result = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1F00, 512, &mut dst,
        );
        assert_eq!(result, Ok(512));
        for i in 0..256 {
            assert_eq!(dst[i], 0xAA, "first half byte {}", i);
        }
        for i in 256..512 {
            assert_eq!(dst[i], 0xBB, "second half byte {}", i);
        }
    }

    #[test]
    fn copy_from_pages_max_buffer_straddles_two_pages() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0x11);
        space.map(0x2000, |_| 0x22);

        let mut dst = [0u8; 4096];
        // Start at 0x1080 → 0x1000 page contributes 0xF80 bytes (3968),
        // 0x2000 page contributes 0x80 bytes (128). Total 4096.
        let result = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1080, 4096, &mut dst,
        );
        assert_eq!(result, Ok(4096));
        for i in 0..3968 {
            assert_eq!(dst[i], 0x11);
        }
        for i in 3968..4096 {
            assert_eq!(dst[i], 0x22);
        }
    }

    #[test]
    fn copy_from_pages_one_byte_at_end_of_page() {
        let space = FakeSpace::new();
        space.map(0x1000, |i| if i == 0xFFF { 0x42 } else { 0 });

        let mut dst = [0u8; 1];
        let result = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1FFF, 1, &mut dst,
        );
        assert_eq!(result, Ok(1));
        assert_eq!(dst[0], 0x42);
    }

    #[test]
    fn copy_from_pages_two_bytes_across_page_boundary() {
        let space = FakeSpace::new();
        space.map(0x1000, |i| if i == 0xFFF { 0xAA } else { 0 });
        space.map(0x2000, |i| if i == 0 { 0xBB } else { 0 });

        let mut dst = [0u8; 2];
        let result = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1FFF, 2, &mut dst,
        );
        assert_eq!(result, Ok(2));
        assert_eq!(dst, [0xAA, 0xBB]);
    }

    // ---- copy_from_user_pages: unmapped pages ------------------------------

    #[test]
    fn copy_from_pages_first_page_unmapped_returns_invalid() {
        let space = FakeSpace::new();
        // No pages mapped.

        let mut dst = [0u8; 64];
        let result = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1000, 64, &mut dst,
        );
        assert_eq!(result, Err(SyscallError::InvalidArg));
        // dst is untouched (all zero).
        assert_eq!(dst, [0u8; 64]);
    }

    #[test]
    fn copy_from_pages_second_page_unmapped_returns_invalid_partial_read_visible() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0xAA);
        // Page 0x2000 intentionally unmapped.

        let mut dst = [0u8; 512];
        let result = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1F00, 512, &mut dst,
        );
        assert_eq!(result, Err(SyscallError::InvalidArg));
        // First 256 bytes (page 0x1000) WERE copied before the second-page
        // lookup failed. This documents the partial-read failure mode —
        // callers must not trust dst contents on error.
        for i in 0..256 {
            assert_eq!(dst[i], 0xAA, "first chunk should be present");
        }
        for i in 256..512 {
            assert_eq!(dst[i], 0, "second chunk untouched");
        }
    }

    // ---- copy_from_user_pages: translate call accounting -------------------

    #[test]
    fn copy_from_pages_translate_called_once_per_page() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0);
        space.map(0x2000, |_| 0);

        let mut dst = [0u8; 512];
        let _ = copy_from_user_pages(
            space.translator(), space.reader(),
            0x1F00, 512, &mut dst,
        );
        // Expect exactly two translates — one per page touched.
        assert_eq!(space.translate_count(), 2);
    }

    // ---- copy_to_user_pages: writes ----------------------------------------

    #[test]
    fn copy_to_pages_single_page_full_write() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0);

        let src: [u8; 4096] = core::array::from_fn(|i| (i & 0xFF) as u8);
        let result = copy_to_user_pages(
            space.translator(), space.writer(),
            0x1000, &src,
        );
        assert_eq!(result, Ok(4096));
        let page = space.page(0x1000);
        for i in 0..4096 {
            assert_eq!(page[i], (i & 0xFF) as u8);
        }
    }

    #[test]
    fn copy_to_pages_two_pages_at_boundary() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0);
        space.map(0x2000, |_| 0);

        let src = [0xCC; 512];
        let result = copy_to_user_pages(
            space.translator(), space.writer(),
            0x1F00, &src,
        );
        assert_eq!(result, Ok(512));
        let p1 = space.page(0x1000);
        let p2 = space.page(0x2000);
        // Page 0x1000 has the last 256 bytes set to 0xCC.
        for i in 0..0xF00 {
            assert_eq!(p1[i], 0, "page1 prefix untouched at {}", i);
        }
        for i in 0xF00..0x1000 {
            assert_eq!(p1[i], 0xCC);
        }
        // Page 0x2000 has the first 256 bytes set to 0xCC.
        for i in 0..256 {
            assert_eq!(p2[i], 0xCC);
        }
        for i in 256..4096 {
            assert_eq!(p2[i], 0);
        }
    }

    #[test]
    fn copy_to_pages_first_page_unmapped_no_write() {
        let space = FakeSpace::new();
        // No pages mapped — first translate fails immediately.

        let src = [0xFF; 64];
        let result = copy_to_user_pages(
            space.translator(), space.writer(),
            0x1000, &src,
        );
        assert_eq!(result, Err(SyscallError::InvalidArg));
        // No pages exist, so nothing to inspect — but writer was never called
        // (it would have panicked on missing page). Translate was called once.
        assert_eq!(space.translate_count(), 1);
    }

    #[test]
    fn copy_to_pages_second_page_unmapped_partial_write_visible() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0);
        // Page 0x2000 intentionally unmapped.

        let src = [0xDD; 512];
        let result = copy_to_user_pages(
            space.translator(), space.writer(),
            0x1F00, &src,
        );
        assert_eq!(result, Err(SyscallError::InvalidArg));
        // Page 0x1000's last 256 bytes WERE written before second-page
        // translate failed. Documents the partial-write failure mode —
        // callers cannot assume atomicity.
        let p1 = space.page(0x1000);
        for i in 0xF00..0x1000 {
            assert_eq!(p1[i], 0xDD, "first chunk write should be present");
        }
    }

    #[test]
    fn copy_to_pages_one_byte_at_end_of_page() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0);

        let src = [0x99; 1];
        let result = copy_to_user_pages(
            space.translator(), space.writer(),
            0x1FFF, &src,
        );
        assert_eq!(result, Ok(1));
        let p = space.page(0x1000);
        assert_eq!(p[0xFFF], 0x99);
        for i in 0..0xFFF {
            assert_eq!(p[i], 0);
        }
    }

    #[test]
    fn copy_to_pages_two_bytes_across_page_boundary() {
        let space = FakeSpace::new();
        space.map(0x1000, |_| 0);
        space.map(0x2000, |_| 0);

        let src = [0xAA, 0xBB];
        let result = copy_to_user_pages(
            space.translator(), space.writer(),
            0x1FFF, &src,
        );
        assert_eq!(result, Ok(2));
        assert_eq!(space.page(0x1000)[0xFFF], 0xAA);
        assert_eq!(space.page(0x2000)[0], 0xBB);
    }
}
