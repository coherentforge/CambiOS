// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Safe MMIO register access abstraction
//!
//! Wraps volatile reads/writes to memory-mapped I/O regions. All MMIO access
//! in the kernel should go through this module rather than calling
//! `core::ptr::read_volatile`/`write_volatile` directly.
//!
//! # Safety model
//! The unsafe boundary is at construction time: the caller of `new()` must
//! guarantee that `base` points to a valid, mapped MMIO region of sufficient
//! size. Once constructed, all register reads and writes are safe — the type
//! encapsulates the pointer validity invariant.

/// A memory-mapped I/O region with typed 32-bit register access.
///
/// Constructed from a validated base address (e.g., from HHDM mapping or
/// `early_map_mmio`). All subsequent reads/writes are safe because the base
/// address validity is guaranteed at construction time.
#[derive(Clone, Copy)]
pub struct MmioRegion {
    base: usize,
}

impl MmioRegion {
    /// Create a new MMIO region handle.
    ///
    /// # Safety
    /// `base` must be a valid virtual address pointing to a mapped MMIO region.
    /// The region must remain mapped for the lifetime of this handle.
    /// The mapping must use appropriate caching attributes (e.g., uncacheable
    /// for device MMIO).
    #[inline]
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Read a 32-bit register at the given byte offset from the base.
    #[inline]
    pub fn read32(&self, offset: usize) -> u32 {
        // SAFETY: base was validated at construction time. The caller is
        // responsible for providing a valid offset within the MMIO region.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    /// Write a 32-bit value to a register at the given byte offset from the base.
    #[inline]
    pub fn write32(&self, offset: usize, value: u32) {
        // SAFETY: base was validated at construction time. The caller is
        // responsible for providing a valid offset within the MMIO region.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Read a 64-bit register at the given byte offset from the base.
    #[inline]
    pub fn read64(&self, offset: usize) -> u64 {
        // SAFETY: Same as read32.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u64) }
    }

    /// Write a 64-bit value to a register at the given byte offset from the base.
    #[inline]
    pub fn write64(&self, offset: usize, value: u64) {
        // SAFETY: Same as write32.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u64, value) }
    }

    /// Return the base address of this MMIO region.
    #[inline]
    pub const fn base(&self) -> usize {
        self.base
    }
}

// ============================================================================
// Typed register cells (ADR-036)
//
// A `#[repr(C)]` device register block is built from these cells; each cell
// sits at a field offset that IS the hardware register offset. Constructing the
// block from a mapped base is the single `unsafe` boundary (ADR-036 § 3); from
// there every register access is safe, access-class-checked, and value-typed.
// `#[inline(always)]` keeps each access a single volatile load/store, identical
// to the prior hand-rolled `(base + offset)` form (ADR-036 § 2).
//
// The cells wrap `UnsafeCell<T>`, which is load-bearing for soundness: it opts
// out of the `&T`-is-immutable assumption that asynchronous hardware writes to a
// live register would otherwise violate. A plain `#[repr(C)]` field of `T` read
// through `&` would be UB; `UnsafeCell<T>` + `volatile` is what makes it sound.
// ============================================================================

/// Conversion between a register's storage width `T` and a typed value view
/// `F` (e.g. a `bitflags` type). The blanket identity impl covers registers
/// whose value view is just their storage type.
pub trait RegVal<T: Copy>: Copy {
    /// Convert the typed view into the raw value written to the register.
    fn into_raw(self) -> T;
    /// Reconstruct the typed view from a raw value read from the register.
    fn from_raw(raw: T) -> Self;
}

impl<T: Copy> RegVal<T> for T {
    #[inline(always)]
    fn into_raw(self) -> T {
        self
    }
    #[inline(always)]
    fn from_raw(raw: T) -> T {
        raw
    }
}

/// Read-only volatile register cell at a fixed offset in a register block.
#[repr(transparent)]
pub struct ReadOnly<T: Copy> {
    cell: core::cell::UnsafeCell<T>,
}

// SAFETY: This impl asserts only that &-sharing the cell across harts is sound,
// not that accesses are synchronized. The cell guarantees a single untorn
// width-correct volatile access with no compiler reorder/elide/fuse/tear.
// It does NOT provide atomicity, RMW-safety, or happens-before ordering:
// cross-hart correctness on stateful registers is the driver's responsibility
// via architectural set/clear registers, and device-effect ordering via
// explicit barriers (this cell emits none — volatile is not a fence).
// No-tear is contingent on natural alignment, enforced by the register-block
// offset_of! layout asserts, not by this cell.
unsafe impl<T: Copy> Sync for ReadOnly<T> {}

impl<T: Copy> ReadOnly<T> {
    /// Volatile-read the register.
    #[inline(always)]
    pub fn read(&self) -> T {
        // SAFETY: the cell is a field of a register block constructed from a
        // valid mapped MMIO base (ADR-036 § 3); the pointer is valid and
        // aligned for a volatile `T` read.
        unsafe { core::ptr::read_volatile(self.cell.get()) }
    }
}

/// Write-only volatile register cell at a fixed offset in a register block.
#[repr(transparent)]
pub struct WriteOnly<T: Copy> {
    cell: core::cell::UnsafeCell<T>,
}

// SAFETY: see `ReadOnly` - shared MMIO, `UnsafeCell`-backed, volatile access.
unsafe impl<T: Copy> Sync for WriteOnly<T> {}

impl<T: Copy> WriteOnly<T> {
    /// Volatile-write the register.
    #[inline(always)]
    pub fn write(&self, value: T) {
        // SAFETY: as `ReadOnly::read`; valid and aligned for a volatile `T` write.
        unsafe { core::ptr::write_volatile(self.cell.get(), value) }
    }
}

/// Read-write volatile register cell at a fixed offset in a register block.
/// `T` is the access width; `F` the typed value view (default `T`).
#[repr(transparent)]
pub struct ReadWrite<T: Copy, F: RegVal<T> = T> {
    cell: core::cell::UnsafeCell<T>,
    _view: core::marker::PhantomData<F>,
}

// SAFETY: see `ReadOnly` - shared MMIO, `UnsafeCell`-backed, volatile access.
// `PhantomData<F>` is zero-sized and carries no data, so it adds no obligation.
unsafe impl<T: Copy, F: RegVal<T>> Sync for ReadWrite<T, F> {}

impl<T: Copy, F: RegVal<T>> ReadWrite<T, F> {
    /// Volatile-read the register and return its typed value.
    #[inline(always)]
    pub fn read(&self) -> F {
        // SAFETY: as `ReadOnly::read`; valid and aligned for a volatile `T` read.
        F::from_raw(unsafe { core::ptr::read_volatile(self.cell.get()) })
    }

    /// Volatile-write the typed value to the register.
    #[inline(always)]
    pub fn write(&self, value: F) {
        // SAFETY: as `ReadOnly::read`; valid and aligned for a volatile `T` write.
        unsafe { core::ptr::write_volatile(self.cell.get(), value.into_raw()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmio_region_construction() {
        // Verify construction preserves the base address.
        // SAFETY: Test only — we never dereference the pointer.
        let region = unsafe { MmioRegion::new(0xDEAD_0000) };
        assert_eq!(region.base(), 0xDEAD_0000);
    }

    // The cells are tested over a plain backing value (host memory stands in
    // for the MMIO region — the volatile access is a normal load/store there).
    // Access-class enforcement (ReadOnly has no `write`, WriteOnly no `read`)
    // is a compile-time property of the absent methods, not a runtime test.

    #[test]
    fn readonly_reads_backing_value() {
        let r = ReadOnly::<u32> {
            cell: core::cell::UnsafeCell::new(0xDEAD_BEEF),
        };
        assert_eq!(r.read(), 0xDEAD_BEEF);
    }

    #[test]
    fn writeonly_writes_backing_value() {
        let w = WriteOnly::<u32> {
            cell: core::cell::UnsafeCell::new(0),
        };
        w.write(0x1234_5678);
        assert_eq!(w.cell.into_inner(), 0x1234_5678);
    }

    #[test]
    fn readwrite_roundtrips_raw() {
        let rw = ReadWrite::<u32> {
            cell: core::cell::UnsafeCell::new(0xAA),
            _view: core::marker::PhantomData,
        };
        assert_eq!(rw.read(), 0xAA);
        rw.write(0x55);
        assert_eq!(rw.read(), 0x55);
    }

    #[derive(Clone, Copy, PartialEq, Debug)]
    struct TestView(u32);
    impl RegVal<u32> for TestView {
        fn into_raw(self) -> u32 {
            self.0
        }
        fn from_raw(raw: u32) -> Self {
            TestView(raw)
        }
    }

    #[test]
    fn readwrite_typed_view_roundtrips() {
        let rw = ReadWrite::<u32, TestView> {
            cell: core::cell::UnsafeCell::new(0),
            _view: core::marker::PhantomData,
        };
        rw.write(TestView(0xF00D));
        assert_eq!(rw.read(), TestView(0xF00D));
    }
}
