// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors

//! The kernel owns CR0 and CR4 (ADR-040 § 6).
//!
//! Every bit of both registers gets the value the kernel chose, on every
//! CPU, before that CPU loads the kernel's IDT or runs a program. Before
//! this, the kernel ran on whatever the bootloader left (Limine: CR0 =
//! PE ET WP PG, CR4 = PAE): x87 and MMX usable from ring 3 with no state
//! saved across a switch, SMEP and SMAP off, `rdtsc` and `sidt` open to
//! ring 3.
//!
//! The values are computed by pure functions ([`KERNEL_CR0`],
//! [`kernel_cr4`]) from the value found and the CPU's features, so each
//! row of the ADR's table is a host test. [`init_bsp`] and [`init_ap`]
//! are the effects: read CPUID and CR4, write both registers, and on the
//! boot CPU publish the feature set the APs must match and the SMAP flag
//! the trap entry reads ([`super::trap::X86_SMAP_ACTIVE`]).

use core::sync::atomic::{AtomicU8, Ordering};

/// CR0 bits (Intel SDM Vol. 3A § 2.5, Figure 2-7).
pub mod cr0 {
    /// HARDWARE: CR0.PE, bit 0: protected mode.
    pub const PE: u64 = 1 << 0;
    /// HARDWARE: CR0.MP, bit 1: WAIT/FWAIT honours TS.
    pub const MP: u64 = 1 << 1;
    /// HARDWARE: CR0.EM, bit 2: x87 instructions raise #NM, MMX and SSE #UD.
    pub const EM: u64 = 1 << 2;
    /// HARDWARE: CR0.TS, bit 3: the next x87/SSE instruction raises #NM.
    pub const TS: u64 = 1 << 3;
    /// HARDWARE: CR0.ET, bit 4: reserved, reads as 1 on every x86_64 CPU.
    pub const ET: u64 = 1 << 4;
    /// HARDWARE: CR0.NE, bit 5: x87 errors raise #MF, not FERR#.
    pub const NE: u64 = 1 << 5;
    /// HARDWARE: CR0.WP, bit 16: ring 0 honours read-only pages.
    pub const WP: u64 = 1 << 16;
    /// HARDWARE: CR0.AM, bit 18: RFLAGS.AC enables #AC in ring 3.
    pub const AM: u64 = 1 << 18;
    /// HARDWARE: CR0.NW, bit 29: not write-through.
    pub const NW: u64 = 1 << 29;
    /// HARDWARE: CR0.CD, bit 30: cache disable.
    pub const CD: u64 = 1 << 30;
    /// HARDWARE: CR0.PG, bit 31: paging.
    pub const PG: u64 = 1 << 31;
}

/// CR4 bits (Intel SDM Vol. 3A § 2.5, Figure 2-8).
pub mod cr4 {
    /// HARDWARE: CR4.TSD, bit 2: `rdtsc`/`rdtscp` fault outside ring 0.
    pub const TSD: u64 = 1 << 2;
    /// HARDWARE: CR4.PAE, bit 5: PAE paging (required in long mode).
    pub const PAE: u64 = 1 << 5;
    /// HARDWARE: CR4.MCE, bit 6: machine checks raise #MC.
    pub const MCE: u64 = 1 << 6;
    /// HARDWARE: CR4.PGE, bit 7: global pages.
    pub const PGE: u64 = 1 << 7;
    /// HARDWARE: CR4.PCE, bit 8: `rdpmc` allowed outside ring 0.
    pub const PCE: u64 = 1 << 8;
    /// HARDWARE: CR4.OSFXSR, bit 9: SSE and FXSAVE/FXRSTOR enabled.
    pub const OSFXSR: u64 = 1 << 9;
    /// HARDWARE: CR4.OSXMMEXCPT, bit 10: unmasked SIMD exceptions raise #XM.
    pub const OSXMMEXCPT: u64 = 1 << 10;
    /// HARDWARE: CR4.UMIP, bit 11: `sgdt`/`sidt`/`sldt`/`smsw`/`str` fault outside ring 0.
    pub const UMIP: u64 = 1 << 11;
    /// HARDWARE: CR4.LA57, bit 12: 5-level paging.
    pub const LA57: u64 = 1 << 12;
    /// HARDWARE: CR4.FSGSBASE, bit 16: `wrgsbase` and friends allowed in ring 3.
    pub const FSGSBASE: u64 = 1 << 16;
    /// HARDWARE: CR4.PCIDE, bit 17: process-context identifiers in CR3.
    pub const PCIDE: u64 = 1 << 17;
    /// HARDWARE: CR4.OSXSAVE, bit 18: XSAVE and the AVX state enabled.
    pub const OSXSAVE: u64 = 1 << 18;
    /// HARDWARE: CR4.SMEP, bit 20: ring 0 cannot execute user pages.
    pub const SMEP: u64 = 1 << 20;
    /// HARDWARE: CR4.SMAP, bit 21: ring 0 cannot touch user pages unless RFLAGS.AC.
    pub const SMAP: u64 = 1 << 21;
}

/// ARCHITECTURAL: the CR0 every CPU runs with (ADR-040 § 6). Independent of what the
/// bootloader left: paging and protection on (PE, PG), read-only pages
/// honoured in ring 0 (WP), caching on (CD = NW = 0), no alignment-check
/// faults from ring 3 (AM = 0), and EM set so that no x87, MMX or SSE
/// instruction runs anywhere: FP/SIMD register state is not saved across a
/// context switch, so none may exist (ADR-040 § Open Problems names the
/// trigger that clears EM). MP and NE are the values that change wants;
/// with EM set neither has an effect. Every reserved bit is 0.
pub const KERNEL_CR0: u64 = cr0::PE | cr0::MP | cr0::ET | cr0::NE | cr0::EM | cr0::WP | cr0::PG;

/// ARCHITECTURAL: the CR4 bits carried over from the value found rather than chosen:
/// the paging-mode bits must match the page tables already in use
/// (ADR-040 § 6, "checked, not rewritten"). LA57 and PCIDE are carried
/// only in the sense that [`kernel_cr4`] refuses a value with either set.
const CR4_CARRIED: u64 = cr4::PAE | cr4::PGE;

/// ARCHITECTURAL: the CR4 bits every CPU sets regardless of features. Every x86_64 CPU
/// implements machine-check exceptions and FXSR/SSE (the AMD64 baseline),
/// so none of these can make the write fault.
const CR4_ALWAYS: u64 = cr4::MCE | cr4::OSFXSR | cr4::OSXMMEXCPT | cr4::TSD;

/// The CPUID-reported features [`kernel_cr4`] turns on when present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cr4Features {
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
}

impl Cr4Features {
    /// No optional feature: the value on a CPU that reports none.
    pub const NONE: Self = Self { smep: false, smap: false, umip: false };

    /// Decode CPUID leaf 7, subleaf 0: SMEP is EBX bit 7, SMAP EBX bit 20,
    /// UMIP ECX bit 2 (Intel SDM Vol. 2A, CPUID, Table 3-8). A CPU whose
    /// highest basic leaf (CPUID leaf 0, EAX) is below 7 reports none:
    /// Intel CPUs answer an unsupported leaf with the highest basic leaf's
    /// data, so leaf 7's registers mean nothing there.
    pub const fn from_cpuid(max_basic_leaf: u32, leaf7_ebx: u32, leaf7_ecx: u32) -> Self {
        if max_basic_leaf < 7 {
            return Self::NONE;
        }
        Self {
            smep: leaf7_ebx & (1 << 7) != 0,
            smap: leaf7_ebx & (1 << 20) != 0,
            umip: leaf7_ecx & (1 << 2) != 0,
        }
    }

    /// True when this CPU has every feature in `required`.
    pub const fn covers(self, required: Self) -> bool {
        (self.smep || !required.smep) && (self.smap || !required.smap) && (self.umip || !required.umip)
    }

    const fn to_bits(self) -> u8 {
        (self.smep as u8) | ((self.smap as u8) << 1) | ((self.umip as u8) << 2)
    }

    const fn from_bits(bits: u8) -> Self {
        Self { smep: bits & 1 != 0, smap: bits & 2 != 0, umip: bits & 4 != 0 }
    }
}

/// CR4 as found has a paging-mode bit the kernel's page tables and CR3
/// writes do not assume. Each is a typed boot error on the boot CPU
/// ([`crate::boot::BootError`]) and leaves an AP halted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingModeError {
    /// PAE clear: not long mode, which cannot be the case while 64-bit
    /// code runs; a value this far wrong means the read is not CR4.
    PaeClear,
    /// 5-level paging on: the kernel builds 4-level tables.
    La57Set,
    /// PCIDs on: the kernel's CR3 writes assume bits 11:0 are not a PCID.
    PcideSet,
}

impl From<PagingModeError> for crate::boot::BootError {
    fn from(e: PagingModeError) -> Self {
        match e {
            PagingModeError::PaeClear => Self::Cr4PaeClear,
            PagingModeError::La57Set => Self::Cr4La57Set,
            PagingModeError::PcideSet => Self::Cr4PcideSet,
        }
    }
}

/// The CR4 a CPU runs with (ADR-040 § 6), from the value `found` and the
/// feature set `features` (the boot CPU's, on every CPU). Pure.
///
/// Set: PAE (carried; required), PGE (carried), MCE, OSFXSR, OSXMMEXCPT,
/// TSD, and SMEP / SMAP / UMIP when `features` has them. Everything else is
/// 0, including FSGSBASE (a program must not write GS base, § 2), OSXSAVE,
/// PCE, LA57 and PCIDE.
pub const fn kernel_cr4(found: u64, features: Cr4Features) -> Result<u64, PagingModeError> {
    if found & cr4::PAE == 0 {
        return Err(PagingModeError::PaeClear);
    }
    if found & cr4::LA57 != 0 {
        return Err(PagingModeError::La57Set);
    }
    if found & cr4::PCIDE != 0 {
        return Err(PagingModeError::PcideSet);
    }
    let mut value = (found & CR4_CARRIED) | CR4_ALWAYS;
    if features.smep {
        value |= cr4::SMEP;
    }
    if features.smap {
        value |= cr4::SMAP;
    }
    if features.umip {
        value |= cr4::UMIP;
    }
    Ok(value)
}

/// ARCHITECTURAL: the bit set in [`BSP_FEATURES`] once the boot CPU has
/// published; the feature bits ([`Cr4Features::to_bits`]) use bits 0-2.
const PUBLISHED: u8 = 1 << 7;

/// The boot CPU's [`Cr4Features`] (low bits) and [`PUBLISHED`]. Written
/// once by [`init_bsp`] before any AP starts; read by each [`init_ap`].
/// Every CPU runs the boot CPU's set, so [`super::trap::X86_SMAP_ACTIVE`]
/// is true of every CPU that takes a trap through the kernel's IDT.
static BSP_FEATURES: AtomicU8 = AtomicU8::new(0);

/// This CPU's features, from CPUID. CPUID is unprivileged and has no side
/// effects; leaf 0 first, because leaf 7 means nothing on a CPU whose
/// highest basic leaf is below it.
fn this_cpu_features() -> Cr4Features {
    let max_basic_leaf = core::arch::x86_64::__cpuid(0).eax;
    if max_basic_leaf < 7 {
        return Cr4Features::NONE;
    }
    let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
    Cr4Features::from_cpuid(max_basic_leaf, leaf7.ebx, leaf7.ecx)
}

/// Write the computed CR0 and CR4 on this CPU.
///
/// # Safety
/// Ring 0, interrupts disabled, `cr4` from [`kernel_cr4`] with a feature
/// set this CPU reports. The obligations the values place on the rest of
/// the kernel are ADR-040 § 6's: ring 0 never executes x87, MMX or SSE
/// (EM), never touches a user address except through the direct map
/// (SMAP), never executes a user page (SMEP), and keeps RFLAGS.AC clear
/// (every trap entry runs `clac` behind `X86_SMAP_ACTIVE`; `SFMASK` clears
/// AC at syscall entry).
unsafe fn write(cr4: u64) {
    // SAFETY: KERNEL_CR0 keeps PE and PG set (clearing either in long mode
    // would #GP), sets no reserved bit, and only adds restrictions the
    // kernel already meets: no kernel code is x87/MMX/SSE (soft-float
    // target), WP was already set by the bootloader. Caller: ring 0.
    unsafe { x86_64::registers::control::Cr0::write_raw(KERNEL_CR0) };
    // SAFETY: `cr4` keeps PAE (clearing it in long mode would #GP), keeps
    // LA57 and PCIDE as found (both 0, checked by kernel_cr4), and sets
    // SMEP/SMAP/UMIP only where CPUID reports them, so no bit is
    // unsupported. Kernel code runs from kernel pages with AC clear, so
    // SMEP and SMAP take effect without faulting the next instruction.
    unsafe { x86_64::registers::control::Cr4::write_raw(cr4) };
}

/// Take ownership of CR0 and CR4 on the boot CPU, publish its feature set
/// for the APs, and turn the trap entry's `clac` on when SMAP is.
///
/// # Safety
/// Once, on the boot CPU, during single-threaded boot with interrupts
/// disabled, before any AP starts and before any program runs.
pub unsafe fn init_bsp() -> Result<Cr4Features, PagingModeError> {
    let features = this_cpu_features();
    let cr4 = kernel_cr4(x86_64::registers::control::Cr4::read_raw(), features)?;
    // SAFETY: caller guarantees ring 0, boot CPU, interrupts off; `cr4`
    // came from kernel_cr4 with this CPU's own features.
    unsafe { write(cr4) };
    BSP_FEATURES.store(features.to_bits() | PUBLISHED, Ordering::Release);
    if features.smap {
        // After the CR4 write: an entry from ring 0 in between has AC
        // clear already, so skipping `clac` there costs nothing.
        super::trap::X86_SMAP_ACTIVE.store(true, Ordering::Release);
    }
    Ok(features)
}

/// Why an AP did not take the boot CPU's control-register values. The AP
/// stays halted and never signals ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApControlRegisterError {
    /// [`init_bsp`] has not run: a boot-sequencing bug.
    NotPublished,
    /// This CPU's CR4 as found has a paging-mode bit the kernel does not assume.
    PagingMode(PagingModeError),
    /// This CPU lacks a feature the boot CPU turned on. Running it without
    /// would make `X86_SMAP_ACTIVE` false of it (and `clac` #UD), or leave
    /// it with a weaker CR4 than every other CPU.
    FeatureMissing { boot_cpu: Cr4Features, this_cpu: Cr4Features },
}

/// Take ownership of CR0 and CR4 on an AP, with the boot CPU's feature set.
///
/// # Safety
/// Once per AP, on that AP, interrupts disabled, after [`init_bsp`] and
/// before this AP loads the kernel's IDT.
pub unsafe fn init_ap() -> Result<(), ApControlRegisterError> {
    let bits = BSP_FEATURES.load(Ordering::Acquire);
    if bits & PUBLISHED == 0 {
        return Err(ApControlRegisterError::NotPublished);
    }
    let boot_cpu = Cr4Features::from_bits(bits);
    let this_cpu = this_cpu_features();
    if !this_cpu.covers(boot_cpu) {
        return Err(ApControlRegisterError::FeatureMissing { boot_cpu, this_cpu });
    }
    let cr4 = kernel_cr4(x86_64::registers::control::Cr4::read_raw(), boot_cpu)
        .map_err(ApControlRegisterError::PagingMode)?;
    // SAFETY: caller guarantees ring 0, this AP, interrupts off; `cr4`
    // came from kernel_cr4 with a feature set this CPU reports (covers).
    unsafe { write(cr4) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What Limine leaves on QEMU and the Dell 3630: CR4 = PAE.
    const LIMINE_CR4: u64 = cr4::PAE;
    const ALL: Cr4Features = Cr4Features { smep: true, smap: true, umip: true };

    #[test]
    fn cr0_is_the_table() {
        for bit in [cr0::PE, cr0::PG, cr0::WP, cr0::EM, cr0::NE, cr0::MP, cr0::ET] {
            assert_ne!(KERNEL_CR0 & bit, 0, "{bit:#x} must be set");
        }
        for bit in [cr0::TS, cr0::AM, cr0::CD, cr0::NW] {
            assert_eq!(KERNEL_CR0 & bit, 0, "{bit:#x} must be clear");
        }
        // Nothing outside the named bits: every reserved bit is 0.
        let named = cr0::PE | cr0::MP | cr0::EM | cr0::TS | cr0::ET | cr0::NE
            | cr0::WP | cr0::AM | cr0::NW | cr0::CD | cr0::PG;
        assert_eq!(KERNEL_CR0 & !named, 0);
    }

    #[test]
    fn cr4_from_limine_with_every_feature() {
        let v = kernel_cr4(LIMINE_CR4, ALL).unwrap();
        assert_eq!(
            v,
            cr4::PAE | cr4::MCE | cr4::OSFXSR | cr4::OSXMMEXCPT | cr4::TSD
                | cr4::SMEP | cr4::SMAP | cr4::UMIP
        );
    }

    #[test]
    fn cr4_features_only_when_reported() {
        let v = kernel_cr4(LIMINE_CR4, Cr4Features::NONE).unwrap();
        assert_eq!(v & (cr4::SMEP | cr4::SMAP | cr4::UMIP), 0);
        let smap_only = Cr4Features { smep: false, smap: true, umip: false };
        let v = kernel_cr4(LIMINE_CR4, smap_only).unwrap();
        assert_eq!(v & (cr4::SMEP | cr4::SMAP | cr4::UMIP), cr4::SMAP);
    }

    #[test]
    fn cr4_clears_what_ring_3_must_not_have() {
        // A bootloader that left FSGSBASE, OSXSAVE, PCE (and junk) set:
        // all cleared. FSGSBASE would let a program set a kernel-half GS
        // base and break the paranoid entry's test (ADR-040 § 2).
        let found = LIMINE_CR4 | cr4::FSGSBASE | cr4::OSXSAVE | cr4::PCE | (1 << 3) | (1 << 0);
        let v = kernel_cr4(found, ALL).unwrap();
        assert_eq!(v & (cr4::FSGSBASE | cr4::OSXSAVE | cr4::PCE | (1 << 3) | (1 << 0)), 0);
    }

    #[test]
    fn cr4_carries_pge_as_found() {
        assert_ne!(kernel_cr4(LIMINE_CR4 | cr4::PGE, ALL).unwrap() & cr4::PGE, 0);
        assert_eq!(kernel_cr4(LIMINE_CR4, ALL).unwrap() & cr4::PGE, 0);
    }

    #[test]
    fn cr4_refuses_paging_modes_it_does_not_assume() {
        assert_eq!(kernel_cr4(0, ALL), Err(PagingModeError::PaeClear));
        assert_eq!(kernel_cr4(LIMINE_CR4 | cr4::LA57, ALL), Err(PagingModeError::La57Set));
        assert_eq!(kernel_cr4(LIMINE_CR4 | cr4::PCIDE, ALL), Err(PagingModeError::PcideSet));
    }

    #[test]
    fn cpuid_decode() {
        let ebx = (1 << 7) | (1 << 20);
        let ecx = 1 << 2;
        assert_eq!(Cr4Features::from_cpuid(7, ebx, ecx), ALL);
        assert_eq!(Cr4Features::from_cpuid(0x16, ebx, 0), Cr4Features { smep: true, smap: true, umip: false });
        // Highest basic leaf below 7: leaf 7's registers are not leaf 7's.
        assert_eq!(Cr4Features::from_cpuid(6, ebx, ecx), Cr4Features::NONE);
    }

    #[test]
    fn covers_and_bits_round_trip() {
        let smep = Cr4Features { smep: true, smap: false, umip: false };
        assert!(ALL.covers(smep));
        assert!(!smep.covers(ALL));
        assert!(Cr4Features::NONE.covers(Cr4Features::NONE));
        for bits in 0u8..8 {
            let f = Cr4Features::from_bits(bits);
            assert_eq!(f.to_bits(), bits);
        }
        assert_eq!(Cr4Features::from_bits(ALL.to_bits() | PUBLISHED), ALL);
    }
}
