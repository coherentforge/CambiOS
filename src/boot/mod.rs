// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Boot protocol abstraction.
//!
//! The kernel consumes boot-provided hardware information (HHDM offset,
//! memory map, framebuffers, ACPI RSDP, modules) through the
//! `BootInfo` struct in this module. Every adapter for a concrete boot
//! protocol — currently `boot::limine`, planned `boot::cambios` — is
//! responsible for populating a `BootInfo` once at very early boot via
//! [`install`], and the rest of the kernel calls [`info`] to read it.
//!
//! No `limine::*` types (or any other boot-protocol crate types) leak
//! past the adapter. This is the seam camBIOS will plug into when it
//! replaces UEFI + Limine.
//!
//! ## Why this exists
//!
//! Limine is a small, single-maintainer hobby/research bootloader. For
//! the v1 timeline it is a fine choice; long-term, CambiOS plans its
//! own firmware (camBIOS) to address boot quirks across UEFI vendors,
//! ARM SBCs, and RISC-V variants. Routing every boot-info consumer
//! through this abstraction means the eventual swap is a new file in
//! `src/boot/`, not a kernel-wide refactor.
//!
//! ## Lifetime model
//!
//! `BootInfo` is installed once before any consumer reads it. After
//! install it is conceptually `&'static` and read-only. The
//! implementation uses a `OnceBootInfo` cell (UnsafeCell + AtomicBool)
//! to give lock-free `&'static BootInfo` access after init, with a
//! single `unsafe` block guarded by the atomic flag.

pub mod limine;

#[cfg(target_arch = "riscv64")]
pub mod riscv;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Bounds
// ============================================================================

/// SCAFFOLDING: max memory map entries copied from the boot protocol.
/// Why: bounded array for verification + zero-heap-alloc population at
///      pre-heap boot. QEMU reports ~10-15 entries; bare-metal systems
///      can have several dozen depending on firmware fragmentation.
///      128 covers all realistic firmwares with margin.
///      Memory cost: 128 × ~24 B ≈ 3 KiB in `.bss`.
/// Replace when: a real firmware reports >128 entries (extremely
///      unusual; would indicate badly-fragmented memory map worth
///      investigating regardless). See docs/ASSUMPTIONS.md.
pub const MAX_MEMORY_REGIONS: usize = 128;

/// SCAFFOLDING: max framebuffers (= active displays) the boot protocol
/// reports.
/// Why: matches the v1 endgame multi-monitor target from
///      [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md):
///      3+ displays at the design point, with ~2× headroom. Memory
///      cost: 8 × ~40 B ≈ 320 B.
/// Replace when: workstation deployments with >8 active displays
///      (uncommon — even pro multi-monitor rigs rarely exceed 6).
pub const MAX_FRAMEBUFFERS: usize = 8;

/// SCAFFOLDING: max boot modules tracked in BootInfo. Mirrors
/// `MAX_MODULES` in [src/boot_modules.rs] (the runtime registry that
/// the spawn syscall queries).
/// Why: same accounting; BootInfo holds the boot-protocol view, the
///      registry holds the spawnable view.
pub const MAX_BOOT_MODULES: usize = 16;

/// SCAFFOLDING: max virtio-mmio device regions discovered from the boot
/// protocol. RISC-V QEMU virt populates from DTB `/soc/virtio_mmio@*`
/// nodes; x86_64 and AArch64 leave this empty (virtio devices come
/// through PCI enumeration instead).
/// Why: QEMU virt exposes 8 slots by default. v1 endgame virtio
///      workload is blk + net + gpu + input + audio ≈ 5 active devices.
///      16 gives ~3× headroom on v1 and bounded iteration. Memory
///      cost: 16 × 16 B ≈ 256 B. See docs/ASSUMPTIONS.md.
/// Replace when: a QEMU machine config or real silicon exposes >16
///      virtio-mmio regions.
pub const MAX_VIRTIO_MMIO_DEVICES: usize = 16;

/// SCAFFOLDING: max harts enumerated from the boot protocol.
/// Why: the RISC-V DTB lists one `cpu@N` node per hart. v1 CambiOS
///      target hardware is ≤8 cores; workstation-class RISC-V silicon
///      (SiFive P870, T-Head C910) ships ≤4 cores per socket. 8 gives
///      ~2× headroom with bounded iteration and negligible memory
///      cost (64 B). Larger platforms are deferred to the post-v1
///      SMP-scale pass. x86_64 and AArch64 populate hart IDs via
///      Limine's MP response and ignore this bound; RISC-V uses it
///      directly. See docs/ASSUMPTIONS.md.
/// Replace when: targeting a RISC-V platform with > 8 cores.
pub const MAX_HARTS: usize = 8;

/// Maximum bytes captured from a module's path (must match
/// [`crate::boot_modules::MAX_NAME_LEN`]).
pub const MAX_MODULE_NAME_LEN: usize = 64;

// ============================================================================
// Types — kernel-owned, no boot-protocol-crate types leak through these
// ============================================================================

/// A region of physical memory described by the boot protocol.
#[derive(Clone, Copy, Debug)]
pub struct MemoryRegion {
    /// Physical base address (page-aligned in practice).
    pub base: u64,
    /// Length in bytes.
    pub length: u64,
    /// Kind: usable / reserved / ACPI / etc.
    pub kind: MemoryRegionKind,
}

/// Bootloader-reported memory region category.
///
/// Mirrors Limine's `EntryType` set as of crate version 0.5. New boot
/// adapters MUST be able to express these categories or report unknown
/// regions as [`MemoryRegionKind::Unknown`] — the kernel treats Unknown
/// conservatively (skipped by the heap and frame allocator passes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRegionKind {
    Usable,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    BadMemory,
    BootloaderReclaimable,
    ExecutableAndModules,
    Framebuffer,
    /// Boot adapter saw a region category it didn't know how to map.
    /// Inner value preserves the raw boot-protocol code for diagnostics.
    Unknown(u64),
}

impl MemoryRegionKind {
    /// Short human-readable label for boot-time logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usable => "Usable",
            Self::Reserved => "Reserved",
            Self::AcpiReclaimable => "ACPI Reclaim",
            Self::AcpiNvs => "ACPI NVS",
            Self::BadMemory => "Bad",
            Self::BootloaderReclaimable => "Bootloader",
            Self::ExecutableAndModules => "Executable",
            Self::Framebuffer => "Framebuffer",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// A framebuffer surface reported by the boot protocol.
///
/// Captures everything the v1 graphics stack needs:
/// `SYS_MAP_FRAMEBUFFER` will return the geometry (width/height/pitch/
/// bpp) and pixel format (RGB mask sizes/shifts per Limine convention),
/// while the kernel keeps the physical address private.
#[derive(Clone, Copy, Debug)]
pub struct FramebufferInfo {
    pub phys_addr: u64,
    pub width: u32,
    pub height: u32,
    /// Bytes per scanline (may exceed `width * bpp/8` due to alignment).
    pub pitch: u32,
    /// Bits per pixel.
    pub bpp: u16,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
}

impl FramebufferInfo {
    /// Total framebuffer size in bytes (`pitch × height`).
    pub fn size_bytes(&self) -> u64 {
        self.pitch as u64 * self.height as u64
    }
}

/// A boot module reported by the boot protocol.
///
/// `name_len` bytes of `name` are valid (the module's path,
/// pre-stripped of directory and `.elf` suffix by
/// [`crate::boot_modules::strip_module_name`] before insertion).
#[derive(Clone, Copy)]
pub struct ModuleInfo {
    pub phys_addr: u64,
    pub size: u64,
    pub name: [u8; MAX_MODULE_NAME_LEN],
    pub name_len: u8,
}

impl ModuleInfo {
    /// Borrow the valid prefix of the name buffer.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// A virtio-mmio device region reported by the boot protocol.
///
/// On RISC-V the DTB's `/soc/virtio_mmio@*/reg` property gives us the
/// physical base and byte size of the MMIO register file. The device
/// kind (net, blk, …) is not in the DTB — it's in the device's
/// `DeviceID` register at offset 0x008, which the kernel reads after
/// boot to synthesize a PCI-shaped device descriptor for the
/// `SYS_DEVICE_INFO` syscall (see ADR-013 / R-6).
#[derive(Clone, Copy, Debug)]
pub struct VirtioMmioInfo {
    pub phys_base: u64,
    pub size: u64,
}

// ============================================================================
// BootInfo — the aggregated, kernel-owned view
// ============================================================================

/// Aggregated boot-time hardware information.
///
/// Built once at very early boot by the active boot adapter (currently
/// [`limine::populate`]) and then read-only for the kernel's lifetime.
///
/// # Invariants (for formal verification)
///
/// - `memory_region_count <= MAX_MEMORY_REGIONS`
/// - `framebuffer_count <= MAX_FRAMEBUFFERS`
/// - `module_count <= MAX_BOOT_MODULES`
/// - Entries beyond the count are valid memory but their contents are
///   unspecified — accessors slice down to the valid prefix.
pub struct BootInfo {
    /// Higher-half direct map offset. The kernel translates a physical
    /// address `P` into a kernel-readable virtual address by adding
    /// `hhdm_offset`.
    pub hhdm_offset: u64,
    /// ACPI Root System Description Pointer physical address, if the
    /// boot protocol reported one.
    pub rsdp_phys: Option<u64>,

    /// Platform timer base frequency in Hz, when the boot adapter has
    /// authoritative knowledge of it. RISC-V populates from the DTB's
    /// `/cpus/timebase-frequency` property; x86_64 and AArch64 leave
    /// this `None` (x86 calibrates APIC via PIT; AArch64 reads
    /// `CNTFRQ_EL0` directly).
    pub timer_base_frequency_hz: Option<u32>,

    /// Platform-level interrupt controller MMIO range
    /// `(phys_base, size_bytes)`, when the boot adapter has
    /// authoritative knowledge. RISC-V populates from the DTB's
    /// `/soc/plic@*` node's `reg` property; x86_64 and AArch64 leave
    /// this `None` (APIC/IOAPIC and GIC addresses arrive via ACPI /
    /// separate paths).
    pub plic_mmio: Option<(u64, u64)>,

    /// Console IRQ number — the hardware interrupt line the primary
    /// UART signals on. RISC-V populates from the DTB's
    /// `/soc/serial@*/interrupts` property (single-cell encoding on
    /// QEMU virt — source ID into the PLIC). Left `None` on x86_64
    /// (IRQ 4 hardcoded in legacy ISA) and AArch64 (PL011 IRQ from
    /// GIC).
    pub console_irq: Option<u32>,

    /// Hart IDs discovered from the boot protocol. Index 0 is the
    /// boot hart (BSP). RISC-V populates from DTB `/cpus/cpu@N/reg`;
    /// x86_64 and AArch64 leave this `None` — their AP wakeup uses
    /// Limine's MP response directly.
    harts: [Option<u64>; MAX_HARTS],
    hart_count: usize,

    memory_regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    memory_region_count: usize,

    framebuffers: [Option<FramebufferInfo>; MAX_FRAMEBUFFERS],
    framebuffer_count: usize,

    modules: [Option<ModuleInfo>; MAX_BOOT_MODULES],
    module_count: usize,

    /// Virtio-mmio regions discovered by the boot adapter. RISC-V
    /// populates from DTB `/soc/virtio_mmio@*`; x86_64 and AArch64
    /// leave this empty (those targets route virtio through PCI).
    virtio_mmio_devices: [Option<VirtioMmioInfo>; MAX_VIRTIO_MMIO_DEVICES],
    virtio_mmio_count: usize,
}

impl BootInfo {
    /// Empty BootInfo builder. Adapter populates fields then calls
    /// [`install`].
    pub const fn empty() -> Self {
        const ZERO_REGION: MemoryRegion = MemoryRegion {
            base: 0,
            length: 0,
            kind: MemoryRegionKind::Reserved,
        };
        Self {
            hhdm_offset: 0,
            rsdp_phys: None,
            timer_base_frequency_hz: None,
            plic_mmio: None,
            console_irq: None,
            harts: [None; MAX_HARTS],
            hart_count: 0,
            memory_regions: [ZERO_REGION; MAX_MEMORY_REGIONS],
            memory_region_count: 0,
            framebuffers: [None; MAX_FRAMEBUFFERS],
            framebuffer_count: 0,
            modules: [const { None }; MAX_BOOT_MODULES],
            module_count: 0,
            virtio_mmio_devices: [const { None }; MAX_VIRTIO_MMIO_DEVICES],
            virtio_mmio_count: 0,
        }
    }

    /// Append a memory region. Returns false if the table is full.
    pub fn push_memory_region(&mut self, region: MemoryRegion) -> bool {
        if self.memory_region_count >= MAX_MEMORY_REGIONS {
            return false;
        }
        self.memory_regions[self.memory_region_count] = region;
        self.memory_region_count += 1;
        true
    }

    /// Append a framebuffer. Returns false if the table is full.
    pub fn push_framebuffer(&mut self, fb: FramebufferInfo) -> bool {
        if self.framebuffer_count >= MAX_FRAMEBUFFERS {
            return false;
        }
        self.framebuffers[self.framebuffer_count] = Some(fb);
        self.framebuffer_count += 1;
        true
    }

    /// Append a module. Returns false if the table is full.
    pub fn push_module(&mut self, module: ModuleInfo) -> bool {
        if self.module_count >= MAX_BOOT_MODULES {
            return false;
        }
        self.modules[self.module_count] = Some(module);
        self.module_count += 1;
        true
    }

    /// Append a hart ID. Returns false if the table is full.
    pub fn push_hart(&mut self, hart_id: u64) -> bool {
        if self.hart_count >= MAX_HARTS {
            return false;
        }
        self.harts[self.hart_count] = Some(hart_id);
        self.hart_count += 1;
        true
    }

    /// All hart IDs reported by the boot protocol.
    pub fn harts(&self) -> impl Iterator<Item = u64> + '_ {
        self.harts[..self.hart_count]
            .iter()
            .filter_map(|h| *h)
    }

    /// Hart count.
    pub fn hart_count(&self) -> usize {
        self.hart_count
    }

    /// All valid memory regions reported by the boot protocol.
    pub fn memory_regions(&self) -> &[MemoryRegion] {
        &self.memory_regions[..self.memory_region_count]
    }

    /// All valid framebuffers reported by the boot protocol.
    pub fn framebuffers(&self) -> impl Iterator<Item = &FramebufferInfo> {
        self.framebuffers[..self.framebuffer_count]
            .iter()
            .filter_map(|f| f.as_ref())
    }

    /// Convenience: the first framebuffer, if any.
    pub fn primary_framebuffer(&self) -> Option<&FramebufferInfo> {
        self.framebuffers().next()
    }

    /// All valid boot modules reported by the boot protocol.
    pub fn modules(&self) -> impl Iterator<Item = &ModuleInfo> {
        self.modules[..self.module_count]
            .iter()
            .filter_map(|m| m.as_ref())
    }

    /// Module count.
    pub fn module_count(&self) -> usize {
        self.module_count
    }

    /// Append a virtio-mmio region. Returns false if the table is full.
    pub fn push_virtio_mmio(&mut self, info: VirtioMmioInfo) -> bool {
        if self.virtio_mmio_count >= MAX_VIRTIO_MMIO_DEVICES {
            return false;
        }
        self.virtio_mmio_devices[self.virtio_mmio_count] = Some(info);
        self.virtio_mmio_count += 1;
        true
    }

    /// All virtio-mmio regions reported by the boot protocol.
    pub fn virtio_mmio_devices(&self) -> impl Iterator<Item = &VirtioMmioInfo> {
        self.virtio_mmio_devices[..self.virtio_mmio_count]
            .iter()
            .filter_map(|v| v.as_ref())
    }
}

// ============================================================================
// OnceBootInfo — single-init storage for the BootInfo singleton
// ============================================================================

/// One-shot initialized cell holding the kernel's BootInfo singleton.
///
/// Pattern: `UnsafeCell<MaybeUninit<BootInfo>>` plus an `AtomicBool`
/// flag. After `install` succeeds, `get` returns a `&'static BootInfo`
/// without locking. This matches the access pattern (write once at
/// boot, read many times forever) and avoids spinlock overhead on the
/// hot path.
struct OnceBootInfo {
    cell: UnsafeCell<MaybeUninit<BootInfo>>,
    initialized: AtomicBool,
}

// SAFETY: All access to `cell` is gated by `initialized`. The atomic
// uses Acquire/Release ordering so a reader observing
// `initialized == true` also observes the writes that built the
// BootInfo. Single-writer at boot (asserted via swap).
unsafe impl Sync for OnceBootInfo {}

impl OnceBootInfo {
    const fn new() -> Self {
        Self {
            cell: UnsafeCell::new(MaybeUninit::uninit()),
            initialized: AtomicBool::new(false),
        }
    }

    fn install(&self, info: BootInfo) {
        let was_init = self.initialized.swap(true, Ordering::AcqRel);
        assert!(!was_init, "boot::install called twice");
        // SAFETY: The cell pointer comes from &self so is valid for
        // the lifetime of the static; no-one else aliases it (we just
        // CAS-claimed the write slot).
        let cell_ptr = unsafe { &mut *self.cell.get() };
        // SAFETY: `MaybeUninit::write` is safe for a mutable reference
        // to an uninitialized slot; we are the unique initializer.
        cell_ptr.write(info);
    }

    fn get(&self) -> &BootInfo {
        assert!(
            self.initialized.load(Ordering::Acquire),
            "boot::info() called before boot::install"
        );
        // SAFETY: The cell pointer comes from &self so is valid for
        // the lifetime of the static. No writer is active:
        // `initialized == true` was observed via Acquire,
        // synchronizing-with the Release write in `install`, and
        // `install` never re-enters (it panics on second call).
        let cell_ref = unsafe { &*self.cell.get() };
        // SAFETY: `install` wrote a fully-initialized BootInfo before
        // setting `initialized`, so `assume_init_ref` is sound.
        unsafe { cell_ref.assume_init_ref() }
    }
}

static BOOT_INFO: OnceBootInfo = OnceBootInfo::new();

/// Install the populated BootInfo. Called exactly once, by the active
/// boot adapter, at very early boot. Panics if called twice.
pub fn install(info: BootInfo) {
    BOOT_INFO.install(info)
}

/// Access the BootInfo. Panics if called before [`install`]. Returns a
/// `&'static BootInfo` because the cell lives for the lifetime of the
/// kernel.
pub fn info() -> &'static BootInfo {
    BOOT_INFO.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_region() -> MemoryRegion {
        MemoryRegion {
            base: 0x100000,
            length: 0x1000,
            kind: MemoryRegionKind::Usable,
        }
    }

    fn empty_fb() -> FramebufferInfo {
        FramebufferInfo {
            phys_addr: 0xFD00_0000,
            width: 1920,
            height: 1080,
            pitch: 1920 * 4,
            bpp: 32,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
        }
    }

    fn empty_module() -> ModuleInfo {
        let mut name = [0u8; MAX_MODULE_NAME_LEN];
        name[..5].copy_from_slice(b"hello");
        ModuleInfo {
            phys_addr: 0x200000,
            size: 4096,
            name,
            name_len: 5,
        }
    }

    #[test]
    fn test_bootinfo_empty_default() {
        let info = BootInfo::empty();
        assert_eq!(info.hhdm_offset, 0);
        assert!(info.rsdp_phys.is_none());
        assert_eq!(info.memory_regions().len(), 0);
        assert_eq!(info.framebuffers().count(), 0);
        assert_eq!(info.module_count(), 0);
    }

    #[test]
    fn test_bootinfo_push_and_iterate() {
        let mut info = BootInfo::empty();
        assert!(info.push_memory_region(empty_region()));
        assert!(info.push_framebuffer(empty_fb()));
        assert!(info.push_module(empty_module()));

        assert_eq!(info.memory_regions().len(), 1);
        assert_eq!(info.framebuffers().count(), 1);
        assert_eq!(info.modules().count(), 1);
        assert_eq!(info.modules().next().unwrap().name_bytes(), b"hello");
        assert_eq!(info.primary_framebuffer().unwrap().size_bytes(),
                   1920u64 * 4 * 1080);
    }

    #[test]
    fn test_bootinfo_memory_regions_full() {
        let mut info = BootInfo::empty();
        for _ in 0..MAX_MEMORY_REGIONS {
            assert!(info.push_memory_region(empty_region()));
        }
        assert!(!info.push_memory_region(empty_region())); // 129th rejected
        assert_eq!(info.memory_regions().len(), MAX_MEMORY_REGIONS);
    }

    #[test]
    fn test_bootinfo_framebuffers_full() {
        let mut info = BootInfo::empty();
        for _ in 0..MAX_FRAMEBUFFERS {
            assert!(info.push_framebuffer(empty_fb()));
        }
        assert!(!info.push_framebuffer(empty_fb()));
        assert_eq!(info.framebuffers().count(), MAX_FRAMEBUFFERS);
    }

    #[test]
    fn test_bootinfo_modules_full() {
        let mut info = BootInfo::empty();
        for _ in 0..MAX_BOOT_MODULES {
            assert!(info.push_module(empty_module()));
        }
        assert!(!info.push_module(empty_module()));
        assert_eq!(info.module_count(), MAX_BOOT_MODULES);
    }

    #[test]
    fn test_bootinfo_virtio_mmio_push_and_iterate() {
        let mut info = BootInfo::empty();
        assert_eq!(info.virtio_mmio_devices().count(), 0);
        assert!(info.push_virtio_mmio(VirtioMmioInfo {
            phys_base: 0x1000_1000,
            size: 0x200,
        }));
        assert!(info.push_virtio_mmio(VirtioMmioInfo {
            phys_base: 0x1000_2000,
            size: 0x200,
        }));
        let collected: alloc::vec::Vec<_> = info
            .virtio_mmio_devices()
            .map(|v| (v.phys_base, v.size))
            .collect();
        assert_eq!(collected, [(0x1000_1000, 0x200), (0x1000_2000, 0x200)]);
    }

    #[test]
    fn test_bootinfo_virtio_mmio_full() {
        let mut info = BootInfo::empty();
        for _ in 0..MAX_VIRTIO_MMIO_DEVICES {
            assert!(info.push_virtio_mmio(VirtioMmioInfo {
                phys_base: 0x1000_1000,
                size: 0x200,
            }));
        }
        assert!(!info.push_virtio_mmio(VirtioMmioInfo {
            phys_base: 0x1000_1000,
            size: 0x200,
        }));
        assert_eq!(info.virtio_mmio_devices().count(), MAX_VIRTIO_MMIO_DEVICES);
    }

    #[test]
    fn test_memory_region_kind_label() {
        assert_eq!(MemoryRegionKind::Usable.as_str(), "Usable");
        assert_eq!(MemoryRegionKind::Framebuffer.as_str(), "Framebuffer");
        assert_eq!(MemoryRegionKind::Unknown(42).as_str(), "Unknown");
    }

    #[test]
    fn test_framebuffer_size_bytes_with_pitch_padding() {
        // pitch can exceed width*bpp/8 due to alignment; size_bytes
        // must use pitch, not the bare width*bpp/8 product.
        let fb = FramebufferInfo {
            phys_addr: 0xFD00_0000,
            width: 1920,
            height: 1080,
            pitch: 8192, // padded
            bpp: 32,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
        };
        assert_eq!(fb.size_bytes(), 8192u64 * 1080);
    }

    #[test]
    fn test_module_info_name_bytes() {
        let m = empty_module();
        assert_eq!(m.name_bytes(), b"hello");
    }
}
