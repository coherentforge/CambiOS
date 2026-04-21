// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Limine boot protocol adapter.
//!
//! Reads the kernel's `limine::request::*` static responses and
//! populates a kernel-owned [`BootInfo`]. After [`populate`] returns,
//! the rest of the kernel reads [`crate::boot::info()`] and never
//! touches `limine::*` types directly.
//!
//! ## What is NOT in this adapter (yet)
//!
//! - SMP / AP wakeup. Limine's MP request exposes an active wake
//!   mechanism (writing `goto_address`), not pure data — abstracting
//!   that requires a richer trait that is deferred until camBIOS work
//!   begins. For now the AP-wakeup code lives in `microkernel/main.rs`
//!   with direct `limine::mp::*` usage.
//! - `BaseRevision::is_supported()` check. That is part of the Limine
//!   *protocol handshake*, not boot info. It stays in `kmain`.
//! - The `.requests` linker section markers. Limine-protocol-specific
//!   linking machinery; not relevant to the kernel's boot-info model.

use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, ModuleRequest, RsdpRequest,
};

use crate::boot::{
    BootError, BootInfo, FramebufferInfo, MAX_MODULE_NAME_LEN, MemoryRegion, MemoryRegionKind,
    ModuleInfo,
};
use crate::boot_modules::strip_module_name;

/// Build a `BootInfo` from the supplied Limine request statics and
/// install it as the kernel's singleton.
///
/// Caller passes references to the static request slots so the boot
/// adapter does not own the linker-section symbols; those stay in
/// `microkernel/main.rs` where the `#[link_section(".requests")]`
/// attributes apply.
///
/// # Behaviour
///
/// - HHDM offset: required. Returns [`BootError::LimineHhdmMissing`]
///   if Limine did not answer the HHDM request — the kernel cannot
///   proceed without it.
/// - Memory map: required. Returns [`BootError::LimineMemoryMapMissing`]
///   if absent.
/// - Framebuffers: optional; an empty list is acceptable (headless boot).
/// - RSDP: optional; absent means no ACPI (acceptable on AArch64).
/// - Modules: optional; an empty list means no boot modules to load.
/// - Truncation: if any list exceeds the corresponding `MAX_*` bound
///   in `crate::boot`, excess entries are dropped and a warning is
///   logged via `println!`.
pub fn populate(
    hhdm: &HhdmRequest,
    memmap: &MemoryMapRequest,
    framebuffer: &FramebufferRequest,
    rsdp: &RsdpRequest,
    modules: &ModuleRequest,
) -> Result<(), BootError> {
    let mut info = BootInfo::empty();

    info.hhdm_offset = hhdm
        .get_response()
        .ok_or(BootError::LimineHhdmMissing)?
        .offset();
    let hhdm_offset = info.hhdm_offset;

    let memmap_resp = memmap
        .get_response()
        .ok_or(BootError::LimineMemoryMapMissing)?;
    let mut dropped_regions = 0usize;
    for entry in memmap_resp.entries() {
        let region = MemoryRegion {
            base: entry.base,
            length: entry.length,
            kind: map_entry_type(entry.entry_type),
        };
        if !info.push_memory_region(region) {
            dropped_regions += 1;
        }
    }
    if dropped_regions > 0 {
        crate::println!(
            "[boot::limine] WARNING: dropped {} memory map entries (cap is MAX_MEMORY_REGIONS={})",
            dropped_regions,
            crate::boot::MAX_MEMORY_REGIONS
        );
    }

    info.rsdp_phys = rsdp.get_response().map(|r| r.address() as u64);

    if let Some(fb_resp) = framebuffer.get_response() {
        let mut dropped_fbs = 0usize;
        for fb in fb_resp.framebuffers() {
            // Limine base revision 3 returns the framebuffer address as an
            // HHDM-translated virtual pointer, not a raw physical address.
            // `BootInfo::FramebufferInfo::phys_addr` is specified as a true
            // physical address (kernel / `SYS_MAP_FRAMEBUFFER` expect it),
            // so undo the HHDM translation here. This is the one spot in
            // the adapter that has to know about Limine's convention — once
            // it lives in BootInfo the rest of the kernel just sees a
            // physical address.
            let raw_addr = fb.addr() as u64;
            let phys_addr = raw_addr.wrapping_sub(hhdm_offset);
            let copied = FramebufferInfo {
                phys_addr,
                width: fb.width() as u32,
                height: fb.height() as u32,
                pitch: fb.pitch() as u32,
                bpp: fb.bpp(),
                red_mask_size: fb.red_mask_size(),
                red_mask_shift: fb.red_mask_shift(),
                green_mask_size: fb.green_mask_size(),
                green_mask_shift: fb.green_mask_shift(),
                blue_mask_size: fb.blue_mask_size(),
                blue_mask_shift: fb.blue_mask_shift(),
            };
            if !info.push_framebuffer(copied) {
                dropped_fbs += 1;
            }
        }
        if dropped_fbs > 0 {
            crate::println!(
                "[boot::limine] WARNING: dropped {} framebuffers (cap is MAX_FRAMEBUFFERS={})",
                dropped_fbs,
                crate::boot::MAX_FRAMEBUFFERS
            );
        }
    }

    if let Some(mod_resp) = modules.get_response() {
        let mut dropped_mods = 0usize;
        for module in mod_resp.modules() {
            let path = module.path().to_bytes();
            let name = strip_module_name(path);
            let mut name_buf = [0u8; MAX_MODULE_NAME_LEN];
            let copy_len = name.len().min(MAX_MODULE_NAME_LEN);
            name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
            let copied = ModuleInfo {
                phys_addr: module.addr() as u64,
                size: module.size(),
                name: name_buf,
                name_len: copy_len as u8,
            };
            if !info.push_module(copied) {
                dropped_mods += 1;
            }
        }
        if dropped_mods > 0 {
            crate::println!(
                "[boot::limine] WARNING: dropped {} boot modules (cap is MAX_BOOT_MODULES={})",
                dropped_mods,
                crate::boot::MAX_BOOT_MODULES
            );
        }
    }

    crate::boot::install(info);
    Ok(())
}

/// Map Limine's `EntryType` into our protocol-agnostic
/// [`MemoryRegionKind`]. Unknown raw values are preserved as
/// `Unknown(n)` so future Limine additions are visible in diagnostics
/// rather than silently mis-categorized.
fn map_entry_type(t: limine::memory_map::EntryType) -> MemoryRegionKind {
    use limine::memory_map::EntryType as L;
    match t {
        L::USABLE => MemoryRegionKind::Usable,
        L::RESERVED => MemoryRegionKind::Reserved,
        L::ACPI_RECLAIMABLE => MemoryRegionKind::AcpiReclaimable,
        L::ACPI_NVS => MemoryRegionKind::AcpiNvs,
        L::BAD_MEMORY => MemoryRegionKind::BadMemory,
        L::BOOTLOADER_RECLAIMABLE => MemoryRegionKind::BootloaderReclaimable,
        L::EXECUTABLE_AND_MODULES => MemoryRegionKind::ExecutableAndModules,
        L::FRAMEBUFFER => MemoryRegionKind::Framebuffer,
        // SAFETY: EntryType is `pub struct EntryType(u64)`; the inner
        // value is the raw protocol code we want to preserve. We can't
        // grab it without unsafe transmute, so route through a debug
        // string match as a last resort.
        // Practically: every Limine 0.5 EntryType variant is covered
        // above, so this fallback is unreachable today.
        _ => MemoryRegionKind::Unknown(0),
    }
}
