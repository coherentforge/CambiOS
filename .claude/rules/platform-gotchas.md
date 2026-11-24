---
paths:
  - "src/**/*"
  - "user/i219-net/**"
  - "user/nvme/**"
  - "user/scanout-limine/**"
  - "user/scanout-virtio-gpu/**"
  - "user/usb-host/**"
  - "user/virtio-blk/**"
  - "user/virtio-input/**"
  - "user/virtio-net/**"
  - "user/**/*.ld"
  - "*.ld"
  - "limine*.conf"
  - "manifest.toml"
  - "Makefile"
---

# Platform Gotchas

These are persistent platform/bootloader quirks that any new code in the boot or hardware paths must respect. Status of *features* (what's built vs planned) lives in [STATUS.md](../../STATUS.md); this file is for things that won't go away.

- **Boot requires BOTH manifest.bin and init.elf staged (ADR-018 step 9).** The kernel starts no service itself — it transcribes the manifest, registers every module by name, creates init as PID 1, and init spawns the boot wave. Missing manifest ⇒ typed `ManifestModuleMissing` boot failure; manifest without init ⇒ `InitModuleMissing`. There is no fallback chain any more. A module the manifest does not declare is loaded but unspawnable (`SYS_SPAWN` ⇒ `InvalidArg`); a boot-wave row spawned by anyone but init ⇒ `PermissionDenied`; on-demand rows (apps) are spawnable by any `CreateProcess` holder.
- **Limine base revision 3 HHDM gap (x86_64):** ACPI_RECLAIMABLE, ACPI_NVS, and RESERVED regions are NOT in the HHDM. `map_acpi_regions()` in `main.rs` explicitly maps small RESERVED regions (≤1MB, **uncacheable**, read-only) and all ACPI regions (cacheable, read-only) into the HHDM before ACPI parsing. SeaBIOS puts ACPI tables in RESERVED memory (not ACPI_RECLAIMABLE), so the RESERVED mapping is essential. **Device register pages must be claimed through `paging::claim_mmio_page`**, which remaps any earlier mapping uncacheable + writable: on the Dell Precision 3630 the RESERVED sweep had already mapped the Local APIC page cacheable, the APIC driver used it because `map_page` said `AlreadyMapped`, and the first cached APIC read hung the core (2026-10-22). Intel defines APIC access through any memory type but UC as undefined.
- **x86_64 memory types are the PAT Limine programs, plus one entry of ours.** Limine's layout is `0x0000010500070406` (index 0 WB … index 5 WC, the one its framebuffer mapping uses). Limine syncs the APs' MTRRs but not their PAT, so `percpu::init_bsp` captures the BSP's PAT and `init_ap` writes it on every AP (the Dell 3630's slow boot, 2026-10-23: eleven APs writing the console framebuffer write-through). `init_bsp` also sets index 1 (PWT only, no PAT bit) to WC, which `flags::user_framebuffer` selects for `SYS_MAP_FRAMEBUFFER` — never use the PAT bit on a 4 KiB leaf, the `x86_64` crate treats it as HUGE_PAGE and refuses to unmap. Device registers stay UC via `claim_mmio_page` / `user_mmio`.
- **Limine AArch64 HHDM does NOT map device MMIO.** PL011 UART (0x0900_0000) and the GIC Distributor (0x0800_0000) are mapped into TTBR1 via `early_map_mmio()` before any I/O. It uses three bootstrap frames from kernel .bss (physical address found by walking TTBR1 page tables, since kernel statics are NOT in HHDM), enough for one new L1/L2/L3 chain, so it reaches only the 2 MiB blocks those two devices sit in. The GIC Redistributor (0x080A_0000, one 128 KiB frame per CPU) is mapped later through the frame allocator by `gic::map_redistributors`, one frame per CPU Limine reports, bounded by QEMU `virt`'s low redistributor region (123 CPUs; the rest sit in a high region at 0x40_0000_0000 that is not mapped, and those CPUs are not woken). The early mapping used to cover CPUs 0-3 only, and `-smp 6` faulted CPUs 4 and 5 on `GICR_WAKER` (2026-11-23).
- **Limine AArch64 TCR_EL1.T1SZ too narrow.** Limine sets T1SZ for ~39-bit VA, but HHDM at `0xFFFF000000000000` needs 48-bit. `kmain` widens T1SZ to 16 (48-bit) at early boot.
- **AArch64 QEMU requires GICv3.** Must use `-machine virt,gic-version=3` because the GIC driver uses ICC system registers (GICv3). Default GICv2 causes Undefined Instruction on `mrs ICC_SRE_EL1`.
- **AArch64 CPACR_EL1 is per-CPU: every AP must enable FP/SIMD itself.** `arch::aarch64::enable_fpsimd()` (FPEN = 0b11) runs on the BSP and in `ap_entry`. Rust user code reaches NEON through `compiler_builtins::memset`; on a CPU where FPEN is still 0 that instruction traps as EC=0x07 and the task is reaped. The fault line names it; the pre-fix line read as a bad pointer because FAR_EL1 is stale for that class. The first task spawn-time placement homed on CPU 1, the policy service, died this way from 2026-10-27 until 2026-11-04, and the boot-smoke CI job (x86_64 only) never saw it. Neither architecture saves FP/SIMD register state across a context switch yet (STATUS.md Known issues).
- **ELF loader doesn't merge overlapping segment permissions.** If two PT_LOAD segments share a page with different permissions (e.g., .text RX and .got RW), the first segment's permissions are used. User-space linker scripts work around this with `ALIGN(4096)` before `.data`. Loader fix is tracked in [STATUS.md](../../STATUS.md).
- **`SYS_WAIT_IRQ` unregistered-IRQ wake fallback.** Registered device IRQs use targeted single-CPU wake via `TASK_CPU_MAP`. Unregistered IRQs fall back to all-CPU scan with `try_lock()` — if SCHEDULER lock is contended, wake is deferred to the next timer tick. Acceptable; not a bug.
- **Stray level-triggered IRQs are masked (x86_64).** A GSI with no entry in the routing table that wakes nobody is masked in the I/O APIC from its own handler and logged once (`[IRQ] stray GSI N … masked`); `SYS_WAIT_IRQ` unmasks the pin when a driver claims it. Real PCI devices assert level-triggered INTx lines that stay asserted after EOI; without this the handler re-enters forever and the interrupted context never resumes (the Dell 3630's xHCI after RUN, 2026-10-22 — the screen froze mid-string). QEMU never produced one.
- **xHCI on real firmware needs the BIOS → OS hand-off before reset.** `usb-host` walks the Extended Capability list for USB Legacy Support, sets the OS-owned semaphore, waits (bounded) for the BIOS-owned bit to clear, then disables every SMI source. Resetting a BIOS-owned controller drops the CPU into SMM. The Dell's controller also demands 65 scratchpad pages (`MaxScrPads`); qemu-xhci asks for none and has no legacy capability, so neither path exists under QEMU — the Dell is the test.

## Bare-metal images

```bash
make img-usb [PROFILE=headless]  # bare-metal USB image: iso_root + the signed manifest for PROFILE (headless = text shell on the framebuffer console, with the shell rebuilt `--features headless-input` and swapped in so it owns input endpoint 30 and reads the USB keyboard from usb-host; framebuffer-fallback = scanout-limine + compositor + terminal-window, keyboard via usb-host HID → compositor). `make usb DEVICE=/dev/diskN PROFILE=…` writes it.
make run-img-usb DISK_BUS=nvme PROFILE=headless   # the bare-metal rehearsal under QEMU: the headless/framebuffer-fallback profiles spawn `user/nvme`, `default` spawns virtio-blk; both serve the block seam in `cambios-blk-proto`
make usb DEVICE=/dev/diskN PROFILE=framebuffer-fallback KERNEL_FEATURES=fbcon-hold   # diagnostic stick for a machine with no serial: the kernel text console keeps mirroring over the scanout driver after the handoff, so the boot log (policy denials, `[sched]` counters, service lines) stays readable on the panel when the GUI chain fails silently. Garbled by design; never ship it.
```
