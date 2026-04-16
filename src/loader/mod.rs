// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Userspace process loader with verify-before-execute security gate
//!
//! Loads ELF binaries into isolated per-process address spaces. Every binary
//! passes through a `BinaryVerifier` before any memory is allocated or mapped.
//!
//! Pipeline: parse ELF → collect segments → **verify** → allocate + map → create task

pub mod elf;

use crate::ipc::ProcessId;
use crate::memory::frame_allocator::{FrameAllocator, PAGE_SIZE};
use crate::memory::paging;
use crate::process::ProcessTable;
use crate::scheduler::{Priority, Scheduler, TaskId};
use elf::{ElfBinary, ElfError, SegmentLoad};

extern crate alloc;
use alloc::alloc::{alloc, Layout};
use core::mem::size_of;

// ============================================================================
// Constants
// ============================================================================

/// SCAFFOLDING: per-task kernel stack size (8 KiB).
/// Why: small because syscall handlers are currently shallow. Linux uses 16 KiB.
/// Replace when: first deep call chain — recursive ELF verifier, signed-object
///      validator with stack-allocated context, channel teardown that walks
///      process tables. Watch for stack-overflow double-faults landing on IST1.
///      See ASSUMPTIONS.md.
/// SCAFFOLDING: per-task kernel stack size.
/// Why: the original 8 KiB was an unconscious bound — never sized for the
/// real frame budget. Real kernel paths in this build push past it
/// (debug `blake3::avx2::hash8` alone wants ~272 KiB; even fixed paths
/// like channel revoke briefly held arrays in the tens of KiB). Adjacent
/// kstacks are heap-allocated contiguously with no guard pages, so an
/// overflow corrupts the next task's saved context and produces a GPF
/// or silent reschedule death. 32 KiB gives ~4× headroom over current
/// observed usage and costs MAX_TASKS × 32 KiB ≈ 8 MiB of kernel memory.
/// Replace when: per-kstack guard-page mapping lands (then this becomes a
/// HARDWARE-bounded value driven by the page-fault report, not a guess).
const KERNEL_STACK_SIZE: usize = 32 * 1024;

/// SCAFFOLDING: default user stack 16 pages (64 KiB).
/// Why: conservative default that fits all current services.
/// Replace when: per-service decision; should become a process descriptor field
///      rather than a constant once different services have different needs.
///      See ASSUMPTIONS.md.
const DEFAULT_STACK_PAGES: usize = 16;

/// Default user stack top virtual address
const DEFAULT_STACK_TOP: u64 = 0x80_0000;

/// SCAFFOLDING: maximum total memory for a single process (256 MiB).
/// Why: ELF verifier hard cap; prevents OOM via crafted binaries.
/// Replace when: a legitimate user-space service needs > 256 MiB. Fine for now.
///      See ASSUMPTIONS.md.
const MAX_PROCESS_MEMORY: u64 = 256 * 1024 * 1024;

/// Canonical user-space boundary (x86-64 lower half)
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during process loading
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderError {
    /// ELF parsing or validation failed
    Elf(ElfError),
    /// Binary was rejected by the verifier
    Denied(DenyReason),
    /// Frame allocator out of memory
    FrameAllocationFailed,
    /// Page table operation failed
    PagingFailed,
    /// Failed to create process in process table
    ProcessCreationFailed,
    /// Scheduler has no free task slots
    SchedulerFull,
    /// Failed to allocate kernel stack
    KernelStackAllocationFailed,
}

impl core::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Elf(e) => write!(f, "ELF error: {}", e),
            Self::Denied(r) => write!(f, "Verification denied: {:?}", r),
            Self::FrameAllocationFailed => write!(f, "Frame allocation failed"),
            Self::PagingFailed => write!(f, "Page table operation failed"),
            Self::ProcessCreationFailed => write!(f, "Process creation failed"),
            Self::SchedulerFull => write!(f, "Scheduler full"),
            Self::KernelStackAllocationFailed => write!(f, "Kernel stack allocation failed"),
        }
    }
}

// ============================================================================
// Verify-before-execute security gate
// ============================================================================

/// Reason a binary was denied execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Entry point is not within any loadable segment
    EntryPointOutOfRange,
    /// A segment maps into kernel address space
    SegmentInKernelSpace,
    /// A segment is both writable and executable (W^X violation)
    WritableAndExecutable,
    /// Two LOAD segments overlap in virtual memory
    OverlappingSegments,
    /// Total memory footprint exceeds allowed limit
    ExcessiveMemory,
    /// Custom policy rejection (for extended verifiers)
    PolicyViolation,
    /// Binary is not signed (signature trailer missing)
    MissingSignature,
    /// Ed25519 signature verification failed
    InvalidSignature,
}

/// Result of binary verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// Binary is allowed to execute
    Allow,
    /// Binary is denied execution
    Deny(DenyReason),
}

/// Pre-execution binary verification trait.
///
/// Implementations inspect parsed ELF metadata **before** any memory is
/// allocated or mapped. This is the zero-trust "verify before execute" gate.
///
/// The verifier receives:
/// - `binary`: raw ELF bytes (for hash/signature checks)
/// - `metadata`: parsed ELF overview (entry point, load range)
/// - `segments`: all PT_LOAD segments with permissions
pub trait BinaryVerifier {
    fn verify(
        &self,
        binary: &[u8],
        metadata: &ElfBinary,
        segments: &[SegmentLoad],
    ) -> VerifyResult;
}

/// Default verifier enforcing zero-trust security policies.
///
/// Checks:
/// 1. Entry point falls within a LOAD segment
/// 2. All segments are in user space (below canonical hole)
/// 3. W^X: no segment is both writable and executable
/// 4. No overlapping segments
/// 5. Total memory footprint within limit
pub struct DefaultVerifier {
    /// Maximum allowed total memory (bytes)
    pub max_memory: u64,
}

impl Default for DefaultVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultVerifier {
    pub fn new() -> Self {
        Self {
            max_memory: MAX_PROCESS_MEMORY,
        }
    }
}

impl BinaryVerifier for DefaultVerifier {
    fn verify(
        &self,
        _binary: &[u8],
        metadata: &ElfBinary,
        segments: &[SegmentLoad],
    ) -> VerifyResult {
        // 1. Entry point must be within a LOAD segment
        let entry = metadata.entry_point;
        let entry_in_segment = segments.iter().any(|seg| {
            let seg_end = seg.vaddr.saturating_add(seg.memsz);
            entry >= seg.vaddr && entry < seg_end
        });
        if !entry_in_segment {
            return VerifyResult::Deny(DenyReason::EntryPointOutOfRange);
        }

        let mut total_memory: u64 = 0;

        for seg in segments {
            // 2. All segments must be in user space
            let seg_end = seg.vaddr.saturating_add(seg.memsz);
            if seg.vaddr >= USER_SPACE_END || seg_end > USER_SPACE_END {
                return VerifyResult::Deny(DenyReason::SegmentInKernelSpace);
            }

            // 3. W^X enforcement: no segment may be both writable and executable
            if seg.writable && seg.executable {
                return VerifyResult::Deny(DenyReason::WritableAndExecutable);
            }

            total_memory = total_memory.saturating_add(seg.memsz);
        }

        // 4. No overlapping segments
        for i in 0..segments.len() {
            for j in (i + 1)..segments.len() {
                let a = &segments[i];
                let b = &segments[j];
                let a_end = a.vaddr.saturating_add(a.memsz);
                let b_end = b.vaddr.saturating_add(b.memsz);
                if a.vaddr < b_end && b.vaddr < a_end {
                    return VerifyResult::Deny(DenyReason::OverlappingSegments);
                }
            }
        }

        // 5. Total memory within limit
        if total_memory > self.max_memory {
            return VerifyResult::Deny(DenyReason::ExcessiveMemory);
        }

        VerifyResult::Allow
    }
}

// ============================================================================
// Signed binary verification
// ============================================================================

/// Signature trailer appended to ELF binaries by the host-side signing tool.
///
/// Format: `[original ELF bytes][Ed25519 signature: 64 bytes][magic: 8 bytes]`
///
/// Magic: `ARCSIG\x01\x00` (version 1, no padding).
/// Total trailer size: 72 bytes.
///
/// The signature covers all bytes before the trailer (the original ELF).
pub const SIGNATURE_TRAILER_MAGIC: &[u8; 8] = b"ARCSIG\x01\x00";
pub const SIGNATURE_TRAILER_SIZE: usize = 64 + 8; // signature + magic

/// Strip the signature trailer from a signed binary.
///
/// Returns `Some((elf_bytes, signature_bytes))` if the trailer is present,
/// `None` if the binary is unsigned.
pub fn strip_signature_trailer(binary: &[u8]) -> Option<(&[u8], [u8; 64])> {
    if binary.len() < SIGNATURE_TRAILER_SIZE {
        return None;
    }
    let magic_start = binary.len() - 8;
    if &binary[magic_start..] != SIGNATURE_TRAILER_MAGIC {
        return None;
    }
    let sig_start = magic_start - 64;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&binary[sig_start..magic_start]);
    Some((&binary[..sig_start], sig))
}

/// SCAFFOLDING: maximum number of trusted ELF signing keys.
/// Why: bootstrap + a few rotation keys was enough for early development.
/// Replace when: first time we have CI builder + your YubiKey + backup key +
///      rotation key, the budget is gone with zero room for new signers. Coming
///      up faster than other PKI items because CI signing is on the early v1 path.
///      See ASSUMPTIONS.md.
const MAX_TRUSTED_KEYS: usize = 4;

/// Verifier that requires Ed25519 signature verification before executing.
///
/// Wraps `DefaultVerifier` — runs all standard security checks AND requires
/// a valid signature trailer signed by one of the trusted public keys.
///
/// The binary must have an `ARCSIG\x01\x00` trailer containing a 64-byte
/// Ed25519 signature over the Blake3 hash of the original ELF bytes.
/// The signature must verify against at least one of the configured trusted keys.
pub struct SignedBinaryVerifier {
    /// Trusted public keys (Ed25519, 32 bytes each).
    /// At least one must have signed the binary.
    trusted_keys: [[u8; 32]; MAX_TRUSTED_KEYS],
    /// Number of active trusted keys.
    key_count: usize,
    /// Inner verifier for structural checks.
    inner: DefaultVerifier,
}

impl SignedBinaryVerifier {
    /// Create a verifier with a single trusted key.
    pub fn with_key(key: [u8; 32]) -> Self {
        let mut keys = [[0u8; 32]; MAX_TRUSTED_KEYS];
        keys[0] = key;
        Self {
            trusted_keys: keys,
            key_count: 1,
            inner: DefaultVerifier::new(),
        }
    }
}

impl BinaryVerifier for SignedBinaryVerifier {
    fn verify(
        &self,
        binary: &[u8],
        metadata: &ElfBinary,
        segments: &[SegmentLoad],
    ) -> VerifyResult {
        // 1. Check for signature trailer
        let (elf_bytes, sig_bytes) = match strip_signature_trailer(binary) {
            Some(pair) => pair,
            None => return VerifyResult::Deny(DenyReason::MissingSignature),
        };

        // 2. Verify signature against at least one trusted key.
        //    The signature covers blake3(elf_bytes), not the raw bytes.
        //    This allows hardware signing keys (YubiKey) to sign a 32-byte hash
        //    instead of piping entire binaries through the smart card interface.
        let elf_hash = crate::fs::content_hash(elf_bytes);
        let sig_valid = self.trusted_keys[..self.key_count].iter().any(|pk| {
            crate::fs::verify_signature(pk, &elf_hash, &crate::fs::SignatureBytes { data: sig_bytes })
        });
        if !sig_valid {
            return VerifyResult::Deny(DenyReason::InvalidSignature);
        }

        // 3. Run all standard structural checks (on the original ELF, not trailer)
        self.inner.verify(elf_bytes, metadata, segments)
    }
}

// ============================================================================
// Process loading result
// ============================================================================

/// Successful process load result
#[derive(Debug, Clone, Copy)]
pub struct LoadedProcess {
    pub process_id: ProcessId,
    pub task_id: TaskId,
    pub cr3: u64,
    pub entry_point: u64,
}

// ============================================================================
// Production ELF loader
// ============================================================================

/// Load an ELF binary into an isolated process address space.
///
/// Full pipeline:
/// 1. Parse and validate ELF structure
/// 2. Collect LOAD segment metadata
/// 3. **Verify** — security gate rejects before any allocation
/// 4. Create process with per-process PML4
/// 5. For each LOAD segment: allocate frames, map pages, copy data, zero BSS
/// 6. Allocate and map user stack
/// 7. Allocate kernel stack, set up SavedContext for iretq → ring 3
/// 8. Register task in scheduler
///
/// The caller is responsible for lock ordering if calling from a context
/// where the global spinlocks are in play. During boot init (single-threaded),
/// pass the raw references directly.
pub fn load_elf_process(
    binary: &[u8],
    priority: Priority,
    verifier: &dyn BinaryVerifier,
    process_table: &mut ProcessTable,
    frame_alloc: &mut FrameAllocator,
    scheduler: &mut Scheduler,
) -> Result<LoadedProcess, LoaderError> {
    // --- Step 1: Parse ELF ---
    let metadata = elf::analyze_binary(binary).map_err(LoaderError::Elf)?;

    // --- Step 2: Collect LOAD segments ---
    let (segments, seg_count) =
        elf::collect_load_segments(binary).map_err(LoaderError::Elf)?;
    let segments = &segments[..seg_count];

    // --- Step 3: Verify before execute ---
    match verifier.verify(binary, &metadata, segments) {
        VerifyResult::Allow => {
            // Phase 3.3: emit BinaryLoaded audit event.
            let hash_prefix = {
                let mut buf = [0u8; 24];
                let len = binary.len().min(24);
                buf[..len].copy_from_slice(&binary[..len]);
                buf
            };
            crate::audit::emit(crate::audit::RawAuditEvent::binary_loaded(
                binary.len(), hash_prefix, crate::audit::now(), 0,
            ));
        }
        VerifyResult::Deny(reason) => {
            let reason_code = match reason {
                DenyReason::EntryPointOutOfRange => 0,
                DenyReason::SegmentInKernelSpace => 1,
                DenyReason::WritableAndExecutable => 2,
                DenyReason::OverlappingSegments => 3,
                DenyReason::ExcessiveMemory => 4,
                DenyReason::PolicyViolation => 5,
                DenyReason::MissingSignature => 6,
                DenyReason::InvalidSignature => 7,
            };
            crate::audit::emit(crate::audit::RawAuditEvent::binary_rejected(
                reason_code, crate::audit::now(), 0,
            ));
            return Err(LoaderError::Denied(reason));
        }
    }

    // --- Step 4: Create process with per-process page table ---
    // Phase 3.2c: process table allocates the slot and stamps the
    // generation counter into the returned ProcessId.
    let process_id = process_table
        .create_process(frame_alloc, /* create_page_table = */ true)
        .map_err(|_| LoaderError::ProcessCreationFailed)?;

    let cr3 = process_table.get_cr3(process_id);
    if cr3 == 0 {
        return Err(LoaderError::ProcessCreationFailed);
    }

    // --- Step 5: Map LOAD segments ---
    let hhdm = crate::hhdm_offset();

    for seg in segments {
        let page_aligned_vaddr = seg.vaddr & !(PAGE_SIZE - 1);
        let offset_in_first_page = seg.vaddr - page_aligned_vaddr;
        let total_bytes = offset_in_first_page + seg.memsz;
        let num_pages = total_bytes.div_ceil(PAGE_SIZE) as usize;

        let flags = if seg.writable {
            paging::flags::user_rw()
        } else {
            paging::flags::user_ro()
        };

        for page_idx in 0..num_pages {
            let page_vaddr = page_aligned_vaddr + (page_idx as u64 * PAGE_SIZE);

            // Check if this page was already mapped by a prior segment (e.g.,
            // .text and .rodata sharing the same 4 KiB page). If so, reuse
            // the existing frame instead of allocating and re-mapping.
            // SAFETY: cr3 is a valid PML4/L0 physical address allocated by
            // create_process. page_table_from_cr3 creates a temporary reference
            // via the HHDM. translate performs a read-only walk.
            let frame_phys = unsafe {
                let pt = paging::page_table_from_cr3(cr3);
                paging::translate(&pt, page_vaddr)
            };

            let frame_addr = if let Some(existing_phys) = frame_phys {
                // Page already mapped — reuse the existing frame
                existing_phys
            } else {
                // Allocate a new frame
                let frame = frame_alloc
                    .allocate()
                    .map_err(|_| LoaderError::FrameAllocationFailed)?;

                // Zero the frame via HHDM before copying data
                // SAFETY: frame.addr is a freshly allocated physical frame. HHDM maps
                // it to a valid kernel-accessible virtual address. We zero the full page.
                unsafe {
                    core::ptr::write_bytes((frame.addr + hhdm) as *mut u8, 0, PAGE_SIZE as usize);
                }

                // SAFETY: cr3 is a valid PML4 from create_process_page_table(). The
                // frame is freshly allocated and zeroed.
                unsafe {
                    let mut pt = paging::page_table_from_cr3(cr3);
                    paging::map_page(&mut pt, page_vaddr, frame.addr, flags, frame_alloc)
                        .map_err(|_| LoaderError::PagingFailed)?;
                }

                frame.addr
            };

            // Copy file data into this page (if any falls within this page)
            let page_start_in_segment = if page_idx == 0 {
                0u64
            } else {
                page_idx as u64 * PAGE_SIZE - offset_in_first_page
            };

            if page_start_in_segment < seg.filesz {
                let copy_offset_in_page = if page_idx == 0 {
                    offset_in_first_page
                } else {
                    0
                };
                let bytes_available = seg.filesz - page_start_in_segment;
                let bytes_in_page = PAGE_SIZE - copy_offset_in_page;
                let copy_len = core::cmp::min(bytes_available, bytes_in_page) as usize;

                let src_offset = seg.file_offset + page_start_in_segment;

                // SAFETY: src_offset is within binary.len() (validated by collect_load_segments).
                let src = unsafe { binary.as_ptr().add(src_offset as usize) };
                let dst = (frame_addr + hhdm + copy_offset_in_page) as *mut u8;
                // SAFETY: src is within binary bounds, dst is an HHDM-mapped frame
                // (writable), regions don't overlap, copy_len is bounded.
                unsafe { core::ptr::copy_nonoverlapping(src, dst, copy_len) };
            }
            // BSS (memsz > filesz) is already zeroed from the write_bytes above
        }
    }

    // --- Step 6: Allocate and map user stack ---
    let stack_base = DEFAULT_STACK_TOP - (DEFAULT_STACK_PAGES as u64 * PAGE_SIZE);
    for i in 0..DEFAULT_STACK_PAGES {
        let frame = frame_alloc
            .allocate()
            .map_err(|_| LoaderError::FrameAllocationFailed)?;

        // Zero the stack frame
        // SAFETY: Freshly allocated frame, HHDM-mapped.
        unsafe {
            core::ptr::write_bytes((frame.addr + hhdm) as *mut u8, 0, PAGE_SIZE as usize);
        }

        // SAFETY: cr3 is valid, frame is freshly allocated. user_rw grants
        // read/write/user-accessible permission for the stack.
        unsafe {
            let mut pt = paging::page_table_from_cr3(cr3);
            paging::map_page(
                &mut pt,
                stack_base + (i as u64 * PAGE_SIZE),
                frame.addr,
                paging::flags::user_rw(),
                frame_alloc,
            )
            .map_err(|_| LoaderError::PagingFailed)?;
        }
    }

    // --- Step 7: Allocate kernel stack + SavedContext ---
    let kstack_layout = Layout::from_size_align(KERNEL_STACK_SIZE, 16)
        .map_err(|_| LoaderError::KernelStackAllocationFailed)?;

    // SAFETY: Layout is valid (KERNEL_STACK_SIZE=8192, align=16).
    let kstack_base = unsafe { alloc(kstack_layout) };
    if kstack_base.is_null() {
        return Err(LoaderError::KernelStackAllocationFailed);
    }
    let kstack_top = kstack_base as u64 + KERNEL_STACK_SIZE as u64;

    // Set up SavedContext at the top of the kernel stack.
    // On AArch64, the timer ISR stub uses a 288-byte frame (272-byte SavedContext
    // rounded up to 16-byte alignment). The saved_rsp must match so that
    // `add sp, sp, #288` on restore gives the exact kernel stack top.
    #[cfg(target_arch = "aarch64")]
    const ISR_FRAME_SIZE: u64 = 288;
    #[cfg(target_arch = "x86_64")]
    const ISR_FRAME_SIZE: u64 = size_of::<crate::arch::SavedContext>() as u64;
    #[cfg(target_arch = "riscv64")]
    const ISR_FRAME_SIZE: u64 = crate::arch::riscv64::ISR_FRAME_SIZE;
    let saved_ctx_addr = kstack_top - ISR_FRAME_SIZE;
    let saved_ctx = saved_ctx_addr as *mut crate::arch::SavedContext;

    // SAFETY: saved_ctx points within the freshly allocated kernel stack.
    // The SavedContext is fully initialized with the ELF entry point and
    // user stack top. On x86_64 iretq pops this to ring 3; on AArch64 eret
    // returns to EL0 using elr_el1/spsr_el1.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::ptr::write(
            saved_ctx,
            crate::arch::SavedContext {
                r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0,
                r9: 0, r8: 0, rbp: 0, rdi: 0, rsi: 0, rdx: 0,
                rcx: 0, rbx: 0, rax: 0,
                rip: metadata.entry_point,
                cs: crate::arch::gdt::USER_CS as u64,
                rflags: 0x202, // IF set (interrupts enabled)
                rsp: DEFAULT_STACK_TOP,
                ss: crate::arch::gdt::USER_SS as u64,
            },
        );
        #[cfg(target_arch = "aarch64")]
        {
            let ctx = crate::arch::SavedContext {
                gpr: [0u64; 31],
                elr_el1: metadata.entry_point,
                // SPSR_EL1 = EL0t (bits[3:0]=0b0000), DAIF clear = interrupts enabled
                spsr_el1: 0x0,
                sp_el0: DEFAULT_STACK_TOP,
            };
            // x29 (FP) and x30 (LR) are zero — first entry has no caller
            core::ptr::write(saved_ctx, ctx);
        }
        #[cfg(target_arch = "riscv64")]
        {
            // RISC-V U-mode task entry. On sret, the hart restores:
            //   PC ← sepc (entry_point)
            //   privilege ← SPP (must be 0 for U-mode)
            //   SIE ← SPIE (1 so interrupts are enabled after sret)
            // sp lives in gpr[2] (x2 = sp per RISC-V ABI).
            let mut gpr = [0u64; 32];
            gpr[2] = DEFAULT_STACK_TOP; // x2 = sp
            let ctx = crate::arch::SavedContext {
                gpr,
                sepc: metadata.entry_point,
                // sstatus: SPP=0 (previous mode was U), SPIE=1 (SIE restored
                // to 1 after sret), SIE stays 0 in S-mode until sret.
                // Bit 5 (SPIE) = 0x20.
                sstatus: 0x20,
            };
            core::ptr::write(saved_ctx, ctx);
        }
    }

    // --- Step 8: Register task in scheduler ---
    let task_id = scheduler
        .create_isr_task(
            metadata.entry_point,
            saved_ctx_addr,
            kstack_top,
            priority,
        )
        .map_err(|_| LoaderError::SchedulerFull)?;

    // Set process_id and CR3 on the task
    if let Some(task) = scheduler.get_task_mut_pub(task_id) {
        task.process_id = Some(process_id);
        task.cr3 = cr3;
    }

    Ok(LoadedProcess {
        process_id,
        task_id,
        cr3,
        entry_point: metadata.entry_point,
    })
}

// ============================================================================
// ELF construction from raw code
// ============================================================================

/// Construct a minimal valid ELF64 binary from raw machine code bytes.
///
/// Creates a single PT_LOAD segment (RX) at the given virtual address.
/// Used during boot to wrap inline assembly into an ELF for the loader pipeline.
///
/// The resulting ELF passes `DefaultVerifier`: entry is within the segment,
/// segment is in user space, and it's read-execute only (no W^X violation).
pub fn build_boot_elf(code: &[u8], entry_vaddr: u64) -> alloc::vec::Vec<u8> {
    use elf::{Elf64Header, Elf64ProgramHeader, phdr_type, phdr_flags};

    let ehdr_size = size_of::<Elf64Header>();
    let phdr_size = size_of::<Elf64ProgramHeader>();
    let headers_size = ehdr_size + phdr_size;

    let mut binary = alloc::vec![0u8; headers_size];

    // Append the raw code bytes after headers
    binary.extend_from_slice(code);

    // Build the single LOAD program header
    let phdr = Elf64ProgramHeader {
        p_type: phdr_type::PT_LOAD,
        p_flags: phdr_flags::PF_R | phdr_flags::PF_X,
        p_offset: headers_size as u64,
        p_vaddr: entry_vaddr,
        p_paddr: entry_vaddr,
        p_filesz: code.len() as u64,
        p_memsz: code.len() as u64,
        p_align: 0x1000,
    };

    // Build ELF header
    let header = Elf64Header {
        magic: *b"\x7fELF",
        class: 2,  // 64-bit
        data: 1,   // little-endian
        version: 1,
        os_abi: 0,
        abi_version: 0,
        _padding: [0; 7],
        e_type: 2,  // ET_EXEC
        e_machine: elf::ELF_MACHINE_CURRENT,
        e_version: 1,
        e_entry: entry_vaddr,
        e_phoff: ehdr_size as u64,
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: ehdr_size as u16,
        e_phentsize: phdr_size as u16,
        e_phnum: 1,
        e_shentsize: 0,
        e_shnum: 0,
        e_shstrndx: 0,
    };

    // SAFETY: Elf64Header is repr(C), POD. Reinterpreting as bytes is valid.
    let header_bytes = unsafe {
        core::slice::from_raw_parts(
            &header as *const Elf64Header as *const u8,
            ehdr_size,
        )
    };
    binary[..ehdr_size].copy_from_slice(header_bytes);

    // SAFETY: Elf64ProgramHeader is repr(C), POD. Reinterpreting as bytes is valid.
    let phdr_bytes = unsafe {
        core::slice::from_raw_parts(
            &phdr as *const Elf64ProgramHeader as *const u8,
            phdr_size,
        )
    };
    binary[ehdr_size..ehdr_size + phdr_size].copy_from_slice(phdr_bytes);

    binary
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::elf::*;

    // --- Test ELF builder ---

    /// Build a minimal valid x86-64 ELF binary with the given LOAD segments.
    fn build_test_elf(entry: u64, segments: &[(u64, u64, u64, u32)]) -> alloc::vec::Vec<u8> {
        use core::mem::size_of;

        let ehdr_size = size_of::<Elf64Header>();
        let phdr_size = size_of::<Elf64ProgramHeader>();
        let headers_size = ehdr_size + segments.len() * phdr_size;

        // Each segment's file data follows the headers
        let mut data_offset = headers_size;
        let mut binary = alloc::vec![0u8; headers_size];

        // Build program headers and append segment data
        let mut phdrs = alloc::vec::Vec::new();
        for &(vaddr, filesz, memsz, flags) in segments {
            let phdr = Elf64ProgramHeader {
                p_type: phdr_type::PT_LOAD,
                p_flags: flags,
                p_offset: data_offset as u64,
                p_vaddr: vaddr,
                p_paddr: vaddr,
                p_filesz: filesz,
                p_memsz: memsz,
                p_align: 0x1000,
            };
            phdrs.push(phdr);
            // Append file data (filled with 0xCC as a marker)
            binary.extend(core::iter::repeat(0xCC).take(filesz as usize));
            data_offset += filesz as usize;
        }

        // Build ELF header
        let header = Elf64Header {
            magic: *b"\x7fELF",
            class: 2,  // 64-bit
            data: 1,   // little-endian
            version: 1,
            os_abi: 0,
            abi_version: 0,
            _padding: [0; 7],
            e_type: 2,  // ET_EXEC
            e_machine: elf::ELF_MACHINE_CURRENT,
            e_version: 1,
            e_entry: entry,
            e_phoff: ehdr_size as u64,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: ehdr_size as u16,
            e_phentsize: phdr_size as u16,
            e_phnum: segments.len() as u16,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        };

        // SAFETY: Elf64Header and Elf64ProgramHeader are #[repr(C)] structs.
        // Reinterpreting them as byte slices is safe for memcpy into the
        // test binary buffer. The slices don't outlive the struct references.
        // Write header
        let header_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &header as *const Elf64Header as *const u8,
                ehdr_size,
            )
        };
        binary[..ehdr_size].copy_from_slice(header_bytes);

        // Write program headers
        for (i, phdr) in phdrs.iter().enumerate() {
            let offset = ehdr_size + i * phdr_size;
            let phdr_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    phdr as *const Elf64ProgramHeader as *const u8,
                    phdr_size,
                )
            };
            binary[offset..offset + phdr_size].copy_from_slice(phdr_bytes);
        }

        binary
    }

    // --- Verifier tests ---

    #[test]
    fn test_default_verifier_allows_valid_binary() {
        let verifier = DefaultVerifier::new();
        // Single code segment: RX at 0x400000
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Allow,
        );
    }

    #[test]
    fn test_verifier_denies_entry_outside_segment() {
        let verifier = DefaultVerifier::new();
        // Entry at 0x500000 but segment at 0x400000
        let binary = build_test_elf(0x500000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::EntryPointOutOfRange),
        );
    }

    #[test]
    fn test_verifier_denies_kernel_space_segment() {
        let verifier = DefaultVerifier::new();
        // Segment in kernel space
        let binary = build_test_elf(
            0xFFFF_8000_0000_0000,
            &[(0xFFFF_8000_0000_0000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X)],
        );

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::SegmentInKernelSpace),
        );
    }

    #[test]
    fn test_verifier_denies_writable_executable() {
        let verifier = DefaultVerifier::new();
        // W+X segment
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_W | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::WritableAndExecutable),
        );
    }

    #[test]
    fn test_verifier_denies_overlapping_segments() {
        let verifier = DefaultVerifier::new();
        // Two segments that overlap: 0x400000..0x402000 and 0x401000..0x403000
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x2000, phdr_flags::PF_R | phdr_flags::PF_X),
            (0x401000, 0x1000, 0x2000, phdr_flags::PF_R | phdr_flags::PF_W),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::OverlappingSegments),
        );
    }

    #[test]
    fn test_verifier_denies_excessive_memory() {
        let mut verifier = DefaultVerifier::new();
        verifier.max_memory = 0x1000; // Limit to 4KB

        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x2000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::ExcessiveMemory),
        );
    }

    #[test]
    fn test_verifier_allows_code_plus_data_segments() {
        let verifier = DefaultVerifier::new();
        // Typical layout: RX code + RW data, non-overlapping
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x2000, 0x2000, phdr_flags::PF_R | phdr_flags::PF_X), // .text
            (0x600000, 0x1000, 0x2000, phdr_flags::PF_R | phdr_flags::PF_W), // .data+.bss
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Allow,
        );
    }

    #[test]
    fn test_verifier_entry_at_segment_boundary() {
        let verifier = DefaultVerifier::new();
        // Entry point at the very start of the segment (edge case)
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x100, 0x100, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Allow,
        );
    }

    #[test]
    fn test_verifier_entry_at_last_byte() {
        let verifier = DefaultVerifier::new();
        // Entry point at the last valid byte of the segment
        let binary = build_test_elf(0x400FFF, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Allow,
        );
    }

    #[test]
    fn test_verifier_entry_one_past_end() {
        let verifier = DefaultVerifier::new();
        // Entry point one byte past the segment — should be denied
        let binary = build_test_elf(0x401000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::EntryPointOutOfRange),
        );
    }

    #[test]
    fn test_verifier_adjacent_segments_allowed() {
        let verifier = DefaultVerifier::new();
        // Two adjacent (non-overlapping) segments
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
            (0x401000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_W),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Allow,
        );
    }

    // --- ELF parser integration tests ---

    #[test]
    fn test_collect_segments_valid() {
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
            (0x600000, 0x500, 0x1000, phdr_flags::PF_R | phdr_flags::PF_W),
        ]);

        let (segs, count) = elf::collect_load_segments(&binary).unwrap();
        assert_eq!(count, 2);
        assert_eq!(segs[0].vaddr, 0x400000);
        assert!(segs[0].executable);
        assert!(!segs[0].writable);
        assert_eq!(segs[1].vaddr, 0x600000);
        assert!(segs[1].writable);
        assert!(!segs[1].executable);
        assert_eq!(segs[1].filesz, 0x500);
        assert_eq!(segs[1].memsz, 0x1000);
    }

    #[test]
    fn test_elf_roundtrip_parse() {
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x2000, 0x2000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        assert_eq!(metadata.entry_point, 0x400000);
        assert_eq!(metadata.load_base, 0x400000);
        assert_eq!(metadata.load_size, 0x2000);
    }

    // --- Custom verifier tests ---

    #[test]
    fn test_custom_verifier() {
        /// A verifier that denies everything
        struct DenyAll;
        impl BinaryVerifier for DenyAll {
            fn verify(
                &self,
                _binary: &[u8],
                _metadata: &ElfBinary,
                _segments: &[SegmentLoad],
            ) -> VerifyResult {
                VerifyResult::Deny(DenyReason::PolicyViolation)
            }
        }

        let verifier = DenyAll;
        let binary = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let metadata = elf::analyze_binary(&binary).unwrap();
        let (segs, count) = elf::collect_load_segments(&binary).unwrap();

        assert_eq!(
            verifier.verify(&binary, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::PolicyViolation),
        );
    }

    // --- Signature trailer tests ---

    /// Helper: sign a binary and append the ARCSIG trailer.
    /// Signs blake3(binary), not the raw binary — matches the verifier.
    fn sign_binary(binary: &[u8], sk_bytes: &[u8; 64]) -> alloc::vec::Vec<u8> {
        let hash = crate::fs::content_hash(binary);
        let sig = crate::fs::sign_content(sk_bytes, &hash);
        let mut signed = binary.to_vec();
        signed.extend_from_slice(&sig.data);
        signed.extend_from_slice(SIGNATURE_TRAILER_MAGIC);
        signed
    }

    #[test]
    fn test_strip_signature_trailer_present() {
        let elf = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);
        let seed = [1u8; 32];
        let (_, sk) = crate::fs::keypair_from_seed(&seed);
        let signed = sign_binary(&elf, &sk);

        let (stripped, sig) = strip_signature_trailer(&signed).expect("trailer should be found");
        assert_eq!(stripped, &elf[..]);
        assert_ne!(sig, [0u8; 64]);
    }

    #[test]
    fn test_strip_signature_trailer_missing() {
        let elf = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);
        assert!(strip_signature_trailer(&elf).is_none());
    }

    #[test]
    fn test_strip_signature_trailer_too_short() {
        let short = [0u8; 10];
        assert!(strip_signature_trailer(&short).is_none());
    }

    #[test]
    fn test_signed_verifier_allows_valid_signature() {
        let seed = [1u8; 32];
        let (pk, sk) = crate::fs::keypair_from_seed(&seed);
        let elf = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);
        let signed = sign_binary(&elf, &sk);

        let verifier = SignedBinaryVerifier::with_key(pk);

        // Parse from the signed binary (ELF parser ignores trailing data)
        let metadata = elf::analyze_binary(&signed).unwrap();
        let (segs, count) = elf::collect_load_segments(&signed).unwrap();

        assert_eq!(
            verifier.verify(&signed, &metadata, &segs[..count]),
            VerifyResult::Allow,
        );
    }

    #[test]
    fn test_signed_verifier_denies_unsigned() {
        let seed = [1u8; 32];
        let (pk, _) = crate::fs::keypair_from_seed(&seed);
        let elf = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);

        let verifier = SignedBinaryVerifier::with_key(pk);
        let metadata = elf::analyze_binary(&elf).unwrap();
        let (segs, count) = elf::collect_load_segments(&elf).unwrap();

        assert_eq!(
            verifier.verify(&elf, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::MissingSignature),
        );
    }

    #[test]
    fn test_signed_verifier_denies_wrong_key() {
        let (_, sk) = crate::fs::keypair_from_seed(&[1u8; 32]);
        let (wrong_pk, _) = crate::fs::keypair_from_seed(&[2u8; 32]);

        let elf = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);
        let signed = sign_binary(&elf, &sk);

        let verifier = SignedBinaryVerifier::with_key(wrong_pk);
        let metadata = elf::analyze_binary(&signed).unwrap();
        let (segs, count) = elf::collect_load_segments(&signed).unwrap();

        assert_eq!(
            verifier.verify(&signed, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::InvalidSignature),
        );
    }

    #[test]
    fn test_signed_verifier_denies_tampered_binary() {
        let seed = [1u8; 32];
        let (pk, sk) = crate::fs::keypair_from_seed(&seed);
        let elf = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_X),
        ]);
        let mut signed = sign_binary(&elf, &sk);

        // Tamper with a byte in the segment data (offset 200 is in the code
        // section, past the ELF header + program header at offset 120)
        if signed.len() > 200 {
            signed[200] ^= 0xFF;
        }

        let verifier = SignedBinaryVerifier::with_key(pk);
        let metadata = elf::analyze_binary(&signed).unwrap();
        let (segs, count) = elf::collect_load_segments(&signed).unwrap();

        assert_eq!(
            verifier.verify(&signed, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::InvalidSignature),
        );
    }

    #[test]
    fn test_signed_verifier_still_checks_wxe() {
        // Valid signature but W^X violation — should still be denied
        let seed = [1u8; 32];
        let (pk, sk) = crate::fs::keypair_from_seed(&seed);
        let elf = build_test_elf(0x400000, &[
            (0x400000, 0x1000, 0x1000, phdr_flags::PF_R | phdr_flags::PF_W | phdr_flags::PF_X),
        ]);
        let signed = sign_binary(&elf, &sk);

        let verifier = SignedBinaryVerifier::with_key(pk);
        let metadata = elf::analyze_binary(&signed).unwrap();
        let (segs, count) = elf::collect_load_segments(&signed).unwrap();

        assert_eq!(
            verifier.verify(&signed, &metadata, &segs[..count]),
            VerifyResult::Deny(DenyReason::WritableAndExecutable),
        );
    }
}
