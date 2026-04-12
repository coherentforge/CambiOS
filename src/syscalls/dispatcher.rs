// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Syscall dispatcher and handlers
//!
//! Routes syscalls from userspace to kernel handlers with zero-trust
//! interceptor pre-check. All handlers that touch user memory perform
//! page-table walks through the process's CR3 via HHDM.

use crate::syscalls::{SyscallNumber, SyscallArgs, SyscallResult, SyscallError};
use crate::scheduler::TaskId;
use crate::ipc::ProcessId;

/// Syscall handler context
///
/// Passed to each syscall handler to give it access to kernel state.
pub struct SyscallContext {
    /// Calling process ID
    pub process_id: ProcessId,
    /// Calling task ID
    pub task_id: TaskId,
    /// Process page table (CR3). 0 = kernel task (no user address space).
    pub cr3: u64,
}

// ============================================================================
// User-space buffer helpers
// ============================================================================

/// HARDWARE: x86 IDT has 256 entries; vectors 0-31 are CPU exceptions, 32-223 are
/// device IRQs, 224-255 are reserved for APIC/IPI. SYS_WAIT_IRQ accepts < 224.
const MAX_DEVICE_IRQ: u32 = 224;

/// SCAFFOLDING: maximum user buffer size for a single syscall (4 KiB).
/// Why: bounds copy_from_user / copy_to_user; safety net against accidentally
///      mapping huge ranges through the page-table-walk helpers.
/// Replace when: a user-space service needs to read or write > 4 KiB in one
///      syscall and gets a confusing failure at exactly the boundary. Channels
///      (ADR-005) are the long-term answer for bulk data; until then this needs
///      to grow on demand. See ASSUMPTIONS.md.
const MAX_USER_BUFFER: usize = 4096;

/// Canonical user-space address ceiling.
/// x86_64: lower-half canonical addresses end at bit 47.
/// AArch64: TTBR0 covers 0..2^48 with T0SZ=16 (48-bit VA).
#[cfg(target_arch = "x86_64")]
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
#[cfg(not(target_arch = "x86_64"))]
const USER_SPACE_END: u64 = 0x0001_0000_0000_0000;

/// Read bytes from a user-space virtual address into a kernel buffer.
///
/// Walks the process page table (CR3) to translate each page the buffer
/// spans, then reads via HHDM. Returns the number of bytes copied.
///
/// # Safety contract
/// `cr3` must be a valid page table root physical address for the calling
/// process (PML4 on x86_64, L0 on AArch64). Called from syscall context.
fn read_user_buffer(cr3: u64, user_addr: u64, len: usize, dst: &mut [u8]) -> Result<usize, SyscallError> {
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
    if cr3 == 0 {
        return Err(SyscallError::InvalidArg);
    }

    let hhdm = crate::hhdm_offset();
    let mut copied = 0usize;

    while copied < len {
        let vaddr = user_addr + copied as u64;
        let page_offset = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(len - copied, 4096 - page_offset);

        // SAFETY: cr3 is the process's PML4 physical address (non-zero, checked above).
        // page_table_from_cr3 creates a temporary OffsetPageTable via HHDM.
        // translate() performs a read-only page table walk.
        let phys = unsafe {
            let pt = crate::memory::paging::page_table_from_cr3(cr3);
            crate::memory::paging::translate(&pt, vaddr)
        };

        match phys {
            Some(phys_addr) => {
                let src = (phys_addr + hhdm) as *const u8;
                // SAFETY: phys_addr is from the page table walk (user page is mapped).
                // Adding hhdm gives a valid kernel virtual address. chunk doesn't cross
                // a page boundary. dst has capacity for len bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(src, dst[copied..].as_mut_ptr(), chunk);
                }
                copied += chunk;
            }
            None => return Err(SyscallError::InvalidArg),
        }
    }

    Ok(copied)
}

/// Write bytes from a kernel buffer into a user-space virtual address.
///
/// Walks the process page table (CR3) to translate each page, then
/// writes via HHDM. Returns the number of bytes written.
///
/// # Safety contract
/// `cr3` must be a valid page table root physical address for the calling
/// process (PML4 on x86_64, L0 on AArch64). Target pages must be mapped writable.
fn write_user_buffer(cr3: u64, user_addr: u64, src: &[u8]) -> Result<usize, SyscallError> {
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
    if cr3 == 0 {
        return Err(SyscallError::InvalidArg);
    }

    let hhdm = crate::hhdm_offset();
    let mut written = 0usize;

    while written < len {
        let vaddr = user_addr + written as u64;
        let page_offset = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(len - written, 4096 - page_offset);

        // SAFETY: same as read_user_buffer — cr3 is valid, page table walk is safe.
        let phys = unsafe {
            let pt = crate::memory::paging::page_table_from_cr3(cr3);
            crate::memory::paging::translate(&pt, vaddr)
        };

        match phys {
            Some(phys_addr) => {
                let dst = (phys_addr + hhdm) as *mut u8;
                // SAFETY: phys_addr from page table walk. HHDM maps it to a valid
                // kernel virtual address. The page must be mapped writable (caller's
                // responsibility — user stack and data pages are mapped RW).
                unsafe {
                    core::ptr::copy_nonoverlapping(src[written..].as_ptr(), dst, chunk);
                }
                written += chunk;
            }
            None => return Err(SyscallError::InvalidArg),
        }
    }

    Ok(written)
}

// ============================================================================
// Dispatcher
// ============================================================================

/// Dispatcher that routes syscalls to handlers
pub struct SyscallDispatcher;

impl SyscallDispatcher {
    /// Dispatch a syscall to its handler
    ///
    /// Pipeline: parse number → interceptor check → handler dispatch.
    pub fn dispatch(
        syscall_num: u64,
        args: SyscallArgs,
        ctx: &SyscallContext,
    ) -> SyscallResult {
        let num = match SyscallNumber::from_u64(syscall_num) {
            Some(n) => n,
            None => return Err(SyscallError::Enosys),
        };

        // Zero-trust interceptor: pre-dispatch syscall filter
        {
            let ipc_guard = crate::IPC_MANAGER.lock();
            if let Some(ref ipc_mgr) = *ipc_guard {
                if let Some(interceptor) = ipc_mgr.interceptor() {
                    use crate::ipc::interceptor::InterceptDecision;
                    if let InterceptDecision::Deny(_) = interceptor.on_syscall(ctx.process_id, num) {
                        return Err(SyscallError::PermissionDenied);
                    }
                }
            }
        }

        match num {
            SyscallNumber::Exit => Self::handle_exit(args, ctx),
            SyscallNumber::Write => Self::handle_write(args, ctx),
            SyscallNumber::Read => Self::handle_read(args, ctx),
            SyscallNumber::Allocate => Self::handle_allocate(args, ctx),
            SyscallNumber::Free => Self::handle_free(args, ctx),
            SyscallNumber::WaitIrq => Self::handle_wait_irq(args, ctx),
            SyscallNumber::RegisterEndpoint => Self::handle_register_endpoint(args, ctx),
            SyscallNumber::Yield => Self::handle_yield(args, ctx),
            SyscallNumber::GetPid => Self::handle_get_pid(args, ctx),
            SyscallNumber::GetTime => Self::handle_get_time(args, ctx),
            SyscallNumber::Print => Self::handle_print(args, ctx),
            SyscallNumber::BindPrincipal => Self::handle_bind_principal(args, ctx),
            SyscallNumber::GetPrincipal => Self::handle_get_principal(args, ctx),
            SyscallNumber::RecvMsg => Self::handle_recv_msg(args, ctx),
            SyscallNumber::ObjPut => Self::handle_obj_put(args, ctx),
            SyscallNumber::ObjGet => Self::handle_obj_get(args, ctx),
            SyscallNumber::ObjDelete => Self::handle_obj_delete(args, ctx),
            SyscallNumber::ObjList => Self::handle_obj_list(args, ctx),
            SyscallNumber::ClaimBootstrapKey => Self::handle_claim_bootstrap_key(args, ctx),
            SyscallNumber::ObjPutSigned => Self::handle_obj_put_signed(args, ctx),
            SyscallNumber::MapMmio => Self::handle_map_mmio(args, ctx),
            SyscallNumber::AllocDma => Self::handle_alloc_dma(args, ctx),
            SyscallNumber::DeviceInfo => Self::handle_device_info(args, ctx),
            SyscallNumber::PortIo => Self::handle_port_io(args, ctx),
            SyscallNumber::ConsoleRead => Self::handle_console_read(args, ctx),
            SyscallNumber::Spawn => Self::handle_spawn(args, ctx),
            SyscallNumber::WaitTask => Self::handle_wait_task(args, ctx),
            SyscallNumber::RevokeCapability => Self::handle_revoke_capability(args, ctx),

            // Phase 3.2d.iii: shared-memory channels (ADR-005)
            SyscallNumber::ChannelCreate => Self::handle_channel_create(args, ctx),
            SyscallNumber::ChannelAttach => Self::handle_channel_attach(args, ctx),
            SyscallNumber::ChannelClose => Self::handle_channel_close(args, ctx),
            SyscallNumber::ChannelRevoke => Self::handle_channel_revoke(args, ctx),
            SyscallNumber::ChannelInfo => Self::handle_channel_info(args, ctx),
        }
    }

    // ========================================================================
    // Process lifecycle
    // ========================================================================

    /// SYS_EXIT: Terminate the calling task.
    ///
    /// Marks the task as Terminated, then yields to the scheduler via
    /// `yield_save_and_switch`. The Terminated task is never re-scheduled,
    /// so the yield effectively does not return.
    fn handle_exit(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let exit_code = args.arg1_u32();

        // Lock ordering: PER_CPU_SCHEDULER(1) — no higher locks held
        let parent_to_wake = {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_mut() {
                if let Some(task) = sched.get_task_mut_pub(ctx.task_id) {
                    task.state = crate::scheduler::TaskState::Terminated;
                    task.exit_code = exit_code;
                    task.parent_task
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Wake parent if it's blocked in WaitTask
        if let Some(parent_id) = parent_to_wake {
            crate::wake_task_on_cpu(parent_id);
        }

        // Reclaim capability table entries for the exiting process.
        // Lock ordering: CAPABILITY_MANAGER(4) — SCHEDULER(1) was already
        // released above, so we can safely acquire a higher-numbered lock.
        //
        // Per ADR-007 §"What this gives us", process exit invokes
        // revoke_all_for_process() to prevent stale capabilities from
        // accumulating in the capability table.
        let revoked_count = {
            let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
            if let Some(cap_mgr) = cap_guard.as_mut() {
                cap_mgr.revoke_all_for_process(ctx.process_id).unwrap_or(0)
            } else {
                0
            }
        };

        // Phase 3.2d.iii: revoke all channels the exiting process is
        // party to (as creator or peer). For each revoked channel, unmap
        // pages from the surviving peer, issue TLB shootdown, and free
        // the physical frames.
        //
        // Lock ordering: CHANNEL_MANAGER(5) → PROCESS_TABLE(6) →
        // FRAME_ALLOCATOR(7). CAPABILITY_MANAGER(4) was released above.
        let channels_revoked = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            if let Some(chan_mgr) = chan_guard.as_mut() {
                let (revoked, count) = chan_mgr.revoke_all_for_process(ctx.process_id);
                drop(chan_guard); // release CHANNEL_MANAGER(5) before PROCESS_TABLE(6)

                // Teardown each revoked channel's mappings.
                for record in revoked.iter().take(count).flatten() {
                    Self::teardown_channel_mappings(record);
                }
                count
            } else {
                drop(chan_guard);
                0
            }
        };

        // Reclaim process resources: VMA regions, page table frames, heap.
        //
        // Phase 3.2d.ii: `destroy_process` now calls `reclaim_user_vmas`
        // (unmaps VMA-tracked pages, frees frames), then
        // `reclaim_process_page_tables` (frees PML4/intermediate PT frames),
        // then `reclaim_heap` (frees contiguous heap region).
        //
        // Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7), valid.
        let heap_reclaimed = {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            if let Some(pt) = pt_guard.as_mut() {
                if pt.slot_occupied(ctx.process_id) {
                    let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
                    pt.destroy_process(ctx.process_id, &mut fa_guard);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };

        crate::println!(
            "  [Exit] pid={} task={} code={} (reclaimed {} cap(s), {} chan(s){})",
            ctx.process_id.slot(),
            ctx.task_id.0,
            exit_code,
            revoked_count,
            channels_revoked,
            if heap_reclaimed { ", heap+vma+pt" } else { "" }
        );

        // Yield to next task. Terminated tasks are never re-scheduled,
        // so this loop effectively does not return.
        loop {
            // SAFETY: We are on the kernel stack, scheduler lock is not held.
            // Yield switches to the next runnable task; terminated tasks are
            // never re-enqueued so this loop does not return.
            unsafe { crate::arch::yield_save_and_switch(); }
        }
    }

    // ========================================================================
    // IPC: Write / Read
    // ========================================================================

    /// SYS_WRITE: Send data through an IPC endpoint.
    ///
    /// Args: arg1 = endpoint_id, arg2 = buffer (user vaddr), arg3 = len
    ///
    /// Pipeline: validate args → read user buffer → create Message →
    /// capability check + interceptor check → IPC enqueue.
    fn handle_write(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();
        let user_buf = args.arg2;
        let len = args.arg_usize(3);

        if len == 0 {
            return Ok(0);
        }
        if len > 256 {
            return Err(SyscallError::InvalidArg);
        }

        // Read user buffer into kernel
        let mut kbuf = [0u8; 256];
        read_user_buffer(ctx.cr3, user_buf, len, &mut kbuf)?;

        // Build IPC message
        let endpoint = crate::ipc::EndpointId(endpoint_id);
        let mut msg = crate::ipc::Message::new(
            crate::ipc::EndpointId(ctx.process_id.slot()),
            endpoint,
        );
        if msg.set_payload(&kbuf[..len]).is_err() {
            return Err(SyscallError::InvalidArg);
        }

        // Lock ordering: IPC_MANAGER(3) → CAPABILITY_MANAGER(4)
        let mut ipc_guard = crate::IPC_MANAGER.lock();
        let cap_guard = crate::CAPABILITY_MANAGER.lock();

        let ipc_mgr = ipc_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
        let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

        ipc_mgr
            .send_message_with_capability(ctx.process_id, endpoint, msg, cap_mgr)
            .map_err(|_| SyscallError::PermissionDenied)?;

        // Drop IPC/capability locks before acquiring scheduler (lock ordering)
        drop(cap_guard);
        drop(ipc_guard);

        // Wake any tasks blocked waiting for a message on this endpoint.
        // Lock ordering: PER_CPU_SCHEDULER(1) — no higher locks held.
        {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_mut() {
                sched.wake_message_waiters(endpoint_id);
            }
        }

        Ok(len as u64)
    }

    /// SYS_READ: Receive data from an IPC endpoint.
    ///
    /// Args: arg1 = endpoint_id, arg2 = buffer (user vaddr), arg3 = max_len
    ///
    /// Pipeline: capability check + interceptor check → IPC dequeue →
    /// write payload to user buffer. Returns bytes read (0 if queue empty).
    fn handle_read(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();
        let user_buf = args.arg2;
        let max_len = args.arg_usize(3);

        if max_len == 0 {
            return Ok(0);
        }
        if max_len > 256 {
            return Err(SyscallError::InvalidArg);
        }

        let endpoint = crate::ipc::EndpointId(endpoint_id);

        // Lock ordering: IPC_MANAGER(3) → CAPABILITY_MANAGER(4)
        let mut ipc_guard = crate::IPC_MANAGER.lock();
        let cap_guard = crate::CAPABILITY_MANAGER.lock();

        let ipc_mgr = ipc_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
        let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

        let msg = ipc_mgr
            .recv_message_with_capability(ctx.process_id, endpoint, cap_mgr)
            .map_err(|_| SyscallError::PermissionDenied)?;

        // Drop locks before touching page tables
        drop(cap_guard);
        drop(ipc_guard);

        match msg {
            Some(msg) => {
                let payload = msg.payload();
                let copy_len = core::cmp::min(payload.len(), max_len);

                write_user_buffer(ctx.cr3, user_buf, &payload[..copy_len])?;

                Ok(copy_len as u64)
            }
            None => Ok(0), // No message available
        }
    }

    // ========================================================================
    // Endpoint management
    // ========================================================================

    /// SYS_REGISTER_ENDPOINT: Register a message endpoint for this process.
    ///
    /// Args: arg1 = endpoint_id, arg2 = flags (reserved)
    ///
    /// Grants the calling process full capabilities (send/recv/delegate)
    /// on the specified endpoint.
    fn handle_register_endpoint(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();

        if endpoint_id >= crate::ipc::MAX_ENDPOINTS as u32 {
            return Err(SyscallError::EndpointNotFound);
        }

        let endpoint = crate::ipc::EndpointId(endpoint_id);

        // Lock ordering: CAPABILITY_MANAGER(4)
        let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
        let cap_mgr = cap_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        cap_mgr
            .grant_capability(ctx.process_id, endpoint, crate::ipc::CapabilityRights::FULL)
            .map_err(|_| SyscallError::PermissionDenied)?;

        Ok(0)
    }

    // ========================================================================
    // Memory management
    // ========================================================================

    /// SYS_ALLOCATE: Allocate memory for process.
    ///
    /// Args: arg1 = size, arg2 = flags (reserved)
    ///
    /// Allocates a virtual address region via the process VMA tracker,
    /// allocates physical frames, maps them into the process address space,
    /// and returns the user virtual address.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    ///
    /// Performance: data frames are allocated from the per-CPU cache
    /// (no global lock). FRAME_ALLOCATOR is only locked briefly for
    /// map_page() calls that may need intermediate page table frames.
    fn handle_allocate(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let size = args.arg_usize(1);

        if size == 0 || size > 1024 * 1024 {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let num_pages = size.div_ceil(4096) as u32;

        // Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .ok_or(SyscallError::InvalidArg)?;

        let base_vaddr = vma.allocate_region(num_pages).ok_or(SyscallError::OutOfMemory)?;

        let hhdm = crate::hhdm_offset();

        for i in 0..num_pages as usize {
            let page_vaddr = base_vaddr + (i as u64 * 4096);

            // Allocate data frame from per-CPU cache (fast path: no global lock)
            let frame = match crate::cached_allocate_frame() {
                Ok(f) => f,
                Err(_) => {
                    // Rollback: unmap already-mapped pages and free their frames
                    let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
                    for j in 0..i {
                        let rollback_vaddr = base_vaddr + (j as u64 * 4096);
                        // SAFETY: cr3 is valid, pages were just mapped above.
                        unsafe {
                            let mut pte = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                            if let Ok(freed) = crate::memory::paging::unmap_page(&mut pte, rollback_vaddr) {
                                let _ = fa_guard.free(freed);
                            }
                        }
                    }
                    // Remove the VMA entry we just created
                    if let Some(pt) = pt_guard.as_mut() {
                        if let Some(vma) = pt.vma_mut(ctx.process_id) {
                            vma.free_region(base_vaddr);
                        }
                    }
                    return Err(SyscallError::OutOfMemory);
                }
            };

            // Zero the frame
            // SAFETY: Freshly allocated frame, HHDM-mapped.
            unsafe {
                core::ptr::write_bytes((frame.addr + hhdm) as *mut u8, 0, 4096);
            }

            // Map into process page table
            // FRAME_ALLOCATOR only needed here for potential page table frame alloc
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            // SAFETY: cr3 is valid (non-zero, checked above). Frame is fresh.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_page(
                    &mut pt,
                    page_vaddr,
                    frame.addr,
                    crate::memory::paging::flags::user_rw(),
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
            drop(fa_guard); // Release between loop iterations
        }

        Ok(base_vaddr)
    }

    /// SYS_FREE: Free allocated memory.
    ///
    /// Args: arg1 = ptr (user vaddr), arg2 = size (ignored — VMA tracks actual size)
    ///
    /// Looks up the allocation in the process VMA tracker, unmaps all pages,
    /// returns physical frames to the allocator, and removes the VMA entry.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_free(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let ptr = args.arg1;

        if ptr == 0 {
            return Err(SyscallError::InvalidArg);
        }
        if ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma_entry = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .and_then(|vma| vma.free_region(ptr))
            .ok_or(SyscallError::InvalidArg)?;

        // Unmap each page and return frame to per-CPU cache (fast path)
        for i in 0..vma_entry.num_pages as u64 {
            let page_vaddr = vma_entry.base_vaddr + i * 4096;
            // SAFETY: cr3 is valid (non-zero, checked above). These pages were
            // mapped by handle_allocate and recorded in the VMA tracker.
            unsafe {
                let mut pte = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                if let Ok(freed_frame) = crate::memory::paging::unmap_page(&mut pte, page_vaddr) {
                    let _ = crate::cached_free_frame(freed_frame);
                }
            }
        }

        Ok(0)
    }

    // ========================================================================
    // Scheduling
    // ========================================================================

    /// SYS_YIELD: Voluntarily yield CPU to the scheduler.
    ///
    /// Performs an immediate voluntary context switch via `yield_save_and_switch`.
    /// The scheduler moves the Running task to Ready, picks the next task, and
    /// switches. When this task is re-scheduled, execution resumes here and
    /// returns Ok(0) to user space.
    fn handle_yield(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        // Don't change task state — yield_save_and_switch calls schedule(),
        // which correctly moves Running → Ready and re-enqueues.
        // SAFETY: We are on the kernel stack, scheduler lock is not held.
        unsafe { crate::arch::yield_save_and_switch(); }
        Ok(0)
    }

    /// SYS_WAIT_IRQ: Block until a specific hardware interrupt fires.
    ///
    /// Args: arg1 = irq_number
    ///
    /// Registers the task as the handler for the given IRQ (if not already
    /// registered), blocks until the IRQ fires, then returns. Uses the
    /// restart pattern: block → yield → return on wake.
    fn handle_wait_irq(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let irq_num = args.arg1_u32();

        if irq_num >= MAX_DEVICE_IRQ {
            return Err(SyscallError::InvalidArg);
        }

        // Register this task as the IRQ handler and pin to this CPU (one-time setup).
        // Lock ordering: PER_CPU_SCHEDULER(1) → INTERRUPT_ROUTER(8)
        {
            let mut sched_guard = crate::local_scheduler().lock();
            let mut router_guard = crate::INTERRUPT_ROUTER.lock();

            let irq = crate::interrupts::routing::IrqNumber(irq_num as u8);
            let _ = router_guard.register(irq, ctx.task_id, 128);

            if let Some(sched) = sched_guard.as_mut() {
                if let Some(task) = sched.get_task_mut_pub(ctx.task_id) {
                    task.pinned = true;
                }

                // Re-route device IRQ to this CPU via I/O APIC (x86_64) or GIC SPI (AArch64)
                #[cfg(target_arch = "x86_64")]
                {
                    // SAFETY: GS base is valid after percpu_init; reading APIC ID is a
                    // pure read from the per-CPU data structure.
                    let local_apic_id = unsafe {
                        crate::arch::x86_64::percpu::current_percpu().apic_id() as u8
                    };
                    // SAFETY: I/O APIC is initialized before user tasks run.
                    unsafe {
                        crate::arch::x86_64::ioapic::set_irq_destination(irq_num, local_apic_id);
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    if irq_num >= 32 {
                        // SAFETY: GIC distributor is initialized before user tasks run.
                        unsafe { crate::arch::aarch64::gic::enable_spi(irq_num); }
                    }
                }
            }
            // Drop locks before yield
        }

        // Block and yield. The device ISR wakes this task (IoWait → Ready).
        // CRITICAL: Disable interrupts before block_task to prevent the timer
        // ISR from seeing Blocked state before yield_save_and_switch saves context.
        // See handle_recv_msg for detailed race explanation.
        // SAFETY: Disabling interrupts is safe at kernel privilege level.
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
        {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_mut() {
                let _ = sched.block_task(
                    ctx.task_id,
                    crate::scheduler::BlockReason::IoWait(irq_num),
                );
            }
            // IrqSpinlock drop: restores IF to disabled (our cli)
        }
        // SAFETY: We are on the kernel stack, scheduler lock is not held.
        unsafe { crate::arch::yield_save_and_switch(); }
        // Woken by device ISR — IRQ has fired
        Ok(0)
    }

    // ========================================================================
    // Info syscalls
    // ========================================================================

    /// SYS_GET_PID: Get current process ID
    fn handle_get_pid(_args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        Ok(ctx.process_id.slot() as u64)
    }

    /// SYS_GET_TIME: Get system time in ticks
    fn handle_get_time(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        let ticks = crate::scheduler::Timer::get_ticks();
        Ok(ticks)
    }

    /// SYS_PRINT: Print a user-provided string to serial console.
    ///
    /// Args: arg1 = buffer pointer (user vaddr), arg2 = length
    fn handle_print(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let user_buf = args.arg1;
        let len = args.arg_usize(2);

        if len == 0 {
            return Ok(0);
        }
        if len > 256 {
            return Err(SyscallError::InvalidArg);
        }

        let mut buf = [0u8; 256];
        read_user_buffer(ctx.cr3, user_buf, len, &mut buf)?;

        for &byte in &buf[..len] {
            crate::io::print(format_args!("{}", byte as char));
        }

        Ok(len as u64)
    }

    // ========================================================================
    // Identity syscalls
    // ========================================================================

    /// SYS_BIND_PRINCIPAL: Bind a cryptographic Principal to a process.
    ///
    /// Args: arg1 = target process_id, arg2 = pubkey_ptr (user vaddr),
    ///        arg3 = pubkey_len (must be 32)
    ///
    /// Restricted: only the bootstrap Principal can call this. This is the
    /// identity service's privilege — it binds Principals to processes on
    /// behalf of the system.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) only.
    fn handle_bind_principal(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let target_pid = args.arg1_u32();
        let pubkey_ptr = args.arg2;
        let pubkey_len = args.arg_usize(3);

        // Public key must be exactly 32 bytes (Ed25519)
        if pubkey_len != 32 {
            return Err(SyscallError::InvalidArg);
        }

        // Read the 32-byte public key from user buffer
        let mut pubkey = [0u8; 32];
        read_user_buffer(ctx.cr3, pubkey_ptr, 32, &mut pubkey)?;

        // Restriction: only the bootstrap Principal can bind Principals.
        // Check caller's own Principal against the global bootstrap Principal.
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

            let caller_principal = cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::PermissionDenied)?;

            let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
            if caller_principal != bootstrap {
                return Err(SyscallError::PermissionDenied);
            }
        }

        // Bind the Principal to the target process
        let target = ProcessId::new(target_pid, 0);
        let principal = crate::ipc::Principal::from_public_key(pubkey);

        let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
        let cap_mgr = cap_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        cap_mgr
            .bind_principal(target, principal)
            .map_err(|_| SyscallError::PermissionDenied)?;

        Ok(0)
    }

    /// SYS_GET_PRINCIPAL: Read the calling process's bound Principal.
    ///
    /// Args: arg1 = out_buf (user vaddr), arg2 = buf_len (must be >= 32)
    ///
    /// Writes 32 bytes of public key to the user buffer. Returns 32 on
    /// success, or error if no Principal is bound to this process.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) only.
    fn handle_get_principal(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let out_buf = args.arg1;
        let buf_len = args.arg_usize(2);

        if buf_len < 32 {
            return Err(SyscallError::InvalidArg);
        }

        // Look up caller's Principal
        let principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

            cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::InvalidArg)?
        };

        // Write the 32-byte public key to user buffer
        write_user_buffer(ctx.cr3, out_buf, &principal.public_key)?;

        Ok(32)
    }

    // ========================================================================
    // IPC: RecvMsg (identity-aware receive)
    // ========================================================================

    /// SYS_RECV_MSG: Receive an IPC message with sender identity metadata.
    ///
    /// Args: arg1 = endpoint_id, arg2 = buf (user vaddr), arg3 = buf_len
    ///
    /// Writes to buf: [sender_principal:32][from_endpoint_le:4][payload:N]
    /// Returns total bytes written (36 + payload_len), 0 if no message.
    ///
    /// Lock ordering: IPC_MANAGER(3) → CAPABILITY_MANAGER(4), then page tables.
    fn handle_recv_msg(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();
        let user_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        // Need at least 36 bytes for header (32 principal + 4 endpoint)
        if buf_len < 36 {
            return Err(SyscallError::InvalidArg);
        }

        let endpoint = crate::ipc::EndpointId(endpoint_id);

        // Restart loop: try to receive, block + yield if empty, re-check on wake.
        // Eliminates the two-step wake pattern — user space gets the message
        // directly without needing to retry.
        loop {
            // Lock ordering: IPC_MANAGER(3) → CAPABILITY_MANAGER(4)
            let msg = {
                let mut ipc_guard = crate::IPC_MANAGER.lock();
                let cap_guard = crate::CAPABILITY_MANAGER.lock();

                let ipc_mgr = ipc_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
                let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

                ipc_mgr
                    .recv_message_with_capability(ctx.process_id, endpoint, cap_mgr)
                    .map_err(|_| SyscallError::PermissionDenied)?
                // Drop IPC/capability locks here
            };

            if let Some(msg) = msg {
                let payload = msg.payload();
                let payload_len = core::cmp::min(payload.len(), buf_len - 36);

                // Build response: [principal:32][from:4][payload:N]
                let mut header = [0u8; 36];

                if let Some(principal) = msg.sender_principal {
                    header[0..32].copy_from_slice(&principal.public_key);
                }
                header[32..36].copy_from_slice(&msg.from.0.to_le_bytes());

                write_user_buffer(ctx.cr3, user_buf, &header)?;
                if payload_len > 0 {
                    write_user_buffer(ctx.cr3, user_buf + 36, &payload[..payload_len])?;
                }

                return Ok((36 + payload_len) as u64);
            }

            // No message — block and yield. The IPC send path
            // (handle_write) calls wake_message_waiters() after enqueue.
            //
            // CRITICAL: Disable interrupts BEFORE block_task to prevent a
            // race with the timer ISR. If the ISR fires between block_task
            // (state=Blocked) and yield_save_and_switch (saves saved_rsp),
            // the ISR skips saving RSP (because !Running), leaving stale
            // saved_rsp. When the task is later woken, iretq restores from
            // garbage → triple fault. cli ensures the ISR cannot observe
            // the Blocked state before yield saves the correct context.
            // IrqSpinlock preserves the disabled state on drop.
            // yield_save_and_switch also does cli (redundant) then saves
            // and switches. .Lyield_resume does sti on wake.
            // SAFETY: Disabling interrupts is safe at kernel privilege level.
            #[cfg(target_arch = "x86_64")]
            unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
            #[cfg(target_arch = "aarch64")]
            unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
            {
                let mut sched_guard = crate::local_scheduler().lock();
                if let Some(sched) = sched_guard.as_mut() {
                    let _ = sched.block_task(
                        ctx.task_id,
                        crate::scheduler::BlockReason::MessageWait(endpoint_id),
                    );
                }
                // IrqSpinlock drop: restores IF to our cli state (disabled)
            }
            // Interrupts still disabled — yield_save_and_switch saves
            // correct context before any ISR can see the Blocked state.
            // SAFETY: We are on the kernel stack, scheduler lock is not held.
            unsafe { crate::arch::yield_save_and_switch(); }
            // Woken — loop back and re-check the queue
        }
    }

    // ========================================================================
    // ObjectStore syscalls
    // ========================================================================

    /// SYS_OBJ_PUT: Store an ArcObject in the object store.
    ///
    /// Args: arg1 = content_ptr (user vaddr), arg2 = content_len, arg3 = out_hash (user vaddr)
    ///
    /// Creates an ArcObject with author/owner = caller's Principal.
    /// Writes 32-byte content hash to out_hash. Returns 0 on success.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) then OBJECT_STORE(9) — sequential, not nested.
    fn handle_obj_put(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let content_ptr = args.arg1;
        let content_len = args.arg_usize(2);
        let out_hash = args.arg3;

        if content_len == 0 || content_len > MAX_USER_BUFFER {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Read content from user buffer
        let mut kbuf = [0u8; 4096];
        let copied = read_user_buffer(ctx.cr3, content_ptr, content_len, &mut kbuf)?;

        // Get caller's Principal (required — anonymous puts are not allowed)
        let principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::PermissionDenied)?
        };

        // Get current time for created_at
        let ticks = crate::scheduler::Timer::get_ticks();

        // Create ArcObject with caller as author and owner
        let content_vec = {
            extern crate alloc;
            let mut v = alloc::vec::Vec::with_capacity(copied);
            v.extend_from_slice(&kbuf[..copied]);
            v
        };
        let obj = crate::fs::ArcObject::new(principal, content_vec, ticks);
        let hash = obj.content_hash;

        // Store in OBJECT_STORE (lock position 8)
        let mut store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        use crate::fs::ObjectStore;
        store.put(obj).map_err(|e| match e {
            crate::fs::StoreError::CapacityExceeded => SyscallError::OutOfMemory,
            crate::fs::StoreError::InvalidObject => SyscallError::InvalidArg,
            _ => SyscallError::InvalidArg,
        })?;
        drop(store_guard);

        // Write hash to user buffer
        write_user_buffer(ctx.cr3, out_hash, &hash)?;

        Ok(0)
    }

    /// SYS_OBJ_GET: Retrieve object content by content hash.
    ///
    /// Args: arg1 = hash_ptr (user vaddr, 32 bytes), arg2 = out_buf, arg3 = out_buf_len
    ///
    /// Returns bytes written on success, or negative error.
    /// Verifies the object's Ed25519 signature before returning content.
    /// Objects with empty (unsigned) signatures are returned without verification
    /// (graceful degradation for legacy/unsigned objects).
    ///
    /// Lock ordering: OBJECT_STORE(9) only.
    fn handle_obj_get(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let hash_ptr = args.arg1;
        let out_buf = args.arg2;
        let out_buf_len = args.arg_usize(3);

        if out_buf_len == 0 || ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Read 32-byte hash from user
        let mut hash = [0u8; 32];
        read_user_buffer(ctx.cr3, hash_ptr, 32, &mut hash)?;

        // Look up in OBJECT_STORE
        let store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

        use crate::fs::ObjectStore;
        let obj = store.get(&hash).map_err(|e| match e {
            crate::fs::StoreError::NotFound => SyscallError::EndpointNotFound,
            _ => SyscallError::InvalidArg,
        })?;

        // Verify signature if the object is signed (non-empty signature).
        // Unsigned objects (empty signature) are returned as-is for backward
        // compatibility — the caller can check the signature field if needed.
        if !obj.signature.is_empty_sig()
            && !crate::fs::verify_signature(&obj.owner, &obj.content, &obj.signature) {
                drop(store_guard);
                return Err(SyscallError::PermissionDenied);
            }

        let copy_len = core::cmp::min(obj.content.len(), out_buf_len);
        let content_slice = &obj.content[..copy_len];

        // Must copy before dropping lock (can't hold reference across drop)
        let mut kbuf = [0u8; 4096];
        kbuf[..copy_len].copy_from_slice(content_slice);
        drop(store_guard);

        write_user_buffer(ctx.cr3, out_buf, &kbuf[..copy_len])?;

        Ok(copy_len as u64)
    }

    /// SYS_OBJ_DELETE: Delete an object from the store.
    ///
    /// Args: arg1 = hash_ptr (user vaddr, 32 bytes)
    ///
    /// Only the object's owner can delete. Returns 0 on success.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) then OBJECT_STORE(9) — sequential.
    fn handle_obj_delete(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let hash_ptr = args.arg1;

        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Read 32-byte hash from user
        let mut hash = [0u8; 32];
        read_user_buffer(ctx.cr3, hash_ptr, 32, &mut hash)?;

        // Get caller's Principal
        let principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::PermissionDenied)?
        };

        // Check ownership then delete
        let mut store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        use crate::fs::ObjectStore;

        // Verify caller is owner before deleting
        {
            let obj = store.get(&hash).map_err(|_| SyscallError::EndpointNotFound)?;
            if obj.owner != principal.public_key {
                return Err(SyscallError::PermissionDenied);
            }
        }

        store.delete(&hash).map_err(|_| SyscallError::EndpointNotFound)?;

        Ok(0)
    }

    /// SYS_OBJ_LIST: List all object hashes in the store.
    ///
    /// Args: arg1 = out_buf (user vaddr), arg2 = out_buf_len
    ///
    /// Writes packed 32-byte hashes. Returns number of objects listed.
    ///
    /// Lock ordering: OBJECT_STORE(9) only.
    fn handle_obj_list(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let out_buf = args.arg1;
        let out_buf_len = args.arg_usize(2);

        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let max_objects = out_buf_len / 32;
        if max_objects == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

        use crate::fs::ObjectStore;
        let listing = store.list().map_err(|_| SyscallError::InvalidArg)?;
        drop(store_guard);

        let count = core::cmp::min(listing.len(), max_objects);

        // Write packed hashes to user buffer
        for (i, (hash, _meta)) in listing.iter().take(count).enumerate() {
            let offset = (i * 32) as u64;
            write_user_buffer(ctx.cr3, out_buf + offset, hash)?;
        }

        Ok(count as u64)
    }

    // ========================================================================
    // Key Store syscalls
    // ========================================================================

    /// SYS_CLAIM_BOOTSTRAP_KEY: One-shot delivery of the bootstrap secret key.
    ///
    /// Args: arg1 = out_sk_ptr (user vaddr, must hold 64 bytes)
    ///
    /// Writes the 64-byte Ed25519 secret key to the caller's buffer, then
    /// permanently zeroes the kernel's copy. Restricted to the bootstrap
    /// Principal. Fails if the key has already been claimed.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) only (BOOTSTRAP_SECRET_KEY is
    /// independent of the lock hierarchy — single atomic claim operation).
    fn handle_claim_bootstrap_key(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let out_sk_ptr = args.arg1;

        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Verify caller holds the bootstrap Principal
        let principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::PermissionDenied)?
        };

        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        if principal != bootstrap {
            return Err(SyscallError::PermissionDenied);
        }

        // Claim the key (one-shot: returns None if already claimed)
        let sk = crate::BOOTSTRAP_SECRET_KEY
            .claim()
            .ok_or(SyscallError::PermissionDenied)?;

        // Write 64-byte secret key to user buffer
        write_user_buffer(ctx.cr3, out_sk_ptr, &sk)?;

        crate::println!("  [ClaimBootstrapKey] pid={} — key claimed, kernel copy zeroed", ctx.process_id.slot());

        Ok(64)
    }

    /// SYS_OBJ_PUT_SIGNED: Store a pre-signed ArcObject.
    ///
    /// Args: arg1 = content_ptr, arg2 = content_len, arg3 = sig_ptr (64 bytes),
    ///        arg4 = out_hash_ptr (32 bytes)
    ///
    /// Like ObjPut but accepts a pre-computed Ed25519 signature. The kernel
    /// verifies the signature against the caller's Principal before storing.
    /// This is the path for signed objects when the key-store service holds
    /// the private key.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) then OBJECT_STORE(9) — sequential.
    fn handle_obj_put_signed(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let content_ptr = args.arg1;
        let content_len = args.arg_usize(2);
        let sig_ptr = args.arg3;
        let out_hash = args.arg4;

        if content_len == 0 || content_len > MAX_USER_BUFFER {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Read content from user buffer
        let mut kbuf = [0u8; 4096];
        let copied = read_user_buffer(ctx.cr3, content_ptr, content_len, &mut kbuf)?;

        // Read 64-byte signature from user buffer
        let mut sig_bytes = [0u8; 64];
        read_user_buffer(ctx.cr3, sig_ptr, 64, &mut sig_bytes)?;
        let signature = crate::fs::SignatureBytes { data: sig_bytes };

        // Get caller's Principal
        let principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::PermissionDenied)?
        };

        // Verify the signature against the caller's Principal and content
        if !crate::fs::verify_signature(&principal.public_key, &kbuf[..copied], &signature) {
            return Err(SyscallError::PermissionDenied);
        }

        // Get current time for created_at
        let ticks = crate::scheduler::Timer::get_ticks();

        // Create ArcObject with the verified signature
        let content_vec = {
            extern crate alloc;
            let mut v = alloc::vec::Vec::with_capacity(copied);
            v.extend_from_slice(&kbuf[..copied]);
            v
        };
        let mut obj = crate::fs::ArcObject::new(principal, content_vec, ticks);
        obj.signature = signature;
        let hash = obj.content_hash;

        // Store in OBJECT_STORE (lock position 8)
        let mut store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        use crate::fs::ObjectStore;
        store.put(obj).map_err(|e| match e {
            crate::fs::StoreError::CapacityExceeded => SyscallError::OutOfMemory,
            crate::fs::StoreError::InvalidObject => SyscallError::InvalidArg,
            _ => SyscallError::InvalidArg,
        })?;
        drop(store_guard);

        // Write hash to user buffer
        write_user_buffer(ctx.cr3, out_hash, &hash)?;

        Ok(0)
    }

    // ========================================================================
    // Device / DMA support
    // ========================================================================

    /// SYS_MAP_MMIO: Map device MMIO into user-space.
    ///
    /// Args: arg1 = physical address (page-aligned), arg2 = num_pages
    ///
    /// Maps a device MMIO region into the calling process with uncacheable
    /// page attributes. The kernel validates the physical address is not in
    /// a RAM region (only device MMIO ranges are permitted).
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_map_mmio(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let phys_addr = args.arg1;
        let num_pages = args.arg2_u32();

        if num_pages == 0 || num_pages > 256 {
            return Err(SyscallError::InvalidArg);
        }
        if phys_addr & 0xFFF != 0 {
            return Err(SyscallError::InvalidArg); // Must be page-aligned
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Security: reject mapping RAM regions as MMIO.
        // MMIO should be above RAM or in known device ranges.
        // On x86_64 QEMU, RAM is typically 0..128MB. Device MMIO is above 0xFE00_0000.
        // We reject anything in the frame allocator's tracked range as a conservative check.
        {
            let fa_guard = crate::FRAME_ALLOCATOR.lock();
            let max_ram = fa_guard.total_count() as u64 * 4096;
            if phys_addr < max_ram {
                return Err(SyscallError::PermissionDenied);
            }
        }

        // Allocate virtual address range via VMA tracker
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .ok_or(SyscallError::InvalidArg)?;

        let base_vaddr = vma
            .allocate_region(num_pages)
            .ok_or(SyscallError::OutOfMemory)?;

        // Map each page with uncacheable (MMIO) flags
        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
        for i in 0..num_pages as u64 {
            let page_vaddr = base_vaddr + i * 4096;
            let page_phys = phys_addr + i * 4096;

            // SAFETY: cr3 is valid, phys_addr is validated above.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_page(
                    &mut pt,
                    page_vaddr,
                    page_phys,
                    crate::memory::paging::flags::user_mmio(),
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
        }
        drop(fa_guard);
        drop(pt_guard);

        Ok(base_vaddr)
    }

    /// SYS_ALLOC_DMA: Allocate physically contiguous DMA-capable pages.
    ///
    /// Args: arg1 = num_pages, arg2 = flags (reserved), arg3 = out_paddr_ptr
    ///
    /// Allocates contiguous physical frames with guard pages (unmapped pages
    /// on both sides) to contain device overflows. Maps into the calling
    /// process and writes the physical address to *out_paddr_ptr.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_alloc_dma(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let num_pages = args.arg1_u32();
        let _flags = args.arg2_u32(); // Reserved for IOMMU hints
        let out_paddr_ptr = args.arg3;

        if num_pages == 0 || num_pages > 64 {
            return Err(SyscallError::InvalidArg);
        }
        if out_paddr_ptr == 0 || out_paddr_ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Allocate contiguous physical frames
        let base_frame = {
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            fa_guard
                .allocate_contiguous(num_pages as usize)
                .map_err(|_| SyscallError::OutOfMemory)?
        };
        let base_phys = base_frame.addr;

        // Allocate virtual address range: num_pages + 2 guard pages (before/after)
        let total_pages = num_pages + 2;
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .ok_or(SyscallError::InvalidArg)?;

        let region_vaddr = vma
            .allocate_region(total_pages)
            .ok_or(SyscallError::OutOfMemory)?;

        // The actual DMA mapping starts after the first guard page
        let dma_vaddr = region_vaddr + 4096;

        let hhdm = crate::hhdm_offset();
        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();

        // Map the DMA pages (guard pages at region_vaddr and region_vaddr + (num_pages+1)*4096
        // are left unmapped — any device overflow faults into unmapped memory)
        for i in 0..num_pages as u64 {
            let page_vaddr = dma_vaddr + i * 4096;
            let page_phys = base_phys + i * 4096;

            // Zero the frame
            // SAFETY: Freshly allocated contiguous frame, HHDM-mapped.
            unsafe {
                core::ptr::write_bytes((page_phys + hhdm) as *mut u8, 0, 4096);
            }

            // SAFETY: cr3 is valid, frame is fresh.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_page(
                    &mut pt,
                    page_vaddr,
                    page_phys,
                    crate::memory::paging::flags::user_rw(),
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
        }
        drop(fa_guard);
        drop(pt_guard);

        // Write physical address to user buffer
        let paddr_bytes = base_phys.to_le_bytes();
        write_user_buffer(ctx.cr3, out_paddr_ptr, &paddr_bytes)?;

        Ok(dma_vaddr)
    }

    /// SYS_DEVICE_INFO: Query PCI device info by index.
    ///
    /// Args: arg1 = device index, arg2 = out_buf ptr, arg3 = buf_len
    ///
    /// Writes a fixed-format device descriptor to the user buffer:
    ///   [vendor_id:2][device_id:2][class:1][subclass:1][bus:1][device:1]
    ///   [function:1][pad:1][bar_count:1][pad:1]
    ///   [bar0_addr:8][bar0_size:4][pad:4] × 6
    /// Total: 12 + 6×16 = 108 bytes
    #[cfg(target_arch = "x86_64")]
    fn handle_device_info(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let index = args.arg1_u32() as usize;
        let out_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        const DESCRIPTOR_SIZE: usize = 108;

        if buf_len < DESCRIPTOR_SIZE {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let dev = crate::pci::get_device(index).ok_or(SyscallError::InvalidArg)?;

        let mut desc = [0u8; DESCRIPTOR_SIZE];
        // Header: vendor, device, class, subclass, bus, dev, func, pad, bar_count, pad
        desc[0..2].copy_from_slice(&dev.vendor_id.to_le_bytes());
        desc[2..4].copy_from_slice(&dev.device_id.to_le_bytes());
        desc[4] = dev.class;
        desc[5] = dev.subclass;
        desc[6] = dev.bus;
        desc[7] = dev.device;
        desc[8] = dev.function;
        desc[9] = 0; // pad
        // Count non-zero BARs
        desc[10] = dev.bars.iter().filter(|&&b| b != 0).count() as u8;
        desc[11] = 0; // pad

        // BARs: 6 × [addr:8][size:4][is_io:1][pad:3]
        for i in 0..6 {
            let offset = 12 + i * 16;
            desc[offset..offset + 8].copy_from_slice(&dev.bars[i].to_le_bytes());
            desc[offset + 8..offset + 12].copy_from_slice(&dev.bar_sizes[i].to_le_bytes());
            desc[offset + 12] = if dev.bar_is_io[i] { 1 } else { 0 };
            // remaining pad bytes already zero
        }

        write_user_buffer(ctx.cr3, out_buf, &desc)?;

        Ok(0)
    }

    /// SYS_DEVICE_INFO stub for non-x86_64 targets (PCI not yet supported).
    #[cfg(not(target_arch = "x86_64"))]
    fn handle_device_info(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    /// SYS_PORT_IO: Validated port I/O from user-space.
    ///
    /// Args: arg1 = port (u16), arg2 = value (for writes), arg3 = flags
    ///   flags bit 0: 0=read, 1=write
    ///   flags bits 2:1: 0=byte, 1=word, 2=dword
    ///
    /// The kernel validates the port is within a PCI device's I/O BAR range
    /// before performing the operation. This prevents user-space from accessing
    /// arbitrary ports (PIC, PIT, PCI config space, etc.).
    #[cfg(target_arch = "x86_64")]
    fn handle_port_io(args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        let port = args.arg1 as u16;
        let value = args.arg2 as u32;
        let flags = args.arg3 as u32;
        let is_write = (flags & 1) != 0;
        let width = (flags >> 1) & 0x3; // 0=byte, 1=word, 2=dword

        // Validate port is within a PCI device I/O BAR
        if !crate::pci::is_port_in_pci_bar(port) {
            return Err(SyscallError::PermissionDenied);
        }

        // Validate width alignment
        match width {
            1 if port & 1 != 0 => return Err(SyscallError::InvalidArg), // word: 2-byte aligned
            2 if port & 3 != 0 => return Err(SyscallError::InvalidArg), // dword: 4-byte aligned
            0..=2 => {}
            _ => return Err(SyscallError::InvalidArg),
        }

        if is_write {
            match width {
                0 => {
                    // SAFETY: Port validated against PCI I/O BARs above.
                    let p = unsafe { crate::arch::x86_64::portio::Port8::new(port) };
                    p.write(value as u8);
                }
                1 => {
                    // SAFETY: Port validated, 2-byte aligned.
                    let p = unsafe { crate::arch::x86_64::portio::Port16::new(port) };
                    p.write(value as u16);
                }
                2 => {
                    // SAFETY: Port validated, 4-byte aligned. Use inline asm for 32-bit.
                    unsafe {
                        core::arch::asm!(
                            "out dx, eax",
                            in("dx") port,
                            in("eax") value,
                            options(nomem, nostack, preserves_flags),
                        );
                    }
                }
                _ => unreachable!(),
            }
            Ok(0)
        } else {
            let result = match width {
                0 => {
                    // SAFETY: Port validated against PCI I/O BARs above.
                    let p = unsafe { crate::arch::x86_64::portio::Port8::new(port) };
                    p.read() as u64
                }
                1 => {
                    // SAFETY: Port validated, 2-byte aligned.
                    let p = unsafe { crate::arch::x86_64::portio::Port16::new(port) };
                    p.read() as u64
                }
                2 => {
                    let v: u32;
                    // SAFETY: Port validated against PCI BAR, 4-byte aligned. 32-bit IN instruction.
                    unsafe {
                        core::arch::asm!(
                            "in eax, dx",
                            in("dx") port,
                            out("eax") v,
                            options(nomem, nostack, preserves_flags),
                        );
                    }
                    v as u64
                }
                _ => unreachable!(),
            };
            Ok(result)
        }
    }

    /// SYS_PORT_IO stub for non-x86_64 targets.
    #[cfg(not(target_arch = "x86_64"))]
    fn handle_port_io(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    // ========================================================================
    // Shell / interactive: ConsoleRead, Spawn, WaitTask
    // ========================================================================

    /// SYS_CONSOLE_READ: Read bytes from the serial console (polling mode).
    ///
    /// Args: arg1 = user buffer pointer, arg2 = max_len
    /// Returns: number of bytes read (0 if no data available)
    fn handle_console_read(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let user_buf = args.arg1;
        let max_len = args.arg_usize(2);

        if max_len == 0 {
            return Ok(0);
        }
        if max_len > MAX_USER_BUFFER {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Try to read one byte (polling — non-blocking)
        match crate::io::read_byte() {
            Some(byte) => {
                // Write the byte to user buffer
                let kbuf = [byte];
                write_user_buffer(ctx.cr3, user_buf, &kbuf)?;
                Ok(1)
            }
            None => Ok(0),
        }
    }

    /// SYS_SPAWN: Spawn a boot module by name.
    ///
    /// Args: arg1 = name_ptr (user), arg2 = name_len
    /// Returns: new task ID on success, negative error otherwise.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7), then
    /// CAPABILITY_MANAGER(4) separately after dropping the first two.
    fn handle_spawn(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::loader::{self, SignedBinaryVerifier};
        use crate::scheduler::Priority;
        use crate::ipc::capability::CapabilityKind;

        let name_ptr = args.arg1;
        let name_len = args.arg_usize(2);

        if name_len == 0 || name_len > 64 {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Phase 3.2b (ADR-008): check CreateProcess authority before any
        // resource allocation. CAPABILITY_MANAGER lock level = 4, no
        // other locks held yet.
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            if let Some(cap_mgr) = cap_guard.as_ref() {
                let has_right = cap_mgr
                    .has_system_capability(ctx.process_id, CapabilityKind::CreateProcess)
                    .unwrap_or(false);
                if !has_right {
                    return Err(SyscallError::PermissionDenied);
                }
            }
        }

        // Read module name from user memory
        let mut name_buf = [0u8; 64];
        read_user_buffer(ctx.cr3, name_ptr, name_len, &mut name_buf)?;
        let name = &name_buf[..name_len];

        // Look up module in boot module registry
        let (module_addr, module_size) = crate::BOOT_MODULE_REGISTRY
            .lock()
            .find_by_name(name)
            .ok_or(SyscallError::InvalidArg)?;

        // SAFETY: module_addr points to Limine EXECUTABLE_AND_MODULES memory,
        // which is valid for the kernel's lifetime via HHDM.
        let binary = unsafe { core::slice::from_raw_parts(module_addr, module_size) };

        // Use signed verifier with bootstrap key
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        let verifier = SignedBinaryVerifier::with_key(bootstrap.public_key);

        // Lock ordering: SCHEDULER(1) → PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
        let mut sched_guard = crate::local_scheduler().lock();
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();

        let sched = sched_guard.as_mut().ok_or(SyscallError::OutOfMemory)?;
        let pt = pt_guard.as_mut().ok_or(SyscallError::OutOfMemory)?;

        // Phase 3.2c: process table allocates the slot internally;
        // ProcessId returned in the result.
        let result = loader::load_elf_process(
            binary,
            Priority::NORMAL,
            &verifier,
            pt,
            &mut fa_guard,
            sched,
        ).map_err(|_| SyscallError::OutOfMemory)?;

        let process_id = result.process_id;

        let new_task_id = result.task_id;

        // Set parent on the new task so handle_exit can wake us
        if let Some(task) = sched.get_task_mut_pub(new_task_id) {
            task.parent_task = Some(ctx.task_id);
        }

        // Register task in CPU map
        let cpu_id = {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: GS base is valid after percpu_init; pure read from per-CPU data.
            { unsafe { crate::arch::x86_64::percpu::current_percpu().cpu_id() } }
            #[cfg(target_arch = "aarch64")]
            // SAFETY: TPIDR_EL1 base is valid after percpu_init; pure read from per-CPU data.
            { unsafe { crate::arch::aarch64::percpu::current_percpu().cpu_id() } }
        };
        crate::set_task_cpu(new_task_id.0, cpu_id as u16);

        // Drop all locks before acquiring CAPABILITY_MANAGER(4)
        // Note: CAPABILITY_MANAGER is level 4, lower than SCHEDULER(1), but
        // we already released SCHEDULER. The ordering constraint is about
        // simultaneous holding, not sequential acquisition.
        drop(sched_guard);
        drop(fa_guard);
        drop(pt_guard);

        // Register capabilities for the new process (CAPABILITY_MANAGER lock = level 4)
        {
            let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
            if let Some(cap_mgr) = cap_guard.as_mut() {
                let _ = cap_mgr.register_process(process_id);
                // Grant send/receive on all endpoints (spawned processes are trusted boot modules)
                for ep in 0..crate::ipc::MAX_ENDPOINTS as u32 {
                    let _ = cap_mgr.grant_capability(
                        process_id,
                        crate::ipc::EndpointId(ep),
                        crate::ipc::CapabilityRights { send: true, receive: true, delegate: false, revoke: false },
                    );
                }
                // Phase 3.2b (ADR-008): spawned processes inherit
                // CreateProcess (trusted boot modules only for now).
                let _ = cap_mgr.grant_system_capability(
                    process_id,
                    CapabilityKind::CreateProcess,
                );
                // Phase 3.2d.iv (ADR-005): spawned processes may create channels.
                let _ = cap_mgr.grant_system_capability(
                    process_id,
                    CapabilityKind::CreateChannel,
                );
                // Bind bootstrap Principal
                if !bootstrap.is_zero() {
                    let _ = cap_mgr.bind_principal(process_id, bootstrap);
                }
            }
        }

        crate::println!(
            "  [Spawn] '{}' → task {} process {} (parent=task {})",
            core::str::from_utf8(name).unwrap_or("?"),
            new_task_id.0, process_id.slot(), ctx.task_id.0
        );

        Ok(new_task_id.0 as u64)
    }

    /// SYS_WAIT_TASK: Block until a child task exits.
    ///
    /// Args: arg1 = child task ID
    /// Returns: child's exit code
    fn handle_wait_task(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::scheduler::{TaskState, BlockReason};

        let child_id = crate::scheduler::TaskId(args.arg1_u32());

        // Check the child task's state
        {
            let mut sched_guard = crate::local_scheduler().lock();
            let sched = sched_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

            let child = sched.get_task_mut_pub(child_id)
                .ok_or(SyscallError::InvalidArg)?;

            // Only the parent can wait on a child
            if child.parent_task != Some(ctx.task_id) {
                return Err(SyscallError::PermissionDenied);
            }

            // If already terminated, return exit code immediately
            if child.state == TaskState::Terminated {
                return Ok(child.exit_code as u64);
            }

            // Block the caller until the child exits
            if let Some(task) = sched.get_task_mut_pub(ctx.task_id) {
                task.state = TaskState::Blocked;
                task.block_reason = Some(BlockReason::ChildWait);
            }
        }

        // Yield — when the child exits, handle_exit wakes us via wake_task_on_cpu
        // SAFETY: Scheduler lock is released, we are on the kernel stack.
        unsafe { crate::arch::yield_save_and_switch(); }

        // We've been woken — child should be terminated now. Read exit code.
        {
            let sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_ref() {
                if let Some(child) = sched.get_task_pub(child_id) {
                    return Ok(child.exit_code as u64);
                }
            }
        }

        Ok(0)
    }

    /// SYS_REVOKE_CAPABILITY: Revoke a capability held by another process on
    /// a given endpoint.
    ///
    /// Args: arg1 = target_process_id (u32), arg2 = endpoint_id (u32)
    ///
    /// Authority — Phase 3.1 (per ADR-007 §"Who can revoke"):
    ///   Only the bootstrap Principal can call this. Matches the restriction
    ///   pattern of `handle_bind_principal` and `handle_claim_bootstrap_key`.
    ///
    /// Phase 3.4 will relax this to also accept: the original grantor of the
    /// capability, and any process holding the `revoke` right on the endpoint
    /// (once the policy service exists as the mediator for those paths).
    ///
    /// Phase 3.2d will refactor the argument shape from `(pid, endpoint)` to a
    /// single `CapabilityHandle`, once channels force a system-wide capability
    /// registry into existence.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) — no higher locks held.
    fn handle_revoke_capability(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let target_pid = crate::ipc::ProcessId::new(args.arg1_u32(), 0);
        let endpoint_id = crate::ipc::EndpointId(args.arg2_u32());

        // Read the bootstrap Principal once at the syscall boundary.
        // Passed into CapabilityManager::revoke() as the authority reference,
        // so the primitive stays testable without touching globals.
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();

        // Lock ordering: CAPABILITY_MANAGER(4)
        let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
        let cap_mgr = cap_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        // Look up the caller's bound Principal.
        let revoker_principal = cap_mgr
            .get_principal(ctx.process_id)
            .map_err(|_| SyscallError::PermissionDenied)?;

        // Delegate to the primitive. revoke() performs the authority check
        // (revoker_principal == bootstrap) and the table mutation atomically
        // under the lock we hold.
        cap_mgr
            .revoke(target_pid, endpoint_id, revoker_principal, bootstrap)
            .map_err(|e| match e {
                crate::ipc::capability::CapabilityError::AccessDenied => SyscallError::PermissionDenied,
                crate::ipc::capability::CapabilityError::ProcessNotFound => SyscallError::InvalidArg,
                crate::ipc::capability::CapabilityError::EndpointNotFound => SyscallError::EndpointNotFound,
                _ => SyscallError::InvalidArg,
            })?;

        crate::println!(
            "  [RevokeCapability] caller_pid={} target_pid={} endpoint={} — revoked",
            ctx.process_id.slot(), target_pid.slot(), endpoint_id.0
        );

        Ok(0)
    }

    // ========================================================================
    // Phase 3.2d.iii: Shared-memory channels (ADR-005)
    // ========================================================================

    /// SYS_CHANNEL_CREATE: Create a shared-memory channel.
    ///
    /// Args: arg1 = size_pages, arg2 = peer_principal_ptr (*const u8, 32 bytes),
    ///       arg3 = role (0=Producer, 1=Consumer, 2=Bidirectional),
    ///       arg4 = out_vaddr_ptr (*mut u64, creator's mapping address)
    ///
    /// Returns: ChannelId (u64) on success, negative error on failure.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) → CHANNEL_MANAGER(5) →
    /// PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_channel_create(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::{ChannelRole, MAX_CHANNEL_PAGES, MIN_CHANNEL_PAGES};

        let size_pages = args.arg1_u32();
        let peer_principal_ptr = args.arg2;
        let role_raw = args.arg3 as u32;
        let out_vaddr_ptr = args.arg4;

        // --- Validate args ---
        if !(MIN_CHANNEL_PAGES..=MAX_CHANNEL_PAGES).contains(&size_pages) {
            return Err(SyscallError::InvalidArg);
        }
        let role = ChannelRole::from_u32(role_raw).ok_or(SyscallError::InvalidArg)?;
        if peer_principal_ptr == 0 || peer_principal_ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if out_vaddr_ptr == 0 || out_vaddr_ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // --- Read peer Principal from user buffer ---
        let mut peer_key = [0u8; 32];
        read_user_buffer(ctx.cr3, peer_principal_ptr, 32, &mut peer_key)?;
        let peer_principal = crate::ipc::Principal::from_public_key(peer_key);

        // --- Check CreateChannel capability + get creator's Principal ---
        let creator_principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

            let has_cap = cap_mgr
                .has_system_capability(ctx.process_id, crate::ipc::capability::CapabilityKind::CreateChannel)
                .map_err(|_| SyscallError::PermissionDenied)?;
            if !has_cap {
                return Err(SyscallError::PermissionDenied);
            }

            cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::PermissionDenied)?
        }; // drop CAPABILITY_MANAGER(4)

        // --- Allocate contiguous physical frames ---
        let base_phys = {
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            fa_guard
                .allocate_contiguous(size_pages as usize)
                .map_err(|_| SyscallError::OutOfMemory)?
                .addr
        }; // drop FRAME_ALLOCATOR(7)

        // Zero the channel memory.
        let hhdm = crate::hhdm_offset();
        // SAFETY: Freshly allocated contiguous frames, HHDM-mapped, exclusive.
        unsafe {
            core::ptr::write_bytes(
                (base_phys + hhdm) as *mut u8,
                0,
                size_pages as usize * 4096,
            );
        }

        // --- Allocate VMA region + map into creator's page table ---
        let creator_vaddr = {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            let vma = pt_guard
                .as_mut()
                .and_then(|pt| pt.vma_mut(ctx.process_id))
                .ok_or(SyscallError::InvalidArg)?;

            let vaddr = vma
                .allocate_region(size_pages)
                .ok_or(SyscallError::OutOfMemory)?;

            // Map pages into creator's address space.
            let creator_flags = if role.creator_writable() {
                crate::memory::paging::flags::user_rw()
            } else {
                crate::memory::paging::flags::user_ro()
            };

            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            // SAFETY: ctx.cr3 is a valid PML4/L0 for this process.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_range(
                    &mut pt,
                    vaddr,
                    base_phys,
                    size_pages as usize,
                    creator_flags,
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
            drop(fa_guard);
            drop(pt_guard);
            vaddr
        };

        // --- Register in ChannelManager ---
        let tick = crate::scheduler::Timer::get_ticks();

        let channel_id = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            chan_mgr
                .create(crate::ipc::channel::ChannelCreateParams {
                    creator_principal,
                    peer_principal,
                    creator_pid: ctx.process_id,
                    role,
                    num_pages: size_pages,
                    physical_base: base_phys,
                    creator_vaddr,
                    created_at_tick: tick,
                })
                .map_err(|_| SyscallError::OutOfMemory)?
        }; // drop CHANNEL_MANAGER(5)

        // --- Write creator_vaddr to output pointer ---
        let vaddr_bytes = creator_vaddr.to_le_bytes();
        write_user_buffer(ctx.cr3, out_vaddr_ptr, &vaddr_bytes)?;

        crate::println!(
            "  [ChannelCreate] pid={} id={} pages={} role={:?} → vaddr={:#x}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            size_pages,
            role,
            creator_vaddr,
        );

        Ok(channel_id.as_raw())
    }

    /// SYS_CHANNEL_ATTACH: Attach to an existing channel as the named peer.
    ///
    /// Args: arg1 = channel_id (u64)
    ///
    /// Returns: user-space virtual address of the shared region, or negative error.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) → CHANNEL_MANAGER(5) →
    /// PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_channel_attach(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::ChannelId;

        let channel_id = ChannelId::from_raw(args.arg1);

        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // --- Get caller's Principal ---
        let caller_principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::PermissionDenied)?
        }; // drop CAPABILITY_MANAGER(4)

        // --- Read channel record to get physical_base, num_pages, role ---
        let (physical_base, num_pages, peer_writable) = {
            let chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            let record = chan_mgr.get(channel_id).map_err(|_| SyscallError::InvalidArg)?;

            // Verify state and principal before allocating anything.
            if record.state != crate::ipc::channel::ChannelState::AwaitingAttach {
                return Err(SyscallError::InvalidArg);
            }
            if record.peer_principal != caller_principal {
                return Err(SyscallError::PermissionDenied);
            }

            (record.physical_base, record.num_pages, record.role.peer_writable())
        }; // drop CHANNEL_MANAGER(5) — will re-acquire below for the attach mutation

        // --- Allocate VMA region + map into peer's page table ---
        let peer_vaddr = {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            let vma = pt_guard
                .as_mut()
                .and_then(|pt| pt.vma_mut(ctx.process_id))
                .ok_or(SyscallError::InvalidArg)?;

            let vaddr = vma
                .allocate_region(num_pages)
                .ok_or(SyscallError::OutOfMemory)?;

            let flags = if peer_writable {
                crate::memory::paging::flags::user_rw()
            } else {
                crate::memory::paging::flags::user_ro()
            };

            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            // SAFETY: ctx.cr3 is a valid PML4/L0 for the peer process.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_range(
                    &mut pt,
                    vaddr,
                    physical_base,
                    num_pages as usize,
                    flags,
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
            drop(fa_guard);
            drop(pt_guard);
            vaddr
        };

        // --- Finalize attach in ChannelManager ---
        {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            chan_mgr
                .attach(channel_id, caller_principal, ctx.process_id, peer_vaddr)
                .map_err(|_| SyscallError::InvalidArg)?;
        }

        crate::println!(
            "  [ChannelAttach] pid={} channel={} → vaddr={:#x}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            peer_vaddr,
        );

        Ok(peer_vaddr)
    }

    /// SYS_CHANNEL_CLOSE: Close a channel gracefully.
    ///
    /// Args: arg1 = channel_id (u64)
    ///
    /// Lock ordering: CHANNEL_MANAGER(5) → PROCESS_TABLE(6) → FRAME_ALLOCATOR(7),
    /// then TLB shootdown (lock-free).
    fn handle_channel_close(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::ChannelId;

        let channel_id = ChannelId::from_raw(args.arg1);

        // --- Close in ChannelManager (returns the record) ---
        let record = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            chan_mgr
                .close(channel_id, ctx.process_id)
                .map_err(|e| match e {
                    crate::ipc::channel::ChannelError::PermissionDenied => SyscallError::PermissionDenied,
                    crate::ipc::channel::ChannelError::NotFound => SyscallError::InvalidArg,
                    _ => SyscallError::InvalidArg,
                })?
        }; // drop CHANNEL_MANAGER(5)

        // --- Unmap from both processes + free VMA slots ---
        Self::teardown_channel_mappings(&record);

        crate::println!(
            "  [ChannelClose] pid={} channel={} pages={}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            record.num_pages,
        );

        Ok(0)
    }

    /// SYS_CHANNEL_REVOKE: Force-close a channel (bootstrap authority).
    ///
    /// Args: arg1 = channel_id (u64)
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) → CHANNEL_MANAGER(5) →
    /// PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_channel_revoke(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::ChannelId;

        let channel_id = ChannelId::from_raw(args.arg1);

        // --- Authority check: bootstrap Principal only (Phase 3.1 pattern) ---
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            let caller_principal = cap_mgr
                .get_principal(ctx.process_id)
                .map_err(|_| SyscallError::PermissionDenied)?;
            if caller_principal != bootstrap {
                return Err(SyscallError::PermissionDenied);
            }
        } // drop CAPABILITY_MANAGER(4)

        // --- Revoke in ChannelManager ---
        let record = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            chan_mgr
                .revoke(channel_id)
                .map_err(|_| SyscallError::InvalidArg)?
        }; // drop CHANNEL_MANAGER(5)

        // --- Teardown ---
        Self::teardown_channel_mappings(&record);

        crate::println!(
            "  [ChannelRevoke] pid={} channel={} pages={}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            record.num_pages,
        );

        Ok(0)
    }

    /// SYS_CHANNEL_INFO: Read channel metadata.
    ///
    /// Args: arg1 = channel_id (u64), arg2 = out_buf, arg3 = buf_len
    ///
    /// Writes a fixed-format descriptor to the user buffer:
    ///   [state:1][role:1][num_pages:4][creator_pid_slot:4][peer_pid_slot:4]
    ///   [creator_vaddr:8][peer_vaddr:8][physical_base:8][created_at_tick:8]
    /// Total: 46 bytes
    ///
    /// Lock ordering: CHANNEL_MANAGER(5) only.
    fn handle_channel_info(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::ChannelId;

        let channel_id = ChannelId::from_raw(args.arg1);
        let out_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        if buf_len < 46 || out_buf == 0 || out_buf >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let mut info = [0u8; 46];

        {
            let chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            let record = chan_mgr.get(channel_id).map_err(|_| SyscallError::InvalidArg)?;

            info[0] = record.state as u8;
            info[1] = record.role as u8;
            info[2..6].copy_from_slice(&record.num_pages.to_le_bytes());
            info[6..10].copy_from_slice(&record.creator_pid.slot().to_le_bytes());
            let peer_slot = record.peer_pid.map(|p| p.slot()).unwrap_or(u32::MAX);
            info[10..14].copy_from_slice(&peer_slot.to_le_bytes());
            info[14..22].copy_from_slice(&record.creator_vaddr.to_le_bytes());
            info[22..30].copy_from_slice(&record.peer_vaddr.to_le_bytes());
            info[30..38].copy_from_slice(&record.physical_base.to_le_bytes());
            info[38..46].copy_from_slice(&record.created_at_tick.to_le_bytes());
        } // drop CHANNEL_MANAGER(5)

        write_user_buffer(ctx.cr3, out_buf, &info)?;

        Ok(0)
    }

    // ========================================================================
    // Channel teardown helper (shared by close, revoke, process exit)
    // ========================================================================

    /// Unmap a closed/revoked channel's pages from both processes,
    /// issue TLB shootdown, free VMA slots, and free the physical frames.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7), then
    /// TLB shootdown (lock-free).
    ///
    /// Called after the ChannelManager lock has been released (the record
    /// is already taken out of the table).
    fn teardown_channel_mappings(record: &crate::ipc::channel::ChannelRecord) {
        // Collect vaddrs for TLB shootdown after locks are released.
        let mut shootdown_creator = false;
        let mut shootdown_peer = false;

        {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            if let Some(pt) = pt_guard.as_mut() {
                // Unmap from creator.
                if record.creator_vaddr != 0 {
                    if let Some(vma) = pt.vma_mut(record.creator_pid) {
                        vma.free_region(record.creator_vaddr);
                    }
                    let creator_cr3 = pt.get_cr3(record.creator_pid);
                    if creator_cr3 != 0 {
                        // SAFETY: creator_cr3 is a valid page table. The
                        // channel is closed so no user-space writes are
                        // racing (the record is already Closed/Revoked).
                        unsafe {
                            let mut page_table = crate::memory::paging::page_table_from_cr3(creator_cr3);
                            for i in 0..record.num_pages as u64 {
                                let vaddr = record.creator_vaddr + i * 4096;
                                let _ = crate::memory::paging::unmap_page(&mut page_table, vaddr);
                            }
                        }
                        shootdown_creator = true;
                    }
                }

                // Unmap from peer (if attached).
                if record.peer_vaddr != 0 {
                    if let Some(peer_pid) = record.peer_pid {
                        if let Some(vma) = pt.vma_mut(peer_pid) {
                            vma.free_region(record.peer_vaddr);
                        }
                        let peer_cr3 = pt.get_cr3(peer_pid);
                        if peer_cr3 != 0 {
                            // SAFETY: same reasoning as creator.
                            unsafe {
                                let mut page_table = crate::memory::paging::page_table_from_cr3(peer_cr3);
                                for i in 0..record.num_pages as u64 {
                                    let vaddr = record.peer_vaddr + i * 4096;
                                    let _ = crate::memory::paging::unmap_page(&mut page_table, vaddr);
                                }
                            }
                            shootdown_peer = true;
                        }
                    }
                }
            }
        } // drop PROCESS_TABLE(6)

        // TLB shootdown for unmapped ranges (lock-free).
        // SAFETY: shootdown_range requires ring 0 and that the page table
        // modifications (above) are already visible in memory.
        if shootdown_creator {
            unsafe {
                crate::arch::tlb_shootdown_range(record.creator_vaddr, record.num_pages);
            }
        }
        if shootdown_peer {
            unsafe {
                crate::arch::tlb_shootdown_range(record.peer_vaddr, record.num_pages);
            }
        }

        // Free the contiguous physical frames.
        {
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            let _ = fa_guard.free_contiguous(record.physical_base, record.num_pages as usize);
        }
    }
}
