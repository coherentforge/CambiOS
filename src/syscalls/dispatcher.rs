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

/// Maximum user buffer size for a single syscall (4 KB)
const MAX_USER_BUFFER: usize = 4096;

/// Canonical user-space address ceiling (x86-64 lower half)
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// Read bytes from a user-space virtual address into a kernel buffer.
///
/// Walks the process page table (CR3) to translate each page the buffer
/// spans, then reads via HHDM. Returns the number of bytes copied.
///
/// # Safety contract
/// `cr3` must be a valid PML4 physical address for the calling process.
/// Called from syscall context with interrupts disabled.
#[cfg(target_arch = "x86_64")]
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
/// `cr3` must be a valid PML4 physical address for the calling process.
/// The target pages must be mapped writable in the process page table.
#[cfg(target_arch = "x86_64")]
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
        }
    }

    // ========================================================================
    // Process lifecycle
    // ========================================================================

    /// SYS_EXIT: Terminate the calling task.
    ///
    /// Marks the task as Terminated in the scheduler. The scheduler will
    /// skip terminated tasks and the next timer tick will context-switch
    /// to a ready task.
    fn handle_exit(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let exit_code = args.arg1_u32();

        // Lock ordering: PER_CPU_SCHEDULER(1) — no higher locks held
        let mut sched_guard = crate::local_scheduler().lock();
        if let Some(sched) = sched_guard.as_mut() {
            if let Some(task) = sched.get_task_mut_pub(ctx.task_id) {
                task.state = crate::scheduler::TaskState::Terminated;
            }
        }
        drop(sched_guard);

        crate::println!(
            "  [Exit] pid={} task={} code={}",
            ctx.process_id.0, ctx.task_id.0, exit_code
        );

        Ok(exit_code as u64)
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
        #[cfg(target_arch = "x86_64")]
        read_user_buffer(ctx.cr3, user_buf, len, &mut kbuf)?;

        // Build IPC message
        let endpoint = crate::ipc::EndpointId(endpoint_id);
        let mut msg = crate::ipc::Message::new(
            crate::ipc::EndpointId(ctx.process_id.0),
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

                #[cfg(target_arch = "x86_64")]
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
    /// Lock ordering: PROCESS_TABLE(5) → FRAME_ALLOCATOR(6)
    fn handle_allocate(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let size = args.arg_usize(1);

        if size == 0 || size > 1024 * 1024 {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let num_pages = ((size + 4095) / 4096) as u32;

        // Lock ordering: PROCESS_TABLE(5) → FRAME_ALLOCATOR(6)
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .ok_or(SyscallError::InvalidArg)?;

        let base_vaddr = vma.allocate_region(num_pages).ok_or(SyscallError::OutOfMemory)?;

        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
        let hhdm = crate::hhdm_offset();

        for i in 0..num_pages as usize {
            let page_vaddr = base_vaddr + (i as u64 * 4096);

            let frame = match fa_guard.allocate() {
                Ok(f) => f,
                Err(_) => {
                    // Rollback: unmap already-mapped pages and free their frames
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
    /// Lock ordering: PROCESS_TABLE(5) → FRAME_ALLOCATOR(6)
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

        // Lock ordering: PROCESS_TABLE(5) → FRAME_ALLOCATOR(6)
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma_entry = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .and_then(|vma| vma.free_region(ptr))
            .ok_or(SyscallError::InvalidArg)?;

        // Unmap each page and free its backing frame
        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
        for i in 0..vma_entry.num_pages as u64 {
            let page_vaddr = vma_entry.base_vaddr + i * 4096;
            // SAFETY: cr3 is valid (non-zero, checked above). These pages were
            // mapped by handle_allocate and recorded in the VMA tracker.
            unsafe {
                let mut pte = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                if let Ok(freed_frame) = crate::memory::paging::unmap_page(&mut pte, page_vaddr) {
                    let _ = fa_guard.free(freed_frame);
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
    /// Moves the calling task from Running → Ready so the scheduler can
    /// pick a different task on the next tick. Returns immediately; the
    /// actual context switch happens at the next timer ISR.
    fn handle_yield(_args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let mut sched_guard = crate::local_scheduler().lock();
        if let Some(sched) = sched_guard.as_mut() {
            if let Some(task) = sched.get_task_mut_pub(ctx.task_id) {
                if task.state == crate::scheduler::TaskState::Running {
                    task.state = crate::scheduler::TaskState::Ready;
                    task.time_remaining = 0; // Force reschedule on next tick
                }
            }
        }

        Ok(0)
    }

    /// SYS_WAIT_IRQ: Block until a specific hardware interrupt fires.
    ///
    /// Args: arg1 = irq_number
    ///
    /// Registers the task as the handler for the given IRQ (if not already
    /// registered) and blocks the task until the IRQ fires.
    fn handle_wait_irq(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let irq_num = args.arg1_u32();

        if irq_num >= 224 {
            return Err(SyscallError::InvalidArg);
        }

        // Lock ordering: PER_CPU_SCHEDULER(1) → INTERRUPT_ROUTER(7)
        let mut sched_guard = crate::local_scheduler().lock();
        let mut router_guard = crate::INTERRUPT_ROUTER.lock();

        // Register this task as the IRQ handler (ignore if already registered)
        let irq = crate::interrupts::routing::IrqNumber(irq_num as u8);
        let _ = router_guard.register(irq, ctx.task_id, 128);

        // Block the task until the IRQ fires
        if let Some(sched) = sched_guard.as_mut() {
            sched
                .block_task(ctx.task_id, crate::scheduler::BlockReason::IoWait(irq_num))
                .map_err(|_| SyscallError::InvalidArg)?;
        }

        drop(router_guard);
        drop(sched_guard);

        Ok(0)
    }

    // ========================================================================
    // Info syscalls
    // ========================================================================

    /// SYS_GET_PID: Get current process ID
    fn handle_get_pid(_args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        Ok(ctx.process_id.0 as u64)
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
        #[cfg(target_arch = "x86_64")]
        read_user_buffer(ctx.cr3, user_buf, len, &mut buf)?;

        for &byte in &buf[..len] {
            crate::io::print(format_args!("{}", byte as char));
        }

        Ok(len as u64)
    }
}
