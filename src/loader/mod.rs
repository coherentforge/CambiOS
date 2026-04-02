//! Userspace process loader
//!
//! Loads ELF binaries into isolated memory regions and creates tasks.
//! Designed with verification and capability-based security in mind.

pub mod elf;

use crate::scheduler::{Scheduler, TaskId, Priority};
use crate::ipc::ProcessId;
use elf::ElfError;

/// Errors that can occur during process loading
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderError {
    ElfError(ElfError),
    InvalidMemoryLayout,
    MemoryAllocationFailed,
    SchedulerFull,
}

impl core::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::ElfError(e) => write!(f, "ELF error: {}", e),
            Self::InvalidMemoryLayout => write!(f, "Invalid memory layout"),
            Self::MemoryAllocationFailed => write!(f, "Memory allocation failed"),
            Self::SchedulerFull => write!(f, "Scheduler is full"),
        }
    }
}

/// Process memory layout
///
/// Each userspace process has:
/// - Code segment (read/execute)
/// - Data segment (read/write)
/// - BSS segment (read/write, zero-initialized)
/// - Heap (read/write, growable)
/// - Stack (read/write, grows downward)
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemoryLayout {
    /// Process ID
    pub process_id: ProcessId,
    /// Base address for code/data (aligned)
    pub code_base: u64,
    /// Base address for stack (grows downward)
    pub stack_base: u64,
    /// Stack size (grows downward from stack_base)
    pub stack_size: u64,
    /// Total virtual address space allocated
    pub total_size: u64,
}

/// Load address allocation strategy
/// 
/// Keeps track of next available address for process loading.
/// In a full system, this would integrate with paging/MMU.
pub struct ProcessAllocator {
    /// Next available load address
    next_load_addr: u64,
    /// Stack allocation pointer (grows downward)
    next_stack_addr: u64,
    /// Maximum address
    max_addr: u64,
}

impl ProcessAllocator {
    /// Create a new process allocator
    /// 
    /// Userspace: 0x400000 to 0x7FFFFFFF (conservative allocation)
    pub fn new() -> Self {
        ProcessAllocator {
            // Userspace code starts at 0x400000
            next_load_addr: 0x400000,
            // Stacks grow downward from 0x7F000000
            next_stack_addr: 0x7F000000,
            // Stop before kernel space (0x80000000)
            max_addr: 0x80000000,
        }
    }

    /// Allocate contiguous memory for a process's code/data
    pub fn allocate_code_region(&mut self, size: u64) -> Result<u64, LoaderError> {
        if size == 0 {
            return Err(LoaderError::InvalidMemoryLayout);
        }

        let addr = self.next_load_addr;
        let aligned_size = (size + 0xFFF) & !0xFFF; // Align to 4K

        if addr + aligned_size >= self.next_stack_addr {
            return Err(LoaderError::MemoryAllocationFailed);
        }

        self.next_load_addr = addr + aligned_size;
        Ok(addr)
    }

    /// Allocate a stack region for a process (grows downward)
    pub fn allocate_stack(&mut self, size: u64) -> Result<u64, LoaderError> {
        if size == 0 {
            return Err(LoaderError::InvalidMemoryLayout);
        }

        let aligned_size = (size + 0xFFF) & !0xFFF; // Align to 4K

        if self.next_stack_addr < aligned_size + self.next_load_addr {
            return Err(LoaderError::MemoryAllocationFailed);
        }

        // Stack grows downward, so return the top of the stack
        let stack_top = self.next_stack_addr - aligned_size;
        self.next_stack_addr = stack_top;

        Ok(stack_top)
    }
}

/// Load an ELF binary into memory and create a task
///
/// This function:
/// 1. Validates the ELF binary
/// 2. Allocates memory regions for code/data/stack
/// 3. Loads program segments into memory
/// 4. Creates a task in the scheduler
pub fn load_process(
    binary: &[u8],
    scheduler: &mut Scheduler,
    priority: Priority,
    allocator: &mut ProcessAllocator,
) -> Result<(ProcessId, TaskId), LoaderError> {
    // Parse and analyze ELF
    let elf_binary = elf::analyze_binary(binary).map_err(LoaderError::ElfError)?;

    // Allocate memory for code/data
    let code_base = allocator.allocate_code_region(elf_binary.load_size)?;

    // Allocate stack (8KB default)
    let stack_size = 0x2000;
    let stack_base = allocator.allocate_stack(stack_size)?;

    // Load all LOAD segments into memory
    load_segments(binary, code_base, elf_binary.load_base)?;

    // Calculate entry point (adjusted for new load base)
    let entry_offset = elf_binary.entry_point - elf_binary.load_base;
    let adjusted_entry = code_base + entry_offset;

    // Stack pointer points to top of stack (grows downward)
    let stack_ptr = stack_base + stack_size;

    // Create task in scheduler
    let task_id = scheduler
        .create_task(adjusted_entry, stack_ptr, priority)
        .map_err(|_| LoaderError::SchedulerFull)?;

    // Assign process ID (use task ID as process ID for now)
    let process_id = ProcessId(task_id.0);

    Ok((process_id, task_id))
}

/// Load all LOAD segments from ELF binary into memory
fn load_segments(
    binary: &[u8],
    load_base: u64,
    elf_load_base: u64,
) -> Result<(), LoaderError> {
    let header = elf::parse_header(binary).map_err(LoaderError::ElfError)?;

    for i in 0..header.e_phnum as usize {
        let phdr = elf::get_program_header(binary, &header, i)
            .map_err(LoaderError::ElfError)?;

        if phdr.p_type == elf::phdr_type::PT_LOAD {
            // Calculate where this segment should go
            let offset_in_segment = phdr.p_vaddr - elf_load_base;
            let dest_addr = load_base + offset_in_segment;

            // Copy from file into memory
            let src = unsafe {
                core::slice::from_raw_parts(
                    binary.as_ptr().add(phdr.p_offset as usize),
                    phdr.p_filesz as usize,
                )
            };

            let dest = unsafe {
                core::slice::from_raw_parts_mut(
                    dest_addr as *mut u8,
                    phdr.p_filesz as usize,
                )
            };

            // Copy file data
            dest.copy_from_slice(src);

            // Zero-fill any BSS (memory beyond file size)
            if phdr.p_memsz > phdr.p_filesz {
                let bss_start = dest_addr + phdr.p_filesz;
                let bss_size = (phdr.p_memsz - phdr.p_filesz) as usize;

                let bss = unsafe {
                    core::slice::from_raw_parts_mut(
                        bss_start as *mut u8,
                        bss_size,
                    )
                };

                bss.fill(0);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocator() {
        let mut alloc = ProcessAllocator::new();

        let code1 = alloc.allocate_code_region(0x1000).unwrap();
        let code2 = alloc.allocate_code_region(0x1000).unwrap();

        assert!(code2 > code1);

        let stack1 = alloc.allocate_stack(0x1000).unwrap();
        let stack2 = alloc.allocate_stack(0x1000).unwrap();

        assert!(stack2 < stack1);
        assert!(code2 < stack2); // No overlap
    }

    #[test]
    fn test_allocator_exhaustion() {
        let mut alloc = ProcessAllocator::new();

        // Allocate code up to stack region
        while alloc.allocate_code_region(0x1000).is_ok() {
            // Keep allocating until we fail
        }

        // Should fail now
        assert!(alloc.allocate_code_region(0x1000).is_err());
    }
}
