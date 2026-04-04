//! Memory management subsystem
//!
//! Handles memory initialization, paging, and allocation strategies.
//! Designed with verification in mind: clear interfaces and explicit assumptions.

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::PageTable;
use core::sync::atomic::{AtomicU8, Ordering};

pub mod buddy_allocator;
pub mod frame_allocator;
pub mod heap;
pub mod paging;

/// Memory configuration constants
pub mod config {
    /// Bootloader entry point in physical memory (real mode)
    pub const BOOTLOADER_BASE: u64 = 0x7c00;
    
    /// Kernel load address in physical memory
    pub const KERNEL_LOAD_ADDR: u64 = 0x100000;
    
    /// Extended memory base address
    pub const EXTENDED_MEMORY_BASE: u64 = 0x100000;
}

/// Memory initialization state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryInitState {
    Uninitialized = 0,
    Configured = 1,
    Ready = 2,
}

static MEMORY_STATE: AtomicU8 = AtomicU8::new(MemoryInitState::Uninitialized as u8);

/// Initialize memory management
///
/// # Safety
/// Must be called once during boot. Currently a placeholder.
pub unsafe fn init() {
    // SAFETY: configure_memory only writes an atomic; no actual unsafe memory ops yet.
    configure_memory();
    MEMORY_STATE.store(MemoryInitState::Ready as u8, Ordering::Release);
}

/// Configure memory structures and enable protections
unsafe fn configure_memory() {
    // Placeholder for memory configuration
    // In a full implementation, this would:
    // - Set up page tables
    // - Enable paging
    // - Configure memory protection units
    MEMORY_STATE.store(MemoryInitState::Configured as u8, Ordering::Release);
}

/// Get current memory initialization state
pub fn state() -> MemoryInitState {
    match MEMORY_STATE.load(Ordering::Acquire) {
        1 => MemoryInitState::Configured,
        2 => MemoryInitState::Ready,
        _ => MemoryInitState::Uninitialized,
    }
}

/// Interface for memory allocation verification
pub trait MemoryAllocator {
    fn allocate(&mut self, size: usize) -> Option<*mut u8>;
    fn deallocate(&mut self, ptr: *mut u8, size: usize);
    fn is_aligned(&self, ptr: *const u8, alignment: usize) -> bool;
}

/// Get current page table root via HHDM mapping.
///
/// CR3 holds a physical address — we add the HHDM offset to get a
/// kernel-accessible virtual pointer.
pub unsafe fn get_page_table() -> Option<&'static mut PageTable> {
    let (level_4_table_frame, _) = Cr3::read();
    let phys_addr = level_4_table_frame.start_address().as_u64();
    let virt_addr = (phys_addr + crate::hhdm_offset()) as *mut PageTable;
    // SAFETY: CR3 points to a valid PML4 frame set up by Limine or create_process_page_table.
    // Adding the HHDM offset gives a kernel-accessible virtual address. The borrow is
    // 'static because the page table lives as long as the kernel does.
    Some(&mut *virt_addr)
}
