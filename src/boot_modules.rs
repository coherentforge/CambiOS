// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Boot module registry
//!
//! Remembers Limine boot module names and addresses so that user-space
//! processes can spawn modules by name at runtime via the Spawn syscall.
//! Module memory (EXECUTABLE_AND_MODULES) persists via HHDM for the
//! kernel's lifetime.

/// Maximum number of boot modules the registry can track.
pub(crate) const MAX_MODULES: usize = 16;

/// Maximum length of a module name (bytes).
const MAX_NAME_LEN: usize = 64;

/// A single boot module entry.
#[derive(Clone)]
struct ModuleEntry {
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    /// Physical address of the module data (accessible via HHDM).
    addr: *const u8,
    /// Size of the module in bytes.
    size: usize,
}

/// SAFETY: Module addresses point to Limine EXECUTABLE_AND_MODULES memory
/// which is valid for the kernel's lifetime and only read (never mutated)
/// after boot. The registry is protected by a Spinlock.
unsafe impl Send for ModuleEntry {}
/// SAFETY: Read-only after boot; spinlock-protected registry ensures no data races.
unsafe impl Sync for ModuleEntry {}

impl ModuleEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            addr: core::ptr::null(),
            size: 0,
        }
    }
}

/// Registry of boot modules available for runtime spawning.
pub struct BootModuleRegistry {
    entries: [ModuleEntry; MAX_MODULES],
    count: usize,
}

impl Default for BootModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BootModuleRegistry {
    pub const fn new() -> Self {
        Self {
            entries: [const { ModuleEntry::empty() }; MAX_MODULES],
            count: 0,
        }
    }

    /// Register a module. `name` is the stripped filename (e.g., "hello" from
    /// "boot():/boot/hello.elf"). Returns false if the registry is full.
    pub fn register(&mut self, name: &[u8], addr: *const u8, size: usize) -> bool {
        if self.count >= MAX_MODULES || name.is_empty() {
            return false;
        }
        let truncated_len = name.len().min(MAX_NAME_LEN);
        let entry = &mut self.entries[self.count];
        entry.name[..truncated_len].copy_from_slice(&name[..truncated_len]);
        entry.name_len = truncated_len;
        entry.addr = addr;
        entry.size = size;
        self.count += 1;
        true
    }

    /// Look up a module by name. Returns (addr, size) if found.
    pub fn find_by_name(&self, name: &[u8]) -> Option<(*const u8, usize)> {
        for i in 0..self.count {
            let entry = &self.entries[i];
            if entry.name_len == name.len() && entry.name[..entry.name_len] == *name {
                return Some((entry.addr, entry.size));
            }
        }
        None
    }

    /// Number of registered modules.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get module name by index (for listing available commands).
    pub fn get_name(&self, index: usize) -> Option<&[u8]> {
        if index < self.count {
            Some(&self.entries[index].name[..self.entries[index].name_len])
        } else {
            None
        }
    }
}

/// Extract a short module name from a Limine module path.
///
/// Strips the directory prefix and ".elf" suffix:
/// `"boot():/boot/hello.elf"` → `"hello"`
/// `"boot():/boot/fs-service.elf"` → `"fs-service"`
pub fn strip_module_name(path: &[u8]) -> &[u8] {
    // Find last '/' to strip directory prefix
    let start = path.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
    let name = &path[start..];
    // Strip ".elf" suffix if present
    if name.len() > 4 && &name[name.len() - 4..] == b".elf" {
        &name[..name.len() - 4]
    } else {
        name
    }
}

// ============================================================================
// Sequential boot-release chain
//
// The kernel parks modules 1..N in `BlockReason::BootGate` at load time
// and releases them one-at-a-time as each predecessor calls the
// `SYS_MODULE_READY` syscall. This replaces the old "all modules Ready
// immediately, race to init" model with a deterministic chain whose
// ordering is fixed by `limine.conf`.
//
// Invariants:
// - Only module 0 (the first in limine.conf) starts `Ready` at boot. All
//   other loaded modules start `Blocked` on `BootGate` via
//   `Scheduler::block_task`.
// - `BOOT_MODULE_ORDER` is populated in `load_boot_modules` with the
//   TaskIds in limine.conf order.
// - `next_to_release` starts at 1 (module 0 is already Running).
// - Each `sys_module_ready` call from a boot module advances the cursor
//   by one and wakes the task at the new cursor position.
// - Once `next_to_release >= len`, the chain is complete and subsequent
//   `sys_module_ready` calls are no-ops (harmless for modules that call
//   it redundantly or for late-loaded modules).
// ============================================================================

use crate::scheduler::TaskId;

/// Ordered roster of boot-loaded tasks + a cursor tracking which one to
/// release next. Populated by `load_boot_modules`, advanced by
/// `handle_module_ready`.
pub struct BootModuleOrder {
    tasks: [Option<TaskId>; MAX_MODULES],
    len: u8,
    /// Index of the next module to unblock. Starts at 1 because module 0
    /// is the first module in limine.conf and runs `Ready` from boot.
    /// Reaching `len` means the chain is complete.
    next_to_release: u8,
}

impl Default for BootModuleOrder {
    fn default() -> Self {
        Self::new()
    }
}

impl BootModuleOrder {
    pub const fn new() -> Self {
        Self {
            tasks: [None; MAX_MODULES],
            len: 0,
            next_to_release: 1,
        }
    }

    /// Append a TaskId to the ordered roster. Returns false if full.
    pub fn push(&mut self, tid: TaskId) -> bool {
        let idx = self.len as usize;
        if idx >= MAX_MODULES {
            return false;
        }
        self.tasks[idx] = Some(tid);
        self.len += 1;
        true
    }

    /// Advance the release cursor. Returns the TaskId of the module now
    /// eligible to run (to be unblocked by the caller), or `None` if the
    /// chain is complete.
    pub fn advance(&mut self) -> Option<TaskId> {
        let idx = self.next_to_release as usize;
        if idx >= self.len as usize {
            return None;
        }
        let tid = self.tasks[idx];
        self.next_to_release += 1;
        tid
    }

    /// Number of registered boot tasks.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Current cursor position. Diagnostic / test use.
    pub fn cursor(&self) -> u8 {
        self.next_to_release
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_module_name() {
        assert_eq!(strip_module_name(b"boot():/boot/hello.elf"), b"hello");
        assert_eq!(strip_module_name(b"boot():/boot/fs-service.elf"), b"fs-service");
        assert_eq!(strip_module_name(b"hello.elf"), b"hello");
        assert_eq!(strip_module_name(b"hello"), b"hello");
        assert_eq!(strip_module_name(b"/a/b/c.elf"), b"c");
    }

    #[test]
    fn test_registry_register_and_find() {
        let mut reg = BootModuleRegistry::new();
        let data = [0u8; 4];
        assert!(reg.register(b"hello", data.as_ptr(), 4));
        assert!(reg.register(b"fs-service", data.as_ptr(), 100));
        assert_eq!(reg.count(), 2);

        let (_, size) = reg.find_by_name(b"hello").unwrap();
        assert_eq!(size, 4);

        let (_, size) = reg.find_by_name(b"fs-service").unwrap();
        assert_eq!(size, 100);

        assert!(reg.find_by_name(b"nonexistent").is_none());
    }

    #[test]
    fn test_registry_full() {
        let mut reg = BootModuleRegistry::new();
        let data = [0u8; 1];
        for i in 0..MAX_MODULES {
            let name = [b'a' + (i as u8 % 26)];
            assert!(reg.register(&name, data.as_ptr(), 1));
        }
        assert!(!reg.register(b"overflow", data.as_ptr(), 1));
    }

    #[test]
    fn test_registry_get_name() {
        let mut reg = BootModuleRegistry::new();
        let data = [0u8; 1];
        reg.register(b"shell", data.as_ptr(), 1);
        assert_eq!(reg.get_name(0), Some(b"shell".as_slice()));
        assert_eq!(reg.get_name(1), None);
    }

    // ========================================================================
    // BootModuleOrder — sequential boot-release chain
    // ========================================================================

    #[test]
    fn test_boot_order_new_is_empty() {
        let order = BootModuleOrder::new();
        assert_eq!(order.len(), 0);
        assert!(order.is_empty());
        assert_eq!(order.cursor(), 1);
    }

    #[test]
    fn test_boot_order_push_grows_len() {
        let mut order = BootModuleOrder::new();
        assert!(order.push(TaskId(1)));
        assert!(order.push(TaskId(2)));
        assert!(order.push(TaskId(3)));
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn test_boot_order_push_fills_to_capacity() {
        let mut order = BootModuleOrder::new();
        for i in 0..MAX_MODULES as u32 {
            assert!(order.push(TaskId(i)));
        }
        assert_eq!(order.len(), MAX_MODULES);
        // Overflow pushed entries must be refused.
        assert!(!order.push(TaskId(999)));
        assert_eq!(order.len(), MAX_MODULES);
    }

    #[test]
    fn test_boot_order_advance_walks_chain() {
        let mut order = BootModuleOrder::new();
        order.push(TaskId(10));  // module 0
        order.push(TaskId(20));  // module 1
        order.push(TaskId(30));  // module 2

        // Initial cursor is 1: module 0 runs first without any advance().
        // First advance returns module 1 (TaskId(20)).
        assert_eq!(order.advance(), Some(TaskId(20)));
        // Second advance returns module 2 (TaskId(30)).
        assert_eq!(order.advance(), Some(TaskId(30)));
        // Third advance: chain complete.
        assert_eq!(order.advance(), None);
        // Repeated advances past the end stay None — idempotent.
        assert_eq!(order.advance(), None);
    }

    #[test]
    fn test_boot_order_advance_on_empty_is_none() {
        let mut order = BootModuleOrder::new();
        assert_eq!(order.advance(), None);
    }

    #[test]
    fn test_boot_order_single_module_has_no_chain_work() {
        let mut order = BootModuleOrder::new();
        order.push(TaskId(5));
        // len == 1, cursor starts at 1, so advance() returns None
        // immediately — there's nothing after module 0 to release.
        assert_eq!(order.advance(), None);
    }
}
