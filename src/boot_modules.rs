// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Boot module registry
//!
//! Remembers Limine boot module names and addresses so that user-space
//! processes can spawn modules by name at runtime via the Spawn syscall.
//! Module memory (EXECUTABLE_AND_MODULES) persists via HHDM for the
//! kernel's lifetime.

/// Maximum number of boot modules the registry can track.
const MAX_MODULES: usize = 16;

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
}
