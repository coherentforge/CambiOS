//! Architecture abstraction layer
//!
//! Re-exports the active architecture's primitives. Portable modules (spinlock)
//! live directly under `arch/`. Architecture-specific modules live under
//! `arch/<target>/` and are selected at compile time via `#[cfg(target_arch)]`.
//!
//! ## Adding a new architecture
//!
//! 1. Create `arch/<target>/mod.rs` with the same public API as `x86_64/mod.rs`
//! 2. Add a `#[cfg(target_arch = "<target>")]` block below
//! 3. Implement: SavedContext, context_save/restore/switch, timer_isr_stub,
//!    GDT/privilege setup, syscall entry

// Portable modules (no architecture-specific code)
pub mod spinlock;

// Architecture-specific modules
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
