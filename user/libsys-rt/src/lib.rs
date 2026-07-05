// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS service runtime — L0 of the native app framework (ADR-037).
//!
//! Collapses the entry ritual every service hand-rolls (`_start` →
//! `register_endpoint` → `module_ready` → main loop, plus the panic
//! handler) into one [`service_main!`] invocation. Pure `macro_rules!` —
//! no proc-macro crate in the build graph, per ADR-037 L0.
//!
//! # Usage
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//! #![deny(unsafe_code)]
//!
//! use cambios_libsys as sys;
//!
//! cambios_libsys_rt::service_main! {
//!     name: "POLICY",                 // panic-message prefix
//!     endpoint: 22,                   // or `endpoints: [24, 26]`
//!     main: service_loop,
//! }
//!
//! fn service_loop() -> ! {
//!     loop { /* recv → dispatch → reply → yield */ }
//! }
//! ```
//!
//! The macro emits, at module scope in the consumer crate:
//! - `_start`: registers each endpoint in order, calls
//!   `sys::module_ready()` (releasing the next module behind the boot
//!   gate), then tail-calls the given `main: fn() -> !`.
//! - a `#[panic_handler]` that prints `[NAME] PANIC!` to serial and
//!   calls `sys::exit(1)` — byte-identical in behavior to the handler
//!   all 23 services carried by hand.
//!
//! # Opt-in heap (`heap` feature)
//!
//! `alloc`-consuming services opt in (ADR-037's allocator resolution:
//! non-`alloc` services pay nothing) by enabling the `heap` feature and
//! adding `heap: <bytes>` to the invocation:
//!
//! ```ignore
//! cambios_libsys_rt::service_main! {
//!     name: "TERM",
//!     endpoint: 31,
//!     heap: 64 * 1024,   // static BSS arena, the terminal-window pattern
//!     main: run,
//! }
//! ```
//!
//! This emits a `#[global_allocator]` `LockedHeap` over a `[u8; N]`
//! static, initialized first thing in `_start` before any allocation
//! can run. The arena size is the consumer's conscious bound — tag it
//! at the call site per Development Convention 8 (terminal-window's
//! 64 KiB SCAFFOLDING tag is the reference).
//!
//! The `heap:` arms expand only in consumers (macro bodies are not
//! type-checked until expansion); terminal-window's port is the
//! expansion-proof consumer (ADR-037 Phase 1).

#![no_std]

// The macro expands inside consumer crates, so everything it calls must
// be reachable through `$crate::` — consumers must not need their own
// `use cambios_libsys` for the emitted code to resolve.
#[doc(hidden)]
pub use cambios_libsys as __sys;

#[cfg(feature = "heap")]
#[doc(hidden)]
pub use linked_list_allocator as __alloc;

/// Emit the service entry ritual: `_start` (endpoint registration +
/// `module_ready` + jump to `main`) and the standard panic handler.
///
/// Arms:
/// - `name: "SVC", endpoint: E, main: f` — single endpoint.
/// - `name: "SVC", endpoints: [E1, E2], main: f` — multi-endpoint
///   services (e.g. virtio-blk's client + kernel-command pair).
/// - `name: "SVC", main: f` — **no-endpoint form** for services whose
///   registration and readiness the macro cannot order for them (GUI
///   apps register reply endpoints inside `libgui::Client::open`, and
///   gate readiness on window setup). The macro emits only `_start`
///   (+ heap) and the panic handler; **`main` MUST call
///   `sys::module_ready()` itself once ready**, or the boot gate holds
///   every later module forever.
/// - Add `heap: SIZE` (requires the `heap` feature) to any form for
///   `alloc` consumers; SIZE is the static arena in bytes.
///
/// `name` is a string literal used as the panic-message prefix
/// (`[NAME] PANIC!`). `main` must be `fn() -> !`.
#[macro_export]
macro_rules! service_main {
    // --- sugar: single endpoint -> endpoints list ---
    (name: $name:literal, endpoint: $ep:expr, main: $main:path $(,)?) => {
        $crate::service_main!(name: $name, endpoints: [$ep], main: $main);
    };
    (name: $name:literal, endpoint: $ep:expr, heap: $size:expr, main: $main:path $(,)?) => {
        $crate::service_main!(name: $name, endpoints: [$ep], heap: $size, main: $main);
    };

    // --- core arm: no heap ---
    (name: $name:literal, endpoints: [$($ep:expr),+ $(,)?], main: $main:path $(,)?) => {
        #[panic_handler]
        fn __cambios_rt_panic(_info: &::core::panic::PanicInfo) -> ! {
            $crate::__sys::print(::core::concat!("[", $name, "] PANIC!\n").as_bytes());
            $crate::__sys::exit(1)
        }

        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            $( let _ = $crate::__sys::register_endpoint($ep); )+
            $crate::__sys::module_ready();
            $main()
        }
    };

    // --- no-endpoint arms: registration + module_ready stay in `main`
    //     (GUI apps — see the macro docs; `main` must call module_ready) ---
    (name: $name:literal, main: $main:path $(,)?) => {
        #[panic_handler]
        fn __cambios_rt_panic(_info: &::core::panic::PanicInfo) -> ! {
            $crate::__sys::print(::core::concat!("[", $name, "] PANIC!\n").as_bytes());
            $crate::__sys::exit(1)
        }

        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            $main()
        }
    };
    (name: $name:literal, heap: $size:expr, main: $main:path $(,)?) => {
        #[panic_handler]
        fn __cambios_rt_panic(_info: &::core::panic::PanicInfo) -> ! {
            $crate::__sys::print(::core::concat!("[", $name, "] PANIC!\n").as_bytes());
            $crate::__sys::exit(1)
        }

        #[global_allocator]
        static __CAMBIOS_RT_ALLOC: $crate::__alloc::LockedHeap =
            $crate::__alloc::LockedHeap::empty();

        static mut __CAMBIOS_RT_HEAP: [u8; $size] = [0u8; $size];

        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            // SAFETY: __CAMBIOS_RT_HEAP is a 'static BSS arena; _start
            // runs exactly once, before any allocation, so this is the
            // sole direct access and the allocator takes ownership of
            // the region for the process lifetime.
            unsafe {
                __CAMBIOS_RT_ALLOC.lock().init(
                    ::core::ptr::addr_of_mut!(__CAMBIOS_RT_HEAP) as *mut u8,
                    $size,
                );
            }
            $main()
        }
    };

    // --- core arm: opt-in heap (requires the `heap` feature) ---
    (name: $name:literal, endpoints: [$($ep:expr),+ $(,)?], heap: $size:expr, main: $main:path $(,)?) => {
        #[panic_handler]
        fn __cambios_rt_panic(_info: &::core::panic::PanicInfo) -> ! {
            $crate::__sys::print(::core::concat!("[", $name, "] PANIC!\n").as_bytes());
            $crate::__sys::exit(1)
        }

        #[global_allocator]
        static __CAMBIOS_RT_ALLOC: $crate::__alloc::LockedHeap =
            $crate::__alloc::LockedHeap::empty();

        static mut __CAMBIOS_RT_HEAP: [u8; $size] = [0u8; $size];

        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            // SAFETY: __CAMBIOS_RT_HEAP is a 'static BSS arena; _start
            // runs exactly once, before any allocation, so this is the
            // sole direct access and the allocator takes ownership of
            // the region for the process lifetime.
            unsafe {
                __CAMBIOS_RT_ALLOC.lock().init(
                    ::core::ptr::addr_of_mut!(__CAMBIOS_RT_HEAP) as *mut u8,
                    $size,
                );
            }
            $( let _ = $crate::__sys::register_endpoint($ep); )+
            $crate::__sys::module_ready();
            $main()
        }
    };
}
