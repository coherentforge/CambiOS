// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS init (PID 1) — syscall shell (ADR-018 § 4).
//!
//! Everything that decides lives in [`cambios_init::engine`]; this
//! binary parses the manifest the kernel mapped, registers init's
//! endpoint, and runs the three-line supervision loop: ask the
//! engine, perform the syscall, feed back the event.
//!
//! Entry is hand-rolled rather than `service_main!`: init is
//! kernel-created PID 1, outside the `BOOT_MODULE_ORDER` gate, so it
//! must not call `module_ready()` (both macro arms do — correctly,
//! for gated services; the syscall itself retires at migration
//! step 9). One binary of ritual does not meet the framework's
//! second-consumer bar for a new macro arm.
//!
//! Dormant until migration step 7: nothing loads this ELF or maps the
//! blob before then, so nothing here runs. It compiles for all three
//! kernel targets and its logic is host-tested through the lib crate.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

/// Host stub so `cargo test` in this package can build the bin target;
/// the engine's tests live in the lib crate (`cargo test --lib` works
/// too). The real entry is `svc::_start` below, target builds only.
#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!("cambios-init is a CambiOS boot binary; nothing to run on the host");
}

#[cfg(target_os = "none")]
mod svc {
    use cambios_init::engine::{Action, EngineError, Event, SupervisorEngine};
    use cambios_libsys as sys;
    use cambios_manifest::{
        payload_extent, topo_order, Manifest, HEADER_LEN, MANIFEST_USER_VADDR,
        MAX_MANIFEST_ENTRIES, READY_PING_TAG,
    };

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        sys::print(b"[init] PANIC!\n");
        sys::exit(1)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        main()
    }

    /// recv buffer: 36-byte verified header + 256-byte max payload.
    const RECV_BUF: usize = 292;

    fn main() -> ! {
        sys::print(b"[init] CambiOS init starting\n");

        // The kernel maps the verified manifest blob read-only at
        // MANIFEST_USER_VADDR before init's first instruction
        // (ADR-018 § 6 step 4). Size the parse slice from the
        // self-describing header — a slice must never extend past the
        // mapped region, so "parse with a max window" is not an option
        // (payload_extent's doc carries the full argument).
        //
        // SAFETY: the boot contract above guarantees at least the
        // 64-byte header is mapped at MANIFEST_USER_VADDR, read-only,
        // for the life of the process; HEADER_LEN bytes from it form a
        // single mapped object, and u8 has no validity invariants.
        let header = unsafe {
            core::slice::from_raw_parts(MANIFEST_USER_VADDR as *const u8, HEADER_LEN)
        };
        let extent = match payload_extent(header) {
            Some(n) => n,
            None => {
                // The kernel refused to boot on any invalid manifest,
                // so a bad header here means the mapping contract is
                // broken — nothing sane to supervise.
                sys::print(b"[init] manifest header invalid at MANIFEST_USER_VADDR\n");
                sys::exit(1)
            }
        };
        // SAFETY: `extent` came from payload_extent, which caps it at
        // MANIFEST_MAX_BYTES and derives it from the same header the
        // kernel validated when it transcribed this blob; the kernel
        // maps the whole blob, so [vaddr, vaddr + extent) is mapped,
        // read-only, and outlives the process's use of it.
        let blob = unsafe {
            core::slice::from_raw_parts(MANIFEST_USER_VADDR as *const u8, extent)
        };
        let m = match Manifest::parse(blob) {
            Ok(m) => m,
            Err(_) => {
                sys::print(b"[init] manifest re-parse failed (kernel/init parser skew?)\n");
                sys::exit(1)
            }
        };

        // Init's endpoint: the header value is authoritative (the
        // const is the v1 default the build tool writes). Reserved to
        // init's AID at transcription; the kernel bound that AID at
        // our creation, so the reservation gate admits us.
        let init_ep = m.init_endpoint();
        if sys::register_endpoint(init_ep) < 0 {
            sys::print(b"[init] cannot register init endpoint\n");
            sys::exit(1)
        }

        let mut order = [0u16; MAX_MANIFEST_ENTRIES];
        let n = match topo_order(&m, &mut order) {
            Ok(n) => n,
            Err(_) => {
                sys::print(b"[init] manifest dependency graph rejected\n");
                sys::exit(1)
            }
        };
        let mut eng = match SupervisorEngine::new(&m, &order[..n]) {
            Ok(e) => e,
            Err(_) => {
                sys::print(b"[init] supervisor construction failed\n");
                sys::exit(1)
            }
        };

        sys::print(b"[init] manifest parsed; supervising boot wave\n");
        supervise(&m, &mut eng, init_ep);

        let s = eng.summary();
        sys::print(b"[init] boot wave settled: ");
        print_num(s.ready as u32);
        sys::print(b" ready, ");
        print_num(s.spawn_failed as u32);
        sys::print(b" spawn-failed, ");
        print_num(s.dep_failed as u32);
        sys::print(b" dep-failed\n");

        // Idle: block on our endpoint and discard. Post-boot traffic
        // has no consumer yet.
        // Revisit when: ADR-019 restart policy lands (migration step
        // 10) — this loop becomes the supervision wake point.
        loop {
            let mut buf = [0u8; RECV_BUF];
            let _ = sys::recv_msg(init_ep, &mut buf);
        }
    }

    /// Drive the engine over the boot wave: one spawn in flight at a
    /// time, readiness matched by kernel-stamped sender AID.
    fn supervise(m: &Manifest<'_>, eng: &mut SupervisorEngine, init_ep: u32) {
        loop {
            match eng.next_action() {
                Action::Spawn { idx } => {
                    let name = match m.entry(idx as usize) {
                        Some(e) => e.module_name(),
                        None => "", // unreachable: engine indices < entry_count
                    };
                    sys::print(b"[init] spawning ");
                    sys::print(name.as_bytes());
                    sys::print(b"\n");
                    let ret = sys::spawn(name.as_bytes());
                    let ev = if ret < 0 {
                        sys::print(b"[init] spawn FAILED: ");
                        sys::print(name.as_bytes());
                        sys::print(b"\n");
                        Event::SpawnFailed { idx }
                    } else {
                        Event::SpawnSucceeded { idx, task: ret as u64 }
                    };
                    // Engine rejections here mean an init bug, not a
                    // service failure; log and keep supervising.
                    if eng.on_event(ev).is_err() {
                        sys::print(b"[init] BUG: spawn report rejected by engine\n");
                    }
                }
                Action::AwaitReady { .. } => {
                    let mut buf = [0u8; RECV_BUF];
                    let Some(msg) = sys::recv_verified(init_ep, &mut buf) else {
                        // Anonymous or malformed sender — recv_verified
                        // already dropped it; identity is the whole
                        // basis of readiness, so just keep waiting.
                        sys::print(b"[init] dropped unverified message on init endpoint\n");
                        continue;
                    };
                    match msg.command() {
                        Some((READY_PING_TAG, _)) => {
                            let sender_aid = *msg.sender().as_bytes();
                            match eng.on_event(Event::ReadyPing { sender_aid }) {
                                Ok(()) => {}
                                Err(EngineError::UnknownSender) => {
                                    // Something outside the manifest
                                    // holds send access to init's
                                    // endpoint — loud, worth eyes.
                                    sys::print(b"[init] ready ping from UNKNOWN sender AID\n");
                                }
                                Err(_) => {
                                    // Duplicate or premature ping.
                                    sys::print(b"[init] out-of-order ready ping ignored\n");
                                }
                            }
                        }
                        _ => {
                            sys::print(b"[init] non-ping message on init endpoint ignored\n");
                        }
                    }
                }
                Action::Done => return,
            }
        }
    }

    /// Decimal print without an allocator (u32 max is 10 digits).
    fn print_num(mut n: u32) {
        let mut buf = [0u8; 10];
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        sys::print(&buf[i..]);
    }
}
