// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors

//! regression-probe — reruns, from ring 3, the reproductions of kernel
//! findings that have been fixed, so a later change that reopens one fails
//! a boot instead of going unnoticed.
//!
//! Each stage is the user-side half of a probe that demonstrated a finding
//! under QEMU before its fix. It prints one line, `[REGRESS] PASS <id>: ...`
//! or `[REGRESS] FAIL <id>: ...`, saying in plain words what the kernel must
//! (or must not) do, and the run ends with `[REGRESS] done: N pass, M fail`.
//!
//! The manifest row that spawns this probe carries `profile = ["regress"]`,
//! so no shipping image runs it. `make run-regress` builds the x86_64 image
//! with `MANIFEST_PROFILES=default,regress` and requires the `done` line
//! with `0 fail`, plus the kernel's own `[sched]` line for the reaper stage.
//!
//! Stages:
//! - **R4 control**: the kernel writes a syscall result into a writable
//!   stack buffer. Must still land, or the R4 check below proves nothing.
//! - **R4** (user copies ignored page permissions, fixed `bb32b7b`): the
//!   kernel is asked to write into this process's read-only `.rodata`. The
//!   call must fail and the bytes stay unchanged.
//! - **R1** (`SYS_MAP_MMIO` mapped the kernel image writable and panicked on
//!   an address at or above 2^52, fixed `425bc05`): mapping physical memory
//!   that is not inside a device BAR must be refused. One address per
//!   class: firmware or interrupt-controller pages the old deny-list (refuse
//!   only usable RAM) mapped, and one above 2^52.
//! - **Reaper** (the idle-loop reaper stopped after the boot wave, so later
//!   exits leaked their kernel stack, page tables and task slot; ADR-034 §
//!   Divergence 2026-11-24): after the wave has settled, spawn `faultme`
//!   several times and wait for each. Every child faults and is reaped.
//!   The probe checks that each spawn and wait completes; the kernel's
//!   `[sched]` line at tick 2000 (x86_64) shows whether the reaper kept up
//!   (pending and high-water at most 1 per CPU), and `make run-regress`
//!   requires that line.
//! - **Trap stages** (x86_64; most exceptions had no handler, so any of
//!   them from ring 3 became a double fault that halted the kernel;
//!   ADR-040 § 4): spawn `regress-victim`, wait for it to report that it
//!   is listening on its endpoint, send it one mode byte, and wait for it.
//!   It executes the instruction the byte names (`ud2`; a push through a
//!   non-canonical stack pointer, #SS on Intel hardware and #GP under
//!   QEMU; `int1`, #DB; the trap flag set across `syscall`; the
//!   nested-task flag set across a yielding syscall, ADR-040 § 5). The
//!   stage passes when the child comes back reaped for a fault (exits 0
//!   for the nested-task stage) and the probe itself is still running. `SYS_WAIT_TASK` does not yet say which fault (ADR-019's
//!   `ExitInfo`); the kernel's `[Fault]` line in the log does.

#![no_std]
#![no_main]

use cambios_libsys as sys;

cambios_libsys_rt::service_main! {
    name: "REGRESSION-PROBE",
    main: run,
}

/// The R4 target: 32 bytes in `.rodata`, which the linker script puts on
/// its own page, mapped read-only to ring 3. Never written by this program.
#[used]
static RO_TARGET: [u8; 32] = [0xAA; 32];

/// TUNING: the tick after which the reaper stage starts. Well past the
/// boot wave (the idle-loop reaper last ran at tick 4 to 14 in the
/// measurements that found the bug) and well before the kernel's `[sched]`
/// line at tick 2000, so every child's death lands in the window that line
/// reports on.
const REAPER_STAGE_TICK: u64 = 1000;

/// TUNING: children spawned by the reaper stage. Two or more deaths per CPU
/// on a two-CPU QEMU are what make an unreaped backlog visible as
/// `pending > 1`; four covers both CPUs under least-populated placement.
const REAPER_CHILDREN: usize = 4;

/// ARCHITECTURAL: this probe's endpoint (its manifest row): regress-victim
/// reports there that it is listening.
#[cfg(target_arch = "x86_64")]
const PROBE_ENDPOINT: u32 = 59;

/// ARCHITECTURAL: regress-victim's endpoint (its manifest row): the probe
/// sends the mode byte there.
#[cfg(target_arch = "x86_64")]
const VICTIM_ENDPOINT: u32 = 60;

/// What regress-victim sends once it is listening.
#[cfg(target_arch = "x86_64")]
const VICTIM_READY: &[u8] = b"victim-ready";

/// TUNING: ticks (5 s at 100 Hz) the probe waits for regress-victim to
/// report that it is listening before the stage fails. A spawn and the
/// child's first syscalls take a few ticks under QEMU.
#[cfg(target_arch = "x86_64")]
const VICTIM_READY_TICKS: u64 = 500;

/// What `SYS_WAIT_TASK` returns for a child the kernel reaped for a fault:
/// the kernel's `reap::FAULTED_EXIT_CODE` (`i32::MIN`), sign-extended.
#[cfg(target_arch = "x86_64")]
const FAULTED: i64 = i32::MIN as i64;

/// The x86_64 trap stages: regress-victim's mode byte (shared with
/// `user/regress-victim`; keep the two in step), the stage id, and what a
/// correct kernel does. `trap-badstack` is #SS on Intel hardware, which had
/// no handler before ADR-040; QEMU's TCG raises #GP for it instead, which
/// did, so under QEMU that stage also passes on a kernel without the fix
/// and only `trap-UD` and `trap-ICEBP` tell the two apart.
///
/// The fourth value is the `SYS_WAIT_TASK` result a correct kernel gives:
/// [`FAULTED`] for the stages whose instruction must fault in ring 3, 0
/// for trap-NT and the two GS stages, where the program must simply
/// finish (the danger was the kernel faulting on state the program set:
/// its own `iretq` on NT, its per-CPU reads through a GS base the program
/// loaded). The last is the CPU feature the stage needs: the kernel turns
/// UMIP on only where the CPU reports it (ADR-040 § 6), so trap-UMIP is
/// skipped, not counted, on a CPU without it.
#[cfg(target_arch = "x86_64")]
const TRAP_STAGES: [(u8, &[u8], &[u8], i64, Requires); 10] = [
    (1, b"trap-UD", b"a ring-3 ud2 (invalid opcode) reaps the program and the kernel runs on", FAULTED, Requires::Nothing),
    (2, b"trap-badstack", b"a ring-3 push through a non-canonical stack pointer reaps the program and the kernel runs on", FAULTED, Requires::Nothing),
    (3, b"trap-ICEBP", b"a ring-3 int1 (#DB) reaps the program and the kernel runs on", FAULTED, Requires::Nothing),
    (4, b"trap-TF", b"a trap flag set across syscall single-steps nothing in the kernel; the program is reaped for #DB back in ring 3", FAULTED, Requires::Nothing),
    (5, b"trap-NT", b"a nested-task flag set across a yielding syscall does not reach the kernel's iretq; the program exits normally", 0, Requires::Nothing),
    (6, b"trap-GS-syscall", b"a ring-3 mov gs followed by a syscall does not move the kernel's per-CPU base; the program exits normally", 0, Requires::Nothing),
    (7, b"trap-GS-tick", b"a ring-3 mov gs followed by timer ticks in ring 3 does not move the kernel's per-CPU base; the program exits normally", 0, Requires::Nothing),
    (8, b"trap-x87", b"an x87 instruction in ring 3 reaps the program: no FP register state exists while none is saved across a switch", FAULTED, Requires::Nothing),
    (9, b"trap-rdtsc", b"rdtsc in ring 3 reaps the program: a program's time comes from the kernel", FAULTED, Requires::Nothing),
    (10, b"trap-UMIP", b"sidt in ring 3 reaps the program: the IDT's kernel address stays in ring 0", FAULTED, Requires::Umip),
];

/// A CPU feature a trap stage needs before its expectation holds.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
enum Requires {
    Nothing,
    /// CPUID leaf 7, subleaf 0, ECX bit 2.
    Umip,
}

#[cfg(target_arch = "x86_64")]
impl Requires {
    /// Whether this CPU has the feature. CPUID is unprivileged: ring 3
    /// reads the same leaf the kernel decided from. Leaf 0 first, because
    /// leaf 7 means nothing on a CPU whose highest basic leaf is below it.
    fn met(self) -> bool {
        match self {
            Requires::Nothing => true,
            Requires::Umip => {
                core::arch::x86_64::__cpuid(0).eax >= 7
                    && core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 2) != 0
            }
        }
    }
}

/// Physical addresses `SYS_MAP_MMIO` must refuse on this architecture: none
/// lies inside a device BAR. The first ones are pages the old deny-list
/// (refuse only usable RAM) mapped user-writable; the last is above the
/// 52-bit physical-address limit, which used to panic the kernel.
#[cfg(target_arch = "x86_64")]
const NON_DEVICE_ADDRESSES: [(u64, &[u8]); 4] = [
    (0x000F_0000, b"legacy BIOS ROM"),
    (0xFEC0_0000, b"I/O APIC registers (not a PCI BAR)"),
    (0xFEE0_0000, b"local APIC registers (not a PCI BAR)"),
    (1 << 52, b"above the 52-bit physical limit"),
];
#[cfg(target_arch = "aarch64")]
const NON_DEVICE_ADDRESSES: [(u64, &[u8]); 4] = [
    (0x0800_0000, b"GIC distributor (not a PCI BAR)"),
    (0x0900_0000, b"PL011 UART (not a PCI BAR)"),
    (0x4000_0000, b"start of RAM"),
    (1 << 52, b"above the 52-bit physical limit"),
];
#[cfg(target_arch = "riscv64")]
const NON_DEVICE_ADDRESSES: [(u64, &[u8]); 4] = [
    (0x0C00_0000, b"PLIC (not a device BAR)"),
    (0x1000_0000, b"UART (not a device BAR)"),
    (0x8000_0000, b"OpenSBI firmware at the start of RAM"),
    (1 << 52, b"above the 52-bit physical limit"),
];

/// One output line, built in a fixed buffer (no heap in this program).
struct Line {
    buf: [u8; 160],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Line { buf: [0; 160], len: 0 }
    }

    fn text(mut self, s: &[u8]) -> Self {
        for &b in s {
            // Leave room for the CR LF `emit` appends.
            if self.len < self.buf.len() - 2 {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        self
    }

    fn hex(self, v: u64) -> Self {
        let mut digits = [0u8; 18];
        digits[0] = b'0';
        digits[1] = b'x';
        for (i, d) in digits[2..].iter_mut().enumerate() {
            let nibble = ((v >> (60 - 4 * i)) & 0xF) as u8;
            *d = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        }
        self.text(&digits)
    }

    fn dec(self, v: u64) -> Self {
        let mut digits = [0u8; 20];
        let mut n = v;
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 || i == 0 {
                break;
            }
        }
        self.text(&digits[i..])
    }

    fn emit(mut self) {
        self.buf[self.len] = b'\r';
        self.buf[self.len + 1] = b'\n';
        sys::print(&self.buf[..self.len + 2]);
    }
}

/// Running count of stage results.
struct Tally {
    pass: u64,
    fail: u64,
}

impl Tally {
    fn record(&mut self, ok: bool, id: &[u8], what: &[u8]) {
        let verdict: &[u8] = if ok { b"[REGRESS] PASS " } else { b"[REGRESS] FAIL " };
        Line::new().text(verdict).text(id).text(b": ").text(what).emit();
        if ok {
            self.pass += 1;
        } else {
            self.fail += 1;
        }
    }
}

/// `SYS_GET_PRINCIPAL` into an arbitrary user address, issued directly so
/// no Rust reference to the target is created: the R4 target is read-only
/// memory, and a `&mut` to it would be undefined behaviour in this program
/// whatever the kernel does. Returns the kernel's result (32 on success,
/// negative on error).
fn get_principal_at(addr: u64) -> i64 {
    raw_syscall3(sys::SyscallNumber::GetPrincipal as u64, addr, 32, 0)
}

#[cfg(target_arch = "x86_64")]
fn raw_syscall3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: the same SYSCALL sequence as libsys's `syscall_raw3` (x86_64):
    // the kernel validates every argument, and the instruction touches no
    // memory of this program's itself. The CPU clobbers RCX and R11; the
    // kernel stub does not restore RDI, RSI, RDX, R8-R10, all declared.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            inlateout("rdi") arg1 => _,
            inlateout("rsi") arg2 => _,
            inlateout("rdx") arg3 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
fn raw_syscall3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: the same `svc #0` sequence as libsys's `syscall_raw3`
    // (aarch64): x8 = number, x0-x2 = arguments, x0 = result; the kernel
    // validates every argument. `clobber_abi("C")` declares x0-x18, x30
    // and all of v0-v31 clobbered, as libsys does: the kernel does not
    // preserve the FP/SIMD registers across a syscall.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x0") arg1 as i64 => ret,
            inlateout("x1") arg2 => _,
            inlateout("x2") arg3 => _,
            inlateout("x8") num => _,
            clobber_abi("C"),
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "riscv64")]
fn raw_syscall3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: the same `ecall` sequence as libsys's `syscall_raw3`
    // (riscv64): a7 = number, a0-a2 = arguments, a0 = result; the kernel
    // validates every argument. a0-a7 and t0-t6 are declared clobbered, as
    // libsys does.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg1 as i64 => ret,
            inlateout("a1") arg2 => _,
            inlateout("a2") arg3 => _,
            inlateout("a7") num => _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
            lateout("a6") _,
            lateout("t0") _,
            lateout("t1") _,
            lateout("t2") _,
            lateout("t3") _,
            lateout("t4") _,
            lateout("t5") _,
            lateout("t6") _,
            options(nostack),
        );
    }
    ret
}

/// Read the R4 target through volatile loads: the compiler may not assume
/// an immutable static keeps its initializer if the kernel is the one being
/// tested.
fn ro_target_unchanged() -> bool {
    let base = core::hint::black_box(RO_TARGET.as_ptr());
    (0..RO_TARGET.len()).all(|i| {
        // SAFETY: `base + i` is inside `RO_TARGET` (i < its length), a
        // mapped, readable, aligned `u8`; a read-only load cannot fault.
        let b = unsafe { core::ptr::read_volatile(base.add(i)) };
        b == 0xAA
    })
}

fn stage_r4(t: &mut Tally) {
    let mut stack_buf = [0xAAu8; 32];
    let rc = sys::get_principal(&mut stack_buf);
    let landed = rc == 32 && stack_buf.iter().any(|&b| b != 0xAA);
    t.record(
        landed,
        b"R4 control",
        b"the kernel's write into a writable stack buffer landed",
    );

    let addr = core::hint::black_box(RO_TARGET.as_ptr()) as u64;
    let rc = get_principal_at(addr);
    let refused = rc < 0 && ro_target_unchanged();
    let what: &[u8] = if refused {
        b"the kernel refused to write into a read-only user page"
    } else {
        b"the kernel wrote into, or claimed to write into, a read-only user page"
    };
    t.record(refused, b"R4", what);
}

fn stage_r1(t: &mut Tally) {
    for &(phys, what) in NON_DEVICE_ADDRESSES.iter() {
        let r = sys::map_mmio(phys, 1);
        let refused = r < 0;
        let verdict: &[u8] = if refused {
            b"[REGRESS] PASS R1: refused "
        } else {
            b"[REGRESS] FAIL R1: MAPPED "
        };
        Line::new()
            .text(verdict)
            .hex(phys)
            .text(b" (")
            .text(what)
            .text(b")")
            .emit();
        if refused {
            t.pass += 1;
        } else {
            t.fail += 1;
        }
    }
}

fn stage_reaper(t: &mut Tally) {
    // Yield until the wave is long settled. This makes the probe one more
    // yield-polling task, the condition under which the idle-loop reaper
    // starved; the death-path drain must not depend on any CPU idling.
    // Bounded by the tick counter, which the timer advances.
    while sys::get_time() < REAPER_STAGE_TICK {
        sys::yield_now();
    }
    let mut reaped = 0usize;
    for _ in 0..REAPER_CHILDREN {
        let handle = sys::spawn(b"faultme");
        if handle < 0 {
            Line::new().text(b"[REGRESS] reaper: spawn faultme failed rc=").dec(handle.unsigned_abs()).emit();
            continue;
        }
        let code = sys::wait_task(handle as u64);
        Line::new()
            .text(b"[REGRESS] reaper: faultme reaped at tick ")
            .dec(sys::get_time())
            .text(b", wait rc=")
            .hex(code as u64)
            .emit();
        reaped += 1;
    }
    let all = reaped == REAPER_CHILDREN;
    let what: &[u8] = if all {
        b"every child spawned after the boot wave faulted and was reaped; [sched] reports the backlog"
    } else {
        b"a child spawned after the boot wave could not be spawned"
    };
    t.record(all, b"reaper", what);
}

/// One x86_64 trap stage: spawn regress-victim, wait (bounded) for it to
/// say it is listening, send it `mode`, wait for it to end, and pass if
/// `SYS_WAIT_TASK` returns `expect`.
#[cfg(target_arch = "x86_64")]
fn stage_trap(t: &mut Tally, mode: u8, id: &[u8], what: &[u8], expect: i64) {
    let handle = sys::spawn(b"regress-victim");
    if handle < 0 {
        Line::new().text(b"[REGRESS] ").text(id).text(b": spawn regress-victim failed rc=")
            .dec(handle.unsigned_abs()).emit();
        t.record(false, id, b"regress-victim could not be spawned");
        return;
    }
    let deadline = sys::get_time() + VICTIM_READY_TICKS;
    let mut buf = [0u8; 96];
    let listening = loop {
        if let Some(msg) = sys::try_recv_verified(PROBE_ENDPOINT, &mut buf) {
            if msg.payload() == VICTIM_READY {
                break true;
            }
        }
        if sys::get_time() > deadline {
            break false;
        }
        sys::yield_now();
    };
    if !listening {
        t.record(false, id, b"regress-victim never reported that it was listening");
        return;
    }
    if sys::write(VICTIM_ENDPOINT, &[mode]) < 0 {
        t.record(false, id, b"the mode byte could not be sent to regress-victim");
        return;
    }
    let code = sys::wait_task(handle as u64);
    Line::new().text(b"[REGRESS] ").text(id).text(b": regress-victim ended, wait rc=")
        .hex(code as u64).emit();
    t.record(code == expect, id, what);
}

fn run() -> ! {
    // The trap stages' handshake endpoint; registered before the readiness
    // ping, as the entry macro would.
    #[cfg(target_arch = "x86_64")]
    if sys::register_endpoint(PROBE_ENDPOINT) < 0 {
        sys::print(b"[REGRESS] could not register endpoint 59; the trap stages will fail\r\n");
    }
    // A boot-wave row: report ready first so init settles the wave while the
    // stages run.
    cambios_libsys_rt::ready();
    sys::print(b"[REGRESS] start\r\n");

    let mut t = Tally { pass: 0, fail: 0 };
    stage_r4(&mut t);
    stage_r1(&mut t);
    stage_reaper(&mut t);
    #[cfg(target_arch = "x86_64")]
    for (mode, id, what, expect, requires) in TRAP_STAGES {
        if !requires.met() {
            Line::new().text(b"[REGRESS] SKIP ").text(id)
                .text(b": the CPU does not report the feature this stage needs").emit();
            continue;
        }
        stage_trap(&mut t, mode, id, what, expect);
    }

    Line::new()
        .text(b"[REGRESS] done: ")
        .dec(t.pass)
        .text(b" pass, ")
        .dec(t.fail)
        .text(b" fail")
        .emit();
    sys::exit(if t.fail == 0 { 0 } else { 1 })
}
