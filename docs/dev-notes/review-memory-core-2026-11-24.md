<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors -->

# Review of the kernel memory core, sandbox run 004 (2026-11-24)

Reviewed at `bb32b7b`. No kernel file was changed in this run; this file is the only thing committed.

## Scope and method

In scope: the frame allocator and per-CPU frame cache, the two page-table layers (x86_64 `src/memory/paging.rs`, and the shared AArch64 / RISC-V layer in `src/memory/mod.rs`), the kernel heap, the object table, the per-process region tracker (VMA, virtual memory area) and address-space creation and teardown in `src/process.rs`, the ELF (Executable and Linkable Format) loader, the per-architecture page-table encodings, TLB (translation lookaside buffer) shootdown code and trap / syscall entry paths, and the places where the boot memory map becomes allocator regions and the HHDM (Higher Half Direct Map, the kernel's direct map of physical memory; `.claude/rules/platform-gotchas.md`) offset is set. `src/reap.rs` and `src/reaper.rs` were followed into but not reviewed.

Read in full, non-test code: `src/memory/{frame_allocator,paging,mod,heap,buddy_allocator,object_table}.rs`, `src/process.rs`, `src/loader/{elf,mod}.rs`, `src/arch/x86_64/{syscall,percpu,tlb}.rs`, `src/arch/aarch64/{paging,tlb,syscall,percpu}.rs`, `src/arch/riscv64/{paging,tlb,trap,syscall}.rs`, `src/arch/spinlock.rs`. Read in the parts that matter here: `src/lib.rs` (per-CPU accessors, preempt count, frame cache, load balancer, `halt`), the trap, timer and yield stubs in `src/arch/{x86_64,aarch64,riscv64}/mod.rs`, `src/arch/x86_64/gdt.rs` (descriptors, `set_kernel_stack`), `src/arch/riscv64/{entry,percpu}.rs` (boot page tables, per-CPU layout), `src/boot/{mod,limine,riscv}.rs` (memory-region intake), `init_kernel_heap` / `init_frame_allocator` in `src/microkernel/main.rs`, the x86_64 exception handlers and IDT (Interrupt Descriptor Table) setup in `src/interrupts/mod.rs`, and the syscall handlers that call the in-scope primitives (`handle_allocate`, `handle_free`, `handle_map_mmio`, `handle_alloc_dma`, `handle_spawn`, `teardown_channel_mappings`) plus `src/syscalls/user_slice.rs` for the `bb32b7b` fix. Skimmed only: the scheduler (migration and `on_timer_isr` gating), `src/manifest.rs` blob mapping, `src/audit/drain.rs` ring allocation. Not read: `src/ipc/`, `src/policy/`, `src/fs/`, the device-driver crates, the AArch64 GIC and PCI mapping callers beyond their one `map_page` line, host tests.

Design records: `CLAUDE.md`, `.claude/rules/{kernel,locks,scheduling,platform-gotchas,x86_64}.md` and ADR-034 were read in full before the code. ADR-020 was read for its scope boundary only. ADR-008, ADR-019, ADR-004, ADR-013, ADR-036, ADR-021 and `docs/ASSUMPTIONS.md` were not read end to end: I looked up the rows and sections the code cites (the `KERNEL_HEAP_SIZE`, `KERNEL_STACK_SIZE`, `MAX_RAM_EXTENTS`, `MAX_FRAMES` and `IST_STACK_SIZE` rows; ADR-013's `early_map_mmio` divergence). The code-against-record disagreements reported here are therefore against `CLAUDE.md`, the rules files, ADR-034 and those rows; a full pass of the other ADRs against this code is still owed.

Three findings (M1, M2, M3) and one out-of-scope observation were run under QEMU with a throwaway probe built in a clone outside the repository (`/tmp/probe`); the probe source is in the appendix. An unmodified clone booted to the shell with `make run-quiet` (exit 0) as the baseline. Everything else is by tracing the code, and each finding says which.

Severity counts: 2 critical, 5 high, 6 medium, 7 low, 2 informational.

## Findings

### M1. x86_64: ring 3 can set the kernel's GS base to zero; the next syscall or interrupt takes its kernel stack pointer and per-CPU pointer from address 0

- **Lens:** trap and syscall entry.
- **Severity:** critical. Any unprivileged process halts the machine and overwrites megabytes of kernel heap on the way down. If the process has a page mapped at virtual address 0 (the loader allows a segment there, see below) the kernel loads its stack pointer from user-controlled memory, which is ring-0 control.
- **Confidence:** confirmed under QEMU (appendix, probe 1).
- **Location:** `src/arch/x86_64/syscall.rs:142-144`; every `gs:[0]` reader, for example `src/arch/x86_64/percpu.rs:308-321`, `src/lib.rs:149-154`, `src/lib.rs:557-570`; descriptor at `src/arch/x86_64/gdt.rs:51`.

**Path.**

1. A ring-3 task executes `mov ax, 0x1b; mov gs, ax`. `0x1b` is the user data selector (`USER_SS`, GDT (Global Descriptor Table) index 3, DPL 3), so the load is legal. In 64-bit mode a load of FS or GS still reloads the hidden base from the descriptor, and the descriptor is flat: base 0. `IA32_GS_BASE` is now 0.
2. The task executes `syscall`. The entry stub runs `mov gs:[32], rsp` — a ring-0 write to virtual address 0x20.
3. With nothing mapped at page 0 this is a ring-0 page fault taken on the user's stack (no privilege change, so no stack switch). The page-fault handler calls `current_cpu_id()`, which reads `gs:[0]`, which faults again; the recursion walks down the user stack until it runs off the bottom, the CPU raises a double fault onto IST1 (Interrupt Stack Table entry 1, a 4 KiB heap block, `src/interrupts/mod.rs:564`), and the double-fault handler's `println!` takes a `Spinlock`, whose `preempt_disable` reads `gs:[0]` and faults again. From there the CPU loops: page faults nest downward from the IST stack through the kernel heap, a double fault resets the stack pointer to the IST top, repeat.
4. No syscall is needed: the next timer interrupt on that CPU reads `gs:[0]` in `local_scheduler()` with the same result.

**Why the code allows it.** The entry stub states the assumption and nothing enforces it:

```
// GS base points to this CPU's PerCpu (kernel owns GS at all times).
// No swapgs needed — user code cannot modify GS base (FSGSBASE not enabled).
"mov gs:[32], rsp",     // Save user RSP to PerCpu.user_rsp_scratch
"mov rsp, gs:[24]",     // Load kernel RSP from PerCpu.kernel_rsp0
```

FSGSBASE is one way to change the GS base; a segment load is another, and it needs no CPU feature. The kernel also never clears `CR4.FSGSBASE` itself (no code in the tree writes CR4), so the comment's premise rests on what the bootloader left.

**With page 0 mapped.** `DefaultVerifier` rejects only segments at or above `USER_SPACE_END` (`src/loader/mod.rs:222`); a signed binary may carry a `PT_LOAD` at virtual address 0. There is no SMAP (Supervisor Mode Access Prevention) or SMEP (Supervisor Mode Execution Prevention) in the tree. Then step 2 succeeds, `mov rsp, gs:[24]` loads the kernel stack pointer from user memory at 0x18, and the stub pushes the frame and calls `syscall_handler_inner` on a stack the process chose. Not run; it follows directly from the confirmed step 2.

**Proposed fix.** Keep the kernel per-CPU base in `IA32_KERNEL_GS_BASE` and `swapgs` on every ring-3 entry and exit (syscall, every interrupt and exception stub, with the usual care for ring-0-to-ring-0 entries), or stop using GS for per-CPU data on entry and take it from somewhere ring 3 cannot write (the TSS (Task State Segment) `rsp0` via the task register, or `rdtscp`/`rdpid` with a per-CPU table). Clear `CR4.FSGSBASE` explicitly at boot until user FS/GS base support is designed, and enable SMEP and SMAP so a wrong base cannot reach user memory. Add a host or QEMU regression that runs probe 1 and requires the task to be reaped.

**Demonstration.** Probe 1. Serial log: `[PROBE-GS] ring 3: mov gs, 0x1b (user data selector) then syscall`, then on the first run a `!!! KERNEL PAGE FAULT !!!` reported by the other CPU, on the second a `MICROKERNEL PANIC` in `src/ipc/mod.rs:290` with a wild slice index — both are the heap being overwritten by step 3. QEMU's exception trace (`-d int`) for the probing CPU:

```
62: v=0e e=0002 i=0 cpl=0 IP=0008:ffffffff80005294 SP=0010:00000000007fffe8 CR2=0000000000000020
63: v=0e e=0000 i=0 cpl=0 IP=0008:ffffffff8002ce5e SP=0010:00000000007ffea8 CR2=0000000000000000
... (same fault, stack pointer descending to 0x7f0728)
268: v=08 e=0000 i=0 cpl=0 IP=0008:ffffffff8002cdea SP=0010:00000000007effa8
6138: v=08 e=0000 i=0 cpl=0 IP=0008:ffffffff8002cdcc SP=0000:ffff800000100000
12007: v=08 ...   (a double fault every ~5,870 exceptions, for as long as the run lasted)
```

`ffffffff80005294` is `syscall_entry`; `ffffffff8002cdc0` is `exceptions::page_fault`. About 5,870 nested frames of roughly 0x140 bytes between double faults is about 1.8 MiB written below a 4 KiB IST stack.

### M2. riscv64: a user process's `tp` is left in `sscratch`; the next trap taken in supervisor mode uses it as the per-CPU pointer

- **Lens:** trap and syscall entry.
- **Severity:** critical on riscv64. A supervisor-mode store to `tp + 40` and a load of the kernel stack pointer from `tp + 24`, with `tp` chosen by an unprivileged process. A value that is not mapped halts the kernel; a value that is a kernel address (the direct map of a page the process controls) is a stack pivot.
- **Confidence:** confirmed under QEMU (appendix, probe 4) for the kernel-fault outcome; the pivot is by tracing.
- **Location:** `src/arch/riscv64/trap.rs:94-99` (entry), `:136-139`, `:175`, `:201-234` (return to supervisor mode), `:367` (`reap_user_fault` enabling interrupts).

**Path.** The vector tells user entries from supervisor entries by one fact: `sscratch` is zero while the kernel runs.

```
csrrw tp, sscratch, tp
bnez tp, 10f                    // tp != 0 → came from U-mode
```

On an entry from user mode the swap leaves `sscratch` holding the user's `tp`. The stub reads it (`csrr t0, sscratch`, line 175) to save it and never writes zero back. The kernel then runs with `sscratch` equal to whatever the process put in `tp`. Two ways a supervisor-mode trap arrives in that state:

1. **Fault path.** A user fault reaches `reap_user_fault`, which sets `sstatus.SIE` (line 367) and runs the reap with interrupts on. Any timer tick or shootdown IPI (inter-processor interrupt) during the reap enters the vector from supervisor mode with `sscratch` = user `tp`.
2. **Preemption path.** A timer tick preempts the user task and the scheduler switches to a context saved in supervisor mode (the idle task, or a task that yielded inside a syscall). The vector's "restore for sret to S-mode" block (lines 201-234) does not touch `sscratch`; only the return-to-user block (line 239) and the yield stub (`src/arch/riscv64/mod.rs:484-488`) maintain it. The resumed supervisor context runs with interrupts on and `sscratch` = the preempted process's `tp`.

In either case the next supervisor-mode trap does the swap, finds `tp` non-zero, and takes the user-entry branch:

```
sd sp, 40(tp)                   // PerCpu.user_sp_scratch = user_sp
ld sp, 24(tp)                   // sp = PerCpu.kernel_stack_top
```

with `tp` = the process's value. Rust user programs leave `tp` at its initial zero, which is why boots pass.

**Proposed fix.** Write `sscratch = 0` on the user-entry path immediately after the user `tp` has been read into the frame (before anything can trap), so the invariant the vector depends on holds for the whole time the kernel runs. Do not rely on the exit paths to restore it. A cheap cross-check in the user-entry branch (`sstatus.SPP == 0`) would turn any future violation into a typed kernel fault instead of a store through a user value.

**Demonstration.** Probe 4: allocate 16 MiB (so the reap is long), `li tp, 0xdead0000`, store to page 0. Serial log:

```
[PROBE-TP] U-mode: allocate 16 MiB, set tp = 0xdead0000, then fault
  [Fault] U-mode scause=15 PageFault stval=0x10 sepc=0x40006e
  [Fault] pid=10 task=8 PageFault at 0x10 (pc=0x40006e) — reaping

!! RISC-V S-MODE TRAP — KERNEL FAULT !!
  cause: store/AMO page fault
  sepc:  0xffffffff802034e2
  stval: 0xdead0028  (faulting store address)
```

`sepc` is `_riscv_trap_vector + 0x52`, the `sd sp, 40(tp)`; `stval` is `0xdead0000 + 40`. Two earlier variants (set `tp` and spin; set `tp` and fault with a small address space) booted to the shell: the window is the time the kernel spends in supervisor mode with interrupts on, and a short reap did not span a tick.

### M3. x86_64: `syscall` entry masks only the interrupt flag; a set trap flag reaches ring 0 on the user's stack pointer and halts the kernel

- **Lens:** trap and syscall entry.
- **Severity:** high. Unprivileged kernel halt in four instructions; the CPU writes an exception frame at an address the process chose, with ring-0 rights.
- **Confidence:** confirmed under QEMU (appendix, probe 2).
- **Location:** `src/arch/x86_64/syscall.rs:94-97` (`SFMASK = 0x200`), `:143` (first instruction still on the user stack), `:212-222` (return path).

**Path.** `pushfq; or qword ptr [rsp], 0x100; popfq; syscall`. SFMASK clears only IF, so TF (trap flag) survives the transition and the single-step trap (#DB, vector 1) is delivered after `syscall` completes: at ring 0, at `syscall_entry`, with RSP still the user's value because the stub has not switched stacks yet. There is no privilege change, so the CPU pushes the frame at the user-supplied RSP. The IDT has no handler for vector 1 (see "Seen outside scope"), so delivery escalates to a double fault and the handler halts the CPU.

**Why the code allows it.**

```
// SFMASK: RFLAGS bits to CLEAR on SYSCALL entry
// 0x200 = IF — disable interrupts until the handler explicitly re-enables them
unsafe { super::msr::write(MSR_SFMASK, 0x200) };
```

The same mask leaves NT (nested task; an `iretq` with NT set faults, and a syscall preempted by the timer returns through `iretq`), AC (alignment check) and DF (direction; the stub does run `cld`) under user control inside the kernel.

**Second path on the same stub.** The return sequence restores the user RSP and then chooses between `sysretq` and a ring-0 `jmp rcx` on bit 47 of the saved return address:

```
"pop rsp",              // user RSP (safe: sysretq doesn't touch stack)
"bt rcx, 47",
"jc .Lsyscall_kernel_ret",
```

A `syscall` instruction whose last byte is at `0x7FFF_FFFF_FFFF` saves `RCX = 0x8000_0000_0000`, which has bit 47 set. The loader accepts a segment ending exactly at `USER_SPACE_END` (`src/loader/mod.rs:222` rejects only `seg_end > USER_SPACE_END`). The stub then runs `push r11; popfq; jmp rcx` in ring 0 on the user stack and takes a general-protection fault there on the non-canonical jump. By tracing; not run.

**Proposed fix.** Set SFMASK to clear at least TF, DF, IF, IOPL, NT and AC. Remove the ring-0 return branch from the production stub (it is documented as "for ring 0 testing") or select it from a kernel-side fact, not from a bit of the return address. Reject a user segment that includes the last user page, or check `RCX` is canonical-low before `sysretq`. Give #DB an IST stack like the double fault has.

**Demonstration.** Probe 2. Serial log:

```
[PROBE-TF] ring 3: set RFLAGS.TF then syscall
EXCEPTION: DOUBLE FAULT (code: 0x0)
InterruptStackFrame {
    instruction_pointer: VirtAddr(0xffffffff80005294),   // syscall_entry
    code_segment: 8,
    cpu_flags: 0x102,                                    // TF set, IF clear
    stack_pointer: VirtAddr(0x7fffe8),                   // the user stack
    stack_segment: 16,
}
```

### M4. x86_64: the syscall handler finds "the current task" through a per-CPU pointer read while the task can still be migrated, so a syscall can be dispatched under another task's process ID and page-table root

- **Lens:** lifetime and concurrency.
- **Severity:** high. Cross-process identity confusion: capability checks and user-buffer copies run against a different process.
- **Confidence:** confirmed by tracing; the window is a few instructions wide and was not hit under QEMU. What would settle it: a kernel test hook that forces a preemption and migration between the two instructions named below, then asserts `ctx.process_id` equals the caller's.
- **Location:** `src/lib.rs:149-154` (`local_scheduler`), `src/arch/x86_64/syscall.rs:174` (`sti`), `:249-260`; `src/lib.rs:957-1035` (`try_load_balance`), `src/scheduler/mod.rs:1514-1527` (`pick_migratable_task`).

**Path.**

1. The entry stub enables interrupts (`sti`) and calls `syscall_handler_inner`, which evaluates `crate::local_scheduler().lock()`.
2. `local_scheduler()` reads `gs:[0]`, loads `cpu_id`, and returns `&PER_CPU_SCHEDULER[cpu_id]`. Interrupts are on and the preempt count is zero.
3. A timer tick lands after the read and before `IrqSpinlock::lock` disables interrupts. The task goes Ready on CPU A.
4. The BSP (bootstrap processor) idle loop runs `try_load_balance`; `pick_migratable_task` returns any Ready, unpinned task with no regard for whether it was preempted in the kernel; the task moves to CPU B.
5. On CPU B the task continues: it locks CPU A's scheduler and reads `s.current_task()` and `task.process_id` / `task.cr3` — the task now running on CPU A.
6. `SyscallContext { process_id, task_id, cr3 }` is built from that other task and the syscall is dispatched with it.

**Why the code allows it.**

```rust
pub fn local_scheduler() -> &'static IrqSpinlock<Option<Box<Scheduler>>> {
    let cpu_id = unsafe { arch::x86_64::percpu::current_percpu().cpu_id() } as usize;
    &PER_CPU_SCHEDULER[cpu_id]
}
```

The function returns a reference whose meaning ("this CPU's") expires at the first preemption point, and its type does not say so. AArch64 and riscv64 take the lock with interrupts still masked from exception entry, so only x86_64 has the window at syscall entry; every other `local_*()` accessor called with interrupts on (`local_frame_cache`, `local_reclaim_queue`, `local_timer`, `block_local_task`) has the same shape on x86_64 with milder outcomes (the lock protects the data; the "local" is wrong).

**Proposed fix.** Resolve the caller's identity before `sti`: either in the stub (pass the task pointer from `PerCpu`) or by keeping interrupts off until `syscall_handler_inner` has copied `(task_id, process_id, cr3)`. More generally, make per-CPU access return a guard that holds preemption off (the `PREEMPT_DEPTH` mechanism already exists), so "local" cannot outlive the CPU it was read on; and have `pick_migratable_task` skip tasks whose saved context is in ring 0, or accept that every kernel preemption point is a migration point and audit for it.

### M5. The kernel heap's private lock does not raise the preempt count, so its holder can be descheduled; a waiter with interrupts off or a counted lock held then spins forever

- **Lens:** lifetime and concurrency.
- **Severity:** high (whole-system hang; no memory-safety consequence).
- **Confidence:** confirmed by tracing. What would demonstrate it: a QEMU run with a one-CPU guest, a task looping `Box::new`/drop with no lock held, and a second task looping `SYS_SPAWN`; or a test hook that raises a timer interrupt inside `LockedHeapAllocator::alloc`.
- **Location:** `src/memory/heap.rs:91-99` (`acquire` / `release`), `:166`, `:260`; the rule it misses is `src/arch/spinlock.rs:46-48` and `.claude/rules/locks.md` ("A plain `Spinlock` holder is never descheduled").

**Path.**

1. Task A, in a syscall on x86_64 (interrupts on, no hierarchy lock held), enters `alloc` or `dealloc` and takes the heap's `AtomicBool` lock. `PREEMPT_DEPTH` stays 0 because this lock is not a `Spinlock`.
2. The timer preempts A inside the free-list walk. A is Ready and holds the heap lock.
3. Task B on the same CPU runs `handle_spawn`: it holds `PER_CPU_SCHEDULER[home]` (an `IrqSpinlock`, interrupts off), `PROCESS_TABLE` and `FRAME_ALLOCATOR`, and `load_elf_process` calls `alloc(kstack_layout)` (`src/loader/mod.rs:698`).
4. B spins on the heap lock with interrupts off. A cannot run on this CPU. Unless the load balancer happens to move A, the CPU is dead, and it is dead holding `PROCESS_TABLE` and `FRAME_ALLOCATOR`, so every other CPU stops at its next syscall.

The same holds for any waiter that holds a plain `Spinlock` (not preemptible by design) and for an allocation made from interrupt context. The idle-loop reaper frees kernel stacks with interrupts on, which adds holders that can be preempted. This is the 2026-10-27 spawn deadlock again, through the one lock the `PREEMPT_DEPTH` change did not cover. The x86_64 shootdown lock (`src/arch/x86_64/tlb.rs:60-68`) is the same kind of private lock; its waiters today hold nothing, so it is latent there.

**Proposed fix.** Build `LockedHeapAllocator` on `Spinlock` (so the holder is not descheduled), or on `IrqSpinlock` if any interrupt path can allocate; add the heap lock to `.claude/rules/locks.md` as a leaf. Do the same for the x86_64 shootdown lock.

### M6. The preempt count is indexed by a CPU number read before the increment; a migration in between leaves two CPUs that never preempt again

- **Lens:** lifetime and concurrency.
- **Severity:** high (liveness: a busy user loop then owns a CPU indefinitely; the timer still ticks but never switches).
- **Confidence:** confirmed by tracing; same narrow window and same migration precondition as M4. A host test of `preempt_disable` / `preempt_enable` with an injected CPU-id change between the read and the atomic would demonstrate it.
- **Location:** `src/lib.rs:576-583` and `:590-597`.

**Path.** `preempt_disable` computes `cpu = local_cpu_index()` and then `PREEMPT_DEPTH[cpu].fetch_add(1)`. If the task is preempted between the two and resumes on another CPU, it increments the old CPU's counter. The matching `preempt_enable` reads the new CPU's index and decrements that counter from 0 to `u32::MAX`. `preemption_held()` is then true on both CPUs for good (`!= 0`), and `on_timer_isr` / `on_resched_ipi` stop switching tasks there.

**Why the code allows it.**

```rust
pub fn preempt_disable() {
    if PREEMPT_DEPTH_LIVE.load(core::sync::atomic::Ordering::Acquire) {
        let cpu = local_cpu_index();
        if cpu < MAX_CPUS {
            PREEMPT_DEPTH[cpu].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
```

**Proposed fix.** Make the read-and-increment atomic with respect to preemption: a single `gs`-relative `inc` on x86_64 (put the counter in `PerCpu`), or mask interrupts around the pair. Do not migrate a task whose saved context is in the kernel. A `debug_assert` that the decrement does not wrap would have turned this into a visible failure.

### M7. riscv64: a TLB shootdown waits for acknowledgements while its caller holds `PROCESS_TABLE` and `FRAME_ALLOCATOR`; a hart spinning on either with interrupts masked can never acknowledge

- **Lens:** lifetime and concurrency.
- **Severity:** high on riscv64 SMP (deadlock in ordinary operation: one process exits or frees while another makes a memory syscall).
- **Confidence:** confirmed by tracing. What would demonstrate it: riscv64 QEMU with `-smp 2`, one process looping `SYS_ALLOCATE`/`SYS_FREE` and one looping spawn-and-exit.
- **Location:** `src/memory/mod.rs:325-326` (`unmap_page` calls `shootdown_page`), `src/arch/riscv64/tlb.rs:187-235`; callers `src/process.rs:951` (under both locks), `src/syscalls/dispatcher.rs:1031` (under `PROCESS_TABLE`), `:3489` (under both).

**Path.** On AArch64 and riscv64 `unmap_page` invalidates inside the call. On riscv64 that is `broadcast_shootdown`: send an SBI (Supervisor Binary Interface) IPI to every other online hart and spin until `SHOOTDOWN_ACK` reaches the target count. The callers hold `PROCESS_TABLE`, and for exit and channel teardown `FRAME_ALLOCATOR` too. riscv64 syscall handlers run with `sstatus.SIE` clear from trap entry until their first yield, so a second hart that is in any syscall and spinning on `PROCESS_TABLE` or `FRAME_ALLOCATOR` — or on `SHOOTDOWN_LOCK` itself, for a concurrent unmap — cannot take the IPI. The initiator waits for an acknowledgement that cannot come; the waiter waits for a lock the initiator holds.

Two smaller defects in the same protocol: acknowledgements are a count, not a set (`SHOOTDOWN_ACK.fetch_add(1)`), so one hart acknowledging twice for any reason satisfies the wait while another hart has not flushed; and `1u64 << hart_id` (`tlb.rs:120`, `:164`) is guarded only by a `debug_assert` for hart IDs of 64 and above.

**Proposed fix.** Split unmap from invalidate on every architecture the way x86_64 already does: clear the entries under the locks, drop the locks, shoot down, then free the frames (`teardown_channel_mappings` is the model, `dispatcher.rs:3553-3578`). Track acknowledgements as a hart mask. Bound the wait and report a typed error.

### M8. aarch64: the kernel-fault stub switches to `SP_EL0`, which during a syscall is the user's stack pointer

- **Lens:** trap and syscall entry (fault path).
- **Severity:** medium. It needs a kernel fault to start from (several known findings supply one), and then turns a diagnostic halt into a write and a Rust call frame at an address the process chose.
- **Confidence:** confirmed by tracing. A test hook that dereferences a bad pointer inside a syscall, with the caller's `sp` set to an unmapped or kernel address, would show the recursion or the write.
- **Location:** `src/arch/aarch64/mod.rs:743-748`.

**Path.** A syscall from EL0 (exception level 0, user) runs its handler on `SP_EL1` with `SPSel = 1`; `SP_EL0` still holds the user's stack pointer. If the handler takes a synchronous exception at EL1, the vector goes to:

```
"sync_el1_stub:",
// Exception entry forces SPSel=1. Switch back to SPSel=0 to use
// SP_EL0 (the kernel stack that was active before the fault).
"msr spsel, #0",
"stp x29, x30, [sp, #-16]!",
```

The comment is true for kernel tasks that run on `SP_EL0`; it is false for a kernel fault during a syscall. There is no PAN (Privileged Access Never) in the tree, so the store lands in user memory, or in kernel memory if the process set `sp` to a kernel address before `svc`, and `fault_el1_inner` then runs on that stack. If the address is unmapped the store faults, re-enters the same stub, and loops without printing.

**Proposed fix.** Stay on `SP_EL1` in this stub (it is the valid kernel stack in every case in which the fault came from an exception handler), or switch to a dedicated per-CPU fault stack. Record the invariant "which SP is the kernel stack in which context" in `.claude/rules/scheduling.md`.

### M9. Every read-only user mapping is executable on all three architectures: the loader ignores the segment's execute bit and the flag vocabulary has no read-only, no-execute constructor

- **Lens:** permissions and attributes; the loader.
- **Severity:** medium. Read-only data is executable in every process, and pages one process can write are executable in another (the read-only side of a channel).
- **Confidence:** confirmed by tracing.
- **Location:** `src/loader/mod.rs:568-572`; `src/memory/paging.rs:524-526`, `src/arch/aarch64/paging.rs:334` ("User read-only, executable from EL0"), `src/arch/riscv64/paging.rs:281` (`PTE_R | PTE_X | PTE_U`).

**Why the code allows it.** `SegmentLoad` carries `executable`, the verifier uses it for the W^X check, and the mapping step drops it:

```rust
let flags = if seg.writable {
    paging::flags::user_rw()
} else {
    paging::flags::user_ro()
};
```

`user_ro()` is the only non-writable user constructor and it is the code-page constructor. It is also what the kernel uses for read-only data mappings: the read-only side of a channel (`dispatcher.rs:2892`, `:3020`), the tombstone page (`:3501`, `:3537`), the audit ring (`:4531`) and the manifest blob (`src/manifest.rs:818`). A producer writes bytes into a channel; the consumer has those same frames mapped read-execute. On x86_64 this compounds with the known missing `NO_EXECUTE` on `user_rw()`.

**Proposed fix.** Split the constructor into `user_rx()` and `user_ro()` (no execute) on every architecture; have the loader choose from `(writable, executable)` with an exhaustive match and no writable-executable arm; move every data mapping to the no-execute one. A host test over each architecture's `make_leaf_pte` can assert that only `user_rx()` produces an EL0/U/ring-3-executable entry.

### M10. `load_elf_process` verifies the signature and hashes the whole binary while its caller holds a scheduler `IrqSpinlock`, `PROCESS_TABLE` and `FRAME_ALLOCATOR`

- **Lens:** lifetime and concurrency; the loader.
- **Severity:** medium (interrupts off on the spawning CPU, the target CPU's scheduler unavailable to its own timer, and both global memory locks held, for an Ed25519 verification plus a BLAKE3 pass over the ELF plus all page zeroing and copying).
- **Confidence:** confirmed by tracing.
- **Location:** `src/loader/mod.rs:497-545` (signature: `&mut ProcessTable, &mut FrameAllocator, &mut Scheduler`, then `verifier.verify` first); caller `src/syscalls/dispatcher.rs:2496-2512`.

The function's signature forces the caller to have all three locks before the first line runs, and the first thing it does is the slowest and needs none of them. The same span includes the kernel-stack heap allocation that makes M5 reachable.

**Proposed fix.** Split the loader into a lock-free phase (parse, collect, verify, returning a typed "verified image" value) and a locked phase that takes the verified value. Allocate the kernel stack before taking the scheduler lock. The verified-image type also gives the Formal Verification rule its "pure logic separated from effects" shape here. The `&dyn BinaryVerifier` parameter can become a generic at the same time (spawn is not a hot path, but the rule names kernel code generally).

### M11. Kernel stacks are unguarded blocks of the 4 MiB kernel heap, and the heap is half the size the stack bound assumes

- **Lens:** ownership; kernel rules (bounds).
- **Severity:** medium.
- **Confidence:** confirmed by tracing (sizes); the overflow consequence is as the code's own comment states.
- **Location:** `src/loader/mod.rs:30-50` and `:694-702`; `src/microkernel/main.rs:1180` (`KERNEL_HEAP_SIZE`); `src/interrupts/mod.rs:564` (IST stack, same shape).

`KERNEL_STACK_SIZE`'s comment says the bound "costs MAX_TASKS × 32 KiB ≈ 8 MiB of kernel memory"; the stacks are allocated from a heap of 4 MiB that also holds every `Box` and `Vec` in the kernel. So fewer than 128 tasks can exist, well under `MAX_TASKS` (256), and the limit arrives as `KernelStackAllocationFailed` from a spawn that has already created its process (the known leak). A stack overflow writes into whichever heap block is below: another task's saved context, a scheduler `Vec`, the IST stack. M1's trace is what that looks like when it happens. The constant carries two stacked doc comments, the first still describing 8 KiB.

**Proposed fix.** Allocate kernel stacks as frames mapped in a dedicated kernel virtual range with an unmapped guard page on each side (the "Replace when" line already names this). Until then, size the heap from `MAX_TASKS × KERNEL_STACK_SIZE` plus its other load and record the arithmetic in `docs/ASSUMPTIONS.md`. Give the double-fault stack a guard as well.

### M12. A dying driver's DMA frames go back to the allocator, and are zeroed, while its device can still write them

- **Lens:** ownership.
- **Severity:** medium (hardware-dependent: after the frames are reallocated, a device that was mid-transfer writes into another owner's memory).
- **Confidence:** plausible. What would settle it: on QEMU, kill `virtio-net` or `virtio-blk` with receive buffers posted and check whether the device model writes to the freed frames; on hardware, the same with an NVMe or xHCI controller.
- **Location:** `src/process.rs:937-961` (`reclaim_user_vmas` frees every leaf, including `VmaBacking::DmaGrant` regions) reached from `destroy_process` at `:1372`.

A `DmaGrant` region records that the process was told the physical address and handed it to a device. Process exit treats it like any other region: unmap, `frame_alloc.free`, zero. Nothing resets the device, clears bus-master enable, or waits. With no IOMMU (input-output memory management unit) the device's view of those frames is unchanged. This is a distinct owner from the cases in the known list (the kernel's copies after a block driver exits): here the second owner is hardware.

**Proposed fix.** In the ownership record this review's census is meant to feed, give DMA grants their own state with a release condition: the device that was given the address has been quiesced (bus-master disabled or reset by the kernel through the device table it already keeps), or the frames are quarantined and never reused. Until then, do not return `DmaGrant` frames to the allocator on exit.

### M13. `map_page` on aarch64 and riscv64 accepts any virtual or physical address; x86_64 `unmap_page` and `translate` still panic on a non-canonical one

- **Lens:** permissions and attributes; kernel rules. This is the review of the `425bc05` fix.
- **Severity:** medium.
- **Confidence:** confirmed by tracing.
- **Location:** `src/memory/mod.rs:268-297`; `src/arch/aarch64/paging.rs:149`; `src/arch/riscv64/paging.rs:123`; `src/memory/paging.rs:168` and `:259`.

`425bc05` made the x86_64 `map_page` return `InvalidAddress` (`VirtAddr::try_new`, `PhysAddr::try_new`). The shared AArch64 / RISC-V `map_page` has the same error variant and never returns it. A virtual address with bits above 47 set is silently reduced by the index masks (`(va >> 39) & 0x1FF`) and mapped at the truncated address. A physical address is OR-ed or shifted into the entry unmasked: on AArch64 bits 48-63 of `phys` land on the reserved, contiguous-hint, PXN and UXN bits of the descriptor (`phys | DESC_VALID | ...`); on riscv64 `(phys >> 12) << 10` puts bits 56 and up on the reserved, PBMT and N bits. `handle_map_mmio` passes a physical address that comes from a device's BAR (Base Address Register) register.

On x86_64 the fix stopped at `map_page`: `unmap_page` calls `VirtAddr::new(virt_addr)` and `translate` calls `VirtAddr::new(virt_addr)`, both of which panic on a non-canonical address. Today's callers pass tracked or loader-checked addresses, so this is a rule violation waiting for a caller, not a reachable panic. The same function reports every `map_to` failure, including an out-of-memory in an intermediate table, as `AlreadyMapped` (`paging.rs:147`), which `claim_mmio_page` then acts on by unmapping.

**Proposed fix.** Validate in one place for all three architectures: a `UserVirtPage` / `PhysFrame` newtype whose constructor checks alignment, the per-architecture user-half bound, and the physical-address width, so `map_page` cannot be called with anything else (Convention "invariants encoded in types"). Use `try_new` in `unmap_page` and `translate`. Map `MapToError` variants one to one.

### M14. `VmaTracker::register_region` does not enforce the tracker's no-overlap invariant, and the loader's regions can overlap each other, the fixed user stack, and the bump area

- **Lens:** ownership; the loader.
- **Severity:** low (the harm found is to the process itself and to leak accounting).
- **Confidence:** confirmed by tracing.
- **Location:** `src/process.rs:85-92` (stated invariants), `:175-202`; `src/loader/mod.rs:563-566`, `:649-654`, `:658-691`.

The struct documents "No two `Some` entries overlap". `register_region` checks alignment and the upper bound and then stores. Three ways the loader produces overlap from a binary the verifier accepts: two same-permission segments that share a page each register that page (the verifier's page check, 4a, rejects only differing permissions); a segment that covers `[0x7F0000, 0x800000)` collides with the user stack, which the verifier does not know about (the stack `map_page` then fails and the half-built process is left behind); a segment at or above `VMA_ALLOC_BASE` (`0x1000_0000`) sits where `allocate_region` will later hand out addresses, so `SYS_ALLOCATE` returns `OutOfMemory` and leaks one frame per call. Related loader gaps, same severity: a segment may start at virtual address 0 (see M1); `p_filesz > p_memsz` is not rejected (the copy stays inside the mapped page, `loader/mod.rs:628-630`, so it is not a memory-safety issue, but bytes beyond `memsz` are loaded); the entry point is checked to be inside a segment, not inside an executable one.

**Proposed fix.** Make `register_region` return a typed error on overlap, and have the verifier reject segments that touch page 0, the stack range, the bump area, or the last user page, and `filesz > memsz`. Register one region per distinct page run, not per segment.

### M15. The RAM-extent table silently drops extents past 16 while the allocator still hands those frames out; the comment says the opposite, and the table covers only USABLE memory

- **Lens:** ownership; this is the second layer of the `425bc05` fix.
- **Severity:** low.
- **Confidence:** confirmed by tracing.
- **Location:** `src/memory/frame_allocator.rs:174-213`; consumer `src/syscalls/dispatcher.rs:1853-1862`.

`add_region` clears the bitmap bits for every frame of the region and only then records the extent if there is room. The comment claims "the bitmap-tracked frame allocator still refuses to hand those frames out"; it does not — the frames of a 17th extent are allocatable RAM that `is_ram_overlap` reports as not RAM. `boot::MAX_MEMORY_REGIONS` is 128 and its comment expects "several dozen" entries on real firmware, so more than 16 usable extents is ordinary. The `MAX_RAM_EXTENTS` row of `docs/ASSUMPTIONS.md` sizes the table for "2-3 extents" on a typical PC and repeats the claim that a dropped extent is harmless. Separately, the table records only `Usable` regions, so the "broken or hostile device" check in `handle_map_mmio` does not cover a BAR that points at the kernel image, a boot module, or the bootloader-reclaimable frames that hold the kernel's page tables — the memory the first review's probe wrote through.

**Proposed fix.** Have `handle_map_mmio` use the same question the `bb32b7b` fix asks (`frame_is_ram` over the boot memory map, which holds every region), and delete `ram_extents`. If it stays, refuse to free frames of an extent that could not be recorded and make the drop a typed boot error.

### M16. x86_64: a process's kernel half is a snapshot of whichever PML4 was active when it was created

- **Lens:** ownership; permissions.
- **Severity:** low.
- **Confidence:** plausible. What would settle it: list every kernel `map_page` into the direct map that can run after the first process exists and check whether any can need a PML4 (Page Map Level 4, the x86_64 root table) slot that was empty at boot (a 64-bit BAR or framebuffer above the highest mapped 512 GiB slot would).
- **Location:** `src/memory/paging.rs:352-363`; riscv64 equivalent `src/memory/mod.rs:444-466`.

`create_process_page_table` copies entries 256..512 from `Cr3::read()`, the spawner's root, not from `kernel_cr3()`. Lower-level kernel tables are shared, so most later kernel mappings propagate; a mapping that needs a new top-level entry exists only in the root it was made through. A syscall on a process that lacks the entry would fault in ring 0. The active-root guard in `reclaim_process_page_tables` (`:421-440`) has the same single-CPU view: it compares against this CPU's CR3 only, which is sufficient today (one task per address space, every switch reloads the root) and is the clause ADR-034 says changes when threads arrive.

**Proposed fix.** Copy from the canonical kernel root, and pre-populate all 256 kernel-half PML4 entries at boot so the top level never changes afterwards (then the snapshot is always complete, and the fact can be asserted).

### M17. riscv64: the boot page tables map the whole 512 GiB direct map and the kernel image read-write-execute, and the identity map stays in the kernel root

- **Lens:** permissions and attributes.
- **Severity:** low.
- **Confidence:** confirmed by tracing.
- **Location:** `src/arch/riscv64/entry.rs:205-256`.

Every gigapage leaf is `V | R | W | X | G | A | D`: kernel text is writable, all of RAM and every device range is executable in supervisor mode, and `L3[0]` keeps a supervisor-only identity map of the low 512 GiB in the root that kernel and idle tasks run on (a null-pointer dereference in a kernel task reads physical page 0 without faulting). Process roots copy only entries 256..512, so the identity map does not reach user address spaces.

**Proposed fix.** After the jump to the high half, drop `L3[0]`; map the direct map `R | W` without `X`; map the kernel image with per-section permissions (text `R | X`, rodata `R`, data `R | W`).

### M18. aarch64: TLB invalidation of a kernel-half address puts address bits in the TTL field of the `TLBI` operand

- **Lens:** lifetime and concurrency.
- **Severity:** low (no kernel-half unmap exists on aarch64 today).
- **Confidence:** plausible; settle by reading the Arm Architecture Reference Manual entry for `TLBI VALE1IS` (operand bits 47:44 are TTL, translation table level hint, when FEAT_TTL is implemented) and by testing on an Armv8.4 core.
- **Location:** `src/arch/aarch64/tlb.rs:27-45`, `:63-72`; `src/arch/aarch64/paging.rs` `early_map_mmio` flush closure.

The operand is built as `virt_addr >> 12`. For a user address the upper bits are zero. For `0xFFFF_...` the result has bits 44-51 set: bits 43:0 are the page number as intended, and bits 47:44 are `0b1111`, which a core with FEAT_TTL reads as "64 KiB granule, level 3" and may use to skip entries that do not match. The ASID (address space identifier) field is zero in both cases, which is correct for the single-ASID design.

**Proposed fix.** Mask the operand to bits 43:0 (`(va >> 12) & ((1 << 44) - 1)`).

### M19. x86_64 TLB shootdown: the target count and the IPI audience are computed differently, and a halted CPU hangs every later shootdown

- **Lens:** lifetime and concurrency.
- **Severity:** low.
- **Confidence:** confirmed by tracing.
- **Location:** `src/arch/x86_64/tlb.rs:185-222`; `src/lib.rs:1496-1525` (`halt`).

`pending` is set from `percpu::cpu_count()` and the IPI is sent with the all-excluding-self shorthand. Any CPU that receives the IPI but is not in the count, or the reverse, makes `pending` wrap or never reach zero; the initiator spins with the shootdown lock held and no bound. `halt()` stops only the calling CPU (`cli; hlt`), so after any "kernel fault, halt" on one CPU the others keep running on whatever state the fault left and then hang at their first shootdown or at the first lock the halted CPU held.

**Proposed fix.** Track pending acknowledgements as a CPU mask built from the same set the IPI is addressed to; bound the wait. Make `halt` on a kernel fault stop all CPUs (an NMI or a dedicated IPI vector) so a faulted kernel does not continue.

### M20. Boot memory intake: riscv64 reservations are appended after the RAM regions and their failure is discarded; `Unknown` regions are not reserved

- **Lens:** ownership (reserved frames must never be handed out).
- **Severity:** low.
- **Confidence:** confirmed by tracing.
- **Location:** `src/boot/riscv.rs:668-676`, `:739-796`; `src/microkernel/main.rs:1349-1362`; `src/boot/mod.rs:467-474`.

On riscv64 RAM arrives as usable regions and the kernel image, OpenSBI, the device tree and the initrd are laid over it as later entries. Each is pushed with `let _ = info.push_memory_region(...)`, so if the table is full the reservation is dropped without a word and the allocator will hand out the kernel image. The OpenSBI extent is a hardcoded QEMU value and `/reserved-memory` is not parsed. In `init_frame_allocator`, `MemoryRegionKind::Unknown(_)` shares the arm with `Usable` and is not reserved; under the overlay model an unknown-kind region inside RAM stays allocatable. ADR-021 asks for typed boot errors here.

**Proposed fix.** Push reservations first, return a `BootError` when any push fails, and reserve every kind that is not `Usable`.

### M21. Kernel-rule and design-record disagreements (informational)

Each is one line; none is a reachable fault on its own.

- `src/process.rs:940-945`: the `// SAFETY:` on the walk in `reclaim_user_vmas` says "the process is terminated so its page table is not loaded in any CPU's CR3". ADR-034 and `destroy_process`'s own comment (`:1369-1371`) say the opposite: it is the dying task's active root. On x86_64 that is what makes the local-only flush in `unmap_page` sufficient.
- `src/memory/frame_allocator.rs:527-535`: `zero_frame_range`'s `// SAFETY:` says the frames "were just confirmed allocated (and therefore mapped via HHDM)". Allocated does not imply direct-mapped (the known `free` finding is the counterexample).
- `src/memory/frame_allocator.rs:84`: "FRAME_ALLOCATOR spinlock (lock order 6)"; it is 8. `dispatcher.rs` comments say `PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)`.
- `.claude/rules/locks.md`: "`PER_CPU_FRAME_CACHE[cpu]` — per-CPU, never held with FRAME_ALLOCATOR. Cache lock released before acquiring global allocator on refill/drain." `src/lib.rs:1393-1396` and `:1423-1426` take `FRAME_ALLOCATOR` while holding the cache lock. No inversion exists today; the record is wrong.
- `.claude/rules/kernel.md` § Memory Layout: "Frame allocator: bitmap covers 0-2 GiB physical (524288 frames, 64 KB bitmap)". The code covers 16 GiB with a 512 KiB bitmap (`frame_allocator.rs:42`).
- `src/process.rs:530-550` and `src/memory/buddy_allocator.rs:24`: each process gets a 4 MiB contiguous "heap"; the allocator placed in it manages 512 KiB (`MAX_ORDER = 19`); and `ProcessTable::allocate_for` / `free_for` have no caller in the kernel. Every process pins, and every exit zeroes under `FRAME_ALLOCATOR`, 4 MiB of contiguous RAM that nothing allocates from; `process_table_init` adds three more for kernel tasks.
- Panic paths in non-test kernel code: `assert!` in `src/memory/heap.rs:111-113`, `src/arch/x86_64/percpu.rs:265`, `src/arch/x86_64/gdt.rs:155` and `:272`, `src/arch/aarch64/percpu.rs:195`; `VirtAddr::new` in `src/memory/paging.rs:168` and `:259` (M13).
- Unbounded waits: `src/arch/x86_64/tlb.rs:216`, `:245`; `src/arch/riscv64/tlb.rs:233`; the heap free-list walks (`heap.rs`), bounded only by heap contents.
- Numeric constants without a Convention 8 tag: `MAX_LOAD_SEGMENTS` (`loader/elf.rs:291`), `USER_SPACE_END` and `DEFAULT_STACK_TOP` (`loader/mod.rs:59`, `:68`), `VMA_ALLOC_BASE` (`process.rs:39`), `MAX_INDIVIDUAL_PAGES` (`arch/x86_64/tlb.rs:32`), `MIN_BLOCK_SIZE` / `HEAP_ALIGN` (`heap.rs:17`, `:20`), `MIN_ORDER` / `MAX_ORDER` (`buddy_allocator.rs`), `ENTRIES_PER_TABLE` (`memory/mod.rs:89`), the literal `0x0000_8000_0000_0000` in `process.rs:188` and `:232`.
- `src/syscalls/user_slice.rs:66-67` says "AArch64 / RISC-V: TTBR0 / Sv48 cover 0..2^48"; true for TTBR0 (the AArch64 user root register), not for Sv48 (the known finding).

### M22. Zero-on-free does not cover frames that pass through the per-CPU cache (informational)

- **Location:** `src/lib.rs:1412-1431`, `src/memory/frame_allocator.rs:617-624`, `:488-498`.

`zero_frame_range` documents a guarantee ("if it crashes before zeroing the buffer, this guarantees the key is gone by the time the frame is reallocated"). `SYS_FREE` pushes frames to the per-CPU cache without zeroing; they keep their contents until `SYS_ALLOCATE` pops and zeroes them, or a drain reaches the global allocator. No reader gets stale data, because the only consumer of the cache zeroes on allocation (`dispatcher.rs:967-971`), but the data stays in RAM for an unbounded time, which is what the guarantee was written to prevent. Zero on push, or state the weaker guarantee.

## Ownership census

One row per site that allocates, maps, unmaps, frees, or writes through the direct map. "Assumes" is the frame state the code takes for granted; "Checks" is what it verifies. States used: **free** (bit clear), **allocated** (bit set by `allocate*`; the allocator records no owner), **reserved** (bit set, never added or explicitly reserved), **cached** (bit set, sitting in a per-CPU cache).

### In scope

| Site | Does | Assumes | Checks |
|---|---|---|---|
| `src/microkernel/main.rs:1298` | hands 4 MiB of a usable region to the kernel heap through the direct map | region is usable RAM not used by anything else | overlay scan of non-usable regions that start inside the span; none for regions that start before it |
| `src/microkernel/main.rs:1328` → `frame_allocator.rs:174` `add_region` | reserved → free for every frame of a usable region | region is RAM, not otherwise owned | index < `MAX_FRAMES`; idempotent bit accounting |
| `src/microkernel/main.rs:1335`, `:1338`, `:1359` → `frame_allocator.rs:244` `reserve_region` | free → reserved (first 1 MiB on x86_64, kernel heap, every non-usable kind but `Unknown`) | list of regions is complete | none (see M20) |
| `frame_allocator.rs:269` `allocate` | free → allocated | initialized | bit clear; index < `total_frames` |
| `frame_allocator.rs:322` `allocate_contiguous` | free → allocated for a run | initialized | every bit of the run clear; `count <= free_frames` |
| `frame_allocator.rs:429` `free` | allocated → free, then zero through direct map | caller owns the frame; frame is direct-mapped; nothing still maps it | bit set; index < `total_frames`. No owner, no alignment (address is truncated), no "was ever added" |
| `frame_allocator.rs:375` `free_contiguous` | same for a run | same | alignment; every bit set; end ≤ `total_frames` |
| `frame_allocator.rs:511-538` `zero_frame_range` | writes zeros through the direct map | frames are direct-mapped RAM | `hhdm != 0` only |
| `frame_allocator.rs:630` `FrameCache::refill` | free → cached | global lock held by caller | via `allocate` |
| `frame_allocator.rs:650` `FrameCache::drain` | cached → free (zeroed) | cached frames are valid allocated frames | via `free`; result discarded |
| `frame_allocator.rs:605` / `:617` `pop` / `push` | cached ↔ caller | pushed frame is allocated and unmapped | capacity only |
| `src/lib.rs:1383` `cached_allocate_frame` | cached → allocated (contents not zeroed) | this CPU's cache (may be another CPU's after migration; the lock still protects it) | none beyond `pop`; `unwrap` (known) |
| `src/lib.rs:1412` `cached_free_frame` | allocated → cached (no zero, no bitmap check) | caller owned the frame and unmapped it | none (known) |
| `memory/paging.rs:71` `FrameAllocatorAdapter::allocate_frame` | free → page-table frame of the root being mapped (crate zeroes it) | — | via `allocate` |
| `memory/paging.rs:117` `map_page` (x86_64) | writes a leaf into the given root; allocates intermediates | caller owns `phys` or it is device memory; caller holds what serializes this root | canonical virtual, 52-bit physical; "not already mapped". No ownership, no user/kernel-half check |
| `memory/paging.rs:164` `unmap_page` (x86_64) | clears a leaf, local `invlpg`, returns the frame | root is active on this CPU only | mapped as a 4 KiB page; panics on non-canonical input |
| `memory/paging.rs:212` `claim_mmio_page` | unmap + map with `kernel_mmio` | single-threaded boot | none beyond the two calls |
| `memory/paging.rs:233` `map_range` | loop of `map_page` | as `map_page`; partial progress stays on error | as `map_page` |
| `memory/paging.rs:295` `translate_user` | read-only walk by physical address | root and tables are live for the duration | present, user, writable-for-write, not huge at every level |
| `memory/paging.rs:333-365` `create_process_page_table` (x86_64) | free → root; zero via direct map; copy kernel half from active CR3 | active root's kernel half is complete (M16) | allocation result |
| `memory/paging.rs:374` `free_process_page_table` | root → free | no CPU has it loaded; nothing below it | none; result discarded |
| `memory/paging.rs:405-509` `reclaim_process_page_tables` (x86_64) | frees PT, PD, PDP frames of the user half, then the root | all leaves already unmapped; no CPU on this root; no walker mid-walk | not this CPU's CR3; present and not-huge per entry. Leaves still present in a freed PT are dropped unexamined; free results discarded |
| `memory/mod.rs:165-202` `walk_to_l3` | allocates and zeroes intermediates, writes table entries | every valid entry on the way is a table | valid bit only (a block or gigapage is descended into; see wider reach) |
| `memory/mod.rs:268-297` `map_page` (AArch64 / RISC-V) | writes a leaf | as x86_64 | "not already valid" only (M13) |
| `memory/mod.rs:300-329` `unmap_page` (AArch64 / RISC-V) | clears a leaf, broadcast shootdown inside the call, returns the frame | caller's locks may be held across the shootdown (M7) | leaf valid |
| `memory/mod.rs:385-409` `translate_user` | read-only walk | as x86_64 | table descriptor at L0-L2, user leaf with the access at L3 |
| `memory/mod.rs:424-470` `create_process_page_table` | free → root; zero; riscv64 copies entries 256..512 from the active `satp` | active root's kernel half is the kernel's | allocation result |
| `memory/mod.rs:477` `free_process_page_table` | root → free | as x86_64 | none |
| `memory/mod.rs:504-596` `reclaim_process_page_tables` | frees L3, L2, L1 tables of L0[0..256], then L0 | as x86_64 | not the active root; `pte_is_table` at each level |
| `memory/mod.rs:647-657` `bootstrap_alloc` | takes one of three static frames in the kernel image for a kernel page table | single-core boot | count < 3 |
| `memory/mod.rs:670-722` `early_map_mmio_arch` | writes table and leaf entries into the kernel root; zeroes bootstrap frames | single-core boot; `pa` is device memory | `pte_is_table`; an existing block entry is replaced by a new empty table |
| `arch/aarch64/paging.rs` `early_map_mmio` | device leaf (Device-nGnRnE, no execute) in TTBR1 | as above | none on `phys_addr` |
| `arch/riscv64/entry.rs:205-256` | builds identity, direct-map and kernel gigapages in three static tables | physical 0..512 GiB may all be mapped read-write-execute | none (M17) |
| `memory/heap.rs:166-258`, `:260-336` | writes block headers and free-list nodes inside the heap region | pointer came from this allocator; lock holder keeps running (M5) | none on `dealloc` input |
| `memory/object_table.rs:172-222` | free → object table (never freed); writes every slot through the direct map | single-threaded boot | allocation result; `num_slots != 0` |
| `process.rs:796-837` `init_live` | free → process heap (4 MiB run); writes a `BuddyAllocator` at its start | slot is `Empty` | slot state; allocation result |
| `process.rs:869-875` `allocator_mut` | dereferences the heap base through the direct map | descriptor is `Live` and the heap is still owned | none (invariant by construction) |
| `process.rs:894-899` `reclaim_heap` | process heap → free, zeroed | `phys_base` is this process's heap | via `free_contiguous`; result discarded by `destroy_process` |
| `process.rs:915-964` `reclaim_user_vmas` | for every tracked page: unmap, then `free` whatever frame the leaf named | every mapped leaf in a tracked region is a frame this process alone owns | none (known); on x86_64 the flush is local only, which is sufficient because the root is active on this CPU and nowhere else |
| `process.rs:1196-1240` `create_process` | heap + root; unwinds the heap if the root allocation fails | — | results |
| `process.rs:1345-1391` `destroy_process` | VMAs, heap, slot; returns the root for the reaper | caller enqueues the root exactly once | generation and slot state |
| `loader/mod.rs:583-586` | by-physical-address `translate` of the new root | caller holds `FRAME_ALLOCATOR` (it does, by the `&mut`) | — |
| `loader/mod.rs:593-613` | free → user page: allocate, zero, map | — | allocation and map results; nothing is undone on a later error |
| `loader/mod.rs:588-590`, `:636-639` | reuses an already-mapped frame and copies file bytes into it through the direct map | the existing mapping is this load's own earlier segment | none |
| `loader/mod.rs:659-683` | free → user stack pages: allocate, zero, map `user_rw` | stack range is unmapped | map result |
| `loader/mod.rs:694-702`, `:721-767` | kernel stack from the kernel heap; writes the initial saved context | — | null check |

### Callers outside scope (for completeness of the record; not reviewed)

| Site | Does | Frame state it creates or assumes |
|---|---|---|
| `syscalls/dispatcher.rs:102` `init_tombstone` | one frame, never freed, mapped read-only (executable) into many processes | kernel-owned, shared |
| `syscalls/dispatcher.rs:943-986` `handle_allocate` | cached → user page (zeroed, `user_rw`), tracked as `Mapped` | process-owned |
| `syscalls/dispatcher.rs:949-956`, `:1026-1034` | unmap + free / cache on rollback and `SYS_FREE` | assumes process-owned (known) |
| `syscalls/dispatcher.rs:1876-1893` `handle_map_mmio` | device frames mapped `user_mmio`, tracked as `Mapped` | device memory, later "freed" by `reclaim_user_vmas` (known) |
| `syscalls/dispatcher.rs:1936-1996` `handle_alloc_dma` | contiguous run, zeroed, mapped `user_rw`, tracked as `DmaGrant` | process + device (M12) |
| `syscalls/dispatcher.rs:2095` `handle_map_framebuffer` | framebuffer frames mapped `user_framebuffer` | device memory |
| `syscalls/dispatcher.rs:2858-2905` `handle_channel_create` | contiguous run, zeroed, mapped into the creator | channel-owned, also tracked in the creator's VMAs |
| `syscalls/dispatcher.rs:3029-3066` `handle_channel_attach` | same frames mapped into the peer; unmap on failure | channel-owned, second mapping |
| `syscalls/dispatcher.rs:3463-3578` `teardown_channel_mappings` | unmap both sides (or remap to tombstone), shootdown, then `free_contiguous` | correct order; assumes the VMA entries it removes were still present |
| `syscalls/dispatcher.rs:4537` `handle_audit_attach` | audit ring frames mapped read-only (executable) | kernel-owned, tracked in the consumer's VMAs (known) |
| `audit/drain.rs:116-126` | contiguous run, zeroed, kernel-owned for life | kernel-owned |
| `manifest.rs:750-758` | contiguous run for an unaligned manifest blob; tail of the last page not zeroed | kernel-owned, later user-mapped |
| `manifest.rs:806-822` `map_blob_into` | blob frames mapped `user_ro` (executable), not VMA-tracked | kernel-owned or boot-module, shared |
| `arch/aarch64/gic.rs:528`, `pci/mod.rs:556`, `arch/x86_64/apic.rs:293`, `arch/x86_64/ioapic.rs:171`, `arch/riscv64/plic.rs:240`, `microkernel/main.rs:1586`, `:1614` | boot-time kernel mappings of device and firmware ranges | reserved / device |
| `reaper.rs:281` | `reclaim_process_page_tables` run by the idle-loop reaper (ADR-034) | root + tables → free |

## Known findings, wider reach

- **`free` accepts a frame `add_region` never added.** `free_contiguous` (`frame_allocator.rs:375-426`) has the same gap, and `free` also accepts an unaligned address (`PhysFrame::index` truncates, `:127`, `:434`).
- **Per-CPU frame cache.** `FrameCache::drain` discards the result of every `free` (`frame_allocator.rs:650-656`), so a bad frame pushed by `SYS_FREE` disappears silently one drain later; cached frames are not zeroed (M22).
- **Failure paths leak.** In `load_elf_process` every `?` between `loader/mod.rs:550` and `:813` returns with a `Live` process slot, its 4 MiB heap, its root and tables, every frame mapped so far, and (after `:698`) a 32 KiB kernel stack; `handle_spawn` reports all of them as `OutOfMemory`. Each failed spawn consumes a process slot permanently.
- **x86_64 flags without `NO_EXECUTE`.** `user_framebuffer()` (`paging.rs:561-566`), `kernel_rw()` (`:519-521`) and `KERNEL_RO` (`:516`) omit it as well; `user_ro()` is M9.
- **`walk_to_l3_readonly` descends through blocks.** The mutating walk `walk_to_l3` (`memory/mod.rs:176-199`) has the same test (`pte_is_valid` only) on AArch64 as well as riscv64; through `map_page` it writes a leaf entry into the memory a block maps. `reclaim_process_page_tables` and `early_map_mmio_arch` do check `pte_is_table`.
- **riscv64 `USER_SPACE_END`.** The loader and `VmaTracker` use 2^47 on every architecture (`loader/mod.rs:68`, `process.rs:188`, `:232`); only `user_slice.rs:72` and the handlers that import it have the 2^48 bound.
- **Kernel heap exhaustion.** Kernel stacks are the larger consumer (M11); AP-init `assert!`s are listed in M21.
- **Process exit frees every leaf.** It also frees DMA grants under a live device (M12).

## What holds

- **A frame is never handed out twice by the allocator.** `allocate` and `allocate_contiguous` set bits only where they are clear (`frame_allocator.rs:281-299`, `:339-360`); regions between RAM extents stay set (`:154`), so a contiguous run cannot span a hole.
- **Double free through the global allocator is refused.** `free` and `free_contiguous` check the bit before clearing (`:439-441`, `:399-405`), and `free_contiguous` is all-or-nothing.
- **Kernel-owned boot memory is not allocatable on the Limine architectures.** Kernel image, modules, bootloader-reclaimable frames (which hold the boot page tables) and firmware ranges are never passed to `add_region` (`main.rs:1326-1330`) and are reserved again explicitly (`:1349-1360`); the kernel heap is reserved at `:1338`.
- **Pages given to user space are zeroed first** on every path in scope: loader segments and stack (`loader/mod.rs:601`, `:667`), and in the callers `handle_allocate`, `handle_alloc_dma`, `handle_channel_create`. New page-table frames are zeroed (`memory/mod.rs:188`, `:433`; `paging.rs:349`; the `x86_64` crate for intermediates).
- **The `bb32b7b` fix does what it says.** A kernel copy touches a user page only if every level of the walk grants the access to user mode and no level is a large page (`paging.rs:295-322`, `memory/mod.rs:385-409`, `arch/aarch64/paging.rs` `pte_table_permits_user` / `pte_leaf_permits_user`, `arch/riscv64/paging.rs` same names), and only if the frame is in a RAM region the direct map covers (`user_slice.rs:117-150`). I could not construct a leaf that passes the check and is not user-accessible on any of the three encodings. The check answers "is this direct-mapped RAM the user can reach", not "does this process own it"; kernel image and page-table frames count as RAM, so it depends on no user-accessible leaf ever pointing at them.
- **The first layer of the `425bc05` fix holds.** `handle_map_mmio` maps only ranges inside a discovered device BAR (`dispatcher.rs:1844-1852`); the weakness is in the second layer (M15) and in `map_page`'s validation off x86_64 (M13).
- **Intermediate table entries grant no more than the leaf.** x86_64: parent flags are the leaf's `PRESENT | WRITABLE | USER` subset (`x86_64` crate 0.14.13 `map_to`), in user-half tables that belong to one process. AArch64: table descriptors carry no permission bits (`make_table_pte`). riscv64: non-leaf entries carry none by architecture.
- **A user mapping cannot be created in the kernel half by the loader or the tracker**: both bound at 2^47 (`loader/mod.rs:222`, `process.rs:188`, `:232`), below the kernel half on all three architectures.
- **The ELF copy cannot leave the page it maps or the file it reads.** `copy_len` is `min(bytes left in file range, bytes left in page)` (`loader/mod.rs:628-630`) and the file range was bounds-checked against the binary (`elf.rs:316-323`); address arithmetic is bounded by the verifier's `seg_end <= 2^47` and the 256 MiB total.
- **Overlapping segments with different permissions are rejected** at byte and page granularity (`loader/mod.rs:236-275`), so the documented "first segment's permissions win" case cannot be reached with a W^X downgrade.
- **Teardown frees no kernel tables.** Both `reclaim_process_page_tables` walk entries 0..256 only (`paging.rs:453`, `memory/mod.rs:551`) and refuse the root that is active on the calling CPU in release builds (`paging.rs:421-440`, `memory/mod.rs:520-539`).
- **Channel teardown orders unmap, shootdown, free correctly** on all three architectures (`dispatcher.rs:3463-3578`).
- **x86_64 exit does not leave stale translations on other CPUs** today: no PCID, one task per address space, and every context switch writes CR3 (`arch/x86_64/mod.rs:591-622`); AArch64 flushes with `tlbi vmalle1` after every TTBR0 change (`arch/aarch64/mod.rs:1013-1015`).
- **riscv64 never sets `sstatus.SUM`**, so supervisor code cannot touch a user-accessible page except through the direct map; user memory is reached only through `translate_user`.
- **The syscall stubs take arguments from a saved frame, not from live registers** (`syscall.rs:232-268`, `aarch64/mod.rs:1085-1100`, `riscv64/syscall.rs`); the x86_64 stub does not use the user stack after the switch, and its return path disables interrupts before restoring RSP.
- **Stale process IDs do not reach another process's regions**: every tracker access goes through `resolve`, which checks slot, generation and state (`process.rs:1258-1272`), and `destroy_process` repeats the checks (`:1350-1365`).
- **Zeroed memory is not taken for `None`** in the object table or the tracker: slots are written explicitly (`object_table.rs:206-222`, `process.rs:128-148`, `:393-413`).

## Seen outside scope

- `src/interrupts/mod.rs:619-631`: the x86_64 IDT has handlers for divide error, general protection, page fault and double fault only, so any other exception raised in ring 3 escalates to a double fault and halts the kernel; confirmed under QEMU with a two-byte `ud2` (appendix, probe 3). This is the cheapest kernel halt found in this run and is what makes M3 fatal.
- `src/interrupts/mod.rs:225-234`: the double-fault handler prints through `println!`, which takes a counted `Spinlock` and reads per-CPU state; when that state is the cause, it faults inside the handler (M1's loop).
- `src/syscalls/dispatcher.rs:2892`, `:3020`, `:3501`, `:3537`, `:4531`, `src/manifest.rs:818`: read-only data mapped with the executable `user_ro()` (M9).
- `src/manifest.rs:750-758`: an unaligned manifest blob is copied into freshly allocated frames whose last-page tail is not zeroed before the pages are mapped into init and the policy service.
- `src/syscalls/dispatcher.rs:986`, `:1893`, `:1992`: a `map_page` error returns with the region tracked and earlier pages mapped (the known leak class), and reports every cause as `OutOfMemory`.
- `src/scheduler/mod.rs:1514-1527`: `pick_migratable_task` migrates tasks preempted inside the kernel (precondition of M4 and M6).
- `src/microkernel/main.rs:2253-2263`: three kernel-task "processes" each pin an unused 4 MiB heap.

## Open questions

1. Does Limine leave `CR4.FSGSBASE`, `CR4.SMEP` and `CR4.SMAP` clear on the target machines? The kernel never reads or writes CR4. If FSGSBASE is set by firmware or a later bootloader, M1 needs no segment load at all.
2. Can any interrupt handler allocate or free on the kernel heap (a `VecDeque` growing in a ready queue, a `Box` dropped in a device ISR)? If so M5 has a single-CPU form that needs no second task.
3. Is a task that was preempted in ring 0 meant to be migratable? If not, M4 and M6 close at `pick_migratable_task`; if so, every per-CPU read in preemptible kernel code needs a guard.
4. On x86_64, can a kernel direct-map `map_page` run after the first process exists and need a new PML4 entry (M16)? I found no such caller but did not read every driver path.
5. What state should a frame in a per-CPU cache have in the ownership record: free, or a state of its own? The answer decides whether `cached_free_frame` must zero and whether the bitmap or the cache is the authority for double-free detection.
6. For DMA grants (M12): is the intended release condition "device reset by the kernel" or "frames quarantined until reboot"? The kernel has the device table but no reset path today.
7. On riscv64, is the supervisor identity map at `L3[0]` relied on after boot (AP bring-up reads `BOOT_SATP` at a low address)? That decides how early it can be dropped (M17).

## Appendix: probe source

The probes replace the body of `user/faultme/src/main.rs` `run()` in a clone of the repository (never in the repository itself), with the `faultme` manifest entry changed from `lifetime = "on-demand"` to `lifetime = "one-shot"` so init spawns it in the boot wave, and for probe 4 `"allocate"` added to its `syscalls` list. x86_64: `make run-quiet TIMEOUT=240`. riscv64: `make kernel-riscv64 img-riscv64`, then the `run-riscv64` QEMU command line with `-serial file:...` under `timeout 240`. For the exception trace in M1 the x86_64 QEMU command was rerun by hand with `-d int,cpu_reset -D <file>` (the trace grows by gigabytes per minute once the loop starts; stop QEMU promptly).

```rust
#[allow(dead_code)]
const PROBE: u8 = 1; // 1 = M1, 2 = M3, 3 = ud2 (Seen outside scope)

fn run() -> ! {
    sys::print(b"[FAULTME] about to store to an unmapped page on purpose\r\n");
    cambios_libsys_rt::ready();

    #[cfg(target_arch = "x86_64")]
    if PROBE == 1 {
        sys::print(b"[PROBE-GS] ring 3: mov gs, 0x1b (user data selector) then syscall\r\n");
        // SAFETY: probe. Loads the user data selector into GS from ring 3
        // (legal: DPL 3), which reloads the hidden GS base from the flat
        // descriptor (base 0), then enters the kernel.
        unsafe {
            core::arch::asm!(
                "mov ax, 0x1b",
                "mov gs, ax",
                "mov eax, 9",          // SYS_GET_TIME
                "syscall",
                out("rax") _, out("rcx") _, out("r11") _,
            );
        }
        sys::print(b"[PROBE-GS] survived\r\n");
    }
    #[cfg(target_arch = "x86_64")]
    if PROBE == 2 {
        sys::print(b"[PROBE-TF] ring 3: set RFLAGS.TF then syscall\r\n");
        // SAFETY: probe. Sets the trap flag from ring 3 (legal) and
        // executes SYSCALL; SFMASK does not clear TF.
        unsafe {
            core::arch::asm!(
                "pushfq",
                "or qword ptr [rsp], 0x100",
                "popfq",
                "syscall",
                inout("rax") 9u64 => _, out("rcx") _, out("r11") _,
            );
        }
        sys::print(b"[PROBE-TF] survived\r\n");
    }
    #[cfg(target_arch = "x86_64")]
    if PROBE == 3 {
        sys::print(b"[PROBE-UD] ring 3: ud2\r\n");
        // SAFETY: probe. An invalid opcode executed in ring 3.
        unsafe { core::arch::asm!("ud2"); }
        sys::print(b"[PROBE-UD] survived\r\n");
    }
    // Probe 4 (M2), riscv64.
    #[cfg(target_arch = "riscv64")]
    {
        sys::print(b"[PROBE-TP] U-mode: allocate 16 MiB, set tp = 0xdead0000, then fault\r\n");
        // A large address space makes the fault reap long enough (one
        // unmap + TLB shootdown per page) to span timer ticks.
        let r = sys::allocate(4096);
        if r <= 0 {
            sys::print(b"[PROBE-TP] allocate failed\r\n");
        }
        // SAFETY: probe. tp is an ordinary user register (the TLS pointer);
        // the store that follows is the fixture's deliberate fault.
        unsafe {
            core::arch::asm!("li tp, 0xdead0000", "sd zero, 16(zero)", options(noreturn));
        }
    }
    let unmapped = 0x10 as *mut u32;
    // SAFETY: deliberate fault (original fixture behaviour).
    unsafe { core::ptr::write_volatile(unmapped, 0xDEAD_BEEF) };

    sys::print(b"[FAULTME] BUG: the store did not fault\r\n");
    sys::exit(2)
}
```

Results: probe 1 — M1 (kernel heap overwritten, kernel page fault / panic on the other CPU). Probe 2 — M3 (double fault at `syscall_entry` on the user stack). Probe 4 — M2 (supervisor store page fault at `0xdead0028` inside `_riscv_trap_vector`). Probe 3 — see below.

Probe 3 serial log (the frame is the user's: `code_segment: 35` is the ring-3 code selector, and the instruction pointer is in the probe's text):

```
[PROBE-UD] ring 3: ud2
EXCEPTION: DOUBLE FAULT (code: 0x0)
InterruptStackFrame {
    instruction_pointer: VirtAddr(0x400043),
    code_segment: 35,
    cpu_flags: 0x246,
    stack_pointer: VirtAddr(0x7fffe8),
    stack_segment: 27,
}
```
