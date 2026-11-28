# ADR-040: Trap Entry Discipline - the Per-CPU Anchor, One x86_64 Trap Entry, Kernel-Owned Control Registers

- **Status:** Accepted
- **Date:** 2026-11-25
- **Depends on:** [ADR-001](001-smp-scheduling-and-lock-hierarchy.md) (per-CPU data and the context-switch paths this ADR's entry feeds), [ADR-019](019-process-fault-reaping-and-peer-generation.md) (the user-fault reap every exception arm calls), [ADR-034](034-deferred-task-resource-reclamation.md) (the reap path, which re-enables interrupts and can be preempted), [ADR-021](021-typed-boot-error-propagation.md) (typed boot errors for the per-CPU stack allocation)
- **Related:** [ADR-013](013-riscv64-architecture-support.md) (tri-architecture discipline; riscv64's `sscratch` answers the same question), [ADR-020](020-typed-user-buffer-slices-at-syscall-boundary.md) (user copies go through the direct map, which is what lets SMAP be on), [ADR-016](016-win-compat-api-ai-boundary.md) (a Windows program's thread block lives at GS, which is why `swapgs` is the v1 shape), [threat-model.md](../threat-model.md) T-4
- **Supersedes:** N/A

## Scope Boundary (read this first)

This ADR decides how the kernel takes control when the CPU enters it from a less-privileged mode: where it finds its own per-CPU data, which stack it runs on, what the entry code must do before any Rust runs, and which CPU control bits the kernel sets itself instead of inheriting.

| Concern | Owner |
|---|---|
| How the kernel finds its per-CPU data on entry from a less-privileged mode, every architecture (the principle) | **This ADR § 1** |
| x86_64: `swapgs`, the one trap entry, exception coverage, syscall entry flags, emergency (IST) stacks, CR0 / CR4 ownership | **This ADR § 2-7** |
| riscv64: the `sscratch` invariant and the entry-branch check | **This ADR § 9** |
| aarch64 trap-entry mechanism | The § 1 principle binds it; its mechanism is recorded here, as its own section, when its entry is brought under the rule |
| What the scheduler does with a saved context | [ADR-001](001-smp-scheduling-and-lock-hierarchy.md), [SCHEDULER.md](../../src/scheduler/SCHEDULER.md), unchanged |
| What happens to a task that faults | [ADR-019](019-process-fault-reaping-and-peer-generation.md), [ADR-034](034-deferred-task-resource-reclamation.md), unchanged |
| Copying to and from user memory | [ADR-020](020-typed-user-buffer-slices-at-syscall-boundary.md), unchanged |

## Context

Before this ADR, the x86_64 kernel reached its per-CPU data (`PerCpu`, which holds the kernel stack pointer the syscall entry switches to) through the GS segment base, and assumed a program could not change it. The entry stub said so in a comment: "No swapgs needed - user code cannot modify GS base (FSGSBASE not enabled)". Interrupt and exception handlers were compiler-generated `extern "x86-interrupt"` functions, with two hand-written stubs (timer, reschedule IPI) and a third save path in `yield_save_and_switch`. The interrupt descriptor table (IDT) had handlers for four of the 32 CPU exception vectors. One emergency stack (an IST entry, below) existed, on the boot CPU only, for the double fault. The kernel wrote one CR4 bit (PAE) and no CR0 bits, so the rest were whatever the bootloader or firmware left.

**IST (Interrupt Stack Table).** When the CPU takes an interrupt or exception it pushes the interrupted context onto a stack before running the handler. From ring 3 that is the current task's kernel stack (`TSS.RSP0`, rewritten at every task switch); from ring 0 it is whatever stack the kernel is on. The TSS (Task State Segment, one per CPU) also holds seven extra stack pointers. An IDT entry that names one makes the CPU switch to that stack for that vector unconditionally. That is how a double fault, an NMI (non-maskable interrupt) or a machine check gets a known-good stack when the current one cannot be trusted. The stack restarts at its top on every entry.

## Problem

1. **The per-CPU anchor was writable from ring 3.** A program can change the GS base with an ordinary segment load, which needs no CPU feature. The kernel's next syscall or interrupt on that CPU then took its stack pointer and per-CPU pointer from wherever the program pointed GS.
2. **Most exceptions had no handler.** Any exception without one escalates to a double fault, and the double-fault handler halts. A two-byte instruction in any program halted the machine.
3. **The syscall entry masked only the interrupt flag.** The trap flag, direction flag, alignment-check flag and nested-task flag reached ring 0 with the program's values.
4. **Only the boot CPU had an emergency stack.** Every other CPU's TSS held 0 there, so a double fault on it pushed to address 0, faulted again, and reset the machine with no message.
5. **The kernel ran on inherited control-register state.** SMEP and SMAP (Supervisor Mode Execution / Access Prevention) were off; FSGSBASE, OSXMMEXCPT, MCE and CR0.WP were unknown.
6. **riscv64: the kernel ran with `sscratch` holding the program's `tp`.** The user-entry path read the program's `tp` out of `sscratch` and left it there, so a trap the kernel then took in S-mode with interrupts on (a timer tick during a fault reap, or after a switch into a context saved in S-mode) took the user-entry branch, stored through `tp + 40` and loaded its stack pointer from `tp + 24`, with `tp` the program's value. An unmapped value halted the kernel; a kernel address the program could influence was a stack pivot. Separately, every return to S-mode (the vector's exit and `yield_save_and_switch`) loaded `tp` from the frame, so a kernel context saved on one hart and resumed on another brought the saving hart's `PerCpu` with it.

## Decision

### 1. The per-CPU anchor comes from state the less-privileged mode cannot write

**On entry from a less-privileged mode, the kernel locates its per-CPU data and its stack only through state that mode cannot write.** This holds on every architecture.

- **x86_64:** `IA32_KERNEL_GS_BASE`, reached by `swapgs` (§ 2).
- **aarch64:** `TPIDR_EL1`, which EL0 cannot write ([src/arch/aarch64/percpu.rs](../../src/arch/aarch64/percpu.rs)).
- **riscv64:** `sscratch`, which U-mode cannot read or write (§ 9).

### 2. x86_64: the GS invariant

**In ring 3, `IA32_GS_BASE` holds the program's value and `IA32_KERNEL_GS_BASE` holds this CPU's `PerCpu`. In ring 0, `IA32_GS_BASE` holds this CPU's `PerCpu`.** `swapgs` exchanges the two at every ring-3 boundary and nowhere else.

| Transition | Where | Rule |
|---|---|---|
| `syscall` entry | `syscall_entry`, first instruction | always `swapgs`: only ring 3 executes `syscall` (§ 5) |
| `sysretq` | `syscall_entry` exit | always `swapgs`, immediately followed by `sysretq` |
| interrupt or exception entry | the common trap entry (§ 3) | `swapgs` iff the saved CS has RPL 3 |
| `iretq` | the common exit, which every path that resumes a task uses (timer, reschedule, device, exception, the restore half of `yield_save_and_switch`) | `swapgs` iff the CS of the frame being returned *to* has RPL 3, immediately followed by `iretq`. This covers a task's first entry to ring 3 and a switch to a different task |
| NMI, #MC, #DF | IST stacks, "paranoid" entry | these can land between `syscall` and its `swapgs`, or between the exit `swapgs` and `iretq`, so they decide by reading `IA32_GS_BASE` (kernel half or not) instead of trusting CS, and restore what they found on the way out |

Rules that go with the invariant:

- **Speculation fences on both paths.** A CPU can speculatively skip a `swapgs` it should execute, or execute one it should skip (CVE-2019-1125, two variants). An `lfence` follows the conditional on both sides: after `swapgs` on the from-ring-3 path, and on the path that skips it.
- **AC is cleared on every entry.** Interrupt and exception delivery does not clear `RFLAGS.AC`, ring 3 can set it with `popfq`, and with AC set SMAP does not apply. The common entry executes `clac`. `clac` is an invalid opcode on a CPU without SMAP, so it sits behind a flag written once at boot: a branch, not code patching, so the entry path contains no self-modifying code. The syscall path gets the same from `SFMASK` (§ 5).
- **Nothing between the exit `swapgs` and its `iretq` or `sysretq` can fault.** Interrupts are off, the registers are already restored, and the two instructions are adjacent. Only NMI and #MC can land there, and their entries are paranoid.
- **The paranoid test is sound only while a program cannot put a kernel-half value in GS base.** Today the only base a program can load is 0: every user-loadable descriptor is flat and `CR4.FSGSBASE` is clear (§ 6). `wrgsbase` accepts any canonical address, so enabling FSGSBASE invalidates the test.
- **Frames the exit returns to ring 3 with come from the hardware or the loader only.** RIP, RSP and RFLAGS were saved by the CPU when the task was interrupted, or set by the loader (entry point checked inside a segment, fixed stack top); CS and SS are kernel constants. So `iretq` to ring 3 cannot fault, and there is no recovery path for a fault on it (Open Problems).

User GS base is not per-task state. With FSGSBASE clear every value a task can leave behind is 0, so nothing leaks from one task to the next (Open Problems).

### 3. x86_64: one trap entry for every vector

Every one of the 256 IDT vectors gets a small generated stub that jumps to one common entry. The entry builds the `SavedContext` the scheduler already uses and calls

```rust
extern "C" fn x86_trap(ctx: *mut SavedContext, vector: u64, error: u64) -> u64
```

which dispatches on the vector (timer, reschedule IPI, TLB shootdown, device interrupts, exceptions, unassigned) and returns the stack pointer to restore: the same contract the timer handler had. One common exit pops the context, applies the § 2 exit rule and executes `iretq`. The `extern "x86-interrupt"` ABI leaves the kernel, and with it the `abi_x86_interrupt` feature gate.

**What the stub owns.** The compiler-generated ABI did the first four without saying so; the stub does all of them explicitly:

1. **Error-code normalization.** The CPU pushes an error code for vectors 8, 10-14, 17, 21, 29 and 30 only. Every other stub pushes a 0, so every frame has one shape.
2. **The vector number**, pushed by each stub.
3. **16-byte stack alignment at the call.** The CPU aligns RSP to 16 bytes before it pushes its frame. Five hardware words, the error code, the vector and fifteen general registers make 22 words (176 bytes), so RSP is aligned at the `call`. A compile-time assertion on `size_of::<SavedContext>()` keeps the count even.
4. **`cld`** before the call: delivery does not clear the direction flag, and the SysV ABI requires it clear.
5. **`clac`**, behind the boot-time flag (§ 2).
6. **`lfence`** on both sides of the conditional `swapgs` (§ 2).
7. **A default arm for unassigned vectors.** It logs once, sends EOI (end of interrupt) unless the vector is the local APIC's spurious vector, and returns. A stray vector must not become a fault blamed on whichever task was running.

`yield_save_and_switch` builds a synthetic frame of the same shape, including the vector and error slots, and restores through the common exit.

Why one entry: one assembly path to audit and later verify, instead of about thirty compiler-written prologues; the same shape as the aarch64 and riscv64 backends (one trap vector, dispatch on a cause code); and the only place the exit-side `swapgs` can go, since the compiler-generated ABI emits its own `iretq`.

### 4. x86_64: every exception has a decision

| Source | Decision |
|---|---|
| Vectors 0-31 from ring 3 | reap the task ([ADR-019](019-process-fault-reaping-and-peer-generation.md)): `FaultKind::InvalidOpcode` for #UD, `FaultKind::ArchSpecific(vector)` for the rest. Both exist, so the audit taxonomy and `ExitInfo` wire format are unchanged |
| Vectors 0-31 from ring 0 | halt with a message through `io::try_print`; no counted lock, and no GS read the paranoid entry has not vouched for |
| NMI | not the task's fault: log through `try_print` and return. The handler must not take an exception, because the `iretq` of a nested exception re-enables NMIs and a second NMI would reuse the same IST stack |
| #MC | halt |
| #DB | an ordinary entry, not on an IST stack (§ 7) |
| reserved vectors | treated as a ring-0 bug if one ever arrives |

**A trap that enters on an IST stack never calls the scheduler.** NMI returns; #MC and #DF halt. The reap path re-enables interrupts and can be preempted ([ADR-019](019-process-fault-reaping-and-peer-generation.md) § 6), and a second entry through the same IST slot on that CPU would overwrite the first one's frames. A trap that may reap therefore arrives on the task's own kernel stack.

A program's `int N` on a gate whose DPL (descriptor privilege level) is 0 already becomes #GP, so a program cannot invoke device or IPI vectors directly.

### 5. x86_64: syscall entry

- `SFMASK` clears TF, IF, DF, IOPL, NT and AC (`0x47700`).
- There is no ring-0 return path: no kernel code executes `syscall`, and with `swapgs` at entry a ring-0 `syscall` would be wrong.
- Before `sysretq`, a return address that is not canonical in the lower half reaps the task instead of returning to it. A `syscall` in the last user page saves `RCX = 0x8000_0000_0000`, and Intel CPUs raise the resulting #GP in ring 0 on the user's stack (CVE-2012-0217). The user address ceiling (§ 8) prevents that case at its source; this check is the backstop.

### 6. x86_64: the kernel owns CR0 and CR4

Every bit gets a defined value, written at boot-CPU and secondary-CPU init:

| Bit | Value | Why |
|---|---|---|
| CR4.FSGSBASE | 0 | a program must not write GS base directly (§ 2) |
| CR4.SMEP, CR4.SMAP | 1 when CPUID leaf 7 reports them | the kernel never executes user pages, and never reads or writes a user address directly ([ADR-020](020-typed-user-buffer-slices-at-syscall-boundary.md)'s copies go through the direct map) |
| CR4.UMIP | 1 when reported | `sgdt`, `sidt`, `sldt`, `smsw` and `str` fault in ring 3 |
| CR4.OSFXSR, CR4.OSXMMEXCPT | 1 | the values FP/SIMD state saving needs: SSE enabled, and an unmasked SIMD exception is #XM rather than #UD. Until that saving exists, CR0.EM keeps every x87, MMX and SSE instruction from running |
| CR4.MCE | 1 | without it a machine check shuts the CPU down instead of reaching the #MC handler |
| CR4.OSXSAVE | 0 while FP/SIMD register state is not saved across a context switch | an AVX instruction is #UD and its program is reaped: a defined outcome |
| CR4.TSD | 1 | `rdtsc` and `rdtscp` fault in ring 3. A program gets time from a syscall, so time is the kernel's to give (it can be coarsened, or the instruction emulated) rather than a free high-resolution timer for cache side channels |
| CR4.PCE | 0 | `rdpmc` faults in ring 3: performance counters are a side channel |
| CR0.EM | 1 while FP/SIMD register state is not saved across a context switch | an x87 instruction is #NM and an MMX or SSE instruction is #UD, and the program is reaped. Without it the x87 and MMX registers, and the SSE registers once OSFXSR is set, carry one task's values into the next task on that CPU. No x86_64 code in the tree uses them: both targets are soft-float |
| CR0.AM | 0 | a program cannot turn on alignment-check faults. RFLAGS.AC then matters only to SMAP in ring 0, where every entry clears it |
| CR0.WP | 1 | the kernel honours read-only pages |
| CR0.NE, CR0.MP = 1; CR0.TS = 0; CR0.CD, CR0.NW = 0 | | x87 errors are #MF rather than the legacy FERR# interrupt once EM is 0; caching on |
| CR4.PAE, LA57, PGE, PCIDE | checked, not rewritten | paging-mode bits must match the page tables already in use; the kernel asserts the values it depends on |
| every other bit | 0, except CR0.PE, PG and ET, which stay 1 | long mode requires PE and PG; ET reads as 1 on every x86_64 CPU |

QEMU's default `qemu64` CPU model has none of SMEP, SMAP and UMIP, so every x86_64 QEMU target passes `-cpu qemu64,+smep,+smap,+umip` (the Makefile's `QEMU_CPU_X86`; spelled out rather than `max`, whose feature set changes between QEMU versions), and CI keeps one regression boot on bare `qemu64` so the feature-absent branches stay tested.

### 7. x86_64: emergency stacks on every CPU

Each CPU gets three IST stacks, for NMI, #MC and #DF, allocated during that CPU's own initialization, outside the kernel heap. Failure is a typed boot error ([ADR-021](021-typed-boot-error-propagation.md)). The stack size is a Convention 8 bound with its row in [ASSUMPTIONS.md](../ASSUMPTIONS.md).

#DB is not on an IST stack. With TF masked at syscall entry and no interface through which a program can set the debug registers, nothing raises #DB in ring 0 before the stack switch, and a #DB from ring 3 may reap (§ 4).

### 8. The user address floor and ceiling

The VMA tracker (each process's record of its mapped regions) refuses a region that covers page 0 or the last user page, whether the caller chose the address (the loader) or the tracker did (the allocator syscalls use). With page 0 refused, a future mistake in the per-CPU anchor is a fault rather than ring-0 control, even on a CPU without SMAP; with the last page refused, the § 5 non-canonical return cannot arise.

### 9. riscv64: the `sscratch` invariant

**While U-mode runs, `sscratch` holds this hart's `PerCpu` and `tp` holds the program's value. While the kernel runs, `tp` holds `PerCpu` and `sscratch` is 0.** The trap vector's first instruction, `csrrw tp, sscratch, tp`, exchanges the two, and a non-zero `tp` after it means the trap came from U-mode. The vector decides from this sentinel because at its first instruction no register is free to read `sstatus.SPP` with (x86_64 decides from the saved CS, which the CPU pushes); Linux's riscv entry uses the same sentinel.

| Transition | Where | Rule |
|---|---|---|
| trap from U-mode | `_riscv_trap_vector`, user branch | one store after entry (the program's `sp` into `PerCpu.user_sp_scratch`, addressed through `tp` = `PerCpu`), `csrrw sp, sscratch, zero` reads the program's `tp` and writes the sentinel back in one instruction; the `tp` is parked in `PerCpu.user_tp_scratch` until the frame exists. No stack is touched before the swap |
| trap from S-mode | the vector's S-mode branch | the swap finds 0 and a second swap restores it; `sscratch` stays 0 |
| `sret` to U-mode | the vector's exit when the frame's SPP is 0; `yield_save_and_switch` for a target whose SPP is 0 | `csrw sscratch, tp` (this hart's `PerCpu`) just before the program's registers are restored. Every saved frame's `sstatus` has SIE = 0, so no interrupt lands between it and `sret` |
| `sret` to S-mode | the vector's exit when SPP is 1; `yield_save_and_switch` for a target whose SPP is 1 | `sscratch` is already 0; the yield path writes 0 again. `tp` is not loaded from the frame: it holds this hart's `PerCpu`, and the frame's copy is the hart the context was saved on |
| hart start | `percpu::init_bsp`, `percpu::init_ap` | `csrw sscratch, zero` before the trap vector is installed: the privileged spec leaves its value at hart start unspecified |

**The entry-branch check.** The vector passes the branch it took to the Rust handler, which compares it with `sstatus.SPP` before any dispatch and halts with `TrapError::EntryBranchMismatch` if they disagree. Under the rule above the kernel runs with `sscratch` non-zero only in the entry stub before its `csrrw` and in the exit path after `csrw sscratch, tp`, and there the value is this hart's own `PerCpu`, so a trap in either window is a kernel bug. The check turns it into a typed report instead of a dispatch on a frame built from the wrong anchor. It is pure logic over two integers in `src/arch/riscv64/entry_branch.rs`, which `src/arch/mod.rs` declares for the host test build on every architecture, so `make test` exercises it; no riscv64 host exists. A non-host backend's other decisions get host tests the same way.

## Architecture

| Piece | Lives in |
|---|---|
| Per-vector stubs, common entry, common exit | `src/arch/x86_64/` (a trap-entry module alongside `mod.rs`) |
| `x86_trap` dispatch and the exception decisions | `src/interrupts/mod.rs` (x86_64 arm) |
| `syscall_entry` | `src/arch/x86_64/syscall.rs` |
| CR0 / CR4 ownership, SMAP flag | `src/arch/x86_64/`, called from boot-CPU and secondary-CPU init |
| IST stacks | `src/arch/x86_64/gdt.rs` (TSS), allocated from per-CPU init |
| Floor and ceiling | `src/process.rs` (`VmaTracker`) |
| riscv64 trap vector, `sscratch` at hart start; the entry-branch check | `src/arch/riscv64/trap.rs`, `yield_save_and_switch` in `src/arch/riscv64/mod.rs`, `src/arch/riscv64/percpu.rs`; `src/arch/riscv64/entry_branch.rs` (pure, host-tested) |

## Threat Model Impact

[threat-model.md](../threat-model.md) T-4 (`unsafe` in syscall entry and exit and context switch) names the agreement between separate save paths as the invariant held by discipline alone. This ADR reduces the x86_64 save paths from three (timer stub, reschedule stub, `yield_save_and_switch`) plus about thirty compiler-generated frames to two (the common entry and `yield_save_and_switch`), both producing the same `SavedContext`, plus `syscall_entry`'s own frame. It adds one invariant to T-4's surface, the § 2 GS state, and makes it explicit. T-4 is updated when the common entry lands. On riscv64 it makes the § 9 `sscratch` state explicit in T-4's surface; T-4 is updated in the change that fixes the user-entry path.

## Verification Target

- **The GS state machine.** Per CPU, two states (kernel GS active, user GS active), with transitions only at the `swapgs` sites in § 2. Target: every path from an entry to a Rust call passes through exactly one transition into the kernel state; every path from a Rust return to `iretq` or `sysretq` into ring 3 passes through exactly one transition out.
- **Frame agreement.** `SavedContext` layout, the stub's push order and `yield_save_and_switch`'s synthetic frame agree, by compile-time assertion and host layout tests.
- **Exception totality.** `x86_trap`'s dispatch is an exhaustive match over the vector number; no vector reaches the double fault for lack of a handler.
- **The IST rule.** No IST-entered arm reaches the scheduler: checkable as a call-graph property of the NMI, #MC and #DF arms.
- **The `sscratch` state machine (riscv64).** Per hart, two states (kernel running: `sscratch` = 0; U-mode running: `sscratch` = `PerCpu`), with transitions only at the § 9 sites. Target: no path from the vector's entry reaches the Rust handler with `sscratch` non-zero, and every path to an `sret` into U-mode writes `PerCpu` to it with interrupts off and nothing after it but loads from the frame and the `sret`; every path to an `sret` into S-mode leaves `tp` as this hart's `PerCpu`.

## Alternatives Considered

### Keep GS pointing at `PerCpu` and rewrite it on every entry from ring 3

Fails at `syscall`: there is no trusted stack and no free register to find `PerCpu` with, so the syscall path needs `swapgs` anyway, and two mechanisms are worse than one. It would also be torn down for [ADR-016](016-win-compat-api-ai-boundary.md)'s compatibility layer, where the program owns GS.

### Keep the `x86-interrupt` handlers and add `swapgs` around them

Not possible: that ABI emits its own `iretq`, so there is nowhere to put the exit `swapgs`.

### Put #DB on an IST stack and state that a reaping trap's frame is never resumed

The dead frame is not the problem: the reap path itself runs on that stack with interrupts on and can be preempted, and a second #DB on that CPU would overwrite it. Removing #DB from the IST costs nothing once TF is masked at syscall entry.

### Recover from a fault on the exit `iretq` now (Linux's "bad iret" path)

Unreachable while § 2's frame rule holds, and untested assembly in the entry path is a liability. Open Problems records when to build it.

### Patch `clac` in at boot (Linux's alternatives)

Self-modifying code in the entry path is harder to audit and to verify than a branch on a boot-time flag, and the branch costs a predictable jump at a boundary that is already expensive.

## Open Problems (deferred)

> **Deferred decision.** Per-task user GS base (save and restore at context switch) and a paranoid entry that does not rely on the kernel-half test (find `PerCpu` another way, for example RDPID or the per-CPU GDT). Why: today every user GS base is 0, so neither is needed and neither can be tested. **Revisit when:** a syscall or CPU feature lets a program set a non-zero GS base (FSGSBASE enabled, or [ADR-016](016-win-compat-api-ai-boundary.md)'s thread block at GS). Both change together: the paranoid test is wrong the moment that trigger fires.

> **Deferred decision.** Recovery from a fault on the exit `iretq`. Why: unreachable while every ring-3 frame comes from the hardware or the loader. **Revisit when:** a syscall can write any field of a task's saved frame (a set-context or debugger interface).

> **Deferred decision.** Guard pages below the IST stacks. Why: the stacks live in the direct map, which has no 4 KiB holes to leave unmapped; guard pages need a kernel-stack virtual region, which task kernel stacks need too. **Revisit when:** a kernel-stack virtual region with guard pages exists for task stacks; the IST stacks move into it in the same change.

> **Deferred decision.** FP/SIMD register state saved across a context switch, so ring 3 can use x87, SSE and AVX. Why: no x86_64 program uses them today (both x86_64 targets are soft-float), and saving needs a per-task save area with its own design: eager rather than lazy, an area outside `SavedContext`, FXSAVE or XSAVE, and the initial state of a new task. **Revisit when:** a program needs floating point or vector instructions on x86_64, or the aarch64 FP/SIMD save lands, whichever is first. CR0.EM goes to 0 and CR4.OSXSAVE is decided in that change, and the probe's x87 stage becomes one that checks state survives a switch.

> **Deferred decision.** CR0.AM = 1, so a program can ask for alignment-check faults on its own accesses. Why: nothing asks for it, and with AM = 0 one fewer exception is reachable from ring 3. **Revisit when:** a program, or the [ADR-016](016-win-compat-api-ai-boundary.md) compatibility layer, needs #AC delivered.

## Sequencing

Each step is its own commit, and each step's regression-probe stage fails on the commit before it:

1. Emergency stacks on every CPU (§ 7).
2. The common trap entry and full exception coverage, GS handling unchanged (§ 3, § 4), with the `clac` flag still off. Probe stages: `ud2` and `int1`. A third, a push through a non-canonical stack pointer, is #SS on Intel hardware and a gate there; QEMU's TCG raises #GP for it, which had a handler before this step, so under QEMU it passes on the earlier kernel too.
3. Syscall entry flags, no ring-0 return path, the return-address backstop (§ 5). Probe stage: trap flag set across `syscall`.
4. `swapgs`, the paranoid entries and the fences (§ 2). Probe stages: GS reloaded from ring 3, then a syscall; then a timer interrupt.
5. CR0 and CR4 ownership, the SMAP flag on, the QEMU `-cpu` flags (§ 6). Probe stages: an x87 instruction, `rdtsc`, and (on a CPU that reports UMIP) `sidt` in ring 3 each reap the program.
6. riscv64: the `sscratch` invariant and the entry-branch check (§ 9). Probe stage: `trap-tp-reap`, a program that sets `tp` and faults with 16 MiB mapped, so that its reap, with interrupts on, spans timer ticks.
7. The user address floor and ceiling (§ 8).

## Divergence

The body above reflects the implemented design. The original wordings, with the date and commit where they changed, are preserved here.

- **Step 2's non-canonical stack push is a gate on Intel hardware only** (2026-11-25, eb0bf98). Under QEMU the push raised #GP, not #SS, and the earlier kernel had a #GP handler, so the stage passed on it too; `ud2` and `int1` are the stages that tell the two kernels apart there. The stage stays, as `trap-badstack`. *Prior wording (§ Sequencing, step 2): "Probe stages: `ud2`, a push through a non-canonical stack pointer, `int1`."*
- **The x87, MMX and SSE registers stay unavailable to ring 3 until their state is saved; TSD and AM decided** (2026-11-27, measured on 1185ae0). Step 5 read CR0 = PE ET WP PG and CR4 = PAE on both CPUs under QEMU: x87 and MMX already ran in ring 3 with no state saved across a switch, and setting OSFXSR alone would have added SSE to that channel. A scan of the built kernel and every x86_64 user program found no x87, MMX or SSE instruction and no `rdtsc` or `sidt` in user code, so EM = 1, TSD = 1 and UMIP cost nothing in the tree. QEMU's TCG emulates UMIP, so it joined the `-cpu` flags. *Prior wording (§ 6 table): "| CR4.OSFXSR, CR4.OSXMMEXCPT | 1 | without OSXMMEXCPT an unmasked SIMD exception is #UD rather than #XM |", "| CR4.TSD, CR0.AM | decided in the change that writes this table | whether ring 3 may read the time-stamp counter; whether a program can turn on alignment-check faults |", "| CR0.NE, CR0.MP = 1; CR0.EM, CR0.TS = 0 | | x87 and SSE behave as the compiler assumes |"; (§ 6 QEMU paragraph) "QEMU's default `qemu64` CPU model has neither SMEP nor SMAP, so every x86_64 QEMU target passes `-cpu qemu64,+smep,+smap`"; (§ Sequencing, step 5) "Probe stage: an unmasked SIMD exception arrives as #XM."; (Open Problems) "> **Deferred decision.** The values of CR4.TSD and CR0.AM. **Revisit when:** the change that writes § 6's table lands; it records both values here."*
- **riscv64's mechanism recorded as § 9; § Sequencing gains it as step 6** (2026-11-28; the fix is the kernel commit that follows this one, "riscv64: the trap vector keeps sscratch at 0 while the kernel runs"). The user-entry path read the program's `tp` out of `sscratch` and left it there (sandbox review of the memory core, 2026-11-24); the fix brings riscv64's entry under § 1, as the Scope Boundary anticipated. *Prior wording (Scope Boundary): "| riscv64 and aarch64 trap-entry mechanisms | The § 1 principle binds them; each architecture's mechanism is recorded here, as its own section, when its entry is brought under the rule |"; (§ 1) "- **riscv64:** `sscratch` must hold the kernel's value whenever U-mode runs; its mechanism is recorded here when the riscv64 trap entry is brought under this rule."; (§ Sequencing) "6. The user address floor and ceiling (§ 8)."*
