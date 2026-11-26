---
paths:
  - "src/scheduler/**"
  - "src/arch/**"
  - "src/interrupts/**"
  - "src/ipc/**"
  - "src/syscalls/**"
  - "src/policy/**"
  - "src/microkernel/**"
  - "src/audit/**"
  - "src/io/**"
  - "src/loader/**"
  - "src/memory/**"
  - "src/fs/block_driver_client.rs"
  - "src/reap.rs"
  - "src/reaper.rs"
  - "src/lib.rs"
---

# Timer / Preemptive Scheduling

- **APIC timer** at 100Hz (periodic mode, PIT-calibrated), fires on vector 32
- **I/O APIC** routes device IRQs (keyboard, serial, IDE) on vectors 33-56
- Device ISRs: `x86-interrupt` ABI handlers, wake blocked tasks via `try_lock()` + EOI
- 8259 PIC disabled (remapped to 0xF0-0xFF, all lines masked)
- PIT used only for one-shot APIC timer calibration at boot
- Timer ISR: naked asm stub (`global_asm!` in `arch/mod.rs`) → Rust `timer_isr_inner`
- APIC EOI (`apic::write_eoi()`) replaces PIC EOI
- Emergency (IST) stacks: every CPU allocates three in its own init, for double fault (IST1, wired), NMI and machine check (IST2, IST3, wired with their handlers), 8 KiB each from the frame allocator (ADR-040 § 7). A trap entered on one never calls the scheduler
- Uses `try_lock()` to avoid deadlock when interrupted code holds a lock
- Portable `on_timer_isr()` + `ContextSwitchHint` pattern in `scheduler/mod.rs`
- **Voluntary context switch** via `yield_save_and_switch`: builds synthetic SavedContext (identical layout to timer ISR) on the kernel stack, calls `yield_inner` → `on_voluntary_yield` → `scheduler.voluntary_yield()`. No EOI (not a hardware interrupt). x86_64 (`arch/x86_64/mod.rs`): synthetic iretq frame, TSS/CR3 updates. AArch64 (`arch/aarch64/mod.rs`): synthetic eret frame, SP_EL0 via SPSel toggle, TTBR0_EL1/TLB updates. Used by handle_exit, handle_yield, handle_recv_msg (restart loop), handle_wait_irq.
- **Blocking pattern**: disable interrupts (`cli`/`msr daifset, #2`) → `block_task(Blocked)` → `yield_save_and_switch()` → re-check on wake. The interrupt disable before `block_task` prevents the timer ISR from seeing Blocked state before yield saves correct context. **When blocking on a condition another CPU signals (e.g. `MessageWait`), the condition re-check must be atomic with `block_task`** — hold the lock the signaler publishes under (IPC_MANAGER for message queues; SCHEDULER(1) → IPC(3) is downward) across the block decision, or a signal in the check-to-block gap is lost forever. And the signaler's wake must be **all-CPU** (`wake_message_waiters_all_cpus`, plain lock) — endpoint waiters can't be resolved via TASK_CPU_MAP, and a local-only or try_lock wake silently misses waiters on other CPUs (the ADR-018 boot-wave stall, 2026-09-14).
- **IPI primitives** in `apic.rs`: `send_ipi()`, `send_ipi_all_excluding_self()`, `send_ipi_self()` via ICR
- **Reschedule kick** (vector 0xFD, `RESCHED_VECTOR`): `arch::kick_cpu(cpu)` after a cross-CPU wake, sent only from syscall/kernel-thread context with the target's scheduler lock already dropped and only when `CPU_IDLE[cpu]` says the target is halted. `resched_isr_stub` → `on_resched_ipi` → `Scheduler::isr_kick`: switches off the idle task (or a no-longer-Running current), never preempts a Running task. Without it a halted core saw a wake at its next timer tick — up to 10 ms per IPC hop, the Dell 3630's slow games and 16 s wave (2026-10-26). Device ISRs do not kick (ICR reentrancy); their remote wakes still ride the tick.
- **TLB shootdown** via vector 0xFE (`tlb.rs`): `shootdown_page()`, `shootdown_range()`, `shootdown_all()` — broadcast IPI, target CPUs execute `invlpg` or CR3 reload, initiating CPU spins on atomic pending counter
- **Cross-CPU task wake**: `TASK_CPU_MAP` (`[AtomicU16; 256]` in `lib.rs`) tracks task→CPU assignment (lock-free). `wake_task_on_cpu(TaskId)` reads the map and acquires the correct CPU's scheduler to wake. `block_local_task(TaskId, BlockReason)` uses `local_scheduler()`. All IPC helpers, ISR dispatch, and diagnostics use these instead of hardcoded `PER_CPU_SCHEDULER[0]`. `migrate_task_between()` updates the map atomically.
- **IPC reply-endpoint registry**: `REPLY_ENDPOINT` (`[AtomicU32; 256]` in `lib.rs`) stores the first endpoint each process registered via `SYS_REGISTER_ENDPOINT`. `handle_write` uses this as the `from` field of outgoing messages, so receivers doing `sys::write(msg.from_endpoint(), reply)` route replies back to a queue the sender is actually listening on. Falls back to pid-slot when a process has never registered. Landed in Phase 4b — before this fix, `from` was the sender's pid slot, which was always a different number from the registered endpoint, and any reply sent via `msg.from_endpoint()` went into a queue nobody read.
