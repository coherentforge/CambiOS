---
paths:
  - "src/**"
---

# Lock Ordering

Lock ordering MUST be followed to prevent deadlock.

```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
CLUSTER_MANAGER(5) → CHANNEL_MANAGER(6) → PROCESS_TABLE(7) →
FRAME_ALLOCATOR(8) → INTERRUPT_ROUTER(9) → OBJECT_STORE(10) →
POSIX_STORE(11) → BLOCK_BITMAP_LOCK(12) → JOURNAL_LOCK(13)
```
`*` = IrqSpinlock (saves/disables interrupts before acquiring, prevents same-CPU deadlock when timer ISR fires while lock is held). Others use plain Spinlock — including `CLUSTER_MANAGER`, `POSIX_STORE`, `BLOCK_BITMAP_LOCK`, and `JOURNAL_LOCK`, which never run in ISR context (all four are syscall-driven).

`CLUSTER_MANAGER(5)` inserted per [ADR-027 § Architecture](../../docs/adr/027-service-clusters.md). Cluster operations acquire `CLUSTER_MANAGER` → (`CAPABILITY_MANAGER` for cap promotion / revoke) → `CHANNEL_MANAGER` (per-channel teardown during cluster revoke) → `PROCESS_TABLE` (member-PID lookup) → `FRAME_ALLOCATOR` (unmap-driven frame frees). Strictly downward — no inversion.

`POSIX_STORE(11)`, `BLOCK_BITMAP_LOCK(12)`, and `JOURNAL_LOCK(13)` inserted per [ADR-029 § Decision 4](../../docs/adr/029-posix-file-storage-model.md) (POSIX_STORE + BLOCK_BITMAP_LOCK) and [ADR-029 § Divergence 2](../../docs/adr/029-posix-file-storage-model.md) (JOURNAL_LOCK promotion from POSIX-internal sub-lock to top-level position 13, to support cross-backend use forecast by [ADR-010 § Divergence 3](../../docs/adr/010-persistent-object-store-on-disk-format.md)). Acquisition patterns are strictly downward — no inversion:

- **POSIX-only write path** (e.g., `SYS_FILE_WRITE`): `POSIX_STORE → BLOCK_BITMAP_LOCK → JOURNAL_LOCK`. Skips `OBJECT_STORE` (no CambiObject touched).
- **CambiObject-only write path** (post-[ADR-010 § Divergence 3](../../docs/adr/010-persistent-object-store-on-disk-format.md) landing in step 5D): `OBJECT_STORE → BLOCK_BITMAP_LOCK → JOURNAL_LOCK`. Skips `POSIX_STORE` (no POSIX inode touched).
- **CAMBIO cross-backend transaction**: `OBJECT_STORE → POSIX_STORE → BLOCK_BITMAP_LOCK → JOURNAL_LOCK`. Full chain.

`POSIX_STORE(11)`'s concrete `Spinlock<Option<PosixFsBackend<...>>>` is reserved in the hierarchy doc but its declaration is deferred to ADR-029 migration step 6+, when the kernel singleton wire-up picks a concrete `BlockDevice`. The slot is referenced in the hierarchy now so the invariant lands with the data structures rather than as a retrofit. Unit tests use the `PosixFsBackend` instance's struct fields directly without touching the global slot.

`BLOCK_BITMAP_LOCK` and `JOURNAL_LOCK` are held only briefly — lock, mutate, journal-append, unlock. No device I/O while held; the byte writes happen with locks released, then a final commit step under-lock applies the in-memory bitmap mark (per [ADR-029 § Decision 2 step 4](../../docs/adr/029-posix-file-storage-model.md): journal record durable before in-memory bitmap commits).

Lower-numbered locks must be acquired before higher-numbered ones. See `src/lib.rs` comment.

**A plain `Spinlock` holder is never descheduled.** Syscall handlers run with interrupts on, so without help the timer could switch away from a task mid-critical-section and leave a plain lock held by a task that is not running; a CPU then spinning on that lock with interrupts masked (an `IrqSpinlock` holder — `handle_spawn` with the target scheduler lock, `wake_message_waiters_all_cpus`) can never run the holder (the 2026-10-27 spawn deadlock: init on `FRAME_ALLOCATOR`, virtio-net on `PER_CPU_SCHEDULER[0]`, the allocator's holder preempted). `Spinlock::lock`/`try_lock` raise the per-CPU `PREEMPT_DEPTH` before the acquire attempt and the guard lowers it after the release; `on_timer_isr` and `on_resched_ipi` switch tasks only when it is zero (the tick is still accounted; an expired slice is collected at the first tick after release). Interrupts stay live — this is not IrqSpinlock-everywhere. Consequence for the hierarchy's deadlock-freedom argument: every lock holder is running and makes progress. `on_voluntary_yield` debug-asserts the count is zero: never block or yield with a plain lock held (the Blocking pattern already requires dropping it first). **The boot context is held the same way:** `boot_context_holds_cpu()` is true until the BSP's `kmain` calls `boot_handoff()` at the door of its idle loop, and the ISRs switch nothing before then on any CPU. The boot context is the idle task (slot 0, one-tick slice); on x86_64 interrupts come on inside `init_hardware_interrupts`, before AP bring-up, and a slow machine's first tick handed the CPU to init mid-boot (boot-smoke CI 2026-10-31). Boot work that must precede the first task goes before that call, never after.

**Additional lock domains (independent of hierarchy above):**
- `PER_CPU_FRAME_CACHE[cpu]` — per-CPU, never held with FRAME_ALLOCATOR. Cache lock released before acquiring global allocator on refill/drain.
- `SHARDED_IPC.shards[endpoint]` — per-endpoint, never held cross-endpoint. Released before acquiring scheduler for task wake. A blocking receiver on a kernel-origin endpoint (policy queries on 22, virtio-blk commands on 26) holds `SCHEDULER → IPC_MANAGER → shard` across its block decision — the shard is the lock the kernel-side sender publishes under, so it is the lock the Blocking pattern's atomic re-check must hold (a `has_message()` that took and dropped it left the policy service sleeping through queries on the Dell 3630: `expired 11`, 2026-10-28). No path holds a shard while taking a scheduler lock.
- `BOOTSTRAP_PRINCIPAL` — written once at boot, read-only thereafter. Not part of the lock hierarchy.
- `ENDPOINT_RESERVATIONS`, `SPAWN_GRANTS`, `INIT_PROCESS` (ADR-018) — BOOTSTRAP_PRINCIPAL lifecycle: written once during single-threaded boot (manifest transcription; init creation for `INIT_PROCESS`), read-only thereafter. Not in the hierarchy; every accessor is a self-contained lock-copy-unlock, never called with another lock held.
- `AUDIT_RING` — acquired by `drain_tick()` (try_lock from BSP ISR, holds no other lock) and by `SYS_AUDIT_ATTACH`/`SYS_AUDIT_INFO` handlers (two-phase protocol: never held while PROCESS_TABLE or FRAME_ALLOCATOR is held). `audit::emit()` never touches it.
- `PER_CPU_AUDIT_BUFFER[cpu]` — lock-free SPSC; no lock at all. Written by local CPU, drained by BSP.
- `CPU_IDLE[cpu]` — lock-free `AtomicBool` per CPU, written by that CPU's own scheduling entry points after each decision, read by the wake helpers to gate the reschedule kick. Advisory: a stale read costs one timer tick, never correctness.
- `TASK_SLOT_BITMAP` — lock-free global task-slot allocator (`claim_task_slot`/`release_task_slot`, ADR-034 Residual Risk closure); CAS only, no lock. `claim` may be called while SCHEDULER is held (it acquires no lock); `release` runs in the reaper with SCHEDULER dropped. Arbitrates the global slot namespace so concurrent cross-CPU spawns can't collide.
- `SERIAL1` and `io::fbcon::FBCON` — the two console sinks, each a plain `Spinlock`, never held together: `io::print` writes serial, drops that guard, then takes the framebuffer console. Neither is in the hierarchy; nothing inside them may block or take another lock. **Interrupt handlers never call `print`/`println!`; they use `io::try_print`**, which `try_lock`s both sinks and drops the output on contention — that is what makes a plain lock safe (a handler landing on the CPU mid-print cannot spin on it). An interrupt-masking `IrqSpinlock` was tried here and froze the Dell 3630's boot mid-print (2026-10-22); interrupts stay live during the slow real-hardware console writes. The framebuffer console mirrors every `println!` / `SYS_PRINT` onto framebuffer 0 as text (x86_64; init right after `boot::populate`) and goes `Released` at the first successful `SYS_MAP_FRAMEBUFFER` — the kernel never draws over a scanout driver. Consequence for hardware debugging: on a machine with no serial, the last text line a *successful* GUI boot shows is `[SCANOUT-LIMINE] starting`; everything after the handoff is invisible unless the compositor draws. The `fbcon-hold` kernel feature (`KERNEL_FEATURES=fbcon-hold`) keeps the mirror alive for diagnosis only.
