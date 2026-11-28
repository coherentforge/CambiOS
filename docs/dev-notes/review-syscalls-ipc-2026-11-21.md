<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors -->

# Review of the syscall boundary and the IPC layer, sandbox run 003

Scope: `src/syscalls/dispatcher.rs` (every handler), `src/syscalls/user_slice.rs`, `src/syscalls/userspace.rs`, all of `src/ipc/` and `cambios-abi/src/lib.rs`, read at commit `4d53b2b` against CLAUDE.md, the three rules files (`locks.md`, `scheduling.md`, `syscalls.md`) and ADR (Architecture Decision Record) 000, 002, 005, 006 (failure table and § Divergence 2026-10-28), 007, 019, 020, 024, 025, 026 and 027. I read every file in scope in full except the test modules. Traced end to end, including the callees outside scope they depend on: `handle_write` (with the endpoint 25 and 23 intercepts), `handle_read`, `handle_recv_msg`, `handle_try_recv_msg`, `handle_register_endpoint`, `handle_allocate`, `handle_free`, `handle_map_mmio`, `handle_alloc_dma`, `handle_map_framebuffer`, `handle_spawn` (up to `load_elf_process`, which I did not read), `handle_wait_task`, `handle_exit` through `reap_process` and `destroy_process`, `handle_revoke_capability`, the seven channel handlers with `teardown_channel_mappings`, the four cluster handlers with `do_cluster_revoke`, `handle_audit_attach` and `handle_get_process_principal`. Skimmed only: the object-store handlers (the store itself was not followed), the three volume-header and master-key handlers, `handle_device_info`, `handle_virtio_modern_caps`, `handle_port_io`, `handle_console_read`, the wall-clock pair and the two audit-info handlers. Not read: the architecture syscall entry stubs, the loader, the object store, the block-driver client. I did not run `make check-all` or `make test` on the checkout. To confirm readings I copied the tree to `/tmp/review-scratch` (outside the repository, nothing from it is committed), added ten throwaway host tests there (all pass, each asserting the behaviour a finding describes) and booted four scratch images under QEMU (Quick Emulator) x86_64 with a throwaway user program in place of `faultme`; each finding says which of these it rests on.

Findings are numbered R1 to R24 so they cannot be confused with the open F1 to F8 and K1 to K3. For each finding "reach today" names the manifest rows whose `syscalls` list admits the handler: the policy service's allowlist is the only thing between several of these and every process, and R5 shows that allowlist is off whenever the policy service is absent.

Abbreviations used below: IPC (inter-process communication), VMA (virtual memory area, the per-process region tracker in `src/process.rs`), MMIO (memory-mapped input/output), HHDM (Higher Half Direct Map, the kernel's mapping of physical memory; `.claude/rules/platform-gotchas.md`), PTE (page table entry), TLB (translation lookaside buffer), DMA (direct memory access), BAR (Base Address Register of a PCI, Peripheral Component Interconnect, device), IRQ (interrupt request), AID (Autonomic Identifier, the 32-byte Principal; ADR-025), ABI (application binary interface), TOCTOU (time-of-check to time-of-use), GUI (graphical user interface).

## Findings

### R1. `SYS_MAP_MMIO` maps the kernel image and the boot modules read-write into the caller, and panics the kernel on a physical address at or above 2^52

- Lens: both. Severity: critical. Confidence: confirmed, demonstrated under QEMU.
- Location: `src/syscalls/dispatcher.rs:1705-1780` (check at 1738-1744); `src/memory/frame_allocator.rs:224-239`; `src/microkernel/main.rs:1282-1286`; `src/memory/paging.rs:128-129` and `477-482`.
- Reach today: `virtio-blk`, `nvme`, `virtio-net`, `scanout-virtio-gpu`, `virtio-input`, `usb-host` (every row that lists `map-mmio`). No capability is checked in the handler.

Path:
1. The caller passes any page-aligned physical address and up to 16384 pages.
2. The only content check is `fa_guard.is_ram_overlap(phys_addr, map_len)` (1741), which walks `ram_extents`.
3. `ram_extents` is filled only by `add_region`, and `init_frame_allocator` calls `add_region` only for `MemoryRegionKind::Usable` (main.rs:1283-1284). The kernel image and every boot module (`ExecutableAndModules`), bootloader-reclaimable memory, the firmware's ACPI tables, reserved ranges, the framebuffer, and every other device's BAR are therefore "not RAM".
4. The handler maps the range with `flags::user_mmio()`, which is `PRESENT | WRITABLE | USER_ACCESSIBLE | NO_CACHE` (paging.rs:477-482).

Why the code allows it: the handler's comment says "Security: reject mapping RAM regions as MMIO" and the syscall doc says "Kernel validates the physical address is not in RAM regions", but the test is "not in a USABLE extent", a deny-list of one region kind. Nothing ties the range to a device the caller drives.

Second consequence, same handler: on x86_64 `map_page` builds `X86PhysFrame::containing_address(PhysAddr::new(phys_addr))` (paging.rs:129). `PhysAddr::new` in `x86_64` 0.14.13 (`src/addr.rs:441-447`) panics when any of bits 52 to 63 is set. `phys_addr = 1 << 52` is page-aligned, overlaps no USABLE extent, and reaches that line: a kernel panic from one syscall. (Confirmed by reading the crate source; not run.)

Demonstration (run): in the scratch copy the `faultme` row was given `map-mmio` and made a boot-wave service; its program probes physical addresses from 1 MiB upward, maps every range the kernel accepts, searches for the bytes `[Spawn]` and overwrites them with `[PWNED]`. Serial output of `make run-quiet` (2 CPUs, 4 GiB):

```
[PROBE] stage2 probes denied (USABLE RAM)   =000000000000bf4c
[PROBE] stage2 first non-USABLE phys mapped =00000000bf590000
[PROBE] stage2 successful SYS_MAP_MMIO calls=000000000000001b
[PROBE] stage2 non-USABLE pages mapped RW   =0000000000024970
[PROBE] stage2 kernel strings patched       =000000000000000b
  [PWNED] 'usb-host' → task 13 process 15 (parent=task 1, cpu 1)
  [PWNED] 'ccid' → task 14 process 16 (parent=task 1, cpu 0)
```

The last two lines are printed by the kernel's `handle_spawn` (`dispatcher.rs:2493`) from kernel read-only data that a ring 3 process rewrote. A process that can write kernel text holds everything.

Proposed fix: make the check an allow-list. Accept a range only if it lies wholly inside a memory BAR of a discovered PCI device (the table `SYS_DEVICE_INFO` already serves), reject anything that overlaps any memory-map entry of any kind, and bound the address by the CPU's physical address width before it reaches `map_page`. Gate the syscall on a system capability granted per driver row, and when device assignment exists bind the BAR to the row that owns the device. Have `paging::map_page` use `PhysAddr::try_new` and return a typed error.

Test: a host test on `FrameAllocator` (the scratch probe `probe_non_usable_ram_is_not_ram_overlap_and_can_be_freed` passes today and should fail after the fix); the QEMU probe above as a boot-smoke negative test ("zero successful calls outside a BAR").

### R2. `SYS_CHANNEL_ATTACH` maps the channel before it commits the attach and never rolls back: the caller keeps a mapping of frames the kernel has freed

- Lens: security. Severity: critical. Confidence: confirmed by tracing; the manager-level sequence is confirmed by a scratch host test; the race was not run under QEMU.
- Location: `src/syscalls/dispatcher.rs:2845-2932`; `src/ipc/channel.rs:616-648` and `658-689`; `src/syscalls/dispatcher.rs:3352-3386` and `3415-3418`.
- Reach today: every row with `channel-attach`: `tree`, `worm`, `sprouty`, `ping`, `hello-window`, `terminal-window`, `compositor`. One malicious GUI client and the unmodified compositor are enough.

Path:
1. The compositor creates a surface channel naming the client's Principal as peer (`user/compositor/src/windows.rs:724`, role Consumer, so the peer side is writable) and sends the channel id.
2. The client sends `DestroyWindow` and immediately calls `SYS_CHANNEL_ATTACH`.
3. Attach step 1 (2858-2872): under `CHANNEL_MANAGER` it checks `state == AwaitingAttach` and the Principal, copies `physical_base` and `num_pages`, and drops the lock.
4. Attach step 2 (2875-2909): under `PROCESS_TABLE` it allocates a VMA region and maps `num_pages` pages. For a 3 MiB surface this is 768 `map_page` calls.
5. Meanwhile the compositor handles `DestroyWindow` and, by my reading of `windows.rs:819-854`, calls `channel_close` for the owner whether or not the client has attached. `ChannelManager::close` accepts `AwaitingAttach`, removes the record and bumps the generation (channel.rs:665-688). `teardown_channel_mappings` unmaps the creator, skips the peer because `record.peer_vaddr == 0` (3352), and frees the frames (3417).
6. Attach step 3 (2912-2918): `chan_mgr.attach(...)` returns `NotFound`; the handler does `.map_err(|_| SyscallError::InvalidArg)?` and returns. The VMA region and the PTEs from step 4 stay.

The client now has a read-write mapping (at a predictable address: the VMA tracker is a bump allocator from `0x1000_0000`) of frames that are free. `free_contiguous` moves `search_hint` back to the freed range (frame_allocator.rs:413-417), so the next allocations, including page-table frames for the client's own next mapping, come from exactly those frames. Writing a page-table frame through the stale mapping gives arbitrary physical memory. When the client exits, `reclaim_user_vmas` frees the same frames a second time (`src/process.rs:949-953`), whoever owns them by then.

Why the code allows it: the check and the commit are two critical sections with the side effect between them, and the failure arm of the commit has no undo:

```rust
chan_mgr
    .attach(channel_id, caller_principal, ctx.process_id, peer_vaddr)
    .map_err(|_| SyscallError::InvalidArg)?;
```

The same hole opens without any close when two processes bound to the peer Principal (two instances of one on-demand row) attach at once (the loser returns `InvalidState` with its mapping in place), and when `map_range` fails part-way (a partial mapping of a live channel, recorded as an ordinary region that the caller's exit will free).

Proposed fix: commit first, then map, and undo on failure. Either hold `CHANNEL_MANAGER` across the map (6 then 7 then 8 is downward), or add an `Attaching` state that records `peer_pid` under the first lock so that close and revoke see the peer and tear its mapping down. Every error after the VMA region exists must unmap what was mapped and release the region. Record channel regions with their own `VmaBacking` so that neither exit nor `SYS_FREE` ever frees their frames (see R3).

Test: host test at the manager level (the scratch probe `probe_attach_after_close_fails_after_caller_mapped` shows `get` then `close` then `attach` returning `NotFound` with `peer_pid == None` on the closed record). Under QEMU: a client that sends `DestroyWindow` and attaches in a loop, then reads `0x1000_0000` after an attach that returned an error; today the read succeeds, after the fix it faults.

### R3. Regions that map memory the process does not own are recorded as ordinary regions, so process exit frees and zeroes the audit ring, device registers and anything mapped through R1

- Lens: both. Severity: high. Confidence: confirmed by tracing; the exit path was observed under QEMU in the R1 setup; the audit-ring case was not run.
- Location: `src/syscalls/dispatcher.rs:1753-1755` (`handle_map_mmio`), `1959-1961` (`handle_map_framebuffer`), `4367-4369` and `4393-4403` (`handle_audit_attach`); path through `src/process.rs:52-62`, `915-964`, `src/memory/frame_allocator.rs:429-456` and `511-539`, `src/reap.rs:374-397`.
- Reach today: `audit-tail` (audit ring), `scanout-limine` (framebuffer), the six `map-mmio` rows. No malice is needed: an ordinary exit or a fault-reap of one of these processes triggers it.

Path, audit ring:
1. `handle_audit_attach` maps the kernel's 16 ring frames into the consumer with `vma.allocate_region(page_count)`, which records `VmaBacking::Mapped`.
2. The consumer exits or faults. `reap_process` has no audit step; `AuditRing::clear_consumer` (`src/audit/drain.rs:322`) has no caller outside tests.
3. `destroy_process` calls `reclaim_user_vmas`, which for every page of every region does `unmap_page` and `frame_alloc.free(phys_frame)` (process.rs:949-953).
4. The ring frames were allocated by `allocate_contiguous` (drain.rs:116), so `free` succeeds: the bit is cleared and `zero_frame_range` wipes the frame.
5. The kernel keeps writing audit events through `kernel_vaddr` into frames the allocator now hands to the next caller. `consumer_attached` stays true, so no later process can attach.

Path, device memory: the same steps with `handle_map_mmio`. `FrameAllocator::free` only checks `idx < total_frames` and that the bit is set; a frame that was never added by `add_region` has its bit set from construction, so the call "frees" it and zeroes it through the HHDM. With 4 GiB of RAM (every `make run*` target) `total_frames` lies above the 32-bit PCI hole, so a driver's BAR pages qualify.

Observed: in the R1 run where the probe exited after mapping, the kernel's last lines were the reap line and then kernel page faults on both CPUs:

```
  [Fault] pid=14 task=12 PageFault at 0x401000 (pc=0x4002ab) — reaping
!!! KERNEL PAGE FAULT !!!
  Address: 0x25
  Type: not-present read
  CPU=1, task=9
```

That is consistent with step 3 zeroing the mapped ranges (the kernel image among them); I did not instrument the reclaim to prove which frame faulted first.

Why the code allows it: `VmaBacking` has two variants, `Mapped` and `DmaGrant`, and the reclaim treats every mapped leaf as owned ("reclaimed by walking the page table", process.rs:53-55). The handlers in scope use `allocate_region` for memory the process only borrows. The `handle_audit_attach` race arm also leaves a mapping behind ("Undo: should unmap", 4398).

Proposed fix: add a backing kind for borrowed memory (device, framebuffer, kernel-owned, channel) that exit and `SYS_FREE` unmap without freeing; detach the audit consumer in `reap_process` (unmap, `clear_consumer`); make `FrameAllocator::free` and `cached_free_frame` refuse a frame outside the recorded USABLE extents.

Test: host test on `ProcessDescriptor::reclaim_user_vmas` with a borrowed region (frame count unchanged); under QEMU, exit `audit-tail` and assert `SYS_AUDIT_INFO` still reports the ring intact and a second attach succeeds.

### R4. User copies ignore the page's permissions and what backs it: any process can have the kernel write into its read-only mappings

- Lens: both. Severity: high. Confidence: the write to a read-only page is demonstrated under QEMU; the kernel fault on a device-backed buffer is plausible (it needs one run with a BAR-mapped buffer to settle).
- Location: `src/syscalls/user_slice.rs:231-259` (and `187-224` for reads); `src/memory/paging.rs:249-253`; `src/memory/mod.rs:343-356`.
- Reach today: every process (`get-principal` and `recv-msg` are in every row).

Path:
1. `UserWriteSlice::write_from` calls `write_user_buffer`, which asks `paging::translate` for the physical address behind each page and copies through the HHDM.
2. `translate` returns the address for any present PTE. On x86_64 it is `translate_addr`; on aarch64 and riscv64 it checks `pte_is_valid` only. Neither looks at the writable or user bits.
3. The copy therefore lands in pages the caller itself cannot write.

What is mapped read-only into user processes today: program text and read-only data; the read-only side of every channel (`flags::user_ro()`, dispatcher.rs:2771-2775 and 2886-2890); the global tombstone page that revoke maps into every read-only peer (3337-3343); the audit ring (4371); the manifest blob shared by init and the policy service (`src/manifest.rs:814-818`). So the read-only side of a channel can write the channel (ADR-005's threat table: "B's mapping is RO. Writes fault."), a tombstone holder can make the shared zero page non-zero for every other holder (ADR-007 § Divergence 8 calls a writable tombstone "a data-corruption vector and a cross-process leak channel"), and the audit consumer can rewrite the ring (ADR-007: "Forgery requires kernel compromise").

Why the code allows it: the SAFETY comment states an invariant nothing enforces:

```rust
// SAFETY: phys is mapped; hhdm + phys is kernel-writable; the page
// must be RW (caller guarantees via VMA tracker / page-table flags).
```

No caller checks either. The same comment's "hhdm + phys is kernel-writable" is also assumed, not checked: a buffer inside a `SYS_MAP_MMIO` region translates to a device address that Limine's HHDM does not map (`platform-gotchas.md`), so the copy would fault in kernel mode, and a kernel fault halts.

Demonstration (run): the probe passed the address of a `static` in its read-only data to `SYS_GET_PRINCIPAL`, then stored to the same address itself:

```
[PROBE] stage1 rodata byte before=00000000000000aa
[PROBE] stage1 rodata byte after =0000000000000012
[PROBE] stage3 storing to the read-only page directly (must fault)
  [PageFault] user protection write at 0x401000 (RIP=0x4002ab)
```

Proposed fix: give the walk a direction. `translate_for_write` returns an address only for a PTE that is present, user and writable; `translate_for_read` requires present and user. Refuse pages whose region is not RAM-backed (the backing kind from R3 gives the answer). State the result as the function's contract so the SAFETY comment describes a check that exists.

Test: host test with the existing `FakeSpace` fixture extended to carry permissions; the QEMU probe's stage 1 as a boot-smoke negative test.

### R5. With no policy service the syscall allowlist is off for the whole boot, and nothing says so

- Lens: both. Severity: medium. Confidence: confirmed, demonstrated under QEMU.
- Location: `src/syscalls/dispatcher.rs:209-228` (the call and its "fail closed" comment) and `745-751` (the only place the flag is set); `src/policy/mod.rs:521-523`.

Path:
1. `policy_check` begins `if !crate::POLICY_SERVICE_READY.load(Ordering::Acquire) { return InterceptDecision::Allow; }`.
2. The flag is set only when the process recorded in `POLICY_SERVICE_PID` registers endpoint 22.
3. If that never happens (the row is missing from the manifest for a profile, the module is not staged, its signature fails, its spawn fails), init reports at most one `spawn FAILED` line and carries on; every later process runs with every syscall allowed.

CLAUDE.md allows one structural exception: "a window in which there is provably no one to ask (init before the policy service exists)". The code's exception is "the flag is unset", which also covers every other process for as long as the flag stays unset.

Demonstration (run): scratch manifest with the `policy-service` row removed and `faultme`'s row without `map-mmio`. The boot reported `boot wave settled: 15 ready, 0 spawn-failed, 0 dep-failed` and the probe's 27 `SYS_MAP_MMIO` calls succeeded (`[PWNED] 'usb-host' …` again). The control run, same row with the policy service present, denied all 57,328 calls with `enforce.syscall_denied`.

Proposed fix: make the bypass a statement about the caller, not about the flag: while the flag is unset allow only `INIT_PROCESS` and the process in `POLICY_SERVICE_PID`, deny and audit everyone else. Treat a manifest without a policy-service row as a boot error (`BootError`), the way a missing init already is.

Test: the scratch run above as a boot-smoke case (a row-less syscall must be denied with no policy service staged).

### R6. A user copy is not synchronized with another process tearing the same pages down: the kernel can read or write a frame after it was freed

- Lens: security. Severity: medium. Confidence: plausible. It would be settled by a QEMU run with a delay injected between `translate` and the copy, or by a stress run of the sequence below.
- Location: `src/syscalls/user_slice.rs:113-126` and `158-171`; `src/syscalls/dispatcher.rs:3303-3418`.
- Reach today: the copying side is any channel peer (the GUI clients); the unmapping side is the compositor's `channel_close`, or the kernel reaping the other end.

Path:
1. Process A calls `SYS_RECV_MSG` (or any syscall with a buffer) with the buffer inside its channel mapping. The copy loop translates a page, then copies to `phys + hhdm`. It holds no lock and runs with interrupts on and preemption allowed.
2. Between the translate and the end of the copy, the other end closes the channel. `teardown_channel_mappings` clears A's PTEs, issues the TLB shootdown (which A's CPU acknowledges from its interrupt handler without leaving the copy), and frees the frames.
3. A's copy completes into a frame that is free or already reallocated. For a read (`SYS_WRITE`, `SYS_PRINT`) the kernel instead copies another owner's bytes out to A.

The window is normally a few hundred nanoseconds per page, but a timer tick inside it deschedules A for a full slice with the stale physical address in hand.

Why the code allows it: ADR-020 defers construction-time or locked validation on the grounds that "TOCTOU isn't exploitable under the current single-CPU-per-process execution model". The model overlooks that channel teardown and process reap edit another process's address space.

Proposed fix: make frame release wait for copies in flight. Options: take `PROCESS_TABLE` (or a per-process address-space lock) across translate and copy; or keep a per-CPU "in user copy" epoch that teardown must observe advancing on every CPU before `free_contiguous`. Record the decision in ADR-020, whose "Revisit when" trigger names only threads.

Test: a kernel feature flag that sleeps between translate and copy, plus a two-process QEMU fixture that closes during the sleep and checks the freed frame's contents.

### R7. Two-phase channel teardown can leave a task blocked in `ChannelQuiesceWait` forever

- Lens: both. Severity: medium. Confidence: the first path is confirmed by a scratch host test on the scheduler; the others by tracing.
- Location: `src/syscalls/dispatcher.rs:2995-3068`, `3083-3135`, `3153-3208`; path through `src/scheduler/mod.rs:890-917`, `974-1004`, `1015-1046`, `src/lib.rs:906-918`, `src/reap.rs:287-302`, `src/ipc/channel.rs:80` and `796-814`.
- Reach today: `compositor` is the only row with the teardown pair; its resize path (`windows.rs:553-616`) runs begin and complete back to back. The victims are its clients.

Four ways a task is stranded:
1. Wake before park. `begin_teardown` arms the peer; if the peer is Running on another CPU `arm_quiesce` only sets `pending_quiesce_channel`. `complete_teardown` then calls `wake_quiesce_for_channel`, which touches only tasks already `Blocked(ChannelQuiesceWait)` and leaves the hint set. At its next tick or yield the peer parks itself on a channel whose only wake has already run. The compositor's resize does begin, create, notify, complete within microseconds, so the window is the normal case whenever the client is running. Scratch test `probe_quiesce_wake_before_park_strands_peer`: arm on a Running task, `wake_quiesce` returns 0, `isr_tick_and_schedule` leaves the task `Blocked(ChannelQuiesceWait)`.
2. No completion. Nothing bounds the time between begin and complete: `QUIESCE_TIMEOUT_TICKS` (channel.rs:80) has no user, although ADR-027 § Decision 3 specifies a bounded wait. If the initiator exits or faults first, `revoke_all_for_process` takes the `Revoking` record and `reap_process` tears it down without calling `wake_quiesce_for_channel`.
3. Peer-initiated teardown. The handler arms `snapshot.peer_pid` whoever called (3049-3051). When the peer itself calls begin, it arms itself, is parked at its next tick, and cannot call complete.
4. `handle_channel_quiesce_ack` checks `state == Revoking` under `CHANNEL_MANAGER`, drops it, then blocks (3162-3201). A complete that lands in between wakes nobody.

Also: `complete_teardown` takes a `kind` but the record does not store the one given to begin, so the "kind-mismatch → InvalidArg" the ABI doc promises is not checked.

Proposed fix: have `wake_quiesce` clear a matching pending hint on tasks that have not parked yet; call the wake from `reap_process` for every revoked channel; arm the endpoint that is not the caller; make the acknowledgement's state check atomic with its block (hold the scheduler lock across the check, as `handle_recv_msg` does); store the kind in the record; either implement the timeout or delete the constant and amend ADR-027.

Test: the scratch scheduler probe, inverted; a QEMU resize loop against a client that renders continuously on the second CPU.

### R8. `SYS_REVOKE_CAPABILITY` can only name a process whose slot has never been reused

- Lens: both. Severity: medium. Confidence: confirmed by a scratch host test.
- Location: `src/syscalls/dispatcher.rs:2654`; `src/ipc/capability.rs:495-508` and `784-801`.
- Reach today: none (no row lists `revoke-capability`); it is the primitive ADR-007 gives the policy service for containment.

Path: the handler builds `ProcessId::new(args.arg1_u32(), 0)`. `CapabilityManager::lookup` compares the whole id (`caps.process_id != process_id`), so for any process in a slot whose generation is 1 or more the call returns `ProcessNotFound` and the capability stays. A process that was killed and restarted, the case revocation exists for, is exactly the one it cannot reach. Scratch test `probe_syscall_shaped_revoke_cannot_reach_generation_1`.

Proposed fix: take the full 64-bit `ProcessId` in `arg1` (as `SYS_GET_PROCESS_PRINCIPAL` does), or resolve the slot's current occupant through `ProcessTable::occupant` and state in the ABI that the target is "whoever holds the slot now". Fix the ABI doc, which says `target_process_id: u32`.

Test: the scratch probe with the expected result flipped.

### R9. Failure paths leak physically contiguous runs for good, and no quota bounds what one process can take

- Lens: both. Severity: medium. Confidence: confirmed by tracing.
- Location: `src/syscalls/dispatcher.rs:1817-1845` and `1868-1875` (`handle_alloc_dma`); `2739-2768`, `2781-2789`, `2799-2814` (`handle_channel_create`); `826-877` (`handle_allocate`); `1757-1775` (`handle_map_mmio`).
- Reach today: the six driver rows (`alloc-dma`), `compositor` and the scanout drivers (`channel-create`), `sprouty` (`allocate`).

Path, worst case: a process fills its 256 VMA slots, then calls `SYS_ALLOC_DMA` with 32768 pages. The handler runs `allocate_contiguous` first and `allocate_region_with(...).ok_or(SyscallError::OutOfMemory)?` second; on the second failing, 128 MiB of frames are allocated with no record anywhere. Killing the process does not return them. `handle_channel_create` has the same order (frames, then `allocate_region`, then `map_range`, then `chan_mgr.create`, each with a bare `?`) for up to 256 MiB per call. In `handle_allocate` a `map_page` failure returns without freeing the frame just taken from the per-CPU cache or rolling back the pages already mapped, although the cache-miss arm just above it (832-852) does roll back.

Shared resources with no per-process or per-Principal bound: physical frames (`SYS_ALLOCATE` 64 MiB per call), the 256 channel slots (a create-channel holder can fill the table with channels nobody attaches), the 32 cluster slots (a cluster whose creator exits is never freed unless a member exits), process slots for a `CreateProcess` holder. All fail closed for the next caller (typed out-of-memory errors), so this is loss of service, not loss of isolation. `handle_allocate` also holds `PROCESS_TABLE`, with preemption disabled, while it zeroes and maps up to 64 MiB.

Proposed fix: reserve the VMA slot before allocating frames, and give every later failure an undo arm (the ChannelManager doc already says "the caller must unwind its frame allocation and VMA reservation"). Add per-row budgets to the manifest for frames and channels and charge them in these four handlers.

Test: host tests that drive each handler's bookkeeping to each failure and compare `free_count` before and after.

### R10. A message's `from` falls back to the sender's process slot, which is a number in the endpoint namespace

- Lens: security. Severity: medium. Confidence: the kernel side is confirmed; the effect on a particular service depends on its reply logic, which I did not read.
- Location: `src/syscalls/dispatcher.rs:516-527` (and `467-470` for the endpoint 25 path).

Path: `let from_ep = if reply_ep != 0 { reply_ep } else { ctx.process_id.slot() };`. A process that has registered no endpoint sends with `from` equal to its slot. Slots are handed out lowest-free, and after the boot wave they sit in the middle of the reserved endpoint range: in the baseline scratch boot `audit-tail`, which reserves and registers no endpoint, was process 16, so its messages carry fs-service's endpoint number as `from`; the shell was process 17, so the first on-demand app gets slot 18, the shell's endpoint. A service that answers `msg.from_endpoint()` then delivers its reply, stamped with its own Principal, into another service's queue. The attacker chooses the request; the victim receives a genuine message from a trusted sender that it never asked for. For a slot of 64 or more `from` is not an endpoint at all, against the invariant on `Message` ("`from` and `to` are valid `EndpointId` values").

Proposed fix: drop the fallback. A sender with no registered endpoint sends `from = 0` (already documented as the unusable sentinel), and receivers treat 0 as "no reply path".

Test: host test on `handle_write`'s message construction; under QEMU, an unregistered app sends a request to a replying service and the test asserts nothing arrives on the endpoint equal to its slot.

### R11. `SYS_REGISTER_ENDPOINT` grants receive, delegate and revoke to any caller on any unreserved endpoint and empties its queues

- Lens: security. Severity: low. Confidence: confirmed by tracing; the revoke consequence by a scratch host test.
- Location: `src/syscalls/dispatcher.rs:715-717` and `732-738`; `src/ipc/mod.rs:296-305` and `322-327`.

Path: for an endpoint with no reservation the handler has no check at all, then `grant_capability(ctx.process_id, endpoint, CapabilityRights::FULL)` and `clear_endpoint` on both IPC managers. A second process doing the same gets the same rights and drops whatever was queued for the first. `FULL` includes `revoke`, although the doc comment on `CapabilityRights` says "no entry declares it yet, so the syscall admits nobody until one does" and ADR-007 says the right "is *not* automatically granted". With `revoke` in hand, `CapabilityManager::revoke` lets the registrant strip any other process's capability on that endpoint (scratch test `probe_register_shape_grant_carries_revoke`). On reserved endpoints the reservation gate holds, but two live processes with the same AID (an on-demand row spawned twice) both pass it, and each registration, and each exit (`reap.rs:251-262`), clears the queue the other is reading.

Today every endpoint a service listens on is reserved in the default profile; the unreserved ones are 0, 2 to 14, 34 to 60 and, per profile, the endpoints of rows the profile omits.

Proposed fix: grant `send + receive` on registration and leave `delegate` and `revoke` to the manifest; refuse a second registrant while a live process holds the endpoint; decide whether unreserved endpoints should exist at all once every sender has a reserved reply endpoint.

Test: the scratch probe, inverted; host test for double registration.

### R12. Two enforcement checks are skipped, not failed, when their decider is absent

- Lens: correctness. Severity: low. Confidence: confirmed by reading; unreachable after boot today.
- Location: `src/syscalls/dispatcher.rs:2296-2305`; `src/ipc/mod.rs:773-779` and `800-806`.

`handle_spawn` wraps its `CreateProcess` check in `if let Some(cap_mgr) = cap_guard.as_ref() { … }` with no `else`: with no capability manager the spawn proceeds. Every other capability gate in the file uses `.ok_or(SyscallError::PermissionDenied)?`. The IPC managers do the same with the interceptor: `if let Some(ref interceptor) = self.interceptor { … }`. Both are the shape the "Enforcement fails closed" rule forbids; that both deciders are installed at boot is an argument, not a type.

Proposed fix: deny in the `None` arm of the spawn check; make the interceptor field non-optional (construct the managers with a backend).

Test: host test that dispatches `Spawn` with `CAPABILITY_MANAGER` unset and expects `PermissionDenied`.

### R13. `requires_identity()` is a list of gated syscalls, so a new syscall is exempt unless someone remembers to add it

- Lens: correctness. Severity: low. Confidence: confirmed by reading.
- Location: `cambios-abi/src/lib.rs:941-978`; tests at `1725-1784` and `1797-1828`.

The function is `matches!(self, Self::Write | Self::Read | …)`: anything not named returns `false`. The three tests rely on a hand-written `all` array and a hand-written `0..=75` bound; `all_syscall_numbers_covered` ends in `let _ = num.unwrap().requires_identity();` and asserts nothing about the result. A variant added at 76 with its `from_u64` arm and nothing else compiles, passes every test, and is callable without a Principal.

Proposed fix: an exhaustive `match self` with no wildcard that names the seven exempt variants as `false` and every other variant as `true`, so the compiler stops the build until a new variant is classified. Derive the test's variant list from `NAMES` and assert `NAMES` covers `from_u64`'s domain.

Test: the compile error is the test.

### R14. `IpcManager::new_boxed` relies on zeroed memory being `None`, and for `Option<Message>` it is not

- Lens: correctness. Severity: low. Confidence: confirmed by a scratch host test.
- Location: `src/ipc/mod.rs:662-684`.

The SAFETY comment says "Option<Message>::None = discriminant 0 = zeroed". `Message` contains an `Option<Principal>`, whose tag byte gives the outer `Option` a niche: `size_of::<Option<Message>>() == size_of::<Message>() == 312`, and `core::mem::zeroed::<Option<Message>>().is_none()` is `false` (scratch probe output: `zeroed.is_none=false`). Every slot of every queue, and `SyncChannel::message` and `reply`, start as `Some` of an all-zero message. The queue's `count` hides this for the asynchronous path; `SyncChannel::take_reply` would return a message nobody sent. No syscall reaches the synchronous path today. This is the case Convention 7 exists for, and `ChannelManager::new_boxed` and `ClusterManager::new_boxed` already do it correctly.

Proposed fix: initialise field by field with `alloc` and `addr_of_mut!().write(...)`, as the sibling managers do.

Test: host test that `new_boxed().take_reply(ep)` is `None` for every endpoint.

### R15. `revoke_all_for_process` leaves `unlock_volume` set; ADR-000 and proof P3.11 say every flag is cleared

- Lens: correctness. Severity: low. Confidence: confirmed by a scratch host test.
- Location: `src/ipc/capability.rs:879-888`; `verification/capability-proofs/src/lib.rs:460-511`; ADR-000 § Verified properties.

The reset list ends at `cluster_revoke`; the comment above it records that `emit_input_audit` was once missed the same way. P3.11's doc says "every system capability flag" and asserts five of the eleven. Dead today because exit also unregisters the process; it is the full-disk-encryption unlock right that survives a "soft revoke".

Proposed fix: reset by assigning a fresh `ProcessCapabilities::new(process_id)` with the Principal carried over, so the list cannot fall behind; extend P3.11 to quantify over `CapabilityKind`.

Test: scratch probe `probe_revoke_all_leaves_unlock_volume`, inverted.

### R16. A dead policy service cannot be restarted, because init's own syscalls are subject to it

- Lens: correctness. Severity: low. Confidence: confirmed by reading `policy_check`; restart is not implemented yet, so not run.
- Location: `src/syscalls/dispatcher.rs:209-228`; `src/policy/mod.rs:519-533`.

ADR-006's failure table says init restarts the policy service and "the first query after the restart is answered normally". The bypasses in `policy_check` are: flag unset, caller is the policy service, kernel task. Init is none of these once the flag is set. Its cached `spawn` decision expires after `POLICY_TTL_TICKS`; the `spawn` that would restart the service then waits out the timeout and is denied. Failing closed is right; the recovery path the design relies on does not exist.

Proposed fix: decide in ADR-006 how init is authorized while the service is down (for example a kernel-held allow entry for init's `spawn` of the policy-service row only) before ADR-018 step 10 lands.

### R17. A closed or revoked channel is not observable in its terminal state, contrary to ADR-005 and ADR-007

- Lens: correctness. Severity: low. Confidence: confirmed by a scratch host test.
- Location: `src/ipc/channel.rs:679-688`, `707-726`, `806-813`; `src/syscalls/dispatcher.rs:3239`.

ADR-007 § Divergence 7 and 9 and ADR-005 § Divergence 2026-05-12 items 4 and 5 say the record "stays in `Revoked`, observable via `SYS_CHANNEL_INFO`", and that is how a tombstoned reader is meant to learn to stop. Every teardown path takes the record out of the table and bumps the generation; `SYS_CHANNEL_INFO` on the old id returns `InvalidArg`, the same answer as for an id that never existed. `Closed` and `Revoked` are never stored, which makes the terminal arms in `close`, `revoke` and `revoke_all_for_process` dead code. (`probe_terminal_states_are_never_observable`.)

Proposed fix: either keep a small per-slot "last terminal state and generation" so the old id answers `Revoked`, or amend both ADRs to say the signal is `InvalidArg`.

### R18. `SYS_WAIT_IRQ` ignores a failed registration, re-routes the interrupt anyway, and routes are never removed

- Lens: both. Severity: low. Confidence: confirmed by reading; no row lists `wait-irq`.
- Location: `src/syscalls/dispatcher.rs:952-1041` (966: `let _ = router_guard.register(irq, ctx.task_id, 128);`); `src/interrupts/routing.rs:105-117`.

No capability or ownership check ties an IRQ to a driver. When another task already owns the line the call still pins the caller, points the I/O APIC pin at the caller's CPU, unmasks it, and blocks the caller on an interrupt whose wake goes to the owner. `InterruptRoutingTable::unregister` has no caller outside tests, so a driver that exits leaves a route to a dead task and its restarted instance can never claim the line. The registration and the block are separate critical sections, so an interrupt between them finds the task Running.

Proposed fix: return the registration error; bind lines to manifest rows; unregister in `reap_process`; latch a pending count per line that the block consumes.

### R19. Cluster bookkeeping: duplicate roles can never join, the revoke capability is not scoped to membership, clusters outlive their creator

- Lens: correctness. Severity: low. Confidence: first item by scratch host test, the rest by reading. Dormant: no row holds `create-cluster`.
- Location: `src/ipc/cluster.rs:506-511` and `569-573`; `src/syscalls/dispatcher.rs:3650-3665`.

`join` finds its member with `position(|slot| … m.role == role)`, the first slot with that role. `create` accepts two members with one role (two input devices, which ADR-027 expects); the second gets `PrincipalMismatch` forever and the cluster never leaves `Forming` (`probe_duplicate_role_never_joins`). `handle_cluster_revoke` accepts any holder of `ClusterRevoke` for any cluster, where ADR-027 says "a cluster the holder is a member of". A cluster whose creator exits stays in the table until a member exits; with no members joined it is permanent.

Proposed fix: match on `(role, principal)`; require the holder to be a `Joined` member; revoke a process's created clusters in `reap_process`.

### R20. The interceptor's self-send rule compares a process slot with an endpoint number; `on_delegate` is never called; capability.rs still takes `&dyn IpcInterceptor`

- Lens: correctness. Severity: low. Confidence: confirmed (scratch host test for the first).
- Location: `src/ipc/interceptor.rs:221-224`; `src/ipc/capability.rs:666-684`.

`if msg.from.0 == endpoint.0 && sender.slot() == endpoint.0` denies a self-send only when the sender's slot happens to equal the endpoint. A process in slot 3 whose endpoint is 16 may send to 16. ADR-002 lists "no self-send" as a Layer 3 guarantee. `delegate_capability` passes `None` for the interceptor, so ADR-002's "Delegation Enforcement" step 1 does not run (no syscall reaches delegation today). The parameter type `Option<&dyn crate::ipc::interceptor::IpcInterceptor>` contradicts ADR-002 § Divergence 2026-04-17: "The kernel binary contains no `dyn IpcInterceptor` references."

Proposed fix: compare the destination with the sender's registered endpoints (the bitmask in `ProcessDescriptor`), or drop the rule from ADR-002; take `Option<&IpcInterceptorBackend>`.

### R21. Capability denials on the receive paths and on every system-capability gate leave no audit event

- Lens: security. Severity: low. Confidence: confirmed by reading.
- Location: `src/syscalls/dispatcher.rs:1154-1156`, `1340-1342` (no emit), `616-623` (every error audited as a capability denial), and the gates at `1934`, `2302`, `2732`, `3473`, `3663`, `3914`, `4026`, `4342`, `4445`, `4577`, `4620`.

ADR-007's `cap.denied` is defined as "when a capability check returns `PermissionDenied`". `handle_write` and `handle_read` emit it; `handle_recv_msg`, `handle_try_recv_msg` and all eleven system-capability checks return `PermissionDenied` silently, so a process probing for rights it lacks is invisible to the audit consumer. `handle_read` maps every `IpcError` to a denial event.

Proposed fix: one helper that denies and emits, used by every gate.

### R22. Process exit allocates from the kernel heap while holding `CHANNEL_MANAGER` and `CLUSTER_MANAGER`

- Lens: correctness. Severity: low. Confidence: confirmed by reading.
- Location: `src/ipc/channel.rs:833-863`; `src/ipc/cluster.rs:660-688`; `src/reap.rs:317-350`.

`revoke_all_for_process` and `mark_departed_for_process` build a `Vec` with `push`. An allocation failure there is the allocator's error path, which panics, in the path whose own comment says "Never panic or block in the death path". The bound is small (256 records of about 272 bytes), so it needs an exhausted 4 MiB kernel heap, which `SYS_OBJ_PUT` also draws on.

Proposed fix: iterate with a cursor (return one record per call under the lock, as `do_cluster_revoke` already does per channel) so the exit path allocates nothing.

### R23. Any process can keep any 16-slot endpoint queue full

- Lens: security. Severity: informational. Confidence: confirmed by reading.
- Location: `src/ipc/mod.rs:377-386`; `src/syscalls/dispatcher.rs:548-558`.

Every row holds send on all 64 endpoints and nothing rate-limits or apportions a queue per sender, so a process with only the default capability can make `SYS_WRITE` to a chosen service fail with the queue-full error for everyone else (init's endpoint 1 during the boot wave is the sensitive one). ADR-005 accepts `QueueFull` as "a normal error"; it does fail closed and the flooder is identified by its stamp. Recorded because the adversary list asks for it; a per-sender slot cap is the obvious remedy if it is ever wanted.

### R24. Documentation and dead code in scope that disagree with the code

- Lens: correctness. Severity: informational. Confidence: confirmed by reading.

- `cambios-abi/src/lib.rs`: `WaitTask` is documented as taking `child_task_id: u32` (the handler takes the 64-bit handle) and as returning the exit code (a negative code is indistinguishable from an error: `Ok(code as u64)` at `dispatcher.rs:2526`, and a faulted child is `i32::MIN`); `ReadVolumeHeader` documents a 176-byte minimum and a bootstrap-Principal gate (the handler needs 16384 bytes and `UnlockVolume`); `ClusterCreate`, `ClusterJoin`, `ClusterRevoke`, `ClusterInfo` say their handlers return `Enosys`; `ChannelCompleteTeardown` promises a kind check (R7); `from_u64`'s doc still calls 39 and 40 unimplemented.
- `src/syscalls/dispatcher.rs:140-151`: the doc comment for `kernel_origin_endpoint` is attached to `struct Latin1`. `1164-1167`: a documented local `const BLK_KERNEL_CMD_ENDPOINT` that nothing uses. `2196`, `2224`: `unreachable!()` in non-test kernel code (not reachable: `width` is range-checked above; a typed error would satisfy the rule as written).
- `src/syscalls/user_slice.rs:37`: "Compile-fail tests assert the lifetime and direction invariants"; there are none (ADR-020 phase D is deferred).
- `src/syscalls/userspace.rs`: eleven stub wrappers that return constants, with bare `TODO` comments and no "Revisit when"; nothing calls them.
- `src/ipc/channel.rs:80`: `QUIESCE_TIMEOUT_TICKS` is unused (R7). `src/ipc/mod.rs:1132-1133`: the `Send` justification still speaks of "a trait object behind a Spinlock".
- `.claude/rules/locks.md` and ADR-027 § Lock ordering say cluster operations "acquire `CLUSTER_MANAGER` → (`CAPABILITY_MANAGER` …)", which is 5 then 4. The code never nests them (`dispatcher.rs:3583-3604`, `4207-4281`); the sentence should say so.
- ADR-000: "up to 32 capabilities" (64 since the endpoint bump); the Verified-properties row "Bootstrap-gated revocation" (P3.12 now proves the revoke-right gate); the Divergence entry "All object storage now requires a valid Ed25519 signature via `ObjPutSigned`" while `SYS_OBJ_PUT` stores unsigned objects, `handle_obj_get` returns them, and fs-service's row lists `obj-put` and not `obj-put-signed`.

## Known findings, wider reach

- F5: `handle_free` frees any region whose base it is given, not only a DMA grant: a channel mapping (the peer keeps its mapping and `ChannelManager` later frees the same frames again), a `SYS_MAP_MMIO` or framebuffer region, the audit ring; and it frees through `cached_free_frame` (`src/lib.rs:1382-1403`), which pushes the frame onto the per-CPU cache with no bitmap check, so the next `SYS_ALLOCATE` on that CPU is handed it.
- F1: `handle_recv_msg` and `handle_try_recv_msg` serve the `IPC_MANAGER` queue before the kernel's shard (`msg.or_else(...)`, `dispatcher.rs:1169` and `1347`), so a sender that keeps user messages queued on endpoint 22 starves kernel policy queries into timeouts, which deny every uncached syscall system-wide.
- F8: the same stale lock numbers stand at `dispatcher.rs` lines 792, 815, 960, 1394, 1432, 1459, 1520, 1560, 1618, 1675, 1704, 1905, 2276, 2377, 2693, 2843, 2938, 3219, 3290, 3388, 4327 and 4421, and at `reap.rs:285-286` and `369`; "256 KiB kernel boot stack" justifies task-stack buffers at 3816 and 3926.
- K1: `handle_cluster_info` (`dispatcher.rs:3695-3739`) has the same shape: any identified caller reads any cluster's state, policy, creator slot and counts.
- K2 (plausible, not run): a child that exits before the parent reaches `register_process` (`dispatcher.rs:2443`) leaves a capability-table entry carrying the old generation; no exit will ever unregister it, and every later process in that slot fails `register_process` (ignored by `let _`) and `install_manifest_row`, so the slot never again holds an identified process.

## What holds

Each of these I tried to break and could not.

- The identity gate runs before any handler for every gated syscall and treats a missing or all-zero Principal alike: `dispatcher.rs:185-207`. `POLICY_SERVICE_PID` starts at `u64::MAX`, so no process matches it before the service is spawned: `src/lib.rs:1214`.
- No handler dereferences a user pointer. The copy helpers are private to `user_slice.rs` (187, 231); `validate` rejects a zero page-table root, a length above 16 KiB, an address at or past the user-space end and any wrap (`user_slice.rs:307-322`, `387-402`). Every handler copies once into a kernel buffer and decides from the copy (for example `handle_cluster_create`, `dispatcher.rs:3486-3492`); I found no double fetch.
- Kernel buffers cannot be overrun from user lengths: `handle_write` 409-417, `handle_print` 1068-1075, `handle_obj_put` 1403-1413 (guard and buffer share one constant), `handle_spawn` 2286 and 2310, `handle_cluster_create` 3453 and 3486-3492, the receive header and payload split 1136 and 1176.
- `sender_principal` cannot be supplied by the sender. `Message::new` sets `None` (`ipc/mod.rs:228`); the only writers are `send_message_with_capability` (`ipc/mod.rs:770`) and the endpoint 25 intercept (`dispatcher.rs:474`), both from the capability table.
- A stale process, channel or cluster id resolves to nothing: `capability.rs:495-508`, `process.rs:1258-1272` (so `teardown_channel_mappings` against a dead peer is a no-op: `dispatcher.rs:3309-3313`, `3354-3358`), `channel.rs:531-543`, `cluster.rs:473-485`. `SYS_WAIT_TASK` compares the generation-carrying parent id on every path: `dispatcher.rs:2522-2526`, `2534`, `2609`, `2624`.
- A reserved endpoint can be registered only by its AID, and a failed Principal lookup denies: `dispatcher.rs:686-713`. Endpoint 25 accepts only the reservation owner and nobody when unreserved: 442-466. Endpoint 23 accepts only the recorded policy-service id, generation included: 485-488.
- The blocking receive cannot lose a wakeup: the queue re-check and `block_task` are one critical section under scheduler, then `IPC_MANAGER`, then the shard (`dispatcher.rs:1243-1287`), and the sender wakes every CPU after dropping its locks (564-584). `SYS_WAIT_TASK` re-checks the exit ring under the lock its waker takes: 2583-2594.
- Lock order in every handler I traced: 3 then 4 in write, read and both receives (533-534, 610-611, 1148-1149, 1334-1335); `handle_register_endpoint` releases 4 before taking 3 (696-737); `handle_spawn` takes 1, 7, 8, releases, then 4 (2378-2441); channel handlers take 6 and then 7 and 8 in separate sections; cluster code never holds 5 and 4 together (3583-3604, 4207-4281). No handler in scope yields with a plain spinlock held: the yields at 387, 941, 1038, 1305, 2618 and 3201 all follow the guards' scopes.
- Spawn authority: capability, then manifest row, then init-only by full `ProcessId`, then a signature check on every spawn: `dispatcher.rs:2296-2350`. The new process gets exactly the row's grants: `src/manifest.rs:418-442`.
- System-capability gates other than spawn (R12) deny when the manager is absent or the lookup fails: `dispatcher.rs:1926-1936`, `2726-2734`, `3465-3475`, `3906-3916`, `4018-4028`, `4337-4344`, `4440-4447`, `4572-4579`, `4615-4622`.
- The per-process capability table cannot overflow or duplicate an endpoint: `capability.rs:244-266`, `269-284`. No syscall reaches `delegate_capability`.
- Channel close and both teardown phases accept only the creator or the attached peer, compared as full ids: `channel.rs:673-677`, `dispatcher.rs:3019-3023`, `3105-3109`. Attach checks state and Principal under the lock both times: `dispatcher.rs:2864-2869`, `channel.rs:625-633`.
- Teardown order is PTE change, TLB shootdown, then frame free: `dispatcher.rs:3303-3418`.
- Every loop in a handler is bounded by a constant-checked count or by kernel state: 806 and 826, 1719 and 1759, 1806 and 1855, 2704, 3453 and 3502, 1582-1592. Arithmetic on user values is checked or cannot wrap: `buf_len - 36` after 1136; `checked_add` at 1196, 1368, 1594; the `phys_addr + i * 4096` at 1761 is covered by `is_ram_overlap` rejecting a wrapping range (`frame_allocator.rs:228-231`).
- With the policy service present, a syscall outside the caller's row is denied and audited (the control run in R5: 57,328 denials, none allowed). Table-full, queue-full and timeout all deny: `src/policy/mod.rs:593-611`, `694-705`.

## Seen outside scope

- `src/process.rs:915-964`: `reclaim_user_vmas` frees every mapped leaf of every region whatever backs it (root of R3).
- `src/memory/frame_allocator.rs:429-456`: `free` accepts and zeroes a frame that `add_region` never added.
- `src/lib.rs:1382-1403`: `cached_free_frame` caches any frame unchecked; `src/lib.rs:1370`: `cache.pop().unwrap()` in non-test kernel code.
- `src/memory/paging.rs:128-129`: `PhysAddr::new` and `VirtAddr::new` panic on out-of-range input (reached in R1).
- `src/memory/paging.rs:460-482`: `user_rw()` and `user_mmio()` omit `NO_EXECUTE`, so every `SYS_ALLOCATE`, DMA, channel and device page is writable and executable.
- `src/policy/mod.rs:521`: the unset-flag bypass (R5). `src/policy/mod.rs:553` and `724`: the per-CPU policy cache is read and written with interrupts on and preemption allowed, under a SAFETY comment that claims no concurrent access.
- `src/scheduler/mod.rs:974-1004`: `wake_quiesce` leaves `pending_quiesce_channel` set on tasks that have not parked (R7).
- `src/audit/drain.rs:322`: `clear_consumer` has no caller (R3).
- `src/interrupts/routing.rs:120-132`: `unregister` has no caller (R18).

## Open questions

- Does Limine's HHDM map device BARs on any supported machine? If it does, the device-backed buffer in R4 is a kernel write to device registers and not a fault.
- Is one manifest row spawned twice (two live processes with one AID) intended? R2 and R11 are both easier with it, and nothing in `handle_spawn` prevents it for on-demand rows.
- Are `SYS_OBJ_GET` and `SYS_OBJ_LIST` meant to be open to every identified process? Neither handler checks ownership or a capability (`dispatcher.rs:1460-1512`, `1561-1602`); ADR-003 was not on this run's reading list.
- R3's kernel faults after the probe exited: I attribute them to `reclaim_user_vmas` zeroing the mapped ranges, from the code and the ordering of the log. Instrumenting `FrameAllocator::free` would confirm which frame went first.
- On riscv64 `unmap_page` issues its remote TLB flush while `teardown_channel_mappings` holds `PROCESS_TABLE` and `FRAME_ALLOCATOR` (`src/memory/mod.rs:311-314`). I assumed the flush does not need the target hart to have supervisor interrupts enabled; if it does, a hart in `handle_spawn` (interrupts masked, waiting on `PROCESS_TABLE`) deadlocks against it.
- How large is `num_slots()` on the tiers that ship? `REPLY_ENDPOINT` and `TASK_CPU_MAP` have 256 entries; a process in a slot above 255 never has a reply endpoint recorded (`dispatcher.rs:517-522`, `767-775`).
