<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2024-2026 Jason Ricca -->

# Security review: the block-driver reply seam (endpoint 25), 2026-11-18

Sandbox run 001. Target: commit `1d9e03f` ("blk seam: endpoint 25
identity-gated, replies tagged, page a DMA grant") and the code as it stands
at `be1dda7`.

## What the seam does and what this review covered

The kernel is the *client* of a userspace block driver (virtio-blk in the
`default` manifest profile, nvme in the bare-metal profiles). It sends commands
`[kcmd:1][tag:4 LE][args]` to the driver on IPC (Inter-Process Communication)
endpoint 26, the driver answers `[status:1][tag:4 LE][data]` on endpoint 25,
and block data moves through one 4 KiB page that the driver obtained from
`SYS_ALLOC_DMA` (DMA: Direct Memory Access) and named, by physical address, in
its handshake reply; the kernel reaches that page through the HHDM (Higher Half
Direct Map, the kernel's linear map of physical memory; CLAUDE.md § Platform
Gotchas). Commit `1d9e03f` closed three gaps: a write to 25 is accepted only
from the process whose Principal is the manifest's reservation owner of 25 and
is stamped with it, the kernel accepts only a stamped reply echoing its tag,
and the handshake address is accepted only as a page inside a DMA grant of the
replying process. This review read `git show 1d9e03f`, then `handle_write`,
`handle_alloc_dma`, `handle_free`, the receive handlers and the two FDE
(Full-Disk Encryption; ADR-032) syscalls in `src/syscalls/dispatcher.rs`; all
of `src/fs/block_driver_client.rs` and `cambios-blk-proto/src/lib.rs`; the
grant record and `occupant` in `src/process.rs`; every endpoint-25 reply path
in `user/virtio-blk` and `user/nvme`; `src/manifest.rs`,
`src/ipc/endpoint_reservation.rs`, `tools/build-manifest` and `manifest.toml`;
the send path in `src/ipc/mod.rs` and `src/ipc/interceptor.rs`; the reaper;
the spinlock / `PREEMPT_DEPTH` machinery and the scheduler entry points;
CLAUDE.md; and the relevant sections of ADR-005 (Architecture Decision Record
005, IPC primitives), ADR-010 § Divergence 1–2 and ADR-018 (init process and
boot manifest). The adversary is any userspace process, including a compromised
block driver.

**How the findings were established.** Everything below comes from reading the
code. Nothing was built, no host test was run, and nothing was booted under
QEMU in this run. Each finding says which steps are read directly off the code
and which are reasoned from it. The rust-analyzer navigation server was not
available in the sandbox (`mcp-rust-analyzer` not on `PATH`), so navigation was
by `grep`; line numbers are against `be1dda7`.

**Summary.** 3 high, 1 medium, 2 low, 2 informational. The endpoint-25 gate
itself holds against every direct attack tried. The seam fails one hop away:
the command endpoint (26) accepts messages from anyone, which turns the honest
driver into a deputy that both corrupts the disk and emits correctly-stamped
replies with attacker-chosen tags.

---

## Findings

### F1. Endpoint 26 is not kernel-only: any process can inject "kernel" commands into the block driver

**Severity:** high

**Location:**
- `src/syscalls/dispatcher.rs:512-548` (ordinary send path; no refusal for a
  kernel-origin endpoint)
- `src/syscalls/dispatcher.rs:1168-1172`, `:1347` (receive serves the
  `IPC_MANAGER` queue first, the kernel's shard second)
- `src/manifest.rs:423-428`, `tools/build-manifest/src/main.rs:436`
  (every manifest row gets send on every endpoint)
- `user/virtio-blk/src/main.rs:687-695`, `user/nvme/src/main.rs:317-321`
  (`poll_raw`: the sender Principal is discarded)
- `src/fs/block_driver_client.rs:138`, `:171-178` (kernel tags are a per-client
  counter from 0)

**Attack path.** The adversary is any process whose manifest row lists the
`write` syscall (every row does), for example an on-demand app.

1. It calls `SYS_WRITE` to endpoint 26 with a 13-byte payload
   `[KCMD_WRITE_BLOCK][tag:4][lba:8]`. Endpoint 26 is not 25 and not the policy
   reply endpoint, so `handle_write` falls through to the ordinary path:
   `send_message_with_capability` checks the send right (which the row holds on
   all endpoints), stamps the adversary's Principal, and enqueues on
   `IPC_MANAGER`'s queue 26. (Read.)
2. The driver's loop calls `poll_raw(BLK_KERNEL_CMD_ENDPOINT, …)`. The receive
   handler reads `IPC_MANAGER`'s queue first and consults the kernel's
   `SHARDED_IPC` shard only if that is empty, so the injected command is served
   ahead of any real kernel command. `poll_raw` drops the sender Principal; the
   driver cannot tell the message from a kernel one. (Read.)
3. The driver executes it. Consequences that need nothing further:
   - **Write to any LBA (Logical Block Address).** `WRITE_BLOCK` writes whatever
     is in the shared page to the chosen block. LBA 0..=3 hold the signed
     volume header that wraps the FDE master key; overwriting it makes the
     volume unmountable on the next boot. Any substrate block can be
     overwritten the same way.
   - **Block copy / rollback.** `READ_BLOCK a` then `WRITE_BLOCK b` copies
     block *a* over block *b*. The adversary never sees plaintext or
     ciphertext, but it can park a block's ciphertext and restore it later in
     the same LBA (the XTS tweak is per LBA, so the restored block decrypts
     cleanly to the earlier content).
   - **Shared-page clobber.** An injected `READ_BLOCK` between the kernel's
     `write_shared_region` and the driver servicing the kernel's `WRITE_BLOCK`
     replaces the data the kernel meant to write.
4. The driver then writes its reply to endpoint 25. The reply is genuinely from
   the reservation owner, so the endpoint-25 gate passes and stamps it, and it
   carries **the tag the adversary chose**. Kernel tags are predictable: every
   `connect()` starts at 0, so `HANDSHAKE` is tag 0, `CAPACITY` is tag 1, and
   the installed client counts up from there. A reply to an injected command
   that arrives after the kernel's drain (`clear_endpoint`) and before the real
   reply is accepted as the answer to the kernel's request, because the reply
   carries no echo of the command it answers. (Reasoned; the race is winnable
   by repetition since each attempt costs the adversary one syscall.)
   - Injected `FLUSH` with the tag of a pending kernel `WRITE_BLOCK`: the
     kernel is told "OK" before the write ran; its next `write_block` overwrites
     the shared page while the first write is still queued, so block *K*
     receives block *K+1*'s data.
   - Injected `HANDSHAKE` with tag 1: `connect()` reads the page's physical
     address as `capacity_sectors`.
   - Injected `CAPACITY` with tag 0: `connect()` reads the capacity as the page
     address, the ownership check refuses it, and the FDE mount fails for this
     boot (denial of service of `fde-mount`, which is one-shot).

Kernel memory safety appears to survive this finding: the page address is
still held to the DMA-grant check, and both drivers bounds-check the LBA
against the real capacity. What does not survive is disk integrity,
availability of the volume, and the claim that "a matching tag is this
request's reply".

**Why the code allows it.** The seam's documentation rests on a premise the
kernel does not enforce. `cambios-blk-proto/src/lib.rs:27-30`:

```
//!   Kernel-origin messages carry no sender Principal, which
//!   `recv_verified` rejects; the driver trusts 26 because the manifest
//!   reserves it to the driver's row and nobody else can send to a
//!   kernel-consumed queue.
```

and `user/virtio-blk/src/main.rs:687-690`:

```rust
// Kernel-facing endpoint: the kernel is the anonymous sender —
// trust is by endpoint choice; nobody else registers ep26. See
// the RawMessage docs for why poll_raw is legitimate here.
did_work |= ipc::poll_raw(BLK_KERNEL_CMD_ENDPOINT, &mut kern_recv_buf, |msg| {
```

The reservation controls who may *register* (receive on) 26. It says nothing
about who may *send*. Send is universal by design (ADR-018 § "Default grant
posture (v1): narrow receive, wildcard send"), and the commit's own comment at
`src/syscalls/dispatcher.rs:427` says so: "Every process holds
`AllEndpoints { send }`". `tools/build-manifest/src/main.rs:436`:

```rust
grants.push(CapabilityGrant::AllEndpoints { rights: Rights::SEND });
```

`handle_write` has an intercept for 25 and for the policy reply endpoint, and
nothing for a kernel-*origin* endpoint, so the write reaches
`src/syscalls/dispatcher.rs:548`:

```rust
match ipc_mgr.send_message_with_capability(ctx.process_id, endpoint, msg, cap_mgr) {
```

and the receive side merges the two queues, user queue first
(`src/syscalls/dispatcher.rs:1168-1169`):

```rust
let msg = if kernel_origin_endpoint(endpoint_id) {
    msg.or_else(|| crate::SHARDED_IPC.recv_message(endpoint))
```

The interceptor (`src/ipc/interceptor.rs:205-227`) checks bounds, payload
length and self-send only. The per-row syscall policy is keyed on syscall
number, not on destination endpoint.

**Proposed fix.**
1. Structural: in `handle_write`, refuse a user-origin send whose destination
   satisfies `kernel_origin_endpoint()` — deny, emit `cap.denied`, return
   `PermissionDenied` — exactly the shape of the endpoint-25 gate. The kernel
   is the only legitimate producer for those queues, so there is nobody for
   whom the refusal degrades a feature. This also covers the policy query
   endpoint (see Open question 1).
2. Defence in depth in the drivers: a message on 26 that carries a sender
   Principal is not from the kernel; drop it. (`poll_raw` would need to expose
   "was a Principal stamped".)
3. Defence in depth on the wire: see F4 (one tag sequence for the whole boot,
   and a command echo in the reply).
4. Correct the two comments quoted above once the kernel enforces what they
   say.

**How a test would demonstrate it.**
- Host test on `IpcManager`: a process holding only the manifest default grants
  sends to endpoint 26; today the send succeeds and the message is the next
  one the receive path returns for 26, ahead of a message placed in the shard.
  After the fix the syscall-level check denies it.
- QEMU test: a fixture app (in the style of the `faultme` fixture) writes
  `[3][0,0,0,0][0,0,0,0,0,0,0,0]` (`WRITE_BLOCK`, LBA 0) to endpoint 26 under
  `make run-quiet-dev-piv` after `master key installed`. Today LBA 0 of
  `cambios-disk.img` changes and a second boot fails header verification; the
  fixed kernel prints a `cap.denied` for endpoint 26 and the image is
  untouched.

---

### F2. The kernel keeps writing through the shared frame after the driver exits, and the driver chooses when

**Severity:** high (use of a freed physical frame by the kernel; recorded as a
known issue, but the recorded mitigation is not a safety argument)

**Location:**
- `src/fs/block_driver_client.rs:154` (address stored once at connect)
- `src/fs/block_driver_client.rs:353-375` (`write_shared_region`, with the
  deferral comment)
- `src/fs/block_driver_client.rs:402-409` (`write_block`: copy, then send)
- `src/process.rs:915-960` (`reclaim_user_vmas` frees every VMA's frames,
  DMA grants included), `src/reap.rs:355-380`
- `STATUS.md:247` (the known-issue entry)

**Attack path.** The adversary is a compromised block driver, or anything that
can make the driver fault.

1. Boot proceeds normally: `fde-mount` calls `SYS_INSTALL_MASTER_KEY`, the
   kernel `connect()`s, the ownership check passes, and the client is installed
   inside the disk-backed store under `OBJECT_STORE`. (Read.)
2. The driver exits. Both driver rows list the `exit` syscall, and any fault
   reaps the process too. `reclaim_user_vmas` returns the DMA frame to the
   frame allocator. (Read.)
3. The frame is handed out again: a page-table page, another process's heap, a
   later DMA grant, a per-process kernel object region. (Reasoned: one
   allocator serves all of these.)
4. `fs-service` performs any object put. `write_block` runs:

   ```rust
   self.write_shared_region(buf);
   let tag = self.take_tag();
   self.command(tag, &encode_klba_request(KCMD_WRITE_BLOCK, tag, lba))
   ```

   The 4 KiB copy into the stale address happens **before** the command is
   sent. The command then times out; the copy has already landed in the frame's
   new owner. One frame-sized corruption per attempted block write, repeated on
   every retry and every later put. (Read.)
5. If init restarts the driver (same manifest row, same AID (Autonomic
   Identifier, the 32-byte Principal; ADR-025), new process and generation),
   the new driver allocates a new page and answers commands again. The
   installed client still points at the old frame: `read_block` now succeeds
   and returns the old frame's current contents as block data, and
   `write_block` reports success for data the driver never saw. (Reasoned;
   restart has not landed, `user/init/src/engine.rs:41`.)

**Why the code allows it.** Ownership is checked once, at connect, and nothing
pins the grant afterwards. The deferral says so
(`src/fs/block_driver_client.rs:354-363`):

```rust
// Deferred: a block-driver exit frees the shared frame while this
// client, installed under OBJECT_STORE, keeps its address.
// Revisit when: init restarts a block-driver row (ADR-019 restart
// for the block seam).
// ...
// Today a driver exit also
// leaves every request timing out, so the seam is unusable after
// one either way.
```

Two parts of that reasoning do not hold:

- "Unusable either way" describes *availability*. The copy in `write_block`
  precedes the request, so an unusable seam still performs the write into the
  freed frame. Only the read path is protected by the timeout (the copy follows
  a successful reply).
- The trigger "init restarts a block-driver row" is later than the hazard. The
  exit alone frees the frame; a restart only adds the read-side consequence.

This is also the general form of the connect-time race the review was asked
about: between `check_shared_page` and any later copy, the only things keeping
the frame allocated are that the driver stays alive and never frees the region
(see F5 for the second half).

**Caveat on ranking.** There is no IOMMU (Input-Output Memory Management Unit)
support yet, so a compromised driver that controls a bus-mastering device can
already direct that device at arbitrary physical memory. F2 is a separate path:
the kernel itself performs the write, it needs no device at all (the no-device
loop process qualifies), and it is reachable by a plain driver crash with no
malice involved.

**Proposed fix.** Make the kernel a co-owner of the frame for the client's
lifetime, so that the check at connect stays true by construction rather than
by the driver's good behaviour:

- At connect, under `PROCESS_TABLE`, convert the accepted grant into a pinned
  one (a `VmaBacking` state or a kernel-held reference count on the frame).
  `reclaim_user_vmas` and `handle_free` unmap a pinned grant from the process
  but do not return its frames; the frames are released when the client is
  dropped. This needs no lock at copy time, so it does not disturb the
  `OBJECT_STORE` ordering.
- Independently, give the client a lock-free liveness signal (a reaper-bumped
  epoch for the endpoint-25 owner, compared before each copy) and fail closed
  with `BlockError::NotReady` when it has moved. That turns the post-exit case
  from "silent writes into a kernel-owned orphan frame" into a typed error, and
  it is what a restart will need in order to re-handshake.
- Move the `write_block` copy so that a client known to be dead never copies.

**How a test would demonstrate it.**
- Host test at the `ProcessTable` level: allocate a DMA grant, record it as the
  shared page, destroy the process, and assert the frame is not returned to the
  allocator while a pin is outstanding (fails today: the frame is freed).
- QEMU test under `make run-quiet-dev-piv`: after `master key installed`, make
  the driver exit (a debug-only command, or a fault fixture), then have a
  client put an object. With a poison/owner assertion in the frame allocator's
  debug build, today's kernel writes 4 KiB into a frame the allocator considers
  free or re-issued; the fixed kernel returns an error without touching it.

---

### F3. `OBJECT_STORE` (a plain `Spinlock`) is held across `yield_save_and_switch` on every disk-backed object operation

**Severity:** high (release builds: one CPU-bound unprivileged task can capture
a CPU and wedge the object store; the per-CPU preempt count can be corrupted)

**Location:**
- `src/syscalls/dispatcher.rs:1433-1436` (`handle_obj_put`), and the same
  pattern at `:1482-1484`, `:1540-1544`, `:1576`, `:1676-1679`
- `src/fs/block_driver_client.rs:288-310` (poll loop; yield at `:306-309`)
- `src/scheduler/mod.rs:165-168`, `:226-228` (ISRs do not switch while
  `preemption_held()`), `:257` (`debug_assert!` only)
- `src/lib.rs:578-600` (`preempt_disable` / `preempt_enable` index
  `PREEMPT_DEPTH` by the CPU running *at that moment*)
- `docs/adr/010-persistent-object-store-on-disk-format.md` § Divergence 1

**Attack path.** Preconditions: the disk-backed store is installed (any boot
where `fde-mount` succeeded). The adversary is an unprivileged process that can
reach `fs-service` (or simply runs while `fs-service` serves someone else) and
can spin in user mode.

1. `fs-service` calls an object syscall. The handler takes `OBJECT_STORE`:
   `Spinlock::lock` raises `PREEMPT_DEPTH[cpu]` to 1. The store call descends
   to `BlockDriverClient::call` with the guard still held. (Read.)
2. `call` sends the command and enters its poll loop, which calls
   `yield_save_and_switch()`. In a debug-assertion build `on_voluntary_yield`
   stops here:

   ```rust
   debug_assert!(!crate::preemption_held(), "voluntary yield with a plain spinlock held");
   ```

   Every kernel build in the Makefile is `--release` and `Cargo.toml`'s release
   profile does not enable debug assertions, so the check is compiled out and
   the switch happens with `PREEMPT_DEPTH[cpu] == 1`. (Read.)
3. Whatever task runs next on that CPU inherits a non-zero count. The timer and
   reschedule handlers see `preemption_held()` and only account the tick:

   ```rust
   if crate::preemption_held() || crate::boot_context_holds_cpu() {
       sched.isr_tick_only(current_rsp);
       return (current_rsp, None);
   }
   ```

   A task that spins without making a blocking syscall is therefore never
   preempted. The adversary's task, Ready on that CPU, is such a task. (Read
   for the mechanism; reasoned for the outcome.)
4. The lock holder never runs again, so it never evaluates its 5-second
   timeout and never releases `OBJECT_STORE`. That CPU is captured, the object
   store is wedged for the life of the boot, and every other task homed on that
   CPU starves.
5. Variant without a spinner: the BSP idle loop's `try_load_balance` may
   migrate the lock holder while it is Ready (`pick_migratable_task` takes any
   Ready, non-pinned task). The guard is then dropped on a different CPU:
   `fetch_sub` runs on a counter that was never incremented and wraps to
   `u32::MAX`, while the original CPU's counter stays at 1 forever. Both CPUs
   are now permanently non-preemptible. (Reasoned; whether migration has hit a
   task in this window in practice is Open question 4.)
6. A compromised or merely slow driver widens the window to the full 5 s per
   request by not answering.

A second taker of `OBJECT_STORE` would additionally spin, non-preemptibly, for
as long as the holder is switched out. Today only `fs-service` has the `obj-*`
syscalls and `fde-mount` is one-shot, which limits that case; it is the direct
consequence of the next object-store client.

**Why the code allows it.** The client's own comments assert the opposite of
what its callers do. `src/fs/block_driver_client.rs:306-309`:

```rust
// SAFETY: on kernel stack, no locks held.
unsafe {
    crate::arch::yield_save_and_switch();
}
```

and `:279`, "Syscall context, no lock held", above the all-CPU wake. Both are
true for `connect()` (the commit made sure of that) and false for
`read_block` / `write_block` / `flush`, which run under `OBJECT_STORE`:

```rust
let mut store_guard = crate::OBJECT_STORE.lock();
let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
store.put(obj).map_err(|e| match e {
```

The module doc defers to ADR-010 § Divergence 1, which argues that holding
`OBJECT_STORE` across disk I/O is safe because no circular wait exists. That
argument predates the "a plain `Spinlock` holder is never descheduled" rule
(CLAUDE.md § Lock Ordering, 2026-10-28) and does not consider it. The same
path also takes scheduler locks (position 1, in `call`'s task-context check and
in `wake_message_waiters_all_cpus`) while holding position 10, which the
hierarchy forbids outright.

**Proposed fix.**
- Do no device I/O under `OBJECT_STORE`. ADR-010's original plan / execute /
  commit split is the shape: take the lock to plan (allocate, journal intent),
  drop it, perform the block I/O, retake it to commit. The existing
  `BLOCK_BITMAP_LOCK` / `JOURNAL_LOCK` discipline ("no device I/O while held")
  is the model.
- If the disk store must be serialised across I/O, serialise it with a
  blocking primitive (owner-recorded sleep lock using the Blocking pattern),
  not a plain `Spinlock`.
- Make the invariant a release-mode fact: `on_voluntary_yield` returning a
  typed refusal (or the yield path refusing to switch) when
  `preemption_held()`, so a violation fails closed instead of silently
  transferring the count.
- This is an ADR-010 body change (Divergence 1 is no longer true) and touches
  the lock hierarchy; both are stop-and-ask items.

**How a test would demonstrate it.**
- Build the kernel with debug assertions enabled and run
  `make run-quiet-dev-piv` with one object put after the mount: the
  `on_voluntary_yield` assertion fires.
- Release build: add a boot-time check that `PREEMPT_DEPTH[cpu] == 0` at every
  syscall return and at idle entry; it trips during the first disk-backed put.
- Release build, behavioural: a fixture app that requests a put from
  `fs-service` and then spins in user mode, pinned to `fs-service`'s CPU; the
  shell on that CPU stops responding and `[sched]` counters for it stop
  advancing.

---

### F4. Tags restart at 0 for every client and are predictable; a reply does not say which command it answers

**Severity:** medium (low in isolation; it is what makes F1's reply confusion
cheap)

**Location:**
- `src/fs/block_driver_client.rs:136-142` (`next_tag: 0`), `:171-178`
  (`take_tag`), `:255-257` (drain), `:314-331` (`accept`)
- `cambios-blk-proto/src/lib.rs:157-162` (`TAG_LEN` doc)
- `src/syscalls/dispatcher.rs:3922`, `:4058` (two independent `connect()`s)

**Attack path.**
1. `SYS_READ_VOLUME_HEADER` builds client A: tags 0 (handshake), 1 (capacity),
   2..5 (four block reads). `SYS_INSTALL_MASTER_KEY` then builds client B,
   again from tag 0.
2. A slow or compromised driver withholds the reply to A's request *n* until
   A has timed out and B has sent its request *n*, then delivers it. The drain
   at the top of `call` removes only what is already queued, so a reply that
   arrives after the drain with tag *n* is accepted by B. (Reasoned.)
3. With *n* = 0 or 1 the cross-match is between a handshake and a handshake or
   a capacity and a capacity, which is benign. With F1, the adversary does not
   need a slow driver at all: it manufactures a stamped reply with any tag and
   any of the driver's reply shapes.
4. Two clients alive at once (nothing prevents a second `UnlockVolume` holder
   calling `SYS_READ_VOLUME_HEADER` while the installed store is doing I/O)
   share shard 25 and drain each other's in-flight replies; both use
   overlapping tag ranges.

**Why the code allows it.** The protocol doc states the collision bound for a
single counter (`cambios-blk-proto/src/lib.rs:157-160`):

```
/// One request is in flight at a time (the kernel serializes the seam),
/// so a tag collides with a stale reply only after 2^32 requests have
/// passed it;
```

but the counter is per client instance, `src/fs/block_driver_client.rs:138`:

```rust
next_tag: 0,
```

and nothing serialises separate clients against each other: the drain's
comment ("the kernel is the only consumer and nothing is in flight") is true
only if exactly one client exists. `Reply` carries status, tag and data; a
13-byte handshake reply and a 13-byte capacity reply are indistinguishable.

**Proposed fix.** One kernel-global tag sequence for the life of the boot
(an atomic counter, optionally started from a boot-random value so user space
cannot predict it), so the 2^32 argument in the doc becomes true; a command
echo byte in the reply so a reply to command X cannot answer command Y; and
one seam owner (a single client instance, or a seam-level mutual exclusion) so
the "nothing is in flight" precondition of the drain is enforced rather than
assumed.

**How a test would demonstrate it.** Host test over `accept`: construct two
clients, take tag *n* from each, and feed a stamped reply built for the first
client's request to the second; today it is accepted. With F1 open, a QEMU
fixture that sends `[KCMD_CAPACITY][0,0,0,0]` to endpoint 26 in a loop during
boot makes `fde-mount` print `handshake refused`.

---

### F5. `SYS_FREE` frees a `DmaGrant` region of a live process; only the per-row syscall list stops the block driver

**Severity:** low (not reachable by today's driver rows; one userspace-enforced
layer stands between a live driver and F2)

**Location:** `src/syscalls/dispatcher.rs:890-925` (`handle_free`),
`src/process.rs:282-295` (`free_region`), `manifest.toml:97-114` (driver rows)

**Attack path.** A driver whose row included `free` (or any future row that
both holds DMA and may free) allocates the shared page, answers the handshake
truthfully so the ownership check passes, then calls `SYS_FREE` on the region
base (`dma_vaddr - 4096`, the leading guard page). The mapped pages are
unmapped and their frames returned to the per-CPU frame cache. The driver is
still alive and still answers commands with correct tags, so unlike F2 nothing
times out: every kernel `read_block` / `write_block` now copies through a
frame someone else owns, with success reported. The driver also loses nothing
by doing this before the handshake's use.

**Why the code allows it.** `handle_free` removes the region by base address
and frees whatever was mapped, with no look at the backing:

```rust
let vma_entry = pt_guard
    .as_mut()
    .and_then(|pt| pt.vma_mut(ctx.process_id))
    .and_then(|vma| vma.free_region(ptr))
    .ok_or(SyscallError::InvalidArg)?;
```

(The comment two lines above also still reads `PROCESS_TABLE(6) →
FRAME_ALLOCATOR(7)`; the positions are 7 and 8.) What prevents this today is
that neither driver row lists `free`, and that list is enforced by the
userspace policy service (ADR-006), which answers Allow before it is ready.
The grant record that `1d9e03f` added is the evidence the kernel relies on; a
syscall that can delete the evidence's backing should not depend on a
different subsystem's configuration.

**Proposed fix.** `handle_free` refuses a region whose backing is
`VmaBacking::DmaGrant` (typed `InvalidArg` or `PermissionDenied`) until a
dedicated DMA release exists; with F2's pin in place, a pinned grant is refused
or unmapped-without-free.

**How a test would demonstrate it.** Host test on `VmaTracker`: allocate with
`VmaBacking::DmaGrant`, call the free path, assert refusal (today the region is
returned and `owns_dma_range` flips to false while the frames go back to the
allocator).

---

### F6. `handle_read_volume_header` puts roughly 20 KiB of buffers on a 32 KiB kernel task stack that has no guard page

**Severity:** low (fixed depth, not adversary-controlled; needs a measurement)

**Location:** `src/syscalls/dispatcher.rs:3926-3937`,
`src/loader/mod.rs:49`, `:694-698`

**Attack path.** None that an adversary steers: the depth is the same on every
call and only `fde-mount` (holder of `UnlockVolume`) reaches it. The concern is
margin. The handler holds `kbuf` (16 KiB) and a `Block` (4 KiB) and then calls
down through `read_block` → `command` → `call` → `yield_save_and_switch`, with
interrupts enabled, on a kernel stack of `KERNEL_STACK_SIZE = 32 * 1024` that
is carved from the kernel heap. An overflow would write into the neighbouring
heap allocation silently (the failure signature CLAUDE.md records for the
2026-09-14 riscv64 boot rot and the 32,856-byte `create_process` frame of
2026-11-09).

**Why the code allows it.** The sizing comment reasons about the wrong stack:

```rust
// Read 16 KiB into a kernel-local stack buffer. 16 KiB is
// well within the 256 KiB boot stack budget; per the
// CLAUDE.md kernel stack guidance, we avoid heap allocation
// for boot-path one-shots.
let mut kbuf = [0u8; HEADER_BYTES];
for lba in 0..HEADER_BLOCKS {
    let mut block: Block = [0u8; BLOCK_SIZE];
```

This is a syscall handler on a task's kernel stack, not the boot stack.

**Proposed fix.** Copy each block to the user slice as it is read (one 4 KiB
buffer, or none if the read can target a heap block), and correct the comment.
Measure the frame the way the `create_process` case was measured.

**How a test would demonstrate it.** A stack-high-water probe (pattern-fill the
kernel stack at task creation, read the low-water mark after
`SYS_READ_VOLUME_HEADER`) printed under `make run-quiet-dev-piv`; the assertion
is "more than N KiB free", with N chosen from the measurement.

---

### F7. The device capacity is taken from the wire and is the kernel's only LBA bound

**Severity:** informational

**Location:** `src/fs/block_driver_client.rs:157-169`, `:393-395`, `:403-405`;
bounded by `src/fs/disk.rs:1096-1110` and `src/fs/block.rs:147-148`

The kernel's `lba >= capacity_blocks_cached()` check compares against the
number the driver supplied. A lying driver can make the kernel address blocks
that do not exist (the driver then answers as it likes) or shrink the device
(the format path rejects a too-small device; the offset wrapper saturates).
No kernel memory consequence was found: capacity feeds only clamped or
saturating arithmetic. It is listed because question 5 asked for values taken
from the wire, and because with F1 an unprivileged process can supply this
value. The kernel has no independent source for a device size, so the right
posture is the current one (treat it as a hint and clamp), stated as such in
the client's doc.

---

### F8. Comments and docs that state invariants the code does not enforce

**Severity:** informational

- `cambios-blk-proto/src/lib.rs:27-30` and
  `user/virtio-blk/src/main.rs:687-689`: "nobody else can send to a
  kernel-consumed queue" (see F1).
- `cambios-blk-proto/src/lib.rs:157-162`: the 2^32 collision bound (see F4).
- `src/fs/block_driver_client.rs:279`, `:306`: "no lock held" (see F3).
- `src/syscalls/dispatcher.rs:3926-3929`: the 256 KiB boot stack (see F6).
- `src/syscalls/dispatcher.rs:903`, and the same numbering in
  `handle_alloc_dma`: `PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)`; the hierarchy
  has had them at 7 and 8 since `CLUSTER_MANAGER` was inserted.
- `user/nvme/src/main.rs:341`: the no-device loop reads the user-facing
  endpoint 24 with `poll_raw`, which `user/libipc` documents as never to be
  used on a user-facing endpoint. Harmless here (the only reply is
  `STATUS_NO_DEVICE`), but it is the pattern F1 is about.
- `handle_register_endpoint` (`src/syscalls/dispatcher.rs:733-738`) clears the
  `SHARDED_IPC` queue of the endpoint being registered. The driver, as the
  reservation owner, may register 25 and thereby empty the kernel's reply
  queue; this harms only its own replies.

These matter because several of them are `// SAFETY:`-adjacent or are the
stated reason a check is absent; a future verifier would take them as
preconditions.

---

## What holds

Each of these was attacked by reading for a way around it and none was found.

1. **A write to 25 from anyone but the reservation owner is denied and
   audited.** `src/syscalls/dispatcher.rs:452-466`. The comparison is on the
   kernel's own record of the caller's Principal (`get_principal(ctx.process_id)`),
   not on anything in the message.
2. **No reservation, no writer.** `src/syscalls/dispatcher.rs:444-451`: a
   manifest that names no block driver leaves endpoint 25 closed (fail closed),
   and `connect()` returns `NotReady` (`src/fs/block_driver_client.rs:131-133`).
3. **The stamp and the `from` slot on an accepted reply are kernel-set.**
   `src/syscalls/dispatcher.rs:467-474`. User payload bytes cannot influence
   either; `from` is `ctx.process_id.slot()`, not the caller's registered reply
   endpoint.
4. **The client re-checks the stamp and the tag on every reply.**
   `src/fs/block_driver_client.rs:314-331`. An unstamped message (which only
   kernel code could place on shard 25) or a wrong-tag message is discarded
   and the wait continues.
5. **No user receive path reads shard 25.** `kernel_origin_endpoint`
   (`src/syscalls/dispatcher.rs:163-166`) names only 26 and the policy query
   endpoint, and the shard is consulted only behind it (`:1168-1172`, `:1347`).
   Even the driver, which may register 25 and hold full rights on it, cannot
   read back or replay kernel-accepted replies.
6. **Only the reservation owner can register 24, 25 or 26.**
   `src/syscalls/dispatcher.rs:686-713`. A process spawned on demand cannot
   become a receiver on the command endpoint.
7. **Reservations cannot be changed after boot and come only from the signed
   manifest.** `src/manifest.rs:554-582` (population), `:620-675` (ARCSIG
   Ed25519 verification before parsing; single-threaded boot);
   `src/ipc/endpoint_reservation.rs` `install` rejects out-of-range endpoints,
   the zero AID and a second reservation of the same endpoint. No syscall
   writes the table.
8. **Receiving on 26 requires the receive right**, checked in
   `recv_message_with_capability` before the shard is consulted, so an
   unprivileged process cannot steal kernel commands (and with them the tags).
9. **The handshake address must be the replying process's own DMA grant.**
   `src/fs/block_driver_client.rs:189-226`: page-aligned; the reply's `from`
   slot is resolved to a generation-carrying `ProcessId` only if the slot is
   Live (`src/process.rs:1430-1439`); that process's Principal is re-checked
   against the driver AID; and the range must lie inside one grant
   (`src/process.rs:253-271`, `:1445-1449`). Consequences checked: an address
   in kernel memory, in another process's memory, in MMIO space, or in an
   ordinary (non-DMA) allocation of the driver is refused; a reply from a dead
   generation or from a different process that reused the slot is refused;
   `len == 0`, a range that straddles the grant's end and one that overflows
   `u64` are refused (host tests at `src/process.rs:1629-1728`).
10. **A refused handshake is audited and leaves no client behind.**
    `src/fs/block_driver_client.rs:199-212`; `connect()` returns a value only
    after both exchanges succeeded, so no half-initialised client exists
    (`:128-165`).
11. **`connect()` holds no lock across a wait and nests none.** The ownership
    check takes `PROCESS_TABLE`(7), drops it, takes `CAPABILITY_MANAGER`(4),
    drops it, takes `PROCESS_TABLE`(7) again
    (`src/fs/block_driver_client.rs:216-226`, `:189-198`); both callers invoke
    `connect()` with `OBJECT_STORE` not held (`src/syscalls/dispatcher.rs:3922`,
    `:4058`, with the idempotency check's guard at `:4041` scoped and dropped).
    The inversion F3 describes is in the post-connect I/O path only.
12. **The endpoint-25 intercept takes `CAPABILITY_MANAGER`(4) alone** and
    releases it before the shard enqueue (`src/syscalls/dispatcher.rs:453-458`,
    `:475`).
13. **The wait is bounded in a running task.** 500 ticks or 10,000,000 polls,
    whichever first (`src/fs/block_driver_client.rs:79`, `:84`, `:299-304`).
    A driver that never answers costs 5 s per request and a typed error; it
    cannot hold the caller forever by silence alone. (F3 is the case where the
    task does not get to run.)
14. **A reply flood is bounded.** Shard 25 is a 16-deep queue; a full queue
    returns `OutOfMemory` to the writer (`src/syscalls/dispatcher.rs:475-477`)
    and the client discards at most one non-matching message per poll. Only the
    reservation owner can flood at all.
15. **Replies queued before a request are never accepted for it.**
    `src/fs/block_driver_client.rs:255-257` drains the shard before each send.
    (Replies that arrive *after* the drain are F1 and F4.)
16. **Both drivers echo the request tag on every decodable path**, including
    error, unknown-command, pre-handshake and no-device paths, and send nothing
    for an undecodable request: `user/virtio-blk/src/main.rs:534-565`,
    `:727-731`; `user/nvme/src/main.rs:158-205`, `:346-350`. There is no
    untagged or default-tagged reply.
17. **Wire decoders reject short input.** `cambios-blk-proto/src/lib.rs`:
    `decode_kernel_reply`, `decode_u64_data` and the request decoders return
    `None` on truncation; `encode_kstatus_reply` returns 0 rather than writing
    a partial header.
18. **Both drivers bound-check the LBA against the device's real capacity**
    before I/O (`user/nvme/src/nvme.rs:364`; virtio-blk's handler), so an
    injected or mistaken LBA cannot reach past the device.
19. **A dead driver's stale commands and replies do not outlive it on the
    endpoints it registered.** `src/reap.rs:236-282` clears both managers'
    queues for those endpoints. (Shard 25 is not among them, but every request
    drains it first.)

## Open questions

Things this review could not settle by reading.

1. **The policy query endpoint has F1's root cause.** Any process can enqueue a
   message on the policy service's query endpoint; `user/policy-service`'s
   handler parses `[query_id:8][caller_pid:4][syscall_num:4][caller_principal:32]`
   from the payload and does not look at the sender, and query ids are
   sequential (`src/policy/mod.rs:240-250`). Can a forged query that names a
   permissive Principal and the id of a real pending query produce an Allow for
   that pending query? This depends on timing and on what `complete_query`
   tolerates, and was not traced to a conclusion. The endpoint-23 reply gate is
   still pid-based, as the commit message notes. The structural fix proposed
   in F1 covers both endpoints.
2. **Policy cache keying.** The per-CPU decision cache is keyed on process
   slot. Does a restarted process in a reused slot inherit its predecessor's
   cached decisions for the cache lifetime? Relevant to F5's "only the syscall
   list stops it".
3. **Actual stack depth of `handle_read_volume_header`** (F6). Needs the
   high-water measurement.
4. **Has the load balancer ever migrated a task that was inside
   `BlockDriverClient::call` under `OBJECT_STORE`?** A one-line audit of
   `PREEMPT_DEPTH` at idle entry on each CPU would answer it (F3, step 5).
   Related: is `fs-service`'s boot-time behaviour today "limps along" because
   every other task on its CPU happens to block quickly?
5. **What the object store does with a block that fails integrity** after a
   cross-matched reply or a shared-page clobber (F1, F4): typed error and
   retry, or a persistent bad record?
6. **nvme is proven by build only** (STATUS.md, 2026-11-10 entry). Its reply
   paths were read, not exercised; the reading found them equivalent to
   virtio-blk's.
7. **Can a process run with no Principal bound?** If so, F1's proposed
   driver-side check ("a message on 26 with a Principal is not the kernel's")
   is insufficient on its own, which is one more reason to make the kernel-side
   refusal the primary fix.
8. **Is the F1 window open before the policy service is ready?** Policy answers
   Allow until `POLICY_SERVICE_READY`; F1 does not depend on that (every row
   lists `write`), but F5's protection does.
