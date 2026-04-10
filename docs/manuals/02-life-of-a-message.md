# The Life of a Message

*Follow an IPC message from a user-space syscall through capability checks, identity stamping, and endpoint delivery. A story about trust.*

---

## The Sender's Intent

A user-space process — say, the UDP stack — wants to send a message to the virtio-net driver. It has a buffer of bytes (an Ethernet frame to transmit) and knows the driver is listening on endpoint 20. It calls `sys::write(20, &buffer)`.

In a monolithic kernel, this would be a function call into shared address space. The sender and receiver would share memory. A bug in either could corrupt the other. In ArcOS, these are isolated processes with separate page tables. They cannot see each other's memory. The only way to communicate is to convince the kernel to carry a message between them.

That convincing is not automatic. The kernel doesn't trust the sender. It doesn't trust the message. It doesn't even trust that the sender is who it claims to be. Every step of delivery is a checkpoint where something can be denied.

## Crossing the Boundary

The `sys::write()` wrapper in libsys puts the syscall number (1, for Write) into RAX, the endpoint ID into RDI, a pointer to the buffer into RSI, and the buffer length into RDX. Then it executes the `syscall` instruction.

This instruction is a hardware-level privilege transition. The CPU saves the user's instruction pointer and flags, loads the kernel's code segment from the STAR MSR, masks interrupts via SFMASK (so the kernel can't be interrupted before it's ready), and jumps to the address in LSTAR — the `syscall_entry` assembly stub in the kernel.

On AArch64, the equivalent is `svc #0`, which triggers a synchronous exception routed through the vector table at VBAR_EL1.

The assembly stub saves every register the user was using, builds a `SyscallFrame` on the kernel stack, and calls into Rust. From here, everything is in safe, structured code — but the kernel is holding the CPU at the highest privilege level, with interrupts off, running on behalf of a process it hasn't yet decided to trust.

## The First Question: "Are You Allowed to Be Here?"

The syscall dispatcher's first act is to check whether this process is even allowed to make this kind of syscall. The zero-trust interceptor fires: `interceptor.on_syscall(process_id, SyscallNumber::Write)`.

Today, this check is permissive — it always allows. But the hook is wired. The architecture anticipates a world where each process has a syscall profile: a serial driver might only be allowed Write, WaitIrq, and Yield. A process that tries to call Allocate when its profile doesn't include it gets `PermissionDenied` before any work begins. The policy is missing, but the enforcement point is real.

## Reading the Sender's Words

The kernel now needs to read the message bytes from user memory. But it can't just dereference the pointer the user provided — that pointer is in the user's virtual address space, which may not be mapped, may point into kernel memory, or may be deliberately crafted to cause the kernel to read something it shouldn't.

The kernel performs a page-table walk. It loads the process's page table root (CR3 on x86_64, TTBR0 on AArch64), walks the four levels of page tables, and translates the user's virtual address to a physical address. Then it accesses the physical memory through the HHDM — the higher-half direct map that makes all physical memory accessible at a fixed offset in the kernel's address space.

If the page isn't mapped, the syscall returns `InvalidArg`. If the address is in kernel space (above the canonical boundary), it's rejected. The kernel copies the bytes into its own buffer — a kernel-side `[u8; 256]` array. From this point forward, the user's original buffer is irrelevant. The kernel has its own copy.

This copy is not just for safety. It's for isolation. Once the bytes are in kernel space, the user process can't modify them. The message the receiver gets is the message the sender sent, not whatever the sender's memory looks like by the time the receiver reads it.

## Building the Envelope

The kernel constructs a `Message` struct: a fixed-size container with a `from` endpoint, a `to` endpoint, a 256-byte payload array, and — crucially — a `sender_principal` field that starts as `None`.

The sender didn't set `sender_principal`. The sender *can't* set it. Even if the user wrote a principal into their buffer and tried to claim an identity, it wouldn't matter. The kernel is about to overwrite that field with the truth.

## The Second Question: "Do You Have Permission?"

The kernel acquires two locks — IPC_MANAGER and CAPABILITY_MANAGER — in the correct order (lock positions 3 and 4 in the global hierarchy). Lock ordering is strict in ArcOS: acquiring a lower-numbered lock while holding a higher-numbered one is a deadlock waiting to happen, and the design prevents it structurally.

The capability manager checks whether this process holds a capability with `send` rights on endpoint 20. Capabilities are kernel-managed `(endpoint, rights)` pairs. User-space can't see them, can't fabricate them, can't guess them. They're stored in a per-process table inside the kernel.

A process gets capabilities in exactly two ways: it creates an endpoint (and gets full rights on it), or another process delegates rights to it (and can only delegate rights it already holds, and only if it has the `delegate` flag). There is no third path. There is no "admin mode" that bypasses this check.

If the process doesn't hold the right capability, the syscall returns `PermissionDenied`. The message is dropped. Nothing was enqueued. The receiver never knows a send was attempted.

## The Stamp

If the capability check passes, the kernel does something the sender cannot do for itself. It looks up the sender's bound Principal — a 32-byte Ed25519 public key that was bound to this process at creation time — and stamps it onto the message: `msg.sender_principal = Some(principal)`.

This is the moment the message acquires an unforgeable identity. The kernel — and only the kernel — can write this field. It's set in one place in the codebase (`send_message_with_capability()` in `ipc/mod.rs`), and it's set from the capability manager's own records, not from anything the sender provided.

When the receiver reads this message later, it will see the sender's cryptographic identity. It can trust that identity because the kernel attested to it. A compromised process cannot claim to be someone else. It can only send messages stamped with its own identity, or with no identity at all.

## The Third Question: "Is This Message Well-Formed?"

The interceptor fires again: `interceptor.on_send(sender, endpoint, &msg)`. This time, it checks the message itself:

- Is the endpoint ID within bounds (less than 32)? An out-of-bounds endpoint could cause a kernel memory access error.
- Is the payload length within limits (256 bytes or less)? An oversized payload is a buffer overflow attempt.
- Is the sender trying to send to its own endpoint? Self-sends can deadlock.

These are structural checks — invariants about the *message*, not the *authority*. The capability check verified that the sender is allowed to talk to this endpoint. The interceptor verifies that what the sender is saying is structurally valid.

Three layers of enforcement, each independent of the others. Bypassing one doesn't bypass the others.

## Delivery

The message is enqueued into endpoint 20's queue — a circular buffer holding up to 16 messages. If the queue is full, the send fails with `PermissionDenied`. The sender learns that the receiver isn't keeping up, but the system doesn't deadlock or drop messages silently.

The kernel drops both locks — IPC_MANAGER and CAPABILITY_MANAGER — before the next step, because the next step requires the scheduler lock, which is position 1 in the hierarchy (the highest). Acquiring it while holding position-3 and position-4 locks would violate ordering.

The scheduler checks whether any task is blocked waiting for a message on endpoint 20. If the virtio-net driver called `recv_msg()` earlier and found the queue empty, it was put to sleep — marked as `Blocked` with a `WaitingForMessage` reason. The scheduler now marks it `Ready` and puts it back in the run queue. On the next timer tick (or sooner, if the receiver is on a different CPU that's currently idle), the receiver will wake up and find the message waiting.

## The Receiver's Perspective

When the virtio-net driver's `recv_msg()` resumes, it goes through its own enforcement gauntlet. The capability manager verifies that this process has `receive` rights on endpoint 20. The interceptor checks endpoint bounds. Only then does the kernel dequeue the message and begin copying it to the receiver's buffer.

The copy goes the opposite direction: kernel buffer to user memory, via another page-table walk through the receiver's CR3/TTBR0. The kernel writes the payload into the receiver's buffer, and returns the number of bytes delivered.

For `RecvMsg` (syscall 13, the identity-aware variant), the kernel prepends 36 bytes of metadata: the 32-byte `sender_principal` followed by a 4-byte `from_endpoint` ID. The receiver can inspect who sent this message and from which endpoint, with cryptographic assurance that the identity is genuine.

## What Just Happened

A user-space process put some bytes in a buffer and asked the kernel to deliver them. The kernel:

1. Verified the process was allowed to make this kind of syscall
2. Safely copied the bytes out of user memory via a page-table walk
3. Checked that the sender holds a capability with send rights on the target endpoint
4. Stamped the message with the sender's unforgeable cryptographic identity
5. Verified the message is structurally valid (bounds, size, no self-send)
6. Enqueued the message and woke up the receiver
7. Performed the reverse page-table walk to deliver bytes to the receiver's memory

Seven steps. Three independent enforcement layers. Two page-table walks. One identity stamp that no user-space code can forge.

In a monolithic kernel, this would be a function call — fast, no enforcement, no isolation, no identity. One shared address space where any bug is everyone's problem.

In ArcOS, the overhead of those seven steps is the price of a system where a compromised process can send messages stamped with its own (real) identity to endpoints it has (real) permission to use, containing payloads that are (really) validated. It cannot pretend to be someone else. It cannot talk to endpoints it hasn't been granted access to. It cannot send malformed data that corrupts kernel state.

The message arrived. The receiver knows who sent it. That's not a feature. That's the architecture.
