# Why a Buggy Driver Can't Kill You

*What happens when a device driver misbehaves in ArcOS versus a monolithic kernel.*

---

## The Conventional Disaster

In Linux, Windows, or macOS, device drivers run inside the kernel. They share the kernel's address space, the kernel's privilege level, and the kernel's ability to touch every byte of memory in the system. This is fast — a driver that needs to access a hardware register just reads a memory-mapped address. No context switch, no permission check, no overhead.

It's also catastrophic when things go wrong.

A network driver that misparses a packet can write past the end of a buffer and corrupt kernel data structures. A GPU driver with a use-after-free can crash the entire machine. A USB driver with an integer overflow can escalate a plugged-in thumb drive into full kernel control. These aren't hypothetical — they're the most common source of kernel vulnerabilities in every major operating system. Drivers account for roughly 70% of kernel code in Linux, and they're written by thousands of different authors with varying levels of care.

The problem is structural. When you give driver code the same privileges as the scheduler and memory manager, a bug in any driver is a bug in everything.

## The ArcOS Model

In ArcOS, the virtio-net driver is a user-space process. It runs in ring 3 (on x86_64) or EL0 (on AArch64) — the lowest privilege level the CPU provides. It has its own page tables, its own address space, and its own 64 KB stack. It cannot see kernel memory. It cannot see other processes' memory. It cannot execute privileged instructions.

When the driver needs something from the kernel — memory allocation, device register access, interrupt notification — it makes a syscall. That syscall goes through the same enforcement pipeline as every other process: interceptor pre-check, capability verification, argument validation. The driver gets exactly the permissions it was granted, no more.

Let's follow a specific scenario to see what this means in practice.

## Scenario: A Hostile Device

The virtio-net driver discovers its NIC via the DeviceInfo syscall — it asks the kernel to describe PCI devices, finds the one with the virtio vendor ID, and reads its I/O BAR address. It then initializes virtqueues: shared ring buffers where the driver and the device exchange packet descriptors.

Here's the thing about virtqueues: the device writes to them. The device is a piece of hardware (or, in QEMU, emulated hardware) that the driver doesn't control. A well-behaved device writes valid descriptor indices and reasonable lengths. A hostile or buggy device writes whatever it wants.

The ArcOS virtio-net driver treats every value read from the device as untrusted. It wraps device-sourced values in a `DeviceValue<T>` type that forces validation before use:

- `validate_index(value, max)` — checks that a descriptor index is within the queue size. A device that returns index 65,535 for a 256-entry queue gets caught here.
- `clamp_length(value, max)` — caps a returned byte count to the buffer size. A device that claims it wrote 10 MB into a 4 KB buffer gets truncated.

If validation fails — if the device provides an out-of-bounds index — the driver kills the device. Not the system. Not the kernel. Just the device. The driver sets the device status to "failed" and stops processing. Other drivers, other processes, the kernel itself — none of them are affected.

## DMA: The Memory Boundary

Direct Memory Access is where driver isolation gets interesting. The device needs to read and write memory directly — that's what DMA is. In a monolithic kernel, the driver would just hand the device a kernel buffer address, and the device would DMA directly into kernel memory. If the device or driver is compromised, it can read or write anywhere in physical memory.

ArcOS uses DMA bounce buffers. The driver requests physically contiguous memory via the AllocDma syscall. The kernel allocates pages, maps them into the driver's user-space address space, and places unmapped guard pages before and after the allocation. The kernel returns both the user virtual address (so the driver can read/write the buffer) and the physical address (so the device can DMA to it).

The guard pages mean a DMA overrun — a device writing past the end of its buffer — hits an unmapped page and faults rather than corrupting adjacent memory. The buffer is in user-space, not kernel space, so even if the device writes garbage, it can only corrupt the driver's own address space.

When the driver has data to send, it copies the packet into a bounce buffer, tells the device the buffer's physical address via the virtqueue descriptor, and notifies the device to process it. When data arrives, the device writes into a pre-posted bounce buffer, and the driver copies the data out. At no point does the device have access to kernel memory or any other process's memory.

## Port I/O: The Kernel as Gatekeeper

On x86, legacy devices use I/O ports — a separate address space accessed via `in` and `out` instructions. These are privileged instructions that user-space can't execute directly. The driver uses the PortIo syscall, which tells the kernel: "I want to write this value to this port."

The kernel doesn't blindly execute the port access. It checks whether the requested port falls within a PCI device's I/O BAR — a range of ports that the device actually owns. If the port isn't within any discovered PCI device's address range, the kernel rejects the request. A driver can't use PortIo to access arbitrary hardware or probe ports belonging to other devices.

This is the kernel as gatekeeper: it doesn't understand what the driver is doing with the device, but it ensures the driver can only talk to the specific device it's been granted access to.

## What Happens When the Driver Crashes

Suppose the virtio-net driver has a bug. Maybe it indexes an array out of bounds, or dereferences a null pointer, or divides by zero. In a monolithic kernel, this is a kernel panic. The whole system goes down.

In ArcOS, the driver is a user-space process. An out-of-bounds access triggers a page fault. The kernel's page fault handler sees that a user-space process accessed an unmapped address and terminates that process. It's the same mechanism that handles any misbehaving program.

The driver's IPC endpoint (endpoint 20) goes silent. Processes that try to send messages to it won't get responses. The UDP stack, which talks to the driver via IPC, will notice that its requests are timing out. No response is different from a crash — the system degrades but doesn't die.

The kernel's scheduler removes the dead task. The kernel's frame allocator reclaims the driver's physical pages. The kernel's page table for that process is freed. The system resources the driver was using return to the pool.

What doesn't happen is equally important:
- The kernel doesn't crash.
- Other drivers keep running.
- The filesystem service keeps serving.
- The scheduler keeps scheduling.
- Memory belonging to other processes is untouched.

## The Cost

This isolation is not free. A monolithic kernel driver can access device registers with a single memory-mapped load instruction — a few nanoseconds. An ArcOS driver must make a syscall, which involves a privilege transition, register saves, argument validation, and a return — perhaps a few hundred nanoseconds.

IPC adds latency too. When the UDP stack sends a frame through the virtio-net driver, the data crosses two process boundaries: UDP stack to kernel (syscall), kernel to driver (IPC delivery), driver to kernel (syscall for port I/O), kernel back to driver (return). In a monolithic kernel, the networking stack and the driver share an address space, and a function call is all it takes.

ArcOS accepts this cost because the alternative — giving every driver the ability to destroy the system — is a worse tradeoff. The question isn't "is IPC slower than a function call?" It is. The question is "would you rather have a system that's slightly slower or a system where a graphics driver bug can corrupt your filesystem?" For an operating system that takes security seriously, the answer is architectural, not benchmarkable.

## The Broader Pattern

The virtio-net driver is one example, but the pattern applies to everything ArcOS pushes to user space:

- **Filesystem service**: runs as a user process on endpoint 16. A bug in the filesystem can't corrupt the scheduler or the memory manager.
- **Key store service**: runs as a user process on endpoint 17. Even the process that manages cryptographic keys can't access kernel memory.
- **Future drivers**: GPU, USB, audio, storage — all will be user-space processes with the same isolation guarantees.

Each service is an island. It can only affect the system through the narrow, validated, capability-checked channels that the kernel provides. A vulnerability in any one service gains the attacker exactly what that service was authorized to do — not one bit more.

This is what microkernel isolation means in practice. Not just "drivers are separate processes" as an architectural diagram. Specific mechanisms — per-process page tables, DMA bounce buffers, port I/O validation, capability-gated IPC, device value validation — that make "a buggy driver crashed" into a local event rather than a system-wide catastrophe.
