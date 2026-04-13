# Waking Up

*What happens when CambiOS boots, from the first instruction to the first scheduled task.*

---

## Nothing Works Yet

The Limine bootloader has done its job. It loaded the kernel ELF into memory, set up a page table with a higher-half direct map, switched the CPU to 64-bit long mode, and jumped to `kmain()`. Then it stepped aside.

The kernel is now running at the highest privilege level the CPU offers. But almost nothing works. There is no exception handler — if anything goes wrong, the CPU will triple-fault and reset. There is no heap — the kernel can't allocate memory. There is no way to print — the serial port hasn't been configured. Interrupts are masked, so no timer is ticking, no keyboard will respond, and no device can signal anything.

The boot sequence is the story of solving these problems in the right order. Every step enables the next. Get the order wrong, and the machine crashes silently.

## First Words

The very first thing the kernel does is store the HHDM offset — a number that Limine provides, telling the kernel where physical memory is mapped in the virtual address space. This number is stored in an atomic integer, not on the heap, because the heap doesn't exist yet.

On AArch64, there is an immediate complication. Limine's HHDM only covers RAM. Device I/O registers — the UART serial port, the interrupt controller — are not mapped. The kernel can't print, and it can't handle interrupts. Before anything else, AArch64 must call `early_map_mmio()` to manually map the PL011 UART at `0x0900_0000` and the GIC interrupt controller at `0x0800_0000` into the kernel's page tables.

This is done using "bootstrap frames" — page table pages allocated from the kernel's own `.bss` section, because the page frame allocator doesn't exist yet. The kernel literally finds physical pages by walking its own page tables, since kernel statics live in HHDM-mapped memory that can be reverse-translated. It's a bootstrap paradox: you need page tables to build page tables, so you use the ones Limine already set up as scaffolding.

On x86_64, this problem doesn't exist — Limine's HHDM maps everything, including MMIO regions. The kernel moves straight to serial port initialization.

Once `io::init()` runs — configuring COM1 on x86_64 or the PL011 UART on AArch64 — `println!()` works. The kernel can finally speak. Everything before this point was silent.

## Building the Foundation

With serial output working, the kernel prints its first banner and checks that Limine's boot protocol version is compatible. Then it reads the memory map — a table Limine provides listing every region of physical memory and what it's for (usable RAM, ACPI tables, reserved, etc.). The kernel prints this map as a diagnostic. It's the first time the system can describe itself.

Next comes the heap. The kernel scans the memory map for a usable region of at least 4 MB, skips the first megabyte (to avoid low-memory conflicts with BIOS artifacts), converts the physical address to a kernel virtual address via the HHDM, and hands the range to the heap allocator. After `init_kernel_heap()` returns, `Box::new()` and `Vec::new()` work. This is the moment the kernel goes from static data structures to dynamic ones.

Immediately after, the frame allocator initializes. This is the physical memory manager — it tracks which 4 KB pages of RAM are free and which are in use. It scans the memory map, marks all usable regions as available, then reserves the pages already claimed by the kernel heap and by process heap regions. A bitmap covering 2 GiB of physical memory (524,288 frames, 64 KB of bitmap stored in `.bss`) represents the entire physical address space the kernel manages.

Now the kernel saves its own page table root — CR3 on x86_64, TTBR1 on AArch64 — into a global atomic. This value will be needed later when context-switching back from user mode. Without it, the kernel couldn't restore its own address space after running a user process.

## Installing the Safety Net

With memory management in place, the kernel installs exception handlers. On x86_64, this means loading a Global Descriptor Table (GDT) with kernel and user code/data segments plus a Task State Segment (TSS), then loading an Interrupt Descriptor Table (IDT) with handlers for all 32 CPU exceptions — divide by zero, page fault, double fault, general protection fault, and so on. On AArch64, it means writing the exception vector table address to VBAR_EL1.

The SYSCALL/SYSRET mechanism (x86_64) or SVC exception routing (AArch64) is configured here too. This is how user-space processes will request kernel services — fast system call entry without the overhead of a full interrupt.

After this point, exceptions are handled instead of being fatal. A page fault produces an error message rather than a silent reset. The safety net is in place.

## Bringing Up the Subsystems

Now the kernel initializes its core subsystems, one at a time, in a specific order dictated by the lock hierarchy. CambiOS has a strict rule: locks must be acquired in a fixed global order to prevent deadlock. The subsystems initialize in that same order, because each one builds on what came before.

**Process table** comes first. It creates descriptors for the three kernel processes (PIDs 0, 1, 2), each with its own page table. These aren't real processes yet — they're just bookkeeping entries. But the scheduler and IPC system need them to exist.

**IPC manager** comes next. It creates 32 endpoint queues, each holding up to 16 messages, and installs the default zero-trust interceptor. Messages can now be routed between endpoints, though nothing is sending yet.

**Capability manager** follows. It creates a permission table that tracks which process holds which rights on which endpoints. The kernel processes get broad capabilities — they need to manage the system. User processes will get only what they're explicitly granted.

**Bootstrap identity** is next, and this is where the trust model becomes concrete. The kernel loads a 32-byte Ed25519 public key that was compiled into the binary from `bootstrap_pubkey.bin`. This key was extracted from a YubiKey — a hardware security module where the corresponding private key lives and will never leave. The kernel creates a `Principal` from this public key and binds it to kernel processes 0-2. From this point forward, the kernel has a cryptographic identity. It can prove that messages it stamps were stamped by the entity that controls the YubiKey.

The signing secret key is *not* stored anywhere in kernel memory. It doesn't need to be. Binaries were signed at build time on the developer's machine, through the YubiKey. At runtime, the kernel only needs the public key to verify those signatures. This is a deliberate design choice: there is no secret in kernel memory to steal.

**Object store** initializes last in this sequence — a RAM-backed content-addressed store for up to 256 objects, each identified by its Blake3 hash.

## Creating Work

With all subsystems ready, the scheduler initializes. This is the most complex step, because it depends on everything that came before.

The scheduler creates the idle task (Task 0) on the boot stack — this is the task that runs when there's nothing else to do. It creates two kernel-mode tasks with their own stacks. Then it loads the boot modules.

Boot modules are ELF binaries that Limine loaded into memory alongside the kernel. Before CambiOS will run any of them, every binary must pass through the `SignedBinaryVerifier`. The verifier strips a 72-byte ARCSIG trailer from the end of the binary, extracts a 64-byte Ed25519 signature, computes the Blake3 hash of the remaining ELF bytes, and checks the signature against the bootstrap public key. If the signature doesn't match — if even a single byte has been changed — the binary is rejected. No memory is allocated for it. No pages are mapped. It simply doesn't load.

For each verified module, the kernel creates a full user-space process: a new set of page tables (with the kernel half cloned for the upper address space), user code mapped at `0x400000`, a 64 KB user stack below `0x800000`, and a `SavedContext` on a kernel stack that will be used for context switching. The ELF loader enforces W^X — no memory page is both writable and executable — and rejects binaries with segments that overlap or extend into kernel space.

By the end of this step, the scheduler has a set of ready-to-run tasks: kernel tasks, the hello test module, the key-store service, the filesystem service, the virtio-net driver, and the UDP stack.

## Waking the Hardware

Now the kernel enables hardware interrupts. On x86_64, this means disabling the legacy 8259 PIC (remapping its vectors to 0xF0-0xFF and masking all lines), then enabling the Local APIC. The APIC timer is calibrated against the PIT — a one-shot countdown that tells the kernel how many APIC ticks correspond to a known time interval — and configured to fire at 100 Hz (every 10 milliseconds). The I/O APIC is programmed to route device interrupts (keyboard, serial ports, disk controllers) to specific CPU vectors.

On AArch64, the GIC (Generic Interrupt Controller) distributor, redistributor, and CPU interface are initialized. The ARM Generic Timer is configured to fire at 100 Hz using the system counter frequency.

The PCI bus is scanned on x86_64, discovering attached devices and recording their vendor IDs, device classes, and BAR addresses. This device table will be available to user-space drivers via the DeviceInfo syscall.

After this point, the timer will fire 100 times per second. Each tick invokes `on_timer_isr()`, which checks whether the current task's time slice has expired and, if so, picks the next task to run. Preemptive multitasking has begun.

## Waking the Other CPUs

On a multi-core system, only one CPU — the BSP (bootstrap processor) — has been running this entire time. The other CPUs are parked, waiting to be told what to do.

The kernel uses Limine's MP protocol to wake each application processor. For each AP, it writes the address of `ap_entry()` to a field in Limine's per-CPU structure. The AP wakes, jumps to that address, and runs its own initialization sequence: load a per-CPU GDT and TSS (x86_64), set up per-CPU data via the GS base register (x86_64) or TPIDR_EL1 (AArch64), install SYSCALL MSRs or exception vectors, enable the local interrupt controller, start a timer, and create a per-CPU scheduler.

Each AP signals ready by incrementing an atomic counter. The BSP busy-waits until all APs have reported in. Then it distributes some of the ready tasks across the available CPUs — roughly half the tasks migrate to APs in round-robin fashion — and updates the global `TASK_CPU_MAP` so the IPC system knows which CPU owns which task.

## The Loop

The BSP enters the microkernel loop. It enables interrupts globally and begins halting between ticks. Every 10 seconds, it prints scheduler statistics. Every 60 seconds, it verifies scheduler invariants. Periodically, it samples per-CPU workloads and migrates a task if one CPU has two more runnable tasks than another.

But the BSP doesn't really *do* anything anymore. The system is interrupt-driven now. Timer ticks drive preemption. Syscalls drive IPC. Device interrupts drive I/O. The boot sequence is over. The microkernel is alive, and the work happens in the spaces between ticks — in the user-space services that are now running, exchanging messages, signing objects, and discovering hardware.

The choreography that got here — 26 steps, each enabling the next, no heap before the heap exists, no printing before the UART is mapped, no signing verification before the public key is loaded — collapses into the background. From the outside, it looks like the machine just... woke up.
