# ArcOS Manuals

These are narrative walkthroughs of how ArcOS works. They follow real things — a message, a boot sequence, a packet, a signature — through the system, explaining what happens and why at each step. They are not reference material (see the [architecture document](../../ArcOS.md) and [syscall reference](../../SYSCALLS.md) for that). They are stories.

Each manual is self-contained. Read whichever one interests you.

1. **[Waking Up](01-waking-up.md)** — What happens when ArcOS boots, from the first instruction to the first scheduled task. Bootstrap paradoxes, dependency chains, and the careful choreography of bringing a microkernel to life on bare metal.

2. **[The Life of a Message](02-life-of-a-message.md)** — Follow an IPC message from a user-space `write()` syscall through capability checks, identity stamping, and endpoint delivery. A story about trust: at every checkpoint, someone asks "who are you and what do you want?"

3. **[The Signature Chain](03-signature-chain.md)** — How ArcOS knows the code it runs is the code that was built. A YubiKey, a hash, a trailer, and a kernel that refuses to allocate a single byte of memory for code it can't verify.

4. **[Why a Buggy Driver Can't Kill You](04-driver-isolation.md)** — What happens when a device driver misbehaves in ArcOS versus a monolithic kernel. The microkernel isolation story told through consequences.

5. **[From NTP Query to UTC Clock](05-ntp-query.md)** — Follow a UDP packet from construction to transmission to parsing, through the full networking stack. How ArcOS asks Google what time it is, and why the answer requires every layer of the system to work.
