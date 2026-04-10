# From NTP Query to UTC Clock

*How ArcOS asks Google what time it is, and why the answer requires every layer of the system to work.*

---

## The Question

The UDP stack service, shortly after starting up, wants to know what time it is. Not from a local clock — from the internet. It will send an NTP packet to Google's time server at `216.239.35.0`, port 123, and parse the response into a human-readable UTC timestamp.

This is a simple question. The answer requires Ethernet framing, ARP resolution, IPv4 with RFC 1071 checksums, UDP, NTP parsing, a virtio network device, DMA bounce buffers, PCI device discovery, IPC between two user-space services, and multiple kernel syscalls. Every layer of the networking stack has to work.

## Finding the Wire

The UDP stack is a user-space process. It has no direct access to network hardware. It doesn't even know its own MAC address yet.

Its first act is to ask the virtio-net driver — another user-space process, running on IPC endpoint 20 — for the NIC's MAC address. It builds a one-byte IPC message containing `CMD_GET_MAC` (0x3), sends it to endpoint 20 via `sys::write()`, and blocks waiting for a response via `sys::recv_msg()`.

The IPC message crosses two process boundaries and passes through the full enforcement pipeline described in "The Life of a Message": capability check, principal stamping, interceptor validation, endpoint delivery. The virtio-net driver wakes up, reads its NIC's MAC address from the device's configuration registers (via MMIO), and sends the six-byte MAC address back.

Now the UDP stack knows who it is on the network: a specific Ethernet interface with a specific hardware address.

## Learning to Reach the Gateway

The NTP server is at `216.239.35.0`. The UDP stack is at `10.0.2.15` with a `/24` subnet mask. A quick bitwise AND tells it the server is not on the local subnet — the packet needs to go through the gateway at `10.0.2.2`.

But Ethernet doesn't understand IP addresses. To send a frame to the gateway, the UDP stack needs the gateway's MAC address. This is what ARP is for.

The UDP stack constructs a 28-byte ARP request: "Who has IP 10.0.2.2? Tell 10.0.2.15." It wraps this in an Ethernet frame with the broadcast MAC address (`FF:FF:FF:FF:FF:FF`) as the destination, its own MAC as the source, and EtherType `0x0806` (ARP).

This frame goes to the virtio-net driver via IPC — another `CMD_SEND_PACKET` message to endpoint 20. Inside the driver, the frame is copied into a DMA bounce buffer: a page of physically contiguous memory that the kernel allocated with guard pages on either side. The driver prepends a 10-byte virtio-net header (all zeros — no offload features), posts the buffer's physical address into the TX virtqueue's descriptor table, updates the available ring index with a volatile write, and notifies the device by writing to the queue notify port via the PortIo syscall.

The device reads the descriptor, DMAs the frame from the bounce buffer, and transmits it on the virtual wire. QEMU's SLIRP network stack, sitting on the other end, receives the ARP request and responds with its own MAC address.

The response arrives in the opposite direction. The device writes received data into a pre-posted RX bounce buffer (one of 16 that the driver posted at initialization), updates the used ring, and raises an interrupt. The driver polls the used ring, finds the new entry, validates the descriptor index and length against the queue size (hostile device checks via `DeviceValue<T>`), copies the frame out of the bounce buffer, recycles the buffer back into the RX ring, and delivers the frame to the UDP stack via IPC.

The UDP stack peels the Ethernet header, finds EtherType `0x0806`, parses the ARP reply, extracts the gateway's MAC address, and stores it in a 4-entry ARP cache. Now it can reach the gateway.

## Building the NTP Request

The UDP stack constructs the NTP query from the inside out, layer by layer:

**NTP payload** (48 bytes): A version 4 client request. Byte 0 is `0x23` — LI (leap indicator) = 0, VN (version) = 4, Mode = 3 (client). The remaining 47 bytes are zeros. This is the simplest valid NTP request: "tell me the time, I have no prior reference."

**UDP header** (8 bytes): Source port 12345, destination port 123 (NTP), length = 8 + 48 = 56, checksum = 0 (optional in IPv4).

**IPv4 header** (20 bytes): Version 4, IHL 5 (no options), total length = 20 + 56 = 76, identification `0x1234`, flags `0x4000` (Don't Fragment), TTL 64, protocol 17 (UDP), source IP `10.0.2.15`, destination IP `216.239.35.0`. The header checksum is computed via `ip_checksum()` — the RFC 1071 Internet checksum algorithm: sum all 16-bit words, fold the carry bits back in, take the one's complement.

**Ethernet frame** (14 bytes + payload): Destination MAC = the gateway's MAC (from the ARP cache). Source MAC = our NIC's MAC. EtherType = `0x0800` (IPv4). Total frame: 14 + 76 = 90 bytes.

The complete 90-byte frame is sent to the virtio-net driver via IPC. The driver copies it into the TX bounce buffer, posts it to the virtqueue, notifies the device. The packet travels through QEMU's SLIRP stack, which performs NAT (rewriting the source address from `10.0.2.15` to the host's real IP), and sends a real UDP packet to `216.239.35.0:123` — Google's actual NTP server.

## The Response

Google's NTP server responds. The reply travels back through QEMU's NAT, arrives at the virtual NIC, and the device DMAs it into an RX bounce buffer. The virtio-net driver polls the used ring, validates the descriptor, copies the frame out, and delivers it to the UDP stack via IPC.

Now the UDP stack parses in the opposite direction:

**Ethernet**: strip the 14-byte header, check EtherType = `0x0800` (IPv4).

**IPv4**: verify version = 4, read IHL to find header length, extract protocol (17 = UDP), source IP, destination IP, and payload offset.

**UDP**: read source port (should be 123), destination port, length, and extract the payload.

**NTP**: the response payload is 48 bytes. Bytes 40-43 contain the **transmit timestamp** — a 32-bit big-endian value representing seconds since the NTP epoch (January 1, 1900, 00:00:00 UTC).

The UDP stack converts this to a Unix timestamp by subtracting the NTP-to-Unix epoch offset: 2,208,988,800 seconds (the 70 years between 1900 and 1970).

## Telling the Time

The `unix_to_datetime()` function performs the calendar arithmetic manually — there's no `chrono` crate, no `time` library, no standard library at all. This is a `no_std` user-space binary with nothing but `libsys` for syscall wrappers and whatever math it writes itself.

Seconds since epoch become hours, minutes, and seconds via integer division and modulo. Days since epoch become years by subtracting 365 or 366 for each year (accounting for leap years: divisible by 4, except centuries, except 400-year marks). Remaining days become months by walking a 12-element table of days-per-month (28 or 29 for February, depending on leap year).

The result is printed to the serial console:

```
[udp-stack] NTP timestamp (Unix): 1775123456
[udp-stack] UTC: 2026-04-07 15:30:56
```

The kernel's `println!()` macro, which the user-space process invokes via the Print syscall, writes each character to the UART. On x86_64, that's COM1 at I/O port `0x3F8`. On AArch64, it's the PL011 UART at its MMIO address. Either way, the timestamp appears on the serial console — proof that the entire stack works.

## What Touched What

Trace the data path for this single NTP query:

1. **UDP stack process** — builds NTP, UDP, IPv4, Ethernet frame
2. **IPC (syscall)** — capability-checked message to virtio-net driver
3. **Virtio-net driver process** — copies frame into DMA bounce buffer
4. **Kernel (PortIo syscall)** — validates port, notifies virtio device
5. **Virtio device (DMA)** — reads frame from bounce buffer, transmits
6. **QEMU SLIRP** — NAT, forwards to real network
7. **Google NTP server** — responds
8. **QEMU SLIRP** — reverse NAT, delivers to virtual NIC
9. **Virtio device (DMA)** — writes response into RX bounce buffer
10. **Virtio-net driver process** — validates device values, copies frame out
11. **IPC (syscall)** — capability-checked message back to UDP stack
12. **UDP stack process** — parses Ethernet, IPv4, UDP, NTP, computes UTC

Two user-space processes. Multiple kernel syscalls. Two IPC round-trips. DMA in both directions. A real network packet to a real server. And at no point did either user-space process access hardware directly, touch kernel memory, or bypass the capability system.

The answer to "what time is it?" is the entire networking stack working. And the networking stack is two isolated processes exchanging carefully validated messages through a kernel that trusts neither of them, talking to hardware through bounce buffers that protect against hostile devices, sending a packet that traverses a real network and comes back with a real answer.

That's the microkernel payoff. Not an abstraction. Not a diagram. A timestamp, printed to a serial console, that proves every layer — from DMA bounce buffers to IPC capability checks to RFC 1071 checksums — is doing its job.
