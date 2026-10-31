<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 CambiOS contributors -->

# CambiOS TCP/IP Stack Specification

**Status:** Draft for review; no implementation authorization implied<br>
**Scope:** Portable user-space IPv4/IPv6 host networking and TCP transport<br>
**Audience:** Spec reviewers, clean-room implementers, verification reviewers
**Requirement IDs:** `NET-REQ`, `NET-INV`, `NET-AT`, and `NET-PROOF`

> **Format note:** This document uses stable numbered requirements, invariants,
> acceptance criteria, and traceability to express the requested “1986 spec”
> style. The exact NAOMS 1986 template was unavailable while that project is
> offline, so exact heading-level conformity is unverified. This draft does not
> claim to reproduce that template.

## 1. Purpose and decision boundary

This specification defines a reviewable target for a secure, portable TCP/IP
host stack on CambiOS. It is a protocol and architecture contract for a future
clean-room implementation. It does not authorize implementation, select an
existing codebase for copying, or ratify a CambiOS architectural decision.

No single open-source stack can be established as “the best” across security,
portability, completeness, performance, and verifiability. Accordingly:

* IETF standards are the normative source for wire behavior.
* OpenBSD is a hardening and defensive-behavior reference.
* smoltcp is a portability and event-driven `no_std` architecture reference.
* FreeBSD, Linux, and lwIP are interoperability, operational, and embedded
  design comparison points.
* Reference implementations are not normative, and their source is not an
  implementation input. Clean-room work derives behavior from this approved
  specification and its cited standards.

## 2. CambiOS context and target boundary

Current CambiOS networking is an isolated user-space service: the UDP stack
implements ARP, IPv4, UDP, and an NTP demonstration; virtio-net supplies a
user-space NIC driver on the currently supported QEMU targets. TCP, DNS, and
general-purpose IPv6 are not claimed as implemented capabilities. DHCP work is
separate and paused pending channel architecture. See `STATUS.md` and
`docs/manuals/05-ntp-query.md` for current behavior.

The protocol core MUST be architecture-independent and buildable without
`std`. Platform support is a separate matrix of boot support, memory/DMA
contracts, driver availability, and hardware validation. x86_64, AArch64, and
RISC-V QEMU targets are CambiOS targets; this does not establish that CambiOS
boots on arbitrary Macs, phones, or Raspberry Pi models. Locked boot chains,
cellular baseband access, firmware, and NIC driver availability remain
platform-specific prerequisites. The stack described here is a host stack;
router forwarding, cellular modem control, Wi-Fi management, TLS, and VPNs are
outside the initial scope.

## 3. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
requirements. Unless a requirement explicitly narrows behavior, the referenced
RFC defines the protocol detail. For conflicting or updated requirements,
implementers MUST use the current RFC Editor status and errata at approval
time, not an obsolete summary in this document.

## 4. Standards profile

The initial profile is a dual-stack host with Ethernet-like link services and
an abstract link-driver boundary. Required protocol specifications:

| Area | Normative baseline | Profile |
|---|---|---|
| IPv4 | RFC 791, RFC 1122, and applicable updates | Host-only IPv4; reject malformed headers and invalid lengths before dispatch |
| ARP | RFC 826 with RFC 5227 address-conflict behavior where applicable | Ethernet/IPv4 neighbor resolution; bounded cache |
| IPv6 | RFC 8200, RFC 4861, RFC 4443, RFC 4862 | Host IPv6, Neighbor Discovery, SLAAC, ICMPv6 essential functions |
| UDP | RFC 768 and RFC 1122 | IPv4 and IPv6 datagrams; checksum rules enforced per family |
| TCP | RFC 9293 plus RFC 5961 and current updates | TCP connection endpoint; no extensions until individually specified |
| TCP timers | RFC 6298 | RTT estimation and retransmission timeout behavior |
| Congestion control | RFC 9438 (CUBIC), RFC 5681 where not superseded | CUBIC sender baseline; loss recovery behavior follows current standards |
| DNS client | RFC 1035 and current updates | Stub resolver only; DNS transport policy is separately configurable |
| DHCPv4 | RFC 2131 | Client only; optional component, not required for static IPv4 bring-up |
| DHCPv6 | RFC 8415 | Client only; optional component, separate from SLAAC |

The profile MUST maintain a generated or reviewed standards-status ledger before
implementation. In particular, RFC 9293 supersedes RFC 793 for TCP, and newer
RFCs update or extend the older host and congestion-control specifications.

## 5. Architecture and trust boundaries

`NET-REQ-001` The protocol engine MUST run as an isolated user-space service;
the kernel MUST NOT parse TCP/IP packets or maintain TCP connection state.

`NET-REQ-002` The stack MUST communicate with device drivers and clients using
capability-checked CambiOS IPC. Packet payloads larger than the bounded control
message MUST use the existing bulk-channel mechanism or a separately reviewed
network bulk interface.

`NET-REQ-003` Device-driver frames and all IPC packet inputs MUST be treated as
hostile, even when the sender is a local service.

`NET-REQ-004` The packet-processing core MUST be separable from effects:
parsing, validation, state transitions, timer decisions, and packet emission
decisions MUST be expressible as deterministic functions over explicit state
and bounded input. Device I/O, IPC, clock reads, and scheduling MUST sit behind
small effect boundaries.

`NET-REQ-005` The service MUST support static configuration first. DHCP, DNS,
and dynamic address configuration MUST be separately enabled components so
that a deployment can omit them.

`NET-REQ-006` The API MUST expose capability-scoped sockets/endpoints, explicit
errors, bounded receive queues, cancellation/close semantics, and per-peer
resource limits. No ambient network authority is implied by process identity.

`NET-REQ-007` The service MUST enforce an explicit network policy boundary for
bind, connect, listen, and packet operations. Policy decisions MUST be
auditable and MUST NOT silently convert denial into success.

## 6. Functional requirements

`NET-REQ-010` The stack MUST implement Ethernet framing for the initially
supported link driver, ARP for IPv4, and IPv6 Neighbor Discovery as specified
above. Link framing MUST be replaceable without changing IP or TCP logic.

`NET-REQ-011` IPv4 and IPv6 input MUST validate version, header/extension
lengths, total lengths, checksums where required, fragmentation rules, and
destination applicability before delivering payloads to a transport.

`NET-REQ-012` The IPv6 extension-header parser MUST have a strict configured
header-count and byte budget. Unknown, malformed, or over-budget chains MUST
be handled as prescribed by the current standards and MUST NOT trigger
unbounded work.

`NET-REQ-013` UDP MUST validate datagram lengths and checksums. IPv6 UDP
checksum omission MUST be rejected except for a standards-defined exception
that is explicitly enabled and documented.

`NET-REQ-014` TCP MUST implement connection establishment, simultaneous open,
data transfer, acknowledgements, retransmission, receive-window handling,
orderly close, reset handling, and TIME-WAIT behavior required by RFC 9293.
Unsupported options MUST be safely ignored or rejected as the RFC specifies.

`NET-REQ-015` TCP MUST apply RFC 5961 challenge-ACK protections and sequence
validation for in-window RST and SYN segments. Challenge-ACK generation MUST
be rate-limited to prevent amplification and CPU exhaustion.

`NET-REQ-016` TCP MUST implement bounded retransmission and congestion control
using the approved RFC 6298 and RFC 9438 profile. A connection MUST NOT emit
data beyond the peer's advertised window or the congestion window.

`NET-REQ-017` The first release MUST NOT claim TLS, peer authentication,
confidentiality, or integrity against on-path attackers. Those properties
belong to separately specified upper layers. Plain TCP MUST be identified as
unauthenticated transport in user-facing API documentation.

`NET-REQ-018` DNS, DHCPv4, and DHCPv6 MUST be opt-in services. DNS transaction
IDs, source ports, response matching, and cache lifetime MUST follow current
standards and defensive guidance; DHCP state and lease timers MUST be bounded.

## 7. Security and resource requirements

`NET-REQ-020` All parsers MUST use checked arithmetic and validate bounds
before slicing, allocation, state mutation, or checksum traversal.

`NET-REQ-021` No packet input may cause panic, process abort, unbounded loop,
unbounded allocation, or unchecked kernel access. Kernel access is outside the
network service's authority except through declared syscalls/capabilities.

`NET-REQ-022` Every table and queue MUST have an explicit capacity and a
specified full behavior. Exhaustion MUST return an explicit error, drop an
eligible packet with a counter, or evict according to a documented policy; it
MUST NOT corrupt another connection or starve unrelated principals.

`NET-REQ-023` Per-principal and global quotas MUST bound connection count,
half-open connections, retransmit memory, out-of-order segments, neighbor
entries, DNS state, and queued bytes. Defaults and deployment overrides MUST
be documented and reviewable.

`NET-REQ-024` Reassembly MUST reject overlaps or resolve them consistently
according to a specified policy; it MUST cap fragments per datagram, bytes,
concurrent datagrams, and lifetime. Ambiguous reassembly MUST NOT be delivered
to transports.

`NET-REQ-025` The stack MUST validate source and destination address classes,
ports, TCP flags/options, ICMP errors, and neighbor advertisements according to
the relevant RFCs. It MUST avoid reflecting oversized responses to spoofable
sources.

`NET-REQ-026` Security-relevant counters and policy denials MUST be observable
through a capability-protected interface. Packet payloads and DNS contents
MUST NOT be logged by default.

`NET-REQ-027` Unsafe Rust MUST be absent from the protocol core where
practicable. Any unsafe code MUST be isolated at a narrow FFI/DMA boundary,
documented with its safety invariants, and separately reviewed.

## 8. Formal-verification contract

The specification is designed to support machine-checked local properties,
not to claim a proof of all network behavior or hardware. A verification plan
MUST accompany implementation review.

`NET-PROOF-001` Safe packet parsers MUST have Kani harnesses proving that all
byte strings within the harness bounds produce either a valid bounded view or
an explicit error without panic or out-of-bounds access.

`NET-PROOF-002` Sequence-number comparisons and range/window checks MUST have
proof harnesses covering wraparound boundaries and documenting the half-range
assumption required by TCP serial arithmetic.

`NET-PROOF-003` State-transition functions for TCP MUST have proof harnesses
for safety invariants: no send outside the peer window, no invalid state
transition, no sequence advancement without accounted data/control flags, and
bounded timer/retransmit state.

`NET-PROOF-004` Resource accounting MUST prove that each transition preserves
configured upper bounds and that allocation failure leaves state consistent.

`NET-PROOF-005` Checksum and length routines MUST be tested against independent
known-answer vectors; proof of arithmetic safety MUST be distinct from proof
of protocol correctness.

`NET-PROOF-006` Proof claims MUST name the exact crate revision, harness,
compiler/toolchain, assumptions, bounds, and excluded behaviors. Bounded model
checking MUST NOT be described as an unbounded proof of TCP correctness.

Kani is suitable for bounded Rust properties, but cannot alone prove RFC
conformance, timing behavior, device correctness, or end-to-end security.
Additional evidence MUST include property-based and coverage-guided fuzzing,
RFC-derived packet tests, differential interoperability tests against at least
two independent stacks, and QEMU end-to-end tests. Differential results are
evidence, not the normative oracle; disagreements are resolved against the
applicable RFC text and errata.

## 9. Acceptance criteria

`NET-AT-001` Every `NET-REQ` has one or more traceable tests, proofs, or a
reviewed rationale for why the property is not mechanically testable.

`NET-AT-002` Valid and invalid packet corpora cover IPv4, IPv6, ARP, ICMP,
UDP, TCP options, TCP state transitions, fragmentation/reassembly, and malformed
length/checksum cases.

`NET-AT-003` The same protocol-core test suite passes for x86_64, AArch64, and
RISC-V build targets where host execution or cross-compilation is supported;
hardware-specific claims are separately listed by verified device/firmware.

`NET-AT-004` Interoperability demonstrates TCP open, transfer, retransmission,
window limitation, close, reset defense, IPv4, IPv6, and UDP against independent
Linux and BSD-derived peers, with packet captures retained as review artifacts.

`NET-AT-005` Adversarial fuzzing finds no panic, memory-safety defect, or
resource-bound violation in parsers and transition functions for the declared
campaign corpus and duration. A clean fuzz run is not proof of absence.

`NET-AT-006` The service remains isolated: malformed device input cannot
corrupt kernel state or another principal's queues, and capability revocation
prevents subsequent network operations through the revoked authority.

## 10. Portability and deployment matrix

| Target class | Protocol-core expectation | Platform evidence required before claiming support |
|---|---|---|
| x86_64 QEMU | Same core semantics | CambiOS boot + virtio-net driver + end-to-end IPv4/IPv6/TCP tests |
| AArch64 QEMU | Same core semantics | CambiOS boot + virtio-net MMIO driver + end-to-end test parity |
| RISC-V QEMU | Same core semantics | CambiOS boot + virtio-net MMIO integration; current driver status must be confirmed |
| Raspberry Pi | No model-independent claim | Exact model, boot firmware, memory map, NIC/Wi-Fi driver, DMA/IOMMU, and physical test |
| Mac hardware | No general claim | Exact model, boot path, secure-boot constraints, NIC support, and physical test |
| Phone hardware | No general claim | Unlocked/replaceable boot path, exact SoC, Wi-Fi/modem policy and drivers, and physical test |

The core may be portable across those classes while the complete OS is not.
The protocol core MUST NOT depend on a particular NIC, PCI topology, timer
frequency, or architecture-specific pointer width.

## 11. Delivery and review gates

1. Review this specification and resolve open standards-profile questions.
2. Approve and baseline the specification before implementation begins.
3. Implement independently in a clean room; record derivation traceability to
   requirements and RFC clauses without importing reference-stack code.
4. Review formal claims, tests, fuzz evidence, interoperability captures, and
   platform support claims independently.

Until gate 2 is explicitly passed, no implementation work is authorized by
this document.

## 12. Traceability and open review items

| Review item | Draft decision | Approval needed |
|---|---|---|
| IPv4/IPv6 baseline | Dual-stack host profile | Confirm support priority and required ICMPv6 subset |
| TCP congestion control | CUBIC per RFC 9438 | Confirm embedded low-memory profile and any alternate algorithm |
| DNS transports | UDP/TCP DNS stub in later opt-in component | Confirm encrypted DNS is intentionally out of initial scope |
| DHCP | Separate optional clients | Confirm DHCPv4/v6 priority relative to static configuration |
| Resource caps | Explicit bounded quotas required; numeric defaults deferred | Set deployment tiers and memory budgets before implementation |
| Formal methods | Kani for bounded safety properties plus fuzz/interop | Confirm proof coverage and acceptable toolchain pinning |
| 1986 formatting | Stable IDs and traceability used | Exact external template unavailable; reviewer may supply canonical template |

## References

* [RFC 9293 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293.html)
* [RFC 5961 — Improving TCP's Robustness to Blind In-Window Attacks](https://www.rfc-editor.org/rfc/rfc5961.html)
* [RFC 6298 — Computing TCP's Retransmission Timer](https://www.rfc-editor.org/rfc/rfc6298.html)
* [RFC 9438 — CUBIC for Fast and Long-Distance Networks](https://www.rfc-editor.org/rfc/rfc9438.html)
* [RFC 8200 — Internet Protocol, Version 6](https://www.rfc-editor.org/rfc/rfc8200.html)
* [RFC 4861 — Neighbor Discovery for IP version 6](https://www.rfc-editor.org/rfc/rfc4861.html)
* [RFC 4443 — ICMPv6](https://www.rfc-editor.org/rfc/rfc4443.html)
* [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791.html)
* [RFC 826 — Ethernet Address Resolution Protocol](https://www.rfc-editor.org/rfc/rfc826.html)
* [RFC 1122 — Requirements for Internet Hosts: Communication Layers](https://www.rfc-editor.org/rfc/rfc1122.html)
* [RFC 768 — User Datagram Protocol](https://www.rfc-editor.org/rfc/rfc768.html)
* [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035.html)
* [RFC 2131 — Dynamic Host Configuration Protocol](https://www.rfc-editor.org/rfc/rfc2131.html)
* [RFC 8415 — Dynamic Host Configuration Protocol for IPv6](https://www.rfc-editor.org/rfc/rfc8415.html)
* [RFC 5227 — IPv4 Address Conflict Detection](https://www.rfc-editor.org/rfc/rfc5227.html)
* [smoltcp project](https://github.com/smoltcp-rs/smoltcp) — non-normative portability reference
* [OpenBSD TCP implementation](https://github.com/openbsd/src/blob/master/sys/netinet/tcp_input.c) — non-normative hardening reference
* [FreeBSD Handbook: Network](https://docs.freebsd.org/en/books/handbook/network/) — non-normative operational reference
* [lwIP documentation](https://www.nongnu.org/lwip/) — non-normative embedded-stack reference
