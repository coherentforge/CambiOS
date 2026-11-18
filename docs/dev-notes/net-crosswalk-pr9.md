# Crosswalk: PR #9 network spec → ADR-039 boundaries

Companion to [ADR-039](../adr/039-network-stack-architecture.md). Every id in
PR #9's `spec/crates/net.md` (behaviours `B-n`, invariants `INV-net-nnn`,
acceptance tests `AT-net-nnn`) is bound here to the place in ADR-039 where it
is satisfied, or marked for reconciliation. This is the document the two
designs merge in; the PR author reviews it line by line and the ADR body is
amended where the crosswalk shows it short.

Status column: **core** = satisfied by the first networked build (ADR-039 § 5.2);
**later** = specified work after the core (§ 5.3), with the spec as source;
**reconcile** = the two designs differ and a decision is needed, proposed
resolution given; **internal** = describes the inside of the service, not an
observable boundary, so it binds to the engine's code rather than the contract;
**n/a** = out of the stack's scope in CambiOS, with the reason.

Boundaries referenced: **ep 20/36** (NIC seam control), **ep 34** (socket
control), **ring** (libchan control page and slots), **step** (the pure
engine's `Engine::step`, the proof boundary), **shell** (`user/net-stack`
effects), **driver** (`virtio-net`, `i219-net`), **policy** (the future
egress-policy record, ADR-039 § 10).

## 1. Behaviours (B-1 … B-17)

| id | behaviour | binds to | status |
|---|---|---|---|
| B-1 | wire validity: framing, lengths, checksums, legal field combinations | step: every parser is a total function over a length-asserted slice, typed error on any violation; P6 | core |
| B-2 | host delivery only to a local address and bound endpoint | step: destination check before transport dispatch; ICMP echo is the one control response in the core | core |
| B-3 | TCP state per RFC 9293 + 5961 | step: `TRANSITIONS` table, acceptance test, RFC 5961 checks; P1 to P4 | core |
| B-4 | timers and congestion per RFC 6298 + 9438 | step: RFC 6298 RTO is core; Reno (RFC 5681) is core; CUBIC (RFC 9438) is later. See reconcile R-5 (RTO minimum) | core / later |
| B-5 | neighbour data is unauthenticated, never identity | step: ARP cache updates only entries we asked for; identity is the kernel-stamped AID and never a link address (ADR-039 § 1) | core; ND later |
| B-6 | bounded work everywhere | step: fixed tables, bounded iterators, `MAX_ACTIONS_PER_STEP`; ring: bounded checks, violation limit; P6, P7 | core |
| B-7 | bind/listen/connect/send/receive are capability-checked per Principal | ep 34: socket ownership by stamped AID is core; which Principal may open which endpoint is the policy record (§ 10). Raw-packet operations do not exist in CambiOS (see n/a note under INV-net-014) | core (ownership) / later (policy) |
| B-8 | dynamic configuration is explicit, bounded, subordinate to operator config | shell + step: DHCPv4 with bounded retries, static fallback, `SET_CONFIG` on ep 21 overrides; DHCPv6 and DNS later | core / later |
| B-9 | receive-before-dispatch | shell asserts frame length from the ring slot (`len ≤ 1514`) before `step` sees it; step parsers never see an unasserted slice | core |
| B-10 | fragmentation within bounds; overlapping fragments rejected | IPv4 fragments dropped in the core (TCP sets DF; DHCP and NTP fit one MTU); reassembly and IPv6 fragments later. See reconcile R-8 | later |
| B-11 | IPv4 zero-checksum UDP accepted; IPv6 rejected unless configured | step: UDP receive | core (v4) / later (v6) |
| B-12 | TCP open/close per RFC 9293; no duplicate stream bytes from duplicate or reordered segments | step: state machine, `MAX_OOO_SEGMENTS` reassembly; P5 | core |
| B-13 | challenge ACK for unacceptable RST, rate-limited | step: P3, `CHALLENGE_ACK_PER_SEC`. See reconcile R-6 (unit of the limit) | core |
| B-14 | congestion per RFC 9438 (CUBIC) | step: `CongestionControl` enum with Reno arm in the core; CUBIC arm later | later |
| B-15 | DNS acceptance rules | later (DNS record, PR author owns) | later |
| B-16 | DHCP acceptance rules | step: DHCPv4 client binds offers/acks to interface + transaction, pinned address wins | core (v4) / later (v6) |
| B-17 | absent and unauthorised listeners indistinguishable to a remote peer | step: one RST path, same timing class; the "unauthorised" half exists once the policy record lands | core |

## 2. Invariants (INV-net-001 … 022)

| id | invariant (short) | binds to | status |
|---|---|---|---|
| 001 | delivered frame has a complete link header and declared length ≤ MTU + header | shell: ring slot `len` checked against 1514 (`ETHERNET_MTU_DEFAULT + 14`); step: Ethernet parser rejects short frames; P6 | core |
| 002 | IPv4 reaches transport only when version, IHL, length, checksum, fragment fields, destination are valid | step: IPv4 parser; fragments rejected (not reassembled) in the core | core |
| 003 | IPv6 reaches transport only after full validation | step: IPv6 header parser exists for the dual-stack types (ADR-039 § 5.2); extension-header traversal and transport dispatch are later | later |
| 004 | IPv6 extension processing bounded by headers and bytes | later, with `MAX_IPV6_EXTENSION_HEADERS/BYTES` as the bounds when the IPv6 work is cut | later |
| 005 | neighbour entries affect only the interface and address they name; never identity or capability | step: ARP cache keyed by (interface, address); identity is the AID (ADR-039 § 1) | core |
| 006 | UDP delivered only when length and family checksum rules hold and a permitted endpoint matches | step: UDP receive; ep 21 compat surface is the UDP client API in the core | core |
| 007 | TCP changes state only through an RFC 9293 transition whose guard holds | step: `TRANSITIONS` table + acceptance test; **P1, P2** | core |
| 008 | sender transmits nothing outside both the peer's window and cwnd | step: send path takes `min(snd_wnd, cwnd)`; a bounded Kani harness on the send-size computation is added to P-list as **P8** (see ADR correction below) | core |
| 009 | in-window RST or SYN failing RFC 5961 does not close or advance the connection | step: **P3, P4** | core |
| 010 | retransmission deadlines and cwnd changes follow RFC 6298 / 9438 within timer bounds | step: RTO per RFC 6298, measured by the timer vectors (AT-net-009), not proved; CUBIC later. See R-5 | core (6298) / later (9438) |
| 011 | every table and queue consumes no more than its named capacity | step: fixed-size arrays make most of this type-level; counters (half-open, OOO) are **P7** | core |
| 012 | exhausting a capacity returns `ResourceLimit` or drops only the protected packet, without touching another Principal | step + ep 34: `MAX_SOCKETS_PER_PRINCIPAL`, `FULL` to the exhausted client; P7 | core |
| 013 | no input causes panic, OOB, unchecked wrap or unbounded work at the boundary | step: **P6**; ring: single-fetch rule, fuzz target; shell: `deny(unsafe_code)` | core |
| 014 | an operation has effect only if `NetworkPolicy` permits it for the Principal and endpoint tuple | policy record (§ 10): `CONNECT` / `LISTEN` query, deny on no answer. In the core only ownership is enforced. His `NetworkPolicy` trait is the policy service seen from inside the stack | later |
| 015 | DNS answers only for an outstanding matching query, cached ≤ TTL and bound | later (DNS record) | later |
| 016 | DHCP lease changes only for the requesting interface and transaction; pinned address wins | step: DHCPv4 client | core (v4) / later (v6) |
| 017 | errors reported without payload bytes in default diagnostics | shell + drivers: no payload bytes in any log line; AT-net-015 needs a stats surface, see reconcile R-3 | core, R-3 |
| 018 | reassembly only from non-overlapping fragments, before deadline, within bounds | later (fragment reassembly); core drops fragments | later |
| 019 | a listener accepts only when a capability permits that address and port for the Principal | policy record (§ 10); in the core any Principal may `LISTEN` on a free port and owns what it opens | later |
| 020 | IPv6 UDP carries a nonzero checksum except the explicit exception, off by default | later (IPv6 UDP) | later |
| 021 | outbound route = longest prefix, lowest metric, lowest interface id; never forwarded | step: the core has one interface per NIC driver and a default gateway per interface; a route table with metrics is later. See R-7 | later |
| 022 | an RA-learned IPv6 address is assigned only after DAD succeeds | later (IPv6 behaviour; `SlaacState` is his, adopted as-is when cut) | later |

## 3. Acceptance tests (AT-net-001 … 020)

Each AT is replayed from its `NET-V-*` vectors by the engine's host test
harness (`cambios-netcore/tests/`), through `Engine::step`, which is the
black-box boundary his test surfaces (`ScriptedLink`, `ScriptedClock`,
`ScriptedPolicy`, `StackFixture`, `PacketTrace`) describe. The mapping of his
surfaces onto ours: `ScriptedLink::push_input` = `Event::Frame`;
`ScriptedClock::set` = the `now` argument and `Event::Tick`;
`ScriptedPolicy::allow` = out of the pure core (policy is a shell concern, § 10);
`PacketTrace::frames` = the `Action::Emit` sequence; `StackFixture` = an
`Engine` constructed with test bounds.

| id | boundary (his) | replayed at | status |
|---|---|---|---|
| 001 | link frame input | step: short frame → `Malformed`, no action, counter +1 | core |
| 002 | IPv4 input | step | core |
| 003 | IPv6 input | later | later |
| 004 | neighbour cache | step: ARP conflict with a pinned mapping; "pinned" = operator entry via `SET_CONFIG`, see R-7 | core (ARP) / later (ND) |
| 005 | UDP receive | step; the IPv6 zero-checksum case runs when IPv6 UDP is cut | core (v4 cases) / later (v6 case) |
| 006 | TCP state machine | step: handshake vector; P2 covers it exhaustively | core |
| 007 | TCP output | step: `min(snd_wnd, cwnd)`; P8 | core |
| 008 | TCP input | step: RST/SYN vectors; P3, P4. Rate-limit unit per R-6 | core |
| 009 | TCP timer | step: timer vectors replayed with `Tick`; expected values computed from RFC 6298; CUBIC values later. RTO minimum per R-5 | core (6298) / later (9438) |
| 010 | resource accounting | step: per-Principal quota; P7 | core |
| 011 | packet parsers | step: boundary partition + serial-number wrap; P1, P6 | core |
| 012 | network IPC (authorised vs unauthorised listen) | ep 34 + policy record; the "denied has no packet effect" half is testable in the core by ownership denial, the policy half later | later |
| 013 | resolver | later (DNS) | later |
| 014 | DHCP client | step: the three IPv4 cases; the IPv6 case later | core (v4) / later (v6) |
| 015 | stats / log interface | needs a stats surface: R-3 | reconcile |
| 016 | IP reassembly | later | later |
| 017 | remote TCP response to absent vs denied listener | step: one RST path; the denied half once policy lands | core (absent) / later (denied) |
| 018 | interoperability with Linux and BSD peers | pcap replay through step + the QEMU host-peer runs; Linux/BSD traces are a named later surface (ADR-039 § 6.3). The CambiOS-to-CambiOS back-to-back run is the first peer and is not in his list; proposed as **AT-net-021** | later (his) / core (ours) |
| 019 | route selection | later (R-7) | later |
| 020 | IPv6 address configuration | later | later |

## 4. Reconcile list

Each is a difference between the two designs with a proposed resolution.
R-1 to R-4 change the wire contract and are cheap only before a client exists;
they are proposed for the contract-widening edit that precedes any client.

- **R-1 Error vocabulary.** His `NetError` is a closed enum of twelve
  (`Denied, NoRoute, NoAddress, AddressInUse, NoListener, WouldBlock, TimedOut,
  Closed, Malformed, Unsupported, ResourceLimit, NetworkDown`). ADR-039 § 3 has
  eight status bytes (`OK, ERROR, NO_DATA, NO_DEVICE, BUSY, DENIED, FULL,
  BAD_STATE`), and `ERROR` is a catch-all that his acceptance tests cannot
  distinguish. **Proposed:** the ep 34 status byte becomes `OK = 0`, then his
  twelve in his order from 1, with `NO_DATA` folded into `WouldBlock`, `BUSY`
  into `AddressInUse`, `FULL` into `ResourceLimit`, `NO_DEVICE` into
  `NetworkDown`, `BAD_STATE` into `Closed`. ep 20/36 keep the eight-value set
  (device-side, different vocabulary). One table in `cambios-net-proto`.
- **R-2 Socket events.** His `SocketEventKind` is nine kinds (`Bound,
  Connected, ConnectionRefused, Readable, Writable, Closed, AddressConfigured,
  AddressRemoved, DnsComplete`). ADR-039 has one coalesced `DATA_READY` plus
  `STATUS` polling. **Proposed:** `DATA_READY` becomes `EVENT = 6`
  `[cmd][sock:4][kind:1]` with his kinds as the byte; coalescing rule
  unchanged (one message per transition, `Readable` on empty → non-empty).
  `AddressConfigured/Removed` and `DnsComplete` are later kinds, reserved now.
- **R-3 Stats surface.** His `NetStats` (`malformed, checksum_failure,
  resource_limit, policy_denied, retransmitted, timeout`) is what AT-net-015
  reads. ADR-039 has none. **Proposed:** `GET_STATS = 8` on ep 34, reply
  `[status][6 × u32]` in his order, per-Principal view (a Principal sees its
  own sockets' counters plus the shared malformed/checksum counters). Serves
  INV-net-017's test and nothing else; no payload bytes can appear in it by
  construction.
- **R-4 Accept backlog.** His `TCP_LISTEN_BACKLOG_MAX = 256` bounds completed
  connections not yet accepted. ADR-039 bounds half-open connections per
  listener but has no bound on the accept queue. **Proposed:**
  `MAX_ACCEPT_BACKLOG_PER_LISTENER = 8` (TUNING; 25%-rule against a burst of
  2, drawn from `MAX_SOCKETS`), a SYN beyond it dropped like a half-open
  overflow. His `backlog: u16` argument to `tcp_listen` becomes a `[backlog:1]`
  field on `LISTEN`, capped at the constant.
- **R-5 RTO minimum.** His `TCP_RTO_MIN_MS = 1000` cites RFC 6298 § 2.4
  ("SHOULD be rounded up to 1 second"). ADR-039 § 5.2 says 200 ms, the Linux
  value. **Proposed:** follow the RFC: 1000 ms. On a LAN between two CambiOS
  stacks fast retransmit covers single losses; a tail loss waits one second,
  which is the RFC's trade. Measured, not proved; revisit if the back-to-back
  run under 5 % loss shows the floor dominating.
- **R-6 Challenge-ACK rate unit.** His bound is 100 per interface per second;
  ADR-039's is 1 per socket per second. RFC 5961 § 7 asks for a limit and
  names neither unit. **Proposed:** keep both: per-socket 1/s (what stops one
  connection being used as an amplifier) and per-interface 100/s (what bounds
  total unauthenticated output). Two constants, two rows.
- **R-7 Interfaces and routes.** His `MAX_INTERFACES = 16`, `MAX_ROUTES = 256`
  with longest-prefix/metric/interface-id selection. ADR-039 has one seam per
  NIC driver, each with its own default gateway, and no route table.
  **Proposed:** the core carries an interface id on every socket and ARP entry
  (so his INV-net-005 and AT-net-004 hold as written) and selects the
  interface by the destination's on-link prefix, else the first interface's
  default gateway; a metric-bearing route table is later, bound then. "Pinned"
  neighbour and address entries are those set via `SET_CONFIG`.
- **R-8 Fragments.** His `MAX_FRAGMENTS_PER_DATAGRAM = 64`,
  `MAX_REASSEMBLY_BYTES_PER_PRINCIPAL = 4 MiB`. ADR-039 drops IPv4 fragments
  in the core. **Proposed:** stays later; when cut, his two bounds are the
  starting values for the derivation pass, and his overlap rejection (B-10)
  is the policy.
- **R-9 Bounds pass.** His table and ADR-039 § 8 differ on every shared row
  (1024 vs 64 sockets, 128 vs 16 per Principal, 256 KiB vs 16 KiB buffers,
  32 vs 4 out-of-order segments, 256 vs 8 half-open). ADR-039's are derived
  from the agent-sandbox workload and a 4 MiB process heap; his are marked
  🟠 estimates. **Proposed:** one joint pass producing a single table with
  the ADR's categories and his profile idea (constrained / general / server)
  recorded as the Replace-when trigger for the larger values.
- **R-10 TCP options.** His open question 3 asks whether timestamps, SACK,
  window scaling and ECN are in the initial profile. ADR-039 § 5.2: MSS
  only; the others parsed and ignored (safe fallback). **Proposed:** that is
  the answer to his question 3 for the core; SACK first in § 5.3.
- **R-11 Verification route.** His claims ledger names Kani for parsers and
  arithmetic and Lean + Aeneas as a candidate for the pure transition model.
  ADR-039 names Kani now and Verus as the pivot for unbounded functional
  properties (CLAIMS C-11 / C-12). **Proposed:** the pure core is written so
  either route can take it (no unsafe, no alloc, sequential, fixed tables);
  the route decision is CLAIMS.md's, not this ADR's, and his ledger rows
  merge into CLAIMS.md with `proposed` status until a harness runs.
- **R-12 Where things live.** His `spec/crates/net.md`, `spec/claims/net.md`,
  `spec/vectors/net/*.json`, `spec/provenance/net.yaml`. **Proposed:** the
  narrative merges into ADR-039; the claims rows into `verification/CLAIMS.md`;
  the vectors move verbatim to `cambios-netcore/tests/vectors/` (their
  `schema.json` and `index.json` included, licence header kept); the
  provenance file is held for the separate Pathways / Aqua decision.

## 5. Corrections this crosswalk makes to ADR-039

Found while binding the ids; applied in the same commit as this file.

- § 6.1 P1 cited INV-net-006 (UDP delivery). Correct: INV-net-007.
- § 6.1 P2 cited INV-net-006..008. Correct: INV-net-007.
- § 6.1 P5 cited INV-net-010 (timers). Correct: B-12 (no duplicate stream
  bytes); no invariant in his list states reassembly order directly.
- § 6.1 P7 cited INV-net-012. Correct: INV-net-011 (capacity) and INV-net-012
  (isolation on exhaustion).
- § 6.1 gains **P8**: the send path never emits sequence-space data beyond
  `min(snd_wnd, cwnd)` (INV-net-008), a bounded harness over the send-size
  computation; his claims ledger already classes INV-net-008 as a Kani target.
- § 7 INV-net-012 row reworded from "a Principal cannot exhaust the socket
  table" to his statement: exhaustion returns `ResourceLimit` or drops only
  the protected packet, without altering another Principal's state; the
  per-Principal bound itself is INV-net-011's capacity.

## 6. What the crosswalk did not find

No requirement in PR #9 is unsatisfiable at ADR-039's boundaries. Everything
marked **later** is specified work the ADR already names; everything marked
**reconcile** is a contract-widening or a bounds question, none of which
touches the kernel or the seam.
