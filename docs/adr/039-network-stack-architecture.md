# ADR-039: Network Stack Architecture: the NIC seam, a clean-room verifiable engine, and the socket boundary

- **Status:** Proposed
- **Date:** 2026-11-02
- **Depends on:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (channels: the bulk substrate every frame and every stream byte rides on), [ADR-007](007-capability-revocation-and-telemetry.md) (channel teardown: the read-only tombstone and the per-process scratch frame a surviving peer lands on; the `chan.peer_violation` audit event), [ADR-002](002-three-layer-enforcement-pipeline.md) (every control message crosses the interceptor; the kernel stamps the sender's Principal), [ADR-018](018-init-process-and-boot-manifest.md) (the stack, the drivers and the test client are manifest rows; endpoints are reserved to their AIDs), [ADR-037](037-native-app-framework.md) (`service_main!` + `libipc` service shape), [ADR-025](025-principal-as-aid.md) (socket ownership is the kernel-stamped 32-byte AID)
- **Related:** [ADR-006](006-policy-service.md) (the policy service will see `CONNECT` and `LISTEN` as the egress enforcement point; the rule vocabulary is a later record), [ADR-038](038-sandboxed-guest-processes.md) (the agent sandbox is the v1 workload the bounds are sized for and the reason the stack is a trust boundary), [ADR-019](019-process-fault-reaping-and-peer-generation.md) + [ADR-034](034-deferred-task-resource-reclamation.md) (a client or driver dies through this path; the stack must outlive it), [ADR-022](022-wall-clock-time.md) (NTP sync keeps living in the stack), [ADR-014](014-compositor-scanout-driver-protocol.md) (the compositor's channel hand-off is the precedent the seam hand-off copies), [ADR-024](024-syscall-abi-crate.md) (no new syscall; the one kernel change is in ADR-007), [verification/CLAIMS.md](../../verification/CLAIMS.md) (where the proof targets become rows), [docs/ASSUMPTIONS.md](../ASSUMPTIONS.md) (where every bound below is catalogued)
- **Supersedes:** N/A (retires `user/udp-stack` as a program; its ep 21 wire protocol is kept verbatim as a compatibility surface of the new stack)

## Scope Boundary (read this first)

This ADR decides how networking is structured in CambiOS: which processes exist, what crosses between them and over which primitive, what the protocol engine is and how it is held to its specification, and in what order the work is cut. It is the record the collaboration on PR #9 and the maintainer's parallel design merge into; the requirements format in § 7 is PR #9's.

| Concern | Owner |
|---|---|
| Process topology (driver / stack / client), endpoints, who creates and who attaches each channel | **This ADR** |
| Wire format of the NIC seam (ep 20, ep 36) and of socket control (ep 34): `cambios-net-proto` | **This ADR** |
| The ring protocol over a channel pair (`libchan`), including what a lying peer costs | **This ADR** (born here, generic; a second consumer may give it its own record) |
| The protocol engine `cambios-netcore`: shape, protocol scope, proof targets, oracle | **This ADR** |
| Shared-memory channel primitive, syscalls, page-table mechanics | [ADR-005](005-ipc-primitives-control-and-bulk.md) (unchanged) |
| What a surviving peer's mapping becomes when the other side dies (tombstone, scratch frame), `chan.peer_violation` | [ADR-007](007-capability-revocation-and-telemetry.md) § Divergence entries 7 and 8 (the one kernel change this work needs lands there) |
| Which Principal may talk to which host or port | A later egress-policy record; § 10 names the hook and its fail-closed shape only |
| DMA, MMIO, the hostile-device posture of each NIC driver | The drivers, unchanged; this ADR adds the seam to them |
| TLS, DNS, DHCPv6, IPv6 protocol behaviour, SACK, CUBIC, fragment reassembly | Specified work cut from this ADR after the core (§ 5.3); each is a later section or record, several owned by the PR #9 author |
| A POSIX sockets API, `std`, musl | [ADR-038](038-sandboxed-guest-processes.md) consumers, later; the client API here is CambiOS-native |

## Context

Today `virtio-net` and `i219-net` hand frames to `udp-stack` inside 256-byte control messages (`SEND_PACKET` / `RECV_PACKET` on ep 20). A frame is capped near 250 bytes. TCP with a 200-byte MSS is not TCP anyone can use, and [ADR-005](005-ipc-primitives-control-and-bulk.md) already decided that bulk bytes do not ride the control path. The UDP stack also carries the NTP wall-clock sync and a DHCP client that paused waiting for exactly this decision.

Two designs arrived in the same week. The maintainer's hand-off packet (`stage-r1-tcp-stack`) put the frame seam on a channel pair, specified the socket control protocol, built and fuzzed the ring library, and chose smoltcp as the first engine with a clean-room engine as a later ambition. PR #9 (javruben, 2026-11-02) specified a clean-room IPv4 + IPv6 stack from the RFCs in a behaviour → invariant → acceptance-test → vector format, with per-Principal quotas, half-open budgets, RFC 5961 reset defence, diagnostic privacy and a no-panic boundary as named requirements.

Reading the two together informed the engine decision. The reasons are in § 5 and § 6; the short form: a stack whose transition function carries machine-checked invariants does not exist in Rust, the BuddyAllocator shape (pure core, effects outside) is already how this kernel is built for verification, and shipping smoltcp first and replacing it later fails the sawtooth check. smoltcp keeps a permanent role as a host-side differential oracle.

The collaborator's goal is NAOMS running on CambiOS, peer to peer. That makes another CambiOS stack the first-class peer, and it reorders the interoperability work: two instances of the verified engine talking to each other is the first thing that has to work, and Linux and middlebox quirks are a later, separately tested surface.

## Need

Deliver TCP/IP as a userspace service such that:

1. Full-size Ethernet frames cross between a NIC driver and the stack without touching the control path, on QEMU and on the x86_64 dev box I219 with no stack change.
2. The protocol engine is a pure function of its inputs, host-testable, and a proof target from its first commit, with its specification as the authority and an independent implementation as the oracle.
3. The tested contract is what is observable from outside the stack process: the IPC messages, the ring layout, and the engine's `step` boundary. Not a library API.
4. Every party is mutually untrusted at runtime: a client may lie in its ring, a driver may lie in its ring, a peer on the wire may send anything. The stack survives all three, counts the lies, and ends the relationship when they exceed a bound.
5. IPv6 is in the contract and the types from the first commit, because four-byte address fields in a wire format are cheap to widen before anyone depends on them and a migration afterwards.
6. The egress trust boundary of the agent sandbox contains no code the project did not write.

## Decision

### 1. Three process classes, Principal-owned sockets

Networking is three kinds of process, each a manifest row with a derived AID, none holding anything the other two need:

- **NIC drivers** (`virtio-net`, `i219-net`) hold DMA and MMIO and nothing else. They implement the seam (§ 2) and know nothing about IP.
- **The stack** (`user/net-stack`) holds the engine, every socket, the seam to each driver and a stream channel pair to each client. It holds no device. Its manifest row carries `system = ["create-channel", "set-wallclock"]`.
- **Clients** hold a socket control endpoint and the stream channels for their own sockets. A socket belongs to the kernel-stamped AID that opened it; no other AID may read, write, inspect or close it (`STATUS_DENIED`). This is [ADR-025](025-principal-as-aid.md) applied: ownership is the stamped identity, not a token the client presents.

### 2. The NIC seam: control on ep 20, frames in a channel pair

`cambios-net-proto` is the contract: `#![no_std]`, no dependencies, MPL-2.0, host-testable, the shape of `cambios-blk-proto`. Both seam and socket control live in it so one crate is the contract for the whole path.

**Endpoints.** `NIC_ENDPOINT = 20` (driver, unchanged). The stack registers `SEAM_ENDPOINT = 36` first (driver → stack doorbells and replies land here), then `UDP_ENDPOINT = 21` (compat), then `TCP_ENDPOINT = 34` (socket control). The test client takes 35.

**ep 20 commands** (driver `recv_verified`; the stack is a Principal like any other):

| cmd | request | reply |
|---|---|---|
| `GET_MAC = 3` | `[cmd]` | `[status][mac:6]` |
| `GET_STATUS = 4` | `[cmd]` | unchanged |
| `OPEN_SEAM = 5` | `[cmd][tx_chan:8][rx_chan:8]` | `[status]`; a second while one is open → `BUSY` |
| `CLOSE_SEAM = 6` | `[cmd]` | `[status]` |
| `DOORBELL_TX = 7` | `[cmd]` | none ("TX ring went non-empty") |

Driver → stack on ep 36: `DOORBELL_RX = 7`, none back. `SEND_PACKET = 1` and `RECV_PACKET = 2` are removed, not kept beside the ring.

**Two unidirectional channels, not one bidirectional**, so the MMU enforces who writes what: the TX channel (stack `Producer`, driver reads) and the RX channel (stack `Consumer`, driver writes). Each side publishes its own indices in the page it owns, so a consumer never needs write access to the channel it reads.

**Hand-off** copies the compositor precedent ([ADR-014](014-compositor-scanout-driver-protocol.md)): the stack asks `GET_MAC`, reads the driver's AID off the stamped reply, creates both channels with that AID as peer, sends `OPEN_SEAM`, and the driver attaches and validates the control pages. Exactly one seam per driver; the driver remembers the stack's AID and answers a different AID's doorbells with `DENIED`. Either side's exit is survivable by the other (§ 9).

### 3. Socket control on ep 34, dual-stack from the first byte

Every address on the wire is `[family:1][addr:16]` (family 4 or 6; an IPv4 address occupies the first four bytes, the rest zero). There is no IPv4-only message shape to migrate away from later.

| cmd | request | reply |
|---|---|---|
| `CONNECT = 1` | `[cmd][family:1][addr:16][port:2]` | `[status][sock:4][tx_chan:8][rx_chan:8]`; `OK` means SYN sent, poll `STATUS` |
| `LISTEN = 2` | `[cmd][port:2]` | `[status][listener:4]` |
| `ACCEPT = 3` | `[cmd][listener:4]` | `[status][sock:4][tx_chan:8][rx_chan:8][family:1][peer_addr:16][peer_port:2]` or `NO_DATA` |
| `CLOSE = 4` | `[cmd][sock:4]` | `[status]` (also closes a listener id) |
| `STATUS = 5` | `[cmd][sock:4]` | `[status][state:1][rx_avail:4][tx_free:4]` |
| `DOORBELL = 6` | `[cmd][sock:4]` | none; "I wrote to my TX ring" |
| `GET_CONFIG = 7` | `[cmd][family:1]` | `[status][family:1][addr:16][prefix_len:1][gw:16][mac:6]` |

Stack → client: `DATA_READY = 6` `[cmd][sock:4]` to the client's reply endpoint, coalesced (empty → non-empty of the client's RX ring, and every state change). `state` is the RFC 4022 `tcpConnectionState` number (Closed = 1 … TimeWait = 11; 0 is never a state, so a zeroed byte fails decode). RFC 9293 names the states and assigns no numbers; this is not to be "corrected" back to 9293. Status bytes shared by every endpoint: `OK=0, ERROR=1, NO_DATA=2, NO_DEVICE=3, BUSY=4, DENIED=5, FULL=6, BAD_STATE=7`.

Per-socket stream channels are byte rings in the same two-channel shape (client TX = stack `Consumer`, client RX = stack `Producer`). The ep 21 UDP protocol is kept verbatim, including its IPv4-only layouts, as a compatibility surface; it gains nothing and loses nothing.

### 4. The ring protocol (`libchan`), and what a lie costs

One crate for every channel consumer, `#![no_std]`, MPL-2.0, host-tested and fuzzed; the compositor's hand-rolled handshake is the precedent it generalises and the queued consumers (ccid extended APDUs, fs-service file content, the key-store attestation certificate) are the second-consumer evidence the sawtooth check asks for.

A channel is one control page then slots (frame ring, `slot_size = 2048`, `len:2` + payload) or then bytes (byte ring, `slot_size = 0`). Control page: `magic:8 = "CMBCHAN1"`, `slot_size:4`, `slot_count:4` (power of two), `head:4` (this side produces), `peer_tail:4` (this side consumes the other channel), `drops:4`. Indices are free-running `u32`, masked, compared with wrapping arithmetic.

**Every value read from the other side's page is hostile input.** Each is loaded once into a local, validated there, and never re-read for the same decision. A frame slot is copied out, then its copy is validated. No `&[u8]` or `&mut [u8]` is ever formed over a mapping; every access is a volatile byte operation through a raw pointer inside the one `unsafe` module, `libchan::raw`, whose constructors are crate-private and whose only reachable entry points are the one-shot create and attach that the kernel's generational channel ids make one-shot structurally.

**A protocol violation is counted and has a consequence.** A consumer that sees the peer's head run more than `slot_count` ahead resyncs its tail to the peer's head (drops the untrusted span, counts one). A producer that sees the peer's tail claim more consumed than produced treats the ring as full (counts one). At `PEER_VIOLATION_LIMIT = 8` (TUNING) every ring operation returns `PeerUntrusted`, the count freezes, and the holder closes the link with a reason that makes the kernel emit `chan.peer_violation` before `chan.closed` ([ADR-007](007-capability-revocation-and-telemetry.md) § Divergence 8). A lying peer loses its own frames, never ours, and costs at most eight bounded checks.

### 5. The engine: a clean-room pure core, `cambios-netcore`

#### 5.1 Shape

The engine is split exactly as BuddyAllocator is: a pure, host-testable, proof-targeted core with no I/O, and a thin shell (`user/net-stack`) that owns the effects. This split is why a verified TCP is reachable here and it is not negotiable inside the implementation.

`cambios-netcore` is a top-level crate, AGPL-3.0-or-later, `#![no_std]`, `#![forbid(unsafe_code)]`, no `alloc`, no dependencies outside the workspace. One type, one entry point:

```rust
pub struct Engine<const SOCKETS: usize, const LISTENERS: usize> { /* all state */ }

pub enum Event<'a> {
    Frame(&'a [u8]),      // one Ethernet frame from the seam, length asserted by the shell
    Tick(Instant),        // time advanced; fire whatever is due
    Control(Control),     // CONNECT / LISTEN / ACCEPT / SEND / RECV / CLOSE, owner-stamped
}

pub enum Action {
    Emit { frame_len: u16 },                     // shell copies `engine.tx_frame()` to a TX slot
    Notify { socket: SocketId, what: Notify },  // DATA_READY / CONNECTED / CLOSED / ERROR
    Reply { to: Principal, msg: ControlReply }, // the ep 34 reply
    Arm(Instant),                                // earliest deadline; the shell sleeps no longer
}

impl<...> Engine<...> {
    pub fn step(&mut self, now: Instant, ev: Event<'_>) -> Result<Actions<'_>, EngineError>;
}
```

`step` is total: every input, including hostile, yields `Ok(actions)` or a typed `EngineError`; it never panics and never loops unboundedly (every loop is over a fixed-size table or a length-asserted slice). `Actions` is a bounded iterator over an internal array (`MAX_ACTIONS_PER_STEP`, ARCHITECTURAL). Timers are deadlines stored in the socket; there is no heap and no timer wheel. `Instant` is opaque milliseconds; the shell derives it from the 100 Hz tick.

The shell is `#![deny(unsafe_code)]`, built on `service_main!` with `endpoints: [36, 21, 34]`. Its loop drains the three endpoints with `try_recv_msg`, feeds each RX slot and then a `Tick` to `step`, applies the actions (TX slots, client rings, notifies, replies), rings `DOORBELL_TX` if TX went non-empty, and yields; the tick is its sleep, bounded above by the last `Arm`.

#### 5.2 The core

Ethernet II; ARP (RFC 826; bounded cache; a reply updates an entry only if we asked, PR #9 B-5); IPv4 (RFC 791 / 1122; DF set on TCP; fragments dropped, § 5.3); ICMPv4 echo; UDP (RFC 768; v4 zero checksum accepted, B-11); DHCPv4 client (RFC 2131; offers and acks accepted only for the active transaction and interface, B-16); TCP as follows. IPv6 is present as types (`IpAddr { V4, V6 }`, 16-byte storage, dual-stack socket table) and as the wire format; no IPv6 protocol behaviour in the core.

TCP (RFC 9293 as base text):

- Connection state machine per § 3.3.2 as an exhaustive `match` over `(TcpState, flags)`; every transition is in one table (`TRANSITIONS`) the proofs read. States numbered per RFC 4022.
- Segment acceptance per § 3.10.7.4 over wrapping `u32`, with RFC 5961 § 3.2 (RST exact-match or challenge ACK), § 4 (SYN in a synchronised state → challenge ACK) and § 5 (ACK window) on top; challenge ACKs rate-limited per socket (B-13).
- Options: MSS sent and honoured (1460 on Ethernet); Window Scale, Timestamps and SACK-permitted parsed and ignored (16 KiB buffers need no scaling; SACK is first in § 5.3).
- Retransmission per RFC 6298 (SRTT / RTTVAR; RTO min 200 ms, max 60 s, backoff ×2, bounded retries → `Timeout`). The retransmit queue is the TX buffer with an `snd_una` pointer; nothing is copied twice.
- Congestion control: RFC 5681 Reno (slow start, congestion avoidance, fast retransmit on three duplicate ACKs, fast recovery). `CongestionControl` is an enum from day one so CUBIC (B-14) is one more arm.
- Out-of-order receive: at most `MAX_OOO_SEGMENTS` held per socket; beyond that, drop and let the sender retransmit. The in-order prefix goes to the byte ring.
- Close: FIN / ACK, simultaneous close, TIME_WAIT = 2 × MSL with `MSL = 30 s` as a constant (a wrong number here is a correctness bug and a constant can be verified; smoltcp's fixed 10 s is one of the differences the oracle allow-list records). Tuple reuse in TIME_WAIT is `BUSY`, never silent.
- Half-open budget per listener (B-12): SYNs beyond it are dropped, not queued; no SYN cookies in the core. Absent listener and unauthorised listen both RST with the same timing (B-17).

#### 5.3 Specified work after the core

Each of these is named here so none is forgotten and none blocks the first networked boot. Each is cut from this ADR as its own section or record, with PR #9 as the specification source where it has one: IPv6 behaviour (ND, SLAAC, DAD, ICMPv6, fragmentation; B-5, B-10, AT-net-020), DNS (B-15), DHCPv6 (B-16), SACK, CUBIC (B-14), IPv4 fragment reassembly (B-10), TLS, mDNS. **Revisit when:** the core is green and the collaborator has answered what NAOMS needs on day one; that answer orders this list and may move an item into the core.

### 6. Verification: proof targets, the oracle, and the first peer

#### 6.1 Proof targets

`cambios-netcore` ships bounded model-checking harnesses in-tree, run by the existing proofs CI tier (x86_64 CI is authoritative; local aarch64 Kani has false-greened before, see CLAIMS.md). Each is a row in [verification/CLAIMS.md](../../verification/CLAIMS.md) citing the PR #9 invariant it discharges:

| id | property | discharges |
|---|---|---|
| P1 | For all `(seg.seq, seg.len, rcv.nxt, rcv.wnd)`, `acceptable()` agrees with the RFC 9293 § 3.10.7.4 table under wrapping arithmetic | INV-net-007 |
| P2 | For all `(state, flags)`, `next_state()` returns a state in `TRANSITIONS[state]`; no transition leaves the RFC 4022 graph | INV-net-007 |
| P3 | An RST with `seg.seq != rcv.nxt` never changes state and yields exactly one challenge ACK or nothing (rate limit) | INV-net-009, RFC 5961 § 3.2 |
| P4 | A SYN in any synchronised state never resets; it yields a challenge ACK | INV-net-009, RFC 5961 § 4 |
| P5 | The delivered byte sequence is a gap-free, duplicate-free prefix of the sender's sequence space for any arrival order of ≤ `MAX_OOO_SEGMENTS` | B-12 |
| P6 | `step(arbitrary bytes ≤ 1514)` returns without panic and without out-of-bounds access, in every state | INV-net-013, B-6, B-9 |
| P7 | Socket, listener, half-open, out-of-order and ARP tables never exceed their bound | INV-net-011, INV-net-012 |
| P8 | The send path never emits sequence-space data beyond `min(snd_wnd, cwnd)` | INV-net-008 |

Harnesses are bounded (unwind limits named per harness). Full functional correctness of the stream (P5 unbounded) is the Verus target once that pivot lands (CLAIMS C-11 / C-12); until then it is a differential property plus the bounded harness. Performance properties (RTO convergence, cwnd growth) are measured, not proved. A harness is never weakened (bound lowered, assertion removed) without a dated line in the decision log saying why.

#### 6.2 The oracle

smoltcp (latest, 0BSD) is a dev-dependency of the engine's test harness and nothing else; it is reachable from no `*-unknown-none` build. `tests/differential.rs` feeds the same trace (frames + ticks) to both engines and compares emitted segments field by field modulo an allow list (ISN, timestamp option, window rounding, option order, TIME_WAIT length). Traces come from PR #9's `NET-V-*` vectors, generated handshakes and transfers with loss injection, and pcaps from the host-peer acceptance runs. A disagreement is a failing test until it is classified in `tests/differential/allowed.toml`: our bug, the oracle's bug (smoltcp accepting an in-window RST anywhere, against RFC 5961 § 3.2, is the first entry), or an allowed difference.

#### 6.3 The first peer

The engine's first proof of life is two `Engine` instances wired back to back on the host: `CONNECT` / `LISTEN` / `ACCEPT`, 1 MiB each way under 5% random frame loss and reordering of depth 3, close both ways, received bytes equal sent bytes, both sockets end `Closed`. This is the NAOMS-on-CambiOS case and it goes green before anything with a foreign stack. The host-peer runs (a TCP server the host connects to, a TCP client the host receives from, under QEMU user networking, whose own TCP is libslirp's) are the external-interoperability checks. Linux and middlebox behaviour is a named later surface: **Revisit when:** a real peer disagrees with the RFC on a captured trace, or the x86_64 dev box's first LAN run fails to connect to a host that QEMU's SLIRP accepted.

### 7. Requirements format and the merged contract

The requirements format is PR #9's: a normative **behaviour** (`B-n`) names its RFC source; an **invariant** (`INV-net-nnn`) names its behaviours; an **acceptance test** (`AT-net-nnn`) names its invariants; a language-neutral **vector** (`NET-V-nnn`) names the tests it exercises. This ADR adopts the ids and the chain; CLAIMS.md rows cite the invariant they discharge; vectors live in a `vectors/` directory beside the engine's tests and are replayed by the differential harness.

Adopted now, with where each binds:

| id | requirement | binds to |
|---|---|---|
| INV-net-011 / 012 | every table stays within its named capacity; exhausting one returns `ResourceLimit` or drops only the protected packet, without altering another Principal's state | `MAX_SOCKETS_PER_PRINCIPAL` and the other § 8 bounds; `FULL` to the exhausted client only; P7 |
| INV-net-013 | no panic, out-of-bounds, unchecked wrap or unbounded work on any input | `step` totality (P6); `libchan` single-fetch rule; parsers over length-asserted slices |
| INV-net-017 | no packet payload bytes in any default diagnostic output | the stack and both drivers |
| INV-net-009 / B-13 | reset and SYN defence per RFC 5961 with a rate limit | P3, P4, `CHALLENGE_ACK_PER_SEC` |
| B-9 | receive-before-dispatch: length checked before any parser | the shell asserts frame length; the engine's parsers take asserted slices |
| B-12 | half-open budget per listener, drop beyond it | `MAX_HALF_OPEN_PER_LISTENER` |
| B-17 | absent and unauthorised listeners are indistinguishable on the wire | one RST path, same timing class |
| B-5 | ARP / ND data is unauthenticated; update only entries we asked for | ARP cache policy; ND in § 5.3 |
| B-11 | IPv4 zero-checksum UDP accepted; IPv6 rejected unless configured | UDP receive |
| B-16 | DHCP offers and acks accepted only for the active interface, family and transaction | DHCPv4 client; DHCPv6 in § 5.3 |

The complete crosswalk from every PR #9 id to the message, ring field or engine function it binds to, marked core, later or library-internal, is `docs/dev-notes/net-crosswalk-pr9.md`; it is the document the two drafts merge in and is reviewed line by line by the PR author. Where it reveals a requirement this ADR cannot satisfy at the stated boundary, the ADR body is amended and the prior wording kept in a Divergence appendix.

### 8. Bounds

Every numeric bound carries a Convention 8 tag and a row in [ASSUMPTIONS.md](../ASSUMPTIONS.md); the v1 workload they are sized from is the agent sandbox ([ADR-038](038-sandboxed-guest-processes.md)): a package install or git fetch holds four to eight connections, plus a shell, plus audit export; call it 16 live, 25%-rule → 64.

| constant | value | category | one-line why |
|---|---|---|---|
| `MAX_SOCKETS` | 64 | SCAFFOLDING | 16 live × 4; ≈ 2 MiB of socket buffers in a 4 MiB heap |
| `MAX_SOCKETS_PER_PRINCIPAL` | 16 | SCAFFOLDING | 25% of the table; heaviest single tool run ≈ 8 |
| `MAX_LISTENERS` | 16 | SCAFFOLDING | 4 live × 4 |
| `MAX_HALF_OPEN_PER_LISTENER` | 8 | TUNING | a SYN flood costs a fixed amount; the per-listener cap is the first wall, the table the second |
| `MAX_OOO_SEGMENTS` | 4 | TUNING | a 16 KiB window at MSS 1460 is ≈ 11 segments; 4 covers one loss with a few in flight |
| `CHALLENGE_ACK_PER_SEC` | 1 | TUNING | RFC 5961 § 7 |
| `MAX_ARP_ENTRIES` | 32 | TUNING | one segment, a handful of peers and a gateway |
| `MAX_ACTIONS_PER_STEP` | 8 | ARCHITECTURAL | derived from the per-socket action set |
| `SEAM_SLOTS` | 512 | TUNING | 1 ms of 1 GbE line rate is 81 frames, 25%-rule → 324, next power of two |
| `STREAM_PAGES` | 4 | TUNING | 16 KiB per direction matches the socket buffer; a stream channel is 1 + 4 pages |
| `PEER_VIOLATION_LIMIT` | 8 | TUNING | enough to distinguish a bug from an attack; a hostile peer costs eight bounded checks |
| `MSL` | 30 s | TUNING | matches Linux; a constant so TIME_WAIT is verifiable |
| `DHCP_RETRIES` | 8 | TUNING | ≈ 8 s before static fallback so a QEMU without DHCP still boots |

PR #9's values (1024 sockets × 256 KiB buffers) describe a different machine. The pass that derives each of them for this platform is done jointly with the PR author; several of the bounds above did not exist in the maintainer's design until PR #9 named them.

### 9. Survivability

A client's exit must not kill the stack, a driver's exit must not kill the stack, and the stack's exit must not kill a driver. The stack holds one RW ring per client and per driver, so the "kill-via-fault" outcome ADR-007 accepted for catastrophic-state pairs does not hold here, and a `channel_info` check cannot close the check-then-write race. The resolution is in [ADR-007](007-capability-revocation-and-telemetry.md) § Divergence 8: every process owns one zeroed scratch frame allocated at creation, and on revoke a survivor's RW mapping is remapped to it; the RO case keeps the shared zero tombstone. Cooperating userspace still observes `Revoked` via `SYS_CHANNEL_INFO` and drops the dead ring; the scratch frame only makes the window between peer death and that observation harmless. This is the one kernel change the network work needs, and it lands before the stack shell does.

### 10. The enforcement hook

`CONNECT` and `LISTEN` arrive as `write` syscalls the policy service already sees per Principal ([ADR-006](006-policy-service.md)). When the egress-policy record lands, the stack adds a query on those two commands and **denies on no answer**. The shape is named now so no one adds a fail-open default later. Nothing beyond socket ownership is enforced by this ADR.

### 11. Supply chain

The image ships zero third-party crates in the network path: `cambios-netcore` and `user/net-stack` depend only on workspace crates. The oracle is host-only. If smoltcp ever appears in a kernel-target build graph the expected failure is a duplicate `panic_impl`. The cargo-vet / vendoring decision this project has pending is not forced by this work; **Revisit when:** the first third-party crate ships inside an image.

## Architecture

```
                 ep 20 (control, recv_verified)              ep 34 (socket control, recv_verified)
 +-----------+ <------------------------------- +-----------+ <------------------------------- +----------+
 | NIC driver|  OPEN_SEAM / CLOSE_SEAM /        | net-stack |  CONNECT / LISTEN / ACCEPT /     |  client  |
 | virtio-net|  DOORBELL_TX / GET_MAC           |           |  CLOSE / STATUS / DOORBELL /     | (libnet) |
 | i219-net  | -------------------------------> |  shell    |  GET_CONFIG                      |          |
 |           |  ep 36: DOORBELL_RX              |  +------+ | -------------------------------> |          |
 |  DMA/MMIO |                                  |  |engine| |  reply ep: DATA_READY            |          |
 |           | ==== TX ring (stack RW, drv RO)  |  |step()| | ==== client RX (stack RW, cl RO) |          |
 |           | ==== RX ring (drv RW, stack RO)  |  +------+ | ==== client TX (cl RW, stack RO) |          |
 +-----------+   two ADR-005 channels           +-----------+   two ADR-005 channels per socket +----------+
                 (libchan frame rings)            ep 21: UDP compat (verbatim)  (libchan byte rings)
```

Crates: `cambios-net-proto` (wire format), `user/libchan` (rings; the one `unsafe` module), `cambios-netcore` (pure engine; `forbid(unsafe_code)`), `user/net-stack` (shell), `user/libnet` (client API: `Socket::connect / Listener::bind / accept / read / write / state / close`), `user/tcp-echo` (on-demand test client, ep 35). Host-only: the engine's differential and back-to-back harnesses, with smoltcp as a dev-dependency.

## Threat Model Impact

- **A hostile client** can lie in its ring, flood `CONNECT`, or hold sockets. The ring protocol bounds the first at eight counted violations and an audited close; the per-Principal quota bounds the second and third. It cannot touch another Principal's socket (kernel-stamped ownership), and it cannot see another client's bytes (channels are pairwise; dead rings sink into a per-process scratch frame, never a shared writable page).
- **A hostile or faulty NIC driver** can lie in its ring or feed arbitrary frames. The ring protocol treats it exactly as a client; the engine's totality (P6) means an arbitrary frame costs a bounded amount of work and cannot crash the stack. The driver's own hostile-device posture toward the NIC is unchanged.
- **A hostile peer on the wire** gets RFC 5961 treatment (P3, P4), a half-open budget per listener, a bounded out-of-order buffer, and an ARP cache that only honours answers to its own questions. Absent and unauthorised listeners are indistinguishable (B-17).
- **The stack as egress boundary** of the agent sandbox contains no third-party code and has a fail-closed hook for egress policy. What it does not yet do is decide policy; that is the later record.
- **What this does not protect against:** a compromised stack process sees every client's plaintext. TLS is above this layer and is specified work. Confidentiality on the wire is not a property of this ADR.

## Verification Stance

The pure core is the verification target and the whole design exists to make it one: no I/O, no allocation, no unsafe, fixed tables, exhaustive matches, wrapping arithmetic made explicit, a transition table the proofs read directly. P1 to P8 are bounded Kani harnesses in CI from the first engine commit; the unbounded stream property is the Verus target. The ring library is fuzzed (`fuzz_chan_ring`) and its one `unsafe` module has four stated obligations; the engine has its own fuzz target (`fuzz_engine_step`). The shell is thin enough that its correctness argument is "it copies bytes between things the proofs cover". The wire contract is host-tested round-trip. Every acceptance condition in this area is executable: a test suite, a fuzz run, a proof harness, the build gate, or a QEMU run with required serial lines and a scripted host peer, each judged by exit code and never by a person reading output. What is not verified: the drivers' DMA paths (unchanged by this work), timing behaviour (measured), and interoperability with implementations that disagree with the RFC (recorded case by case in the oracle's allow list).

## Why Not Other Options

- **smoltcp as the shipped engine.** Mature, 0BSD, `no_std`, what Redox runs. Rejected for the image because its structure (sockets, buffers and the interface in one mutable graph) cannot be made a pure core without rewriting it, so the proofs would stop at the boundary of code we did not write; because the egress boundary of the sandbox would then be third-party code; and because shipping it first and replacing it later is the tear-down the sawtooth check exists to catch. Kept as the oracle, which is a permanent role.
- **Fragment frames over the 256-byte control path.** Scaffolding; caps throughput at the control-path copy rate; all three services touched anyway.
- **Fold the driver into the stack.** Puts DMA and protocol state in one process, against the isolation principle and against the "driver knows nothing about IP" split that lets the x86_64 dev box's I219 and QEMU's virtio-net share one stack unchanged.
- **One bidirectional channel per seam.** Loses the MMU's enforcement of who writes what; a lying consumer could then corrupt the producer's indices.
- **A kernel-resident stack.** Adds a protocol engine to the TCB and to the kernel's proof burden; everything this ADR wants from verification is easier in a userspace pure core.
- **A POSIX sockets API as the client surface.** The sandbox's libc port will want one, built over this contract ([ADR-038](038-sandboxed-guest-processes.md)); making it the primary surface would bind the stack to a foreign API shape before the native one exists.
- **A `spec/` tree beside `docs/adr/`.** PR #9's content belongs in this record, the claims ledger and `vectors/`; a parallel tree would be a second place architecture lives. The PR's provenance apparatus (Pathways, Aqua) is a separate decision and is not adopted or rejected here.

## Migration Path

In order, each tri-arch green before the next; the kernel step is on main, the rest in the `net-stack` worktree:

1. **Wire contract** (`cambios-net-proto`): landed. Dual-stack address widening is a follow-up edit before any client exists.
2. **Ring library** (`libchan` + fuzz target): landed, including one-shot accessors and the violation limit.
3. **Kernel: scratch frame + `chan.peer_violation`** (ADR-007 § Divergence 8): on main, full review protocol; blocks the stack shell, not the engine.
4. **Drivers** gain the seam, lose `SEND_PACKET` / `RECV_PACKET`.
5. **Engine** (`cambios-netcore`): host tests, back-to-back, differential harness, P1 to P8, CLAIMS rows, ASSUMPTIONS rows. May land before step 3.
6. **Stack shell** + manifest (udp-stack removed); waits on step 3.
7. **Clients** (`libnet`, `tcp-echo`).
8. **Tooling**: runner flags, Makefile targets, the published packet, STATUS.
9. **Specified work after the core** (§ 5.3), each as its own section or record, ordered by the collaborator's day-one needs.

## Open Questions / Deferrals

- **Which of § 5.3 moves into the core.** **Revisit when:** the PR author answers what NAOMS needs from the stack on day one (TCP only or UDP; IPv6 required or desired; multicast; port ranges; connections per node).
- **Egress policy vocabulary** (which Principal may reach which host or port). § 10 names the hook. **Revisit when:** the first sandbox guest needs network access, or the policy service grows a per-service rule table.
- **Zero-copy from the device DMA buffer into the ring.** One copy per frame per side today. **Revisit when:** a measured RX `drops` counter reads > 0 at 1 GbE on the x86_64 dev box, or the sandbox's vsock path shares the ring code.
- **Compositor and scanout migration onto `libchan`.** The precedent generalised; the migration is its own app-tier work. **Revisit when:** `libchan` has shipped in the image and the compositor next touches its handshake.
- **PR #9's provenance apparatus (Pathways, Aqua sidecars).** Not process this project has adopted; Aqua's identity model (wallet addresses) would be a second identity root beside Ed25519 Principals. **Revisit when:** the collaboration proposes it as its own record with that question answered.
- **The NTP server address is hard-coded** in the stack (inherited from udp-stack). **Revisit when:** `SET_CONFIG` gains a field for it or DNS lands and a hostname becomes possible.

## Cross-References

- [ADR-005](005-ipc-primitives-control-and-bulk.md) § Decision 2 (data channels), § Notification (doorbells as control IPC), § Divergence entries on roles and vaddr assignment.
- [ADR-007](007-capability-revocation-and-telemetry.md) § Divergence 7 (RO tombstone) and 8 (per-process scratch frame; `chan.peer_violation`).
- [ADR-014](014-compositor-scanout-driver-protocol.md) (channel hand-off precedent).
- [ADR-038](038-sandboxed-guest-processes.md) (the v1 workload; the stack as egress boundary).
- PR #9, `spec/crates/net.md` + `spec/claims/net.md` (the requirements source; ids cited throughout).
- RFC 9293, 791, 1122, 826, 768, 2131, 5961, 6298, 5681, 4022; RFC 8200, 4861, 4862, 4443 for the IPv6 work.
- Netsem (Bishop et al., "Rigorous specification and conformance testing techniques for network protocols, as applied to TCP, UDP, and Sockets") as the one prior rigorous TCP specification effort; read for what it chose to model.
