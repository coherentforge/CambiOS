<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 CambiOS contributors -->

# CambiOS network stack

Labels: 🔴 ASSUMPTION · 🟠 ESTIMATE · 🟡 UNVERIFIED. Anything unlabelled is a
standard requirement or a fact read from CambiOS source, with its source named.

## 1. Purpose and standalone use

The network stack is the isolated user-space boundary that gives CambiOS
processes interoperable IPv4 and IPv6 host networking. It owns link-layer
address resolution, IP input and output, ICMP, UDP, TCP, DNS stub resolution,
and DHCP client behavior. A client receives only the network authority granted
to its Principal. The stack does not forward packets for other hosts and does
not implement a NIC, Wi-Fi supplicant, cellular modem, TLS, or an application
protocol.

The protocol service MUST remain independent of CPU architecture and device
driver. A link provider supplies bounded Ethernet frames and link properties;
the stack supplies packet services to capability-authorized clients. A process
crash or malformed packet in this service MUST NOT corrupt kernel state or
another process. The normative behavior comes from the RFC profile below. The
OpenBSD, smoltcp, FreeBSD, Linux, and lwIP implementations are comparison
evidence only; none is a source of implementation code or normative behavior.

For users, the service contract provides dual-stack sockets, bounded DNS and
address configuration, and capability-controlled access without requiring
apps to embed a protocol stack. For server workloads, it provides bounded
listeners, per-Principal resource accounting, predictable error reporting,
and an isolated failure boundary. These are target benefits, not claims of
current CambiOS support or measured throughput.

CambiOS currently has a user-space ARP/IPv4/UDP/NTP service and a virtio-net
driver on the target configurations recorded in `STATUS.md`. TCP, general
IPv6, DNS, and DHCP are not current CambiOS capabilities. This specification
does not claim that CambiOS boots on every Mac, phone, or Raspberry Pi. A
platform claim requires evidence for its boot chain, memory/DMA behavior, and
specific link driver.

Normative profile: RFC 9293 (TCP), RFC 8200 (IPv6), RFC 791 and RFC 1122
(IPv4/host requirements), RFC 826 and RFC 5227 (ARP/address conflict), RFC
4861, RFC 4862, RFC 4443, RFC 6980, and RFC 7112 (IPv6 neighbor discovery,
address configuration, ICMPv6, and fragment handling), RFC 768 (UDP), RFC 6298
(TCP retransmission timer), RFC 5961 (TCP blind in-window attack mitigations), and
RFC 9438 (CUBIC congestion control). DNS follows RFC 1035, RFC 7766, RFC 6891,
and current updates. DHCPv4 follows RFC 2131; DHCPv6 follows RFC 8415. Current
RFC updates and errata are part of this contract. The cited editions are the
initial baseline and MUST be rechecked at specification approval.

The behavior ledger is the evidence index for the invariants and acceptance
tests below:

**Attribution path.** Each normative behavior names its primary source in a
`B-` row; each invariant names its `B-` evidence in `why:`; each acceptance
test cites its invariants; each language-neutral vector names its source and
the AT/INV ids it exercises. This records the path from evidence to observable
behavior. RFC text is protocol authority, CambiOS source/docs establish current
OS facts, and 🟠 estimates or 🔴 assumptions remain proposals for review. A
contributor or drafting tool is not evidence for a protocol claim, and
attribution grants no network authority.

**Artifact provenance and authorship.** The Pathways additions are
`Collaboration.Attestation.RecordPathwayRun@v1`,
`Pathways.Provenance.BindCommitToPathwayRun@v1`, and
`Collaboration.Meta.EmbedTechniqueProvenance@v1`. A release-ready spec change
records the producing pathway, source-script hash, exact invocation and
outcome, authenticated author identity, and every produced asset; the
canonical run is attached to the Git commit by a `Pathway-Run:` trailer and
Git note, then verified against the commit tree hash and run content hash.
The self-describing technique metadata names its version, co-originators,
authored enhancements, lineage, and defining pathways.
Where Aqua attribution is used, the signed Aqua sidecar binds the artifact
hash, signer identity, and authorship/lineage metadata. These records describe
who produced and attested the artifact; they do not change the RFC evidence
that determines protocol behavior. The accompanying `spec/provenance/net.yaml`
states what this review draft has and has not attested.

- **B-1 Wire validity.** Frames and packets accepted for delivery have valid
  framing, protocol lengths, checksums where required, and legal field
  combinations. Source: the IPv4, IPv6, UDP, TCP, Ethernet, and ARP standards
  above.
- **B-2 Host delivery.** A packet is delivered only to a local address and a
  bound endpoint, unless a standards-required control response is generated.
  Source: RFC 1122, RFC 8200, RFC 9293.
- **B-3 TCP state.** TCP sequence, acknowledgement, window, options, close, and
  reset behavior follows RFC 9293 and RFC 5961. Source: RFC 9293 §§3–4, RFC
  5961 §§3–5.
- **B-4 Timers and congestion.** Retransmission and congestion behavior follows
  RFC 6298 and RFC 9438. Source: those RFCs.
- **B-5 Neighbor trust.** ARP and Neighbor Discovery data are unauthenticated
  link input and never establish process identity or authorization. Source:
  RFC 826, RFC 4861, CambiOS Principal and capability model.
- **B-6 Bounded work.** Every packet-driven loop, queue, table, timer set, and
  reassembly operation has an explicit finite bound. Source: the configured
  bounds in §2 and the CambiOS isolated-service boundary.
- **B-7 Authority.** Bind, listen, connect, send, receive, and raw-packet
  operations are capability-checked for the calling Principal. Source:
  CambiOS capability-checked IPC and Principal model.
- **B-8 Configuration.** Dynamic address and name configuration is explicit,
  bounded, and subordinate to static operator configuration. Source: RFC
  2131, RFC 8415, RFC 1035 and CambiOS deployment policy.
Standalone use: a CambiOS client that holds the relevant network capability
may bind a local address, open a UDP endpoint, or create/listen on a TCP
endpoint. Network identity is not a peer's IP or MAC address. TCP provides no
confidentiality or peer authentication; applications that need those
properties use a separately specified authenticated protocol.

## 2. Types and invariants

Public types, one per line.

- `NetCapability`: closed authority set for interface, address-family,
  protocol, local/remote address, port range, and operation.
- `InterfaceId`: opaque id for one configured link.
- `IpRoute`: destination prefix, next hop, interface, and metric.
- `LinkProperties`: MTU, link address, and up/down state.
- `MacAddress`, `Ipv4Address`, `Ipv6Address`, `IpPrefix`, `SocketAddress`.
- `IpAddress`, CambiOS `Principal`, `SocketEvent`.
- `Frame`, `Ipv4Packet`, `Ipv6Packet`, `UdpDatagram`, `TcpSegment`.
- `TcpState`: `Closed`, `Listen`, `SynSent`, `SynReceived`, `Established`,
  `FinWait1`, `FinWait2`, `CloseWait`, `Closing`, `LastAck`, `TimeWait`.
- `SlaacState`: `Absent`, `Tentative`, `Preferred`, `Deprecated`, `Duplicate`.
- `SocketId`, `DnsRequestId`, `DhcpLease`, `NeighborEntry`.
- `NetError`: closed enum `Denied`, `NoRoute`, `NoAddress`, `AddressInUse`,
  `NoListener`, `WouldBlock`, `TimedOut`, `Closed`, `Malformed`,
  `Unsupported`, `ResourceLimit`, `NetworkDown`.
- `NetStats`: bounded counters for malformed input, checksum failure,
  resource exhaustion, policy denial, retransmission, timeout, and drop reason.
- `NetLimits`: the finite capacities in the named-bounds table. A deployment
  selects one complete profile; unspecified or zero limits are rejected.
- `LinkPort`, `Clock`, `NetworkPolicy`: injected effect boundaries; the
  protocol state machine receives explicit time and packet data.
- Test surfaces: `ScriptedLink`, `ScriptedClock`, `ScriptedPolicy`,
  `PacketTrace`, `StackFixture`.

Named bounds. Values marked 🟠 are proposed defaults for review; changing a
value changes this specification and its corresponding acceptance cases.

| Name | Value | Source | Why |
|---|---:|---|---|
| `ETHERNET_MTU_DEFAULT` | 1500 bytes | Ethernet II profile; IPv6 minimum MTU RFC 8200 §5 | Common interoperable Ethernet payload size |
| `MAX_LINK_MTU` | 9000 bytes | 🟠 CambiOS deployment estimate | Jumbo frames remain bounded |
| `MAX_INTERFACES` | 16 | 🟠 CambiOS deployment estimate | Bounds interface state |
| `MAX_ROUTES` | 256 | 🟠 CambiOS deployment estimate | Bounds route lookup state |
| `MAX_NEIGHBORS_PER_INTERFACE` | 256 | 🟠 CambiOS deployment estimate | Bounds ARP/ND cache state |
| `MAX_IPV6_EXTENSION_HEADERS` | 8 | 🟠 CambiOS parser budget | Bounds extension-header traversal |
| `MAX_IPV6_EXTENSION_BYTES` | 2048 bytes | 🟠 CambiOS parser budget | Bounds extension-header parsing |
| `MAX_FRAGMENTS_PER_DATAGRAM` | 64 | 🟠 CambiOS reassembly budget | Bounds fragment bookkeeping |
| `MAX_REASSEMBLY_BYTES_PER_PRINCIPAL` | 4 MiB | 🟠 CambiOS resource estimate | Bounds hostile fragmented input |
| `MAX_TCP_CONNECTIONS` | 1024 | 🟠 general/server profile estimate | Bounds connection state |
| `MAX_TCP_CONNECTIONS_PER_PRINCIPAL` | 128 | 🟠 CambiOS policy estimate | Prevents one principal exhausting service capacity |
| `MAX_HALF_OPEN_CONNECTIONS_PER_INTERFACE` | 256 | 🟠 CambiOS policy estimate | Bounds SYN state |
| `MAX_TCP_BUFFER_BYTES_PER_CONNECTION` | 256 KiB | 🟠 CambiOS resource estimate | Bounds send, receive, and reassembly storage |
| `MAX_TCP_OUT_OF_ORDER_SEGMENTS` | 32 | 🟠 CambiOS reassembly budget | Bounds sparse sequence state |
| `MAX_UDP_QUEUE_BYTES_PER_SOCKET` | 256 KiB | 🟠 CambiOS resource estimate | Bounds datagram queue storage |
| `MAX_PACKET_QUEUE_BYTES_PER_INTERFACE` | 4 MiB | 🟠 CambiOS resource estimate | Bounds link input/output queues |
| `MAX_DNS_TRANSACTIONS` | 128 | 🟠 CambiOS resource estimate | Bounds concurrent resolver state |
| `MAX_DNS_CACHE_ENTRIES` | 256 | 🟠 CambiOS resource estimate | Bounds resolver cache |
| `MAX_DNS_NAME_BYTES` | 255 bytes | RFC 1035 §2.3.4 | DNS wire-name maximum |
| `MAX_DNS_CNAME_HOPS` | 16 | 🟠 CambiOS resolver bound | Bounds alias traversal |
| `MAX_DHCP_LEASES_PER_INTERFACE` | 2 (one per family) | RFC 2131, RFC 8415; 🟠 one lease per family | Bounds client lease state |
| `MAX_CHALLENGE_ACKS_PER_INTERFACE_PER_SECOND` | 100 | 🟠 CambiOS rate-limit estimate | Bounds unauthenticated challenge responses |
| `TCP_RTO_INITIAL_MS` | 1000 ms | RFC 6298 §2 | Initial retransmission timer |
| `TCP_RTO_MIN_MS` | 1000 ms | RFC 6298 §2.4 | Minimum retransmission timeout |
| `TCP_RTO_MAX_MS` | 60000 ms | 🟠 CambiOS finite timer cap | Prevents timer arithmetic overflow; verify interoperability |
| `TCP_LISTEN_BACKLOG_MAX` | 256 | 🟠 CambiOS resource estimate | Bounds pending accepts |

Every invariant is one observable statement. Evidence ids `B-1` to `B-8` are
defined in §1.

- **INV-net-001** A frame delivered by `Stack::input` has a complete link header and a declared length no greater than the interface MTU plus its link header. why: B-1.
- **INV-net-002** An IPv4 packet reaches a transport only when its version, IHL, total length, header checksum, fragmentation fields, and destination are valid under the profile. why: B-1, B-2.
- **INV-net-003** An IPv6 packet reaches a transport only after its payload length, hop limit, extension-header sequence, fragment rules, and destination have been validated under the profile. why: B-1, B-2.
- **INV-net-004** IPv6 extension processing visits at most `MAX_IPV6_EXTENSION_HEADERS` headers and `MAX_IPV6_EXTENSION_BYTES` bytes for one packet. why: B-6.
- **INV-net-005** ARP and Neighbor Discovery entries can affect link delivery only for the interface and address they name, and never grant a process identity or network capability. why: B-5.
- **INV-net-006** A UDP datagram is delivered only when its length and family-specific checksum rules are valid and a permitted endpoint matches its destination. why: B-1, B-2, B-7.
- **INV-net-007** A TCP connection changes state only through an RFC 9293 transition whose segment sequence, acknowledgement, flags, and window satisfy that transition's guard. why: B-3.
- **INV-net-008** A TCP sender transmits no sequence-space data outside both the peer's advertised receive window and its congestion window. why: B-3, B-4.
- **INV-net-009** A TCP segment with an in-window RST or SYN that fails RFC 5961 validation does not close or advance the connection. why: B-3.
- **INV-net-010** TCP retransmission deadlines and congestion-window changes follow RFC 6298 and RFC 9438 within the named finite timer bounds. why: B-4, B-6.
- **INV-net-011** Every connection, half-open connection, queue, neighbor cache, DNS transaction, lease, and reassembly consumes no more than its named `NetLimits` capacity. why: B-6.
- **INV-net-012** Exhausting a configured capacity returns `ResourceLimit` or drops only the packet the capacity protects, without altering an unrelated principal's state. why: B-6, B-7.
- **INV-net-013** No packet bytes, protocol option, address, or timer value causes panic, out-of-bounds access, unchecked integer wrap, or unbounded work at the service boundary. why: B-1, B-6.
- **INV-net-014** A network operation has effect only if `NetworkPolicy` permits that operation for the calling Principal and endpoint tuple. why: B-7.
- **INV-net-015** DNS answers are returned only for an outstanding matching query and are cached no longer than the minimum applicable TTL and configured cache bound. why: B-1, B-8.
- **INV-net-016** DHCP lease changes are accepted only for the requesting interface and transaction and cannot override an operator-pinned address. why: B-8.
- **INV-net-017** A UDP or TCP error is reported to a client without exposing packet payloads in default diagnostic output. why: B-6, B-7.
- **INV-net-018** IPv4 and IPv6 reassembly completes only from non-overlapping fragments for one datagram before its deadline and within the fragment and byte bounds. why: B-1, B-6.
- **INV-net-019** A listening TCP endpoint accepts a connection only when a capability permits that local address and port for the calling Principal. why: B-7.
- **INV-net-020** IPv6 UDP packets carry a valid nonzero UDP checksum except for an exception explicitly allowed by the current IPv6 standards and disabled by default. why: B-1.
- **INV-net-021** An outbound packet selects the matching route with the longest prefix, then lowest metric, then lowest interface id, and is never forwarded as another host's packet. why: B-2, B-6.
- **INV-net-022** An IPv6 address learned from router advertisement is assigned only after Duplicate Address Detection completes without conflict. why: B-8.

The callable surface is the boundary contract. Acceptance tests call only
operations declared here and the test surfaces above.

```surface
enum AddressFamily { Ipv4, Ipv6 }
enum Protocol { Icmp, Udp, Tcp }
enum Operation { Bind, Listen, Connect, Send, Receive, Resolve, Configure }
enum TcpState { Closed, Listen, SynSent, SynReceived, Established, FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait }
enum SlaacState { Absent, Tentative, Preferred, Deprecated, Duplicate }
enum NetError { Denied, NoRoute, NoAddress, AddressInUse, NoListener, WouldBlock, TimedOut, Closed, Malformed, Unsupported, ResourceLimit, NetworkDown }
struct MacAddress([u8; 6])
struct Ipv4Address([u8; 4])
struct Ipv6Address([u8; 16])
enum IpAddress { V4(Ipv4Address), V6(Ipv6Address) }
struct IpPrefix { address: IpAddress, prefix_len: u8 }
struct SocketAddress { address: IpAddress, port: u16 }
struct IpRoute { prefix: IpPrefix, next_hop: Option<IpAddress>, interface: InterfaceId, metric: u32 }
struct Principal { aid: [u8; 32] }
struct InterfaceId(u16)
struct SocketId(u32)
struct DnsRequestId(u32)
struct LinkProperties { mtu: u16, mac: MacAddress, is_up: bool }
struct NetLimits { max_link_mtu: u16, interfaces: u8, routes: u16, neighbors_per_interface: u16, ipv6_extension_headers: u8, ipv6_extension_bytes: u16, fragments_per_datagram: u8, reassembly_bytes_per_principal: u32, tcp_connections: u16, tcp_connections_per_principal: u16, half_open_per_interface: u16, tcp_buffer_per_connection: u32, tcp_out_of_order_segments: u8, udp_queue_per_socket: u32, packet_queue_per_interface: u32, dns_transactions: u16, dns_cache_entries: u16, dns_name_bytes: u16, dns_cname_hops: u8, dhcp_leases_per_interface: u8, challenge_acks_per_interface_per_second: u16, tcp_rto_initial_ms: u32, tcp_rto_min_ms: u32, tcp_rto_max_ms: u32, tcp_listen_backlog: u16 }
struct StackConfig { limits: NetLimits, interfaces: Vec<LinkProperties>, routes: Vec<IpRoute> }
struct Endpoint { local: SocketAddress, remote: Option<SocketAddress>, protocol: Protocol }
struct Frame { bytes: Vec<u8> }
struct PacketEvent { interface: InterfaceId, frame: Frame }
struct Ipv4Packet { source: Ipv4Address, destination: Ipv4Address, protocol: u8, payload: Vec<u8> }
struct Ipv6Packet { source: Ipv6Address, destination: Ipv6Address, next_header: u8, payload: Vec<u8> }
struct TcpSegment { source: SocketAddress, destination: SocketAddress, sequence: u32, acknowledgement: u32, flags: u8, window: u16, payload: Vec<u8> }
struct UdpDatagram { peer: SocketAddress, payload: Vec<u8> }
enum SocketEventKind { Bound, Connected, ConnectionRefused, Readable, Writable, Closed, AddressConfigured, AddressRemoved, DnsComplete }
struct SocketEvent { socket: SocketId, kind: SocketEventKind }
struct StackOutput { frames: Vec<Frame>, events: Vec<SocketEvent> }
struct NetStats { malformed: u64, checksum_failure: u64, resource_limit: u64, policy_denied: u64, retransmitted: u64, timeout: u64 }
struct DhcpLease { address: IpAddress, prefix_len: u8, valid_until_ms: u64 }
struct NeighborEntry { interface: InterfaceId, address: IpAddress, mac: MacAddress, expires_at_ms: u64 }
struct NetCapability { operation: Operation, local: Endpoint, remote: Option<SocketAddress> }
struct Stack
struct PacketTrace
struct ScriptedLink
struct ScriptedClock
struct ScriptedPolicy
struct StackFixture
trait Clock { fn now_ms(&self) -> u64 }
trait NetworkPolicy { fn permits(&self, principal: &Principal, capability: &NetCapability) -> bool }
trait LinkPort { fn properties(&self, interface: InterfaceId) -> Result<LinkProperties, NetError>; fn receive(&mut self, interface: InterfaceId) -> Result<Option<Frame>, NetError>; fn transmit(&mut self, interface: InterfaceId, frame: Frame) -> Result<(), NetError> }
fn Stack::new(config: StackConfig, policy: NetworkPolicy, clock: Clock, link: LinkPort) -> Result<Stack, NetError>
fn Stack::route_add(&mut self, principal: Principal, route: IpRoute) -> Result<(), NetError>
fn Stack::route_remove(&mut self, principal: Principal, route: IpRoute) -> Result<(), NetError>
fn Stack::input(&mut self, packet: PacketEvent) -> StackOutput
fn Stack::tick(&mut self, now_ms: u64) -> StackOutput
fn Stack::udp_bind(&mut self, principal: Principal, local: SocketAddress) -> Result<SocketId, NetError>
fn Stack::udp_send(&mut self, principal: Principal, socket: SocketId, peer: SocketAddress, payload: &[u8]) -> Result<(), NetError>
fn Stack::udp_receive(&mut self, principal: Principal, socket: SocketId) -> Result<Option<UdpDatagram>, NetError>
fn Stack::tcp_connect(&mut self, principal: Principal, peer: SocketAddress) -> Result<SocketId, NetError>
fn Stack::tcp_listen(&mut self, principal: Principal, local: SocketAddress, backlog: u16) -> Result<SocketId, NetError>
fn Stack::tcp_accept(&mut self, principal: Principal, listener: SocketId) -> Result<Option<SocketId>, NetError>
fn Stack::tcp_send(&mut self, principal: Principal, socket: SocketId, bytes: &[u8]) -> Result<usize, NetError>
fn Stack::tcp_receive(&mut self, principal: Principal, socket: SocketId, maximum: usize) -> Result<Option<Vec<u8>>, NetError>
fn Stack::tcp_close(&mut self, principal: Principal, socket: SocketId) -> Result<(), NetError>
fn Stack::dns_resolve(&mut self, principal: Principal, name: &[u8], family: AddressFamily) -> Result<DnsRequestId, NetError>
fn Stack::dns_result(&mut self, principal: Principal, request: DnsRequestId) -> Result<Option<Vec<IpAddress>>, NetError>
fn Stack::dhcp_start(&mut self, principal: Principal, interface: InterfaceId, family: AddressFamily) -> Result<(), NetError>
fn Stack::dhcp_lease(&self, principal: Principal, interface: InterfaceId, family: AddressFamily) -> Result<Option<DhcpLease>, NetError>
fn Stack::slaac_start(&mut self, principal: Principal, interface: InterfaceId) -> Result<(), NetError>
fn Stack::slaac_address_state(&self, principal: Principal, interface: InterfaceId, address: Ipv6Address) -> Result<SlaacState, NetError>
fn Stack::tcp_state(&self, principal: Principal, socket: SocketId) -> Result<TcpState, NetError>
fn Stack::stats(&self, principal: Principal) -> Result<NetStats, NetError>
fn Stack::neighbor(&self, principal: Principal, interface: InterfaceId, address: IpAddress) -> Result<Option<NeighborEntry>, NetError>
fn ScriptedLink::push_input(&mut self, interface: InterfaceId, bytes: Vec<u8>)
fn ScriptedLink::take_output(&mut self) -> Vec<Frame>
fn ScriptedClock::set(&mut self, now_ms: u64)
fn ScriptedPolicy::allow(&mut self, principal: Principal, endpoint: Endpoint)
fn StackFixture::new(config: StackConfig, now_ms: u64) -> StackFixture
fn StackFixture::stack(&mut self) -> &mut Stack
fn StackFixture::trace(&self) -> PacketTrace
fn PacketTrace::frames(&self) -> Vec<Frame>
```

## 3. State machines

TCP connection state. Guards are the validation and sequence rules of
INV-net-007 through INV-net-010; an unlisted event leaves state unchanged and
returns its specified refusal or drop result.

| from | event | to | guard |
|---|---|---|---|
| Closed | permitted active open | SynSent | local ephemeral port allocated |
| SynSent | valid SYN+ACK | Established | acknowledgement covers local SYN |
| SynSent | valid simultaneous SYN | SynReceived | RFC 9293 simultaneous-open rules |
| SynSent | timeout or refusal | Closed | retry bound reached or terminal refusal |
| Listen | valid SYN | SynReceived | backlog and half-open capacities remain |
| SynReceived | valid final ACK | Established | ACK covers SYN and sequence is valid |
| SynReceived | timeout, invalid RST, or capacity eviction | Listen | listener remains permitted |
| Established | valid FIN | CloseWait | FIN sequence is in receive window |
| Established | local close | FinWait1 | FIN is queued within send window |
| Established | valid RST | Closed | RFC 5961 reset validation succeeds |
| FinWait1 | peer ACK of FIN | FinWait2 | acknowledgement covers local FIN |
| FinWait1 | peer FIN before FIN ACK | Closing | FIN sequence is in receive window |
| FinWait1 | peer FIN and ACK | TimeWait | both FIN directions are acknowledged |
| FinWait2 | valid peer FIN | TimeWait | FIN sequence is in receive window |
| CloseWait | local close | LastAck | FIN is queued within send window |
| LastAck | valid ACK of FIN | Closed | acknowledgement covers local FIN |
| Closing | valid ACK of FIN | TimeWait | acknowledgement covers local FIN |
| TimeWait | expiry | Closed | 2 × maximum segment lifetime elapsed |
| any open state | interface down | same state or Closed | retry/close result follows RFC and policy; queued effects remain bounded |

DHCP client state.

| from | event | to | guard |
|---|---|---|---|
| Stopped | permitted start | Selecting | interface up; family supported |
| Selecting | valid offer/advertise | Requesting | interface and transaction match |
| Requesting | valid acknowledgement/reply | Bound | address not operator-pinned; lease fields valid |
| Requesting | refusal/timeout | Selecting | finite retry schedule remains |
| Bound | renewal deadline | Renewing | lease not expired |
| Renewing | valid renewal | Bound | transaction and interface match |
| Bound or Renewing | lease expiry/revoke | Selecting | address removed before reuse |
| any state | interface down | Stopped | lease retained only as permitted metadata; no address remains active |

IPv6 SLAAC address state.

| from | event | to | guard |
|---|---|---|---|
| Absent | valid prefix information | Tentative | autonomous flag set; lifetime valid; address derived within profile |
| Tentative | DAD success | Preferred | no conflicting Neighbor Advertisement before DAD deadline |
| Tentative | conflicting Neighbor Advertisement | Duplicate | address is not assigned or used as a source |
| Preferred | preferred lifetime expiry | Deprecated | address remains valid only through valid lifetime |
| Preferred or Deprecated | valid lifetime expiry or interface down | Absent | address removed before reuse |

DNS transaction state.

| from | event | to | guard |
|---|---|---|---|
| Idle | permitted query | Waiting | name, transaction and concurrency bounds valid |
| Waiting | matching valid response | Complete | source, id, question, class and type match |
| Waiting | timeout or malformed response | Failed | malformed response cannot complete another query |
| Complete | TTL expiry | Expired | cache lifetime is no greater than received TTL |
| Failed or Expired | new query | Waiting | new transaction id and fresh deadline |

## 4. Wire formats

Frames follow Ethernet II. The `wire representation` column replaces the
1986 method's CBOR-type column because the protocols specified here use RFC
binary fields, not CBOR. Fields are in wire order; RFCs define reserved-bit,
option, and extension semantics not repeated in this table.

**Ethernet II**

| field | wire representation | rule |
|---|---|---|
| destination | 6 octets | destination MAC; multicast and broadcast use Ethernet rules |
| source | 6 octets | source MAC; all-zero and multicast source are invalid |
| type | 2 octets, network order | `0x0800` IPv4, `0x0806` ARP, `0x86dd` IPv6 |
| payload | 46–1500 octets at default MTU | shorter payload is padded below IP; padding is not IP data |

**ARP, IPv4, IPv6, UDP, and TCP**

| field | wire representation | rule |
|---|---|---|
| ARP hardware/protocol type | 2 octets each | Ethernet `1`, IPv4 `0x0800` for this profile |
| ARP address lengths/opcode | 1, 1, 2 octets | Ethernet/IPv4 lengths are 6/4; request `1`, reply `2` |
| ARP sender/target addresses | 6 + 4 octets each | learned only for the receiving interface; never an identity |
| IPv4 version/IHL | 4 bits each | version `4`; IHL at least `5` and no larger than packet header length |
| IPv4 DSCP/ECN, total length | 1, 2 octets | network order; total length covers header and payload |
| IPv4 identification/flags/offset | 2 octets each | fragmentation follows RFC 791/1122 and the reassembly bounds |
| IPv4 TTL/protocol/checksum | 1, 1, 2 octets | TTL zero is not forwarded; checksum covers header only |
| IPv4 source/destination | 4 octets each | local-host destination required for local delivery |
| IPv6 version/traffic class/flow label | 4/8/20 bits | network order; version `6` |
| IPv6 payload length/next header/hop limit | 2/1/1 octets | payload length zero is handled only as RFC 2675 jumbogram; unsupported here and rejected |
| IPv6 source/destination | 16 octets each | scope and address validity follow RFC 4291 and RFC 1122 updates |
| IPv6 extension header | RFC-defined type and length | order, duplicates, options, fragments, and unknown headers follow RFC 8200, RFC 6980, and RFC 7112; parser bounds apply |
| UDP source/destination port | 2 octets each | network order; zero source port only where standards allow |
| UDP length/checksum | 2 octets each | length covers header and data; checksum includes IP pseudo-header; IPv6 checksum required |
| TCP source/destination port | 2 octets each | network order |
| TCP sequence/acknowledgement | 4 octets each | serial-number arithmetic; comparisons are valid only within the half-sequence-space window |
| TCP data offset/reserved/flags | 4 bits/4 bits/8 bits | header length at least 20 and within segment; reserved bits zero |
| TCP window/checksum/urgent pointer | 2 octets each | checksum includes IP pseudo-header; window scaling and urgent semantics follow RFC 9293 |
| TCP options | kind, length, value octets | each option length is valid; MSS, window scale, SACK-permitted/SACK, and timestamps follow RFC 9293 and its updates |

**ICMP and ICMPv6**

| field | wire representation | rule |
|---|---|---|
| type/code/checksum | 1/1/2 octets | code valid for type; checksum covers message and IPv6 pseudo-header for ICMPv6 |
| rest of header | type-specific | only RFC-defined fields are acted upon; invalid errors do not alter a socket |
| error quotation | bounded original packet prefix | never exceeds received packet or response amplification policy |

**DNS and DHCP**

| field | wire representation | rule |
|---|---|---|
| DNS header | 12 octets | id, flags, and section counts follow RFC 1035; response matches one outstanding query |
| DNS name | label sequence or compression pointer | total wire name at most `MAX_DNS_NAME_BYTES`; pointers are bounded and cannot loop |
| DNS resource record | owner, type, class, TTL, RDLENGTH, RDATA | each length is checked; cache lifetime is capped by TTL |
| DHCPv4 fixed header | RFC 2131 BOOTP layout | op, htype, hlen, xid, flags, addresses, and chaddr validated for the interface transaction |
| DHCPv4 options | code, length, value | pad/end and option lengths follow RFC 2132; malformed option lengths are rejected |
| DHCPv6 message | type, transaction id, options | transaction and client identity match the interface; option lengths are checked |

### Exact rules the acceptance tests rely on

- **B-9 Receive-before-dispatch.** Each frame is length-checked before a protocol parser sees it; parser output is either one validated packet or a closed `NetError`, with no partial delivery.
- **B-10 Fragmentation.** IPv4 fragments may be reassembled within the bounds; IPv6 fragments are processed only as allowed by RFC 8200 and RFC 6980; overlapping fragments are rejected.
- **B-11 UDP.** IPv4 zero-checksum UDP is accepted; IPv6 zero-checksum UDP is rejected unless the standards-defined exception is enabled by explicit configuration.
- **B-12 TCP open and close.** SYN, ACK, FIN, retransmission and TIME-WAIT follow RFC 9293; duplicate or reordered segments do not deliver duplicate stream bytes.
- **B-13 Reset defense.** An unacceptable RST causes the challenge-ACK behavior required by RFC 5961, subject to the response-rate limit.
- **B-14 Congestion.** TCP starts, grows, reduces, and recovers the congestion window according to RFC 9438 and its normative references.
- **B-15 DNS.** A response is accepted only for its outstanding transaction and exact question; compression pointers are validated before name expansion.
- **B-16 DHCP.** Offers and acknowledgements are accepted only for the active interface/family/transaction; pinned addresses remain unchanged.
- **B-17 Error equivalence.** An absent local TCP listener and an unauthorized listener do not disclose protected endpoint existence to an unauthenticated remote peer beyond the responses required by the RFC profile.

## 5. Acceptance tests

Each AT is one black-box statement at its named boundary. Vector files are
language-neutral; a test implementation is written from these statements and
vectors, one test per AT. `covers` names the invariants whose evidence this AT
supplies.

- **AT-net-001** given a frame shorter than the Ethernet header and the vector `NET-V-001`, when `Stack::input` receives it, then the output has no socket event, no emitted frame, and one `Malformed` input count (boundary: link frame input; covers INV-net-001, INV-net-013).
- **AT-net-002** given the vectors `NET-V-010` and `NET-V-011`, when each packet is input, then each is rejected before transport delivery and neither changes neighbor or socket state (boundary: IPv4 input; covers INV-net-002, INV-net-013).
- **AT-net-003** given the vectors `NET-V-020` and `NET-V-021`, when each packet is input, then each is rejected with bounded parser work and no transport event (boundary: IPv6 input; covers INV-net-003, INV-net-004, INV-net-013).
- **AT-net-004** given an ARP reply or Neighbor Advertisement whose sender address conflicts with an operator-pinned mapping in vector `NET-V-030`, when it is input, then the pinned mapping and every Principal's policy remain unchanged (boundary: neighbor cache; covers INV-net-005).
- **AT-net-005** given valid IPv4 UDP, invalid UDP length, invalid IPv4 UDP checksum, and zero-checksum IPv6 UDP cases in vectors `NET-V-040` through `NET-V-044`, when each reaches the UDP boundary, then only the valid IPv4 datagram and the IPv4 zero-checksum case are delivered (boundary: UDP receive; covers INV-net-006, INV-net-020).
- **AT-net-006** given the three-way handshake vector `NET-V-050`, when its SYN/SYN-ACK/ACK events are applied in order, then the connection transitions from `Listen` to `SynReceived` to `Established` without delivering stream bytes (boundary: TCP state machine; covers INV-net-007).
- **AT-net-007** given vector `NET-V-052`, when the sender schedules data, then no more than the minimum of peer receive window and congestion window enters the output trace (boundary: TCP output; covers INV-net-008).
- **AT-net-008** given in-window but unacceptable RST and SYN cases in vectors `NET-V-060` and `NET-V-061`, when each is input, then the connection stays `Established` and a rate-limited challenge ACK is emitted (boundary: TCP input; covers INV-net-009).
- **AT-net-009** given the timer trace in vectors `NET-V-070` and `NET-V-071`, when the clock advances through each deadline and ACK event, then retransmission times and congestion-window values equal the vectors' RFC-derived expected values and remain within the named timer cap (boundary: TCP timer; covers INV-net-010).
- **AT-net-010** given vector `NET-V-080`, when Principal P1 requests one connection beyond its configured per-Principal capacity, then the request returns `ResourceLimit`, P1 remains within capacity, and P2's state is unchanged (boundary: service resource accounting; covers INV-net-011, INV-net-012).
- **AT-net-011** given the declared length-field boundary partition and TCP serial-number wrap case in vectors `NET-V-090` and `NET-V-091`, when each is parsed, then the result is a packet or explicit error with no panic, unchecked wrap, or work beyond the parser budget (boundary: packet parsers; covers INV-net-013).
- **AT-net-012** given an unauthorized and an authorized TCP listen request in vectors `NET-V-100` and `NET-V-101`, when each request is made, then the denied call has no packet effect and the allowed call creates only its declared listener (boundary: network IPC; covers INV-net-014, INV-net-019).
- **AT-net-013** given a wrong-id response, wrong-question response, compression-pointer loop, and matching response that expires in vectors `NET-V-110` through `NET-V-113`, when each is processed, then only the matching response completes the request and no cache entry outlives TTL or capacity (boundary: resolver; covers INV-net-015).
- **AT-net-014** given wrong-interface, pinned-address, valid IPv6, and wrong-transaction DHCP replies in vectors `NET-V-120` through `NET-V-123`, when each is received, then only a matching unpinned reply changes the active lease (boundary: DHCP client; covers INV-net-016).
- **AT-net-015** given vector `NET-V-081` with a distinctive rejected-payload marker, when input is rejected and stats are read, then counters expose the reason and default diagnostics contain none of the payload bytes (boundary: stats/log interface; covers INV-net-017).
- **AT-net-016** given overlapping fragments, incomplete fragments, expired fragments, and an in-bound complete datagram in vectors `NET-V-130` through `NET-V-132`, when each fragment sequence is input, then only the complete in-bound datagram is delivered (boundary: IP reassembly; covers INV-net-018).
- **AT-net-017** given vector `NET-V-102`, when an unauthenticated peer probes an absent listener and a policy-denied listener, then no protected service state is disclosed beyond the common RFC-required response class (boundary: remote TCP response; covers INV-net-019, B-17).
- **AT-net-018** given the IPv4 TCP and IPv6 TCP/UDP scenarios in vectors `NET-V-140` and `NET-V-141`, when an independent Linux and BSD-derived peer exchanges the listed traffic, then stream bytes, datagrams, checksums, and close outcomes match the RFC-derived expectations (boundary: packet trace; covers INV-net-002, INV-net-003, INV-net-006 through INV-net-010).
- **AT-net-019** given vector `NET-V-150` and overlapping route prefixes, when the stack sends to each destination, then it selects longest prefix, lowest metric, and lowest interface id in that order (boundary: route selection and link output; covers INV-net-021).
- **AT-net-020** given an autonomous IPv6 prefix and conflicting and non-conflicting DAD traces in vector `NET-V-160`, when each trace completes, then only the non-conflicting address becomes usable (boundary: IPv6 address configuration; covers INV-net-022).

## 6. Dependencies

Allowed:

- CambiOS capability-checked IPC and Principal metadata, for client authority.
- CambiOS isolated user-space service lifecycle, clock, memory, and link-driver
  frame port, as declared effects only.
- The RFC profile in §1, as the normative wire and state-machine source.
- A clean-room Rust implementation using safe code for parsers and state
  transitions. `unsafe` may appear only at the independently specified IPC or
  DMA boundary and is not part of this protocol contract.
- Kani for bounded Rust proof harnesses; property-based and coverage-guided
  fuzzing; RFC-derived vectors; QEMU; Linux and BSD-derived peers for
  interoperability evidence.

Forbidden as normative source or copied implementation input:

- Any TCP/IP stack implementation, including OpenBSD, smoltcp, FreeBSD, Linux,
  and lwIP. They may be measured as independent comparison peers only.
- Any network service that can bypass the capability boundary or access a NIC
  directly from the kernel.
- Any hidden assumption that TCP provides confidentiality or authentication.

Formal claims are recorded in `spec/claims/net.md`. Kani can establish bounded
memory-safety and state-transition properties for the Rust model; it does not
prove RFC conformance, timing behavior, hardware correctness, or the whole
stack. Each acceptance test remains required even where a Kani claim exists.

Lean is a complementary candidate for mathematical properties over a pure,
safe, sequential protocol model, potentially using Aeneas to translate a
constrained Rust subset. It is not a drop-in substitute for Kani's bit-precise
Rust harnesses and does not by itself cover unsafe DMA/IPC boundaries,
concurrency, or establish that the model matches the RFCs. The claim ledger
keeps these obligations separate and makes no claim that a Lean proof exists.

## 7. Open questions

Close before freeze.

1. 🟠 Approve or replace the named resource-profile values in §2 for
   constrained, general, and server deployments; the current values are
   proposed defaults, not measured CambiOS capacities.
2. 🟠 Confirm whether the first profile includes IPv6 SLAAC and DHCPv6 at the
   same release as DHCPv4, or whether either is deferred. Both are specified
   here so a deferral requires an explicit scope change.
3. 🟠 Confirm whether TCP timestamps, SACK, window scaling, and ECN are enabled
   in the initial profile; current default is to implement RFC-required
   negotiation and safe fallback for each supported option.
4. 🟠 Review the proposed 100 challenge ACKs per interface per second and set a
   bounded DNS retry schedule before freeze; neither value has CambiOS workload
   evidence yet.
5. 🟡 Before calling this spec provenance-attested, record its complete
   authoring run through `Collaboration.Attestation.RecordPathwayRun@v1`, bind
   that canonical run to the final commit with
   `Pathways.Provenance.BindCommitToPathwayRun@v1`, and create/verify the Aqua
   signer sidecar for the final artifact. This PR explicitly records those
   attestations as absent; the source-to-claim attribution in the spec is not a
   substitute.

Status: **DRAFT, revision pass 4**, 2026-11-03. This specification is not
approved for implementation. No implementation code has been written from it.
