// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS UDP Stack — user-space network service
//!
//! Minimal stateless UDP/IP implementation running as a ring-3 process.
//! Communicates with the virtio-net driver (endpoint 20) for raw Ethernet
//! frame I/O, and exposes a UDP send/receive interface to other services
//! on IPC endpoint 21.
//!
//! On startup, performs an NTP query to demonstrate the full networking
//! stack: ARP resolution → IP routing → UDP transport → NTP time sync.
//!
//! ## IPC protocol (endpoint 21, 256-byte payload)
//!
//!   Request:  [cmd:1][data...]
//!   Response: [status:1][data...]
//!
//!   Commands:
//!     1 = UDP_SEND:   [cmd:1][dst_ip:4][dst_port:2][src_port:2][payload:N]
//!                     → [status:1]
//!     2 = UDP_RECV:   [cmd:1][port:2]
//!                     → [status:1][src_ip:4][src_port:2][payload:N]
//!     3 = GET_CONFIG: [cmd:1]
//!                     → [status:1][our_ip:4][our_mac:6]
//!     4 = SET_CONFIG: [cmd:1][ip:4][gateway:4][netmask:4]
//!                     → [status:1]
//!     5 = DHCP_SEND:  [cmd:1][src_port:2][dst_port:2][payload:N]
//!                     → [status:1]   (sends broadcast, src IP 0.0.0.0)
//!
//!   Status: 0=OK, 1=ERROR, 2=NO_DATA
//!
//! ## Network configuration (hardcoded for QEMU SLIRP)
//!
//!   Our IP:   10.0.2.15
//!   Gateway:  10.0.2.2
//!   Netmask:  255.255.255.0  (/24)

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libsys as sys;

/// Blocking receive: loops until recv_msg returns actual data.
///
/// The kernel's blocking recv_msg wakes the task with RAX=0 (no data
/// returned on the wake-up call). The message is in the queue — the
/// next recv_msg call dequeues it. This helper handles that two-step.
fn blocking_recv(endpoint: u32, buf: &mut [u8]) -> usize {
    loop {
        let n = sys::recv_msg(endpoint, buf);
        if n > 0 {
            return n as usize;
        }
    }
}

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[UDP] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// Constants
// ============================================================================

// IPC endpoints
const NET_ENDPOINT: u32 = 20;
const UDP_ENDPOINT: u32 = 21;

// IPC commands (this service)
const CMD_UDP_SEND: u8 = 1;
const CMD_UDP_RECV: u8 = 2;
const CMD_GET_CONFIG: u8 = 3;
/// Update IP/gateway/netmask at runtime (used by DHCP client).
const CMD_SET_CONFIG: u8 = 4;
/// Send a UDP packet with broadcast Ethernet MAC and source IP 0.0.0.0
/// (used by DHCP client for DISCOVER/REQUEST before we have an IP).
const CMD_DHCP_SEND: u8 = 5;

// Status codes
const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
const STATUS_NO_DATA: u8 = 2;

// Virtio-net IPC commands
const NET_CMD_SEND: u8 = 1;
const NET_CMD_RECV: u8 = 2;
const NET_CMD_GET_MAC: u8 = 3;

// Network configuration — initially hardcoded for QEMU SLIRP, but can be
// updated at runtime via CMD_SET_CONFIG (used by the DHCP client to push
// a lease into the stack). Single-threaded user-space service, so plain
// static mut is sound.
static mut OUR_IP: [u8; 4] = [10, 0, 2, 15];
static mut GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
static mut SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];

/// Read the current configured IP. Single-threaded service — no race.
fn our_ip() -> [u8; 4] {
    // SAFETY: Single-threaded user-space service, no concurrent access.
    #[allow(unsafe_code)]
    unsafe { OUR_IP }
}

fn gateway_ip() -> [u8; 4] {
    // SAFETY: Single-threaded user-space service.
    #[allow(unsafe_code)]
    unsafe { GATEWAY_IP }
}

fn subnet_mask() -> [u8; 4] {
    // SAFETY: Single-threaded user-space service.
    #[allow(unsafe_code)]
    unsafe { SUBNET_MASK }
}

/// Update network configuration (called by DHCP client after lease).
fn set_network_config(ip: [u8; 4], gateway: [u8; 4], mask: [u8; 4]) {
    // SAFETY: Single-threaded user-space service, no concurrent access.
    #[allow(unsafe_code)]
    unsafe {
        OUR_IP = ip;
        GATEWAY_IP = gateway;
        SUBNET_MASK = mask;
    }
}

// NTP server: time.google.com (216.239.35.0)
const NTP_SERVER_IP: [u8; 4] = [216, 239, 35, 0];
const NTP_PORT: u16 = 123;
const NTP_CLIENT_PORT: u16 = 12345;

// Ethernet constants
const ETH_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

// IPv4 constants
const IPV4_HEADER_LEN: usize = 20;
const IP_PROTO_UDP: u8 = 17;

// UDP constants
const UDP_HEADER_LEN: usize = 8;

// NTP constants
const NTP_PACKET_LEN: usize = 48;
/// NTP epoch (Jan 1 1900) to Unix epoch (Jan 1 1970) in seconds.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

// IPC recv header: 32-byte principal + 4-byte from_endpoint
const IPC_HEADER_LEN: usize = 36;

// Maximum raw frame payload through virtio-net IPC:
// IPC payload max 256 - 1 (status byte) = 255 bytes for the frame.
// Frame budget: 255 - 14 (eth) - 20 (ip) - 8 (udp) = 213 bytes for UDP payload.
const MAX_UDP_PAYLOAD: usize = 213;

// ARP cache
const ARP_CACHE_SIZE: usize = 4;

// ============================================================================
// Big-endian (network byte order) helpers
// ============================================================================

fn put_be16(buf: &mut [u8], val: u16) {
    buf[0] = (val >> 8) as u8;
    buf[1] = val as u8;
}

fn get_be16(buf: &[u8]) -> u16 {
    (buf[0] as u16) << 8 | buf[1] as u16
}

fn get_be32(buf: &[u8]) -> u32 {
    (buf[0] as u32) << 24 | (buf[1] as u32) << 16 |
    (buf[2] as u32) << 8  | buf[3] as u32
}

// ============================================================================
// Internet checksum (RFC 1071)
// ============================================================================

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ============================================================================
// Ethernet frame builder / parser
// ============================================================================

/// Build an Ethernet frame. Returns total frame length.
fn build_eth_frame(
    buf: &mut [u8],
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    ethertype: u16,
    payload: &[u8],
) -> usize {
    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    put_be16(&mut buf[12..14], ethertype);
    let total = ETH_HEADER_LEN + payload.len();
    buf[ETH_HEADER_LEN..total].copy_from_slice(payload);
    total
}

/// Parse an Ethernet frame header. Returns (ethertype, payload_offset).
fn parse_eth_frame(frame: &[u8]) -> Option<(u16, usize)> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }
    let ethertype = get_be16(&frame[12..14]);
    Some((ethertype, ETH_HEADER_LEN))
}

// ============================================================================
// ARP
// ============================================================================

/// Build an ARP request. Returns the ARP packet (28 bytes).
fn build_arp_request(sender_mac: &[u8; 6], sender_ip: &[u8; 4], target_ip: &[u8; 4]) -> [u8; 28] {
    let mut arp = [0u8; 28];
    put_be16(&mut arp[0..2], 1);       // Hardware type: Ethernet
    put_be16(&mut arp[2..4], 0x0800);  // Protocol type: IPv4
    arp[4] = 6;                        // Hardware addr len
    arp[5] = 4;                        // Protocol addr len
    put_be16(&mut arp[6..8], 1);       // Opcode: Request
    arp[8..14].copy_from_slice(sender_mac);
    arp[14..18].copy_from_slice(sender_ip);
    // target MAC = 0 (unknown)
    arp[24..28].copy_from_slice(target_ip);
    arp
}

/// Parse an ARP reply. Returns Some((sender_ip, sender_mac)) if valid reply.
fn parse_arp_reply(data: &[u8]) -> Option<([u8; 4], [u8; 6])> {
    if data.len() < 28 {
        return None;
    }
    let opcode = get_be16(&data[6..8]);
    if opcode != 2 {
        return None; // Not a reply
    }
    let mut mac = [0u8; 6];
    let mut ip = [0u8; 4];
    mac.copy_from_slice(&data[8..14]);
    ip.copy_from_slice(&data[14..18]);
    Some((ip, mac))
}

// ============================================================================
// IPv4
// ============================================================================

/// Build an IPv4 header + payload. Returns total IP packet length.
fn build_ip_packet(
    buf: &mut [u8],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    protocol: u8,
    payload: &[u8],
) -> usize {
    let total_len = (IPV4_HEADER_LEN + payload.len()) as u16;

    buf[0] = 0x45;                         // Version 4, IHL 5
    buf[1] = 0;                            // DSCP/ECN
    put_be16(&mut buf[2..4], total_len);   // Total length
    put_be16(&mut buf[4..6], 0x1234);      // Identification
    put_be16(&mut buf[6..8], 0x4000);      // Flags: Don't Fragment
    buf[8] = 64;                           // TTL
    buf[9] = protocol;                     // Protocol
    put_be16(&mut buf[10..12], 0);         // Checksum (zeroed for calculation)
    buf[12..16].copy_from_slice(src_ip);
    buf[16..20].copy_from_slice(dst_ip);

    // Calculate and fill checksum
    let cksum = ip_checksum(&buf[..IPV4_HEADER_LEN]);
    put_be16(&mut buf[10..12], cksum);

    // Copy payload
    let end = IPV4_HEADER_LEN + payload.len();
    buf[IPV4_HEADER_LEN..end].copy_from_slice(payload);
    end
}

/// Parse an IPv4 header. Returns (src_ip, dst_ip, protocol, payload_offset, payload_len).
fn parse_ip_packet(data: &[u8]) -> Option<([u8; 4], [u8; 4], u8, usize, usize)> {
    if data.len() < IPV4_HEADER_LEN {
        return None;
    }
    let version = data[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < IPV4_HEADER_LEN || data.len() < ihl {
        return None;
    }
    let total_len = get_be16(&data[2..4]) as usize;
    if total_len < ihl || data.len() < total_len {
        return None;
    }
    let protocol = data[9];
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&data[12..16]);
    dst.copy_from_slice(&data[16..20]);
    Some((src, dst, protocol, ihl, total_len - ihl))
}

// ============================================================================
// UDP
// ============================================================================

/// Build a UDP datagram (header + payload). Returns total UDP length.
fn build_udp_packet(
    buf: &mut [u8],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> usize {
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    put_be16(&mut buf[0..2], src_port);
    put_be16(&mut buf[2..4], dst_port);
    put_be16(&mut buf[4..6], udp_len);
    put_be16(&mut buf[6..8], 0);   // Checksum optional for IPv4
    let end = UDP_HEADER_LEN + payload.len();
    buf[UDP_HEADER_LEN..end].copy_from_slice(payload);
    end
}

/// Parse a UDP header. Returns (src_port, dst_port, payload_offset, payload_len).
fn parse_udp_packet(data: &[u8]) -> Option<(u16, u16, usize, usize)> {
    if data.len() < UDP_HEADER_LEN {
        return None;
    }
    let src_port = get_be16(&data[0..2]);
    let dst_port = get_be16(&data[2..4]);
    let udp_len = get_be16(&data[4..6]) as usize;
    if udp_len < UDP_HEADER_LEN || data.len() < udp_len {
        return None;
    }
    Some((src_port, dst_port, UDP_HEADER_LEN, udp_len - UDP_HEADER_LEN))
}

// ============================================================================
// NTP
// ============================================================================

/// Build an NTP client request (48 bytes).
fn build_ntp_request() -> [u8; NTP_PACKET_LEN] {
    let mut pkt = [0u8; NTP_PACKET_LEN];
    // LI=0 (no warning), VN=4 (NTPv4), Mode=3 (client)
    pkt[0] = 0x23;
    pkt
}

/// Parse NTP response. Returns Unix timestamp (seconds since 1970).
fn parse_ntp_response(data: &[u8]) -> Option<u64> {
    if data.len() < NTP_PACKET_LEN {
        return None;
    }
    // Transmit timestamp at bytes 40-43 (seconds since NTP epoch)
    let ntp_secs = get_be32(&data[40..44]) as u64;
    if ntp_secs < NTP_UNIX_OFFSET {
        return None; // Invalid (before 1970)
    }
    Some(ntp_secs - NTP_UNIX_OFFSET)
}

// ============================================================================
// ARP cache
// ============================================================================

struct ArpEntry {
    ip: [u8; 4],
    mac: [u8; 6],
    valid: bool,
}

struct ArpCache {
    entries: [ArpEntry; ARP_CACHE_SIZE],
}

impl ArpCache {
    fn new() -> Self {
        ArpCache {
            entries: core::array::from_fn(|_| ArpEntry {
                ip: [0; 4], mac: [0; 6], valid: false,
            }),
        }
    }

    fn lookup(&self, ip: &[u8; 4]) -> Option<[u8; 6]> {
        for e in &self.entries {
            if e.valid && e.ip == *ip {
                return Some(e.mac);
            }
        }
        None
    }

    fn insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        // Replace first invalid slot, or overwrite slot 0
        for e in self.entries.iter_mut() {
            if !e.valid || e.ip == ip {
                e.ip = ip;
                e.mac = mac;
                e.valid = true;
                return;
            }
        }
        self.entries[0] = ArpEntry { ip, mac, valid: true };
    }
}

// ============================================================================
// Virtio-net IPC client
// ============================================================================

/// Send a raw Ethernet frame through virtio-net. Returns true on success.
fn net_send_frame(frame: &[u8]) -> bool {
    if frame.len() > 255 {
        return false;
    }
    let mut req = [0u8; 256];
    req[0] = NET_CMD_SEND;
    req[1..1 + frame.len()].copy_from_slice(frame);
    sys::write(NET_ENDPOINT, &req[..1 + frame.len()]);

    let my_ep = sys::get_pid();
    let mut resp = [0u8; 292];
    let n = blocking_recv(my_ep, &mut resp);
    n > IPC_HEADER_LEN && resp[IPC_HEADER_LEN] == 0
}

/// Poll virtio-net for a received Ethernet frame. Returns frame length,
/// or 0 if no frame available.
fn net_recv_frame(out: &mut [u8]) -> usize {
    sys::write(NET_ENDPOINT, &[NET_CMD_RECV]);

    let my_ep = sys::get_pid();
    let mut resp = [0u8; 292];
    let n = blocking_recv(my_ep, &mut resp);
    if n <= IPC_HEADER_LEN || resp[IPC_HEADER_LEN] != 0 {
        return 0; // NO_DATA or error
    }
    let frame_start = IPC_HEADER_LEN + 1;
    let frame_len = n - frame_start;
    let copy_len = core::cmp::min(frame_len, out.len());
    out[..copy_len].copy_from_slice(&resp[frame_start..frame_start + copy_len]);
    copy_len
}

/// Get our MAC address from virtio-net.
fn net_get_mac() -> Option<[u8; 6]> {
    let my_ep = sys::get_pid();
    let mut resp = [0u8; 292];

    sys::write(NET_ENDPOINT, &[NET_CMD_GET_MAC]);
    let n = blocking_recv(my_ep, &mut resp);
    if n >= IPC_HEADER_LEN + 7 && resp[IPC_HEADER_LEN] == 0 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&resp[IPC_HEADER_LEN + 1..IPC_HEADER_LEN + 7]);
        return Some(mac);
    }
    None
}

// ============================================================================
// ARP resolution
// ============================================================================

/// Resolve an IP address to a MAC address via ARP. Checks cache first,
/// then sends an ARP request and polls for the reply.
fn arp_resolve(
    cache: &mut ArpCache,
    our_mac: &[u8; 6],
    target_ip: &[u8; 4],
) -> Option<[u8; 6]> {
    // Check cache
    if let Some(mac) = cache.lookup(target_ip) {
        return Some(mac);
    }

    // Build and send ARP request
    let arp_payload = build_arp_request(our_mac, &our_ip(), target_ip);
    let mut frame = [0u8; 256];
    let frame_len = build_eth_frame(
        &mut frame,
        &BROADCAST_MAC,
        our_mac,
        ETHERTYPE_ARP,
        &arp_payload,
    );

    if !net_send_frame(&frame[..frame_len]) {
        return None;
    }

    // Poll for ARP reply
    let mut recv_frame = [0u8; 256];
    for _ in 0..30 {
        let n = net_recv_frame(&mut recv_frame);
        if n >= ETH_HEADER_LEN + 28 {
            if let Some((ethertype, eth_off)) = parse_eth_frame(&recv_frame[..n]) {
                if ethertype == ETHERTYPE_ARP {
                    if let Some((reply_ip, reply_mac)) = parse_arp_reply(&recv_frame[eth_off..n]) {
                        cache.insert(reply_ip, reply_mac);
                        if reply_ip == *target_ip {
                            return Some(reply_mac);
                        }
                    }
                }
            }
        }
    }
    None
}

// ============================================================================
// UDP send / receive
// ============================================================================

/// Determine the next-hop MAC for a destination IP.
/// Off-subnet → gateway MAC, on-subnet → direct ARP.
fn resolve_next_hop(
    cache: &mut ArpCache,
    our_mac: &[u8; 6],
    dst_ip: &[u8; 4],
) -> Option<[u8; 6]> {
    let our = our_ip();
    let mask = subnet_mask();
    let on_subnet = our[0] & mask[0] == dst_ip[0] & mask[0]
        && our[1] & mask[1] == dst_ip[1] & mask[1]
        && our[2] & mask[2] == dst_ip[2] & mask[2]
        && our[3] & mask[3] == dst_ip[3] & mask[3];

    let hop_ip = if on_subnet { *dst_ip } else { gateway_ip() };
    arp_resolve(cache, our_mac, &hop_ip)
}

/// Send a UDP datagram. Builds Ethernet+IP+UDP, ARP-resolves, and sends.
fn udp_send(
    cache: &mut ArpCache,
    our_mac: &[u8; 6],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> bool {
    if payload.len() > MAX_UDP_PAYLOAD {
        return false;
    }

    let dst_mac = match resolve_next_hop(cache, our_mac, dst_ip) {
        Some(m) => m,
        None => return false,
    };

    // Build UDP → IP → Ethernet (innermost first)
    let mut udp_buf = [0u8; 256];
    let udp_len = build_udp_packet(&mut udp_buf, src_port, dst_port, payload);

    let mut ip_buf = [0u8; 256];
    let ip_len = build_ip_packet(&mut ip_buf, &our_ip(), dst_ip, IP_PROTO_UDP, &udp_buf[..udp_len]);

    let mut frame = [0u8; 256];
    let frame_len = build_eth_frame(&mut frame, &dst_mac, our_mac, ETHERTYPE_IPV4, &ip_buf[..ip_len]);

    net_send_frame(&frame[..frame_len])
}

/// Try to receive a UDP datagram. Polls virtio-net for a raw frame,
/// parses Ethernet+IP+UDP, and copies payload to `out`.
/// Returns Some((src_ip, src_port, payload_len)) on success.
fn udp_recv(out: &mut [u8]) -> Option<([u8; 4], u16, usize)> {
    let mut frame = [0u8; 256];
    let n = net_recv_frame(&mut frame);
    if n < ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN {
        return None;
    }

    let (ethertype, eth_off) = parse_eth_frame(&frame[..n])?;
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }

    let ip_data = &frame[eth_off..n];
    let (src_ip, _dst_ip, proto, ip_off, ip_payload_len) = parse_ip_packet(ip_data)?;
    if proto != IP_PROTO_UDP {
        return None;
    }

    let udp_data = &ip_data[ip_off..ip_off + ip_payload_len];
    let (src_port, _dst_port, udp_off, udp_payload_len) = parse_udp_packet(udp_data)?;

    let copy_len = core::cmp::min(udp_payload_len, out.len());
    out[..copy_len].copy_from_slice(&udp_data[udp_off..udp_off + copy_len]);

    Some((src_ip, src_port, copy_len))
}

// ============================================================================
// NTP demo
// ============================================================================

fn run_ntp_demo(cache: &mut ArpCache, our_mac: &[u8; 6]) {
    // Silent-on-success: NTP demo validates the UDP path, but only errors
    // are printed. The demo is verification-only; results are discarded.
    let ntp_req = build_ntp_request();
    if !udp_send(cache, our_mac, &NTP_SERVER_IP, NTP_CLIENT_PORT, NTP_PORT, &ntp_req) {
        sys::print(b"[UDP] NTP send failed\n");
        return;
    }

    // Poll for NTP response. Silent on success, silent on timeout (demo only).
    let mut payload = [0u8; 128];
    for _ in 0..500 {
        if let Some((_src_ip, src_port, len)) = udp_recv(&mut payload) {
            if src_port == NTP_PORT && len >= NTP_PACKET_LEN {
                if parse_ntp_response(&payload[..len]).is_some() {
                    return;
                }
            }
        }
    }
}

/// Convert Unix timestamp to (year, month, day, hour, minute, second).
#[allow(dead_code)]
fn unix_to_datetime(ts: u64) -> (u32, u8, u8, u8, u8, u8) {
    let second = (ts % 60) as u8;
    let ts = ts / 60;
    let minute = (ts % 60) as u8;
    let ts = ts / 60;
    let hour = (ts % 24) as u8;
    let mut days = (ts / 24) as u32;

    // Calculate year from days since 1970-01-01
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    // Calculate month/day
    let leap = is_leap_year(year);
    let days_in_month: [u32; 12] = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut month = 0u8;
    for (i, &dim) in days_in_month.iter().enumerate() {
        if days < dim {
            month = i as u8 + 1;
            break;
        }
        days -= dim;
    }
    let day = days as u8 + 1;

    (year, month, day, hour, minute, second)
}

#[allow(dead_code)]
fn is_leap_year(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ============================================================================
// Service loop
// ============================================================================

fn service_loop(cache: &mut ArpCache, our_mac: &[u8; 6]) -> ! {
    let mut recv_buf = [0u8; 292];
    let mut resp_buf = [0u8; 256];

    loop {
        let msg = match sys::recv_verified(UDP_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };

        let (cmd, cmd_data) = match msg.command() {
            Some(pair) => pair,
            None => continue,
        };

        let resp_len = match cmd {
            CMD_UDP_SEND => handle_udp_send(cache, our_mac, cmd_data, &mut resp_buf),
            CMD_UDP_RECV => handle_udp_recv(cmd_data, &mut resp_buf),
            CMD_GET_CONFIG => handle_get_config(our_mac, &mut resp_buf),
            CMD_SET_CONFIG => handle_set_config(cmd_data, &mut resp_buf),
            CMD_DHCP_SEND => handle_dhcp_send(our_mac, cmd_data, &mut resp_buf),
            _ => {
                resp_buf[0] = STATUS_ERROR;
                1
            }
        };

        sys::write(msg.from_endpoint(), &resp_buf[..resp_len]);
    }
}

fn handle_udp_send(
    cache: &mut ArpCache,
    our_mac: &[u8; 6],
    data: &[u8],
    resp: &mut [u8],
) -> usize {
    // Expected: [dst_ip:4][dst_port:2][src_port:2][payload:N]
    if data.len() < 8 {
        resp[0] = STATUS_ERROR;
        return 1;
    }
    let mut dst_ip = [0u8; 4];
    dst_ip.copy_from_slice(&data[0..4]);
    let dst_port = get_be16(&data[4..6]);
    let src_port = get_be16(&data[6..8]);
    let payload = &data[8..];

    if udp_send(cache, our_mac, &dst_ip, src_port, dst_port, payload) {
        resp[0] = STATUS_OK;
    } else {
        resp[0] = STATUS_ERROR;
    }
    1
}

fn handle_udp_recv(data: &[u8], resp: &mut [u8]) -> usize {
    // Expected: [port:2]
    if data.len() < 2 {
        resp[0] = STATUS_ERROR;
        return 1;
    }
    let listen_port = get_be16(&data[0..2]);

    let mut payload = [0u8; 220];
    if let Some((src_ip, src_port, len)) = udp_recv(&mut payload) {
        // Filter: only return if destination port matches
        // Note: udp_recv doesn't filter by dst_port — we rely on there being
        // only one listener. For a real stack, we'd buffer and demux.
        let _ = listen_port; // Accept any for now

        resp[0] = STATUS_OK;
        resp[1..5].copy_from_slice(&src_ip);
        put_be16(&mut resp[5..7], src_port);
        let copy_len = core::cmp::min(len, resp.len() - 7);
        resp[7..7 + copy_len].copy_from_slice(&payload[..copy_len]);
        7 + copy_len
    } else {
        resp[0] = STATUS_NO_DATA;
        1
    }
}

fn handle_get_config(our_mac: &[u8; 6], resp: &mut [u8]) -> usize {
    resp[0] = STATUS_OK;
    resp[1..5].copy_from_slice(&our_ip());
    resp[5..11].copy_from_slice(our_mac);
    11
}

/// Update the network configuration. Used by the DHCP client to push
/// a lease (IP/gateway/netmask) into the stack.
///
/// Expected payload: [ip:4][gateway:4][netmask:4]
fn handle_set_config(data: &[u8], resp: &mut [u8]) -> usize {
    if data.len() < 12 {
        resp[0] = STATUS_ERROR;
        return 1;
    }
    let mut ip = [0u8; 4];
    let mut gw = [0u8; 4];
    let mut mask = [0u8; 4];
    ip.copy_from_slice(&data[0..4]);
    gw.copy_from_slice(&data[4..8]);
    mask.copy_from_slice(&data[8..12]);
    set_network_config(ip, gw, mask);
    resp[0] = STATUS_OK;
    1
}

/// Send a packet using the broadcast Ethernet MAC, source IP 0.0.0.0,
/// and destination IP 255.255.255.255. Used by the DHCP client for
/// DISCOVER/REQUEST messages where we don't yet have an IP or know
/// the server's MAC.
///
/// Expected payload: [src_port:2][dst_port:2][udp_payload:N]
fn handle_dhcp_send(our_mac: &[u8; 6], data: &[u8], resp: &mut [u8]) -> usize {
    if data.len() < 4 {
        resp[0] = STATUS_ERROR;
        return 1;
    }
    let src_port = get_be16(&data[0..2]);
    let dst_port = get_be16(&data[2..4]);
    let payload = &data[4..];

    // Build UDP packet with src=0.0.0.0, dst=255.255.255.255
    let zero_ip = [0u8; 4];
    let bcast_ip = [255u8; 4];

    if payload.len() > MAX_UDP_PAYLOAD {
        resp[0] = STATUS_ERROR;
        return 1;
    }

    let mut udp_buf = [0u8; 256];
    let udp_len = build_udp_packet(&mut udp_buf, src_port, dst_port, payload);

    let mut ip_buf = [0u8; 256];
    let ip_len = build_ip_packet(&mut ip_buf, &zero_ip, &bcast_ip, IP_PROTO_UDP, &udp_buf[..udp_len]);

    let mut frame = [0u8; 256];
    let frame_len = build_eth_frame(&mut frame, &BROADCAST_MAC, our_mac, ETHERTYPE_IPV4, &ip_buf[..ip_len]);

    if net_send_frame(&frame[..frame_len]) {
        resp[0] = STATUS_OK;
    } else {
        resp[0] = STATUS_ERROR;
    }
    1
}

// ============================================================================
// Printing helpers (kept for future diagnostic use; currently silenced per
// the "chat on fail only" policy — see services cleanup, Phase 3.4b).
// ============================================================================

#[allow(dead_code)]
fn print_u64(mut val: u64) {
    if val == 0 {
        sys::print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    sys::print(&buf[i..]);
}

#[allow(dead_code)]
fn print_padded_u8(val: u8) {
    let buf = [b'0' + val / 10, b'0' + val % 10];
    sys::print(&buf);
}

#[allow(dead_code)]
fn print_ip(ip: &[u8; 4]) {
    for i in 0..4 {
        print_u64(ip[i] as u64);
        if i < 3 {
            sys::print(b".");
        }
    }
}

#[allow(dead_code)]
fn print_mac(mac: &[u8; 6]) {
    let mut buf = [0u8; 17];
    for i in 0..6 {
        let hi = mac[i] >> 4;
        let lo = mac[i] & 0xF;
        buf[i * 3] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
        buf[i * 3 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
        if i < 5 {
            buf[i * 3 + 2] = b':';
        }
    }
    sys::print(&buf);
}

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Step 1: Get our MAC from virtio-net
    let our_mac = match net_get_mac() {
        Some(mac) => mac,
        None => {
            sys::print(b"[UDP] ERROR: failed to get MAC from virtio-net\n");
            sys::register_endpoint(UDP_ENDPOINT);
            error_loop();
        }
    };

    // Step 2: ARP resolve gateway (silent on success)
    let mut cache = ArpCache::new();
    let gw = gateway_ip();
    if arp_resolve(&mut cache, &our_mac, &gw).is_none() {
        sys::print(b"[UDP] ERROR: ARP resolution failed for gateway\n");
    }

    // Step 3: NTP demo (silent on success)
    run_ntp_demo(&mut cache, &our_mac);

    // Step 4: Register service endpoint and enter service loop
    sys::register_endpoint(UDP_ENDPOINT);
    sys::print(b"[UDP] ready on endpoint 21\n");
    service_loop(&mut cache, &our_mac)
}

fn error_loop() -> ! {
    let mut recv_buf = [0u8; 292];
    let resp = [STATUS_ERROR];

    loop {
        let msg = match sys::recv_verified(UDP_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };
        sys::write(msg.from_endpoint(), &resp);
    }
}
