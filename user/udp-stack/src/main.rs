// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! ArcOS UDP Stack — user-space network service
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

// Status codes
const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
const STATUS_NO_DATA: u8 = 2;

// Virtio-net IPC commands
const NET_CMD_SEND: u8 = 1;
const NET_CMD_RECV: u8 = 2;
const NET_CMD_GET_MAC: u8 = 3;

// QEMU SLIRP network configuration
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
const SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];

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
    let arp_payload = build_arp_request(our_mac, &OUR_IP, target_ip);
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
    let on_subnet = OUR_IP[0] & SUBNET_MASK[0] == dst_ip[0] & SUBNET_MASK[0]
        && OUR_IP[1] & SUBNET_MASK[1] == dst_ip[1] & SUBNET_MASK[1]
        && OUR_IP[2] & SUBNET_MASK[2] == dst_ip[2] & SUBNET_MASK[2]
        && OUR_IP[3] & SUBNET_MASK[3] == dst_ip[3] & SUBNET_MASK[3];

    let hop_ip = if on_subnet { *dst_ip } else { GATEWAY_IP };
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
    let ip_len = build_ip_packet(&mut ip_buf, &OUR_IP, dst_ip, IP_PROTO_UDP, &udp_buf[..udp_len]);

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
    sys::print(b"[UDP] NTP demo: querying time.google.com (216.239.35.0)\n");

    // Build and send NTP request
    let ntp_req = build_ntp_request();
    if !udp_send(cache, our_mac, &NTP_SERVER_IP, NTP_CLIENT_PORT, NTP_PORT, &ntp_req) {
        sys::print(b"[UDP] NTP send failed\n");
        return;
    }
    sys::print(b"[UDP] NTP request sent, waiting for response...\n");

    // Poll for NTP response
    let mut payload = [0u8; 128];
    for _ in 0..500 {
        if let Some((_src_ip, src_port, len)) = udp_recv(&mut payload) {
            if src_port == NTP_PORT && len >= NTP_PACKET_LEN {
                if let Some(unix_ts) = parse_ntp_response(&payload[..len]) {
                    print_ntp_result(unix_ts);
                    return;
                }
            }
        }
    }
    sys::print(b"[UDP] NTP response timeout\n");
}

fn print_ntp_result(unix_ts: u64) {
    sys::print(b"[UDP] NTP response received!\n");
    sys::print(b"[UDP] Unix timestamp: ");
    print_u64(unix_ts);
    sys::print(b"\n");

    // Convert to UTC date/time
    let (year, month, day, hour, minute, second) = unix_to_datetime(unix_ts);
    sys::print(b"[UDP] UTC time: ");
    print_u64(year as u64);
    sys::print(b"-");
    print_padded_u8(month);
    sys::print(b"-");
    print_padded_u8(day);
    sys::print(b" ");
    print_padded_u8(hour);
    sys::print(b":");
    print_padded_u8(minute);
    sys::print(b":");
    print_padded_u8(second);
    sys::print(b" UTC\n");
}

/// Convert Unix timestamp to (year, month, day, hour, minute, second).
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
        let n = sys::recv_msg(UDP_ENDPOINT, &mut recv_buf);
        if n <= 0 {
            sys::yield_now();
            continue;
        }
        let total = n as usize;
        if total < IPC_HEADER_LEN + 1 {
            continue;
        }

        let from_endpoint = u32::from_le_bytes([
            recv_buf[32], recv_buf[33], recv_buf[34], recv_buf[35],
        ]);
        let payload = &recv_buf[IPC_HEADER_LEN..total];
        let cmd = payload[0];
        let cmd_data = &payload[1..];

        let resp_len = match cmd {
            CMD_UDP_SEND => handle_udp_send(cache, our_mac, cmd_data, &mut resp_buf),
            CMD_UDP_RECV => handle_udp_recv(cmd_data, &mut resp_buf),
            CMD_GET_CONFIG => handle_get_config(our_mac, &mut resp_buf),
            _ => {
                resp_buf[0] = STATUS_ERROR;
                1
            }
        };

        sys::write(from_endpoint, &resp_buf[..resp_len]);
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
    resp[1..5].copy_from_slice(&OUR_IP);
    resp[5..11].copy_from_slice(our_mac);
    11
}

// ============================================================================
// Printing helpers
// ============================================================================

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

fn print_padded_u8(val: u8) {
    let buf = [b'0' + val / 10, b'0' + val % 10];
    sys::print(&buf);
}

fn print_ip(ip: &[u8; 4]) {
    for i in 0..4 {
        print_u64(ip[i] as u64);
        if i < 3 {
            sys::print(b".");
        }
    }
}

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
    sys::print(b"[UDP] UDP stack starting\n");

    // Step 1: Get our MAC from virtio-net
    let our_mac = match net_get_mac() {
        Some(mac) => {
            sys::print(b"[UDP] Our MAC: ");
            print_mac(&mac);
            sys::print(b"\n");
            mac
        }
        None => {
            sys::print(b"[UDP] Failed to get MAC from virtio-net\n");
            sys::register_endpoint(UDP_ENDPOINT);
            error_loop();
        }
    };

    // Step 2: ARP resolve gateway
    let mut cache = ArpCache::new();
    sys::print(b"[UDP] ARP: resolving gateway ");
    print_ip(&GATEWAY_IP);
    sys::print(b"\n");

    match arp_resolve(&mut cache, &our_mac, &GATEWAY_IP) {
        Some(gw_mac) => {
            sys::print(b"[UDP] Gateway MAC: ");
            print_mac(&gw_mac);
            sys::print(b"\n");
        }
        None => {
            sys::print(b"[UDP] ARP resolution failed for gateway\n");
        }
    }

    // Step 3: NTP demo
    run_ntp_demo(&mut cache, &our_mac);

    // Step 4: Register service endpoint and enter service loop
    sys::register_endpoint(UDP_ENDPOINT);
    sys::print(b"[UDP] Endpoint 21 registered, entering service loop\n");
    service_loop(&mut cache, &our_mac)
}

fn error_loop() -> ! {
    let mut recv_buf = [0u8; 292];
    let resp = [STATUS_ERROR];

    loop {
        let n = sys::recv_msg(UDP_ENDPOINT, &mut recv_buf);
        if n <= 0 {
            sys::yield_now();
            continue;
        }
        let total = n as usize;
        if total >= IPC_HEADER_LEN + 1 {
            let from_endpoint = u32::from_le_bytes([
                recv_buf[32], recv_buf[33], recv_buf[34], recv_buf[35],
            ]);
            sys::write(from_endpoint, &resp);
        }
    }
}
