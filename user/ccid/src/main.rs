// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CCID 1.1 class driver — frames PC_to_RDR_* messages over
//! usb-host's bulk transport (endpoint 31) and parses RDR_to_PC_*
//! responses. Owns no hardware state; talks to one xHCI controller
//! through usb-host IPC.
//!
//! Wire format on the way out (usb-host endpoint 31):
//!   `[opcode:1][slot_id:1][...payload]`
//!
//! Wire format on the way back (this module's endpoint 33):
//!   `[status:1][...result]`
//!
//! Boot-time smoke: issue `PC_to_RDR_GetSlotStatus` to slot 1 and
//! log the parsed `RDR_to_PC_SlotStatus` response. This replaces
//! the inline smoke that previously lived in usb-host's main, and
//! validates the full enumeration → configure → bulk-transfer
//! path through the proper module boundary.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use cambios_ccid_proto as ccid;
use cambios_libsys as sys;

const CCID_ENDPOINT: u32 = 33;
const USB_HOST_ENDPOINT: u32 = 31;

/// SCAFFOLDING: max bytes of CCID payload this module sends or
/// receives in a single bulk request. Must match usb-host's
/// `MAX_BULK_PAYLOAD` (192) so the IPC envelope round-trips
/// without truncation; reading the same constant from a shared
/// crate is overkill for one number both sides hard-code.
/// Replace when: extended APDUs land and ccid switches to the
/// channel substrate for >MAX_BULK_PAYLOAD transfers.
const MAX_BULK_PAYLOAD: usize = 192;

// IPC opcode constants for usb-host's BULK_OUT / BULK_IN surface.
// Duplicated with usb-host's main.rs; a shared
// `cambios-usb-host-proto` crate lifts when warranted.
// Revisit when: a third consumer of these opcodes appears (e.g.
// a diagnostic shell command bypassing the CCID layer).
const OP_BULK_OUT: u8 = 0x01;
const OP_BULK_IN: u8 = 0x02;

const STATUS_OK: u8 = 0;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[CCID] PANIC!\n");
    sys::exit(1);
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::register_endpoint(CCID_ENDPOINT);
    sys::print(b"[CCID] ready on endpoint 33\n");
    sys::module_ready();

    // Boot-time path: issue a single GetSlotStatus to slot 1 and
    // log the result. After that we idle on the endpoint awaiting
    // future client commands (none yet — PIV APDUs land in a
    // future substage).
    run_get_slot_status_smoke();

    idle_loop();
}

fn run_get_slot_status_smoke() {
    sys::print(b"[CCID] PC_to_RDR_GetSlotStatus (slot=1, seq=0)\n");

    // Build the 10-byte CCID command using the proto crate.
    let mut cmd = [0u8; ccid::CCID_HEADER_LEN];
    ccid::encode_get_slot_status(&mut cmd, /*slot=*/ 1, /*seq=*/ 0);

    // Send BULK_OUT request to usb-host: [opcode][slot_id][bytes].
    // slot_id here is usb-host's xHCI slot (also 1 for the only
    // device today); CCID's bSlot field is independent and lives
    // inside the payload bytes.
    let mut out_req = [0u8; 2 + ccid::CCID_HEADER_LEN];
    out_req[0] = OP_BULK_OUT;
    out_req[1] = 1; // usb-host slot_id
    out_req[2..].copy_from_slice(&cmd);

    let rc = sys::write(USB_HOST_ENDPOINT, &out_req);
    if rc < 0 {
        log_dec(b"[CCID]   bulk OUT write rc = -", -rc as u32);
        return;
    }

    // Wait for the reply on our endpoint.
    let bytes_written = match recv_reply_u16() {
        Some(n) => n,
        None => return,
    };
    sys::print(b"[CCID]   bulk OUT bytes written = ");
    log_dec(b"", bytes_written as u32);

    // BULK_IN request asking for a 10-byte response.
    let in_req = [
        OP_BULK_IN,
        1, // slot_id
        ccid::CCID_HEADER_LEN as u8, // requested_len lo
        0,                            // requested_len hi
    ];
    let rc = sys::write(USB_HOST_ENDPOINT, &in_req);
    if rc < 0 {
        log_dec(b"[CCID]   bulk IN write rc = -", -rc as u32);
        return;
    }

    // Receive the bulk IN reply: [status:1][actual_len:2][bytes:N].
    let mut recv_buf = [0u8; 36 + 3 + MAX_BULK_PAYLOAD];
    let n = sys::recv_msg(CCID_ENDPOINT, &mut recv_buf);
    if n < 0 {
        log_dec(b"[CCID]   recv_msg rc = -", -n as u32);
        return;
    }
    let n = n as usize;
    if n < 36 + 3 {
        sys::print(b"[CCID]   bulk IN reply truncated\n");
        return;
    }
    let payload = &recv_buf[36..n];
    let status = payload[0];
    if status != STATUS_OK {
        sys::print(b"[CCID]   bulk IN status = ");
        log_dec(b"", status as u32);
        return;
    }
    let actual_len =
        u16::from_le_bytes([payload[1], payload[2]]) as usize;
    sys::print(b"[CCID]   bulk IN bytes read = ");
    log_dec(b"", actual_len as u32);
    if 3 + actual_len > payload.len() {
        sys::print(b"[CCID]   bulk IN reply shorter than actual_len\n");
        return;
    }
    let resp_bytes = &payload[3..3 + actual_len];

    // Parse via cambios-ccid-proto.
    match ccid::decode_slot_status(resp_bytes) {
        Ok(s) => log_slot_status(&s),
        Err(_) => sys::print(b"[CCID]   decode_slot_status failed\n"),
    }
}

/// Receive a `[status:1][u16_le]` reply on our endpoint. Returns
/// the u16 on success; logs and returns `None` on any other shape.
fn recv_reply_u16() -> Option<u16> {
    let mut recv_buf = [0u8; 64];
    let n = sys::recv_msg(CCID_ENDPOINT, &mut recv_buf);
    if n < 0 {
        log_dec(b"[CCID]   recv_msg rc = -", -n as u32);
        return None;
    }
    let n = n as usize;
    if n < 36 + 3 {
        sys::print(b"[CCID]   reply truncated\n");
        return None;
    }
    let payload = &recv_buf[36..n];
    if payload[0] != STATUS_OK {
        sys::print(b"[CCID]   status = ");
        log_dec(b"", payload[0] as u32);
        return None;
    }
    Some(u16::from_le_bytes([payload[1], payload[2]]))
}

fn log_slot_status(s: &ccid::SlotStatus) {
    sys::print(b"[CCID]   bSlot = ");
    log_dec(b"", s.slot as u32);
    sys::print(b"[CCID]   bSeq = ");
    log_dec(b"", s.seq as u32);
    sys::print(b"[CCID]   bStatus = ");
    log_hex_byte(s.b_status);
    sys::print(b"[CCID]     ICC presence = ");
    match s.presence() {
        ccid::IccPresence::PresentActive => sys::print(b"present, active\n"),
        ccid::IccPresence::PresentInactive => sys::print(b"present, inactive\n"),
        ccid::IccPresence::Absent => sys::print(b"absent\n"),
        ccid::IccPresence::Reserved => sys::print(b"reserved\n"),
    }
    sys::print(b"[CCID]     command status = ");
    match s.command_status() {
        ccid::CommandStatus::Succeeded => sys::print(b"succeeded\n"),
        ccid::CommandStatus::Failed => sys::print(b"failed\n"),
        ccid::CommandStatus::TimeExtensionRequested =>
            sys::print(b"time extension requested\n"),
        ccid::CommandStatus::Reserved => sys::print(b"reserved\n"),
    }
    sys::print(b"[CCID]   bError = ");
    log_dec(b"", s.b_error as u32);
    sys::print(b"[CCID]   bClockStatus = ");
    log_dec(b"", s.b_clock_status as u32);
}

// ---------------------------------------------------------------------------
// Idle / future command surface
// ---------------------------------------------------------------------------

fn idle_loop() -> ! {
    // No client commands yet (PIV APDU dispatch lands in a future
    // substage). Drain any incoming messages and sleep.
    let mut recv_buf = [0u8; 256];
    loop {
        let n = sys::try_recv_msg(CCID_ENDPOINT, &mut recv_buf);
        if n <= 0 {
            sys::yield_now();
        }
    }
}

// ---------------------------------------------------------------------------
// Diagnostic logging
// ---------------------------------------------------------------------------

fn log_dec(label: &[u8], v: u32) {
    sys::print(label);
    let mut buf = [b'0'; 10];
    let mut i = 9usize;
    let mut n = v;
    if n == 0 {
        sys::print(b"0\n");
        return;
    }
    while n > 0 && i < buf.len() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if i == 0 { break; }
        i -= 1;
    }
    sys::print(&buf[i + 1..]);
    sys::print(b"\n");
}

fn log_hex_byte(b: u8) {
    let nibble = |n: u8| if n < 10 { b'0' + n } else { b'a' + (n - 10) };
    let out = [b'0', b'x', nibble(b >> 4), nibble(b & 0xF), b'\n'];
    sys::print(&out);
}
