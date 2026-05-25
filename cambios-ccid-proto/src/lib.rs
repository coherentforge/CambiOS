// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! USB CCID 1.1 message format encoders + decoders.
//!
//! The USB Integrated Circuit Card Devices class specification ("CCID
//! 1.1", April 22 2005) defines two families of 10-byte-headered
//! messages:
//!
//!   - `PC_to_RDR_*` — host-to-device requests (bulk OUT, § 6.1)
//!   - `RDR_to_PC_*` — device-to-host responses (bulk IN, § 6.2)
//!
//! Every message starts with a fixed 10-byte header
//! `[bMessageType][dwLength:4][bSlot][bSeq][3 RFU bytes]` followed by
//! a per-message-type variable-length data block whose length is
//! given by `dwLength` (little-endian).
//!
//! This crate is the wire-format contract layer for any CambiOS
//! component that speaks CCID — `user/ccid` ships PC_to_RDR_*
//! messages over usb-host's bulk transport and parses RDR_to_PC_*
//! responses; `user/key-store-service`'s `PivBackend::CcidPiv` (post
//! B-ix) consumes the same encoders via IPC to `user/ccid`. The
//! crate has no transport assumptions and no dependencies beyond
//! `core`.

#![no_std]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of the fixed CCID message header (CCID 1.1 § 6.1, § 6.2).
pub const CCID_HEADER_LEN: usize = 10;

/// `bMessageType` values used by the messages this crate encodes /
/// decodes. The full set spans CCID 1.1 § 6.1 + § 6.2; values land
/// here as consumers need them.
pub mod message_type {
    // PC_to_RDR (host-to-device)
    pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
    pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
    pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
    pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;

    // RDR_to_PC (device-to-host)
    pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
    pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
}

// ---------------------------------------------------------------------------
// Slot status (CCID 1.1 § 6.2.1 + § 6.2.2)
// ---------------------------------------------------------------------------

/// ICC presence reported by RDR_to_PC bStatus[1:0] (CCID 1.1
/// § 6.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IccPresence {
    /// ICC is present and in an active state.
    PresentActive,
    /// ICC is present but inactive (no power applied).
    PresentInactive,
    /// No ICC is present in the slot.
    Absent,
    /// Reserved / future-use value (RFU bits set).
    Reserved,
}

impl IccPresence {
    /// Decode `IccPresence` from a `bStatus` byte (CCID 1.1 § 6.2.1).
    /// Only the low 2 bits carry the presence value; higher bits
    /// carry command-status fields the caller handles separately.
    pub fn from_status_byte(b_status: u8) -> Self {
        match b_status & 0x03 {
            0 => Self::PresentActive,
            1 => Self::PresentInactive,
            2 => Self::Absent,
            _ => Self::Reserved,
        }
    }
}

/// Command status reported by RDR_to_PC bStatus[7:6] (CCID 1.1
/// § 6.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    /// Processed without error.
    Succeeded,
    /// Failed; the error code is in bError.
    Failed,
    /// Time extension is requested by the slot.
    TimeExtensionRequested,
    /// Reserved / future-use.
    Reserved,
}

impl CommandStatus {
    pub fn from_status_byte(b_status: u8) -> Self {
        match (b_status >> 6) & 0x03 {
            0 => Self::Succeeded,
            1 => Self::Failed,
            2 => Self::TimeExtensionRequested,
            _ => Self::Reserved,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes for decoding RDR_to_PC responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer shorter than `CCID_HEADER_LEN` (10 bytes).
    Truncated,
    /// `bMessageType` doesn't match the expected response type.
    WrongMessageType { expected: u8, actual: u8 },
    /// `dwLength` says more data follows than the buffer can hold.
    DataBlockTooShort { declared: u32, actual: usize },
}

// ---------------------------------------------------------------------------
// PC_to_RDR_GetSlotStatus (CCID 1.1 § 6.1.6)
// ---------------------------------------------------------------------------

/// Encode a PC_to_RDR_GetSlotStatus message into `out` (must be at
/// least 10 bytes long). Returns the number of bytes written (10).
///
///   byte 0     : bMessageType = 0x65
///   bytes 1-4  : dwLength = 0 (LE)
///   byte 5     : bSlot
///   byte 6     : bSeq
///   bytes 7-9  : abRFU = 0
pub fn encode_get_slot_status(out: &mut [u8], slot: u8, seq: u8) -> usize {
    debug_assert!(out.len() >= CCID_HEADER_LEN);
    out[0] = message_type::PC_TO_RDR_GET_SLOT_STATUS;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = 0;
    out[5] = slot;
    out[6] = seq;
    out[7] = 0;
    out[8] = 0;
    out[9] = 0;
    CCID_HEADER_LEN
}

// ---------------------------------------------------------------------------
// RDR_to_PC_SlotStatus (CCID 1.1 § 6.2.2)
// ---------------------------------------------------------------------------

/// Decoded RDR_to_PC_SlotStatus response (CCID 1.1 § 6.2.2).
#[derive(Clone, Copy, Debug)]
pub struct SlotStatus {
    pub slot: u8,
    pub seq: u8,
    /// Raw `bStatus` byte; use `presence()` + `command_status()` to
    /// decode the sub-fields.
    pub b_status: u8,
    /// `bError` byte. Meaningful only when `command_status() ==
    /// Failed`; per CCID 1.1 § 6.2.6 it carries the per-slot error
    /// code (1 = ICC_MUTE, 2 = XFR_PARITY_ERROR, etc.).
    pub b_error: u8,
    /// `bClockStatus` (CCID 1.1 § 6.2.2): 0 = running, 1 = stopped
    /// in L state, 2 = stopped in H state, 3 = stopped (unknown).
    pub b_clock_status: u8,
}

impl SlotStatus {
    pub fn presence(&self) -> IccPresence {
        IccPresence::from_status_byte(self.b_status)
    }

    pub fn command_status(&self) -> CommandStatus {
        CommandStatus::from_status_byte(self.b_status)
    }
}

/// Decode a RDR_to_PC_SlotStatus response from a bulk IN buffer.
/// Validates the message type and length fields; returns the parsed
/// fields. The 10-byte SlotStatus message has `dwLength = 0` (no
/// data block follows).
pub fn decode_slot_status(buf: &[u8]) -> Result<SlotStatus, DecodeError> {
    if buf.len() < CCID_HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    let b_message_type = buf[0];
    if b_message_type != message_type::RDR_TO_PC_SLOT_STATUS {
        return Err(DecodeError::WrongMessageType {
            expected: message_type::RDR_TO_PC_SLOT_STATUS,
            actual: b_message_type,
        });
    }
    let dw_length = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if dw_length as usize + CCID_HEADER_LEN > buf.len() {
        return Err(DecodeError::DataBlockTooShort {
            declared: dw_length,
            actual: buf.len(),
        });
    }
    Ok(SlotStatus {
        slot: buf[5],
        seq: buf[6],
        b_status: buf[7],
        b_error: buf[8],
        b_clock_status: buf[9],
    })
}

// ---------------------------------------------------------------------------
// Host tests (pure functions — host-runnable via cargo test)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_slot_status_encodes_canonical_10_bytes() {
        let mut buf = [0xFFu8; 10];
        let n = encode_get_slot_status(&mut buf, 0, 0);
        assert_eq!(n, 10);
        assert_eq!(buf, [0x65, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn get_slot_status_threads_slot_and_seq() {
        let mut buf = [0u8; 10];
        encode_get_slot_status(&mut buf, 3, 7);
        assert_eq!(buf[5], 3);
        assert_eq!(buf[6], 7);
    }

    #[test]
    fn slot_status_decodes_qemu_absent_response() {
        // The exact 10-byte response observed from QEMU's usb-ccid
        // at the end of B-vi.c: bMessageType=0x81, bSlot=0, bSeq=0,
        // bStatus=0x02 (ICC absent), bError=0, bClockStatus=0.
        let resp = [0x81, 0, 0, 0, 0, 0, 0, 0x02, 0, 0];
        let s = decode_slot_status(&resp).unwrap();
        assert_eq!(s.slot, 0);
        assert_eq!(s.seq, 0);
        assert_eq!(s.b_status, 0x02);
        assert_eq!(s.presence(), IccPresence::Absent);
        assert_eq!(s.command_status(), CommandStatus::Succeeded);
    }

    #[test]
    fn slot_status_decode_rejects_short_buffer() {
        let too_short = [0x81u8; 9];
        match decode_slot_status(&too_short) {
            Err(DecodeError::Truncated) => {}
            other => panic!("expected Truncated, got {:?}", other),
        }
    }

    #[test]
    fn slot_status_decode_rejects_wrong_message_type() {
        // bMessageType = 0x80 (DataBlock), not 0x81 (SlotStatus).
        let mistyped = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        match decode_slot_status(&mistyped) {
            Err(DecodeError::WrongMessageType { expected: 0x81, actual: 0x80 }) => {}
            other => panic!("expected WrongMessageType, got {:?}", other),
        }
    }

    #[test]
    fn icc_presence_decodes_all_two_bit_values() {
        assert_eq!(IccPresence::from_status_byte(0b00), IccPresence::PresentActive);
        assert_eq!(IccPresence::from_status_byte(0b01), IccPresence::PresentInactive);
        assert_eq!(IccPresence::from_status_byte(0b10), IccPresence::Absent);
        assert_eq!(IccPresence::from_status_byte(0b11), IccPresence::Reserved);
        // Upper bits ignored.
        assert_eq!(IccPresence::from_status_byte(0xFE), IccPresence::Absent);
    }

    #[test]
    fn command_status_decodes_all_two_bit_values() {
        assert_eq!(CommandStatus::from_status_byte(0b00_000_000), CommandStatus::Succeeded);
        assert_eq!(CommandStatus::from_status_byte(0b01_000_000), CommandStatus::Failed);
        assert_eq!(CommandStatus::from_status_byte(0b10_000_000), CommandStatus::TimeExtensionRequested);
        assert_eq!(CommandStatus::from_status_byte(0b11_000_000), CommandStatus::Reserved);
    }
}
