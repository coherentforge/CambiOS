// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Intel I219-LM register offsets and bit definitions.
//!
//! Subset of the e1000e register space — only what the driver actually
//! touches. Reference: Intel I219 Software Developer's Manual.
//!
//! All offsets are in bytes from the MMIO BAR0 base.

#![allow(dead_code)]

// ============================================================================
// Control / Status registers
// ============================================================================

/// Device Control register (RW).
pub const REG_CTRL: u32 = 0x00000;
/// Device Status register (RO).
pub const REG_STATUS: u32 = 0x00008;
/// Extended Device Control (RW).
pub const REG_CTRL_EXT: u32 = 0x00018;
/// MDI Control register (RW) — used to access PHY registers.
pub const REG_MDIC: u32 = 0x00020;
/// Flow Control Address Low (RW).
pub const REG_FCAL: u32 = 0x00028;
/// Flow Control Address High (RW).
pub const REG_FCAH: u32 = 0x0002C;
/// Flow Control Type (RW).
pub const REG_FCT: u32 = 0x00030;

// CTRL bits
pub const CTRL_FD: u32 = 1 << 0; // Full-Duplex
pub const CTRL_ASDE: u32 = 1 << 5; // Auto-Speed Detection Enable
pub const CTRL_SLU: u32 = 1 << 6; // Set Link Up
pub const CTRL_RST: u32 = 1 << 26; // Device Reset
pub const CTRL_PHY_RST: u32 = 1 << 31; // PHY Reset

// STATUS bits
pub const STATUS_FD: u32 = 1 << 0; // Full-Duplex
pub const STATUS_LU: u32 = 1 << 1; // Link Up

// ============================================================================
// Interrupt registers
// ============================================================================

/// Interrupt Cause Read (RC) — reading clears.
pub const REG_ICR: u32 = 0x000C0;
/// Interrupt Mask Set/Read (RW).
pub const REG_IMS: u32 = 0x000D0;
/// Interrupt Mask Clear (WO).
pub const REG_IMC: u32 = 0x000D8;

// ICR/IMS bits
pub const INT_TXDW: u32 = 1 << 0; // TX Descriptor Written Back
pub const INT_TXQE: u32 = 1 << 1; // TX Queue Empty
pub const INT_LSC: u32 = 1 << 2; // Link Status Change
pub const INT_RXDMT0: u32 = 1 << 4; // RX Descriptor Min Threshold
pub const INT_RXO: u32 = 1 << 6; // RX Overrun
pub const INT_RXT0: u32 = 1 << 7; // RX Timer Interrupt

// ============================================================================
// Receive control / descriptor ring
// ============================================================================

/// Receive Control (RW).
pub const REG_RCTL: u32 = 0x00100;
/// RX Descriptor Base Address Low (queue 0).
pub const REG_RDBAL: u32 = 0x02800;
/// RX Descriptor Base Address High (queue 0).
pub const REG_RDBAH: u32 = 0x02804;
/// RX Descriptor Length (queue 0) — total ring size in bytes.
pub const REG_RDLEN: u32 = 0x02808;
/// RX Descriptor Head (queue 0) — written by hardware.
pub const REG_RDH: u32 = 0x02810;
/// RX Descriptor Tail (queue 0) — written by software.
pub const REG_RDT: u32 = 0x02818;

// RCTL bits
pub const RCTL_EN: u32 = 1 << 1; // Receiver Enable
pub const RCTL_SBP: u32 = 1 << 2; // Store Bad Packets
pub const RCTL_UPE: u32 = 1 << 3; // Unicast Promiscuous Enable
pub const RCTL_MPE: u32 = 1 << 4; // Multicast Promiscuous Enable
pub const RCTL_LPE: u32 = 1 << 5; // Long Packet Enable
pub const RCTL_BAM: u32 = 1 << 15; // Broadcast Accept Mode
pub const RCTL_BSIZE_2048: u32 = 0; // BSIZE=00 → 2048 bytes
pub const RCTL_SECRC: u32 = 1 << 26; // Strip Ethernet CRC

// ============================================================================
// Transmit control / descriptor ring
// ============================================================================

/// Transmit Control (RW).
pub const REG_TCTL: u32 = 0x00400;
/// Transmit IPG (RW).
pub const REG_TIPG: u32 = 0x00410;
/// TX Descriptor Base Address Low (queue 0).
pub const REG_TDBAL: u32 = 0x03800;
/// TX Descriptor Base Address High (queue 0).
pub const REG_TDBAH: u32 = 0x03804;
/// TX Descriptor Length (queue 0) — total ring size in bytes.
pub const REG_TDLEN: u32 = 0x03808;
/// TX Descriptor Head (queue 0) — written by hardware.
pub const REG_TDH: u32 = 0x03810;
/// TX Descriptor Tail (queue 0) — written by software.
pub const REG_TDT: u32 = 0x03818;

// TCTL bits
pub const TCTL_EN: u32 = 1 << 1; // Transmitter Enable
pub const TCTL_PSP: u32 = 1 << 3; // Pad Short Packets
pub const TCTL_CT_SHIFT: u32 = 4; // Collision Threshold shift
pub const TCTL_COLD_SHIFT: u32 = 12; // Collision Distance shift

// ============================================================================
// MAC address registers (Receive Address Low/High array)
// ============================================================================

/// Receive Address Low 0 — bits [31:0] of the primary MAC.
pub const REG_RAL0: u32 = 0x05400;
/// Receive Address High 0 — bits [47:32] + AV (valid) + ASEL fields.
pub const REG_RAH0: u32 = 0x05404;

/// Address Valid bit in RAH.
pub const RAH_AV: u32 = 1 << 31;

// ============================================================================
// Multicast Table Array (MTA)
// ============================================================================

/// MTA base — 128 entries, each 32 bits. Cleared at init.
pub const REG_MTA_BASE: u32 = 0x05200;
pub const MTA_ENTRIES: u32 = 128;

// ============================================================================
// TX descriptor format (legacy 16-byte)
// ============================================================================

/// Legacy 16-byte TX descriptor.
///
/// ```text
/// Offset  Size  Field
/// 0       8     Buffer address (physical)
/// 8       2     Length
/// 10      1     CSO (checksum offset)
/// 11      1     CMD
/// 12      1     STA (lower nibble) | RSV (upper nibble)
/// 13      1     CSS (checksum start)
/// 14      2     Special (VLAN tag)
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TxDesc {
    pub addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

// TX CMD bits
pub const TX_CMD_EOP: u8 = 1 << 0; // End Of Packet
pub const TX_CMD_IFCS: u8 = 1 << 1; // Insert FCS
pub const TX_CMD_RS: u8 = 1 << 3; // Report Status

// TX STATUS bits
pub const TX_STATUS_DD: u8 = 1 << 0; // Descriptor Done

// ============================================================================
// RX descriptor format (legacy 16-byte)
// ============================================================================

/// Legacy 16-byte RX descriptor.
///
/// ```text
/// Offset  Size  Field
/// 0       8     Buffer address (physical, written by software)
/// 8       2     Length (written by hardware on receive)
/// 10      2     Packet checksum
/// 12      1     STATUS (DD bit etc.)
/// 13      1     ERRORS
/// 14      2     VLAN tag
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct RxDesc {
    pub addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

// RX STATUS bits
pub const RX_STATUS_DD: u8 = 1 << 0; // Descriptor Done
pub const RX_STATUS_EOP: u8 = 1 << 1; // End Of Packet

// ============================================================================
// MDIC bits — for PHY register access
// ============================================================================

pub const MDIC_DATA_MASK: u32 = 0xFFFF;
pub const MDIC_REGADD_SHIFT: u32 = 16;
pub const MDIC_PHYADD_SHIFT: u32 = 21;
pub const MDIC_OP_WRITE: u32 = 1 << 26;
pub const MDIC_OP_READ: u32 = 2 << 26;
pub const MDIC_R: u32 = 1 << 28; // Ready
pub const MDIC_E: u32 = 1 << 30; // Error

/// Standard PHY address for I219 integrated PHY.
pub const PHY_ADDR_I219: u32 = 1;
