// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! PHY access for the I219-LM via the MDIC register.
//!
//! The integrated Lewisville PHY is accessed by writing to the MDIC
//! register, which generates an MDIO bus transaction. We poll for the
//! ready bit (R) to indicate completion.

use crate::mmio::{spin_delay, Mmio};
use crate::regs::*;

/// Maximum number of polls before giving up on a PHY transaction.
const PHY_POLL_MAX: u32 = 1000;

/// Read a 16-bit PHY register via MDIC.
///
/// Returns `Some(value)` on success, `None` on timeout or error.
pub fn phy_read(mmio: &Mmio, reg: u32) -> Option<u16> {
    let cmd = (reg << MDIC_REGADD_SHIFT)
        | (PHY_ADDR_I219 << MDIC_PHYADD_SHIFT)
        | MDIC_OP_READ;
    mmio.write32(REG_MDIC, cmd);

    for _ in 0..PHY_POLL_MAX {
        let v = mmio.read32(REG_MDIC);
        if v & MDIC_E != 0 {
            return None;
        }
        if v & MDIC_R != 0 {
            return Some((v & MDIC_DATA_MASK) as u16);
        }
        spin_delay(50);
    }
    None
}

/// Write a 16-bit value to a PHY register via MDIC.
///
/// Returns `true` on success, `false` on timeout or error.
pub fn phy_write(mmio: &Mmio, reg: u32, value: u16) -> bool {
    let cmd = (value as u32 & MDIC_DATA_MASK)
        | (reg << MDIC_REGADD_SHIFT)
        | (PHY_ADDR_I219 << MDIC_PHYADD_SHIFT)
        | MDIC_OP_WRITE;
    mmio.write32(REG_MDIC, cmd);

    for _ in 0..PHY_POLL_MAX {
        let v = mmio.read32(REG_MDIC);
        if v & MDIC_E != 0 {
            return false;
        }
        if v & MDIC_R != 0 {
            return true;
        }
        spin_delay(50);
    }
    false
}

/// Wait for link to come up. Returns true if link reached up state
/// within the timeout, false otherwise.
///
/// On real hardware, link bringup typically takes 1-3 seconds after
/// CTRL.SLU is set, depending on auto-negotiation with the switch.
pub fn wait_for_link(mmio: &Mmio, timeout_iters: u32) -> bool {
    for _ in 0..timeout_iters {
        let status = mmio.read32(REG_STATUS);
        if status & STATUS_LU != 0 {
            return true;
        }
        spin_delay(10000);
    }
    false
}
