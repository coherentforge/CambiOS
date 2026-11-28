// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Link state for the I219-LM.
//!
//! The MAC's STATUS register reports link-up (LU) once the integrated PHY
//! has negotiated with the switch; this module waits for it. The driver
//! reads no PHY register directly: MDIC access (the MDIO transaction
//! register, bits in `regs.rs`) has no caller and is not implemented.

use crate::mmio::{spin_delay, Mmio};
use crate::regs::*;

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
