// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! HID boot-protocol keyboard reports → key transitions.
//!
//! Pure logic: no syscalls, no MMIO. The boot keyboard report (HID
//! 1.11 Appendix B.1) is 8 bytes — a modifier bitmap, a reserved
//! byte, and up to six concurrently pressed key usages. The device
//! reports *state*, not events; this module diffs consecutive
//! reports into the key-down / key-up transitions the ADR-012 wire
//! format carries.

/// HARDWARE: boot-protocol keyboard report length (HID 1.11 § B.1).
pub const BOOT_REPORT_LEN: usize = 8;

/// HARDWARE: key usages in a boot report (HID 1.11 § B.1).
const BOOT_REPORT_KEYS: usize = 6;

/// HARDWARE: usage of the first modifier key (Left Control, HID Usage
/// Tables § 10); modifier bit `i` of the report is usage `0xE0 + i`.
const MODIFIER_USAGE_BASE: u8 = 0xE0;

/// HARDWARE: the "ErrorRollOver" usage a boot keyboard fills every
/// key slot with when more keys are held than it can report (HID
/// Usage Tables § 10). Such a report carries no key state.
const USAGE_ERROR_ROLLOVER: u8 = 0x01;

/// Upper bound on transitions one report can produce: every modifier
/// bit and every key slot flipping at once.
pub const MAX_TRANSITIONS: usize = 8 + 2 * BOOT_REPORT_KEYS;

/// One key transition. `usage` is the USB HID usage (page 7), the
/// vocabulary ADR-012 commits `InputEvent.keycode` to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyTransition {
    Down(u8),
    Up(u8),
}

/// Last report seen, so the next one can be diffed against it.
#[derive(Clone, Copy, Debug, Default)]
pub struct BootKeyboardState {
    modifiers: u8,
    keys: [u8; BOOT_REPORT_KEYS],
}

impl BootKeyboardState {
    pub const fn new() -> Self {
        Self { modifiers: 0, keys: [0; BOOT_REPORT_KEYS] }
    }

    /// The modifier bitmap of the most recent report, in the HID
    /// modifier-byte layout `libinput-proto::modifier` mirrors.
    pub fn modifiers(&self) -> u8 {
        self.modifiers
    }

    /// Diff `report` against the previous one, writing transitions
    /// into `out` (modifier changes first, then releases, then
    /// presses) and returning how many were written. A rollover
    /// report leaves the state untouched and yields nothing.
    pub fn apply(
        &mut self,
        report: &[u8; BOOT_REPORT_LEN],
        out: &mut [KeyTransition; MAX_TRANSITIONS],
    ) -> usize {
        let new_mods = report[0];
        let new_keys: [u8; BOOT_REPORT_KEYS] = [
            report[2], report[3], report[4], report[5], report[6], report[7],
        ];
        if new_keys.iter().all(|&k| k == USAGE_ERROR_ROLLOVER) {
            return 0;
        }

        let mut n = 0;
        for bit in 0..8u8 {
            let mask = 1u8 << bit;
            let was = self.modifiers & mask != 0;
            let is = new_mods & mask != 0;
            if was != is {
                let usage = MODIFIER_USAGE_BASE + bit;
                out[n] = if is { KeyTransition::Down(usage) } else { KeyTransition::Up(usage) };
                n += 1;
            }
        }
        for &k in self.keys.iter() {
            if k != 0 && !new_keys.contains(&k) {
                out[n] = KeyTransition::Up(k);
                n += 1;
            }
        }
        for &k in new_keys.iter() {
            if k != 0 && !self.keys.contains(&k) {
                out[n] = KeyTransition::Down(k);
                n += 1;
            }
        }
        self.modifiers = new_mods;
        self.keys = new_keys;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(state: &mut BootKeyboardState, report: [u8; 8]) -> ([KeyTransition; MAX_TRANSITIONS], usize) {
        let mut out = [KeyTransition::Up(0); MAX_TRANSITIONS];
        let n = state.apply(&report, &mut out);
        (out, n)
    }

    #[test]
    fn press_and_release_one_key() {
        let mut st = BootKeyboardState::new();
        let (out, n) = apply(&mut st, [0, 0, 0x04, 0, 0, 0, 0, 0]);
        assert_eq!(&out[..n], &[KeyTransition::Down(0x04)]);
        let (out, n) = apply(&mut st, [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&out[..n], &[KeyTransition::Up(0x04)]);
    }

    #[test]
    fn held_key_does_not_repeat_across_reports() {
        let mut st = BootKeyboardState::new();
        apply(&mut st, [0, 0, 0x04, 0, 0, 0, 0, 0]);
        let (_, n) = apply(&mut st, [0, 0, 0x04, 0, 0, 0, 0, 0]);
        assert_eq!(n, 0);
    }

    #[test]
    fn shift_then_key_orders_modifier_first() {
        let mut st = BootKeyboardState::new();
        let (out, n) = apply(&mut st, [0x02, 0, 0x04, 0, 0, 0, 0, 0]);
        assert_eq!(&out[..n], &[KeyTransition::Down(0xE1), KeyTransition::Down(0x04)]);
        assert_eq!(st.modifiers(), 0x02);
        let (out, n) = apply(&mut st, [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&out[..n], &[KeyTransition::Up(0xE1), KeyTransition::Up(0x04)]);
    }

    #[test]
    fn key_slot_reorder_is_not_a_transition() {
        let mut st = BootKeyboardState::new();
        apply(&mut st, [0, 0, 0x04, 0x05, 0, 0, 0, 0]);
        let (_, n) = apply(&mut st, [0, 0, 0x05, 0x04, 0, 0, 0, 0]);
        assert_eq!(n, 0);
    }

    #[test]
    fn rollover_report_is_ignored() {
        let mut st = BootKeyboardState::new();
        apply(&mut st, [0, 0, 0x04, 0, 0, 0, 0, 0]);
        let (_, n) = apply(&mut st, [0, 0, 1, 1, 1, 1, 1, 1]);
        assert_eq!(n, 0);
        let (out, n) = apply(&mut st, [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&out[..n], &[KeyTransition::Up(0x04)]);
    }

    #[test]
    fn everything_at_once_fits_the_bound() {
        let mut st = BootKeyboardState::new();
        apply(&mut st, [0, 0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        let (_, n) = apply(&mut st, [0xFF, 0, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
        assert_eq!(n, MAX_TRANSITIONS);
    }
}
