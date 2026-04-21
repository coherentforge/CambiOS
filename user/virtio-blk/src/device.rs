// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Device value validation — treats all hardware-returned values as hostile.
//!
//! Structurally identical to `user/virtio-net/src/device.rs`. Every value read
//! from device memory (used ring indices, descriptor lengths, virtio-blk
//! status byte) must pass through validation before use.

/// A value read from device memory. Cannot be used without validation.
#[derive(Clone, Copy)]
pub struct DeviceValue<T: Copy> {
    raw: T,
}

impl<T: Copy> DeviceValue<T> {
    /// Wrap a raw value from device memory.
    pub fn new(raw: T) -> Self {
        Self { raw }
    }

    /// Get the raw value (for logging / status-byte comparison only — not for
    /// indexing arrays or arithmetic that would be injection-sensitive).
    pub fn raw(self) -> T {
        self.raw
    }
}

impl DeviceValue<u16> {
    /// Validate that the value is strictly less than `limit`.
    /// Returns `Some(value)` if valid, `None` if the device returned garbage.
    pub fn validate_index(self, limit: u16) -> Option<u16> {
        if self.raw < limit {
            Some(self.raw)
        } else {
            None
        }
    }
}

impl DeviceValue<u32> {
    /// Validate that the value does not exceed `max_len`.
    /// Returns the clamped length (never exceeds the buffer we actually gave).
    pub fn clamp_length(self, max_len: u32) -> u32 {
        if self.raw <= max_len {
            self.raw
        } else {
            max_len
        }
    }
}
