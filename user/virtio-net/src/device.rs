// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Device value validation — treats all hardware-returned values as hostile.
//!
//! Every value read from device memory (used ring indices, descriptor lengths,
//! etc.) must pass through validation before use. A `DeviceValue<T>` cannot be
//! used as `T` without explicit bounds checking via `.validate()`.

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

    /// Get the raw value (for logging/debugging only — not for indexing).
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
