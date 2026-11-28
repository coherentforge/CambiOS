// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors

//! The pure part of virtio-input: the Linux evdev to USB HID usage map. A
//! library target so its tests run on the host
//! (`make host-test-user-virtio-input`); the driver binary uses it from
//! here.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod evdev;
