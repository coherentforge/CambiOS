// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors

//! The pure parts of usb-host: the configuration-descriptor walk and the
//! HID boot-keyboard report decoder. A library target so their tests run
//! on the host (`make host-test-user-usb-host`); the driver binary uses
//! them from here. Nothing in either module touches hardware or libsys.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod descriptors;
pub mod hid_kbd;
