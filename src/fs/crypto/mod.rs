// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Volume-layer cryptographic primitives — ADR-032.
//!
//! Today this module owns only the volume header parse + signature
//! verify primitives. The full FDE stack (XTS-AES-256 cipher,
//! `EncryptedBlockDevice<B>` decorator, mount path, credential
//! rotation, recovery slots) lands at later substages — see ADR-032
//! § Migration Path. Header verify is the first piece kernel-side
//! because A-iv's first-consumer flow needs it as a runtime test of
//! the new SwPivBackend-produced signatures.

pub mod aes_soft;
pub mod encrypted_device;
pub mod header;
