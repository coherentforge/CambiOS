// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! USB-2.0 descriptor parsing.
//!
//! Pure functions over a configuration-descriptor blob returned by
//! GET_DESCRIPTOR(Configuration). The blob is variable-length and
//! contains a sequence of typed descriptors per USB 2.0 § 9.5:
//!
//!   - Configuration Descriptor   (type 2, 9 bytes)
//!   - one or more Interface      (type 4, 9 bytes) followed by
//!       - zero or more Endpoint  (type 5, 7 bytes)
//!       - zero or more class-specific descriptors (CCID functional,
//!         HID, etc. — variable length, skipped via bLength)
//!
//! No syscalls, no MMIO. Anything that touches the controller belongs
//! in `xhci.rs`; this module is the boundary between the wire format
//! and the rest of the driver.

/// USB descriptor type bytes (USB 2.0 § 9.4 + Table 9-5).
pub mod desc_type {
    pub const CONFIGURATION: u8 = 0x02;
    pub const INTERFACE: u8 = 0x04;
    pub const ENDPOINT: u8 = 0x05;
}

/// USB class codes (usb.org assignments).
pub mod usb_class {
    /// Smart Card / CCID — USB-IF base class assignment.
    /// CCID 1.1 specification § 4.
    pub const CCID: u8 = 0x0B;
}

/// USB endpoint direction (USB 2.0 § 9.6.6, bEndpointAddress bit 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointDirection {
    Out,
    In,
}

/// USB endpoint transfer type (USB 2.0 § 9.6.6, bmAttributes bits [1:0]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

/// Parsed Configuration Descriptor (USB 2.0 § 9.6.3).
#[derive(Clone, Copy, Debug)]
pub struct ConfigurationDescriptor {
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
}

/// Parsed Interface Descriptor (USB 2.0 § 9.6.5).
#[derive(Clone, Copy, Debug)]
pub struct InterfaceDescriptor {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
}

/// Parsed Endpoint Descriptor (USB 2.0 § 9.6.6).
#[derive(Clone, Copy, Debug)]
pub struct EndpointDescriptor {
    /// Raw bEndpointAddress byte. Endpoint number is bits [3:0];
    /// direction is bit [7]. Use `endpoint_number()` + `direction()`.
    pub address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl EndpointDescriptor {
    pub fn endpoint_number(&self) -> u8 {
        self.address & 0x0F
    }

    pub fn direction(&self) -> EndpointDirection {
        if self.address & 0x80 != 0 {
            EndpointDirection::In
        } else {
            EndpointDirection::Out
        }
    }

    pub fn transfer_type(&self) -> EndpointType {
        match self.attributes & 0x03 {
            0 => EndpointType::Control,
            1 => EndpointType::Isochronous,
            2 => EndpointType::Bulk,
            _ => EndpointType::Interrupt,
        }
    }

    /// Max Packet Size field bits [10:0] (USB 2.0 § 9.6.6).
    /// Bits [12:11] are additional-transactions-per-microframe (HS
    /// only); the bulk path always reads via [10:0].
    pub fn max_packet_size_bytes(&self) -> u16 {
        self.max_packet_size & 0x07FF
    }
}

/// CCID interface + bulk endpoints found in a parsed config blob.
#[derive(Clone, Copy, Debug)]
pub struct CcidEndpoints {
    pub configuration_value: u8,
    pub interface_number: u8,
    pub bulk_in: EndpointDescriptor,
    pub bulk_out: EndpointDescriptor,
}

/// Errors surfaced by the configuration-descriptor blob walk.
#[derive(Clone, Copy, Debug)]
pub enum DescriptorError {
    /// Blob is shorter than a single Configuration Descriptor (9 bytes).
    TooShort,
    /// First descriptor in the blob isn't a Configuration Descriptor.
    NotConfiguration,
    /// `wTotalLength` doesn't match the blob length the caller passed
    /// in — partial read or corrupt response.
    TotalLengthMismatch { declared: u16, actual: usize },
    /// A descriptor's `bLength` field is zero (would cause infinite
    /// loop in a length-driven walk) or runs off the end of the blob.
    BadLength,
    /// No interface with `bInterfaceClass = 0x0B` (CCID) found, or
    /// the matching interface lacks the required bulk IN + bulk OUT
    /// endpoint pair.
    NoCcidInterface,
}

/// Parse the top-level Configuration Descriptor from a blob and return
/// `(parsed, remaining_bytes_after_config_desc)`. The remaining bytes
/// hold the nested Interface + Endpoint descriptors.
pub fn parse_configuration(
    blob: &[u8],
) -> Result<(ConfigurationDescriptor, &[u8]), DescriptorError> {
    if blob.len() < 9 {
        return Err(DescriptorError::TooShort);
    }
    if blob[1] != desc_type::CONFIGURATION {
        return Err(DescriptorError::NotConfiguration);
    }
    let b_length = blob[0] as usize;
    if b_length != 9 || b_length > blob.len() {
        return Err(DescriptorError::BadLength);
    }
    let total_length = u16::from_le_bytes([blob[2], blob[3]]);
    if total_length as usize != blob.len() {
        return Err(DescriptorError::TotalLengthMismatch {
            declared: total_length,
            actual: blob.len(),
        });
    }
    Ok((
        ConfigurationDescriptor {
            total_length,
            num_interfaces: blob[4],
            configuration_value: blob[5],
        },
        &blob[b_length..],
    ))
}

/// Parse a 9-byte Interface Descriptor starting at the head of `blob`.
fn parse_interface(blob: &[u8]) -> Result<InterfaceDescriptor, DescriptorError> {
    if blob.len() < 9 {
        return Err(DescriptorError::BadLength);
    }
    Ok(InterfaceDescriptor {
        interface_number: blob[2],
        alternate_setting: blob[3],
        num_endpoints: blob[4],
        interface_class: blob[5],
        interface_subclass: blob[6],
        interface_protocol: blob[7],
    })
}

/// Parse a 7-byte Endpoint Descriptor starting at the head of `blob`.
fn parse_endpoint(blob: &[u8]) -> Result<EndpointDescriptor, DescriptorError> {
    if blob.len() < 7 {
        return Err(DescriptorError::BadLength);
    }
    Ok(EndpointDescriptor {
        address: blob[2],
        attributes: blob[3],
        max_packet_size: u16::from_le_bytes([blob[4], blob[5]]),
        interval: blob[6],
    })
}

/// Walk the post-Configuration-Descriptor body of a config blob and
/// return the first CCID interface together with its bulk IN + bulk
/// OUT endpoints.
///
/// Class-specific descriptors (CCID functional descriptor type 0x21,
/// etc.) between an Interface Descriptor and its endpoints are
/// skipped via their `bLength` field.
pub fn find_ccid_interface(blob: &[u8]) -> Result<CcidEndpoints, DescriptorError> {
    let (config, mut body) = parse_configuration(blob)?;
    let mut current_iface: Option<InterfaceDescriptor> = None;
    let mut bulk_in: Option<EndpointDescriptor> = None;
    let mut bulk_out: Option<EndpointDescriptor> = None;
    let mut current_is_ccid: bool = false;

    while !body.is_empty() {
        // Every descriptor has bLength at offset 0 and bDescriptorType
        // at offset 1 (USB 2.0 § 9.5). Length must be non-zero and
        // must fit the remaining blob.
        let b_length = body[0] as usize;
        if b_length == 0 || b_length > body.len() {
            return Err(DescriptorError::BadLength);
        }
        let b_type = body[1];
        match b_type {
            desc_type::INTERFACE => {
                // Stash the previous interface's findings before
                // starting a new one. CCID interface with both bulk
                // endpoints already found short-circuits the walk.
                if current_is_ccid && bulk_in.is_some() && bulk_out.is_some() {
                    break;
                }
                let iface = parse_interface(&body[..b_length])?;
                current_is_ccid = iface.interface_class == usb_class::CCID;
                current_iface = Some(iface);
                // Reset endpoint search for the new interface.
                if current_is_ccid {
                    bulk_in = None;
                    bulk_out = None;
                }
            }
            desc_type::ENDPOINT if current_is_ccid => {
                let ep = parse_endpoint(&body[..b_length])?;
                if ep.transfer_type() == EndpointType::Bulk {
                    match ep.direction() {
                        EndpointDirection::In => {
                            if bulk_in.is_none() {
                                bulk_in = Some(ep);
                            }
                        }
                        EndpointDirection::Out => {
                            if bulk_out.is_none() {
                                bulk_out = Some(ep);
                            }
                        }
                    }
                }
            }
            _ => {
                // Class-specific, interrupt-endpoint, or unrelated
                // descriptor — skip via bLength.
            }
        }
        body = &body[b_length..];
    }

    match (current_iface, current_is_ccid, bulk_in, bulk_out) {
        (Some(iface), true, Some(b_in), Some(b_out)) => Ok(CcidEndpoints {
            configuration_value: config.configuration_value,
            interface_number: iface.interface_number,
            bulk_in: b_in,
            bulk_out: b_out,
        }),
        _ => Err(DescriptorError::NoCcidInterface),
    }
}
