// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Structured-output helpers.
//!
//! - [`principal_short`] — render a Principal as a short did:key
//!   identifier suitable for prompts and listings.
//! - [`key_value`] — lay out a padded `key: value` line for help and
//!   info dumps; the key is dim-styled in line with the prompt's
//!   visual hierarchy.
//!
//! Both helpers are alloc-free. `principal_short` returns an owned
//! [`DidShort`] (a stack buffer); `key_value` returns a [`KeyValue`]
//! that borrows from its inputs and renders on demand.

use core::fmt::{self, Display, Formatter};

use cambios_libsys::did_key_encode;

use crate::style::{DIM_PREFIX, RESET};

// ─── Constants ────────────────────────────────────────────────────

/// Number of base58 characters of the multibase-encoded pubkey to
/// keep, after the `z6Mk` multibase + multicodec prefix. Picked so
/// the rendered short form fits comfortably in a prompt while still
/// showing enough identity material to disambiguate two principals
/// at a glance.
///
/// SCAFFOLDING: 8 chars is the IIW-demo readability sweet spot —
/// `z6Mk7L4f…` is recognizable to the did: crowd and tight enough
/// for the prompt. The first four characters (`z6Mk`) are fixed for
/// every Ed25519 did:key, so the variable part is the next 4.
/// Why: hands-on demo prompt readability; collision-free among the
/// principals likely on a single machine (≤ a few dozen).
/// Replace when: a real consumer needs guaranteed disambiguation
/// over a population large enough that 4 variable base58 chars
/// (~24 bits) starts to collide.
const SHORT_PREFIX_BYTES: usize = 8;

/// Stack buffer size for [`DidShort`]. Holds 8 ASCII chars + the
/// 3-byte UTF-8 ellipsis = 11 bytes; 16 gives slack for any future
/// length nudge without changing the type.
const DID_SHORT_BUF: usize = 16;

/// UTF-8 encoding of the ellipsis character `…` (U+2026).
const ELLIPSIS: &[u8] = "…".as_bytes();

// ─── DidShort ─────────────────────────────────────────────────────

/// A short, unstyled did:key identifier. Stack-allocated; pass by
/// value or borrow `as_str()` for use in `write!` chains.
///
/// Render the styled form by wrapping with [`crate::style::principal`]:
///
/// ```ignore
/// let short = format::principal_short(&pubkey);
/// write!(f, "{}", style::principal(short.as_str()))?;
/// ```
#[derive(Clone, Copy)]
pub struct DidShort {
    buf: [u8; DID_SHORT_BUF],
    len: u8,
}

impl DidShort {
    /// The rendered short form as a `&str`. The buffer only ever
    /// contains ASCII bytes and the UTF-8 ellipsis sequence, so the
    /// `from_utf8` call cannot fail; the `unwrap_or("")` guards the
    /// impossible case without panicking.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }

    /// Length of the rendered string in bytes (not visible columns).
    pub fn len(&self) -> usize {
        self.len as usize
    }
}

impl Display for DidShort {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Render a Principal pubkey as a short did:key identifier of the
/// shape `z6Mk7L4f…` — multibase + multicodec prefix, 4 chars of
/// pubkey material, ellipsis. The `did:key:` URI prefix is omitted
/// to keep the prompt tight; the `z` and `6Mk` markers remain so a
/// reader familiar with did:key still recognizes the form.
///
/// Delegates the multibase encoding to
/// `cambios_libsys::did_key_encode` so this crate stays the
/// authority on layout, not on encoding.
pub fn principal_short(pubkey: &[u8; 32]) -> DidShort {
    let full = did_key_encode(pubkey);
    let full_bytes = full.as_bytes();

    // The libsys-rendered form is `did:key:z6Mk…` — strip the URI
    // prefix to expose the multibase body.
    const URI_PREFIX: &[u8] = b"did:key:";
    let body: &[u8] = if full_bytes.starts_with(URI_PREFIX) {
        &full_bytes[URI_PREFIX.len()..]
    } else {
        // Defensive: if the libsys encoding ever changes shape, render
        // whatever it gave us rather than producing an empty string.
        full_bytes
    };

    let take = SHORT_PREFIX_BYTES.min(body.len());
    let mut out = DidShort { buf: [0; DID_SHORT_BUF], len: 0 };
    out.buf[..take].copy_from_slice(&body[..take]);
    let mut len = take;
    out.buf[len..len + ELLIPSIS.len()].copy_from_slice(ELLIPSIS);
    len += ELLIPSIS.len();
    out.len = len as u8;
    out
}

// ─── KeyValue ─────────────────────────────────────────────────────

/// A padded `key: value` line for help and info dumps. The key is
/// dim-styled and padded to `key_width` visible columns; the value
/// is rendered with its own `Display` impl, which can carry styling
/// of its own (e.g. [`crate::style::principal`]).
///
/// No trailing newline — the caller decides line separators (`\r\n`
/// on the GUI terminal, `\n` on serial, etc.).
#[derive(Clone, Copy)]
pub struct KeyValue<'a, V: Display> {
    key: &'a str,
    value: V,
    key_width: usize,
}

impl<'a, V: Display> Display for KeyValue<'a, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Two-space leading indent matches the convention shared by
        // `help`, `arcobj`, and other dump-style command output.
        // The dim escape wraps the padded key + colon together so
        // the visual weight is on the value.
        f.write_str("  ")?;
        f.write_str(DIM_PREFIX)?;
        write!(f, "{:<width$}:", self.key, width = self.key_width)?;
        f.write_str(RESET)?;
        f.write_str(" ")?;
        write!(f, "{}", self.value)
    }
}

/// Build a `KeyValue` for a help/info dump line.
pub fn key_value<V: Display>(key: &str, value: V, key_width: usize) -> KeyValue<'_, V> {
    KeyValue { key, value, key_width }
}

// ─── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    use crate::style;

    /// A deterministic pubkey for round-trip tests. Doesn't need to
    /// be a real Ed25519 point — the encoder treats it as opaque
    /// 32 bytes.
    const FIXED_PUBKEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn principal_short_starts_with_multibase_marker() {
        // Every Ed25519 did:key is `did:key:z6Mk…` — after stripping
        // the URI prefix, the short form must start with `z6Mk`.
        let short = principal_short(&FIXED_PUBKEY);
        let s = short.as_str();
        assert!(
            s.starts_with("z6Mk"),
            "short form `{}` does not start with `z6Mk`",
            s
        );
    }

    #[test]
    fn principal_short_ends_with_ellipsis() {
        let short = principal_short(&FIXED_PUBKEY);
        assert!(
            short.as_str().ends_with('…'),
            "short form `{}` does not end with the ellipsis",
            short.as_str()
        );
    }

    #[test]
    fn principal_short_keeps_eight_chars_then_ellipsis() {
        // 8 ASCII bytes from the multibase body + 3-byte ellipsis = 11.
        let short = principal_short(&FIXED_PUBKEY);
        assert_eq!(short.len(), SHORT_PREFIX_BYTES + ELLIPSIS.len());
    }

    #[test]
    fn principal_short_distinguishes_distinct_pubkeys() {
        let mut other = FIXED_PUBKEY;
        other[0] ^= 0xff;
        let a = principal_short(&FIXED_PUBKEY);
        let b = principal_short(&other);
        assert_ne!(
            a.as_str(),
            b.as_str(),
            "8 chars of base58 should disambiguate two pubkeys differing in their first byte"
        );
    }

    #[test]
    fn principal_short_display_matches_as_str() {
        let short = principal_short(&FIXED_PUBKEY);
        assert_eq!(format!("{}", short), short.as_str());
    }

    #[test]
    fn key_value_pads_short_key_to_width() {
        let line = format!("{}", key_value("hash", "abc", 8));
        // "  \x1b[2mhash    :\x1b[0m abc"
        assert_eq!(line, "  \x1b[2mhash    :\x1b[0m abc");
    }

    #[test]
    fn key_value_does_not_truncate_long_key() {
        // Standard Rust padding doesn't truncate; long keys overflow
        // the column. Verifying so we don't grow surprises later.
        let line = format!("{}", key_value("a-very-long-key", "v", 4));
        assert_eq!(line, "  \x1b[2ma-very-long-key:\x1b[0m v");
    }

    #[test]
    fn key_value_carries_value_styling_through() {
        // The value's own Display impl (here: a Styled wrapper) must
        // emit its escapes after the key's reset, so the styling is
        // localized to the value.
        let line = format!(
            "{}",
            key_value("author", style::principal("z6Mk7L4f…"), 8)
        );
        assert_eq!(
            line,
            "  \x1b[2mauthor  :\x1b[0m \x1b[36;2mz6Mk7L4f…\x1b[0m"
        );
    }

    #[test]
    fn key_value_exact_width_no_padding() {
        // "hash" is 4 chars, key_width is 4 — no extra spaces inserted.
        let line = format!("{}", key_value("hash", "v", 4));
        assert_eq!(line, "  \x1b[2mhash:\x1b[0m v");
    }
}
