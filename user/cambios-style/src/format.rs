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
/// SCAFFOLDING: prefix length kept to 4 — exactly the fixed
/// `z6Mk` multibase+multicodec marker shared by every Ed25519
/// did:key. The variable disambiguator lives entirely in the
/// suffix (`SHORT_SUFFIX_BYTES`); rendering it as `z6Mk...XXXX`
/// reads as a deliberate middle-truncation rather than a string
/// that happened to get cut off.
/// Why: hands-on demo prompt readability; collision-free among the
/// principals likely on a single machine (≤ a few dozen).
/// Replace when: a real consumer needs guaranteed disambiguation
/// over a population large enough that 4 variable base58 chars
/// (~24 bits) starts to collide.
const SHORT_PREFIX_BYTES: usize = 4;

/// SCAFFOLDING: 4 chars from the tail of the multibase body. Carries
/// the variable disambiguator now that the prefix is fixed `z6Mk`.
/// Same replace-when criterion as `SHORT_PREFIX_BYTES`.
const SHORT_SUFFIX_BYTES: usize = 4;

/// Stack buffer size for [`DidShort`]. Holds 4 prefix + 3-byte ASCII
/// ellipsis + 4 suffix = 11 bytes; 16 gives slack for any future
/// length nudge without changing the type.
const DID_SHORT_BUF: usize = 16;

/// Three-dot ASCII ellipsis. Originally the Unicode `…` glyph (U+2026,
/// 3 UTF-8 bytes), but a terminal that isn't UTF-8-aware (some
/// SSH-into-tty paths, default macOS Terminal in legacy encodings,
/// QEMU stdout viewed through a Latin-1 pager) renders the byte
/// sequence as `â¦` — wrong, brittle, and exactly the kind of detail
/// that costs a demo. Three ASCII dots render identically in every
/// encoding for a one-glyph cosmetic loss. Replace when: GUI Grid /
/// every surface gains proper UTF-8 rendering AND we have a way to
/// guarantee the consumer terminal is UTF-8 too.
const ELLIPSIS: &[u8] = b"...";

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
/// shape `z6Mk...XXXX` — fixed multibase+multicodec marker, ellipsis,
/// then the last 4 chars of the multibase body. The `did:key:` URI
/// prefix is omitted to keep the prompt tight; the `z` and `6Mk`
/// markers remain so a reader familiar with did:key still recognizes
/// the form. Middle-truncation reads as a deliberate elision rather
/// than a string that ran off a fixed-width display.
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

    let prefix_n = SHORT_PREFIX_BYTES.min(body.len());
    // Keep prefix and suffix disjoint when the body is unexpectedly
    // short (cannot happen for a real did:key, but keep it total).
    let suffix_n = SHORT_SUFFIX_BYTES.min(body.len() - prefix_n);
    let mut out = DidShort { buf: [0; DID_SHORT_BUF], len: 0 };
    let mut len = 0;
    out.buf[len..len + prefix_n].copy_from_slice(&body[..prefix_n]);
    len += prefix_n;
    out.buf[len..len + ELLIPSIS.len()].copy_from_slice(ELLIPSIS);
    len += ELLIPSIS.len();
    out.buf[len..len + suffix_n].copy_from_slice(&body[body.len() - suffix_n..]);
    len += suffix_n;
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

// ─── Prompt ───────────────────────────────────────────────────────

/// Render the standard CambiOS shell prompt as a `Display` value:
/// `cambios@<short-did>:HH:MM> ` with semantic styling on each
/// segment. Sections drop out when their inputs are unavailable so the
/// boot path stays readable:
///
/// | principal | wallclock_secs | rendered prompt          |
/// |-----------|----------------|---------------------------|
/// | anonymous | 0              | `cambios> `               |
/// | anonymous | non-zero       | `cambios:HH:MM> `         |
/// | bound     | 0              | `cambios@z6Mk7L4f…> `     |
/// | bound     | non-zero       | `cambios@z6Mk7L4f…:HH:MM> `|
///
/// "anonymous" is the all-zero Principal returned by
/// `cambios_libsys::get_principal` for unbound processes.
///
/// The returned `Prompt` borrows from `principal`; it must outlive the
/// `write!` / `print!` call that consumes it. Callers who already
/// have the principal in a stack buffer (the common case for
/// `sys::get_principal`) get this for free.
pub fn prompt(principal: &[u8; 32], wallclock_secs: u64) -> Prompt<'_> {
    Prompt {
        principal,
        wallclock_secs,
    }
}

/// Display wrapper produced by [`prompt`]. See [`prompt`] for the
/// rendering rules.
#[derive(Clone, Copy)]
pub struct Prompt<'a> {
    principal: &'a [u8; 32],
    wallclock_secs: u64,
}

impl<'a> Display for Prompt<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use crate::style;
        use cambios_libsys::time::unix_to_datetime;

        write!(f, "{}", style::dim("cambios"))?;

        if !is_anonymous(self.principal) {
            let short = principal_short(self.principal);
            write!(f, "{}{}", style::dim("@"), style::principal(short.as_str()))?;
        }

        if self.wallclock_secs != 0 {
            let (_, _, _, hour, minute, _) = unix_to_datetime(self.wallclock_secs);
            // Compose "HH:MM" into a 5-byte stack buffer. Hour and
            // minute are bounded by 23 and 59 so the two-digit
            // arithmetic always yields valid ASCII.
            let mut hh_mm = [0u8; 5];
            hh_mm[0] = b'0' + (hour / 10);
            hh_mm[1] = b'0' + (hour % 10);
            hh_mm[2] = b':';
            hh_mm[3] = b'0' + (minute / 10);
            hh_mm[4] = b'0' + (minute % 10);
            // Bytes are guaranteed ASCII; from_utf8 cannot fail here.
            // The unwrap_or guards the impossible case without panic.
            let hh_mm_str = core::str::from_utf8(&hh_mm).unwrap_or("00:00");
            write!(f, "{}{}", style::dim(":"), style::time(hh_mm_str))?;
        }

        write!(f, "{}", style::dim("> "))
    }
}

/// All-zero principal — the convention `cambios_libsys::get_principal`
/// uses to mean "this process has no bound identity yet."
fn is_anonymous(principal: &[u8; 32]) -> bool {
    principal.iter().all(|&b| b == 0)
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
    fn principal_short_has_middle_ellipsis() {
        // Shape: `z6Mk` + `...` + 4 trailing chars of the body.
        let short = principal_short(&FIXED_PUBKEY);
        let s = short.as_str();
        assert_eq!(
            &s[SHORT_PREFIX_BYTES..SHORT_PREFIX_BYTES + ELLIPSIS.len()],
            "...",
            "short form `{}` is missing middle ellipsis",
            s,
        );
    }

    #[test]
    fn principal_short_length_is_prefix_plus_ellipsis_plus_suffix() {
        // 4 ASCII bytes prefix + 3-byte ellipsis + 4 ASCII bytes suffix = 11.
        let short = principal_short(&FIXED_PUBKEY);
        assert_eq!(
            short.len(),
            SHORT_PREFIX_BYTES + ELLIPSIS.len() + SHORT_SUFFIX_BYTES,
        );
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

    // ─── Prompt rendering ────────────────────────────────────────

    /// Anonymous principal — `cambios_libsys::get_principal` returns
    /// this for unbound processes.
    const ANON: [u8; 32] = [0u8; 32];

    /// 2026-04-26 13:42:00 UTC. Day-aware; only the HH:MM segment is
    /// rendered in the prompt.
    const WALL_2026_04_26_1342: u64 = 1_777_161_600 + 13 * 3600 + 42 * 60;

    #[test]
    fn prompt_anonymous_unset_wallclock_is_minimal() {
        let line = format!("{}", prompt(&ANON, 0));
        assert_eq!(line, "\x1b[2mcambios\x1b[0m\x1b[2m> \x1b[0m");
    }

    #[test]
    fn prompt_bound_principal_renders_short_did() {
        let line = format!("{}", prompt(&FIXED_PUBKEY, 0));
        // "cambios" + "@" + short-did + "> "  — all dim except short-did
        // which is principal-styled (cyan+dim). Built piecewise so a
        // future prefix-length nudge updates one helper, not the
        // expected string.
        let short = principal_short(&FIXED_PUBKEY);
        let expected = format!(
            "\x1b[2mcambios\x1b[0m\x1b[2m@\x1b[0m\x1b[36;2m{}\x1b[0m\x1b[2m> \x1b[0m",
            short.as_str(),
        );
        assert_eq!(line, expected);
    }

    #[test]
    fn prompt_anonymous_with_wallclock_renders_time() {
        let line = format!("{}", prompt(&ANON, WALL_2026_04_26_1342));
        assert_eq!(
            line,
            "\x1b[2mcambios\x1b[0m\x1b[2m:\x1b[0m\x1b[33;2m13:42\x1b[0m\x1b[2m> \x1b[0m"
        );
    }

    #[test]
    fn prompt_full_form_has_all_segments() {
        let line = format!("{}", prompt(&FIXED_PUBKEY, WALL_2026_04_26_1342));
        let short = principal_short(&FIXED_PUBKEY);
        let expected = format!(
            "\x1b[2mcambios\x1b[0m\
             \x1b[2m@\x1b[0m\x1b[36;2m{}\x1b[0m\
             \x1b[2m:\x1b[0m\x1b[33;2m13:42\x1b[0m\
             \x1b[2m> \x1b[0m",
            short.as_str(),
        );
        assert_eq!(line, expected);
    }

    #[test]
    fn prompt_pads_single_digit_hours_and_minutes() {
        // 2026-04-26 03:05:00 UTC = 1777161600 + 3*3600 + 5*60.
        let wall = 1_777_161_600 + 3 * 3600 + 5 * 60;
        let line = format!("{}", prompt(&ANON, wall));
        assert!(line.contains("03:05"), "rendered: {}", line);
    }

    #[test]
    fn prompt_handles_midnight_zero_zero() {
        let line = format!("{}", prompt(&ANON, 1_777_161_600));
        assert!(line.contains("00:00"), "rendered: {}", line);
    }
}
