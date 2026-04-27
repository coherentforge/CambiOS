// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Semantic ANSI-styling functions.
//!
//! Each function wraps a borrowed `&str` in a [`Styled`] value whose
//! `Display` impl writes the matching ANSI escape prefix, the body,
//! and the universal reset suffix. The wrapping is a pure value
//! transformation — no allocation, no globals.
//!
//! The 16-color VGA-safe palette below is fixed by design: every
//! ANSI-aware terminal renders these correctly, and there is no
//! runtime palette to drift across surfaces.

use core::fmt::{self, Display, Formatter};

// ─── ANSI escape sequences ────────────────────────────────────────
//
// Each prefix selects an attribute combination. `RESET` cancels all
// attributes so styled output never bleeds into surrounding text.
//
// SGR codes used:
//   0 = reset, 1 = bold, 2 = dim,
//   31 = red, 32 = green, 33 = yellow, 36 = cyan.

pub(crate) const RESET: &str = "\x1b[0m";

const PRINCIPAL_PREFIX: &str = "\x1b[36;2m"; // cyan + dim
const TIME_PREFIX: &str = "\x1b[33;2m"; // yellow + dim
const SUCCESS_PREFIX: &str = "\x1b[32m"; // green
const ERROR_PREFIX: &str = "\x1b[31m"; // red
const WARNING_PREFIX: &str = "\x1b[33;1m"; // yellow + bold
pub(crate) const DIM_PREFIX: &str = "\x1b[2m"; // dim only
const EMPHASIS_PREFIX: &str = "\x1b[1m"; // bold only

// ─── Styled wrapper ───────────────────────────────────────────────

/// A borrowed string with an ANSI prefix attached. `Display` emits
/// `prefix + body + RESET`; nothing else carries state.
///
/// The struct is `Copy` so call sites pass it cheaply through
/// `write!` macros without ceremony.
#[derive(Clone, Copy)]
pub struct Styled<'a> {
    prefix: &'static str,
    body: &'a str,
}

impl<'a> Display for Styled<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix)?;
        f.write_str(self.body)?;
        f.write_str(RESET)
    }
}

// ─── Semantic styling functions ───────────────────────────────────

/// Identity surface — a Principal, did:key short form, or any value
/// the reader is meant to recognize as "who/what."
pub fn principal(s: &str) -> Styled<'_> {
    Styled { prefix: PRINCIPAL_PREFIX, body: s }
}

/// Time/timestamp surface — wall-clock strings, durations, ETAs.
pub fn time(s: &str) -> Styled<'_> {
    Styled { prefix: TIME_PREFIX, body: s }
}

/// Success — a "ready" / "ok" / "done" outcome.
pub fn success(s: &str) -> Styled<'_> {
    Styled { prefix: SUCCESS_PREFIX, body: s }
}

/// Error — failure, refusal, hard stop.
pub fn error(s: &str) -> Styled<'_> {
    Styled { prefix: ERROR_PREFIX, body: s }
}

/// Warning — soft failure, degraded path, action recommended.
pub fn warning(s: &str) -> Styled<'_> {
    Styled { prefix: WARNING_PREFIX, body: s }
}

/// Secondary information — labels, hints, supporting prose. The same
/// attribute the prompt's static framing uses.
pub fn dim(s: &str) -> Styled<'_> {
    Styled { prefix: DIM_PREFIX, body: s }
}

/// Emphasized term — a command name, keyword, or any value the
/// reader is meant to scan for.
pub fn emphasis(s: &str) -> Styled<'_> {
    Styled { prefix: EMPHASIS_PREFIX, body: s }
}

// ─── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    #[test]
    fn principal_emits_cyan_dim() {
        assert_eq!(format!("{}", principal("z6Mk")), "\x1b[36;2mz6Mk\x1b[0m");
    }

    #[test]
    fn time_emits_yellow_dim() {
        assert_eq!(format!("{}", time("13:42")), "\x1b[33;2m13:42\x1b[0m");
    }

    #[test]
    fn success_emits_green() {
        assert_eq!(format!("{}", success("ready")), "\x1b[32mready\x1b[0m");
    }

    #[test]
    fn error_emits_red() {
        assert_eq!(format!("{}", error("ENOENT")), "\x1b[31mENOENT\x1b[0m");
    }

    #[test]
    fn warning_emits_yellow_bold() {
        assert_eq!(format!("{}", warning("low-mem")), "\x1b[33;1mlow-mem\x1b[0m");
    }

    #[test]
    fn dim_emits_dim_only() {
        assert_eq!(format!("{}", dim("hint")), "\x1b[2mhint\x1b[0m");
    }

    #[test]
    fn emphasis_emits_bold_only() {
        assert_eq!(format!("{}", emphasis("play")), "\x1b[1mplay\x1b[0m");
    }

    #[test]
    fn empty_body_still_brackets_with_reset() {
        // A common edge case — empty input shouldn't drop the reset, or a
        // following unstyled line could be "stuck" in the previous color.
        assert_eq!(format!("{}", principal("")), "\x1b[36;2m\x1b[0m");
    }

    #[test]
    fn multibyte_body_passes_through_unchanged() {
        // The wrapper is byte-transparent for the body; UTF-8 sequences
        // (e.g. the ellipsis `…`) round-trip unmolested.
        assert_eq!(format!("{}", principal("z6Mk…")), "\x1b[36;2mz6Mk…\x1b[0m");
    }

    #[test]
    fn styled_is_copy() {
        // Surface-level guarantee that call sites can pass styled values
        // without explicit clone() ceremony — the value is small and
        // copying is the right default.
        fn takes_copy<T: Copy>(_: T) {}
        takes_copy(principal("z6Mk"));
    }
}
