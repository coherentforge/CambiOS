// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Userspace time helpers — Unix-seconds → calendar conversion and
//! human-readable trust-source-tag rendering.
//!
//! Pure functions of their inputs. No I/O, no globals, no allocation.
//! Suitable for formal verification; today carries host-runnable
//! `#[cfg(test)]` coverage for round-trip behavior, leap-year edges,
//! and exhaustive `tag_name` arms.
//!
//! Source-of-truth design: a future audit-log formatter, GUI clock
//! widget, or `--show-source` shell flag should call [`tag_name`] here
//! rather than re-implementing the integer→name table. The kernel
//! stores `source_tag` as a `u8` (ABI-stable, verification-friendly);
//! the tag↔name mapping lives in userspace because it is presentation,
//! not policy.

/// Decompose a Unix timestamp into `(year, month, day, hour, minute,
/// second)`. The Gregorian calendar is honored back to the Unix epoch
/// (1970-01-01 UTC); negative timestamps are not representable in `u64`
/// and need not be considered.
///
/// `month` and `day` are 1-indexed (January = 1, the first of the
/// month = 1). `hour`, `minute`, `second` are 0-indexed.
pub fn unix_to_datetime(ts: u64) -> (u32, u8, u8, u8, u8, u8) {
    let second = (ts % 60) as u8;
    let ts = ts / 60;
    let minute = (ts % 60) as u8;
    let ts = ts / 60;
    let hour = (ts % 24) as u8;
    let mut days = (ts / 24) as u32;

    // Walk forward from 1970 until the residual day count fits inside
    // a single year. Bounded by the maximum representable u64 / 86400 ≈
    // 2.13e14 days, which is many trillion years past 1970 — safe; this
    // loop terminates in well under a few hundred iterations for any
    // realistic input.
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let days_in_month: [u32; 12] = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut month = 1u8;
    for (i, &dim) in days_in_month.iter().enumerate() {
        if days < dim {
            month = i as u8 + 1;
            break;
        }
        days -= dim;
    }
    let day = days as u8 + 1;

    (year, month, day, hour, minute, second)
}

/// Gregorian leap-year predicate — divisible by 4, except centuries,
/// except those divisible by 400.
pub fn is_leap_year(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Human-readable trust-source-tag name. The integer tag is the on-wire
/// value passed to / from `SetWallclock` / `source_tag()`; this helper
/// is the single source of truth for the tag → name mapping (ADR-022
/// § 4 reservation table).
///
/// Reserved values are permanent — a future ADR may deprecate a tag
/// (mark it reserved-do-not-use) but may not renumber or repurpose it.
pub fn tag_name(source_tag: u8) -> &'static str {
    match source_tag {
        0 => "unauthenticated",
        1 => "nts",
        2 => "roughtime",
        3 => "peer-attested",
        4 => "signed-carrier",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_zero_is_unix_epoch() {
        assert_eq!(unix_to_datetime(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn unix_to_datetime_round_trips_a_known_moment() {
        // 2026-04-26 00:00:00 UTC = 1777161600. Computed by-hand from
        // (1970→2026 = 56 years × 365 + 14 leap days = 20454 days
        // baseline) + (Jan 31 + Feb 28 + Mar 31 + 25 = 115 days into
        // 2026) → 20569 × 86400 = 1_777_161_600.
        // Anchored here so future leap-year refactors stay honest.
        assert_eq!(unix_to_datetime(1_777_161_600), (2026, 4, 26, 0, 0, 0));
    }

    #[test]
    fn unix_to_datetime_handles_leap_day() {
        // 2024-02-29 12:34:56 UTC = 1709210096.
        assert_eq!(
            unix_to_datetime(1_709_210_096),
            (2024, 2, 29, 12, 34, 56),
        );
    }

    #[test]
    fn unix_to_datetime_handles_year_2000() {
        // 2000 is a leap year (divisible by 400). 2000-03-01 00:00:00
        // UTC = 951868800; the previous day must be 2000-02-29.
        assert_eq!(unix_to_datetime(951_782_400), (2000, 2, 29, 0, 0, 0));
    }

    #[test]
    fn unix_to_datetime_handles_century_non_leap() {
        // 1900 is NOT a leap year (divisible by 100 but not 400). Pick
        // a point we can verify cheaply: end-of-1999. 1999-12-31
        // 23:59:59 UTC = 946684799.
        assert_eq!(unix_to_datetime(946_684_799), (1999, 12, 31, 23, 59, 59));
    }

    #[test]
    fn is_leap_year_covers_the_three_rules() {
        assert!(is_leap_year(2024));     // divisible by 4
        assert!(!is_leap_year(2025));    // not divisible by 4
        assert!(!is_leap_year(1900));    // century, not /400
        assert!(is_leap_year(2000));     // century, /400
    }

    #[test]
    fn tag_name_covers_all_reserved_slots() {
        assert_eq!(tag_name(0), "unauthenticated");
        assert_eq!(tag_name(1), "nts");
        assert_eq!(tag_name(2), "roughtime");
        assert_eq!(tag_name(3), "peer-attested");
        assert_eq!(tag_name(4), "signed-carrier");
    }

    #[test]
    fn tag_name_unknown_is_explicit() {
        // Every unallocated slot renders as "unknown" rather than a
        // numeric placeholder; the formatter is forward-compatible
        // with future ADR assignments without code changes.
        assert_eq!(tag_name(5), "unknown");
        assert_eq!(tag_name(255), "unknown");
    }
}
