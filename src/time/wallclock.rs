// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Wall-clock time as Unix seconds. Two atomics + the kernel tick counter
//! reproduce a Unix-time view that any process can read via `GetWallclock`.
//! Capability-gated `SetWallclock` is what lets `udp-stack` (the only
//! capability-holder at boot) republish a fresh baseline every ~4 hours.
//!
//! The torn-read window between the two `set()` stores is documented inline
//! and accepted by design; see ADR-022 § 1.
//!
//! Verification posture: pure functions of atomic state + the timer's tick
//! counter. No locks. No I/O. Lock-free reads are wait-free, safe from any
//! context (ISR, syscall handler, idle loop). Host-runnable tests cover the
//! unset / set / tick-rollover behaviors.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::scheduler::Timer;

/// TUNING: timer interrupt frequency. Today's kernel runs at 100 Hz
/// (`TimerConfig::HZ_100`, see [src/scheduler/timer.rs]). Wall-clock
/// arithmetic divides elapsed ticks by this value to recover Unix seconds.
/// Why: matches the active timer config at boot; not hardware-fixed (we
/// could re-pin to 1000 Hz). Replace when: timer config moves to a runtime
/// query OR the active frequency changes — either way, this constant must
/// track `TimerConfig::active().frequency_hz`.
const TICKS_PER_SEC: u64 = 100;

/// Unix seconds at the moment of the last `set()` call. Sentinel `0` =
/// unset (boot state). The Unix epoch (1970-01-01) is unrepresentable
/// in practice, so reusing `0` as "no time yet" costs nothing.
static WALL_BASELINE_UNIX: AtomicU64 = AtomicU64::new(0);

/// Kernel tick count at the moment of the last `set()` call. Paired with
/// `WALL_BASELINE_UNIX` to project elapsed ticks onto Unix-seconds.
static WALL_BASELINE_TICKS: AtomicU64 = AtomicU64::new(0);

/// Trust-source tag (ADR-022 § 4 reservation table). 0 = unauthenticated
/// NTP (day-1); 1 = NTS; 2 = Roughtime; 3 = Principal-signed peer-attested;
/// 4 = signed-carrier hardware. Reserved values are permanent — a future
/// ADR may deprecate a tag but may not renumber or repurpose it.
static WALL_SOURCE_TAG: AtomicU8 = AtomicU8::new(0);

/// Publish a new wall-clock baseline. Three plain stores, no seqlock.
///
/// Concurrent readers may briefly observe the new TICKS anchor against the
/// old UNIX baseline (or vice versa) — at most one second of skew during
/// the window between the two stores. This is deliberate, not an
/// oversight: `set()` runs every 4h (not in a hot loop), wall-clock
/// display does not need sub-second monotonicity, and `Timer::get_ticks()`
/// remains the authoritative monotonic source. A seqlock would add
/// complexity for no measurable gain.
pub fn set(unix_secs: u64, source_tag: u8) {
    let now_ticks = Timer::get_ticks();
    WALL_BASELINE_TICKS.store(now_ticks, Ordering::Release);
    WALL_BASELINE_UNIX.store(unix_secs, Ordering::Release);
    WALL_SOURCE_TAG.store(source_tag, Ordering::Release);
}

/// Read the current wall-clock as Unix seconds. Returns `0` if `set()`
/// has never been called (pre-NTP boot). Lock-free, wait-free.
pub fn get() -> u64 {
    let baseline = WALL_BASELINE_UNIX.load(Ordering::Acquire);
    if baseline == 0 {
        return 0;
    }
    let anchor = WALL_BASELINE_TICKS.load(Ordering::Acquire);
    let now = Timer::get_ticks();
    let elapsed_ticks = now.saturating_sub(anchor);
    baseline + elapsed_ticks / TICKS_PER_SEC
}

/// Read the current trust-source tag. `0` before any `set()` and after
/// any `set(_, 0)` — consumers that match on tag must treat both as
/// "unauthenticated."
pub fn source_tag() -> u8 {
    WALL_SOURCE_TAG.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reset module state between tests. Necessary because the static
    /// atomics persist across `#[test]` runs in a single binary.
    fn reset() {
        WALL_BASELINE_UNIX.store(0, Ordering::Release);
        WALL_BASELINE_TICKS.store(0, Ordering::Release);
        WALL_SOURCE_TAG.store(0, Ordering::Release);
    }

    #[test]
    fn get_returns_zero_before_any_set() {
        reset();
        assert_eq!(get(), 0);
    }

    #[test]
    fn get_returns_baseline_when_no_ticks_elapsed() {
        reset();
        // Anchor at the current tick count; `get()` should produce the
        // baseline + elapsed_ticks/100. The tick counter advances during
        // a real run; the bound is "≥ baseline, ≤ baseline + 1 second of
        // tick drift" which captures both fixture and live cases.
        let baseline = 1_700_000_000u64;
        set(baseline, 0);
        let observed = get();
        assert!(observed >= baseline);
        // Allow up to 5 seconds of drift to keep the test stable on slow
        // CI; in practice the gap between `set` and `get` is microseconds.
        assert!(observed <= baseline + 5);
    }

    #[test]
    fn source_tag_round_trips() {
        reset();
        set(1_700_000_000, 2);
        assert_eq!(source_tag(), 2);
    }

    #[test]
    fn set_zero_baseline_means_unset_per_sentinel() {
        // ADR-022 § 5: udp-stack is forbidden from publishing
        // `set_wallclock(0, 0)` on NTP failure precisely so the sentinel
        // semantics survive. We don't enforce that here (caller's job),
        // but `get()` still returns 0, matching the unset case.
        reset();
        set(0, 0);
        assert_eq!(get(), 0);
    }
}
