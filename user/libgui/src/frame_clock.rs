// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! `FrameClock` — fixed-interval tick gate for self-driven apps.
//!
//! Pattern extracted from `user/worm/src/main.rs` when Pong became the
//! second consumer (Development Convention 9 — extract on the second
//! call site, not the first). Worm's ad-hoc
//!
//! ```ignore
//! let mut last_step = sys::get_time();
//! // ...loop...
//! let now = sys::get_time();
//! if now.saturating_sub(last_step) >= STEP_TICKS {
//!     game.step();
//!     last_step = now;
//! }
//! ```
//!
//! becomes
//!
//! ```ignore
//! let mut clock = FrameClock::new(STEP_TICKS);
//! clock.seed(sys::get_time());
//! // ...loop...
//! if clock.tick(sys::get_time()) {
//!     game.step();
//! }
//! ```
//!
//! ## Pure logic
//!
//! `now` is passed in, not read from `sys::get_time()`. Keeps the
//! clock host-testable (no kernel surface) and leaves the caller in
//! control of *when* wall time is sampled relative to input draining,
//! redraw, and yield — same posture as `game` modules in tree and
//! worm. No interior mutability, no `AtomicU64`, no hidden state.
//!
//! ## Tick units
//!
//! The CambiOS kernel scheduler runs at 100 Hz, so one tick is 10 ms
//! and `sys::get_time()` returns a tick count (not milliseconds, not
//! wall-clock). `step_ticks` is in that same unit — pass `20` for
//! 200 ms, `5` for 50 ms, etc. `FrameClock` itself is unit-agnostic:
//! any monotonic u64 counter works, which is why tests can drive it
//! with arbitrary integers.
//!
//! ## Why not `Duration` or `Instant`
//!
//! `no_std` `core` doesn't have them, and dragging in the types only
//! to convert back to ticks at the syscall boundary buys nothing. The
//! kernel speaks ticks; user-space speaks ticks; the clock speaks
//! ticks.
//!
//! ## Saturation, not wrap
//!
//! The subtraction uses `saturating_sub` so a clock seeded with a
//! time value later than "now" (possible if a caller re-seeds on a
//! reset without resampling time, or if time somehow moves backward)
//! produces a zero delta rather than a wrap to ~u64::MAX, which would
//! be indistinguishable from a gigantic real delta and would fire the
//! clock on the very next call.
//!
//! ## What this does NOT do
//!
//! - No catch-up. If the caller falls 10 intervals behind (e.g. the
//!   compositor stalled), the next successful `tick()` advances
//!   `last_step` to `now` — future ticks are measured from *now*, not
//!   from the missed deadline. Pong + Worm both want this: physics
//!   doesn't need to compensate for a GUI stall with 10 back-to-back
//!   steps, it just picks up at the current time.
//! - No fractional steps. Interval is integer ticks.
//! - No variable interval. Worm originally had a score-scaled interval
//!   (`max(5, base - score/5)`) that landed poorly in playtest; if a
//!   future consumer wants speedup, it can wrap `FrameClock` or
//!   mutate `step_ticks` via a setter (not provided in v0 — add when
//!   the second consumer actually needs it).

/// Fires once every `step_ticks` monotonic ticks.
///
/// Typical lifecycle:
///
/// ```ignore
/// let mut clock = FrameClock::new(5);    // 50 ms at 100 Hz
/// clock.seed(sys::get_time());
/// loop {
///     if clock.tick(sys::get_time()) {
///         game.step();
///     }
///     // draw, drain events, yield_now…
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct FrameClock {
    step_ticks: u64,
    last_step: u64,
}

impl FrameClock {
    /// Build a clock with a fixed step interval. `last_step` is seeded
    /// to 0; call [`seed`](Self::seed) before the first [`tick`](Self::tick)
    /// so the first tick waits a full interval instead of firing
    /// immediately (0 is almost always much less than the current
    /// kernel tick count).
    pub const fn new(step_ticks: u64) -> Self {
        Self { step_ticks, last_step: 0 }
    }

    /// Set the reference point for the next interval. Called once at
    /// app start after the first `sys::get_time()` read, and again on
    /// any state reset that should grant a full grace interval before
    /// the next step (e.g. the player pressing R in Pong — they
    /// shouldn't lose a frame of paddle time from the time spent
    /// dying + pressing R).
    pub fn seed(&mut self, now: u64) {
        self.last_step = now;
    }

    /// Test whether the interval has elapsed. Returns `true` exactly
    /// once per interval crossing and advances `last_step` to `now`
    /// on the firing call. Safe to call every loop iteration — the
    /// "did an interval pass?" branch is one saturating subtract.
    pub fn tick(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.last_step) >= self.step_ticks {
            self.last_step = now;
            return true;
        }
        false
    }

    pub const fn step_ticks(&self) -> u64 {
        self.step_ticks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_fire_before_interval_elapses() {
        let mut c = FrameClock::new(10);
        c.seed(100);
        assert!(!c.tick(100));
        assert!(!c.tick(105));
        assert!(!c.tick(109));
    }

    #[test]
    fn fires_exactly_on_interval_boundary() {
        let mut c = FrameClock::new(10);
        c.seed(100);
        assert!(c.tick(110));
    }

    #[test]
    fn does_not_refire_until_next_interval() {
        let mut c = FrameClock::new(10);
        c.seed(100);
        assert!(c.tick(110));
        assert!(!c.tick(111));
        assert!(!c.tick(119));
        assert!(c.tick(120));
    }

    #[test]
    fn large_gap_fires_once_no_catchup() {
        // If the loop stalled for 100 ticks with a 10-tick interval,
        // we want a SINGLE fire, not ten. Physics catches up to
        // wall time, not 10 back-to-back steps.
        let mut c = FrameClock::new(10);
        c.seed(0);
        assert!(c.tick(100));
        assert!(!c.tick(101));
        assert!(!c.tick(109));
        assert!(c.tick(110));
    }

    #[test]
    fn time_going_backward_is_not_a_fire() {
        let mut c = FrameClock::new(10);
        c.seed(1000);
        // Clock says we're 500 ticks BEFORE the last step. Saturating
        // subtract gives 0, which is less than 10, so no fire.
        assert!(!c.tick(500));
        // Forward progress from the seed still fires on schedule.
        assert!(c.tick(1010));
    }

    #[test]
    fn seed_resets_the_interval_window() {
        let mut c = FrameClock::new(10);
        c.seed(0);
        assert!(c.tick(10));
        // Reset: pretend the app just restarted.
        c.seed(1000);
        // Even though now is 1001, we've only been 1 tick past the
        // new seed — no fire.
        assert!(!c.tick(1001));
        assert!(c.tick(1010));
    }

    #[test]
    fn zero_interval_fires_every_call() {
        // Degenerate but well-defined: step_ticks == 0 means "tick
        // every chance you get". Useful in tests.
        let mut c = FrameClock::new(0);
        c.seed(0);
        assert!(c.tick(0));
        assert!(c.tick(0));
        assert!(c.tick(1));
    }

    #[test]
    fn step_ticks_getter_exposes_configured_interval() {
        let c = FrameClock::new(42);
        assert_eq!(c.step_ticks(), 42);
    }
}
