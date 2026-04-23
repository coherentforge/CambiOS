// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Pong game logic — pure bookkeeping, no I/O.
//!
//! First CambiOS first-party app with continuous-motion physics
//! (Tree is grid-based reveal, Worm is grid-stepped cells). Same
//! structural posture as `BuddyAllocator` / `tree::game` /
//! `worm::game`: algorithm-only, explicit enums, bounded iteration,
//! no panics, no heap. Rendering and input (`render.rs`, `main.rs`)
//! consume this module; this module does not know they exist.
//!
//! ## Subpixel coordinate system
//!
//! Physics is integer-only. Every position and velocity is in
//! **subpixels** with [`PX_BITS`]`= 8` fractional bits, i.e. one
//! pixel = 256 subpixels. Ball velocities are handfuls of pixels per
//! tick (e.g. 7 × 256 = 1792 subpixels/tick = 7 px/tick). Render
//! shifts right by `PX_BITS` to get a pixel-space position.
//!
//! Why integer subpixels instead of float: same rationale as the
//! kernel — formal-verification readiness means no IEEE-754 rounding
//! semantics to reason about, and i32 math is exactly what Kani /
//! CBMC / Miri understand. The fractional bits let paddle hits
//! impart smooth angles without a lossy int-only physics integration.
//!
//! ## Court space vs. window space
//!
//! The game thinks in "court" coordinates: a
//! [`COURT_W`]`×`[`COURT_H`] rectangle with origin at its top-left.
//! The renderer is responsible for translating (0, 0) to whatever
//! offset the window uses (in practice, below a status bar). Keeping
//! the game module unaware of the status bar means a future tournament
//! mode with a taller status bar can be added without touching this
//! file.
//!
//! ## State machine
//!
//! ```text
//! Serving(countdown, server)
//!     ticks_remaining == 0 ──► Playing
//!
//! Playing
//!     ball exits left wall  ──► Serving(.., Left)   // Left lost → Left serves back
//!     ball exits right wall ──► Serving(.., Right)
//!     left_score  == WIN    ──► MatchOver(Left)
//!     right_score == WIN    ──► MatchOver(Right)
//!
//! MatchOver(winner)
//!     reset()              ──► Serving(.., Left)
//! ```
//!
//! `reset()` is the only way out of `MatchOver`. `step()` in
//! `MatchOver` is a no-op (no tableau changes).
//!
//! ## Collision posture
//!
//! Basic AABB against the new ball position — ball displacement per
//! tick (≤ 11 px with the v0 speed cap) is less than ball size (12
//! px), so no tunneling through paddles. If the speed cap is ever
//! raised past ball-size-per-tick, swap for swept-AABB before then.

// --- constants ---

/// ARCHITECTURAL: subpixel fractional bits. 1 pixel = 256 subpixels.
/// Fixed across the game; changing this rescales every velocity and
/// collision bound.
pub const PX_BITS: u32 = 8;
pub const PX_ONE: i32 = 1 << PX_BITS;

/// ARCHITECTURAL: court dimensions in pixels. Game logic's coordinate
/// space; renderer offsets these below a status bar.
pub const COURT_W: i32 = 480;
pub const COURT_H: i32 = 320;

/// ARCHITECTURAL: paddle and ball geometry in pixels. Ball is square
/// for symmetry — acorn art fills this bounding box in render.rs.
pub const PADDLE_W: i32 = 12;
pub const PADDLE_H: i32 = 64;
pub const PADDLE_INSET_X: i32 = 24;
pub const BALL_SIZE: i32 = 12;

/// ARCHITECTURAL: paddle left/right x positions in pixels.
pub const LEFT_PADDLE_X: i32 = PADDLE_INSET_X;
pub const RIGHT_PADDLE_X: i32 = COURT_W - PADDLE_INSET_X - PADDLE_W;

/// TUNING: ball's initial horizontal speed in subpixels/tick. At the
/// 50 ms / 20 FPS cadence the main loop runs, 7 px/tick = 140 px/sec,
/// giving a ball-to-paddle flight of ~3 s across the 432-px gap
/// between paddle inner edges. Slow enough for a beginner, fast
/// enough to feel like Pong.
///
/// Replace when: playtest feedback converges on a different starting
/// pace, or the tick rate changes (the derived flight time is the
/// felt metric, not the raw number).
const BALL_INITIAL_VX_SUBPX: i32 = 7 * PX_ONE;

/// TUNING: cap on ball horizontal speed. Each paddle hit adds a small
/// increment (see `SPEEDUP_PER_HIT_SUBPX`); this bounds runaway speed.
/// 11 px/tick < 12 px ball size, so basic AABB collision is sound —
/// ball displacement can't jump across a paddle in one tick. If you
/// raise this above BALL_SIZE - 1, rewrite collision as swept-AABB
/// before committing.
const BALL_MAX_VX_SUBPX: i32 = 11 * PX_ONE;

/// TUNING: horizontal speedup per paddle hit. +0.25 px/tick per rally
/// → ~16 hits to go from 7 to 11 px/tick. Matches classic Pong feel
/// where a long rally accelerates into late-game pressure.
const SPEEDUP_PER_HIT_SUBPX: i32 = PX_ONE / 4;

/// TUNING: max vertical speed a paddle hit can impart. Reached when
/// the ball hits the extreme top or bottom of the paddle. Smaller
/// than the horizontal max so paddle skill (where you hit) gives
/// angle without pinwheeling.
const MAX_SPIN_VY_SUBPX: i32 = 6 * PX_ONE;

/// TUNING: player paddle traversal speed. 5 px/tick = 100 px/sec.
/// The (COURT_H - PADDLE_H) = 256 px corridor takes ~2.6 s corner-to-
/// corner — responsive without being twitchy.
const PLAYER_PADDLE_VY_SUBPX: i32 = 5 * PX_ONE;

/// TUNING: AI paddle traversal speed. 75% of player for beatability
/// — ball diagonals at full-spin exceed 4 px/tick on the y-axis, so
/// a well-placed spin hit outruns the AI. This is the knob to turn
/// if v0 ships and the AI feels too easy / too hard.
const AI_MAX_VY_SUBPX: i32 = 4 * PX_ONE;

/// TUNING: AI doesn't twitch inside this many subpixels of ball
/// alignment — prevents high-frequency jitter when ball is already
/// centered on the paddle.
const AI_DEADBAND_SUBPX: i32 = 6 * PX_ONE;

/// ARCHITECTURAL: match length. First to WIN_SCORE points wins.
pub const WIN_SCORE: u8 = 5;

/// TUNING: pause between score and next serve. 40 ticks at 100 Hz =
/// 400 ms. Long enough that the score update reads as a beat, short
/// enough that the rally momentum doesn't drain.
pub const SERVE_DELAY_TICKS: u64 = 40;

// --- public enums ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

impl Side {
    pub fn flip(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// What the player paddle is doing on this physics tick. `main.rs`
/// translates key state into this enum before calling `step`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaddleMotion {
    None,
    Up,
    Down,
}

/// High-level game phase. Used by the renderer to decide whether to
/// paint a countdown overlay or a win banner, and by `main.rs` to
/// decide whether to keep ticking the frame clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Ball is at center. `ticks_remaining` counts down to zero, then
    /// the state transitions to `Playing` with the ball served
    /// *toward* `server`'s opponent (`server` just lost the previous
    /// point, so they get the serve — classic Pong). Initial game
    /// starts with `server = Left` by convention.
    Serving { ticks_remaining: u64, server: Side },
    Playing,
    MatchOver { winner: Side },
}

// --- per-object state ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Paddle {
    /// Top edge, subpixel. Clamped to `[0, (COURT_H - PADDLE_H) << PX_BITS]`.
    pub y_subpx: i32,
}

impl Paddle {
    const fn top_subpx_max() -> i32 {
        (COURT_H - PADDLE_H) << PX_BITS
    }

    pub fn center_y_subpx(&self) -> i32 {
        self.y_subpx + ((PADDLE_H << PX_BITS) / 2)
    }

    /// Top edge in pixel space, for the renderer.
    pub fn y_px(&self) -> i32 {
        self.y_subpx >> PX_BITS
    }

    fn clamp(&mut self) {
        if self.y_subpx < 0 {
            self.y_subpx = 0;
        }
        let max = Self::top_subpx_max();
        if self.y_subpx > max {
            self.y_subpx = max;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ball {
    pub x_subpx: i32,
    pub y_subpx: i32,
    pub vx_subpx: i32,
    pub vy_subpx: i32,
}

impl Ball {
    pub fn x_px(&self) -> i32 {
        self.x_subpx >> PX_BITS
    }
    pub fn y_px(&self) -> i32 {
        self.y_subpx >> PX_BITS
    }
    fn center_y_subpx(&self) -> i32 {
        self.y_subpx + ((BALL_SIZE << PX_BITS) / 2)
    }
}

// --- full game state ---

pub struct Pong {
    state: State,
    left_score: u8,
    right_score: u8,
    left_paddle: Paddle,
    right_paddle: Paddle,
    ball: Ball,
    rng: Xorshift64,
}

impl Pong {
    /// New game: scores 0–0, paddles centered, ball at center, Left
    /// gets the opening serve. The serve delay grants a beat before
    /// action starts so the player can focus.
    pub fn new(seed: u64) -> Self {
        let mut p = Self {
            state: State::Serving { ticks_remaining: SERVE_DELAY_TICKS, server: Side::Left },
            left_score: 0,
            right_score: 0,
            left_paddle: Paddle { y_subpx: 0 },
            right_paddle: Paddle { y_subpx: 0 },
            ball: Ball { x_subpx: 0, y_subpx: 0, vx_subpx: 0, vy_subpx: 0 },
            rng: Xorshift64::new(seed),
        };
        p.center_paddles();
        p.position_ball_for_serve(Side::Left);
        p
    }

    // --- read-only accessors ---

    pub fn state(&self) -> State {
        self.state
    }

    pub fn left_score(&self) -> u8 {
        self.left_score
    }

    pub fn right_score(&self) -> u8 {
        self.right_score
    }

    pub fn left_paddle(&self) -> &Paddle {
        &self.left_paddle
    }

    pub fn right_paddle(&self) -> &Paddle {
        &self.right_paddle
    }

    pub fn ball(&self) -> &Ball {
        &self.ball
    }

    // --- step ---

    /// Advance one physics tick. `player_motion` is the left paddle's
    /// input for this tick (the AI drives the right paddle). Returns
    /// true iff visible state changed — caller uses this to decide
    /// whether to redraw.
    ///
    /// A tick in `MatchOver` returns false (nothing to redraw; the
    /// win banner is static). A tick in `Serving` returns true
    /// because the countdown visibly changes.
    pub fn step(&mut self, player_motion: PaddleMotion) -> bool {
        match self.state {
            State::MatchOver { .. } => false,
            State::Serving { ticks_remaining, server } => {
                if ticks_remaining == 0 {
                    // Actually launch the ball. Serve toward the
                    // OPPONENT of `server`: the convention is
                    // "loser serves next," and a serve goes toward
                    // the opponent's half.
                    self.launch_ball(server.flip());
                    self.state = State::Playing;
                } else {
                    // Paddles can still reposition during the countdown
                    // — feels less stilted than a frozen tableau.
                    self.move_player_paddle(player_motion);
                    self.run_ai();
                    self.state = State::Serving {
                        ticks_remaining: ticks_remaining - 1,
                        server,
                    };
                }
                true
            }
            State::Playing => {
                self.move_player_paddle(player_motion);
                self.run_ai();
                self.advance_ball_and_resolve_collisions();
                true
            }
        }
    }

    /// Fresh match: reset scores and paddles, Left serves.
    pub fn reset(&mut self) {
        self.left_score = 0;
        self.right_score = 0;
        self.center_paddles();
        self.position_ball_for_serve(Side::Left);
        self.state = State::Serving {
            ticks_remaining: SERVE_DELAY_TICKS,
            server: Side::Left,
        };
    }

    // --- internals ---

    fn center_paddles(&mut self) {
        let center = ((COURT_H - PADDLE_H) / 2) << PX_BITS;
        self.left_paddle.y_subpx = center;
        self.right_paddle.y_subpx = center;
    }

    /// Place the ball at court center with zero velocity. Used during
    /// Serving state — the ball only gets velocity when the countdown
    /// expires.
    fn position_ball_for_serve(&mut self, _server: Side) {
        self.ball.x_subpx = ((COURT_W - BALL_SIZE) / 2) << PX_BITS;
        self.ball.y_subpx = ((COURT_H - BALL_SIZE) / 2) << PX_BITS;
        self.ball.vx_subpx = 0;
        self.ball.vy_subpx = 0;
    }

    /// Give the ball a velocity heading `toward`. Called at the end of
    /// the Serving countdown.
    fn launch_ball(&mut self, toward: Side) {
        let sign: i32 = match toward {
            Side::Left => -1,
            Side::Right => 1,
        };
        self.ball.vx_subpx = sign * BALL_INITIAL_VX_SUBPX;
        // Initial vy: random in [-3, +3] px/tick. Purely horizontal
        // serves are boring — a small angle gets the rally moving.
        // Range is smaller than MAX_SPIN so a paddle hit can still
        // dominate the trajectory.
        let rng_u = self.rng.next_u64();
        // Map to -3..=3 px/tick inclusive (7 distinct values).
        let range: i32 = 7;
        let offset = (rng_u % range as u64) as i32 - (range / 2);
        self.ball.vy_subpx = offset * PX_ONE;
    }

    fn move_player_paddle(&mut self, motion: PaddleMotion) {
        let dy = match motion {
            PaddleMotion::None => 0,
            PaddleMotion::Up => -PLAYER_PADDLE_VY_SUBPX,
            PaddleMotion::Down => PLAYER_PADDLE_VY_SUBPX,
        };
        self.left_paddle.y_subpx += dy;
        self.left_paddle.clamp();
    }

    /// Ball-chasing AI: target the paddle top-edge that puts paddle
    /// center on ball center, move toward it at AI_MAX_VY (capped),
    /// ignore motion smaller than the deadband. Deliberately simpler
    /// than predictive AI — the speed cap is the beatability knob.
    fn run_ai(&mut self) {
        let paddle_half_h = (PADDLE_H << PX_BITS) / 2;
        let target_top = self.ball.center_y_subpx() - paddle_half_h;
        let delta = target_top - self.right_paddle.y_subpx;

        if delta.abs() < AI_DEADBAND_SUBPX {
            return;
        }

        let step = if delta > 0 {
            delta.min(AI_MAX_VY_SUBPX)
        } else {
            delta.max(-AI_MAX_VY_SUBPX)
        };
        self.right_paddle.y_subpx += step;
        self.right_paddle.clamp();
    }

    fn advance_ball_and_resolve_collisions(&mut self) {
        // Advance position first; collisions are AABB-checked against
        // the new position. Speed cap (BALL_MAX_VX_SUBPX) guarantees
        // |displacement| < BALL_SIZE so no tunneling.
        self.ball.x_subpx += self.ball.vx_subpx;
        self.ball.y_subpx += self.ball.vy_subpx;

        self.resolve_wall_collisions();
        self.resolve_paddle_collisions();
        self.resolve_scoring();
    }

    /// Reflect off top/bottom walls. Snap ball position to just inside
    /// the wall so a diagonal at the corner doesn't oscillate inside
    /// the boundary — one reflection per wall contact.
    fn resolve_wall_collisions(&mut self) {
        if self.ball.y_subpx < 0 && self.ball.vy_subpx < 0 {
            self.ball.y_subpx = -self.ball.y_subpx;
            self.ball.vy_subpx = -self.ball.vy_subpx;
        }
        let max_y = (COURT_H - BALL_SIZE) << PX_BITS;
        if self.ball.y_subpx > max_y && self.ball.vy_subpx > 0 {
            self.ball.y_subpx = max_y - (self.ball.y_subpx - max_y);
            self.ball.vy_subpx = -self.ball.vy_subpx;
        }
    }

    fn resolve_paddle_collisions(&mut self) {
        // Left paddle: ball moving left, ball's left edge crossed
        // paddle's right edge, and ball y-range overlaps paddle y-range.
        if self.ball.vx_subpx < 0 {
            let paddle_right = (LEFT_PADDLE_X + PADDLE_W) << PX_BITS;
            let paddle_left = LEFT_PADDLE_X << PX_BITS;
            if self.ball.x_subpx < paddle_right
                && self.ball.x_subpx + (BALL_SIZE << PX_BITS) > paddle_left
                && self.y_overlaps_paddle(&self.left_paddle)
            {
                self.ball.x_subpx = paddle_right; // unstick
                Self::bounce_off_paddle(&mut self.ball, &self.left_paddle);
            }
        }

        // Right paddle: ball moving right, ball's right edge crossed
        // paddle's left edge, and y-overlap.
        if self.ball.vx_subpx > 0 {
            let paddle_left = RIGHT_PADDLE_X << PX_BITS;
            let paddle_right = (RIGHT_PADDLE_X + PADDLE_W) << PX_BITS;
            let ball_right = self.ball.x_subpx + (BALL_SIZE << PX_BITS);
            if ball_right > paddle_left
                && self.ball.x_subpx < paddle_right
                && self.y_overlaps_paddle(&self.right_paddle)
            {
                self.ball.x_subpx = paddle_left - (BALL_SIZE << PX_BITS); // unstick
                Self::bounce_off_paddle(&mut self.ball, &self.right_paddle);
            }
        }
    }

    fn y_overlaps_paddle(&self, paddle: &Paddle) -> bool {
        let paddle_top = paddle.y_subpx;
        let paddle_bot = paddle.y_subpx + (PADDLE_H << PX_BITS);
        let ball_top = self.ball.y_subpx;
        let ball_bot = self.ball.y_subpx + (BALL_SIZE << PX_BITS);
        ball_bot > paddle_top && ball_top < paddle_bot
    }

    /// Reverse horizontal velocity, speed up by a small increment
    /// (capped), and set new vertical velocity based on where the
    /// ball struck the paddle. Classic Pong: hit the paddle's top
    /// edge → ball goes up fast; hit its bottom edge → ball goes
    /// down fast; hit center → flat return.
    fn bounce_off_paddle(ball: &mut Ball, paddle: &Paddle) {
        // Reverse + speed up horizontally.
        let new_abs_vx = (ball.vx_subpx.abs() + SPEEDUP_PER_HIT_SUBPX).min(BALL_MAX_VX_SUBPX);
        ball.vx_subpx = if ball.vx_subpx < 0 { new_abs_vx } else { -new_abs_vx };

        // Spin from hit offset. Fully determines vy — classic Pong.
        let offset = ball.center_y_subpx() - paddle.center_y_subpx();
        let half_paddle = (PADDLE_H << PX_BITS) / 2;
        let clamped = offset.clamp(-half_paddle, half_paddle);
        ball.vy_subpx = (clamped * MAX_SPIN_VY_SUBPX) / half_paddle;
    }

    fn resolve_scoring(&mut self) {
        let ball_right = self.ball.x_subpx + (BALL_SIZE << PX_BITS);
        let ball_left = self.ball.x_subpx;

        let scorer = if ball_right <= 0 {
            Some(Side::Right) // ball exited left wall → right scored
        } else if ball_left >= (COURT_W << PX_BITS) {
            Some(Side::Left)
        } else {
            None
        };

        let Some(scorer) = scorer else { return };

        match scorer {
            Side::Left => self.left_score = self.left_score.saturating_add(1),
            Side::Right => self.right_score = self.right_score.saturating_add(1),
        }

        if self.left_score >= WIN_SCORE {
            self.state = State::MatchOver { winner: Side::Left };
            return;
        }
        if self.right_score >= WIN_SCORE {
            self.state = State::MatchOver { winner: Side::Right };
            return;
        }

        // Reset ball; next serve goes to the loser (classic Pong:
        // server earns the next serve by losing, which is inverted
        // from tennis — CambiOS follows the original arcade rule).
        let next_server = scorer.flip();
        self.position_ball_for_serve(next_server);
        self.state = State::Serving {
            ticks_remaining: SERVE_DELAY_TICKS,
            server: next_server,
        };
    }
}

// --- PRNG (same shape as tree + worm) ---

/// xorshift64 — single-register PRNG, no deps. Seed 0 is replaced
/// with a non-zero constant so callers can pass an uninitialised 0
/// without getting stuck.
pub struct Xorshift64(u64);

impl Xorshift64 {
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

// ============================================================================
// Tests — host-side, no I/O. Exercises the state machine, collision,
// scoring, and AI. Shape matches worm::game::tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn advance_through_serve(p: &mut Pong) {
        // Tick the serve countdown + the first physics step that
        // launches the ball. After this, state must be Playing.
        for _ in 0..=SERVE_DELAY_TICKS as u32 {
            p.step(PaddleMotion::None);
        }
        assert!(matches!(p.state(), State::Playing));
    }

    #[test]
    fn new_game_starts_serving_left_zero_zero() {
        let p = Pong::new(1);
        assert_eq!(p.left_score(), 0);
        assert_eq!(p.right_score(), 0);
        match p.state() {
            State::Serving { server, ticks_remaining } => {
                assert_eq!(server, Side::Left);
                assert_eq!(ticks_remaining, SERVE_DELAY_TICKS);
            }
            s => panic!("expected Serving, got {s:?}"),
        }
    }

    #[test]
    fn serving_countdown_transitions_to_playing() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        // Ball must have a non-zero horizontal velocity now.
        assert_ne!(p.ball().vx_subpx, 0);
    }

    #[test]
    fn ball_reflects_off_top_wall() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        // Force a hard-upward ball trajectory right against the top.
        {
            // Private access via same module.
        }
        p.ball = Ball {
            x_subpx: (COURT_W / 2) << PX_BITS,
            y_subpx: PX_ONE, // 1 px from top
            vx_subpx: 3 * PX_ONE,
            vy_subpx: -5 * PX_ONE, // heading up hard
        };
        let _ = p.step(PaddleMotion::None);
        assert!(p.ball.vy_subpx > 0, "vy should reverse to positive");
    }

    #[test]
    fn ball_reflects_off_bottom_wall() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        p.ball = Ball {
            x_subpx: (COURT_W / 2) << PX_BITS,
            y_subpx: ((COURT_H - BALL_SIZE - 1) << PX_BITS),
            vx_subpx: 3 * PX_ONE,
            vy_subpx: 5 * PX_ONE,
        };
        let _ = p.step(PaddleMotion::None);
        assert!(p.ball.vy_subpx < 0, "vy should reverse to negative");
    }

    #[test]
    fn ball_exits_left_wall_scores_right() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        // Warp ball to the left of the court, moving further left so
        // no paddle can catch it.
        p.ball = Ball {
            x_subpx: -(BALL_SIZE << PX_BITS) - PX_ONE, // well past left
            y_subpx: 0,
            vx_subpx: -PX_ONE,
            vy_subpx: 0,
        };
        let _ = p.step(PaddleMotion::None);
        assert_eq!(p.right_score(), 1);
        assert_eq!(p.left_score(), 0);
        // After scoring, state is Serving, and the loser (Left) serves.
        match p.state() {
            State::Serving { server, .. } => assert_eq!(server, Side::Left),
            s => panic!("expected Serving after score, got {s:?}"),
        }
    }

    #[test]
    fn ball_exits_right_wall_scores_left() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        p.ball = Ball {
            x_subpx: (COURT_W << PX_BITS) + PX_ONE,
            y_subpx: 0,
            vx_subpx: PX_ONE,
            vy_subpx: 0,
        };
        let _ = p.step(PaddleMotion::None);
        assert_eq!(p.left_score(), 1);
        assert_eq!(p.right_score(), 0);
    }

    #[test]
    fn reaching_win_score_transitions_to_match_over() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        // Simulate Left at WIN_SCORE-1, then score one more.
        p.left_score = WIN_SCORE - 1;
        p.ball = Ball {
            x_subpx: (COURT_W << PX_BITS) + PX_ONE,
            y_subpx: 0,
            vx_subpx: PX_ONE,
            vy_subpx: 0,
        };
        p.state = State::Playing;
        let _ = p.step(PaddleMotion::None);
        match p.state() {
            State::MatchOver { winner } => assert_eq!(winner, Side::Left),
            s => panic!("expected MatchOver, got {s:?}"),
        }
    }

    #[test]
    fn match_over_step_is_noop() {
        let mut p = Pong::new(1);
        p.state = State::MatchOver { winner: Side::Left };
        let changed = p.step(PaddleMotion::Up);
        assert!(!changed);
        assert!(matches!(p.state(), State::MatchOver { .. }));
    }

    #[test]
    fn reset_returns_to_zero_zero_serving_left() {
        let mut p = Pong::new(1);
        p.left_score = 4;
        p.right_score = 3;
        p.state = State::MatchOver { winner: Side::Left };
        p.reset();
        assert_eq!(p.left_score(), 0);
        assert_eq!(p.right_score(), 0);
        match p.state() {
            State::Serving { server, .. } => assert_eq!(server, Side::Left),
            s => panic!("expected Serving after reset, got {s:?}"),
        }
    }

    #[test]
    fn player_paddle_moves_up_with_up_motion() {
        let mut p = Pong::new(1);
        let y0 = p.left_paddle.y_subpx;
        let _ = p.step(PaddleMotion::Up);
        assert!(p.left_paddle.y_subpx < y0);
    }

    #[test]
    fn player_paddle_moves_down_with_down_motion() {
        let mut p = Pong::new(1);
        let y0 = p.left_paddle.y_subpx;
        let _ = p.step(PaddleMotion::Down);
        assert!(p.left_paddle.y_subpx > y0);
    }

    #[test]
    fn player_paddle_clamps_at_top() {
        let mut p = Pong::new(1);
        // Drive paddle up for many ticks — must not go above 0.
        for _ in 0..200 {
            let _ = p.step(PaddleMotion::Up);
        }
        assert_eq!(p.left_paddle.y_subpx, 0);
    }

    #[test]
    fn player_paddle_clamps_at_bottom() {
        let mut p = Pong::new(1);
        for _ in 0..200 {
            let _ = p.step(PaddleMotion::Down);
        }
        assert_eq!(
            p.left_paddle.y_subpx,
            (COURT_H - PADDLE_H) << PX_BITS
        );
    }

    #[test]
    fn bouncing_off_paddle_reverses_vx_and_speeds_up() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);

        // Position the left paddle so its center aligns with ball
        // center (flat return expected), and put the ball just past
        // the paddle's right edge moving left.
        p.left_paddle.y_subpx = ((COURT_H - PADDLE_H) / 2) << PX_BITS;
        let initial_vx: i32 = -BALL_INITIAL_VX_SUBPX;
        p.ball = Ball {
            x_subpx: (LEFT_PADDLE_X + PADDLE_W - 1) << PX_BITS,
            y_subpx: p.left_paddle.center_y_subpx() - (BALL_SIZE << PX_BITS) / 2,
            vx_subpx: initial_vx,
            vy_subpx: 0,
        };

        let _ = p.step(PaddleMotion::None);
        assert!(p.ball.vx_subpx > 0, "vx should be positive after left-paddle bounce");
        assert!(
            p.ball.vx_subpx > initial_vx.abs(),
            "speedup: |vx| must exceed initial magnitude"
        );
    }

    #[test]
    fn bouncing_off_paddle_edge_imparts_spin() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);

        // Put the paddle at the top of the court, ball near the
        // paddle's TOP edge. Hit there should send the ball upward.
        p.left_paddle.y_subpx = 0;
        p.ball = Ball {
            x_subpx: (LEFT_PADDLE_X + PADDLE_W - 1) << PX_BITS,
            y_subpx: 0, // ball top at paddle top → offset is negative
            vx_subpx: -BALL_INITIAL_VX_SUBPX,
            vy_subpx: 0,
        };
        let _ = p.step(PaddleMotion::None);
        assert!(p.ball.vy_subpx < 0, "top-of-paddle hit should send ball up (vy<0)");
    }

    #[test]
    fn paddle_speed_cap_respected() {
        // Simulate many hits and confirm vx magnitude never exceeds
        // the cap. Bounded iteration — 1000 rallies is wildly more
        // than any real match.
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        for _ in 0..1000 {
            // Force a paddle hit every iteration by teleporting ball
            // onto left paddle centered.
            p.left_paddle.y_subpx = ((COURT_H - PADDLE_H) / 2) << PX_BITS;
            p.ball = Ball {
                x_subpx: (LEFT_PADDLE_X + PADDLE_W - 1) << PX_BITS,
                y_subpx: p.left_paddle.center_y_subpx() - (BALL_SIZE << PX_BITS) / 2,
                vx_subpx: -BALL_INITIAL_VX_SUBPX,
                vy_subpx: 0,
            };
            let _ = p.step(PaddleMotion::None);
            assert!(p.ball.vx_subpx.abs() <= BALL_MAX_VX_SUBPX);
        }
    }

    #[test]
    fn ai_paddle_follows_ball_vertically() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        // Put ball at the top of the court; AI paddle starts centered.
        p.ball.y_subpx = 0;
        p.ball.vx_subpx = 0;
        p.ball.vy_subpx = 0;
        let start = p.right_paddle.y_subpx;
        for _ in 0..200 {
            let _ = p.step(PaddleMotion::None);
        }
        assert!(
            p.right_paddle.y_subpx < start,
            "AI should have moved up toward a ball at y=0"
        );
        // AI must clamp — never above 0.
        assert!(p.right_paddle.y_subpx >= 0);
    }

    #[test]
    fn ai_deadband_prevents_twitch_when_aligned() {
        let mut p = Pong::new(1);
        advance_through_serve(&mut p);
        // Perfectly align AI paddle center to ball center.
        let paddle_half_h = (PADDLE_H << PX_BITS) / 2;
        p.right_paddle.y_subpx = p.ball.center_y_subpx() - paddle_half_h;
        let y0 = p.right_paddle.y_subpx;
        // Stop ball so its y-position doesn't drift across ticks.
        p.ball.vx_subpx = 0;
        p.ball.vy_subpx = 0;
        let _ = p.step(PaddleMotion::None);
        assert_eq!(p.right_paddle.y_subpx, y0, "AI shouldn't twitch inside deadband");
    }

    #[test]
    fn side_flip_is_involution() {
        assert_eq!(Side::Left.flip(), Side::Right);
        assert_eq!(Side::Right.flip(), Side::Left);
        assert_eq!(Side::Left.flip().flip(), Side::Left);
    }
}
