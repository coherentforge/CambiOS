// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O game state + tick — pure logic, host-testable.
//!
//! Session 2b+2c adds:
//! - `Player`: world position, velocity, on-ground flag, facing.
//! - `Input`: directional-hold flags + edge-triggered jump.
//! - `Game::tick(&Input)`: accel / gravity / jump integration, then
//!   axis-separated AABB-vs-tilemap collision, then camera follow.
//!
//! 2d adds a `Weed` entity + patrol + stomp interaction; 2e adds pit
//! detection + a `Status::Lost` state + restart via R.
//!
//! ## Coordinate + AABB conventions
//!
//! - `player.x, player.y` are the *world-space pixel* top-left of the
//!   player's collision AABB (same as the sprite top-left for v0).
//! - Player size is fixed `PLAYER_W × PLAYER_H`.
//! - Gravity is positive; falling is positive vel_y.
//! - Collision box is half-open `[x, x + w) × [y, y + h)`.

use crate::level::{self, tile_at, LEVEL_COLS, SURFACE_H, SURFACE_W, TILE_SIZE, WEED_SPAWNS};

/// TUNING: horizontal acceleration (px per tick squared).
const ACCEL_X: i32 = 2;

/// TUNING: max horizontal speed (px/tick). Crosses a 32-px tile in
/// ~8 ticks = ~0.24 s at 33 FPS.
const MAX_SPEED_X: i32 = 4;

/// TUNING: friction deceleration when no horizontal input.
const FRICTION_X: i32 = 1;

/// TUNING: gravity (px per tick squared).
const GRAVITY_Y: i32 = 1;

/// TUNING: jump impulse. Gives an arc that clears a 3-tile gap at
/// full run speed.
const JUMP_IMPULSE_Y: i32 = -10;

/// TUNING: terminal fall speed. Caps per-tick displacement below one
/// tile so the swept-axis collision below can't tunnel.
const TERMINAL_Y: i32 = 12;

/// Player AABB size. Matches the sprite cell; visually snug.
pub const PLAYER_W: u32 = 32;
pub const PLAYER_H: u32 = 32;

/// Player spawn position — column 4, row 8 (feet at the row-9 ground).
pub const SPAWN_X: i32 = 4 * TILE_SIZE as i32;
pub const SPAWN_Y: i32 = 8 * TILE_SIZE as i32;

/// Weed AABB size. Matches the sprite cell.
pub const WEED_W: u32 = 32;
pub const WEED_H: u32 = 32;

/// TUNING: weed patrol speed (px / tick). Slower than the player so
/// stomping feels reliable even at reduced reaction time.
const WEED_SPEED: i32 = 1;

/// Vertical band (px) at the weed's top counted as a stomp. A player
/// whose AABB bottom is within `(weed.y, weed.y + STOMP_BAND]` while
/// falling is stomping; anywhere else is a side-hit death.
const STOMP_BAND: i32 = 10;

/// Maximum simultaneous weeds. Fixed-array to stay off the allocator.
pub const MAX_WEEDS: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Playing,
    /// Killed by a weed side-hit or a pit fall. Tick is suspended;
    /// `Game::reset` returns to `Playing`.
    Dead,
}

#[derive(Clone, Copy)]
pub struct Weed {
    pub x: i32,
    pub y: i32,
    /// `+WEED_SPEED` or `-WEED_SPEED` — sign is the facing direction.
    pub vel_x: i32,
}

impl Weed {
    pub fn facing_right(&self) -> bool {
        self.vel_x > 0
    }
}

#[derive(Clone, Copy)]
pub struct Player {
    pub x: i32,
    pub y: i32,
    pub vel_x: i32,
    pub vel_y: i32,
    pub on_ground: bool,
    pub facing_right: bool,
}

impl Player {
    pub fn spawn() -> Self {
        Self {
            x: SPAWN_X,
            y: SPAWN_Y,
            vel_x: 0,
            vel_y: 0,
            on_ground: true,
            facing_right: true,
        }
    }
}

#[derive(Default, Clone, Copy)]
pub struct Input {
    pub left_held: bool,
    pub right_held: bool,
    /// Edge-triggered: set on KeyDown, cleared by `Game::tick` after use.
    pub jump_pressed: bool,
}

/// Single source of truth consumed by the renderer.
pub struct Game {
    pub player: Player,
    pub weeds: [Option<Weed>; MAX_WEEDS],
    pub camera_x: i32,
    pub status: Status,
}

impl Game {
    pub fn new() -> Self {
        Self {
            player: Player::spawn(),
            weeds: spawn_weeds(),
            camera_x: 0,
            status: Status::Playing,
        }
    }

    /// Reset to the spawn state — called on R-press after death.
    pub fn reset(&mut self) {
        self.player = Player::spawn();
        self.weeds = spawn_weeds();
        self.camera_x = 0;
        self.status = Status::Playing;
    }

    /// Advance one physics tick. Mutates `input.jump_pressed` to
    /// clear the edge bit — caller sees it consumed on return.
    pub fn tick(&mut self, input: &mut Input) {
        if self.status != Status::Playing {
            // Drain the jump edge so it doesn't fire on the first
            // post-reset tick.
            input.jump_pressed = false;
            return;
        }
        self.apply_horizontal_input(input);
        self.apply_vertical_input(input);
        self.apply_gravity();
        self.resolve_horizontal_motion();
        self.resolve_vertical_motion();
        self.tick_weeds();
        self.check_player_weed_collisions();
        self.check_pit();
        self.follow_camera();
    }

    fn apply_horizontal_input(&mut self, input: &Input) {
        if input.left_held && !input.right_held {
            self.player.vel_x = (self.player.vel_x - ACCEL_X).max(-MAX_SPEED_X);
            self.player.facing_right = false;
        } else if input.right_held && !input.left_held {
            self.player.vel_x = (self.player.vel_x + ACCEL_X).min(MAX_SPEED_X);
            self.player.facing_right = true;
        } else if self.player.vel_x > 0 {
            self.player.vel_x = (self.player.vel_x - FRICTION_X).max(0);
        } else if self.player.vel_x < 0 {
            self.player.vel_x = (self.player.vel_x + FRICTION_X).min(0);
        }
    }

    fn apply_vertical_input(&mut self, input: &mut Input) {
        if input.jump_pressed && self.player.on_ground {
            self.player.vel_y = JUMP_IMPULSE_Y;
            self.player.on_ground = false;
        }
        input.jump_pressed = false; // consume edge
    }

    fn apply_gravity(&mut self) {
        self.player.vel_y = (self.player.vel_y + GRAVITY_Y).min(TERMINAL_Y);
    }

    /// Move horizontally then resolve any solid-tile overlap by snapping
    /// to the offending tile edge. Zeroes vel_x on contact.
    fn resolve_horizontal_motion(&mut self) {
        if self.player.vel_x == 0 {
            return;
        }
        self.player.x += self.player.vel_x;

        // Horizontal world clamp (level edges — Sprouty can't walk off
        // the authored strip to the left / right).
        let level_px = LEVEL_COLS as i32 * TILE_SIZE as i32;
        if self.player.x < 0 {
            self.player.x = 0;
            self.player.vel_x = 0;
        } else if self.player.x + PLAYER_W as i32 > level_px {
            self.player.x = level_px - PLAYER_W as i32;
            self.player.vel_x = 0;
        }

        // Tile collision: check each tile in the AABB's vertical span.
        if let Some((overlap_col, direction)) = self.find_horizontal_collision() {
            let tile_px = overlap_col * TILE_SIZE as i32;
            if direction > 0 {
                // Moving right — snap so AABB right edge sits on tile left.
                self.player.x = tile_px - PLAYER_W as i32;
            } else {
                // Moving left — snap so AABB left edge sits on tile right.
                self.player.x = tile_px + TILE_SIZE as i32;
            }
            self.player.vel_x = 0;
        }
    }

    /// Move vertically then resolve tile overlap. Updates `on_ground`
    /// when landing on a ceiling-up tile; zeroes vel_y on contact.
    fn resolve_vertical_motion(&mut self) {
        // Default: airborne. A landing below resets it.
        if self.player.vel_y != 0 {
            self.player.on_ground = false;
        }
        if self.player.vel_y == 0 {
            // Still need to re-check ground under foot (in case the
            // horizontal move walked off a ledge).
            self.player.on_ground = self.standing_on_ground();
            return;
        }

        self.player.y += self.player.vel_y;

        if let Some((overlap_row, direction)) = self.find_vertical_collision() {
            let tile_px = overlap_row * TILE_SIZE as i32;
            if direction > 0 {
                // Falling — AABB bottom into tile top.
                self.player.y = tile_px - PLAYER_H as i32;
                self.player.on_ground = true;
            } else {
                // Jumping — AABB top into tile bottom.
                self.player.y = tile_px + TILE_SIZE as i32;
            }
            self.player.vel_y = 0;
        }
    }

    /// Test whether a solid tile is directly under the player's feet
    /// (one pixel below the AABB bottom). Covers the "walked off a
    /// ledge" transition where vel_y is still 0.
    fn standing_on_ground(&self) -> bool {
        let below_y = self.player.y + PLAYER_H as i32;
        let left_col = self.player.x / TILE_SIZE as i32;
        let right_col = (self.player.x + PLAYER_W as i32 - 1) / TILE_SIZE as i32;
        let row = below_y / TILE_SIZE as i32;
        let mut c = left_col;
        while c <= right_col {
            if tile_at(c, row) == level::GROUND {
                return true;
            }
            c += 1;
        }
        false
    }

    /// Find the first column (in the direction of motion) whose solid
    /// tiles overlap the player AABB. Returns (column, direction) where
    /// direction is +1 for right-motion, -1 for left.
    fn find_horizontal_collision(&self) -> Option<(i32, i32)> {
        let dir = if self.player.vel_x > 0 { 1 } else { -1 };
        let left = self.player.x;
        let right = self.player.x + PLAYER_W as i32 - 1;
        let top_row = self.player.y / TILE_SIZE as i32;
        let bot_row = (self.player.y + PLAYER_H as i32 - 1) / TILE_SIZE as i32;
        // Column to test: leading edge for this direction.
        let test_col = if dir > 0 {
            right / TILE_SIZE as i32
        } else {
            left / TILE_SIZE as i32
        };
        let mut r = top_row;
        while r <= bot_row {
            if tile_at(test_col, r) == level::GROUND {
                return Some((test_col, dir));
            }
            r += 1;
        }
        None
    }

    /// Find the first row (in the direction of motion) whose solid tiles
    /// overlap the player AABB. Returns (row, direction) where +1 is
    /// falling, -1 is jumping.
    fn find_vertical_collision(&self) -> Option<(i32, i32)> {
        let dir = if self.player.vel_y > 0 { 1 } else { -1 };
        let top = self.player.y;
        let bot = self.player.y + PLAYER_H as i32 - 1;
        let left_col = self.player.x / TILE_SIZE as i32;
        let right_col = (self.player.x + PLAYER_W as i32 - 1) / TILE_SIZE as i32;
        let test_row = if dir > 0 {
            bot / TILE_SIZE as i32
        } else {
            top / TILE_SIZE as i32
        };
        let mut c = left_col;
        while c <= right_col {
            if tile_at(c, test_row) == level::GROUND {
                return Some((test_row, dir));
            }
            c += 1;
        }
        None
    }

    /// Advance each live weed one step. Reverse direction when the
    /// next position would walk into a wall or off a ledge.
    fn tick_weeds(&mut self) {
        let mut i = 0;
        while i < MAX_WEEDS {
            if let Some(mut w) = self.weeds[i] {
                let next_x = w.x + w.vel_x;
                let body_row = w.y / TILE_SIZE as i32;
                // Row directly under the weed's feet — ground tiles here
                // support it, AIR means a ledge / pit.
                let support_row = (w.y + WEED_H as i32) / TILE_SIZE as i32;
                let leading_col = if w.vel_x > 0 {
                    (next_x + WEED_W as i32 - 1) / TILE_SIZE as i32
                } else {
                    next_x / TILE_SIZE as i32
                };
                let wall = tile_at(leading_col, body_row) == level::GROUND;
                let ledge = tile_at(leading_col, support_row) != level::GROUND;
                if wall || ledge {
                    w.vel_x = -w.vel_x;
                } else {
                    w.x = next_x;
                }
                self.weeds[i] = Some(w);
            }
            i += 1;
        }
    }

    /// Test every live weed against the player AABB. Stomp (player
    /// falling onto weed top) removes the weed and bounces the
    /// player; any other overlap kills the player.
    fn check_player_weed_collisions(&mut self) {
        let px0 = self.player.x;
        let py0 = self.player.y;
        let px1 = px0 + PLAYER_W as i32;
        let py1 = py0 + PLAYER_H as i32;

        let mut i = 0;
        while i < MAX_WEEDS {
            if let Some(w) = self.weeds[i] {
                let wx0 = w.x;
                let wy0 = w.y;
                let wx1 = wx0 + WEED_W as i32;
                let wy1 = wy0 + WEED_H as i32;
                let overlap = px0 < wx1 && px1 > wx0 && py0 < wy1 && py1 > wy0;
                if overlap {
                    // Stomp: falling, and AABB bottom is within the
                    // weed's top STOMP_BAND pixels.
                    let stomping =
                        self.player.vel_y > 0 && py1 <= wy0 + STOMP_BAND;
                    if stomping {
                        self.weeds[i] = None;
                        self.player.vel_y = JUMP_IMPULSE_Y / 2;
                    } else {
                        self.status = Status::Dead;
                    }
                }
            }
            i += 1;
        }
    }

    /// Player has fallen past the viewport bottom — count as death.
    fn check_pit(&mut self) {
        if self.player.y > SURFACE_H as i32 {
            self.status = Status::Dead;
        }
    }

    fn follow_camera(&mut self) {
        let target = self.player.x + PLAYER_W as i32 / 2 - SURFACE_W as i32 / 2;
        self.camera_x = target;
        self.clamp_camera();
    }

    /// Clamp the camera to the level's horizontal bounds.
    pub fn clamp_camera(&mut self) {
        let level_px = LEVEL_COLS as i32 * TILE_SIZE as i32;
        let max = (level_px - SURFACE_W as i32).max(0);
        if self.camera_x < 0 {
            self.camera_x = 0;
        } else if self.camera_x > max {
            self.camera_x = max;
        }
    }
}

impl Default for Game {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the initial weed array from `WEED_SPAWNS`. Extra array slots
/// stay `None`.
fn spawn_weeds() -> [Option<Weed>; MAX_WEEDS] {
    let mut out: [Option<Weed>; MAX_WEEDS] = [None; MAX_WEEDS];
    let mut i = 0;
    while i < MAX_WEEDS && i < WEED_SPAWNS.len() {
        let (x, y) = WEED_SPAWNS[i];
        out[i] = Some(Weed { x, y, vel_x: WEED_SPEED });
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(left: bool, right: bool, jump: bool) -> Input {
        Input { left_held: left, right_held: right, jump_pressed: jump }
    }

    #[test]
    fn spawn_state_is_sane() {
        let g = Game::new();
        assert_eq!(g.player.x, SPAWN_X);
        assert_eq!(g.player.y, SPAWN_Y);
        assert_eq!(g.player.vel_x, 0);
        assert_eq!(g.player.vel_y, 0);
        assert!(g.player.on_ground);
    }

    #[test]
    fn accel_right_reaches_max_speed() {
        let mut g = Game::new();
        let mut input = held(false, true, false);
        for _ in 0..10 {
            g.tick(&mut input);
        }
        assert_eq!(g.player.vel_x, MAX_SPEED_X);
        assert!(g.player.facing_right);
    }

    #[test]
    fn accel_left_reaches_negative_max_speed() {
        let mut g = Game::new();
        let mut input = held(true, false, false);
        for _ in 0..10 {
            g.tick(&mut input);
        }
        assert_eq!(g.player.vel_x, -MAX_SPEED_X);
        assert!(!g.player.facing_right);
    }

    #[test]
    fn friction_decays_vel_x_to_zero_when_no_input() {
        let mut g = Game::new();
        g.player.vel_x = 4;
        let mut input = Input::default();
        for _ in 0..10 {
            g.tick(&mut input);
        }
        assert_eq!(g.player.vel_x, 0);
    }

    #[test]
    fn both_directions_held_cancel_to_zero_accel() {
        let mut g = Game::new();
        g.player.vel_x = 3;
        let mut input = held(true, true, false);
        g.tick(&mut input);
        // With no net accel but friction active, magnitude should decay.
        assert!(g.player.vel_x.abs() < 3);
    }

    #[test]
    fn jump_impulse_only_triggers_on_ground() {
        let mut g = Game::new();
        let mut input = held(false, false, true);
        g.tick(&mut input);
        assert_eq!(g.player.vel_y, JUMP_IMPULSE_Y + GRAVITY_Y); // jump + 1 gravity tick
        assert!(!g.player.on_ground);
        // Second jump attempt while airborne is ignored.
        let mut input2 = held(false, false, true);
        let prev_vy = g.player.vel_y;
        g.tick(&mut input2);
        // vel_y continues to accelerate downward by GRAVITY_Y, not reset
        // to JUMP_IMPULSE_Y.
        assert_eq!(g.player.vel_y, (prev_vy + GRAVITY_Y).min(TERMINAL_Y));
    }

    #[test]
    fn jump_edge_consumed_after_tick() {
        let mut g = Game::new();
        let mut input = held(false, false, true);
        g.tick(&mut input);
        assert!(!input.jump_pressed);
    }

    #[test]
    fn gravity_caps_at_terminal() {
        // Start far above the authored strip so collision never fires
        // — isolates the gravity-accumulation path from the resolver.
        let mut g = Game::new();
        g.player.y = -10_000;
        g.player.on_ground = false;
        let mut input = Input::default();
        for _ in 0..50 {
            g.tick(&mut input);
        }
        assert_eq!(g.player.vel_y, TERMINAL_Y);
    }

    #[test]
    fn player_stands_on_spawn_ground() {
        // Spawn is row 8, feet touch row 9 which is GROUND for col 4.
        let mut g = Game::new();
        let mut input = Input::default();
        for _ in 0..10 {
            g.tick(&mut input);
        }
        assert_eq!(g.player.y, SPAWN_Y, "player should rest on ground");
        assert_eq!(g.player.vel_y, 0);
        assert!(g.player.on_ground);
    }

    #[test]
    fn player_falls_over_pit() {
        let mut g = Game::new();
        // Place player directly above first pit (col 15, row 8).
        g.player.x = 15 * TILE_SIZE as i32;
        g.player.y = 8 * TILE_SIZE as i32;
        g.player.on_ground = false;
        let mut input = Input::default();
        let start_y = g.player.y;
        for _ in 0..20 {
            g.tick(&mut input);
        }
        assert!(g.player.y > start_y, "player should be falling");
        assert!(!g.player.on_ground);
    }

    #[test]
    fn horizontal_level_edge_clamp() {
        let mut g = Game::new();
        g.player.x = 0;
        g.player.vel_x = -MAX_SPEED_X;
        let mut input = held(true, false, false);
        g.tick(&mut input);
        assert_eq!(g.player.x, 0);
        assert_eq!(g.player.vel_x, 0);
    }

    #[test]
    fn walking_off_ledge_clears_on_ground() {
        let mut g = Game::new();
        // Put player one pixel from the first pit's left edge.
        g.player.x = 15 * TILE_SIZE as i32 - 1;
        g.player.y = SPAWN_Y;
        g.player.on_ground = true;
        let mut input = held(false, true, false); // walk right
        // Tick a few times to walk into the pit.
        for _ in 0..6 {
            g.tick(&mut input);
        }
        // Eventually vel_y > 0 and not on_ground.
        assert!(!g.player.on_ground, "expected to have walked off ledge");
    }

    #[test]
    fn camera_follows_player_and_clamps() {
        let mut g = Game::new();
        // At spawn (world x=128, SURFACE_W=480, PLAYER_W=32),
        // target = 128 + 16 - 240 = -96 → clamped to 0.
        let mut input = Input::default();
        g.tick(&mut input);
        assert_eq!(g.camera_x, 0);

        // Teleport player near the right edge.
        g.player.x = (LEVEL_COLS as i32 * TILE_SIZE as i32) - PLAYER_W as i32;
        g.tick(&mut input);
        let level_px = LEVEL_COLS as i32 * TILE_SIZE as i32;
        let max = level_px - SURFACE_W as i32;
        assert_eq!(g.camera_x, max);
    }

    // NOTE: ceiling-hit case (vel_y < 0 colliding with a solid tile
    // above) is symmetric to the falling-onto-ground case and shares
    // the same resolver branch. Without platform tiles in the level,
    // constructing one in a unit test would mean mutating LEVEL at
    // runtime. Revisit when Session 3 adds elevation tiles and a real
    // ceiling geometry is available to stand up in a fixture.

    #[test]
    fn new_game_populates_weeds_from_spawns() {
        let g = Game::new();
        let live: usize = g.weeds.iter().filter(|w| w.is_some()).count();
        assert_eq!(live, WEED_SPAWNS.len());
    }

    #[test]
    fn weed_patrols_but_reverses_at_ledge() {
        // Weed 0 spawns at col 8 moving right. Run enough ticks for it
        // to reach the first pit edge (col 15). Past that its vel_x
        // should have flipped at least once.
        let mut g = Game::new();
        let initial_vx = g.weeds[0].unwrap().vel_x;
        let mut input = Input::default();
        // 15 - 8 = 7 tiles = 224 px at WEED_SPEED=1 → ~224 ticks min.
        for _ in 0..300 {
            g.tick(&mut input);
        }
        let later_vx = g.weeds[0].unwrap().vel_x;
        // Without pit reversal, vel_x would stay at initial sign. With
        // reversal, it must have flipped by now (weed can't have
        // walked into the pit).
        assert!(
            later_vx != initial_vx || g.weeds[0].unwrap().x < 15 * TILE_SIZE as i32,
            "weed either reversed or stayed left of the pit"
        );
        // Stronger: weed position stays within its island [0, 14].
        let w = g.weeds[0].unwrap();
        assert!(w.x < 15 * TILE_SIZE as i32, "weed crossed into pit");
    }

    #[test]
    fn player_stomp_kills_weed_and_bounces() {
        let mut g = Game::new();
        // Teleport player directly above weed 0, falling.
        let w = g.weeds[0].unwrap();
        g.player.x = w.x;
        g.player.y = w.y - PLAYER_H as i32 + 4; // feet within STOMP_BAND
        g.player.vel_y = 4; // falling
        g.check_player_weed_collisions();
        assert!(g.weeds[0].is_none(), "weed 0 should be stomped");
        assert_eq!(g.player.vel_y, JUMP_IMPULSE_Y / 2);
        assert_eq!(g.status, Status::Playing);
    }

    #[test]
    fn player_side_hit_kills_player() {
        let mut g = Game::new();
        let w = g.weeds[0].unwrap();
        // Align player horizontally and vertically with the weed
        // (same y, overlapping x). Not falling → side hit.
        g.player.x = w.x;
        g.player.y = w.y;
        g.player.vel_y = 0;
        g.check_player_weed_collisions();
        assert_eq!(g.status, Status::Dead);
        // Weed survived.
        assert!(g.weeds[0].is_some());
    }

    #[test]
    fn pit_fall_kills_player() {
        let mut g = Game::new();
        g.player.y = SURFACE_H as i32 + 1;
        g.check_pit();
        assert_eq!(g.status, Status::Dead);
    }

    #[test]
    fn reset_after_death_restores_spawn_state() {
        let mut g = Game::new();
        g.status = Status::Dead;
        g.player.x = 1234;
        g.player.y = 5678;
        g.weeds[0] = None;
        g.camera_x = 999;
        g.reset();
        assert_eq!(g.status, Status::Playing);
        assert_eq!(g.player.x, SPAWN_X);
        assert_eq!(g.player.y, SPAWN_Y);
        assert!(g.weeds[0].is_some());
        assert_eq!(g.camera_x, 0);
    }

    #[test]
    fn tick_does_nothing_when_dead() {
        let mut g = Game::new();
        g.status = Status::Dead;
        let before = (g.player.x, g.player.y, g.weeds[0].unwrap().x);
        let mut input = Input { left_held: false, right_held: true, jump_pressed: true };
        g.tick(&mut input);
        g.tick(&mut input);
        let after = (g.player.x, g.player.y, g.weeds[0].unwrap().x);
        assert_eq!(before, after);
        // Jump edge drained on Dead path too.
        assert!(!input.jump_pressed);
    }
}
