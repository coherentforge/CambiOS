// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Tree game logic — pure bookkeeping, no I/O.
//!
//! Mirrors `BuddyAllocator`'s structural posture (per CLAUDE.md's
//! Formal Verification constraint): algorithm-only, all state in
//! explicit enums, no panics in reachable paths, bounded iteration.
//! The rendering and input layers (`render.rs`, `main.rs`) consume
//! this module; this module does not know they exist.
//!
//! Rules are classic minesweeper, Beginner preset: 9×9 / 10 mines,
//! `reveal` / `toggle_flag`, flood-fill on zero-adjacency reveals,
//! win on all-non-mines revealed, loss on mine revealed. Mines are
//! placed on the first `reveal` call (not at board construction) so
//! the first click and its 8 neighbours are guaranteed safe.

pub const BOARD_SIZE: u8 = 9;
pub const CELL_COUNT: usize = (BOARD_SIZE as usize) * (BOARD_SIZE as usize);
pub const MINE_COUNT: u8 = 10;

/// Visible state of a cell. Covered is the initial state; Flagged is
/// the player's mark (does not reveal the underlying mine/dirt);
/// Revealed means the player dug here — if the underlying slot was a
/// mine, the game is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    Covered,
    Flagged,
    Revealed,
}

/// Terminal state of a game.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Playing,
    Won,
    Lost,
}

/// Outcome of a single `reveal` call, used by the caller to drive
/// visual feedback (the renderer does not need this — it reads
/// `Board::state()` and cell grid directly — but main.rs uses it to
/// decide whether to redraw).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevealOutcome {
    /// Click landed on a non-mine cell and the grid changed.
    Progress,
    /// Click was a no-op: already revealed, or flagged, or game over.
    NoChange,
    /// Click landed on a mine — game over.
    Hit,
    /// Last safe cell was revealed.
    Win,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagOutcome {
    Toggled,
    NoChange,
}

pub struct Board {
    cells: [Cell; CELL_COUNT],
    mines: [bool; CELL_COUNT],
    /// Mines are placed lazily on the first `reveal` so we can guarantee
    /// the first click is safe. False until that first reveal fires.
    placed: bool,
    state: State,
    flags: u8,
    revealed: u16,
    rng: Xorshift64,
    /// Set to true after the first board has been generated. Used to
    /// decide whether subsequent `reset()` calls are "first run"
    /// (safe-first-click) or "replay" (mines placed as-is). The
    /// intent per scope discussion: long-term, safe-first-click comes
    /// off after the first game; for v0 it stays on every game (the
    /// player is still getting used to the UI). Tracked so a future
    /// change can flip the policy without re-threading API.
    #[allow(dead_code)]
    first_game_complete: bool,
}

impl Board {
    /// New board. Seed comes from the caller (usually `sys::get_time()`
    /// xor `sys::get_pid()`). Mines are *not* placed yet; the first
    /// `reveal` decides their positions around the clicked cell.
    pub fn new(seed: u64) -> Self {
        Self {
            cells: [Cell::Covered; CELL_COUNT],
            mines: [false; CELL_COUNT],
            placed: false,
            state: State::Playing,
            flags: 0,
            revealed: 0,
            rng: Xorshift64::new(seed),
            first_game_complete: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn cell(&self, row: u8, col: u8) -> Cell {
        self.cells[Self::idx(row, col)]
    }

    /// True after the underlying slot holds a mine. Only meaningful
    /// after `placed == true` or after game-over (for drawing revealed
    /// mines at loss).
    pub fn is_mine(&self, row: u8, col: u8) -> bool {
        self.mines[Self::idx(row, col)]
    }

    /// Number of mines currently flagged. For the "Flags: N/10"
    /// readout — NOT a correctness signal (player can misflag).
    pub fn flags_placed(&self) -> u8 {
        self.flags
    }

    /// 0..=8 mines in the 8 neighbours of (row, col). Undefined-but-
    /// harmless if the cell itself is a mine; callers should only
    /// read this for revealed non-mine cells.
    pub fn adjacent(&self, row: u8, col: u8) -> u8 {
        let mut count = 0u8;
        for (nr, nc) in neighbours(row, col) {
            if self.mines[Self::idx(nr, nc)] {
                count += 1;
            }
        }
        count
    }

    /// Toggle a flag on (row, col). No-op if the cell is already
    /// revealed, if the game is over, or if adding a flag would
    /// exceed MINE_COUNT (matches classic minesweeper — flags are a
    /// limited resource == mine count).
    pub fn toggle_flag(&mut self, row: u8, col: u8) -> FlagOutcome {
        if self.state != State::Playing {
            return FlagOutcome::NoChange;
        }
        let i = Self::idx(row, col);
        match self.cells[i] {
            Cell::Covered => {
                if self.flags >= MINE_COUNT {
                    return FlagOutcome::NoChange;
                }
                self.cells[i] = Cell::Flagged;
                self.flags += 1;
                FlagOutcome::Toggled
            }
            Cell::Flagged => {
                self.cells[i] = Cell::Covered;
                self.flags -= 1;
                FlagOutcome::Toggled
            }
            Cell::Revealed => FlagOutcome::NoChange,
        }
    }

    /// Reveal (row, col). On the first call of a game, mines are
    /// placed avoiding (row, col) and its 8 neighbours. Revealing a
    /// zero-adjacency cell flood-fills its neighbours recursively
    /// (iteratively, bounded by `CELL_COUNT`).
    pub fn reveal(&mut self, row: u8, col: u8) -> RevealOutcome {
        if self.state != State::Playing {
            return RevealOutcome::NoChange;
        }
        let i = Self::idx(row, col);
        match self.cells[i] {
            Cell::Flagged | Cell::Revealed => return RevealOutcome::NoChange,
            Cell::Covered => {}
        }

        if !self.placed {
            self.place_mines(row, col);
            self.placed = true;
        }

        if self.mines[i] {
            self.cells[i] = Cell::Revealed;
            self.state = State::Lost;
            return RevealOutcome::Hit;
        }

        self.flood_reveal(row, col);

        if self.revealed as usize == CELL_COUNT - MINE_COUNT as usize {
            self.state = State::Won;
            self.first_game_complete = true;
            return RevealOutcome::Win;
        }
        RevealOutcome::Progress
    }

    /// Reset to a fresh playing board. Reuses the RNG state (so
    /// subsequent resets don't all produce the same board).
    pub fn reset(&mut self) {
        self.cells = [Cell::Covered; CELL_COUNT];
        self.mines = [false; CELL_COUNT];
        self.placed = false;
        self.state = State::Playing;
        self.flags = 0;
        self.revealed = 0;
        // `rng` and `first_game_complete` deliberately preserved.
    }

    // --- internals ---

    fn idx(row: u8, col: u8) -> usize {
        (row as usize) * (BOARD_SIZE as usize) + (col as usize)
    }

    /// Place MINE_COUNT mines in cells that are not (safe_r, safe_c)
    /// nor any of its 8 neighbours. Rejection sampling terminates in
    /// at most (CELL_COUNT - 9) attempts for the tail mine — bounded
    /// because the safe set has exactly 9 forbidden cells leaving 72
    /// legal positions for 10 mines.
    fn place_mines(&mut self, safe_r: u8, safe_c: u8) {
        let mut safe = [false; CELL_COUNT];
        safe[Self::idx(safe_r, safe_c)] = true;
        for (nr, nc) in neighbours(safe_r, safe_c) {
            safe[Self::idx(nr, nc)] = true;
        }

        let mut placed = 0u8;
        // Bounded loop: CELL_COUNT iterations is a strict upper bound
        // because every iteration either places a mine (10 total) or
        // picks a cell already mined / in the safe set (<= 72 + 9 = 81).
        // The worst case across all placements is ~200 iters; we bound
        // at 4 * CELL_COUNT = 324 as a belt-and-braces guard.
        let mut attempts = 0u32;
        while placed < MINE_COUNT && attempts < 4 * CELL_COUNT as u32 {
            attempts += 1;
            let r = (self.rng.next_u64() % BOARD_SIZE as u64) as u8;
            let c = (self.rng.next_u64() % BOARD_SIZE as u64) as u8;
            let i = Self::idx(r, c);
            if safe[i] || self.mines[i] {
                continue;
            }
            self.mines[i] = true;
            placed += 1;
        }
        // If the bounded loop somehow didn't place all mines (shouldn't
        // happen with 72 slots for 10 mines), fall through — the board
        // has fewer mines than advertised but is still playable. No
        // panic per the formal-verification discipline.
    }

    /// Iterative flood-fill starting at (row, col). Reveals the given
    /// cell and, if its adjacency count is 0, its 8 neighbours, and
    /// their neighbours transitively, until the frontier is exhausted.
    /// Bounded by `CELL_COUNT` since each cell is revealed at most once.
    fn flood_reveal(&mut self, row: u8, col: u8) {
        // Fixed-size stack. Worst case all 81 cells queued at once.
        let mut stack: [(u8, u8); CELL_COUNT] = [(0, 0); CELL_COUNT];
        let mut top: usize = 0;
        stack[top] = (row, col);
        top += 1;

        while top > 0 {
            top -= 1;
            let (r, c) = stack[top];
            let i = Self::idx(r, c);
            if self.cells[i] != Cell::Covered {
                continue;
            }
            self.cells[i] = Cell::Revealed;
            self.revealed += 1;
            if self.adjacent(r, c) == 0 {
                for (nr, nc) in neighbours(r, c) {
                    let ni = Self::idx(nr, nc);
                    if self.cells[ni] == Cell::Covered && !self.mines[ni] && top < CELL_COUNT {
                        stack[top] = (nr, nc);
                        top += 1;
                    }
                }
            }
        }
    }
}

/// xorshift64 — single-register PRNG, no deps. Seed 0 is degenerate
/// and is replaced with a nonzero constant so callers can pass an
/// uninitialised-looking 0 without getting stuck at zero.
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

/// Iterator over the (up to 8) in-bounds neighbours of (row, col).
/// Skips out-of-bounds positions so callers don't have to guard.
fn neighbours(row: u8, col: u8) -> impl Iterator<Item = (u8, u8)> {
    let r = row as i16;
    let c = col as i16;
    const DELTAS: [(i16, i16); 8] = [
        (-1, -1), (-1, 0), (-1, 1),
        (0, -1),           (0, 1),
        (1, -1),  (1, 0),  (1, 1),
    ];
    DELTAS.iter().filter_map(move |(dr, dc)| {
        let nr = r + dr;
        let nc = c + dc;
        if nr < 0 || nr >= BOARD_SIZE as i16 || nc < 0 || nc >= BOARD_SIZE as i16 {
            None
        } else {
            Some((nr as u8, nc as u8))
        }
    })
}
