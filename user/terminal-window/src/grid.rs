// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Text grid state for the GUI terminal window.
//!
//! Stores `COLS × VISIBLE_ROWS` character cells, a cursor, a per-row
//! dirty bitmap, and a small ANSI output-direction state machine that
//! interprets the escape sequences the shell's output path emits. The
//! bytes the grid consumes come from:
//!
//! - `libterm::Terminal::write(bytes)` — which happens whenever the
//!   `LineEditor` redraws the prompt + buffer + cursor-left sequence,
//!   or whenever a shell command handler calls `sys::print(…)`-style
//!   output through the terminal.
//! - The `echo` path while the user is typing (echo happens inside
//!   libterm's LineEditor via `terminal.write(…)`).
//!
//! The render path (separate module) walks the dirty bitmap and blits
//! only changed rows into the shared surface.
//!
//! ## Supported ANSI on the write path
//!
//! The shell and libterm between them emit exactly:
//! `\r`, `\n`, `\t`, `\x08` (backspace), `\x1b[<n>D`/`C` (cursor left/
//! right), `\x1b[K` (clear-to-EOL), `\x1b[2K` (clear-line),
//! `\x1b[<r>;<c>H` (cursor position), `\x1b[2J\x1b[H` (clear screen +
//! home), `\x1b[?25l`/`h` (cursor visibility — ignored), `\x1b[<n>m`
//! (SGR — v1 strips it). Everything else is consumed silently — we'd
//! rather lose a stray byte than show garbage.
//!
//! ## No scrollback (v1)
//!
//! Scrolling off the top of the visible area drops the row. The
//! scrollback ring is a post-HN follow-up; PgUp/PgDn in the GUI
//! backend's encoder already emits the right sequences, they just
//! won't do anything useful yet.
//!
//! ## Fixed dimensions
//!
//! SCAFFOLDING: 128×96 at 8×8 glyphs fills a 1024×768 window — full
//! scanout on the QEMU virtio-vga default. Picking grid dimensions
//! that exactly match the scanout means the compositor's blit covers
//! every pixel; nothing is left over to expose stale frames underneath.
//! Why: HN-launch demo runs against 1024×768 QEMU; matching the grid
//! to the scanout is the cheapest way to get a clean full-screen
//! terminal without coordinating cyan-fill + window-position with the
//! compositor (Option B work).
//! Replace when: variable window sizing lands (multi-window, runtime
//! resize), or the scanout dimensions are queryable through libgui at
//! CreateWindow time so the client can size to fit.

/// SCAFFOLDING: columns in a terminal-window grid. 128 @ 8×8 = 1024 px,
/// matching the QEMU virtio-vga default scanout width. Wider than the
/// 80-column UNIX convention; full-scanout terminal looks intentional
/// even when the user hasn't resized.
/// Replace when: the scanout width is queryable at CreateWindow time
/// or window decorations / multi-window layouts arrive.
pub const COLS: usize = 128;

/// SCAFFOLDING: visible rows. 96 @ 8×8 = 768 px, matching the QEMU
/// virtio-vga default scanout height. Sized for full-scanout coverage
/// rather than a small terminal — see `COLS` for the same rationale.
/// Replace when the scanout height is queryable or window layouts let
/// the terminal claim a deliberately smaller region.
pub const VISIBLE_ROWS: usize = 96;

/// Tab stop interval.
pub const TAB_WIDTH: usize = 8;

/// One character cell. Byte for the glyph; colors/attrs reserved for
/// the next revision (store as a struct then — keep the `set_cell`
/// API stable now).
pub type Cell = u8;

/// Blank cell byte.
pub const BLANK: Cell = b' ';

/// Internal state of the write-direction ANSI parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutState {
    Ground,
    Escape,
    Csi,
}

/// Per-grid ANSI parser. Independent of libterm's parser (that one
/// decodes INPUT bytes into keys; this one decodes OUTPUT bytes into
/// grid mutations).
#[derive(Clone, Copy, Debug)]
struct OutParser {
    state: OutState,
    params: [u16; 4],
    nparams: u8,
    /// Track `?` private-marker CSIs so `\x1b[?25l` et al. don't
    /// fall through into the numeric-param path.
    private: bool,
}

impl OutParser {
    const fn new() -> Self {
        Self {
            state: OutState::Ground,
            params: [0; 4],
            nparams: 0,
            private: false,
        }
    }

    fn reset(&mut self) {
        self.state = OutState::Ground;
        self.params = [0; 4];
        self.nparams = 0;
        self.private = false;
    }
}

pub struct Grid {
    cells: [[Cell; COLS]; VISIBLE_ROWS],
    dirty: [bool; VISIBLE_ROWS],
    cursor_col: u16,
    cursor_row: u16,
    parser: OutParser,
}

impl Grid {
    pub const fn new() -> Self {
        Self {
            cells: [[BLANK; COLS]; VISIBLE_ROWS],
            dirty: [true; VISIBLE_ROWS], // first paint dirties everything
            cursor_col: 0,
            cursor_row: 0,
            parser: OutParser::new(),
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (COLS as u16, VISIBLE_ROWS as u16)
    }

    pub fn cursor(&self) -> (u16, u16) {
        (self.cursor_col, self.cursor_row)
    }

    pub fn cell(&self, col: usize, row: usize) -> Cell {
        self.cells[row][col]
    }

    pub fn is_dirty(&self, row: usize) -> bool {
        self.dirty[row]
    }

    pub fn clear_dirty(&mut self) {
        for d in self.dirty.iter_mut() {
            *d = false;
        }
    }

    pub fn mark_all_dirty(&mut self) {
        for d in self.dirty.iter_mut() {
            *d = true;
        }
    }

    /// Mark a single row dirty without modifying its content. Useful
    /// to the renderer when the cursor moves and the prior caret cell
    /// needs a redraw to wipe the stale block.
    pub fn mark_row_dirty(&mut self, row: usize) {
        if row < VISIBLE_ROWS {
            self.dirty[row] = true;
        }
    }

    /// Feed one output byte through the ANSI state machine. Updates
    /// the grid and dirty bitmap as side effects.
    pub fn write_byte(&mut self, b: u8) {
        match self.parser.state {
            OutState::Ground => self.step_ground(b),
            OutState::Escape => self.step_escape(b),
            OutState::Csi => self.step_csi(b),
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }

    // ------------------------------------------------------------------
    // Ground state — printable bytes + single-byte controls
    // ------------------------------------------------------------------

    fn step_ground(&mut self, b: u8) {
        match b {
            b'\r' => self.cursor_col = 0,
            b'\n' => {
                // Cooked-mode newline: LF implies CR. Most output paths
                // emit `\r\n` and the leading `\r` is then a no-op; a
                // bare `\n` from a non-cooked source still does the
                // expected thing.
                self.cursor_col = 0;
                self.line_feed();
            }
            b'\t' => {
                let next = ((self.cursor_col as usize / TAB_WIDTH) + 1) * TAB_WIDTH;
                self.cursor_col = (next.min(COLS - 1)) as u16;
            }
            0x08 | 0x7F => {
                // Backspace: move left one (non-destructive). The
                // line editor will overwrite the previous cell via its
                // redraw path.
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                }
            }
            0x1B => self.parser.state = OutState::Escape,
            // C0 controls other than the above: drop silently.
            0x00..=0x1F => {}
            // Printable ASCII and high bytes: stamp into the cell.
            _ => {
                self.put_cell(b);
                self.advance_cursor();
            }
        }
    }

    // ------------------------------------------------------------------
    // Escape state — expects `[` to enter CSI, anything else aborts.
    // ------------------------------------------------------------------

    fn step_escape(&mut self, b: u8) {
        match b {
            b'[' => {
                self.parser.state = OutState::Csi;
                self.parser.params = [0; 4];
                self.parser.nparams = 0;
                self.parser.private = false;
            }
            // Other ESC-prefix sequences (SS3, single-char) are not
            // emitted by our output path. Drop and reset.
            _ => self.parser.reset(),
        }
    }

    // ------------------------------------------------------------------
    // CSI state — parameters + final byte dispatch
    // ------------------------------------------------------------------

    fn step_csi(&mut self, b: u8) {
        match b {
            b'?' if self.parser.nparams == 0 && self.parser.params[0] == 0 => {
                self.parser.private = true;
            }
            b'0'..=b'9' => {
                let slot = if self.parser.nparams == 0 {
                    self.parser.nparams = 1;
                    0usize
                } else {
                    (self.parser.nparams as usize) - 1
                };
                if slot < 4 {
                    let d = (b - b'0') as u16;
                    self.parser.params[slot] = self
                        .parser
                        .params[slot]
                        .saturating_mul(10)
                        .saturating_add(d);
                }
            }
            b';' => {
                if self.parser.nparams == 0 {
                    self.parser.nparams = 1;
                }
                if (self.parser.nparams as usize) < 4 {
                    self.parser.nparams += 1;
                }
            }
            0x40..=0x7E => {
                self.dispatch_csi(b);
                self.parser.reset();
            }
            _ => self.parser.reset(),
        }
    }

    fn dispatch_csi(&mut self, final_byte: u8) {
        let p0 = if self.parser.nparams == 0 {
            0
        } else {
            self.parser.params[0]
        };
        let p1 = if (self.parser.nparams as usize) >= 2 {
            self.parser.params[1]
        } else {
            0
        };

        if self.parser.private {
            // `\x1b[?25l` / `\x1b[?25h` and friends — cursor visibility.
            // We always render the cursor in v1; these are no-ops.
            return;
        }

        match final_byte {
            // Cursor left / right by `n` (default 1 when omitted).
            b'D' => {
                let n = if p0 == 0 { 1 } else { p0 };
                self.cursor_col = self.cursor_col.saturating_sub(n);
            }
            b'C' => {
                let n = if p0 == 0 { 1 } else { p0 };
                self.cursor_col = (self.cursor_col + n).min((COLS - 1) as u16);
            }
            // Absolute cursor position — 1-indexed on the wire.
            b'H' | b'f' => {
                let row1 = if p0 == 0 { 1 } else { p0 };
                let col1 = if p1 == 0 { 1 } else { p1 };
                self.cursor_row = (row1 - 1).min((VISIBLE_ROWS - 1) as u16);
                self.cursor_col = (col1 - 1).min((COLS - 1) as u16);
            }
            // Erase in line: 0 = cursor→EOL, 1 = BOL→cursor, 2 = full line.
            b'K' => self.erase_in_line(p0),
            // Erase in display: 0 = cursor→end, 1 = start→cursor, 2 = full.
            b'J' => self.erase_in_display(p0),
            // SGR (colors / attributes) — v1 strips without applying.
            b'm' => {}
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Grid mutations
    // ------------------------------------------------------------------

    fn put_cell(&mut self, b: u8) {
        if self.cursor_col as usize >= COLS {
            // Soft wrap — advance to next line before writing.
            self.cursor_col = 0;
            self.line_feed();
        }
        let (col, row) = (self.cursor_col as usize, self.cursor_row as usize);
        if row < VISIBLE_ROWS {
            self.cells[row][col] = b;
            self.dirty[row] = true;
        }
    }

    fn advance_cursor(&mut self) {
        self.cursor_col += 1;
        // Don't line-feed on the exact rightmost column — wait until the next
        // non-control byte actually needs to write. Matches most
        // terminals' "last-column quirk" closely enough for a shell.
        if (self.cursor_col as usize) > COLS {
            self.cursor_col = COLS as u16;
        }
    }

    fn line_feed(&mut self) {
        self.cursor_row += 1;
        if (self.cursor_row as usize) >= VISIBLE_ROWS {
            self.scroll_up();
            self.cursor_row = (VISIBLE_ROWS - 1) as u16;
        }
    }

    fn scroll_up(&mut self) {
        for r in 1..VISIBLE_ROWS {
            self.cells[r - 1] = self.cells[r];
            self.dirty[r - 1] = true;
        }
        for c in 0..COLS {
            self.cells[VISIBLE_ROWS - 1][c] = BLANK;
        }
        self.dirty[VISIBLE_ROWS - 1] = true;
    }

    fn erase_in_line(&mut self, mode: u16) {
        let row = self.cursor_row as usize;
        if row >= VISIBLE_ROWS {
            return;
        }
        let c = self.cursor_col as usize;
        let range = match mode {
            1 => 0..=c.min(COLS - 1),
            2 => 0..=(COLS - 1),
            _ => c..=(COLS - 1), // 0 or unknown
        };
        for col in range {
            self.cells[row][col] = BLANK;
        }
        self.dirty[row] = true;
    }

    fn erase_in_display(&mut self, mode: u16) {
        match mode {
            1 => {
                // Start of screen through cursor (inclusive).
                for r in 0..(self.cursor_row as usize) {
                    self.cells[r] = [BLANK; COLS];
                    self.dirty[r] = true;
                }
                self.erase_in_line(1);
            }
            2 => {
                for r in 0..VISIBLE_ROWS {
                    self.cells[r] = [BLANK; COLS];
                    self.dirty[r] = true;
                }
            }
            _ => {
                // Cursor to end of screen.
                self.erase_in_line(0);
                for r in (self.cursor_row as usize + 1)..VISIBLE_ROWS {
                    self.cells[r] = [BLANK; COLS];
                    self.dirty[r] = true;
                }
            }
        }
    }
}

impl Default for Grid {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn row_as_str(g: &Grid, row: usize) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        for c in 0..COLS {
            s.push(g.cell(c, row) as char);
        }
        s.trim_end().to_string()
    }

    #[test]
    fn blank_grid_has_spaces_everywhere() {
        let g = Grid::new();
        for r in 0..VISIBLE_ROWS {
            for c in 0..COLS {
                assert_eq!(g.cell(c, r), b' ');
            }
        }
    }

    #[test]
    fn writing_printable_advances_cursor() {
        let mut g = Grid::new();
        g.write_bytes(b"hello");
        assert_eq!(g.cursor(), (5, 0));
        assert_eq!(&row_as_str(&g, 0), "hello");
    }

    #[test]
    fn cr_resets_col() {
        let mut g = Grid::new();
        g.write_bytes(b"hello\rworld");
        assert_eq!(&row_as_str(&g, 0), "world");
        assert_eq!(g.cursor(), (5, 0));
    }

    #[test]
    fn lf_advances_row() {
        let mut g = Grid::new();
        g.write_bytes(b"hi\nthere");
        assert_eq!(&row_as_str(&g, 0), "hi");
        assert_eq!(&row_as_str(&g, 1), "there");
        assert_eq!(g.cursor(), (5, 1));
    }

    #[test]
    fn backspace_moves_left_but_does_not_erase() {
        let mut g = Grid::new();
        g.write_bytes(b"ab\x08c");
        // 'a' at 0, 'b' at 1, BS moves to 1, 'c' overwrites → "ac"
        assert_eq!(&row_as_str(&g, 0), "ac");
    }

    #[test]
    fn tab_advances_to_next_stop() {
        let mut g = Grid::new();
        g.write_bytes(b"a\tb");
        // 'a' at 0; tab moves to col 8; 'b' at col 8.
        assert_eq!(g.cell(0, 0), b'a');
        assert_eq!(g.cell(8, 0), b'b');
    }

    #[test]
    fn scroll_up_on_lf_past_last_row() {
        let mut g = Grid::new();
        for r in 0..VISIBLE_ROWS {
            g.write_bytes(b"row\n");
            // reset col to 0 for next row's baseline check
            let _ = r;
        }
        // Final \n scrolled; the top row is now the formerly-second row.
        // All non-trivial for this test: just check that cursor is at the
        // bottom row and no panic occurred.
        assert_eq!(g.cursor().1 as usize, VISIBLE_ROWS - 1);
    }

    #[test]
    fn csi_k_clears_to_eol() {
        let mut g = Grid::new();
        g.write_bytes(b"hello world");
        // Move cursor back to col 5 (between 'hello' and ' world')
        g.write_bytes(b"\x1b[6D");
        g.write_bytes(b"\x1b[K");
        assert_eq!(&row_as_str(&g, 0), "hello");
    }

    #[test]
    fn csi_2k_clears_full_line() {
        let mut g = Grid::new();
        g.write_bytes(b"keep me");
        g.write_bytes(b"\x1b[2K");
        assert_eq!(&row_as_str(&g, 0), "");
    }

    #[test]
    fn csi_cursor_left_and_right() {
        let mut g = Grid::new();
        g.write_bytes(b"abcdef");
        g.write_bytes(b"\x1b[3D"); // cursor left 3
        assert_eq!(g.cursor(), (3, 0));
        g.write_bytes(b"\x1b[2C"); // cursor right 2
        assert_eq!(g.cursor(), (5, 0));
    }

    #[test]
    fn csi_cursor_left_default_is_one() {
        let mut g = Grid::new();
        g.write_bytes(b"abc");
        g.write_bytes(b"\x1b[D");
        assert_eq!(g.cursor(), (2, 0));
    }

    #[test]
    fn csi_cursor_absolute() {
        let mut g = Grid::new();
        g.write_bytes(b"\x1b[10;20H");
        assert_eq!(g.cursor(), (19, 9)); // 1-indexed on wire
    }

    #[test]
    fn clear_screen_and_home() {
        let mut g = Grid::new();
        g.write_bytes(b"keep\nkeep\nkeep");
        g.write_bytes(b"\x1b[2J\x1b[H");
        for r in 0..VISIBLE_ROWS {
            assert_eq!(&row_as_str(&g, r), "");
        }
        assert_eq!(g.cursor(), (0, 0));
    }

    #[test]
    fn sgr_is_stripped_silently() {
        let mut g = Grid::new();
        g.write_bytes(b"\x1b[1;31mred\x1b[0m.");
        assert_eq!(&row_as_str(&g, 0), "red.");
    }

    #[test]
    fn hide_and_show_cursor_are_noops() {
        let mut g = Grid::new();
        g.write_bytes(b"\x1b[?25l");
        g.write_bytes(b"\x1b[?25h");
        g.write_bytes(b"x");
        assert_eq!(&row_as_str(&g, 0), "x");
    }

    #[test]
    fn malformed_csi_recovers() {
        let mut g = Grid::new();
        // ESC [ then garbage then a real letter
        g.write_bytes(b"pre\x1b[\x01post");
        // 'pre' written, malformed CSI dropped, 'post' written continuing
        // after 'pre'.
        assert_eq!(&row_as_str(&g, 0), "prepost");
    }

    #[test]
    fn line_editor_redraw_pattern() {
        // Simulate the sequence the libterm LineEditor emits on each
        // keystroke. If this test drifts, the editor will visibly
        // smear on screen.
        let mut g = Grid::new();

        // Initial render:   \r + "arcos> " + "hel" + \x1b[K
        g.write_bytes(b"\rarcos> hel\x1b[K");
        assert_eq!(&row_as_str(&g, 0), "arcos> hel");
        assert_eq!(g.cursor(), (10, 0));

        // User types 'l': editor re-emits full line and cursor stays at end.
        g.write_bytes(b"\rarcos> hell\x1b[K");
        assert_eq!(&row_as_str(&g, 0), "arcos> hell");

        // User presses Left arrow: editor re-emits line and seeks left 1.
        g.write_bytes(b"\rarcos> hell\x1b[K\x1b[1D");
        assert_eq!(g.cursor(), (10, 0));

        // User hits Backspace: buffer now "hel", editor re-emits + Ctrl-seek.
        // Wait — nope, Backspace removes one char. Buffer = "hel", cursor
        // at col 3 in buffer = col 10 on screen... but we are already at
        // col 10. Editor redraws "\rarcos> hel\x1b[K\x1b[0D" — the \x1b[0D
        // is emitted only if cursor_from_end > 0. For this case cursor
        // is at end, so just "\rarcos> hel\x1b[K".
        g.write_bytes(b"\rarcos> hel\x1b[K");
        assert_eq!(&row_as_str(&g, 0), "arcos> hel");
    }

    #[test]
    fn dirty_rows_tracked() {
        let mut g = Grid::new();
        g.clear_dirty();
        g.write_bytes(b"hello");
        assert!(g.is_dirty(0));
        for r in 1..VISIBLE_ROWS {
            assert!(!g.is_dirty(r), "row {r} should be clean");
        }
    }

    #[test]
    fn clear_dirty_preserves_cells() {
        let mut g = Grid::new();
        g.write_bytes(b"persistent");
        g.clear_dirty();
        for r in 0..VISIBLE_ROWS {
            assert!(!g.is_dirty(r));
        }
        assert_eq!(&row_as_str(&g, 0), "persistent");
    }

    extern crate alloc;
}
