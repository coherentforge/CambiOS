// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Emacs-style line editor with bounded in-memory history.
//!
//! Consumed by the shell and by any tool that wants a cursor-aware prompt
//! (e.g., nano-style editor's search/replace bottom prompt).
//!
//! Supported bindings:
//!
//! - Arrow Left/Right: move cursor one char.
//! - Arrow Up/Down: recall previous/next history entry.
//! - Home / Ctrl-A: cursor to start of buffer.
//! - End / Ctrl-E: cursor to end of buffer.
//! - Backspace: delete char before cursor.
//! - Delete: delete char under cursor.
//! - Ctrl-K: kill from cursor to end of line.
//! - Ctrl-U: kill from start of line to cursor.
//! - Ctrl-W: kill preceding whitespace-delimited word.
//! - Ctrl-C: abort (returns [`LineResult::Interrupt`]).
//! - Ctrl-D on empty buffer: returns [`LineResult::Eof`].
//! - Enter: commit; returns [`LineResult::Ok`].

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::backend::Backend;
use crate::events::{Event, Key};
use crate::output;
use crate::terminal::Terminal;

/// Result of a single `read_line` call.
#[derive(Debug, Clone)]
pub enum LineResult {
    Ok(Vec<u8>),
    Interrupt,
    Eof,
}

/// Bounded history of committed lines, plus per-call state during editing.
pub struct LineEditor {
    history: VecDeque<Vec<u8>>,
    history_cap: usize,
}

impl LineEditor {
    /// Create a new editor with the given history capacity. A capacity of
    /// 0 disables history recall (Up/Down become no-ops).
    pub fn new(history_cap: usize) -> Self {
        Self {
            history: VecDeque::new(),
            history_cap,
        }
    }

    /// Push a line into the history ring. Consecutive duplicates collapse;
    /// empty lines are ignored. Intended to be called after a successful
    /// `read_line` when the caller decides the line should be remembered.
    pub fn push_history(&mut self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        if let Some(back) = self.history.back() {
            if back.as_slice() == line {
                return;
            }
        }
        self.history.push_back(line.to_vec());
        while self.history.len() > self.history_cap {
            self.history.pop_front();
        }
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Read one line. Emits the prompt, processes events, returns on Enter,
    /// Ctrl-C, or Ctrl-D-on-empty.
    pub fn read_line<B: Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
        prompt: &[u8],
    ) -> LineResult {
        let mut buffer: Vec<u8> = Vec::new();
        // Cursor position inside `buffer` (0..=buffer.len()).
        let mut cursor: usize = 0;
        // `history_pos == Some(i)` means we've recalled history[i] and
        // `saved_draft` holds the pre-recall user input.
        let mut history_pos: Option<usize> = None;
        let mut saved_draft: Vec<u8> = Vec::new();

        terminal.write(prompt);

        loop {
            match terminal.next_event_blocking() {
                Event::Key(Key::Enter) => {
                    terminal.write(b"\r\n");
                    return LineResult::Ok(buffer);
                }
                Event::Key(Key::Ctrl(3)) => {
                    // Ctrl-C: echo ^C, return Interrupt with the partial buffer discarded.
                    terminal.write(b"^C\r\n");
                    return LineResult::Interrupt;
                }
                Event::Key(Key::Ctrl(4)) => {
                    // Ctrl-D on empty buffer = EOF; otherwise ignored.
                    if buffer.is_empty() {
                        terminal.write(b"\r\n");
                        return LineResult::Eof;
                    }
                }
                Event::Key(key) => {
                    apply_edit(
                        &mut buffer,
                        &mut cursor,
                        &mut history_pos,
                        &mut saved_draft,
                        &self.history,
                        key,
                    );
                    redraw(terminal, prompt, &buffer, cursor);
                }
                // Other event variants are not emitted by SerialBackend today.
                _ => {}
            }
        }
    }
}

fn apply_edit(
    buffer: &mut Vec<u8>,
    cursor: &mut usize,
    history_pos: &mut Option<usize>,
    saved_draft: &mut Vec<u8>,
    history: &VecDeque<Vec<u8>>,
    key: Key,
) {
    match key {
        Key::Char(b) => {
            // 0x20..=0xFF inserts. Below 0x20 without a named variant is
            // ignored (we already mapped Ctrl letters separately).
            if b >= 0x20 {
                buffer.insert(*cursor, b);
                *cursor += 1;
            }
        }
        Key::Backspace => {
            if *cursor > 0 {
                *cursor -= 1;
                buffer.remove(*cursor);
            }
        }
        Key::Delete => {
            if *cursor < buffer.len() {
                buffer.remove(*cursor);
            }
        }
        Key::Left => {
            if *cursor > 0 {
                *cursor -= 1;
            }
        }
        Key::Right => {
            if *cursor < buffer.len() {
                *cursor += 1;
            }
        }
        Key::Home | Key::Ctrl(1) => {
            *cursor = 0;
        }
        Key::End | Key::Ctrl(5) => {
            *cursor = buffer.len();
        }
        Key::Ctrl(11) => {
            // Ctrl-K: kill to end of line.
            buffer.truncate(*cursor);
        }
        Key::Ctrl(21) => {
            // Ctrl-U: kill from start to cursor.
            buffer.drain(..*cursor);
            *cursor = 0;
        }
        Key::Ctrl(23) => {
            // Ctrl-W: kill preceding whitespace-delimited word.
            let mut i = *cursor;
            // Skip trailing spaces immediately before cursor.
            while i > 0 && buffer[i - 1] == b' ' {
                i -= 1;
            }
            // Back up over word characters.
            while i > 0 && buffer[i - 1] != b' ' {
                i -= 1;
            }
            buffer.drain(i..*cursor);
            *cursor = i;
        }
        Key::Up => {
            if history.is_empty() {
                return;
            }
            let new_pos = match *history_pos {
                None => {
                    *saved_draft = buffer.clone();
                    history.len() - 1
                }
                Some(0) => 0,
                Some(i) => i - 1,
            };
            *history_pos = Some(new_pos);
            *buffer = history[new_pos].clone();
            *cursor = buffer.len();
        }
        Key::Down => {
            match *history_pos {
                None => {}
                Some(i) if i + 1 < history.len() => {
                    *history_pos = Some(i + 1);
                    *buffer = history[i + 1].clone();
                    *cursor = buffer.len();
                }
                Some(_) => {
                    // Past the end: restore the pre-recall draft.
                    *history_pos = None;
                    *buffer = core::mem::take(saved_draft);
                    *cursor = buffer.len();
                }
            }
        }
        _ => {
            // Tab, F-keys, Alt, Insert, PgUp/PgDn, ShiftTab, unhandled
            // Ctrl variants — ignored by the line editor. Callers that want
            // completion/Tab handling wrap the editor.
        }
    }
}

fn redraw<B: Backend>(
    terminal: &mut Terminal<B>,
    prompt: &[u8],
    buffer: &[u8],
    cursor: usize,
) {
    output::cursor_to_col1(terminal.backend_mut());
    terminal.write(prompt);
    terminal.write(buffer);
    output::clear_to_eol(terminal.backend_mut());
    let back = buffer.len().saturating_sub(cursor);
    // ANSI cursor-left caps at u16; clamp (prompt + buffer > 65k cols is
    // outside the serial target's realistic range).
    let back = core::cmp::min(back, u16::MAX as usize) as u16;
    output::cursor_left(terminal.backend_mut(), back);
}
