// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! POSIX-strict argument flag parser for CambiOS user-space tools.
//!
//! # Grammar
//!
//! - `-x`: short flag (one byte after `-`).
//! - `-abc`: bundled short flags = `-a -b -c`. A bundled run may end with a
//!   value-taking flag whose inline remainder becomes the value
//!   (`-o file.txt` can be written `-ofile.txt`; `-vofile.txt` is `-v`
//!   plus `-o file.txt`).
//! - `--flag`: long flag.
//! - `--flag=value`: long flag with an inline value.
//! - `--flag value`: long flag whose value is the next argv element (only
//!   when the flag declares `takes_val = true`).
//! - `-flag value`: short flag whose value is the next argv element (only
//!   when no inline value is present).
//! - `--`: terminator. Everything after is positional, even if it starts
//!   with `-`.
//! - `-`: a single dash is always positional (convention for "stdin").
//!
//! # Non-goals
//!
//! - Quoting and tokenization. Consumers pass a pre-tokenized
//!   `argv: &[&[u8]]`; the shell tokenizer is responsible for handling
//!   quotes, backslashes, and whitespace before `parse` is called.
//! - Allocation. The parser is `no_std` and makes no heap allocations.
//!   All output fits in caller-sized stack arrays (const generics `N`
//!   for flag count and `P` for positional capacity).
//! - Dynamic flag sets. The flag spec is `&'static [FlagSpec; N]`, so
//!   the flag grammar is baked in at compile time.

#![no_std]

/// Description of one flag.
///
/// Construct a `&'static [FlagSpec; N]` per command and hand it to [`parse`].
/// Rationale for a flat const table: the verifier and the reader both see
/// the full grammar at the call site; no builder state, no runtime plugin.
#[derive(Debug, Clone, Copy)]
pub struct FlagSpec {
    /// ASCII byte for the short form (e.g., `b'v'` for `-v`). Use `0` to
    /// disable the short form.
    pub short: u8,
    /// Long form without the leading `--` (e.g., `"verbose"`). Use `""` to
    /// disable the long form.
    pub long: &'static str,
    /// True if the flag consumes a value (either `--flag=V`, `--flag V`,
    /// `-fV`, or `-f V`). False for boolean switches.
    pub takes_val: bool,
    /// Free-form help text. Not interpreted by the parser; surfaced by
    /// callers that render their own `--help` or `man` pages.
    pub help: &'static str,
}

impl FlagSpec {
    /// Convenience: boolean short flag only.
    pub const fn short_bool(short: u8, help: &'static str) -> Self {
        Self { short, long: "", takes_val: false, help }
    }

    /// Convenience: boolean short+long flag.
    pub const fn bool_flag(short: u8, long: &'static str, help: &'static str) -> Self {
        Self { short, long, takes_val: false, help }
    }

    /// Convenience: value-taking short+long flag.
    pub const fn value_flag(short: u8, long: &'static str, help: &'static str) -> Self {
        Self { short, long, takes_val: true, help }
    }
}

/// Parse error. References argv bytes via `'a` — caller can format with them
/// but must not outlive the argv buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError<'a> {
    /// `-x` was seen but `x` is not declared.
    UnknownShort(u8),
    /// `--foo` was seen but `foo` is not declared.
    UnknownLong(&'a [u8]),
    /// `-f` or `--flag` was seen with `takes_val = true` but no value is
    /// available (end of argv, and no inline `=` / remainder).
    MissingValueShort(u8),
    MissingValueLong(&'a [u8]),
    /// `--flag=value` was seen but the flag does not take a value.
    UnexpectedValue(&'a [u8]),
    /// More positional arguments than `P` positional capacity.
    TooManyPositional,
}

/// Result of a successful parse.
///
/// - `set[i]` is `true` if flag `i` (index into the caller's FlagSpec
///   array) appeared at least once.
/// - `vals[i]` is the final value for value-taking flag `i`, or `None`.
/// - `positional` holds the non-flag arguments in order of appearance, up
///   to `P` slots. Only the first `npos` are meaningful.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseResult<'a, const N: usize, const P: usize> {
    pub set: [bool; N],
    pub vals: [Option<&'a [u8]>; N],
    pub positional: [Option<&'a [u8]>; P],
    pub npos: usize,
}

impl<'a, const N: usize, const P: usize> ParseResult<'a, N, P> {
    /// Return the `i`th positional argument, or `None` if `i >= npos`.
    #[inline]
    pub fn pos(&self, i: usize) -> Option<&'a [u8]> {
        if i < self.npos { self.positional[i] } else { None }
    }

    /// Iterate over positional args in order.
    pub fn positionals(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        (0..self.npos).filter_map(|i| self.positional[i])
    }

    /// Convenience: was a flag present?
    #[inline]
    pub fn is_set(&self, idx: usize) -> bool {
        idx < N && self.set[idx]
    }

    /// Convenience: value of a flag.
    #[inline]
    pub fn value(&self, idx: usize) -> Option<&'a [u8]> {
        if idx < N { self.vals[idx] } else { None }
    }
}

fn find_short(spec: &[FlagSpec], c: u8) -> Option<usize> {
    if c == 0 {
        return None;
    }
    let mut i = 0;
    while i < spec.len() {
        if spec[i].short == c {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_long(spec: &[FlagSpec], name: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < spec.len() {
        if !spec[i].long.is_empty() && spec[i].long.as_bytes() == name {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse `argv` against `spec`.
///
/// `argv` should NOT include the program name — callers strip argv[0] if
/// their convention includes it. Each entry is an un-quoted byte slice.
pub fn parse<'a, const N: usize, const P: usize>(
    spec: &'static [FlagSpec; N],
    argv: &'a [&'a [u8]],
) -> Result<ParseResult<'a, N, P>, ParseError<'a>> {
    let mut result: ParseResult<'a, N, P> = ParseResult {
        set: [false; N],
        vals: [None; N],
        positional: [None; P],
        npos: 0,
    };

    let mut i = 0;
    let mut past_ddash = false;
    while i < argv.len() {
        let arg = argv[i];

        if past_ddash {
            push_positional(&mut result, arg)?;
            i += 1;
            continue;
        }

        // Empty arg, lone `-`, or non-dash prefix → positional.
        if arg.is_empty() || arg[0] != b'-' || arg == b"-" {
            push_positional(&mut result, arg)?;
            i += 1;
            continue;
        }

        // `--` alone: terminator.
        if arg == b"--" {
            past_ddash = true;
            i += 1;
            continue;
        }

        // `--something`: long flag.
        if arg.len() >= 2 && &arg[..2] == b"--" {
            let rest = &arg[2..];
            let (name, inline_val) = split_eq(rest);
            let idx = find_long(spec, name).ok_or(ParseError::UnknownLong(name))?;
            if spec[idx].takes_val {
                let val = if let Some(v) = inline_val {
                    v
                } else if i + 1 < argv.len() {
                    i += 1;
                    argv[i]
                } else {
                    return Err(ParseError::MissingValueLong(name));
                };
                result.set[idx] = true;
                result.vals[idx] = Some(val);
            } else {
                if inline_val.is_some() {
                    return Err(ParseError::UnexpectedValue(name));
                }
                result.set[idx] = true;
            }
            i += 1;
            continue;
        }

        // `-xyz`: one or more short flags, possibly ending with a value.
        let rest = &arg[1..];
        let mut j = 0;
        let consumed_next = parse_short_run(spec, rest, argv, i, &mut j, &mut result)?;
        i += 1 + consumed_next;
    }

    Ok(result)
}

fn push_positional<'a, const N: usize, const P: usize>(
    result: &mut ParseResult<'a, N, P>,
    arg: &'a [u8],
) -> Result<(), ParseError<'a>> {
    if result.npos >= P {
        return Err(ParseError::TooManyPositional);
    }
    result.positional[result.npos] = Some(arg);
    result.npos += 1;
    Ok(())
}

fn split_eq(rest: &[u8]) -> (&[u8], Option<&[u8]>) {
    let mut k = 0;
    while k < rest.len() {
        if rest[k] == b'=' {
            return (&rest[..k], Some(&rest[k + 1..]));
        }
        k += 1;
    }
    (rest, None)
}

/// Parse a bundled short run such as `-abc` or `-ofile`.
///
/// `rest` is the bytes after the leading `-`. `j` is advanced as letters
/// are consumed. If a value-taking flag consumes argv[i + 1], the function
/// returns 1 to tell the caller to skip that arg too.
fn parse_short_run<'a, const N: usize, const P: usize>(
    spec: &'static [FlagSpec; N],
    rest: &'a [u8],
    argv: &'a [&'a [u8]],
    i: usize,
    j: &mut usize,
    result: &mut ParseResult<'a, N, P>,
) -> Result<usize, ParseError<'a>> {
    let mut consumed_next = 0usize;
    while *j < rest.len() {
        let c = rest[*j];
        let idx = find_short(spec, c).ok_or(ParseError::UnknownShort(c))?;
        if spec[idx].takes_val {
            // Remainder of this arg, if any, is the value. Otherwise
            // consume the next argv element.
            if *j + 1 < rest.len() {
                let val = &rest[*j + 1..];
                result.set[idx] = true;
                result.vals[idx] = Some(val);
                *j = rest.len();
            } else if i + 1 < argv.len() {
                let val = argv[i + 1];
                result.set[idx] = true;
                result.vals[idx] = Some(val);
                consumed_next = 1;
                *j += 1;
            } else {
                return Err(ParseError::MissingValueShort(c));
            }
            return Ok(consumed_next);
        } else {
            result.set[idx] = true;
            *j += 1;
        }
    }
    Ok(consumed_next)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAGS: &[FlagSpec; 5] = &[
        FlagSpec::bool_flag(b'a', "all", "include dotfiles"),
        FlagSpec::bool_flag(b'l', "long", "long listing"),
        FlagSpec::bool_flag(b'v', "verbose", "verbose"),
        FlagSpec::value_flag(b'o', "output", "output file"),
        FlagSpec::value_flag(b'n', "name", "name filter"),
    ];

    const A: usize = 0;
    const L: usize = 1;
    const V: usize = 2;
    const O: usize = 3;

    /// Build an &[&[u8]] from a slice of &str.
    fn argv<'a>(s: &'a [&'a str]) -> [&'a [u8]; 16] {
        let mut out: [&[u8]; 16] = [b""; 16];
        for (i, v) in s.iter().enumerate() {
            out[i] = v.as_bytes();
        }
        out
    }

    fn parse_strs<'a>(input: &'a [&'a str]) -> Result<ParseResult<'a, 5, 8>, ParseError<'a>> {
        let full = argv(input);
        // `parse` must see only the populated prefix.
        let slice: &[&[u8]] = unsafe {
            core::slice::from_raw_parts(full.as_ptr(), input.len())
        };
        // Transmute the array lifetime — safe because `slice` borrows from
        // `full`, and `full` is dropped after this function returns.
        // (We deliberately avoid std::vec here.)
        parse::<5, 8>(FLAGS, slice)
    }

    #[test]
    fn no_flags_all_positional() {
        let r = parse_strs(&["foo", "bar", "baz"]).unwrap();
        assert_eq!(r.npos, 3);
        assert_eq!(r.pos(0), Some(b"foo".as_ref()));
        assert_eq!(r.pos(1), Some(b"bar".as_ref()));
        assert_eq!(r.pos(2), Some(b"baz".as_ref()));
        for idx in 0..5 {
            assert!(!r.is_set(idx), "flag {idx} should be unset");
        }
    }

    #[test]
    fn short_bool_flag() {
        let r = parse_strs(&["-a", "file"]).unwrap();
        assert!(r.is_set(A));
        assert_eq!(r.npos, 1);
        assert_eq!(r.pos(0), Some(b"file".as_ref()));
    }

    #[test]
    fn long_bool_flag() {
        let r = parse_strs(&["--verbose", "file"]).unwrap();
        assert!(r.is_set(V));
        assert_eq!(r.pos(0), Some(b"file".as_ref()));
    }

    #[test]
    fn short_bundle_expands() {
        let r = parse_strs(&["-alv"]).unwrap();
        assert!(r.is_set(A));
        assert!(r.is_set(L));
        assert!(r.is_set(V));
        assert_eq!(r.npos, 0);
    }

    #[test]
    fn short_value_inline() {
        let r = parse_strs(&["-ofile.txt"]).unwrap();
        assert!(r.is_set(O));
        assert_eq!(r.value(O), Some(b"file.txt".as_ref()));
    }

    #[test]
    fn short_value_separate() {
        let r = parse_strs(&["-o", "file.txt", "positional"]).unwrap();
        assert!(r.is_set(O));
        assert_eq!(r.value(O), Some(b"file.txt".as_ref()));
        assert_eq!(r.pos(0), Some(b"positional".as_ref()));
    }

    #[test]
    fn bundle_ending_in_value_flag() {
        // -vofile.txt = -v -o file.txt
        let r = parse_strs(&["-vofile.txt"]).unwrap();
        assert!(r.is_set(V));
        assert!(r.is_set(O));
        assert_eq!(r.value(O), Some(b"file.txt".as_ref()));
    }

    #[test]
    fn long_equals_value() {
        let r = parse_strs(&["--output=a.out"]).unwrap();
        assert!(r.is_set(O));
        assert_eq!(r.value(O), Some(b"a.out".as_ref()));
    }

    #[test]
    fn long_separate_value() {
        let r = parse_strs(&["--output", "a.out"]).unwrap();
        assert!(r.is_set(O));
        assert_eq!(r.value(O), Some(b"a.out".as_ref()));
    }

    #[test]
    fn ddash_terminator_stops_flag_parsing() {
        let r = parse_strs(&["-a", "--", "-l", "--flag"]).unwrap();
        assert!(r.is_set(A));
        assert!(!r.is_set(L));
        assert_eq!(r.npos, 2);
        assert_eq!(r.pos(0), Some(b"-l".as_ref()));
        assert_eq!(r.pos(1), Some(b"--flag".as_ref()));
    }

    #[test]
    fn lone_dash_is_positional() {
        let r = parse_strs(&["-", "-a"]).unwrap();
        assert!(r.is_set(A));
        assert_eq!(r.npos, 1);
        assert_eq!(r.pos(0), Some(b"-".as_ref()));
    }

    #[test]
    fn unknown_short() {
        let r = parse_strs(&["-q"]);
        assert_eq!(r, Err(ParseError::UnknownShort(b'q')));
    }

    #[test]
    fn unknown_long() {
        let r = parse_strs(&["--nope"]);
        assert_eq!(r, Err(ParseError::UnknownLong(b"nope".as_ref())));
    }

    #[test]
    fn missing_value_short() {
        let r = parse_strs(&["-o"]);
        assert_eq!(r, Err(ParseError::MissingValueShort(b'o')));
    }

    #[test]
    fn missing_value_long() {
        let r = parse_strs(&["--output"]);
        assert_eq!(r, Err(ParseError::MissingValueLong(b"output".as_ref())));
    }

    #[test]
    fn unexpected_value_on_bool_long() {
        let r = parse_strs(&["--verbose=yes"]);
        assert_eq!(r, Err(ParseError::UnexpectedValue(b"verbose".as_ref())));
    }

    #[test]
    fn too_many_positional() {
        let input = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let full = argv(&input);
        let slice: &[&[u8]] = unsafe { core::slice::from_raw_parts(full.as_ptr(), input.len()) };
        let r = parse::<5, 8>(FLAGS, slice);
        assert_eq!(r.err(), Some(ParseError::TooManyPositional));
    }

    #[test]
    fn flag_repeat_keeps_last_value() {
        let r = parse_strs(&["-o", "first", "-o", "second"]).unwrap();
        assert!(r.is_set(O));
        assert_eq!(r.value(O), Some(b"second".as_ref()));
    }

    #[test]
    fn mixed_order() {
        let r = parse_strs(&["file1", "-a", "file2", "--output=x", "file3"]).unwrap();
        assert!(r.is_set(A));
        assert_eq!(r.value(O), Some(b"x".as_ref()));
        assert_eq!(r.npos, 3);
        assert_eq!(r.pos(0), Some(b"file1".as_ref()));
        assert_eq!(r.pos(1), Some(b"file2".as_ref()));
        assert_eq!(r.pos(2), Some(b"file3".as_ref()));
    }

    #[test]
    fn positionals_iterator() {
        let r = parse_strs(&["a", "-v", "b"]).unwrap();
        let pos: [&[u8]; 2] = {
            let mut it = r.positionals();
            [it.next().unwrap(), it.next().unwrap()]
        };
        assert_eq!(pos[0], b"a".as_ref());
        assert_eq!(pos[1], b"b".as_ref());
    }

    #[test]
    fn empty_argv_is_fine() {
        let empty: [&[u8]; 0] = [];
        let r = parse::<5, 8>(FLAGS, &empty).unwrap();
        assert_eq!(r.npos, 0);
        for idx in 0..5 {
            assert!(!r.is_set(idx));
        }
    }
}
