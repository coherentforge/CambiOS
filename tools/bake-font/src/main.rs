// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! `bake-font` — rasterize a TrueType font into a fixed-cell antialiased
//! bitmap table that libgui can blit at runtime without dragging in a
//! full TTF parser / rasterizer.
//!
//! Usage:
//!
//! ```text
//! bake-font <ttf> <out.rs> --px <H> --cell <W>x<H> --const-prefix <NAME>
//! ```
//!
//! Each glyph in the printable ASCII range (0x20..=0x7F, 96 glyphs) is
//! rasterized at `--px` pixel height, then placed inside a `cell_w ×
//! cell_h` slot. Horizontal positioning is the font's reported `xmin`
//! offset from the left edge; vertical positioning aligns the font's
//! ascent to a baseline derived from the cell height + descent budget,
//! so descenders (g/j/p/q/y) sit below the baseline like a real
//! terminal cell. Output is a Rust source file with a single
//! `pub static <PREFIX>_DATA: &[u8] = &[...]` table plus the
//! corresponding cell / glyph metrics constants.
//!
//! No runtime allocation, no embedded TTF in the kernel image — every
//! pixel of the final font is decided here at build time.

use fontdue::{Font, FontSettings};
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process;

const FIRST_CHAR: u8 = 0x20;
const NUM_CHARS: usize = 0x80 - FIRST_CHAR as usize; // 96

struct Args {
    ttf_path: String,
    out_path: String,
    px_height: f32,
    cell_w: usize,
    cell_h: usize,
    prefix: String,
}

fn die(msg: &str) -> ! {
    eprintln!("bake-font: {msg}");
    eprintln!("usage: bake-font <ttf> <out.rs> --px <H> --cell <W>x<H> --const-prefix <NAME>");
    process::exit(2);
}

fn parse_args() -> Args {
    let mut argv: Vec<String> = env::args().collect();
    if argv.len() < 8 {
        die("not enough arguments");
    }
    let ttf_path = argv.remove(1);
    let out_path = argv.remove(1);
    let mut px_height: Option<f32> = None;
    let mut cell: Option<(usize, usize)> = None;
    let mut prefix: Option<String> = None;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--px" => {
                let v = argv.get(i + 1).unwrap_or_else(|| die("--px needs a value"));
                px_height = Some(v.parse().unwrap_or_else(|_| die("--px not numeric")));
                i += 2;
            }
            "--cell" => {
                let v = argv.get(i + 1).unwrap_or_else(|| die("--cell needs WxH"));
                let mut parts = v.split('x');
                let w: usize = parts
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| die("bad --cell"));
                let h: usize = parts
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| die("bad --cell"));
                cell = Some((w, h));
                i += 2;
            }
            "--const-prefix" => {
                let v = argv
                    .get(i + 1)
                    .unwrap_or_else(|| die("--const-prefix needs a value"));
                prefix = Some(v.clone());
                i += 2;
            }
            other => die(&format!("unknown arg: {other}")),
        }
    }
    let (cell_w, cell_h) = cell.unwrap_or_else(|| die("missing --cell"));
    Args {
        ttf_path,
        out_path,
        px_height: px_height.unwrap_or_else(|| die("missing --px")),
        cell_w,
        cell_h,
        prefix: prefix.unwrap_or_else(|| die("missing --const-prefix")),
    }
}

fn main() {
    let args = parse_args();

    let ttf_bytes = fs::read(&args.ttf_path)
        .unwrap_or_else(|e| die(&format!("read {}: {e}", args.ttf_path)));
    let font = Font::from_bytes(ttf_bytes, FontSettings::default())
        .unwrap_or_else(|e| die(&format!("parse font: {e}")));

    // Vertical layout: derive an ascent / descent budget from the font's
    // line metrics at our target pixel size. Distribute the cell's
    // vertical leading evenly above ascent and below descent.
    let line = font
        .horizontal_line_metrics(args.px_height)
        .unwrap_or_else(|| die("font has no horizontal line metrics"));
    let ascent = line.ascent.round() as i32;
    let descent_abs = (-line.descent).round() as i32; // descent is negative
    let glyph_band = ascent + descent_abs;
    let cell_h_i = args.cell_h as i32;
    if glyph_band > cell_h_i {
        die(&format!(
            "glyph band {glyph_band} px exceeds cell height {cell_h_i}; lower --px or raise cell"
        ));
    }
    let leading = cell_h_i - glyph_band;
    let top_pad = leading / 2; // even split, descent gets the leftover odd px
    let baseline_y_in_cell = top_pad + ascent; // pixel row where baseline sits

    let mut data = vec![0u8; NUM_CHARS * args.cell_w * args.cell_h];

    for slot in 0..NUM_CHARS {
        let ch = (FIRST_CHAR as usize + slot) as u8 as char;
        let (metrics, bitmap) = font.rasterize(ch, args.px_height);
        if metrics.width == 0 || metrics.height == 0 {
            continue; // space and other zero-bbox glyphs leave the slot all-zero
        }
        // Horizontal: align glyph to its xmin offset from the cell's left
        // edge. For monospace fonts every character lands in the same
        // column band; xmin is the left side bearing.
        let dst_x = metrics.xmin;
        // Vertical: glyph bitmap top sits at (baseline - ymin - height).
        // ymin is the descent (negative for above-baseline glyphs in
        // fontdue's coordinate system; positive for descenders).
        let glyph_top = baseline_y_in_cell - metrics.height as i32 - metrics.ymin;

        for gy in 0..metrics.height {
            let dy = glyph_top + gy as i32;
            if dy < 0 || dy >= cell_h_i {
                continue;
            }
            for gx in 0..metrics.width {
                let dx = dst_x + gx as i32;
                if dx < 0 || dx >= args.cell_w as i32 {
                    continue;
                }
                let alpha = bitmap[gy * metrics.width + gx];
                if alpha == 0 {
                    continue;
                }
                let dst = slot * args.cell_w * args.cell_h
                    + (dy as usize) * args.cell_w
                    + (dx as usize);
                data[dst] = alpha;
            }
        }
    }

    write_output(&args, &data).unwrap_or_else(|e| die(&format!("write output: {e}")));
    eprintln!(
        "bake-font: wrote {} ({} glyphs × {}×{} = {} bytes)",
        args.out_path,
        NUM_CHARS,
        args.cell_w,
        args.cell_h,
        data.len()
    );
}

fn write_output(args: &Args, data: &[u8]) -> std::io::Result<()> {
    let prefix = &args.prefix;
    let path = Path::new(&args.out_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = fs::File::create(path)?;
    writeln!(out, "// SPDX-License-Identifier: AGPL-3.0-or-later")?;
    writeln!(out, "// Copyright (C) 2024-2026 Jason Ricca")?;
    writeln!(out, "//")?;
    writeln!(
        out,
        "// Generated by tools/bake-font from `{}`. DO NOT EDIT.",
        args.ttf_path
    )?;
    writeln!(
        out,
        "// Re-bake with: cargo run --manifest-path tools/bake-font/Cargo.toml -- \\"
    )?;
    writeln!(
        out,
        "//   {} {} --px {} --cell {}x{} --const-prefix {}",
        args.ttf_path, args.out_path, args.px_height, args.cell_w, args.cell_h, prefix
    )?;
    writeln!(out, "//")?;
    writeln!(
        out,
        "// One byte per pixel = grayscale alpha (0 = transparent, 255 = opaque)."
    )?;
    writeln!(
        out,
        "// Glyphs are stored row-major within their cell, cells stored in"
    )?;
    writeln!(out, "// ASCII order starting at FIRST.")?;
    writeln!(out)?;
    writeln!(out, "pub const {prefix}_FIRST: u8 = 0x{:02X};", FIRST_CHAR)?;
    writeln!(out, "pub const {prefix}_NUM_GLYPHS: u8 = {};", NUM_CHARS)?;
    writeln!(out, "pub const {prefix}_CELL_W: u16 = {};", args.cell_w)?;
    writeln!(out, "pub const {prefix}_CELL_H: u16 = {};", args.cell_h)?;
    writeln!(out)?;
    writeln!(out, "pub static {prefix}_DATA: &[u8] = &[")?;
    let bytes_per_row = args.cell_w;
    for slot in 0..NUM_CHARS {
        let ch = (FIRST_CHAR as usize + slot) as u8;
        let label = if (0x20..=0x7E).contains(&ch) && ch != b'/' {
            format!("0x{ch:02X} '{}'", ch as char)
        } else {
            format!("0x{ch:02X}")
        };
        writeln!(out, "    // {label}")?;
        for row in 0..args.cell_h {
            write!(out, "    ")?;
            for col in 0..bytes_per_row {
                let idx = slot * args.cell_w * args.cell_h + row * args.cell_w + col;
                write!(out, "0x{:02X},", data[idx])?;
                if col + 1 < bytes_per_row {
                    write!(out, " ")?;
                }
            }
            writeln!(out)?;
        }
    }
    writeln!(out, "];")?;
    Ok(())
}
