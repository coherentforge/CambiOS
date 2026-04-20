// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! fb-demo — Phase GUI-1 first-pixels boot module (ADR-011).
//!
//! Maps display 0's framebuffer via `SYS_MAP_FRAMEBUFFER` and paints it
//! with a test pattern that exercises the entire kernel → framebuffer
//! path:
//!
//!   • diagonal RGB gradient across the full surface — proves every
//!     pixel write reaches the right row/column once pitch is honoured.
//!   • alternating 8-pixel-wide columns of solid cyan — catches
//!     pitch/stride errors immediately (columns would smear or skew
//!     if pitch were miscomputed).
//!   • filled white rectangle near centre — proves we can target
//!     specific coordinates without drift.
//!
//! Serial output reports the descriptor contents for diagnostics.
//! After painting, yields forever so the pattern stays on screen for
//! visual inspection.

#![no_std]
#![no_main]

use arcos_libsys as sys;
use arcos_libsys::FramebufferDescriptor;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[FB-DEMO] starting\r\n");

    // Release the boot gate up-front. fb-demo is a leaf — nothing
    // downstream depends on its completion — so signalling ready
    // immediately lets shell come up in parallel.
    sys::module_ready();

    let mut desc = FramebufferDescriptor::default();
    if let Err(rc) = sys::map_framebuffer(0, &mut desc) {
        print_int(b"[FB-DEMO] map_framebuffer rc=", rc);
        sys::exit(1);
    }

    print_fb_descriptor(&desc);

    if desc.bpp != 32 {
        // libgfx will handle non-32bpp; this demo does not. Log and exit
        // cleanly rather than painting garbage.
        print_int(b"[FB-DEMO] unsupported bpp=", desc.bpp as i64);
        sys::exit(2);
    }

    paint_test_pattern(&desc);
    sys::print(b"[FB-DEMO] pattern painted; idling\r\n");

    // Hold the pattern on screen for inspection. No exit — a real
    // compositor would repaint on events; the demo is static.
    loop {
        sys::yield_now();
    }
}

/// Paint the diagnostic pattern into the mapped framebuffer.
fn paint_test_pattern(desc: &FramebufferDescriptor) {
    let width = desc.width as usize;
    let height = desc.height as usize;
    let pitch = desc.pitch as usize;
    let base = desc.vaddr as *mut u8;

    // First pass: diagonal RGB gradient.
    for y in 0..height {
        // SAFETY: `base + y * pitch` stays within the mapped region
        // because `pitch * height == fb.size_bytes()` (framebuffer
        // invariant; see src/boot/mod.rs FramebufferInfo::size_bytes).
        let row = unsafe { base.add(y * pitch) } as *mut u32;
        for x in 0..width {
            let r = ((x * 255) / width.max(1)) as u8;
            let g = ((y * 255) / height.max(1)) as u8;
            let b = (((x + y) * 255) / (width + height).max(1)) as u8;
            let pixel = pack_pixel(desc, r, g, b);
            // SAFETY: `x < width <= pitch/4` so `row.add(x)` is
            // within the row's pitch-bounded span.
            unsafe {
                row.add(x).write_volatile(pixel);
            }
        }
    }

    // Second pass: pitch-sanity bars — every other 8-pixel column solid
    // cyan. Any pitch/stride miscalculation shows as smeared or tilted
    // bars rather than clean verticals.
    let cyan = pack_pixel(desc, 0x00, 0xB0, 0xFF);
    for y in 0..height {
        let row = unsafe { base.add(y * pitch) } as *mut u32;
        let mut x = 0;
        while x < width {
            if (x / 8) & 1 == 1 {
                // leave gradient
            } else {
                // overwrite first 2 pixels of each 8-pixel block with
                // cyan — a thin stripe, not a full bar, so the
                // underlying gradient still shows
                let limit = (x + 2).min(width);
                for bx in x..limit {
                    // SAFETY: as above.
                    unsafe {
                        row.add(bx).write_volatile(cyan);
                    }
                }
            }
            x += 8;
        }
    }

    // Third pass: centred filled rectangle (white on black border).
    // Coordinates chosen to be visible even on modest resolutions.
    let rect_w = (width / 3).min(480);
    let rect_h = (height / 6).min(120);
    let rect_x = (width.saturating_sub(rect_w)) / 2;
    let rect_y = (height.saturating_sub(rect_h)) / 2;
    let border = 4;
    let black = pack_pixel(desc, 0x00, 0x00, 0x00);
    let white = pack_pixel(desc, 0xFF, 0xFF, 0xFF);

    for dy in 0..rect_h {
        let y = rect_y + dy;
        if y >= height {
            break;
        }
        let row = unsafe { base.add(y * pitch) } as *mut u32;
        for dx in 0..rect_w {
            let x = rect_x + dx;
            if x >= width {
                break;
            }
            let in_border = dx < border
                || dy < border
                || dx >= rect_w.saturating_sub(border)
                || dy >= rect_h.saturating_sub(border);
            let pixel = if in_border { black } else { white };
            // SAFETY: bounds checked above.
            unsafe {
                row.add(x).write_volatile(pixel);
            }
        }
    }
}

/// Pack an (R, G, B) triple into the framebuffer's native pixel format
/// using the RGB mask shifts reported in the descriptor.
fn pack_pixel(desc: &FramebufferDescriptor, r: u8, g: u8, b: u8) -> u32 {
    ((r as u32) << desc.red_mask_shift)
        | ((g as u32) << desc.green_mask_shift)
        | ((b as u32) << desc.blue_mask_shift)
}

fn print_fb_descriptor(desc: &FramebufferDescriptor) {
    sys::print(b"[FB-DEMO] vaddr=");
    print_hex64(desc.vaddr);
    sys::print(b" size=");
    print_u32_dec(desc.width);
    sys::print(b"x");
    print_u32_dec(desc.height);
    sys::print(b" pitch=");
    print_u32_dec(desc.pitch);
    sys::print(b" bpp=");
    print_u32_dec(desc.bpp as u32);
    sys::print(b" R");
    print_u32_dec(desc.red_mask_size as u32);
    sys::print(b"<<");
    print_u32_dec(desc.red_mask_shift as u32);
    sys::print(b" G");
    print_u32_dec(desc.green_mask_size as u32);
    sys::print(b"<<");
    print_u32_dec(desc.green_mask_shift as u32);
    sys::print(b" B");
    print_u32_dec(desc.blue_mask_size as u32);
    sys::print(b"<<");
    print_u32_dec(desc.blue_mask_shift as u32);
    sys::print(b"\r\n");
}

// Tiny numeric printers — the demo is pre-compositor, pre-libgfx, so it
// talks to the serial console directly via sys::print.

fn print_int(prefix: &[u8], value: i64) {
    sys::print(prefix);
    if value < 0 {
        sys::print(b"-");
        print_u64_dec((-value) as u64);
    } else {
        print_u64_dec(value as u64);
    }
    sys::print(b"\r\n");
}

fn print_u32_dec(n: u32) {
    print_u64_dec(n as u64);
}

fn print_u64_dec(mut n: u64) {
    if n == 0 {
        sys::print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut len = 0;
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    // reverse
    let mut out = [0u8; 20];
    for i in 0..len {
        out[i] = buf[len - 1 - i];
    }
    sys::print(&out[..len]);
}

fn print_hex64(mut n: u64) {
    sys::print(b"0x");
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let nibble = (n & 0xF) as u8;
        buf[15 - i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        n >>= 4;
    }
    sys::print(&buf);
}

// Panic handler (Rust requires one for no_std binaries).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[FB-DEMO] panic\r\n");
    sys::exit(255);
}
