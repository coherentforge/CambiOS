// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! xHCI Transfer Request Block (TRB) rings — xHCI 1.2 § 4.9 + § 6.4.
//!
//! Three ring abstractions used in B-ii's bring-up:
//!
//! - [`CommandRing`] — producer ring; the driver writes Command TRBs,
//!   the controller consumes them. CRCR.RingPtr points at this ring's
//!   base. A Link TRB at the last slot wraps the ring back to start
//!   (TC=1 so the cycle bit toggles on each wrap).
//! - [`EventRing`] — consumer ring; the controller writes Event TRBs,
//!   the driver reads them. ERDP points at the next event to consume.
//! - [`Erst`] — Event Ring Segment Table; one 16-byte entry pointing
//!   at the (single) event ring segment. ERSTBA points at this table.
//!
//! All three live in DMA memory allocated by `sys::alloc_dma`. Each
//! ring is exactly one page (4 KiB) which holds [`COMMAND_RING_TRBS`]
//! or [`EVENT_RING_TRBS`] 16-byte TRBs. The ERST is also one page —
//! 16 bytes used for the single segment, the rest is reserved.

use cambios_libsys as sys;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// SCAFFOLDING: 16-byte TRB count for the command ring. One 4 KiB
/// page = 256 TRBs; xHCI's minimum is 16, max is 64 K. 255 usable
/// command slots (the last TRB is a Link wrapping to start) is
/// generous v1-endgame capacity — the command stream is low-rate
/// (Enable Slot, Address Device, Configure Endpoint per attached
/// device), not high-throughput.
/// Why: bounded → verifier-tractable; one-page allocations match
/// `sys::alloc_dma`'s native granularity.
/// Replace when: queue-depth instrumentation shows >75% utilization
/// (e.g., a heavily multiplexed USB-IF compliance workload).
pub const COMMAND_RING_TRBS: usize = 256;

/// SCAFFOLDING: 16-byte TRB count for the event ring. Symmetric with
/// the command ring; events are mostly 1:1 with commands plus
/// per-port-change events. 256 events / page is comfortable v1-endgame
/// capacity for a low-rate USB tree (~10 devices, infrequent
/// hot-plug).
/// Why: see COMMAND_RING_TRBS — same shape, same trade-offs.
/// Replace when: event ring overrun (USBSTS.HSE set + Event Ring
/// Overrun event observed) — would mean the driver isn't draining
/// fast enough, B-iv IRQ handling tightens this.
pub const EVENT_RING_TRBS: usize = 256;

// ---------------------------------------------------------------------------
// TRB
// ---------------------------------------------------------------------------

/// A single 16-byte Transfer Request Block (xHCI 1.2 § 4.11 / § 6.4).
///
/// `parameter` is bytes 0..8 (typically a paddr or context pointer);
/// `status` is bytes 8..12 (length / completion code); `control` is
/// bytes 12..16 (cycle bit at [0], TRB type at [10:15], plus
/// type-specific bits).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    /// Zero TRB — used at B-iii when enqueueing fresh command TRBs
    /// (caller fills `parameter` / `control` per command type). Kept
    /// alongside `Trb` itself so B-iii doesn't need to re-derive it.
    #[allow(dead_code)]
    pub const ZERO: Self = Self {
        parameter: 0,
        status: 0,
        control: 0,
    };
}

/// TRB Type field values used through B-ii (xHCI 1.2 § 6.4.6). Other
/// types land as the corresponding command / event surfaces grow.
#[allow(dead_code)]
pub mod trb_type {
    /// Link TRB — terminates a ring segment, wraps to a new segment
    /// (or, for single-segment rings, back to the start of the same
    /// segment). When TC (Toggle Cycle) is set, the producer flips
    /// its cycle bit on traversal.
    pub const LINK: u8 = 6;
    /// Command Completion Event — written by the controller to the
    /// event ring after consuming a Command TRB. Used in B-iii.
    pub const COMMAND_COMPLETION: u8 = 33;
    /// Port Status Change Event — written by the controller when a
    /// PORTSC field changes (e.g., a device connects). Used in B-iii.
    pub const PORT_STATUS_CHANGE: u8 = 34;
}

// ---------------------------------------------------------------------------
// CommandRing
// ---------------------------------------------------------------------------

/// A producer-owned ring of Command TRBs. Single segment, one 4 KiB
/// page. The last slot holds a Link TRB pointing back to the ring's
/// base with TC=1 so the cycle bit toggles on wrap.
#[allow(dead_code)]
pub struct CommandRing {
    pub paddr: u64,
    pub vaddr: u64,
    /// Initial cycle bit (1 at fresh init). Producer toggles on each
    /// wrap; consumer (controller) tracks its own copy.
    pub cycle: u8,
    /// Next-write index. Reserved for B-iii — B-ii does not enqueue.
    pub producer: usize,
}

impl CommandRing {
    /// Allocate one page of DMA memory, zero it, install the Link TRB
    /// at the last slot. Returns `None` on `sys::alloc_dma` failure.
    pub fn new() -> Option<Self> {
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut paddr);
        if ret < 0 {
            return None;
        }
        let vaddr = ret as u64;

        // SAFETY: alloc_dma returned a fresh 4 KiB region uniquely
        // owned by this process; zero-initialize the whole page so
        // every TRB slot starts with cycle=0 (the controller treats
        // mismatched-cycle TRBs as "not yet produced").
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, 4096);
        }

        // Install the Link TRB at the last slot pointing back to the
        // ring's base with TC=1 (toggle cycle on wrap) and Cycle=1
        // (controller's initial cycle bit, matches our `cycle`).
        let link = Trb {
            parameter: paddr,
            status: 0,
            // Cycle=1, TC=1 (bit 1), Type=Link (bits 10..15)
            control: 0x1 | (1 << 1) | ((trb_type::LINK as u32) << 10),
        };
        let link_offset = (COMMAND_RING_TRBS - 1) * core::mem::size_of::<Trb>();
        // SAFETY: link_offset = 255 * 16 = 4080; the 16-byte Link TRB
        // ends at 4096, exactly the page boundary. The cast is to a
        // naturally-aligned location (multiple of 16).
        unsafe {
            core::ptr::write_volatile((vaddr + link_offset as u64) as *mut Trb, link);
        }

        Some(Self {
            paddr,
            vaddr,
            cycle: 1,
            producer: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// EventRing
// ---------------------------------------------------------------------------

/// A consumer-owned ring of Event TRBs. Single segment, one 4 KiB
/// page. No Link TRB — event rings use the ERST to describe segment
/// layout; wrapping is implicit at ERST's described segment size.
#[allow(dead_code)]
pub struct EventRing {
    pub paddr: u64,
    pub vaddr: u64,
    /// Consumer cycle bit (1 initial; toggle on wrap).
    pub cycle: u8,
    /// Next-read index. Reserved for B-iii — B-ii does not consume.
    pub consumer: usize,
}

impl EventRing {
    pub fn new() -> Option<Self> {
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut paddr);
        if ret < 0 {
            return None;
        }
        let vaddr = ret as u64;

        // SAFETY: alloc_dma returned a fresh 4 KiB DMA region; zeroing
        // sets all events' cycle bits to 0, matching the controller's
        // initial state where no events have been produced. The
        // driver's consumer-cycle starts at 1, so the next event the
        // controller writes (with cycle=1) is correctly detected.
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, 4096);
        }

        Some(Self {
            paddr,
            vaddr,
            cycle: 1,
            consumer: 0,
        })
    }

    pub fn capacity_trbs(&self) -> u32 {
        EVENT_RING_TRBS as u32
    }
}

// ---------------------------------------------------------------------------
// ERST (Event Ring Segment Table)
// ---------------------------------------------------------------------------

/// Event Ring Segment Table (xHCI 1.2 § 6.5). One 16-byte entry per
/// segment; we use a single segment so the table has one valid entry
/// followed by zeros.
///
/// Entry layout:
/// - bytes 0..8: Ring Segment Base Address (paddr, 64-byte aligned)
/// - bytes 8..10: Ring Segment Size (TRB count, 16..4096)
/// - bytes 10..16: reserved / RsvdZ
#[allow(dead_code)]
pub struct Erst {
    pub paddr: u64,
    pub vaddr: u64,
}

impl Erst {
    /// Allocate a one-page ERST whose first entry points at the given
    /// event-ring segment. The rest of the page stays zero — ERSTSZ
    /// (written into the interrupter's runtime register) tells the
    /// controller how many entries are valid (1 in B-ii).
    pub fn new(event_ring_paddr: u64, event_ring_size_trbs: u32) -> Option<Self> {
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut paddr);
        if ret < 0 {
            return None;
        }
        let vaddr = ret as u64;

        // SAFETY: alloc_dma returned a fresh 4 KiB DMA region; we
        // zero-init the whole page so unused entries are well-defined
        // RsvdZ, then write the single live entry at offset 0.
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, 4096);
            let base = vaddr as *mut u8;
            // bytes 0..8: Ring Segment Base Address
            core::ptr::write_volatile(base as *mut u64, event_ring_paddr);
            // bytes 8..12: Ring Segment Size (low 16 bits valid;
            // high 16 reserved). Storing the full u32 with the
            // upper half zero is safe — reserved fields are
            // RsvdZ.
            core::ptr::write_volatile(base.add(8) as *mut u32, event_ring_size_trbs);
            // bytes 12..16 stay zero (write_bytes above).
        }

        Some(Self { paddr, vaddr })
    }
}
