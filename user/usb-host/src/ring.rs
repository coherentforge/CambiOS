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

/// SCAFFOLDING: 16-byte TRB count per transfer ring (per endpoint).
/// One 4 KiB page = 256 TRBs (255 usable + Link). EP0 control transfers
/// are short — 3 TRBs per setup/data/status sequence; v1-endgame
/// CCID workload + a handful of HID devices is well under 256 in-flight.
/// Why: bounded → verifier-tractable; one-page allocations match
/// `sys::alloc_dma`'s native granularity.
/// Replace when: bulk IN/OUT endpoints land (B-vi) and per-endpoint
/// queue-depth instrumentation shows pressure — separate constant per
/// endpoint class may be warranted then.
pub const TRANSFER_RING_TRBS: usize = 256;

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
    /// Enqueue a Command TRB at the current producer slot, return the
    /// physical address of the slot the TRB was written to (callers
    /// match completion events on this address via the
    /// `command_trb_pointer` field of `CommandCompletionEvent`).
    ///
    /// The caller-supplied `trb.control` should already have the TRB
    /// type + type-specific bits set; this method ORs in the current
    /// producer cycle bit before the write so the controller treats
    /// the slot as freshly produced.
    ///
    /// Returns `None` if the next write would land in the Link TRB
    /// slot (slot `COMMAND_RING_TRBS - 1`). Link-wrap (rewriting Link
    /// TRB cycle + toggling producer cycle + resetting producer to 0)
    /// is deferred — Stream B issues commands from explicit driver
    /// code paths today, max ~10 commands per boot; the ring's 255
    /// usable slots are unreachable.
    /// Revisit when: a port-status-change-event handler (or any
    /// runtime event source) auto-issues commands without explicit
    /// driver code at the call site — that's when command count
    /// stops being bounded by hand-written code and wrap becomes
    /// reachable. Architectural shift expected around B-vi (runtime
    /// device discovery).
    pub fn enqueue(&mut self, trb: Trb) -> Option<u64> {
        // Reserve the last slot for the Link TRB.
        if self.producer >= COMMAND_RING_TRBS - 1 {
            return None;
        }

        let trb_paddr = self.paddr + (self.producer * core::mem::size_of::<Trb>()) as u64;
        let trb_vaddr = self.vaddr + (self.producer * core::mem::size_of::<Trb>()) as u64;

        // Two-step write to commit the TRB atomically from the
        // controller's perspective:
        //
        //   1. Write parameter + status + control-without-cycle.
        //      This populates the body but the cycle bit (control[0])
        //      stays at its old value (0 on a fresh-zeroed ring), so
        //      the controller still treats the slot as "not produced."
        //   2. Compiler fence (Release) to keep the body write ahead
        //      of the cycle-bit write under reordering.
        //   3. Write the control dword (offset 12, naturally aligned)
        //      with the cycle bit set. This is a single 4-byte store
        //      and acts as the "commit" — the controller sees the
        //      full TRB the instant cycle flips.
        //
        // Doing a single 16-byte `write_volatile<Trb>` would let the
        // compiler split into smaller stores in any order; the
        // controller can then observe a cycle-matched TRB with stale
        // body fields and assert USBSTS.HCE.
        let body = Trb {
            parameter: trb.parameter,
            status: trb.status,
            control: trb.control & !0x1, // cycle bit cleared
        };
        let control_with_cycle = (trb.control & !0x1) | (self.cycle as u32 & 0x1);

        // SAFETY: `trb_vaddr` points into the DMA page allocated by
        // `CommandRing::new`; we own it exclusively. The slot is
        // 16-byte aligned (producer * 16 from a 4 KiB-aligned base);
        // the +12 offset is u32-aligned (16-byte aligned + 12).
        unsafe {
            core::ptr::write_volatile(trb_vaddr as *mut Trb, body);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(
                (trb_vaddr + 12) as *mut u32,
                control_with_cycle,
            );
        }

        self.producer += 1;
        Some(trb_paddr)
    }

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
    /// Read the next TRB if the controller has produced one. Returns
    /// `Some(trb)` when the TRB at the consumer slot has its cycle
    /// bit matching the driver's current consumer cycle (the
    /// controller has written there); `None` otherwise.
    ///
    /// On consumption, the consumer index advances; at end-of-segment
    /// it wraps to 0 and the consumer cycle bit toggles. Callers must
    /// update ERDP after consuming one or more events so the
    /// controller knows how far the driver has caught up.
    pub fn poll_next(&mut self) -> Option<Trb> {
        let slot_offset = self.consumer * core::mem::size_of::<Trb>();
        let trb_vaddr = self.vaddr + slot_offset as u64;

        // SAFETY: `trb_vaddr` is within the DMA page allocated by
        // `EventRing::new`. 16-byte aligned. The volatile read forces
        // the load to observe the controller's most recent write.
        let trb = unsafe { core::ptr::read_volatile(trb_vaddr as *const Trb) };

        // Cycle bit at control[0]; if it doesn't match the consumer's
        // current expected cycle, no event has been written here yet.
        if (trb.control & 0x1) as u8 != self.cycle {
            return None;
        }

        // Advance the consumer. End-of-segment → wrap to 0 + toggle
        // cycle (controller flips its producer cycle on wrap, so the
        // next batch of events arrives with the toggled cycle bit).
        self.consumer += 1;
        if self.consumer >= EVENT_RING_TRBS {
            self.consumer = 0;
            self.cycle ^= 1;
        }
        Some(trb)
    }

    /// Physical address of the next slot the consumer will read from
    /// (used to compute the new ERDP value the caller writes back).
    pub fn dequeue_paddr(&self) -> u64 {
        self.paddr + (self.consumer * core::mem::size_of::<Trb>()) as u64
    }

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
// TransferRing
// ---------------------------------------------------------------------------

/// A producer-owned ring of Transfer TRBs (one per endpoint). Single
/// segment, one 4 KiB page. Structurally identical to [`CommandRing`]:
/// Link TRB at the last slot with TC=1, cycle=1 at fresh init.
///
/// B-iv allocates one for EP0 of the addressed device and installs its
/// base into the EP0 Endpoint Context's TR Dequeue Pointer field. B-v
/// enqueues the 3-TRB Setup/Data/Status sequence for GET_DESCRIPTOR.
/// Revisit when: a second transfer ring lands (bulk endpoint at B-vi)
/// and the duplication with `CommandRing` becomes concrete enough to
/// justify a shared `TrbRing` underlying type.
#[allow(dead_code)]
pub struct TransferRing {
    pub paddr: u64,
    pub vaddr: u64,
    /// Initial cycle bit (1 at fresh init). Producer toggles on each
    /// wrap; consumer (controller) tracks its own copy.
    pub cycle: u8,
    /// Next-write index.
    pub producer: usize,
}

impl TransferRing {
    /// Enqueue a Transfer TRB at the current producer slot. Same shape
    /// as `CommandRing::enqueue`: two-step write (body without cycle
    /// → compiler_fence(Release) → control DWord with cycle bit) so
    /// the controller cannot observe a cycle-matched TRB with stale
    /// body fields under compiler-split single-write reordering.
    ///
    /// Returns the physical address of the TRB slot written, so
    /// callers can match Transfer Events on the TRB pointer field.
    /// Returns `None` if the next write would land in the Link TRB
    /// slot (slot `TRANSFER_RING_TRBS - 1`). Link-wrap is
    /// unimplemented — see [`CommandRing::enqueue`] for the same
    /// rationale; transfer rings are bounded by hand-written EP0
    /// transfers in B-v (3 TRBs per GET_DESCRIPTOR).
    /// Revisit when: a runtime path (bulk endpoints with IRQ-driven
    /// queue refill at B-vi) auto-issues transfers beyond hand-written
    /// driver call sites.
    pub fn enqueue(&mut self, trb: Trb) -> Option<u64> {
        if self.producer >= TRANSFER_RING_TRBS - 1 {
            return None;
        }

        let trb_paddr = self.paddr + (self.producer * core::mem::size_of::<Trb>()) as u64;
        let trb_vaddr = self.vaddr + (self.producer * core::mem::size_of::<Trb>()) as u64;

        let body = Trb {
            parameter: trb.parameter,
            status: trb.status,
            control: trb.control & !0x1, // cycle bit cleared
        };
        let control_with_cycle = (trb.control & !0x1) | (self.cycle as u32 & 0x1);

        // SAFETY: `trb_vaddr` points into the DMA page allocated by
        // `TransferRing::new`; we own it exclusively. The slot is
        // 16-byte aligned (producer * 16 from a 4 KiB-aligned base);
        // the +12 offset is u32-aligned (16-byte aligned + 12).
        unsafe {
            core::ptr::write_volatile(trb_vaddr as *mut Trb, body);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(
                (trb_vaddr + 12) as *mut u32,
                control_with_cycle,
            );
        }

        self.producer += 1;
        Some(trb_paddr)
    }

    /// Allocate one page of DMA memory, zero it, install the Link TRB
    /// at the last slot pointing back to the ring's base. Returns
    /// `None` on `sys::alloc_dma` failure.
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
        let link_offset = (TRANSFER_RING_TRBS - 1) * core::mem::size_of::<Trb>();
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
