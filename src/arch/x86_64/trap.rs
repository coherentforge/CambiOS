// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors

//! x86_64 trap entry (ADR-040 § 3): the IDT, one generated stub per
//! vector, one common entry and one common exit.
//!
//! Every interrupt and exception enters the kernel the same way:
//!
//! 1. The CPU aligns RSP to 16 bytes (from ring 3 it first switches to
//!    `TSS.RSP0`, or to an IST stack when the gate names one) and pushes
//!    SS, RSP, RFLAGS, CS, RIP, and for some vectors an error code.
//! 2. The vector's stub pushes a 0 where the CPU pushed no error code, then
//!    the vector number, and jumps to `x86_trap_common`.
//! 3. `x86_trap_common` pushes the fifteen general registers, completing a
//!    [`SavedContext`](super::SavedContext) on the stack, clears AC when
//!    SMAP is on, and calls `interrupts::x86_trap(ctx, vector, error)`.
//! 4. `x86_trap` returns the stack pointer of the context to resume: the
//!    same one, or another task's after a switch.
//! 5. `x86_trap_restore` pops that context and executes `iretq`.
//!
//! `yield_save_and_switch` builds the same `SavedContext` shape and leaves
//! through `x86_trap_restore` too, so every resumption of a saved context
//! takes the one exit. `syscall_entry` is the only other way in.
//!
//! The stub owns what the compiler-generated `x86-interrupt` ABI used to do
//! without saying so: one frame shape for every vector (the error-code
//! normalization), 16-byte stack alignment at the call into Rust (the CPU's
//! five or six words, the stub's one or two, and fifteen registers make 22
//! words, 176 bytes, a multiple of 16; `SavedContext`'s size is asserted),
//! and a clear direction flag (`cld`), which interrupt delivery does not
//! clear and the SysV ABI requires.
//!
//! GS is not touched here yet: the kernel's per-CPU GS base is still live in
//! ring 3 (ADR-040 § 2's `swapgs` lands separately).

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;

/// HARDWARE: the IDT has 256 gates, one per vector (Intel SDM Vol. 3A
/// § 6.10).
pub const IDT_ENTRIES: usize = 256;

/// HARDWARE: type and attribute byte of a present, DPL-0, 64-bit interrupt
/// gate: P = 1, DPL = 0, type 0xE (Intel SDM Vol. 3A § 6.14.1, Figure
/// 6-8). An interrupt gate clears IF on entry; DPL 0 makes a ring-3
/// `int N` on it a #GP instead of a call into the handler.
const INTERRUPT_GATE_DPL0: u8 = 0x8E;

/// One 16-byte IDT gate (Intel SDM Vol. 3A § 6.14.1, Figure 6-8).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdtGate {
    offset_low: u16,
    selector: u16,
    /// Bits 0-2: the IST entry the CPU switches to (1-7), 0 for none.
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

const _: () = assert!(core::mem::size_of::<IdtGate>() == 16);

impl IdtGate {
    /// A gate that is not present.
    pub const MISSING: IdtGate = IdtGate {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    /// A present DPL-0 interrupt gate that enters `handler` in code segment
    /// `selector`, switching to IST entry `ist` (1-7) first, or staying on
    /// the current or `TSS.RSP0` stack if `ist` is 0. Bits of `ist` above
    /// the low three are not representable and are dropped.
    pub const fn interrupt(handler: u64, selector: u16, ist: u8) -> IdtGate {
        IdtGate {
            offset_low: handler as u16,
            selector,
            ist: ist & 0x7,
            type_attr: INTERRUPT_GATE_DPL0,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    /// The handler address this gate enters.
    pub const fn handler(&self) -> u64 {
        (self.offset_low as u64) | ((self.offset_mid as u64) << 16) | ((self.offset_high as u64) << 32)
    }

    /// The IST entry this gate switches to (0 for none).
    pub const fn ist(&self) -> u8 {
        self.ist
    }

    /// Whether the gate is present.
    pub const fn is_present(&self) -> bool {
        self.type_attr & 0x80 != 0
    }
}

/// Whether the CPU pushes an error code for `vector`: #DF, #TS, #NP, #SS,
/// #GP, #PF, #AC, #CP, #VC and #SX (Intel SDM Vol. 3A Table 6-1; AMD APM
/// Vol. 2 § 8.2 for #VC and #SX). The stub table's assembly (below) encodes
/// the same set; this function is its testable statement.
pub const fn pushes_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}

#[repr(C, align(16))]
struct Idt([IdtGate; IDT_ENTRIES]);

/// The IDT. Written by the boot CPU during single-threaded init (every gate
/// in [`init_idt`], the IST bits of three gates in [`set_gate_ist`]), then
/// read only by the CPUs' interrupt delivery.
struct IdtStorage(UnsafeCell<Idt>);

// SAFETY: written only during single-threaded boot init, with interrupts
// disabled, before any AP loads it; read only by hardware afterwards.
unsafe impl Sync for IdtStorage {}

static IDT: IdtStorage = IdtStorage(UnsafeCell::new(Idt([IdtGate::MISSING; IDT_ENTRIES])));

/// Set once the boot CPU has turned SMAP on (ADR-040 § 6). The common entry
/// reads it to decide whether to execute `clac`, which is an invalid opcode
/// on a CPU without SMAP: a branch on a flag written once at boot, not code
/// patching. Nothing sets it yet.
#[unsafe(no_mangle)]
pub static X86_SMAP_ACTIVE: AtomicBool = AtomicBool::new(false);

extern "C" {
    /// The 256 stub addresses, in vector order, emitted by the stub
    /// assembly below into `.rodata`.
    static X86_TRAP_STUB_TABLE: [u64; IDT_ENTRIES];
}

/// Point every IDT gate at its vector's stub (no IST switch yet) and load
/// the IDT on this CPU.
///
/// # Safety
/// The boot CPU only, once, during single-threaded init with interrupts
/// disabled; no other CPU has loaded the IDT yet.
pub unsafe fn init_idt() {
    // SAFETY: X86_TRAP_STUB_TABLE is a read-only table of IDT_ENTRIES
    // addresses the assembler emitted into .rodata; nothing writes it.
    let stubs: &[u64; IDT_ENTRIES] = unsafe { &X86_TRAP_STUB_TABLE };
    // SAFETY: single-threaded init (caller), so no other reference to the
    // IDT exists while this one is live.
    let gates = unsafe { &mut (*IDT.0.get()).0 };
    for (gate, &stub) in gates.iter_mut().zip(stubs.iter()) {
        *gate = IdtGate::interrupt(stub, super::gdt::KERNEL_CS, 0);
    }
    // SAFETY: the IDT is fully written above and lives for the kernel's
    // lifetime (a static).
    unsafe { load_idt() };
}

/// Make `vector`'s gate switch to emergency stack `slot` (ADR-040 § 7).
///
/// # Safety
/// The boot CPU only, during single-threaded init with interrupts disabled,
/// after its own emergency stacks exist; every AP allocates its stacks
/// before it loads the IDT.
pub unsafe fn set_gate_ist(vector: u8, slot: super::gdt::IstSlot) {
    let idt = IDT.0.get();
    // SAFETY: single-threaded init (caller); vector < 256 = IDT_ENTRIES.
    let gate = unsafe { &mut (*idt).0[vector as usize] };
    *gate = IdtGate::interrupt(gate.handler(), super::gdt::KERNEL_CS, slot.gate_index());
}

/// Load the IDT into this CPU's IDTR.
///
/// # Safety
/// [`init_idt`] has run (on the boot CPU) and interrupts are disabled on
/// this CPU.
pub unsafe fn load_idt() {
    use x86_64::instructions::tables::lidt;
    use x86_64::structures::DescriptorTablePointer;
    let pointer = DescriptorTablePointer {
        limit: (core::mem::size_of::<Idt>() - 1) as u16,
        base: x86_64::VirtAddr::new_truncate(IDT.0.get() as u64),
    };
    // SAFETY: the pointer names the static IDT, fully initialized
    // (caller), which outlives every CPU's use of it.
    unsafe { lidt(&pointer) };
}

// ----------------------------------------------------------------------------
// The stubs: one per vector, each 16-byte aligned, their addresses in
// `X86_TRAP_STUB_TABLE`. AT&T syntax so `$x86_trap_vec` is unambiguously an
// immediate. The `.if` set must stay equal to `pushes_error_code`.
// ----------------------------------------------------------------------------
#[cfg(not(any(fuzzing, test)))]
core::arch::global_asm!(
    ".pushsection .rodata.X86_TRAP_STUB_TABLE, \"a\"",
    ".balign 8",
    ".global X86_TRAP_STUB_TABLE",
    "X86_TRAP_STUB_TABLE:",
    ".popsection",
    ".pushsection .text.x86_trap_stubs, \"ax\"",
    ".set x86_trap_vec, 0",
    ".rept 256",
    ".balign 16",
    "1:",
    ".if (x86_trap_vec == 8) || ((x86_trap_vec >= 10) && (x86_trap_vec <= 14)) || (x86_trap_vec == 17) || (x86_trap_vec == 21) || (x86_trap_vec == 29) || (x86_trap_vec == 30)",
    ".else",
    "pushq $0",
    ".endif",
    "pushq $x86_trap_vec",
    "jmp x86_trap_common",
    ".pushsection .rodata.X86_TRAP_STUB_TABLE, \"a\"",
    ".quad 1b",
    ".popsection",
    ".set x86_trap_vec, x86_trap_vec + 1",
    ".endr",
    ".popsection",
    options(att_syntax),
);

// ----------------------------------------------------------------------------
// Common entry and exit. Stack at entry, low to high: vector, error code,
// RIP, CS, RFLAGS, RSP, SS. After the pushes RSP points at a complete
// SavedContext (r15 first), which is the argument to x86_trap.
// ----------------------------------------------------------------------------
#[cfg(not(any(fuzzing, test)))]
core::arch::global_asm!(
    ".global x86_trap_common",
    "x86_trap_common:",
    "push rax",
    "push rbx",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push rbp",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // AC from the interrupted context would disable SMAP in the handler
    // (ADR-040 § 2). `clac` is #UD without SMAP, hence the flag.
    "cmp byte ptr [rip + X86_SMAP_ACTIVE], 0",
    "je .Lx86_trap_no_clac",
    "clac",
    ".Lx86_trap_no_clac:",
    "mov rdi, rsp",                 // ctx: *mut SavedContext
    "mov rsi, [rsp + 120]",         // vector
    "mov rdx, [rsp + 128]",         // error code
    "cld",
    "call x86_trap",
    "mov rsp, rax",                 // the context to resume
    ".global x86_trap_restore",
    "x86_trap_restore:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rax",
    "add rsp, 16",                  // vector and error code
    "iretq",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupt_gate_round_trips_its_handler_and_ist() {
        let h = 0xFFFF_FFFF_8001_2345_u64;
        let g = IdtGate::interrupt(h, 0x08, 2);
        assert_eq!(g.handler(), h);
        assert_eq!(g.ist(), 2);
        assert!(g.is_present());
        assert_eq!(g.selector, 0x08);
        assert_eq!(g.type_attr, 0x8E);
        assert_eq!(g.reserved, 0);
        assert!(!IdtGate::MISSING.is_present());
    }

    #[test]
    fn ist_is_three_bits() {
        assert_eq!(IdtGate::interrupt(0, 0x08, 7).ist(), 7);
        assert_eq!(IdtGate::interrupt(0, 0x08, 9).ist(), 1);
    }

    /// The architectural error-code vectors, written out a second way.
    #[test]
    fn error_code_vectors_are_the_architectural_set() {
        let expected = [8u8, 10, 11, 12, 13, 14, 17, 21, 29, 30];
        for v in 0..=255u8 {
            assert_eq!(pushes_error_code(v), expected.contains(&v), "vector {}", v);
        }
    }
}
