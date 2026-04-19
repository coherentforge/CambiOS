// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! ELF binary format parser for x86-64
//!
//! Minimal ELF parser designed for verification-ready process loading.
//! Supports x86-64 little-endian ELF binaries (64-bit).

use core::mem;

/// ELF magic number
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// ELF header constants
const ELF_CLASS_64BIT: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;

/// Expected ELF e_machine for the current target architecture.
#[cfg(target_arch = "x86_64")]
const ELF_MACHINE_EXPECTED: u16 = 0x3E; // EM_X86_64
#[cfg(target_arch = "aarch64")]
const ELF_MACHINE_EXPECTED: u16 = 0xB7; // EM_AARCH64
#[cfg(target_arch = "riscv64")]
const ELF_MACHINE_EXPECTED: u16 = 0xF3; // EM_RISCV
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
)))]
const ELF_MACHINE_EXPECTED: u16 = 0x00; // unknown — will reject all ELFs

/// Public re-export for `build_boot_elf()` to use.
pub const ELF_MACHINE_CURRENT: u16 = ELF_MACHINE_EXPECTED;

/// Errors that can occur during ELF parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    InvalidMagic,
    InvalidClass,
    InvalidEndianness,
    InvalidMachine,
    InvalidType,
    InvalidProgramHeaderOffset,
    InvalidProgramHeaderEntrySize,
    InvalidPhdrCount,
    NoLoadableSegments,
    SegmentOutOfBounds,
    EntryPointInvalid,
}

impl core::fmt::Display for ElfError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid ELF magic number"),
            Self::InvalidClass => write!(f, "Not a 64-bit ELF"),
            Self::InvalidEndianness => write!(f, "Not little-endian ELF"),
            Self::InvalidMachine => write!(f, "Not x86-64 ELF"),
            Self::InvalidType => write!(f, "Not executable ELF"),
            Self::InvalidProgramHeaderOffset => write!(f, "Invalid program header offset"),
            Self::InvalidProgramHeaderEntrySize => write!(f, "Invalid program header entry size"),
            Self::InvalidPhdrCount => write!(f, "Invalid program header count"),
            Self::NoLoadableSegments => write!(f, "No loadable segments in ELF"),
            Self::SegmentOutOfBounds => write!(f, "Segment extends beyond binary"),
            Self::EntryPointInvalid => write!(f, "Invalid entry point address"),
        }
    }
}

/// ELF64 header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub magic: [u8; 4],          // 0x7f, 'E', 'L', 'F'
    pub class: u8,               // 1=32-bit, 2=64-bit
    pub data: u8,                // 1=little-endian, 2=big-endian
    pub version: u8,             // Always 1
    pub os_abi: u8,
    pub abi_version: u8,
    pub _padding: [u8; 7],
    pub e_type: u16,             // 1=relocatable, 2=executable, etc
    pub e_machine: u16,          // 0x3E = x86-64
    pub e_version: u32,
    pub e_entry: u64,            // Entry point address
    pub e_phoff: u64,            // Program header offset
    pub e_shoff: u64,            // Section header offset (ignored)
    pub e_flags: u32,
    pub e_ehsize: u16,           // ELF header size
    pub e_phentsize: u16,        // Program header entry size
    pub e_phnum: u16,            // Number of program headers
    pub e_shentsize: u16,        // Section header entry size (ignored)
    pub e_shnum: u16,            // Number of section headers (ignored)
    pub e_shstrndx: u16,         // Section header string table index (ignored)
}

/// ELF64 program header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,             // Segment type
    pub p_flags: u32,            // Segment flags
    pub p_offset: u64,           // Offset in file
    pub p_vaddr: u64,            // Virtual address
    pub p_paddr: u64,            // Physical address
    pub p_filesz: u64,           // Size in file
    pub p_memsz: u64,            // Size in memory
    pub p_align: u64,            // Alignment
}

/// Program header segment types
pub mod phdr_type {
    pub const PT_NULL: u32 = 0;
    pub const PT_LOAD: u32 = 1;
    pub const PT_DYNAMIC: u32 = 2;
    pub const PT_INTERP: u32 = 3;
    pub const PT_NOTE: u32 = 4;
    pub const PT_SHLIB: u32 = 5;
    pub const PT_PHDR: u32 = 6;
    pub const PT_TLS: u32 = 7;
}

/// Program header flags
pub mod phdr_flags {
    pub const PF_X: u32 = 1;     // Execute
    pub const PF_W: u32 = 2;     // Write
    pub const PF_R: u32 = 4;     // Read
}

/// Parsed ELF binary metadata
#[derive(Debug, Clone, Copy)]
pub struct ElfBinary {
    pub entry_point: u64,
    pub load_base: u64,
    pub load_size: u64,
    pub num_segments: u16,
}

/// Load information for a single segment
#[derive(Debug, Clone, Copy)]
pub struct SegmentLoad {
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub file_offset: u64,
    pub writable: bool,
    pub executable: bool,
}

/// Parse and validate ELF binary header
pub fn parse_header(binary: &[u8]) -> Result<Elf64Header, ElfError> {
    if binary.len() < mem::size_of::<Elf64Header>() {
        return Err(ElfError::InvalidMagic);
    }

    // SAFETY: We verified binary.len() >= size_of::<Elf64Header>(). Using
    // read_unaligned because binary.as_ptr() may not be 8-byte aligned (the
    // slice could start at any byte offset). Elf64Header has u64 fields that
    // would require 8-byte alignment for a direct dereference.
    let header = unsafe {
        core::ptr::read_unaligned(binary.as_ptr() as *const Elf64Header)
    };

    // Validate ELF magic
    if header.magic != *ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }

    // Check 64-bit
    if header.class != ELF_CLASS_64BIT {
        return Err(ElfError::InvalidClass);
    }

    // Check little-endian
    if header.data != ELF_DATA_LITTLE_ENDIAN {
        return Err(ElfError::InvalidEndianness);
    }

    // Check machine type matches current architecture
    if header.e_machine != ELF_MACHINE_EXPECTED {
        return Err(ElfError::InvalidMachine);
    }

    // Check executable
    if header.e_type != ELF_TYPE_EXECUTABLE {
        return Err(ElfError::InvalidType);
    }

    // Validate entry point
    if header.e_entry == 0 {
        return Err(ElfError::EntryPointInvalid);
    }

    // Validate program headers
    if header.e_phoff == 0 || header.e_phentsize == 0 {
        return Err(ElfError::InvalidProgramHeaderOffset);
    }

    if header.e_phentsize as usize != mem::size_of::<Elf64ProgramHeader>() {
        return Err(ElfError::InvalidProgramHeaderEntrySize);
    }

    Ok(header)
}

/// Get program header at given index
pub fn get_program_header(
    binary: &[u8],
    header: &Elf64Header,
    index: usize,
) -> Result<Elf64ProgramHeader, ElfError> {
    if index >= header.e_phnum as usize {
        return Err(ElfError::InvalidPhdrCount);
    }

    let phdr_offset = header.e_phoff as usize + (index * header.e_phentsize as usize);
    let phdr_end = phdr_offset + mem::size_of::<Elf64ProgramHeader>();

    if phdr_end > binary.len() {
        return Err(ElfError::InvalidProgramHeaderOffset);
    }

    // SAFETY: phdr_offset is within binary bounds (checked above).
    let phdr_ptr = unsafe { binary.as_ptr().add(phdr_offset) } as *const Elf64ProgramHeader;
    // SAFETY: phdr_offset..phdr_end is within binary bounds. Using read_unaligned
    // because the program header may not be naturally aligned in the binary slice.
    let phdr = unsafe { core::ptr::read_unaligned(phdr_ptr) };

    Ok(phdr)
}

/// Analyze ELF binary and extract load information
pub fn analyze_binary(binary: &[u8]) -> Result<ElfBinary, ElfError> {
    let header = parse_header(binary)?;

    let mut has_loadable = false;
    let mut load_base = u64::MAX;
    let mut load_end = 0u64;

    // Find extent of loadable segments
    for i in 0..header.e_phnum as usize {
        let phdr = get_program_header(binary, &header, i)?;

        if phdr.p_type == phdr_type::PT_LOAD {
            has_loadable = true;

            // Track minimum and maximum addresses
            if phdr.p_vaddr < load_base {
                load_base = phdr.p_vaddr;
            }

            let seg_end = phdr.p_vaddr + phdr.p_memsz;
            if seg_end > load_end {
                load_end = seg_end;
            }

            // Verify segment doesn't exceed binary
            if phdr.p_offset + phdr.p_filesz > binary.len() as u64 {
                return Err(ElfError::SegmentOutOfBounds);
            }
        }
    }

    if !has_loadable {
        return Err(ElfError::NoLoadableSegments);
    }

    Ok(ElfBinary {
        entry_point: header.e_entry,
        load_base,
        load_size: load_end - load_base,
        num_segments: header.e_phnum,
    })
}

/// Maximum number of LOAD segments supported
pub const MAX_LOAD_SEGMENTS: usize = 16;

/// Collect all PT_LOAD segments from an ELF binary.
///
/// Returns the segments and the count. Validates each segment's file range.
pub fn collect_load_segments(
    binary: &[u8],
) -> Result<([SegmentLoad; MAX_LOAD_SEGMENTS], usize), ElfError> {
    let header = parse_header(binary)?;
    let mut segments = [SegmentLoad {
        vaddr: 0,
        filesz: 0,
        memsz: 0,
        file_offset: 0,
        writable: false,
        executable: false,
    }; MAX_LOAD_SEGMENTS];
    let mut count = 0;

    for i in 0..header.e_phnum as usize {
        let phdr = get_program_header(binary, &header, i)?;

        if phdr.p_type == phdr_type::PT_LOAD {
            if count >= MAX_LOAD_SEGMENTS {
                return Err(ElfError::InvalidPhdrCount);
            }

            // Validate segment file range
            if phdr.p_offset + phdr.p_filesz > binary.len() as u64 {
                return Err(ElfError::SegmentOutOfBounds);
            }

            segments[count] = SegmentLoad {
                vaddr: phdr.p_vaddr,
                filesz: phdr.p_filesz,
                memsz: phdr.p_memsz,
                file_offset: phdr.p_offset,
                writable: (phdr.p_flags & phdr_flags::PF_W) != 0,
                executable: (phdr.p_flags & phdr_flags::PF_X) != 0,
            };
            count += 1;
        }
    }

    if count == 0 {
        return Err(ElfError::NoLoadableSegments);
    }

    Ok((segments, count))
}

/// Verify ELF integrity
pub fn verify_binary(binary: &[u8]) -> Result<(), ElfError> {
    let _header = parse_header(binary)?;
    let _analysis = analyze_binary(binary)?;
    Ok(())
}
