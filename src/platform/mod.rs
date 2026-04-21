// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Platform abstraction layer
//!
//! Provides hardware-specific capabilities. Abstract enough for verification
//! while concrete enough for implementation.

#[cfg(target_arch = "x86_64")]
use x86_64::registers::control::{Cr4, Cr4Flags};

/// Platform information and capabilities
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub vendor: &'static str,
    pub architecture: &'static str,
    pub features: PlatformFeatures,
}

/// Available CPU features for the platform
#[derive(Debug, Clone, Copy)]
pub struct PlatformFeatures {
    #[cfg(target_arch = "x86_64")]
    pub pae: bool,         // Physical Address Extension
    #[cfg(target_arch = "x86_64")]
    pub pse: bool,         // Page Size Extension
    #[cfg(target_arch = "x86_64")]
    pub tsc: bool,         // Time Stamp Counter
    #[cfg(target_arch = "x86_64")]
    pub msr: bool,         // Model Specific Registers
    #[cfg(target_arch = "x86_64")]
    pub apic: bool,        // APIC available
    #[cfg(target_arch = "aarch64")]
    pub neon: bool,        // Advanced SIMD (NEON)
    #[cfg(target_arch = "aarch64")]
    pub gicv3: bool,       // GICv3 interrupt controller
    #[cfg(target_arch = "aarch64")]
    pub generic_timer: bool, // ARM Generic Timer
    // RISC-V feature detection is refined in Phase R-4 (reading misa CSR +
    // probing SBI extensions). Phase R-1 ships a minimal stub so the struct
    // is inhabitable on riscv64.
    #[cfg(target_arch = "riscv64")]
    pub rv64gc: bool,      // Base ISA (RV64G + C compressed) — required
    #[cfg(target_arch = "riscv64")]
    pub supervisor: bool,  // S-mode supported (always true — we run in it)
    #[cfg(target_arch = "riscv64")]
    pub sbi: bool,         // Supervisor Binary Interface (OpenSBI provides)
}

impl PlatformInfo {
    /// Detect current platform capabilities
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            PlatformInfo {
                vendor: "x86-64",
                architecture: "x86_64",
                features: PlatformFeatures {
                    pae: true,
                    pse: true,
                    tsc: true,
                    msr: true,
                    apic: true,
                },
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            let (implementer, part_number) = Self::read_midr();
            let vendor = match implementer {
                0x41 => "ARM",
                0x42 => "Broadcom",
                0x43 => "Cavium",
                0x44 => "DEC",
                0x4E => "NVIDIA",
                0x50 => "APM",
                0x51 => "Qualcomm",
                0x56 => "Marvell",
                0x61 => "Apple",
                0x69 => "Intel",
                _    => "Unknown",
            };
            let _ = part_number; // Available for future model identification
            PlatformInfo {
                vendor,
                architecture: "aarch64",
                features: PlatformFeatures {
                    // ARMv8-A mandatory features
                    neon: true,
                    // Assumed true — CambiOS requires GICv3 (see CLAUDE.md)
                    gicv3: true,
                    // ARM Generic Timer is mandatory in ARMv8-A
                    generic_timer: true,
                },
            }
        }
        #[cfg(target_arch = "riscv64")]
        {
            // Phase R-1 stub: feature probing (misa CSR read, SBI
            // extension probes) lands in Phase R-4. Per ADR-013 we
            // report generic RV64GC + SBI; vendor-identifying CSRs
            // (mvendorid/marchid/mimpid) are M-mode-only on most
            // boards and exposed only via DTB — wire that in R-4.
            PlatformInfo {
                vendor: "RISC-V",
                architecture: "riscv64gc",
                features: PlatformFeatures {
                    rv64gc: true,
                    supervisor: true,
                    sbi: true,
                },
            }
        }
    }

    /// Read MIDR_EL1 (Main ID Register) on AArch64.
    ///
    /// Returns (implementer, part_number) for CPU identification.
    #[cfg(target_arch = "aarch64")]
    fn read_midr() -> (u8, u16) {
        let midr: u64;
        // SAFETY: MIDR_EL1 is readable at EL1. It is a read-only register
        // that identifies the CPU implementation.
        unsafe {
            core::arch::asm!(
                "mrs {0}, midr_el1",
                out(reg) midr,
                options(nostack, nomem),
            );
        }
        let implementer = ((midr >> 24) & 0xFF) as u8;
        let part_number = ((midr >> 4) & 0xFFF) as u16;
        (implementer, part_number)
    }

    /// Verify required features are available
    pub fn verify_requirements(&self) -> Result<(), &'static str> {
        #[cfg(target_arch = "x86_64")]
        if !self.features.pae {
            return Err("PAE required");
        }
        #[cfg(target_arch = "aarch64")]
        if !self.features.gicv3 {
            return Err("GICv3 required");
        }
        Ok(())
    }
}

/// CPU feature flags with verification contracts
pub fn enable_features() -> Result<(), &'static str> {
    #[cfg(target_arch = "x86_64")]
    {
        // Enable Physical Address Extension (PAE)
        // SAFETY: CR4 read and write are valid at ring 0. We only insert the PAE flag
        // (which is required for long mode and already enabled). This is idempotent.
        unsafe {
            let mut cr4 = Cr4::read();
            cr4.insert(Cr4Flags::PHYSICAL_ADDRESS_EXTENSION);
            Cr4::write(cr4);
        }
    }
    Ok(())
}

/// Get CPU vendor string
pub fn cpu_vendor() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    { "x86-64" }
    #[cfg(target_arch = "aarch64")]
    { PlatformInfo::detect().vendor }
    #[cfg(target_arch = "riscv64")]
    { "RISC-V" }
}

/// Get CPU model string
pub fn cpu_model() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    { "Generic x86-64" }
    #[cfg(target_arch = "aarch64")]
    { "ARMv8-A" }
    #[cfg(target_arch = "riscv64")]
    { "Generic RV64GC" }
}

/// Interface for platform verification
pub trait PlatformVerifiable {
    fn verify_state(&self) -> Result<(), &'static str>;
    fn check_invariants(&self) -> bool;
}

impl PlatformVerifiable for PlatformInfo {
    fn verify_state(&self) -> Result<(), &'static str> {
        self.verify_requirements()
    }

    fn check_invariants(&self) -> bool {
        true
    }
}

/// CPU Power States (C-States) - Sleep States
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PowerState {
    /// C0: Running (normal execution)
    C0,
    /// C1: Halt (clock stopped, wakes on interrupt)
    C1,
    /// C2: Wait for Break (deeper sleep, requires MSR support)
    C2,
    /// C3: Sleep (deepest, cache flushed, requires MWAIT instruction)
    C3,
}

/// CPU Performance States (P-States) - Frequency Scaling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PerformanceState {
    /// Frequency in MHz
    pub frequency_mhz: u32,
    /// Voltage in mV (approximate)
    pub voltage_mv: u32,
}

impl PerformanceState {
    /// Highest performance state (max frequency)
    pub const MAXIMUM: Self = PerformanceState {
        frequency_mhz: 3500,
        voltage_mv: 1200,
    };

    /// Balanced performance state (typical workload)
    pub const BALANCED: Self = PerformanceState {
        frequency_mhz: 2400,
        voltage_mv: 1050,
    };

    /// Low power state (light workload or thermal limit)
    pub const LOW_POWER: Self = PerformanceState {
        frequency_mhz: 1600,
        voltage_mv: 900,
    };

    /// Minimum viable state (idle with minimal power)
    pub const MINIMUM: Self = PerformanceState {
        frequency_mhz: 800,
        voltage_mv: 750,
    };
}

/// Power management interface for thermal efficiency
pub struct PowerManager {
    current_state: PowerState,
    current_pstate: PerformanceState,
    thermal_limit_reached: bool,
}

impl Default for PowerManager {
    fn default() -> Self { Self::new() }
}

impl PowerManager {
    /// Create a new power manager
    pub const fn new() -> Self {
        PowerManager {
            current_state: PowerState::C0,
            current_pstate: PerformanceState::MAXIMUM,
            thermal_limit_reached: false,
        }
    }

    /// Set CPU performance state (frequency scaling)
    ///
    /// Requires EIST (Enhanced Intel SpeedStep) capability.
    /// Uses MSR 0x199 to set P-state on Intel CPUs.
    pub fn set_performance_state(&mut self, pstate: PerformanceState) -> Result<(), &'static str> {
        if !self.check_cpuid_eist() {
            return Err("EIST (frequency scaling) not supported");
        }

        // MSR_IA32_PERF_STATUS (0x198) - read current state
        // MSR_IA32_PERF_CTL (0x199) - write new state
        // Format: bits [15:8] = frequency ratio
        let _ratio = (pstate.frequency_mhz as u64) / 100;
        // let _msr_value = (_ratio & 0xFF) << 8;

        // In real implementation, use x86_64::registers::msr to write:
        //   unsafe {
        //       let msr = x86_64::registers::msr::Msr::new(0x199);
        //       msr.write(((_ratio & 0xFF) << 8) | 0);
        //   }
        // For verification purposes, just track the state change
        self.current_pstate = pstate;

        Ok(())
    }

    /// Enter idle power state
    ///
    /// Halts CPU to save power. Varies by state:
    /// - C1: HLT instruction (minimal power saving)
    /// - C2+: MWAIT instruction (deeper sleep, requires support)
    #[allow(unused_unsafe)]
    pub fn enter_idle(&self, state: PowerState) {
        match state {
            PowerState::C0 => {
                // Not idle
            }
            PowerState::C1 | PowerState::C2 | PowerState::C3 => {
                #[cfg(target_arch = "x86_64")]
                // SAFETY: HLT is safe at ring 0; wakes on next interrupt.
                unsafe { x86_64::instructions::hlt(); }
                #[cfg(target_arch = "aarch64")]
                // SAFETY: WFI is safe at EL1; wakes on next interrupt or event.
                unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
            }
        }
    }

    /// Get current power state
    pub fn current_state(&self) -> PowerState {
        self.current_state
    }

    /// Get current performance state
    pub fn current_pstate(&self) -> PerformanceState {
        self.current_pstate
    }

    /// Handle thermal throttling on high CPU temperature
    ///
    /// When thermal limit reached, step down to lower power states
    /// to reduce heat generation.
    pub fn handle_thermal_alert(&mut self) -> Result<(), &'static str> {
        self.thermal_limit_reached = true;

        // Step down to lower power state
        if self.current_pstate == PerformanceState::MAXIMUM {
            self.set_performance_state(PerformanceState::BALANCED)?;
        } else if self.current_pstate == PerformanceState::BALANCED {
            self.set_performance_state(PerformanceState::LOW_POWER)?;
        } else if self.current_pstate == PerformanceState::LOW_POWER {
            self.set_performance_state(PerformanceState::MINIMUM)?;
        } else if self.current_pstate == PerformanceState::MINIMUM {
            // Already at minimum, just idle
            self.enter_idle(PowerState::C1);
        }
        Ok(())
    }

    /// Check if EIST capability is available
    fn check_cpuid_eist(&self) -> bool {
        // In real implementation, would check CPUID leaf 0x6, ECX bit 0
        // For now, assume available on modern systems
        true
    }
}
