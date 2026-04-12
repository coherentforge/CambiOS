// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Interrupt routing system
//!
//! Maps hardware IRQs to driver tasks and delivers interrupt context
//! via IPC messages. Verification-ready with deterministic routing.

use crate::scheduler::TaskId;
use core::fmt;

/// Hardware interrupt source (IRQ number)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IrqNumber(pub u8);

impl IrqNumber {
    /// Timer interrupt (usually IRQ 0 on PIT, or vector 32+ on APIC)
    pub const TIMER: Self = IrqNumber(0);
    /// Keyboard interrupt
    pub const KEYBOARD: Self = IrqNumber(1);
    /// Serial port 1
    pub const SERIAL1: Self = IrqNumber(4);
    /// Network card (typically)
    pub const NETWORK: Self = IrqNumber(11);
    /// Disk/storage device
    pub const DISK: Self = IrqNumber(14);

    /// Check if IRQ is valid for x86-64 legacy PIC
    pub fn is_valid_legacy_pic(self) -> bool {
        self.0 < 16
    }

    /// Check if IRQ number is valid for APIC (up to 224 vectors)
    pub fn is_valid_apic(self) -> bool {
        self.0 < 224
    }
}

impl fmt::Display for IrqNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IRQ {}", self.0)
    }
}

/// Interrupt routing entry: maps IRQ → driver task + priority
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptRoute {
    /// Which IRQ this route handles
    pub irq: IrqNumber,
    /// Which task (driver) handles this IRQ
    pub handler_task: TaskId,
    /// Priority for this IRQ (0-255)
    pub priority: u8,
    /// Enabled/disabled
    pub enabled: bool,
}

impl InterruptRoute {
    /// Create a new interrupt route
    pub const fn new(irq: IrqNumber, handler_task: TaskId, priority: u8) -> Self {
        InterruptRoute {
            irq,
            handler_task,
            priority,
            enabled: true,
        }
    }

    /// Disable this route
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enable this route
    pub fn enable(&mut self) {
        self.enabled = true;
    }
}

/// Interrupt routing table (maps IRQs to drivers)
///
/// Supports up to 224 APIC vectors (exceeds legacy PIC's 16 IRQs).
/// Designed for fixed-size verification and deterministic lookup.
pub struct InterruptRoutingTable {
    routes: [Option<InterruptRoute>; 224],
    entry_count: usize,
}

impl Default for InterruptRoutingTable {
    fn default() -> Self { Self::new() }
}

impl InterruptRoutingTable {
    /// Create an empty routing table
    pub const fn new() -> Self {
        InterruptRoutingTable {
            routes: [None; 224],
            entry_count: 0,
        }
    }

    /// Register interrupt handler
    ///
    /// Maps an IRQ to a driver task. Returns Err if IRQ already routed.
    pub fn register(&mut self, irq: IrqNumber, handler_task: TaskId, priority: u8) -> Result<(), InterruptRoutingError> {
        if irq.0 >= 224 {
            return Err(InterruptRoutingError::InvalidIrq);
        }

        if self.routes[irq.0 as usize].is_some() {
            return Err(InterruptRoutingError::IrqAlreadyRegistered);
        }

        self.routes[irq.0 as usize] = Some(InterruptRoute::new(irq, handler_task, priority));
        self.entry_count += 1;
        Ok(())
    }

    /// Unregister interrupt handler
    pub fn unregister(&mut self, irq: IrqNumber) -> Result<(), InterruptRoutingError> {
        if irq.0 >= 224 {
            return Err(InterruptRoutingError::InvalidIrq);
        }

        if self.routes[irq.0 as usize].is_none() {
            return Err(InterruptRoutingError::IrqNotRegistered);
        }

        self.routes[irq.0 as usize] = None;
        self.entry_count = self.entry_count.saturating_sub(1);
        Ok(())
    }

    /// Look up handler for an IRQ
    pub fn lookup(&self, irq: IrqNumber) -> Option<InterruptRoute> {
        if irq.0 < 224 {
            self.routes[irq.0 as usize].filter(|route| route.enabled)
        } else {
            None
        }
    }

    /// Get number of registered routes
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Verify routing table integrity
    pub fn verify_integrity(&self) -> Result<(), &'static str> {
        // Count actual entries
        let mut count = 0;
        for route_opt in self.routes.iter() {
            if route_opt.is_some() {
                count += 1;
            }
        }

        if count != self.entry_count {
            return Err("Routing table entry count mismatch");
        }

        Ok(())
    }
}

/// Interrupt routing errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptRoutingError {
    /// IRQ number out of range
    InvalidIrq,
    /// IRQ already has a handler registered
    IrqAlreadyRegistered,
    /// IRQ has no handler registered
    IrqNotRegistered,
    /// Routing table is full
    RoutingTableFull,
}

impl fmt::Display for InterruptRoutingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InterruptRoutingError::InvalidIrq => write!(f, "Invalid IRQ number"),
            InterruptRoutingError::IrqAlreadyRegistered => write!(f, "IRQ already registered"),
            InterruptRoutingError::IrqNotRegistered => write!(f, "IRQ not registered"),
            InterruptRoutingError::RoutingTableFull => write!(f, "Routing table full"),
        }
    }
}

/// Interrupt context delivered to driver via IPC
///
/// Contains all information a driver needs to handle an interrupt.
#[derive(Debug, Clone, Copy)]
pub struct InterruptContext {
    /// Which IRQ fired
    pub irq: IrqNumber,
    /// System timestamp when interrupt fired (in ticks)
    pub timestamp_ticks: u64,
    /// CPU that received the interrupt
    pub cpu_id: u32,
    /// Optional error code (for exceptions)
    pub error_code: u64,
}

impl InterruptContext {
    /// Create interrupt context for an IRQ
    pub const fn new(irq: IrqNumber, timestamp_ticks: u64, cpu_id: u32) -> Self {
        InterruptContext {
            irq,
            timestamp_ticks,
            cpu_id,
            error_code: 0,
        }
    }

    /// Create with error code (for exceptions)
    pub const fn with_error_code(irq: IrqNumber, timestamp_ticks: u64, cpu_id: u32, error_code: u64) -> Self {
        InterruptContext {
            irq,
            timestamp_ticks,
            cpu_id,
            error_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irq_validity() {
        assert!(IrqNumber::TIMER.is_valid_legacy_pic());
        assert!(IrqNumber(32).is_valid_apic());
        assert!(!IrqNumber(255).is_valid_apic());
    }

    #[test]
    fn test_routing_table_register() {
        let mut table = InterruptRoutingTable::new();
        let irq = IrqNumber::TIMER;
        let task_id = TaskId(1);

        assert!(table.register(irq, task_id, 128).is_ok());
        assert!(table.lookup(irq).is_some());
        assert_eq!(table.entry_count(), 1);
    }

    #[test]
    fn test_routing_table_duplicate() {
        let mut table = InterruptRoutingTable::new();
        let irq = IrqNumber::TIMER;
        let task_id = TaskId(1);

        assert!(table.register(irq, task_id, 128).is_ok());
        assert_eq!(table.register(irq, task_id, 128), Err(InterruptRoutingError::IrqAlreadyRegistered));
    }

    #[test]
    fn test_routing_table_unregister() {
        let mut table = InterruptRoutingTable::new();
        let irq = IrqNumber::TIMER;
        let task_id = TaskId(1);

        table.register(irq, task_id, 128).unwrap();
        assert_eq!(table.entry_count(), 1);

        table.unregister(irq).unwrap();
        assert_eq!(table.entry_count(), 0);
    }
}
