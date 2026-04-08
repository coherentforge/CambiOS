// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Timer tick management for tick-based scheduling
//!
//! Handles timer interrupts and signals scheduling points.
//! Designed for x86-64 with PIT or APIC timer support.

use core::sync::atomic::{AtomicU64, Ordering};
use core::fmt;

/// Global tick counter (incremented by timer ISR)
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Timer tick configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerConfig {
    /// Timer frequency in Hz
    pub frequency_hz: u32,
    /// Tick interval in microseconds
    pub tick_interval_us: u32,
}

impl TimerConfig {
    /// Standard 100 Hz timer (10ms ticks)
    pub const HZ_100: TimerConfig = TimerConfig {
        frequency_hz: 100,
        tick_interval_us: 10_000,
    };

    /// Standard 1000 Hz timer (1ms ticks)
    pub const HZ_1000: TimerConfig = TimerConfig {
        frequency_hz: 1000,
        tick_interval_us: 1_000,
    };

    /// Verify configuration validity
    pub fn verify(&self) -> Result<(), &'static str> {
        if self.frequency_hz == 0 || self.frequency_hz > 100_000 {
            return Err("Frequency must be between 1 and 100,000 Hz");
        }
        if self.tick_interval_us == 0 {
            return Err("Tick interval cannot be zero");
        }
        Ok(())
    }
}

/// Timer interrupt handler state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerState {
    Uninitialized,
    Running,
    Stopped,
}

/// Timer management for scheduling
pub struct Timer {
    config: TimerConfig,
    state: TimerState,
    /// Ticks since timer started
    local_ticks: u64,
}

impl Timer {
    /// Create a new timer with configuration
    pub fn new(config: TimerConfig) -> Result<Self, &'static str> {
        config.verify()?;

        Ok(Timer {
            config,
            state: TimerState::Uninitialized,
            local_ticks: 0,
        })
    }

    /// Initialize the timer (setup hardware)
    pub fn init(&mut self) -> Result<(), &'static str> {
        // In a real implementation, this would:
        // 1. Reprogram PIT or APIC timer
        // 2. Set frequency divisor
        // 3. Enable timer interrupts
        // 4. Verify timer is ticking

        TICK_COUNT.store(0, Ordering::Relaxed);
        self.local_ticks = 0;
        self.state = TimerState::Running;

        Ok(())
    }

    /// Stop the timer
    pub fn stop(&mut self) -> Result<(), &'static str> {
        // In a real implementation, disable timer interrupts
        self.state = TimerState::Stopped;
        Ok(())
    }

    /// Handle a timer interrupt (called by ISR)
    pub fn on_tick(&mut self) {
        if self.state == TimerState::Running {
            TICK_COUNT.fetch_add(1, Ordering::SeqCst);
            self.local_ticks += 1;
        }
    }

    /// Get current global tick count
    pub fn get_ticks() -> u64 {
        TICK_COUNT.load(Ordering::SeqCst)
    }

    /// Get ticks since timer started (local to this timer)
    pub fn local_ticks(&self) -> u64 {
        self.local_ticks
    }

    /// Get timer configuration
    pub fn config(&self) -> TimerConfig {
        self.config
    }

    /// Get current timer state
    pub fn state(&self) -> TimerState {
        self.state
    }

    /// Convert ticks to milliseconds
    pub fn ticks_to_ms(ticks: u64, config: TimerConfig) -> u64 {
        (ticks * config.tick_interval_us as u64) / 1000
    }

    /// Verify timer state integrity
    pub fn verify_integrity(&self) -> Result<(), &'static str> {
        match self.state {
            TimerState::Uninitialized => {
                if self.local_ticks != 0 {
                    return Err("Uninitialized timer should have 0 ticks");
                }
            }
            TimerState::Running => {
                // Running timer can have any tick count
            }
            TimerState::Stopped => {
                // Stopped timer ticks should stabilize
            }
        }

        Ok(())
    }
}

impl fmt::Debug for Timer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Timer")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("local_ticks", &self.local_ticks)
            .field("global_ticks", &Self::get_ticks())
            .finish()
    }
}

/// Timer interrupt handler (to be called by ISR)
pub fn on_timer_interrupt() {
    // Signal to scheduler that a tick occurred
    // In real implementation, would:
    // 1. Increment global tick counter
    // 2. Check if current task's time slice expired
    // 3. Request context switch if needed
    // 4. Send EOI to interrupt controller

    TICK_COUNT.fetch_add(1, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_config_creation() {
        let config = TimerConfig::HZ_100;
        assert!(config.verify().is_ok());
    }

    #[test]
    fn test_timer_creation() {
        let timer = Timer::new(TimerConfig::HZ_100);
        assert!(timer.is_ok());
    }

    #[test]
    fn test_timer_initialization() {
        let mut timer = Timer::new(TimerConfig::HZ_100).unwrap();
        assert!(timer.init().is_ok());
        assert_eq!(timer.state(), TimerState::Running);
    }
}

/// Adaptive timer rate selection based on system load
///
/// Reduces scheduler overhead and power consumption on idle systems
/// by lowering tick frequency. Increases frequency under high load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveTickMode {
    /// Idle system: minimal ticking (10 Hz = 100ms slices)
    /// Benefits: 90% fewer timer interrupts = ↓ power, ↓ thermal
    Idle,
    /// Light load: moderate ticking (50 Hz = 20ms slices)
    /// Typical batch workload (device drivers, services)
    Light,
    /// Normal load: standard ticking (100 Hz = 10ms slices)
    /// Default for balanced systems
    Normal,
    /// High load: frequent ticking (250 Hz = 4ms slices)
    /// Real-time or interactive workloads
    High,
}

impl AdaptiveTickMode {
    /// Get appropriate timer frequency for load level
    pub fn frequency_hz(&self) -> u32 {
        match self {
            AdaptiveTickMode::Idle => 10,
            AdaptiveTickMode::Light => 50,
            AdaptiveTickMode::Normal => 100,
            AdaptiveTickMode::High => 250,
        }
    }

    /// Select mode based on number of ready tasks
    ///
    /// Verification: Load calculation is deterministic and bounded.
    pub fn from_task_count(ready_task_count: u32) -> Self {
        match ready_task_count {
            0 => AdaptiveTickMode::Idle,
            1..=2 => AdaptiveTickMode::Light,
            3..=8 => AdaptiveTickMode::Normal,
            _ => AdaptiveTickMode::High,
        }
    }

    /// Select mode based on CPU utilization percentage (0-100)
    pub fn from_utilization(util_percent: u32) -> Self {
        match util_percent {
            0..=10 => AdaptiveTickMode::Idle,
            11..=25 => AdaptiveTickMode::Light,
            26..=75 => AdaptiveTickMode::Normal,
            _ => AdaptiveTickMode::High,
        }
    }

    /// Create appropriate timer config for this mode
    pub fn to_timer_config(&self) -> TimerConfig {
        let freq = self.frequency_hz();
        TimerConfig {
            frequency_hz: freq,
            tick_interval_us: 1_000_000 / freq,
        }
    }
}

#[cfg(test)]
mod adaptive_tests {
    use super::*;

    #[test]
    fn test_adaptive_from_task_count() {
        assert_eq!(AdaptiveTickMode::from_task_count(0), AdaptiveTickMode::Idle);
        assert_eq!(AdaptiveTickMode::from_task_count(1), AdaptiveTickMode::Light);
        assert_eq!(AdaptiveTickMode::from_task_count(5), AdaptiveTickMode::Normal);
        assert_eq!(AdaptiveTickMode::from_task_count(10), AdaptiveTickMode::High);
    }

    #[test]
    fn test_adaptive_from_utilization() {
        assert_eq!(AdaptiveTickMode::from_utilization(5), AdaptiveTickMode::Idle);
        assert_eq!(AdaptiveTickMode::from_utilization(15), AdaptiveTickMode::Light);
        assert_eq!(AdaptiveTickMode::from_utilization(50), AdaptiveTickMode::Normal);
        assert_eq!(AdaptiveTickMode::from_utilization(95), AdaptiveTickMode::High);
    }

    #[test]
    fn test_timer_config_from_mode() {
        let idle_config = AdaptiveTickMode::Idle.to_timer_config();
        assert_eq!(idle_config.frequency_hz, 10);

        let normal_config = AdaptiveTickMode::Normal.to_timer_config();
        assert_eq!(normal_config.frequency_hz, 100);
    }
}
