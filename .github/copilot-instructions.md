# CambiOS Microkernel Development

## Overview
This project develops a verification-ready microkernel OS for x86-64 using Rust. It uses a **microkernel architecture** where core kernel functionality is minimal and drivers/services run in userspace with message-passing IPC.

## Architecture
- **Bootloader** (`cambios_bootloader`): Minimal, initializes hardware and loads microkernel
- **Microkernel Core** (`cambios_microkernel`): Process scheduler, IPC dispatcher, capability manager
- **Userspace Layer**: Drivers, services, and applications (future)

## Key Components
- **IPC System**: Capability-based message passing for inter-process communication
- **Memory Management**: Process isolation, paging (in development)
- **Interrupt Handling**: Exception routing to appropriate handlers
- **Platform Abstraction**: Hardware capability detection

## Build Commands
```bash
# Build both bootloader and microkernel
cargo build --target x86_64-unknown-none --release

# Build specific component
cargo build --bin cambios_bootloader --target x86_64-unknown-none --release
cargo build --bin cambios_microkernel --target x86_64-unknown-none --release
```

## Binary Outputs
- `target/x86_64-unknown-none/release/cambios_bootloader` (64K)
- `target/x86_64-unknown-none/release/cambios_microkernel` (9.3K)

## Running with QEMU
```bash
qemu-system-x86_64 -drive format=raw,file=target/x86_64-unknown-none/release/cambios_bootloader -serial mon:stdio
```

## Verification Strategy
- Trait-based abstractions for property-based verification
- Explicit state tracking (enums)
- Error handling via Result types
- Clear invariants and contracts

## Development Guidelines
All code must:
- Use `no_std` exclusively
- Maintain strict separation between bootloader and microkernel
- Document assumptions in trait methods
- Provide verification contracts for critical functions
- Keep platform-specific code in `platform/` module
