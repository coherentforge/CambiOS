# ArcOS Microkernel

A verification-ready microkernel OS developed in Rust for x86-64 architecture with modular, extensible design for future formal verification and userspace driver integration.

## Architecture Overview

### Microkernel Model

ArcOS follows the **microkernel paradigm**, where:

- **Bootloader** (`arcos_bootloader`): Minimal stage initializing hardware and loading the microkernel
- **Microkernel** (`arcos_microkernel`): Minimal core providing:
  - Process/task management and scheduling
  - Inter-Process Communication (IPC) via message passing
  - Capability-based security model
  - Interrupt handling and exception routing
- **Userspace Services**: Memory management, filesystem, device drivers all run as independent processes

### Core Modules

- **`io`**: Serial communication and output abstractions
- **`memory`**: Memory initialization and state tracking
- **`interrupts`**: Exception handling with verification-ready contracts
- **`platform`**: Hardware capability detection and abstraction
- **`ipc`**: Message-passing IPC with capability-based access control

### Design Principles

1. **Minimal Trusted Computing Base (TCB)**: Only microkernel runs in privileged mode
2. **Message-Based Communication**: All service interaction through IPC
3. **Capability Security**: Fine-grained access control via capabilities
4. **Modularity**: Each component isolated with clear interfaces
5. **Verification-Ready**: Code structured for formal verification integration
6. **Separation of Concerns**: Hardware specifics abstracted from core logic

## Building the Project

### Prerequisites

- Rust 1.83+ with nightly toolchain
- x86_64-unknown-none target (`rustup target add x86_64-unknown-none`)
- QEMU (optional, for testing)

### Build Commands

```bash
# Build both bootloader and microkernel
cargo build --target x86_64-unknown-none --release

# Build specific binary
cargo build --bin arcos_bootloader --target x86_64-unknown-none --release
cargo build --bin arcos_microkernel --target x86_64-unknown-none --release
```

## Binary Artifacts

```
target/x86_64-unknown-none/release/
├── arcos_bootloader    # 64K - Bootloader binary
├── arcos_microkernel   # 9.3K - Microkernel core
└── ...
```

## Project Structure

```
src/
├── lib.rs                   # Core library (microkernel + shared modules)
├── bootloader/
│   ├── main.rs             # Bootloader entry point
│   ├── boot_constants.rs   # Boot-stage constants
│   └── boot_loader.rs      # Boot implementation details
├── microkernel/
│   └── main.rs             # Microkernel main and event loop
├── ipc/
│   └── mod.rs              # Message-passing IPC primitives
├── io/
│   └── mod.rs              # Serial I/O, output abstractions
├── memory/
│   └── mod.rs              # Memory management, config, state
├── interrupts/
│   └── mod.rs              # IDT, exception handlers, routing
└── platform/
    └── mod.rs              # Hardware detection, capabilities

.cargo/
└── config.toml             # Target configuration and linker settings

linker.ld                    # x86-64 bootloader linker script
```

## Microkernel Boot Sequence

1. **Bootloader Initialization**
   - CPU, memory, interrupts initialized
   - Platform capabilities detected
   - Bootloader verifies requirements met

2. **Microkernel Loading**
   - Microkernel located and verified
   - Loaded into designated memory region
   - Boot structures prepared

3. **Microkernel Transfer**
   - Control transferred from bootloader to microkernel
   - Microkernel takes full system control
   - Scheduler and IPC initialized

4. **Microkernel Event Loop**
   - Process scheduling
   - IPC message handling
   - Exception routing to appropriate handler

## IPC Message Model

ArcOS uses a capability-based IPC system:

```rust
pub struct Message {
    from: EndpointId,
    to: EndpointId,
    priority: Priority,
    payload: [u8; 256],
    payload_len: usize,
}
```

### Key Features

- **Fixed-size messages**: 256 bytes for verification predictability
- **Capability-based access**: `CapabilityRights` controls send/receive/delegate
- **Priority levels**: Critical, High, Normal, Low
- **Error handling**: Comprehensive error types for verification

## Verification Strategy

### Current State

The codebase is designed for formal verification:

- **Trait-based abstractions**: Enable property-based verification
- **Explicit state tracking**: Enum-based states for analysis
- **Clear error contracts**: Result types for all fallible operations
- **Documented invariants**: Pre/post-conditions annotated

### Future Integration

```rust
// All verification-critical modules export verification traits:
pub trait PlatformVerifiable {
    fn verify_state(&self) -> Result<(), &'static str>;
    fn check_invariants(&self) -> bool;
}

pub trait MessageQueue {
    fn send(&mut self, msg: Message) -> Result<(), IpcError>;
    fn receive(&mut self) -> Result<Option<Message>, IpcError>;
}
```

## Limitations & Future Work

### Current

- Bootloader → Microkernel transfer not yet implemented
- Placeholder implementations for scheduler and IPC queues
- No userspace driver support yet
- Minimal error recovery

### Roadmap

1. [ ] Bootloader → Microkernel handoff protocol
2. [ ] Process/task creation and lifecycle
3. [ ] IPC message queue implementation
4. [ ] Capability manager
5. [ ] Userspace runtime support
6. [ ] Device driver framework
7. [ ] Formal verification integration
8. [ ] Unit test framework with mock IPC
9. [ ] Memory protection units (MMU) configuration

## Development Guidelines

### Adding New Features

1. Define trait interfaces for verification
2. Document assumptions and contracts
3. Implement core logic
4. Provide at least one verification method
5. Add module to `lib.rs` exports and initialization

### Code Principles

- Use `no_std` exclusively
- Avoid unwrap() without safety justification
- Annotate all unsafe code with safety comments
- Document invariants and assumptions
- Keep platform-specific code in `platform/` module
- Never assume kernel state transitions

## Running with QEMU

```bash
# Boot the system
qemu-system-x86_64 -drive format=raw,file=target/x86_64-unknown-none/release/arcos_bootloader

# With serial output monitoring
qemu-system-x86_64 -drive format=raw,file=target/x86_64-unknown-none/release/arcos_bootloader -serial mon:stdio
```

## References

- [Microkernel Architecture](https://en.wikipedia.org/wiki/Microkernel)
- [x86-64 System V ABI](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [OSDev Wiki - Microkernel](https://wiki.osdev.org/Microkernel)
- [Rust on Baremetal](https://github.com/rust-osdev)
- [seL4 Microkernel](https://sel4.systems/) - Verification reference
