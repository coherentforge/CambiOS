# ArcOS Developer Experience

## Thesis

ArcOS's strength is architectural: services communicate via IPC, capabilities express permissions, everything is content-addressed and signed. But architecture alone doesn't attract developers. *Experience* does.

**Decentralization should feel like the natural, easy way to build.** The complexity disappears into libraries, and building on ArcOS feels like idiomatic Rust — not a foreign platform.

The values (privacy, sovereignty, auditability) come for free. Developers choose ArcOS because building here is productive. That's how you win.

---

## Principles

1. **Idiomatic Rust.** No custom toolchains, no exotic build systems. `cargo build`, `cargo test`, standard crate ecosystem. ArcOS services are Rust crates that happen to target ArcOS.

2. **Progressive disclosure.** A hello-world service is 15 lines. Capabilities, signing, and ACLs appear when you need them — not before.

3. **Test on host, deploy to kernel.** Unit tests run on macOS/Linux with `cargo test`. No QEMU required until integration testing. This is already how the kernel itself is tested (205 tests on host).

4. **Errors that teach.** When something fails, the developer learns why and what to do about it.

5. **Compose services like functions.** Once IPC is painless, services compose naturally. That's the microkernel payoff.

---

## Layer 1: Syscall Library (`archos-sys`)

The raw syscall interface exists today. What's missing is a thin, safe, well-documented wrapper crate.

**Current (inline assembly, manual buffer management):**
```rust
let mut buf = [0u8; 256];
let result: u64;
unsafe {
    core::arch::asm!(
        "syscall",
        in("rax") 14,  // ObjPut
        in("rdi") buf.as_ptr() as u64,
        in("rsi") buf.len() as u64,
        lateout("rax") result,
        // ...clobbers...
    );
}
```

**With `archos-sys` (safe, typed, documented):**
```rust
use arcos_sys::{obj_put, obj_get, register_endpoint, recv_msg, write_msg};

let hash = obj_put(b"hello world")?;
let data = obj_get(&hash)?;

let ep = register_endpoint(16)?;
let msg = recv_msg(ep)?;
println!("from: {:?}, payload: {:?}", msg.sender_principal, msg.payload);
```

**What this crate provides:**
- Safe wrappers around all 20 syscalls
- Rust `Result` types with meaningful error variants
- `Principal`, `ObjectHash`, `Endpoint` as newtypes (not raw `[u8; 32]`)
- `Message` struct with typed fields
- Doc comments with examples on every function
- `#[cfg(target_arch)]` gated assembly (x86_64 `syscall`, AArch64 `svc`)

**What it does NOT provide:** async, allocation, serialization. It's `no_std`, zero-dep, zero-alloc.

**Prerequisites:** Stable syscall ABI (current 20 syscalls are stable enough to wrap).

---

## Layer 2: Service Framework (`arcos-service`)

A higher-level crate that makes writing IPC services ergonomic. Depends on `arcos-sys` and a `no_std`-compatible allocator (the kernel already provides one via `SYS_ALLOCATE`).

**Goal: a service is a struct with methods.**

```rust
use arcos_service::{Service, IpcHandler, Request, Response};

struct FileService {
    // service state
}

impl IpcHandler for FileService {
    fn handle(&mut self, req: Request) -> Response {
        match req.command() {
            b"GET" => {
                let hash = req.payload_as::<[u8; 32]>();
                match arcos_sys::obj_get(hash) {
                    Ok(data) => Response::ok(&data),
                    Err(e) => Response::err(e),
                }
            }
            b"PUT" => {
                let data = req.payload();
                match arcos_sys::obj_put(data) {
                    Ok(hash) => Response::ok(&hash),
                    Err(e) => Response::err(e),
                }
            }
            _ => Response::unknown_command(),
        }
    }
}

fn main() {
    let mut svc = Service::new(16, FileService::new());
    svc.run(); // register endpoint, recv loop, dispatch
}
```

**What the framework handles:**
- Endpoint registration
- Receive loop
- Request parsing (command byte + payload)
- Response marshaling
- Sender principal extraction (available as `req.sender()`)
- Structured error responses

**What it defers to later layers:**
- Derive macros (Layer 3)
- Serde-based serialization (Layer 3)
- Async (Layer 4)

**Message wire format** (simple, fixed, no serde dependency):

```
[command: 4 bytes][payload_len: 4 bytes][payload: N bytes]
```

This is intentionally minimal. Structured serialization comes in Layer 3 for services that need it.

**Prerequisites:** Stable `arcos-sys`. User-space heap allocator working reliably.

---

## Layer 3: Ergonomics and Ecosystem

Once Layers 1-2 exist, invest in developer productivity.

### Derive Macros

Proc macros that generate the `IpcHandler` boilerplate:

```rust
use arcos_service::ipc;

struct MyService { /* ... */ }

#[ipc]
impl MyService {
    fn get(&self, hash: [u8; 32]) -> Result<Vec<u8>, Error> {
        // just business logic
    }

    fn put(&mut self, data: &[u8]) -> Result<[u8; 32], Error> {
        // just business logic
    }
}
```

The `#[ipc]` attribute generates the match dispatch, serialization glue, and error marshaling. Each method becomes an IPC command.

### Serialization

For services that need structured data over IPC, integrate with `no_std`-compatible serialization:

- **postcard** (compact binary, `no_std`, serde-compatible) — good default
- **serde** with `no_std` feature — for types that already derive `Serialize`/`Deserialize`

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct GetRequest {
    hash: [u8; 32],
    verify_signature: bool,
}
```

This is opt-in. Services that pass raw bytes never pay for serialization.

### Client Generation

If a service uses `#[ipc]`, generate a matching client crate:

```rust
// Generated from MyService's #[ipc] methods
let client = MyServiceClient::connect(endpoint)?;
let data = client.get(hash)?;
client.put(b"new data")?;
```

This makes service-to-service calls feel like function calls. The IPC mechanics are invisible.

### Error Types

Rich, contextual errors — not numeric codes:

```rust
pub enum ArcosError {
    CapabilityDenied {
        principal: Principal,
        endpoint: u32,
        operation: &'static str,
    },
    ObjectNotFound {
        hash: [u8; 32],
    },
    OwnershipViolation {
        caller: Principal,
        owner: Principal,
    },
    // ...
}

impl core::fmt::Display for ArcosError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::CapabilityDenied { principal, endpoint, operation } => {
                write!(f, "capability denied: principal {} cannot {} on endpoint {}",
                    principal, operation, endpoint)
            }
            // ...
        }
    }
}
```

### Documentation

Not reference material. Guidance.

- **"Your First ArcOS Service"** — tutorial that builds a working service in 15 minutes
- **"Capabilities Explained"** — what they are, why they matter, how to use them
- **"Content-Addressed Storage Patterns"** — design patterns with ArcObjects
- **"IPC Cookbook"** — request/response, pub/sub, streaming, error handling
- **Rustdoc on everything** — every public type and function documented with examples

### Testing Utilities

Test services on host without QEMU:

```rust
#[cfg(test)]
mod tests {
    use arcos_test::{MockEndpoint, TestPrincipal};

    #[test]
    fn test_get_enforces_ownership() {
        let alice = TestPrincipal::new("alice");
        let bob = TestPrincipal::new("bob");
        let mut svc = FileService::new();

        // alice stores an object
        let req = Request::put(b"secret", alice);
        let resp = svc.handle(req);
        let hash = resp.payload_as::<[u8; 32]>();

        // bob cannot delete it
        let req = Request::delete(&hash, bob);
        let resp = svc.handle(req);
        assert!(resp.is_err());
        assert_eq!(resp.error_kind(), ErrorKind::OwnershipViolation);
    }
}
```

**Prerequisites:** Stable Layer 2 API. Proc-macro crate infrastructure.

---

## Layer 4: Async Runtime (Future Work)

Modern Rust developers expect async. But async on ArcOS requires a custom executor — there is no epoll, no threads in the traditional sense, no `std::thread::spawn`.

**The path:**
1. Build a minimal single-threaded executor around IPC recv (the natural "await point")
2. Futures that yield on `recv_msg` and `obj_get`
3. Cooperative multitasking within a service process

```rust
// Future goal — NOT current capability
async fn handle_request(hash: [u8; 32]) -> Result<Vec<u8>> {
    let obj = fs_client.get(hash).await?;
    let verified = identity_client.verify(&obj).await?;
    Ok(obj.content)
}
```

This is real work — a custom `no_std` async runtime built on ArcOS primitives. It is explicitly **not** tokio (which requires `std`, OS threads, and epoll/kqueue). It would be a purpose-built executor, similar in spirit to `embassy` (embedded async Rust).

**Prerequisites:** Layers 1-3 stable. Understanding of which syscalls should be async-friendly. Possibly kernel-side changes to support non-blocking recv.

---

## Layer 5: Ecosystem and Distribution

Once building services is pleasant, distribution matters.

### Package Manifest (`Arcos.toml`)

```toml
[service]
name = "fs-service"
version = "1.0.0"
endpoint = 16

[capabilities.required]
object_store = ["read", "write"]

[capabilities.granted]
filesystem = ["read", "write", "delete", "list"]
```

Capability declarations are auditable — users see what a service needs before granting access.

### Signed Distribution

ArcOS already has signed ELF loading (Ed25519 ARCSIG trailer). Extend this to distribution:

- Services are published as signed ELF binaries
- Author's Principal is verifiable
- The signing infrastructure (`tools/sign-elf/`) already exists

### Registry (Long-Term)

A crate registry for ArcOS services. Leverages the existing Rust/Cargo ecosystem:

- Services are published as standard Rust crates
- `cargo install` with an ArcOS target
- Registry tracks capability requirements, author identity, audit status

**Prerequisites:** Stable service API. Real-world services beyond fs-service and key-store.

---

## What Exists Today vs. What's Needed

| Component | Status | Next Step |
|-----------|--------|-----------|
| Syscall ABI (20 calls) | Done | Stabilize, document |
| User-space services (fs, key-store) | Done | Extract common patterns into library |
| Signed ELF loading | Done | Already the distribution primitive |
| IPC with principal stamping | Done | Wrap in safe API |
| Content-addressed storage | Done | Wrap in safe API |
| `arcos-sys` (syscall wrappers) | Not started | **Start here** |
| `arcos-service` (framework) | Not started | After `arcos-sys` |
| Derive macros | Not started | After `arcos-service` |
| Serialization integration | Not started | After framework stabilizes |
| Async runtime | Not started | After Layers 1-3 |
| Package registry | Not started | After real adoption |

The kernel-side work is largely done. The developer experience gap is in the userspace libraries.

---

## Success Criteria

1. A new service can be written in <50 lines of Rust
2. Services build with `cargo build --target <arcos-target>` — standard Rust tooling
3. Tests run on host with `cargo test` — no QEMU for unit tests
4. Error messages tell developers what went wrong and how to fix it
5. Documentation covers every public API with runnable examples
6. Service-to-service calls feel like function calls, not IPC plumbing

---

## The Composability Payoff

When IPC is painless, the microkernel design pays dividends:

```rust
// A service that composes three other services
struct MyApp {
    fs: FsClient,
    identity: IdentityClient,
    network: NetworkClient,
}

impl MyApp {
    fn fetch_and_store(&mut self, url: &str) -> Result<[u8; 32]> {
        let data = self.network.fetch(url)?;
        let sig = self.identity.sign(&data)?;
        let hash = self.fs.put_signed(&data, &sig)?;
        Ok(hash)
    }
}
```

Three services, three IPC calls, zero shared memory, full isolation, complete auditability. And it reads like a normal Rust program.

That's the promise. Build the libraries, and the architecture sells itself.
