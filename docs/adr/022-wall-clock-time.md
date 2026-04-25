# ADR-022: Wall-Clock Time and the Path to Decentralized Time

- **Status:** Accepted
- **Date:** 2026-04-25
- **Depends on:** [identity.md](../identity.md) (Frame B: kernel as arbiter, not Principal), [PHILOSOPHY.md](../PHILOSOPHY.md) (decentralization stance), CLAUDE.md project vision ("no reliance on legacy IP/DNS")
- **Related:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (channels — likely transport for future signed time), [ADR-007](007-capability-revocation-and-telemetry.md) (audit infrastructure consumes wall-clock once it lands), [ADR-000](000-zta-and-cap.md) (the new `SetWallclock` capability follows the existing system-capability pattern)
- **Supersedes:** N/A

## Scope Boundary (read this first)

This ADR defines:

- Kernel state for wall-clock time (two atomics: Unix-seconds baseline + kernel-tick anchor).
- Two new syscalls: `SetWallclock(unix_secs, source_tag) -> Result` (capability-gated) and `GetWallclock() -> u64`.
- A new `SetWallclock` system capability granted only to `udp-stack` at boot.
- A reserved `source_tag` field in the ABI to enable future trust-source migration without breaking consumers.
- Day-1 setter behavior: udp-stack queries NIST `time-a-g.nist.gov` (`129.6.15.28`) every 4h and publishes with `source_tag = 0` (unauthenticated).

This ADR explicitly does **not** define:

| Concern | Owner |
|---|---|
| Distributed causality (Lamport / vector clocks for cross-node IPC) | Out of scope. Today's IPC is single-node; future ADR if cross-node IPC ever lands. |
| Cert / signature validity windows, leap-second semantics | Out of scope. Consumers (TLS, signed-cert validators) define their own tolerance against `GetWallclock`. |
| File mtime / atime semantics | Out of scope. ObjectStore is content-addressed and doesn't carry mtime today. |
| Monotonic-vs-wall divergence handling for sleeping tasks | Out of scope. `sys::get_time()` (kernel ticks) remains the monotonic source of truth; nothing in this ADR changes that. |
| User-space NTP for arbitrary processes | Out of scope. Only `udp-stack` speaks NTP; everyone else reads via `GetWallclock`. |
| Persistent wall-clock across reboots (RTC, ObjectStore checkpoint) | Out of scope. Future RTC-driver ADR. |
| Concrete NTS / Roughtime / peer-attested implementations | Out of scope. This ADR reserves their `source_tag` slots; the implementations are future ADRs. |

## Context

CambiOS today has:

- `sys::get_time()` (syscall 9) returns monotonic kernel ticks — useful for measuring elapsed time, useless for "what year is it."
- `udp-stack` queries NTP at boot, parses the Unix-seconds response, and **discards the result** — `run_ntp_demo` ([user/udp-stack/src/main.rs:628-648](../../user/udp-stack/src/main.rs#L628-L648)) is verification-only; `unix_to_datetime` is `#[allow(dead_code)]` because nobody consumes it.
- No kernel state for wall-clock time. Shell prompt, eventual GUI clock, and audit-log timestamps all have nothing to render.
- Audit log entries carry tick-relative timestamps (microkernel uptime), not Unix time.

The smallest patch — "add `WALL_CLOCK_UNIX: AtomicU64`, give udp-stack a syscall to set it" — gets a clock on the screen but quietly bakes in NTP-from-NIST as the trust anchor for "what time is it." That trust anchor is **cheaper to question now than to migrate later.** The implementation difference between "syscall takes a u64" and "syscall takes a u64 + a source-tag" is one register. The architectural difference is whether future signed-time, peer-attested time, or hardware-attested time can land without breaking callers.

## Problem

**Problem 1 — wall-clock state has to live somewhere.** Three options: kernel atomics (this ADR), a userspace time-service process (everyone IPC-queries it), or a per-process query-on-demand model (every reader contacts udp-stack). Kernel atomics win because: (a) every consumer needs to read it, (b) lock-free read is `O(1)`, (c) any userspace time service ends up stamping its messages with a timestamp anyway, so the kernel ends up needing to know regardless.

**Problem 2 — NTP is unauthenticated.** Plain NTP (RFC 5905) trusts whatever responds at the configured IP. A network-position attacker rewrites the response on the wire; a coerced server lies in its reply; there is no signature to verify. NIST `time-a-g.nist.gov` is operated by a US-government agency. CambiOS's stated stance is **"no reliance on legacy IP/DNS"** (CLAUDE.md project vision) and **"no backdoors, no telemetry"** (project principles). Trusting an unauthenticated UDP packet from a US-government IP is a deliberate concession on day 1, **not the endgame.**

**Problem 3 — the wire format / syscall ABI is a long-lived contract.** Once `SetWallclock(unix_secs)` ships and udp-stack and the shell are built against it, every alternative source has to either (a) impersonate NTP (lie about provenance, lose all forensic value) or (b) trigger a syscall ABI break that ripples through every consumer. This ADR's primary architectural value is the second register — `source_tag` — so that the choice of NTP today does not foreclose Roughtime, NTS, or peer-attested time tomorrow.

**Problem 4 — there is no agreed-upon decentralized time service today.** Roughtime (IETF draft, Google + Cloudflare deployments) is the closest existing thing to a quorum-attested signed-time protocol. NTS (RFC 8915) authenticates NTP but still trusts the operator. Identity-bearing peer-attested time would require the SSB-inspired social layer ([identity.md § Social Layer](../identity.md)) which doesn't exist yet. **None of these are deployable today.** This ADR commits to a forward path, not a forward implementation.

## The Reframe

> **Wall-clock time is a fact about the world that the kernel republishes on behalf of a trusted setter. The identity of the trusted setter, and the protocol it used to learn the fact, are encoded in the syscall ABI from day 1 — so the trust source can migrate without breaking consumers. Day-1 setter is `udp-stack`-via-NTP-from-NIST. Endgame setter is identity-bearing peer-quorum or signed-carrier hardware.**

The kernel does not vouch for time. It republishes what its capability-holder set. This matches the Frame B identity rephrasing (memory: `project_frame_b_identity`): kernel as arbiter, not Principal.

## Decision

### 1. Kernel state — two atomics, no lock

```rust
// src/time/wallclock.rs (new)
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// Unix seconds at the moment of the last `set()` call. Sentinel `0` = unset.
static WALL_BASELINE_UNIX: AtomicU64 = AtomicU64::new(0);
/// Kernel tick count at the moment of the last `set()` call.
static WALL_BASELINE_TICKS: AtomicU64 = AtomicU64::new(0);
/// Trust-source tag (see § 4 — Reserved values).
static WALL_SOURCE_TAG: AtomicU8 = AtomicU8::new(0);

/// Publishes a new wall-clock baseline. Three plain stores, no seqlock.
///
/// Concurrent readers may briefly observe the new TICKS anchor against the
/// old UNIX baseline (or vice versa). Maximum observable error is one
/// second of skew during the window between the two stores. This is
/// deliberate, not an oversight: `set()` runs every 4h (not in a hot
/// loop), wall-clock display does not need sub-second monotonicity, and
/// `get_time()` (kernel ticks) remains the authoritative monotonic
/// source. A seqlock would add complexity for no measurable gain.
pub fn set(unix_secs: u64, source_tag: u8) {
    let now_ticks = scheduler::Timer::get_ticks();
    WALL_BASELINE_TICKS.store(now_ticks, Ordering::Release);
    WALL_BASELINE_UNIX.store(unix_secs, Ordering::Release);
    WALL_SOURCE_TAG.store(source_tag, Ordering::Release);
}

pub fn get() -> u64 {
    let baseline = WALL_BASELINE_UNIX.load(Ordering::Acquire);
    if baseline == 0 { return 0; } // sentinel — unset
    let anchor = WALL_BASELINE_TICKS.load(Ordering::Acquire);
    let now = scheduler::Timer::get_ticks();
    let elapsed_ticks = now.saturating_sub(anchor);
    baseline + elapsed_ticks / TICKS_PER_SEC
}
```

Lock-free. No new lock-hierarchy entry. Reads are wait-free and safe from any context (ISR, syscall handler, idle loop). The torn-read window is documented inline at `set()` so a cold reader does not reach for a seqlock pattern before finding this ADR.

### 2. Two new syscalls

```rust
SetWallclock = 39,    // (u64 unix_secs, u8 source_tag) -> Result. Capability-gated.
GetWallclock = 40,    // () -> u64 (0 = unset). Anyone.
```

`SetWallclock` requires `CapabilityKind::SetWallclock` (new). Anonymous senders rejected (Frame B identity gate).

`GetWallclock` joins the unidentified-allowed exempt set alongside `GetTime` / `GetPid` — displaying the clock from a not-yet-bound process is fine. (See [src/syscalls/mod.rs](../../src/syscalls/mod.rs) `requires_identity()`.)

### 3. New `SetWallclock` system capability

Granted at boot only to `udp-stack` (by name match in `load_boot_modules`, same precedent as `MapFramebuffer` for `fb-demo` / `scanout-limine`). No other module receives it. A future signed-time service or peer-attestation collector would also receive this capability — possibly with `policy-service` mediating to enforce "only one setter at a time" or "tag-floor minimums."

### 4. `source_tag` reserved values (the forward path)

| Tag | Meaning | Status |
|-----|---------|--------|
| `0` | Unauthenticated (plain NTP, no integrity) | **Day 1 — udp-stack uses this** |
| `1` | NTS-authenticated NTP (RFC 8915) | Reserved; lands when an NTS client is built |
| `2` | Roughtime quorum-attested (≥2 server agreement) | Reserved; closest to "decentralized verifiable" |
| `3` | Peer-attested via Principal-signed CambiObject | Reserved; needs the SSB social layer ([identity.md](../identity.md)) |
| `4` | Signed-carrier hardware time (calibrated, identity-stamped) | Reserved; needs the input-carrier ecosystem (memory: `project_signed_carrier_input`) |
| `5..=255` | Unallocated; future ADR assigns | — |

**Reservations are permanent in the sense that a future ADR may deprecate a tag (mark it reserved-do-not-use) but may not renumber or repurpose it.** Once consumers begin matching on `tag == 0` to mean "unauthenticated NTP," reusing slot `0` for something else silently re-meanings every existing `match` arm — the same forward-compat trap as a syscall-number reassignment. New trust sources land at the next free slot.

The kernel **does not enforce** trust-tier minimums today. Consumers query `WALL_SOURCE_TAG` if they care. The forward expectation is that `policy-service` will land tag-based filtering ("audit subsystem drops tagged-0 timestamps once tag-2+ is available") in a follow-up ADR.

### 5. udp-stack — stop discarding NTP

- Swap target IP from `216.239.35.0` (Google `time.google.com`) to `129.6.15.28` (`time-a-g.nist.gov`, NIST). Comment-document the IP source so the next maintainer can update when NIST renumbers.
- After `parse_ntp_response()` returns `Some(unix_ts)`, call `sys::set_wallclock(unix_ts, 0)`.
- Refresh every **4 hours**. NIST publishes a "≥4h between queries" guideline for casual clients; respect it.
- On NTP failure, leave the wall clock at its last-known-good baseline. **Never set it to zero from a failed query.**

### 6. Shell prompt — first consumer

`user/shell` renders the prompt as `arcos@HH:MM> ` from `sys::get_wallclock()`. If `get_wallclock()` returns 0, prompt remains `arcos> ` (today's behavior). This is the visible verification signal: boot lands at `arcos> `, then within seconds (after udp-stack's first NTP response) the next render becomes `arcos@HH:MM> `. The GUI clock widget is a future consumer that lives inside the libgui / compositor work and does not block this ADR.

**`unix_to_datetime` migrates to `user/libsys`.** The Unix-secs → `(year, month, day, hour, minute, second)` math currently lives as `#[allow(dead_code)]` in [user/udp-stack/src/main.rs:650-694](../../user/udp-stack/src/main.rs#L650-L694). It is a pure function on a `u64`, used by every consumer that wants to render time, and belongs in the shared userspace library so it does not get duplicated as more consumers land. Move it to a new `user/libsys/src/time.rs` module; udp-stack and shell both depend on libsys already, no new edge in the dep graph.

**libsys also gets a `tag_name(source_tag: u8) -> &'static str` helper.** The kernel stores `source_tag` as a `u8` for ABI stability and verification-friendly enum exhaustiveness (see § 4 and the rejection of a kernel-side runtime registry). Consumers that want to display a human-readable source name — audit log formatters, the shell's eventual `--show-source` flag, future GUI clock tooltips — should call this single source-of-truth helper rather than each re-implementing the integer→name table. Same place as `unix_to_datetime`; same rationale (pure function, shared by every consumer).

## Consequences

### Positive
- Kernel time-of-day available to every process via one cheap syscall.
- ABI is forward-compatible with NTS, Roughtime, peer-attested, and signed-hardware sources — `source_tag` migration costs a `match` arm in the consumer, not a syscall break.
- Capability-gated setter — no anonymous process can lie about the time.
- udp-stack stops doing dead work (NTP query → `/dev/null`).

### Negative
- Day-1 trust source is unauthenticated NTP from a US-government IP. Network-position attackers can lie. Documented as accepted risk; mitigated by the forward path that lets us migrate without an ABI break.
- Adds two syscalls (39, 40) and one new capability (`SetWallclock`) to the audit surface.
- Wall-clock does not survive reboot (no persistent baseline). Boot shows `arcos> ` until NTP responds (~seconds in QEMU, longer on metal). Acceptable; persistence belongs to a future RTC-driver ADR.

### Neutral
- One more `name == "udp-stack"` match in `load_boot_modules`. The pattern is already established for `fb-demo` and `scanout-limine`.
- `SetWallclock` capability is in the same load-bearing class as `MapFramebuffer` — a wrong grant compromises a system-level invariant.

## Alternatives Considered

**A. Skip the `source_tag` field; ship `SetWallclock(unix_secs)` only.** Rejected. Migration to NTS / Roughtime / peer-attested then requires either (a) impersonating the unauthenticated source (lying about provenance) or (b) a syscall ABI break rippling through every consumer. The cost of one extra register is one extra register; the cost of an ABI break is everyone.

**B. Make wall-clock a userspace time-service process; everyone IPC-queries it.** Rejected. The strong argument is bootstrap ordering, not IPC overhead: a userspace time service has to be started, register its endpoint, finish its init sequence, and survive its lifetime — and *something* has to publish the time before that service is ready to serve. Today that "something" is the kernel itself. Any consumer that reads wall-clock during early boot (audit subsystem stamping startup events, log timestamps before user services exist) needs the answer before user-space scheduling has stabilized. Kernel atomics sidestep the bootstrap ordering problem entirely; a userspace time service reintroduces it. The IPC-overhead argument is real but secondary. Time-service-as-process makes sense if we eventually need different views of time per Principal — that is a future ADR if it materializes.

**C. Use Roughtime today.** Rejected. No no_std-friendly Rust Roughtime client exists; the protocol is still IETF-draft; deploying it requires choosing which Roughtime servers to trust (Google? Cloudflare? Both? A user-curated set?) — a decision larger than this ADR. NTP-from-NIST is the simpler concession that opens the ABI for Roughtime later.

**D. Use the local APIC / Generic-Timer / CLINT free-running counter as a quartz fallback when NTP is unavailable.** Out of scope here. Drift compensation is a separate problem; today's "wall clock is 0 until NTP responds" model is honest about uncertainty rather than projecting confident-but-wrong time.

**E. Persist the last NTP timestamp to ObjectStore so reboots do not lose wall clock.** Out of scope. Useful, but requires ObjectStore-write at shutdown (no shutdown path today) or periodic checkpoint (introduces ObjectStore write traffic). RTC-driver ADR is the right place.

**F. Stay on Google `time.google.com`.** Both Google and NIST are single unauthenticated sources; neither is cryptographically trustworthy on the wire. NIST is marginally closer to the "time.gov" framing this ADR opens with, and source_tag = 0 already documents that the kernel does not cryptographically trust either one. The choice does not matter much; NIST wins on alignment, not on safety.

## Verification

- Confirmed at draft time: highest existing `SyscallNumber` variant is `VirtioModernCaps = 38`, so `SetWallclock = 39` and `GetWallclock = 40` are free. Implementer must re-confirm against `make stats` at land time in case another ADR has consumed the slots first.
- `cargo test --lib` covers `wallclock::get` returning `0` before set, returning `baseline + tick-derived offset` after.
- `make check-all` builds tri-arch (`set` / `get` are arch-agnostic; only `Timer::get_ticks` is arch-specific and already abstracted).
- Boot smoke test: `make run-quiet` lands at `arcos> ` then transitions to `arcos@HH:MM> ` within ~10s of boot (NTP RTT in QEMU).
- Capability test: a non-bootstrap, non-`SetWallclock`-holding process calling `SetWallclock` is rejected with `Eperm`.

## Open Questions / Deferred

> **Deferred decision.** Whether `policy-service` should mediate `SetWallclock` (gate by tag-floor, debounce conflicting setters, log resets > N seconds). **Revisit when:** a second wall-clock source lands (i.e., `source_tag` slot 1 or 2 gets a real implementation). Today there is only one setter; mediation has nothing to do.

> **Deferred decision.** Whether to surface `WALL_SOURCE_TAG` to consumers via a third syscall `GetWallclockTag()`. **Revisit when:** the audit subsystem or a security-sensitive consumer (TLS cert validator, signed-time stamp issuer) needs to filter by trust tier.

> **Deferred decision.** Roughtime client implementation. **Revisit when:** an actor independent of CambiOS publishes a no_std-compatible Rust Roughtime client, or when a bare-metal-friendly NTS client appears in the ecosystem.

> **Deferred decision.** Persistent wall-clock across reboots (RTC driver, ObjectStore checkpoint). **Revisit when:** the bare-metal Dell boot stabilizes and "boot is silent for ~30s while NTP retries" becomes observably annoying.

> **Deferred decision.** Staleness signal — how does a consumer distinguish "fresh time" from "udp-stack crashed five days ago and the displayed clock has drifted"? Today `get()` returns the same shape regardless of how long ago `set()` last ran. Options: (a) a fourth atomic `WALL_LAST_SET_TICKS` plus a `GetWallclockAge() -> u64` syscall returning seconds since last set; (b) shell renders `arcos@HH:MM*>` (asterisk) when the baseline is older than N hours; (c) `get()` returns `0` (sentinel-unset) once the baseline ages past a hard threshold. **Revisit when:** the first non-display consumer of wall-clock lands (audit timestamp, signed-stamp issuer, TLS validity check) — display can tolerate stale-but-plausible time; security-sensitive consumers cannot. For a security-oriented OS this matters; for the day-1 shell-prompt use case it does not, which is why it is deferred and not in the v1 ABI.
