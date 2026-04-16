# ADR-012: Input Architecture and Device Classes

- **Status:** Proposed
- **Date:** 2026-04-14
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-003](003-content-addressed-storage-and-identity.md) (Principals and load-bearing identity), [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC bulk path), [ADR-011](011-graphics-architecture-and-scaling.md) (Graphics architecture)
- **Related:** The planned *ADR-014: Peripheral and document-flow services* covers printers and scanners; they are explicitly not on this path.
- **Supersedes:** N/A

## Problem

CambiOS currently has no input stack, and "no input stack" is another silent design decision until the first driver lands. The Phase GUI-2 plan in [ADR-011](011-graphics-architecture-and-scaling.md) names `ps2-kbd` and `ps2-mouse` as boot modules talking directly to the compositor. That plan is correct for PS/2 in isolation. It is **not** correct as the architecture against which every future input device — USB HID, Bluetooth HID, I²C touchpads, game controllers, styluses, and Jason's planned signed-carrier cryptographic keyboards — will be built.

The risk is not that PS/2 is wrong. The risk is that PS/2's constraints silently become *the constraints* — one device per IRQ, one event-stream endpoint per driver, scancode-shaped wire format, no device identity, no trust tier, no hotplug. Every one of those assumptions is wrong for USB HID; several are wrong for signed-carrier devices; all of them are wrong for game controllers that produce multi-axis analog data at 1000 Hz with stateful rumble commands in the opposite direction. If we wire Phase GUI-2 against PS/2-shaped assumptions, Phase GUI-5 (where USB HID and signed-carrier keyboards land) becomes a rewrite of every client-facing event path, not an additive driver.

A secondary problem: CambiOS's load-bearing identity stance ([ADR-003](003-content-addressed-storage-and-identity.md)) is ruthlessly consistent everywhere *except* hardware input. Every IPC message carries a sender Principal; every stored object has an author Principal and an owner Principal; every syscall from an unidentified process is rejected by the identity gate. But a keystroke — the most consequential byte in any interactive system, because it might be a passphrase or a signing command — currently has no Principal, no tamper evidence, no freshness guarantee. A malicious intermediate in the input path can inject or replay keystrokes without the rest of the OS noticing. This is a structural weakness in the security model, and it wants a structural fix, not a policy one.

This ADR is the load-bearing decision on input shape *before* the first driver ships, so PS/2 (and every driver after it) conforms to the architecture rather than defining it.

## The Target Hardware Spectrum

CambiOS aims to support:

| Class | Transport (today) | Transport (future) | Event rate | Stateful? | Needs identity? |
|---|---|---|---|---|---|
| Keyboard (legacy) | PS/2 (IRQ 1) | USB HID | <100/s | No | No (legacy tier) |
| Keyboard (signed-carrier) | — | USB HID or bespoke | <1000/s (signature batches) | Yes (nonce) | **Yes** (device Principal) |
| Pointer (mouse/trackpad) | PS/2 (IRQ 12) | USB HID, I²C, Bluetooth | 100-1000/s | Yes (button/scroll state) | Weak |
| Game controller (gamepad) | — | USB HID, Bluetooth | 100-1000/s, multi-axis analog | Yes (rumble, battery) | Weak |
| Tablet / stylus | — | USB HID, I²C | 100-1000/s, 4-6 axes (x/y/pressure/tilt/rotation/buttons) | Yes | Weak |
| Touch (multi-touch) | — | USB HID, I²C | 100-1000/s, N-finger | Yes (contact IDs) | Weak |
| Sensor (accel/gyro/ambient light) | — | I²C, USB | 10-1000/s | Typically no | No |
| Accessibility (eye tracker, switch) | — | USB HID | Variable | Usually yes | Weak |

What is *not* on this path:

- **Audio input (microphones)** — different transport pattern (USB audio class, bounded-latency ring buffer), tied to audio services. Future ADR.
- **Video input (cameras)** — document/media flow, tied to media services. Future ADR.
- **Printers / scanners** — document flow, not event flow. Future *ADR-014: Peripheral and document-flow services*.

The span of classes and the unevenness of identity / stateful / rate requirements rules out a single one-size endpoint. But most of them share enough shape that an aggregator service with per-class routing is the right answer.

## Decision

CambiOS has a three-layer input architecture:

1. **Input drivers** — one per transport (ps2-kbd, ps2-mouse, usb-hid, bluetooth-hid, i2c-touchpad, ...). Each is a user-space boot module or runtime-spawned service, claims the hardware IRQs or bus connections, produces normalized input events in the CambiOS wire format.

2. **Input Hub** — a single aggregator service that every driver talks to. Performs device enumeration + hotplug, per-device Principal verification, event classification, capability-based access gating, and trust-tier tagging. Forwards events to the compositor (for focus/cursor routing) or directly to apps that hold appropriate capabilities (for raw input: game controllers, tablets).

3. **Consumers** — compositor (default routing, one logical user), apps holding direct-input capabilities (games, pro-drawing apps), and specialized services (e.g., key-store for passphrase entry on signed input).

### Why a Hub instead of direct driver → compositor

- **Hotplug.** USB/Bluetooth devices appear and disappear during runtime. The compositor should not know or care which transport produced a key event. The Hub tracks the "currently connected" set.
- **Trust tiering.** The compositor decides focus; it does not decide whether a keystroke is worth trusting for passphrase entry. That's an orthogonal concern the Hub owns.
- **Raw input.** A game wants the Xbox controller without the compositor mediating; a tablet app wants stylus pressure without cursor emulation. The Hub can route around the compositor when capabilities authorize it.
- **Policy externalization.** Following the [ADR-006](006-policy-service.md) pattern, trust-tier policy lives in a userspace service, not the Hub itself. The Hub asks "is device X trusted for keyboard input?" and the policy service answers.

### Event wire format (normative)

All input drivers produce events in this format, regardless of transport. Multi-byte fields are little-endian.

```
offset  size  field
0       1     event_type (see below)
1       1     device_class (see below)
2       4     device_id (Hub-assigned, stable across hotplug for same Principal)
6       2     seq (rolling per-device sequence, for ordering / drop detection)
8       8     timestamp_ticks
16     40     payload (class-specific, see below)
56     40     signature_block (reserved: see § Signed Input)
96      —     (event ends; total 96 bytes, fits control IPC 256B payload)
```

**`event_type`:**
```
0x01 key_down       0x10 pointer_move    0x20 button_down     0x30 axis
0x02 key_up         0x11 pointer_button  0x21 button_up       0x31 tablet_tilt
0x03 key_repeat     0x12 pointer_scroll  0x22 button_repeat   0x32 tablet_pressure
                                                              0x40 touch_begin
                                                              0x41 touch_move
                                                              0x42 touch_end
0x80 device_added           0x81 device_removed           0x82 device_trust_change
```

**`device_class`:**
```
0x01 keyboard      0x02 pointer       0x03 controller
0x04 tablet        0x05 touch         0x06 sensor
0x07 accessibility 0xff generic
```

**Payload for common classes (40 bytes each):**

- *Keyboard (0x01):* `{ keycode: u32 (USB HID usage), modifiers: u16, unicode: u32, _pad: u22 bytes }`
- *Pointer (0x02):* `{ dx: i32, dy: i32, buttons: u16, scroll_x: i16, scroll_y: i16, _pad: u20 }`
- *Controller (0x03):* `{ buttons: u32, axes: [i16; 8] (x,y,z,rx,ry,rz,l,r triggers), hat: u8, _pad: u7 }`
- *Tablet (0x04):* `{ x: i32, y: i32, pressure: u16, tilt_x: i16, tilt_y: i16, rotation: u16, buttons: u16, tool_type: u8, _pad: u17 }`
- *Touch (0x05):* `{ contact_id: u32, x: i32, y: i32, pressure: u16, width: u16, height: u16, _pad: u18 }`

This is the Phase GUI-2 format. When the first driver (`ps2-kbd`) ships, it populates `device_class=0x01 keyboard`, `device_id=1` (Hub-assigned on first driver registration), `signature_block` all zeros, and the Hub tags it as **trust tier "unsigned"**. No event-format change is needed when USB HID or signed-carrier drivers land — only new `device_class` and `signature_block` meanings.

### Trust tiers

The Hub tags every event with a trust tier based on the device's registration:

```
0 legacy       (PS/2, non-authenticating serial, etc.)
1 unsigned     (USB HID, Bluetooth HID — device is enumerated but not identified)
2 signed_batch (device holds a Principal, signs event batches — e.g., USB-HID with per-batch Ed25519)
3 signed_carrier (continuous signed carrier + per-event signature; Jason's target keyboard class)
```

The trust tier is a 2-bit field stored out-of-band in the Hub's per-event metadata (not in the wire format consumers see by default — consumers that care opt in via capability). Consumers query the Hub for event-source tier. Policy (which tier is *required* for which operation) lives in the policy service, not the Hub.

**Load-bearing examples:**

- `key-store-service` passphrase entry UI accepts only tier ≥ 2. Typing a passphrase on a PS/2 keyboard structurally fails, forcing the user to a trusted input method.
- General app input accepts tier ≥ 0. Tree-game-grade apps are fine on legacy keyboards.
- Game controller rumble commands (Hub → driver, opposite direction) require the app to hold a per-device output capability; rumble is a consent signal to the player that this app has motor control and shouldn't be invisible.

### Signed input — the signed-carrier path (Jason's target hardware)

**Concept:** the keyboard (or other input device) embeds a Principal at manufacture — a private key inside secure hardware, public key enrolled with the user's CambiOS installation (via the key-store service's trusted-input-device registry). The device emits a continuous signed carrier: small heartbeat frames at a fixed cadence (e.g. 100 Hz) even with no keys pressed, and each keypress batch is signed with a rolling nonce over the carrier.

**Properties:**

- *Spoof resistance:* forging a keypress requires the device's private key. A hardware keylogger on the cable can observe events but cannot alter or inject them (the signature would break).
- *Replay resistance:* the rolling nonce in every signed frame means yesterday's recorded keypresses do not verify today.
- *Tamper evidence:* carrier dropout — missing heartbeat frames — signals either physical disconnection or an MITM holding events back. The Hub raises this as `device_trust_change` with tier dropped to 0 until carrier resumes.
- *Cable-neutrality:* works over USB, Bluetooth, or a future bespoke CambiOS hardware transport. The signature is transport-layer-agnostic.

**`signature_block` layout (when tier ≥ 2):**
```
offset  size  field (within the 40-byte signature_block)
0       32    device_principal (Ed25519 public key)
32      4     signed_batch_seq (monotonic; covers the previous N events)
36      4     batch_length (how many events back this signature covers)
40       signature (NOT in-band for tier ≥ 2 — batch signature is delivered via
                   a paired signature event, since Ed25519 signatures are 64 B)
```

For tier ≥ 2, signatures are delivered as paired **signature events** (event_type ∈ 0x90 reserved) that follow the batch. The Hub verifies on receive, drops the signature-event entries, and forwards the original events with the tier tag. Apps see plain events; they just carry a trust tier in the Hub-to-consumer metadata.

For tier 3 (signed carrier), the Hub additionally tracks heartbeat cadence per device. A gap > 3× expected interval trips `device_trust_change` and the Hub re-tags all subsequent events from that device as tier 0 until the device re-enrolls or carrier resumes with a valid signature.

This is hardware that does not exist yet. But the **event format and Hub architecture must accommodate it on day one**, so when it materializes (post-v1 hardware project) it's a new driver + a key-store enrollment flow, not a protocol redesign.

### Capability model for input access

New `CapabilityKind` variants (reserved — added when consumers exist, not now):

- `InputReadClass(DeviceClass)` — read events of a named class from the Hub. The compositor holds this for all classes (it's the default router). Specific apps hold specific classes (games → `Controller`, drawing apps → `Tablet` and `Touch`).
- `InputReadDevice(DeviceId)` — read from a specific physical device. Required for apps that pin themselves to a specific controller (multiplayer local co-op), specific tablet (pro drawing), etc.
- `InputTrustTier(u8)` — minimum trust tier this app accepts. Apps set this at create-window time; the Hub filters events accordingly before delivery.
- `InputWriteDevice(DeviceId)` — the rumble / LED / feedback direction. Require explicit grant to prevent invisible motor-control by a background app.

All are system capabilities, not endpoint capabilities. Grant pattern follows `CapabilityKind::CreateProcess` (Phase 3.2b): kernel processes and specific boot modules receive them at boot, runtime grants go through the policy service.

### Hotplug protocol

- Drivers register with the Hub on startup via a control IPC `DeviceRegister { class, principal_opt, transport_info }`. The Hub assigns a `DeviceId` (u32, stable for the life of that registration).
- Drivers unregister on device removal (cable unplug, Bluetooth disconnect) via `DeviceUnregister { device_id }`. The Hub emits `device_removed` events to all subscribed consumers.
- Bluetooth pairing / USB device enumeration happens at the driver layer; the Hub sees already-cooked device registrations.
- A device's `Principal` (when present) is stable across reconnections. A Bluetooth keyboard that's been paired retains its `DeviceId` across unpair/repair cycles *if* it presents the same Principal. This is the mechanism that survives hotplug without requiring app-side re-binding.

### What is out of scope

- **Printer and scanner devices** — these flow CambiObjects and document bytes, not event streams. They belong in *ADR-014: Peripheral and document-flow services* (not yet written; lands when the second peripheral class warrants it). Scanners produce images → ObjectStore; printers consume rendered page formats. Different trust model (ObjectStore author/owner Principal per scan), different transport requirements (USB/network/Bluetooth), different latency tier (document jobs, not frame-scale events).
- **Audio and video input** — distinct media services with bounded-latency ring buffers, beyond the per-event model here. Future ADRs.
- **Clipboard** — not input in the hardware sense; a compositor-level content-sharing service. Future ADR.
- **Accessibility output** (screen readers, haptics beyond controllers) — output-direction concern, sibling to this ADR but not scoped here.

## Rationale

**Why lock in the wire format before any driver exists?** Because the first driver shapes every driver that comes after it. PS/2 is the easy default, and "easy" is exactly the risk — a PS/2-first wire format leaks PS/2 assumptions (no device identity, no signatures, scancode-shaped payload) into every consumer. By shipping the full format — `device_id`, `device_class`, `signature_block`, class-indexed payloads — from day one, PS/2 fills the shape rather than defining it. Adding a new class later is 40 bytes of payload spec, not a protocol revision.

**Why the Hub as a separate service?** Because the alternative is "compositor also does input" (what Xorg became) and "kernel does input" (what Linux does). The first couples the compositor to hardware-specific policy; the second puts hotplug, cryptography, and policy in the most-trusted code. CambiOS's microkernel rule is "the kernel mediates policy, not bytes" — but input is *policy* (who's trusted, what class this event is, should rumble be permitted), so it belongs in userspace, but not in the compositor. The Hub is the right seam.

**Why put signed-carrier support in the *design*, not the *roadmap*?** Because it's a structural claim about what "input" *is* in this OS, not a feature to add later. CambiOS's "identity is load-bearing" invariant says every message that crosses a trust boundary carries a sender Principal. Keypresses cross trust boundaries (an attacker between hardware and user-space is exactly the relevant threat for passphrase entry, signing prompts, etc.). Therefore keypresses must carry a source Principal. The current PS/2-shaped world is a compromise where we accept tier-0 input because there is no tier-2-or-3 hardware yet. But the format must already know about tier-3, or the OS silently normalizes to "input has no identity" and the whole invariant weakens.

**Why 96-byte events (not 256-byte full IPC)?** Because input events are bursty and a driver sending them needs to fit multiple events per IPC slot for batching efficiency. 96 bytes × 2 events per 256-byte IPC slot = 2 events per send, which halves per-event IPC overhead. A single event also still fits trivially. The 40-byte class payload was tuned so that every class's natural fields (keyboard modifiers + unicode, controller 8-axis state, tablet 6-axis+pressure) fit without forcing a bulk-channel protocol for control-IPC traffic.

**Why is the policy service consulted for trust-tier decisions, not the Hub itself?** Because trust policy changes ("this user now accepts Bluetooth HID for passphrase entry") shouldn't require a Hub redeploy. Policy goes through [ADR-006](006-policy-service.md), Hub stays mechanical.

## Phased implementation

| Phase | What lands | Prerequisites |
|---|---|---|
| **Input-0** | Wire format locked in (this ADR). `InputEvent` struct added to `libsys` or a new `user/libinput/` crate for drivers + consumers to share. Reserved `CapabilityKind` variants (`InputReadClass`, `InputReadDevice`, `InputTrustTier`, `InputWriteDevice`) **not** landed — added when first consumer exists to avoid noise. | ADR-012 merged. |
| **Input-1 (= Phase GUI-2)** | `ps2-kbd` + `ps2-mouse` boot modules. Compositor talks to them **directly** (no Hub yet — single consumer, two drivers). Events conform to wire format but `device_id` and `signature_block` are cosmetic. | ADR-011 PS/2 port whitelist lands. |
| **Input-2** | **Input Hub service** lands as a boot module. Compositor now talks only to Hub; ps2-kbd/ps2-mouse register with Hub. `CapabilityKind::InputRead*` variants land with the Hub's first consumers. Trust-tier tagging infrastructure present; policy is "all PS/2 is tier 0, and tier 0 is fine for all current apps." | First non-PS/2 input driver is on the horizon, OR compositor has >1 consumer that wants input. |
| **Input-3** | **USB HID driver** as a second transport. USB stack prerequisite. Events from USB HID tagged tier 1 (unsigned). No key-store passphrase UI yet, so no tier-gated consumer yet. | USB host-controller driver (XHCI) lands; post-v1 item. |
| **Input-4** | **Bluetooth HID driver.** Pairing + device Principal persistence in a registry sibling to key-store. Bluetooth stack prerequisite. | Bluetooth stack lands; post-v1. |
| **Input-5** | **Signed-carrier keyboard driver** + key-store-service trusted-input-device registry + policy-service tier-gating rules + key-store passphrase UI that requires tier ≥ 2. | Signed-carrier hardware exists; post-v1 hardware project. |
| **Input-6** | **Game controller / tablet / touch** drivers. These require `CapabilityKind::InputReadClass`-based routing around the compositor. First driver of each new class is its own phase. | App with direct-input need exists (game or drawing app). |

Input-0 is this ADR + a small wire-format header file. Input-1 is Phase GUI-2 of ADR-011. Input-2 onwards is post-v1 work that this architecture prepares for.

## Open Questions

### Should signature verification happen in the driver, the Hub, or a dedicated service?

Three options: (a) driver verifies and sets a trust tag when forwarding to the Hub; (b) Hub verifies centrally; (c) a sibling `input-verify-service` verifies on behalf of the Hub. Argument for (a): drivers are transport-aware and already handle the device; minimal round-trips. Argument for (b): single code path is easier to audit, one verifier implementation to harden. Argument for (c): separation of concerns — the verifier service can be independently formally verified. Lean: (b) for v1 simplicity, (c) if input-verify becomes a verification-critical service. Defer until signed-carrier hardware is near enough that the choice matters.

### How are trusted-input-device Principals enrolled?

Proposed flow (not final): the signed-carrier keyboard ships with a one-time physical-button-press enrollment mode that emits a Principal-publication event over the normal input channel; the key-store-service captures it during a system-wide enrollment flow that requires existing user Principal authentication. Design parallels YubiKey OpenPGP enrollment. Full protocol belongs in a successor ADR once hardware is close.

### What about input for remote sessions (future)?

If CambiOS gains any kind of remote-display or thin-client mode, the remote endpoint's input devices need to be representable. Likely answer: the remote-session service is itself an "input driver" that registers with the local Hub, with all events tagged with a remote-origin Principal and appropriately-restricted trust tier. Out of scope until a remote-session feature exists.

### Haptic output and LED control

The Hub-to-driver reverse direction (rumble, backlight, caps-lock LED, touch-feedback haptics) is mentioned but not detailed. It should use a distinct set of capabilities (`InputWriteDevice`) because unsolicited haptic feedback is a user-visible action — "background app rumbles the controller" is a consent violation even if the app is authorized to read input. Open: is the control path a write to the Hub (Hub forwards to driver) or direct from consumer to driver (with Hub-mediated capability check)? Defer to the first driver that supports output.

## Divergence

*(appended as implementation diverges from the plan)*
