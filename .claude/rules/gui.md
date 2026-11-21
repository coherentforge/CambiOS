---
paths:
  - "user/compositor/**"
  - "user/scanout-virtio-gpu/**"
  - "user/scanout-limine/**"
  - "user/libgui/**"
  - "user/libgui-proto/**"
  - "user/hello-window/**"
  - "user/terminal-window/**"
  - "user/libinput-proto/**"
  - "user/virtio-input/**"
---

# Graphics, GUI client library and input

The decisions are [ADR-011](../../docs/adr/011-graphics-architecture-and-scaling.md) (graphics architecture), [ADR-014](../../docs/adr/014-compositor-scanout-driver-protocol.md) (compositor and scanout protocol) and [ADR-012](../../docs/adr/012-input-architecture-and-device-classes.md) (input). Channel transport is [ADR-005](../../docs/adr/005-ipc-primitives-control-and-bulk.md). Endpoint numbers are in the header of [manifest.toml](../../manifest.toml).

## Compositor and scanout drivers

- **`scanout-virtio-gpu` is the default driver; `scanout-limine` is the fallback.** The virtio-gpu driver uses five 2D operations: CREATE_2D, ATTACH_BACKING, SET_SCANOUT, TRANSFER_TO_HOST_2D, RESOURCE_FLUSH.
- **Scanout transport** is ADR-014 § Divergence 2026-04-20: `SYS_VIRTIO_MODERN_CAPS = 38`, a double-copy frame path, `-vga virtio` under QEMU.
- **The client-compositor protocol** is ADR-014 § Divergence 2026-05-08: ten wire messages in the 0x3xxx and 0x4xxx ranges, with [user/libgui-proto/src/lib.rs](../../user/libgui-proto/src/lib.rs) authoritative for the wire format and the authority model.

## GUI client library (libgui)

- **libgui is an in-process library, and v0 is drawing primitives only** (ADR-011). Drawing needs no kernel syscalls: it is CPU writes into the attached surface channel.
- **`Client::open`** does the CreateWindow / WelcomeClient / `channel_attach` handshake. `user/hello-window/` is the canonical client.
- **`TileGrid::hit_test` is not built.** Don't add it without a consumer; [user/libgui/src/tile_grid.rs](../../user/libgui/src/tile_grid.rs) says where it would go.

## Input

- **ADR-012 § Divergence:** virtio-input first, `COMPOSITOR_INPUT_ENDPOINT = 30`, focus goes to the first live window.
- **Wire format:** [user/libinput-proto/src/lib.rs](../../user/libinput-proto/src/lib.rs), 96-byte events plus class payloads and modifier and button bitfields. `signature_block` is reserved from day one so ADR-012 Input-5 (signed events) lands without a format revision; keep it in every change to the format.
- **Path:** `virtio-input` → the compositor's `pump_input_once` → the focused window as `MsgTag::InputEvent = 0x4030` → `libgui`'s `Client::poll_event`.
- **The Input Hub is not built.** Revisit when: a second input consumer appears, or signed-carrier input hardware does.
