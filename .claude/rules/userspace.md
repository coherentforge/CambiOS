---
paths:
  - "user/**"
  - "manifest.toml"
  - "cambios-manifest/**"
  - "cambios-blk-proto/**"
  - "src/syscalls/dispatcher.rs"
  - "src/fs/block_driver_client.rs"
---

# Service endpoints

The assignment of record is the endpoint map in the header of [manifest.toml](../../manifest.toml) ("change endpoints HERE"); it lists every assigned endpoint. The bullets below explain the numbers whose handling does not read off that map.

- **Endpoint 0** is the REPLY_ENDPOINT "unset" sentinel — structurally unusable.
- **Endpoint 1 is init's** (ADR-018 readiness pings). The manifest reserves every listed entry's endpoints to its derived AID, services and on-demand apps alike.
- **The block driver** (virtio-blk in the `default` profile, nvme in the bare-metal profiles; the seam is `cambios-blk-proto`) owns three endpoints. 24: user clients, `recv_verified`. 26: kernel-only commands, `recv_msg`, no cap check; requests carry `[kcmd][tag:4]`. 25: the kernel's reply endpoint: `handle_write` intercepts it before the IPC pipeline and accepts a write only from a process whose Principal is the manifest's reservation owner of 25, stamps it, and denies + audits anything else; `BlockDriverClient` accepts only a stamped reply echoing its request tag, and takes the handshake's shared-page address only inside a `SYS_ALLOC_DMA` grant of the replying process.
- **Endpoint 30, the input consumer,** is the compositor in the GUI profiles and the shell in `headless`; usb-host always delivers keyboard events there. The manifest's two `shell` entries with disjoint `profile` tags pick the owner.
