---
paths:
  - "user/**"
  - "manifest.toml"
  - "cambios-manifest/**"
  - "cambios-blk-proto/**"
---

# Service endpoints

- **Service endpoints (load-bearing numbers):** init=1 (ADR-018 readiness pings; the manifest reserves every listed entry's endpoints to its derived AID — services AND on-demand apps: tree=61, worm=62, sprouty=63, ping=19, hello-window=29 — and init spawns the service set; the kernel auto-starts nothing), fs-service=16, key-store-service=17, virtio-net=20, udp-stack=21, block driver (virtio-blk in the `default` profile, nvme in the bare-metal profiles; the seam is `cambios-blk-proto`)=24 (user clients, `recv_verified`) + 26 (kernel-only commands, `recv_msg`, no cap check; requests carry `[kcmd][tag:4]`) + 25 (kernel's reply endpoint: `handle_write` intercepts it before the IPC pipeline and accepts a write only from a process whose Principal is the manifest's reservation owner of 25, stamps it, and denies + audits anything else; `BlockDriverClient` accepts only a stamped reply echoing its request tag, and takes the handshake's shared-page address only inside a `SYS_ALLOC_DMA` grant of the replying process), scanout-virtio-gpu=27, compositor=28, input consumer=30 (the compositor in the GUI profiles, the shell in `headless` — usb-host always delivers keyboard events there; the manifest's two `shell` entries with disjoint `profile` tags pick the owner). Endpoint 0 is the REPLY_ENDPOINT "unset" sentinel — structurally unusable.
