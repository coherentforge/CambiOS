// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! virtio-input driver — ADR-012 Input-1 (via virtio transport).
//!
//! Scans PCI for virtio-input devices (vendor=0x1AF4, device=0x1052),
//! initialises each via the modern virtio-pci transport, classifies
//! them as keyboard or pointer by probing the device's event-type
//! bitmap (`VIRTIO_INPUT_CFG_EV_BITS`), sets up one eventq per device,
//! then polls each device in a round-robin loop. Each evdev event is
//! translated into an ADR-012 96-byte `InputEvent` and forwarded to
//! the compositor's input endpoint.
//!
//! ## v0 scope boundaries
//!
//! - **Polling, not IRQ.** Mirrors virtio-blk and scanout-virtio-gpu.
//!   An IRQ-driven path would reduce latency but adds `sys::wait_irq`
//!   registration + a blocking receive pattern; deferred until a
//!   latency measurement justifies it.
//! - **No class beyond keyboard + pointer.** Tablet (EV_ABS) and touch
//!   are ADR-012 reserved classes; added when their first consumer
//!   exists. Controller support waits on game-pad-capable hardware +
//!   a gaming app.
//! - **No modifier tracking in the driver.** Modifier key state is
//!   exposed in `KeyboardPayload.modifiers` as the live mask *at the
//!   moment the event fired*. The driver tracks LeftShift /
//!   RightShift / LeftCtrl / etc. transitions internally and stamps
//!   the current mask on every subsequent KeyDown / KeyUp so clients
//!   don't reconstruct modifier state themselves.
//! - **No per-event signature.** `signature_block` left zeroed. Tier 0
//!   semantically (legacy transport). Signed-carrier hardware is a
//!   post-v1 hardware project per ADR-012 § Signed input; that path
//!   changes the driver, not the wire format.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod evdev;
#[allow(unsafe_code)]
mod transport;
#[allow(unsafe_code)]
mod virtqueue;

use cambios_libinput_proto::{
    button, encode_event, modifier, DeviceClass, EventType, InputEvent, KeyboardPayload,
    PointerPayload, EVENT_SIZE,
};
use cambios_libsys as sys;

use evdev::{
    evdev_to_hid, hid_to_ascii_us, BTN_EXTRA, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SIDE, EV_KEY,
    EV_REL, EV_SYN, KEY_A, KEY_LEFTALT, KEY_LEFTCTRL, KEY_LEFTMETA, KEY_LEFTSHIFT, KEY_RIGHTALT,
    KEY_RIGHTCTRL, KEY_RIGHTMETA, KEY_RIGHTSHIFT, KEY_SPACE, REL_HWHEEL, REL_WHEEL, REL_X, REL_Y,
};
use transport::{
    InitError, ModernTransport, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK,
    STATUS_FAILED, STATUS_FEATURES_OK, VIRTIO_F_VERSION_1,
};
use virtqueue::{EvdevEvent, EventRing};

// ============================================================================
// Constants
// ============================================================================

/// Compositor's input endpoint. Co-located here because the driver is
/// the only component that sends to it; the compositor side uses its
/// own `COMPOSITOR_INPUT_ENDPOINT` const (same value).
///
/// When the Input Hub lands (ADR-012 Input-2) this number moves from
/// "compositor's input endpoint" to "Hub's input endpoint" and the
/// compositor subscribes to the Hub instead.
const COMPOSITOR_INPUT_ENDPOINT: u32 = 30;

const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_INPUT_DEVICE_ID_MODERN: u16 = 0x1052;

const EVENTQ_INDEX: u16 = 0;

// virtio-input device config (spec §5.8).
const CFG_SELECT_OFFSET: usize = 0;
const CFG_SUBSEL_OFFSET: usize = 1;
const CFG_SIZE_OFFSET: usize = 2;
const CFG_U_OFFSET: usize = 8;

const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;

/// SCAFFOLDING: maximum concurrent virtio-input devices. v1 workload:
/// keyboard + mouse = 2. QEMU `-device virtio-keyboard-pci -device
/// virtio-mouse-pci` = 2. Headroom for a future virtio-tablet-pci
/// (drawing) + one spare for hotplug-pending replacement = 4 total
/// gives the ≤25%-utilization bar Convention 8 wants, per libgui's
/// Convention-8-style treatment of bounds (even though userspace isn't
/// scanned by the `make check-assumptions` lint yet).
///
/// Replace when: a real workload enumerates more than one spare device,
/// or USB HID post-v1 blurs "virtio-input device" and "plug-in HID
/// device" into a single driver surface that needs a different cap.
const MAX_INPUT_DEVICES: usize = 4;

// ============================================================================
// Per-device state
// ============================================================================

struct InputDevice {
    transport: ModernTransport,
    eventq: EventRing,
    notify_off: u16,
    class: DeviceClass,
    device_id: u32,
    seq: u16,
    /// Live modifier bitmask (bit-OR of `modifier::*`). Updated on
    /// every modifier-key press/release so the current value can be
    /// stamped on outgoing keyboard events.
    modifiers: u16,
    /// Live pointer button bitmask (bit-OR of `button::*`).
    buttons: u16,
}

// ============================================================================
// Entry
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[VIRTIO-INPUT] starting (ADR-012 Input-1)\r\n");

    // Scan PCI up to a small limit — no known platform exposes more
    // than a handful of input devices.
    let mut devices: [Option<InputDevice>; MAX_INPUT_DEVICES] =
        [const { None }; MAX_INPUT_DEVICES];
    let mut num_devices: usize = 0;
    let mut next_device_id: u32 = 1;

    for pci_index in 0..32u32 {
        if num_devices >= MAX_INPUT_DEVICES {
            break;
        }
        let (vendor, device) = match probe_pci_vendor_device(pci_index) {
            Some(v) => v,
            None => break, // device_info returned an error; past the last entry
        };
        if vendor != VIRTIO_VENDOR_ID || device != VIRTIO_INPUT_DEVICE_ID_MODERN {
            continue;
        }

        match initialize_device(pci_index, next_device_id) {
            Some(d) => {
                sys::print(b"[VIRTIO-INPUT] device ready: ");
                sys::print(class_name(d.class));
                sys::print(b" id=");
                print_u64_dec(d.device_id as u64);
                sys::print(b"\r\n");
                devices[num_devices] = Some(d);
                num_devices += 1;
                next_device_id += 1;
            }
            None => {
                sys::print(b"[VIRTIO-INPUT] skipping device (init failed)\r\n");
            }
        }
    }

    if num_devices == 0 {
        sys::print(b"[VIRTIO-INPUT] no supported devices; entering idle\r\n");
    } else {
        sys::print(b"[VIRTIO-INPUT] ");
        print_u64_dec(num_devices as u64);
        sys::print(b" device(s) online\r\n");
    }

    // Leaf module — no one waits on us — so release the boot gate
    // immediately and move into the poll loop.
    sys::module_ready();

    // Poll each device in round-robin. `yield_now` between rounds
    // prevents a tight spin when there's no input.
    loop {
        let mut any_progress = false;
        for slot in 0..num_devices {
            let dev_opt = &mut devices[slot];
            if let Some(dev) = dev_opt.as_mut() {
                while let Some((ev, desc_id)) = dev.eventq.poll_used() {
                    any_progress = true;
                    on_evdev_event(dev, ev);
                    dev.eventq.refill(&dev.transport, dev.notify_off, desc_id);
                }
            }
        }
        if !any_progress {
            sys::yield_now();
        }
    }
}

// ============================================================================
// Device init
// ============================================================================

fn initialize_device(pci_index: u32, device_id: u32) -> Option<InputDevice> {
    let caps = sys::virtio_modern_caps(pci_index)?;
    if caps.present == 0 {
        return None;
    }

    let (bar_phys, bar_size) = bar_phys_size(pci_index, caps.common_cfg.bar)?;
    let transport = match ModernTransport::new(&caps, bar_phys, bar_size) {
        Ok(t) => t,
        Err(e) => {
            print_init_err(e);
            return None;
        }
    };

    // Standard virtio 1.0 handshake.
    transport.reset();
    for _ in 0..32 {
        if transport.status() == 0 {
            break;
        }
    }
    transport.set_status_bit(STATUS_ACKNOWLEDGE);
    transport.set_status_bit(STATUS_DRIVER);

    let dev_features = transport.device_features();
    if dev_features & VIRTIO_F_VERSION_1 == 0 {
        sys::print(b"[VIRTIO-INPUT] device lacks VIRTIO_F_VERSION_1\r\n");
        transport.set_status_bit(STATUS_FAILED);
        return None;
    }
    transport.set_driver_features(VIRTIO_F_VERSION_1);
    transport.set_status_bit(STATUS_FEATURES_OK);
    if transport.status() & STATUS_FEATURES_OK == 0 {
        sys::print(b"[VIRTIO-INPUT] device rejected FEATURES_OK\r\n");
        transport.set_status_bit(STATUS_FAILED);
        return None;
    }

    if transport.num_queues() < 1 {
        sys::print(b"[VIRTIO-INPUT] device has no eventq\r\n");
        transport.set_status_bit(STATUS_FAILED);
        return None;
    }

    // Classify BEFORE eventq setup — the config probe writes to the
    // device config region and is only well-defined in the init window.
    let class = probe_class(&transport);
    let class = match class {
        Some(c) => c,
        None => {
            sys::print(b"[VIRTIO-INPUT] device class unrecognised; skipping\r\n");
            transport.set_status_bit(STATUS_FAILED);
            return None;
        }
    };

    let (eventq, notify_off) = EventRing::new(&transport, EVENTQ_INDEX)?;

    transport.set_status_bit(STATUS_DRIVER_OK);
    if transport.status() & STATUS_FAILED != 0 {
        sys::print(b"[VIRTIO-INPUT] device set FAILED after DRIVER_OK\r\n");
        return None;
    }

    Some(InputDevice {
        transport,
        eventq,
        notify_off,
        class,
        device_id,
        seq: 0,
        modifiers: 0,
        buttons: 0,
    })
}

/// Probe the device config for supported event types. Returns
/// `DeviceClass::Pointer` if the device reports any REL_* axis (i.e.,
/// a relative pointer = mouse). Otherwise returns
/// `DeviceClass::Keyboard` if the device reports the standard
/// keyboard range (KEY_A + KEY_SPACE both present in EV_KEY bitmap).
/// Returns `None` for devices that match neither.
fn probe_class(t: &ModernTransport) -> Option<DeviceClass> {
    // Check REL_X first — mice advertise EV_REL with at least REL_X.
    if bitmap_bit_set(t, EV_REL as u8, REL_X) {
        return Some(DeviceClass::Pointer);
    }
    // Not a relative pointer — check for keyboard shape.
    if bitmap_bit_set(t, EV_KEY as u8, KEY_A) && bitmap_bit_set(t, EV_KEY as u8, KEY_SPACE) {
        return Some(DeviceClass::Keyboard);
    }
    None
}

/// Query `VIRTIO_INPUT_CFG_EV_BITS[subsel]` and return whether the
/// given event code's bit is set in the returned bitmap.
#[allow(unsafe_code)]
fn bitmap_bit_set(t: &ModernTransport, ev_type_subsel: u8, code: u16) -> bool {
    let cfg = t.device_cfg_vaddr() as *mut u8;

    // SAFETY:
    // - `cfg` points at the device-specific config region (virtio spec
    //   §5.8), which is at least `sizeof(virtio_input_config) = 136` B
    //   by construction; the BAR-map bound was checked at transport init.
    // - The protocol is: write select, write subsel, read size, read
    //   up to `size` bytes of union data. Those fields are all within
    //   `sizeof(virtio_input_config)`.
    // - Single-threaded access, so no interleaved writes race.
    unsafe {
        core::ptr::write_volatile(cfg.add(CFG_SELECT_OFFSET), VIRTIO_INPUT_CFG_EV_BITS);
        core::ptr::write_volatile(cfg.add(CFG_SUBSEL_OFFSET), ev_type_subsel);
        let size = core::ptr::read_volatile(cfg.add(CFG_SIZE_OFFSET)) as usize;
        if size == 0 {
            return false;
        }
        let byte_idx = (code as usize) / 8;
        let bit_idx = (code as usize) % 8;
        if byte_idx >= size {
            return false;
        }
        let b = core::ptr::read_volatile(cfg.add(CFG_U_OFFSET + byte_idx));
        (b >> bit_idx) & 1 == 1
    }
}

// ============================================================================
// Event translation
// ============================================================================

fn on_evdev_event(dev: &mut InputDevice, e: EvdevEvent) {
    match e.etype {
        EV_SYN => {
            // SYN_REPORT marks the end of a batch; v0 sends events as
            // they arrive, so nothing to flush.
        }
        EV_KEY => {
            if (0x110..=0x117).contains(&e.code) {
                // Pointer button (BTN_LEFT .. BTN_EXTRA).
                if dev.class == DeviceClass::Pointer {
                    handle_pointer_button(dev, e.code, e.value);
                }
            } else if dev.class == DeviceClass::Keyboard {
                handle_keyboard_key(dev, e.code, e.value);
            }
        }
        EV_REL => {
            if dev.class == DeviceClass::Pointer {
                handle_pointer_rel(dev, e.code, e.value as i32);
            }
        }
        _ => {
            // EV_ABS / EV_MSC / etc. — not handled in v0. Deliberately
            // ignored so a future tablet / touch driver landing via
            // the same driver binary doesn't break this one.
        }
    }
}

fn handle_keyboard_key(dev: &mut InputDevice, code: u16, value: u32) {
    // Track modifier state regardless of whether we ultimately emit an
    // event — the mask is always up-to-date for the next outgoing key.
    let modifier_bit = match code {
        KEY_LEFTCTRL => modifier::LEFT_CTRL,
        KEY_LEFTSHIFT => modifier::LEFT_SHIFT,
        KEY_LEFTALT => modifier::LEFT_ALT,
        KEY_LEFTMETA => modifier::LEFT_GUI,
        KEY_RIGHTCTRL => modifier::RIGHT_CTRL,
        KEY_RIGHTSHIFT => modifier::RIGHT_SHIFT,
        KEY_RIGHTALT => modifier::RIGHT_ALT,
        KEY_RIGHTMETA => modifier::RIGHT_GUI,
        _ => 0,
    };
    if modifier_bit != 0 {
        if value != 0 {
            dev.modifiers |= modifier_bit;
        } else {
            dev.modifiers &= !modifier_bit;
        }
    }

    let event_type = match value {
        0 => EventType::KeyUp,
        1 => EventType::KeyDown,
        2 => EventType::KeyRepeat,
        _ => return, // unknown value — drop
    };

    let hid = evdev_to_hid(code);
    let payload = KeyboardPayload {
        keycode: hid,
        modifiers: dev.modifiers,
        // US QWERTY layout translation. Returns 0 for keys whose Unicode
        // contribution doesn't apply (Enter/Tab/arrows/modifiers etc) —
        // the encoder's named-key path handles those off `keycode`.
        unicode: hid_to_ascii_us(hid, dev.modifiers),
    };
    let seq = dev.next_seq();
    let event = InputEvent::key(event_type, dev.device_id, seq, sys::get_time(), payload);
    send_event(&event);
}

fn handle_pointer_button(dev: &mut InputDevice, code: u16, value: u32) {
    let bit = match code {
        BTN_LEFT => button::LEFT,
        BTN_RIGHT => button::RIGHT,
        BTN_MIDDLE => button::MIDDLE,
        BTN_SIDE => button::SIDE,
        BTN_EXTRA => button::EXTRA,
        _ => return,
    };
    if value != 0 {
        dev.buttons |= bit;
    } else {
        dev.buttons &= !bit;
    }
    let payload = PointerPayload {
        dx: 0,
        dy: 0,
        buttons: dev.buttons,
        scroll_x: 0,
        scroll_y: 0,
    };
    let seq = dev.next_seq();
    let event = InputEvent::pointer_event(
        EventType::PointerButton,
        dev.device_id,
        seq,
        sys::get_time(),
        payload,
    );
    send_event(&event);
}

fn handle_pointer_rel(dev: &mut InputDevice, code: u16, value: i32) {
    // Skip zero-delta relative events. QEMU's virtio-mouse emits heartbeat
    // REL_X=0 / REL_Y=0 frames whenever the host cursor isn't moving; those
    // carry no new information and produce no state change in any consumer,
    // so dropping them at the source keeps serial output + compositor work
    // proportional to actual motion.
    if value == 0 {
        return;
    }
    let mut payload = PointerPayload {
        dx: 0,
        dy: 0,
        buttons: dev.buttons,
        scroll_x: 0,
        scroll_y: 0,
    };
    let etype = match code {
        REL_X => {
            payload.dx = value;
            EventType::PointerMove
        }
        REL_Y => {
            payload.dy = value;
            EventType::PointerMove
        }
        REL_WHEEL => {
            payload.scroll_y = value.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            EventType::PointerScroll
        }
        REL_HWHEEL => {
            payload.scroll_x = value.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            EventType::PointerScroll
        }
        _ => return,
    };
    let seq = dev.next_seq();
    let event = InputEvent::pointer_event(etype, dev.device_id, seq, sys::get_time(), payload);
    send_event(&event);
}

impl InputDevice {
    fn next_seq(&mut self) -> u16 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }
}

fn send_event(event: &InputEvent) {
    let mut buf = [0u8; EVENT_SIZE];
    let n = match encode_event(&mut buf, event) {
        Some(n) => n,
        None => return, // encode can only fail on a too-small buffer; ours fits
    };
    // Best-effort — if the compositor isn't listening, drop the event.
    // Input is lossy by nature; no retry loop.
    let _ = sys::write(COMPOSITOR_INPUT_ENDPOINT, &buf[..n]);
}

// ============================================================================
// PCI helpers
// ============================================================================

fn probe_pci_vendor_device(pci_index: u32) -> Option<(u16, u16)> {
    let mut buf = [0u8; 108];
    let r = sys::device_info(pci_index, &mut buf);
    if r < 0 {
        return None;
    }
    Some((
        u16::from_le_bytes([buf[0], buf[1]]),
        u16::from_le_bytes([buf[2], buf[3]]),
    ))
}

fn bar_phys_size(pci_index: u32, bar_index: u8) -> Option<(u64, u64)> {
    if bar_index >= 6 {
        return None;
    }
    let mut buf = [0u8; 108];
    let r = sys::device_info(pci_index, &mut buf);
    if r < 0 {
        return None;
    }
    let off = 12 + (bar_index as usize) * 16;
    let addr = u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ]);
    let size = u32::from_le_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]);
    let is_io = buf[off + 12] != 0;
    if addr == 0 || size == 0 || is_io {
        return None;
    }
    Some((addr, size as u64))
}

// ============================================================================
// Logging helpers (no alloc, no format!)
// ============================================================================

fn class_name(class: DeviceClass) -> &'static [u8] {
    match class {
        DeviceClass::Keyboard => b"keyboard",
        DeviceClass::Pointer => b"pointer",
        _ => b"other",
    }
}

fn print_init_err(e: InitError) {
    sys::print(b"[VIRTIO-INPUT] transport init: ");
    match e {
        InitError::NotModernDevice => sys::print(b"not modern\r\n"),
        InitError::MissingCap => sys::print(b"cap missing\r\n"),
        InitError::CapsSpanMultipleBars => sys::print(b"caps span multiple bars\r\n"),
        InitError::MapMmioFailed => sys::print(b"map_mmio failed\r\n"),
    }
}

fn print_u64_dec(n: u64) {
    if n == 0 {
        sys::print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut m = n;
    let mut len = 0;
    while m > 0 {
        buf[len] = b'0' + (m % 10) as u8;
        m /= 10;
        len += 1;
    }
    let mut out = [0u8; 20];
    for i in 0..len {
        out[i] = buf[len - 1 - i];
    }
    sys::print(&out[..len]);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"VIRTIO-INPUT", b"panic");
    sys::exit(255);
}
