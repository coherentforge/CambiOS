// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS USB Host Driver — Stream B, substages B-i through B-v.
//!
//! Userspace xHCI bring-up. Discovers an xHCI controller via the
//! `DeviceInfo` syscall (PCI class=0x0C, subclass=0x03, prog_if=0x30),
//! maps its MMIO BAR, parses the capability register block per xHCI
//! 1.2 § 5.3, resets the controller, sets up the Device Context Base
//! Address Array + command ring + event ring + ERST, starts the
//! controller, enumerates ports, addresses the first attached device,
//! issues a GET_DESCRIPTOR(Device) on EP0, and idles on endpoint 31.
//!
//! ## Scope — B-v
//!
//! End state: the addressed slot has answered a GET_DESCRIPTOR(Device)
//! over the EP0 control endpoint. The 18-byte Device Descriptor is in
//! a DMA buffer and parsed for logging. B-vi layers on top:
//!   - Config + interface + endpoint descriptors
//!   - SET_CONFIGURATION + Configure Endpoint command
//!   - Bulk endpoints + IRQ delivery
//!
//! On platforms where no xHCI controller is discovered (e.g. aarch64 /
//! riscv64 QEMU without `-device qemu-xhci`), the driver logs a single
//! line and idles cleanly, still pinging init ready so the boot wave
//! (ccid depends on us) proceeds.
//!
//! ## IPC protocol
//!
//! Endpoint 31 carries two opcodes for bulk-endpoint access:
//! `BULK_OUT` (0x01) and `BULK_IN` (0x02). Wire format:
//! `[opcode:1][slot_id:1][...payload]`; replies are
//! `[status:1][...result]`. Full details in `serve_loop` below.
//! usb-host owns the xHCI transport and stays protocol-agnostic;
//! CCID semantics live in `user/ccid`.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

mod descriptors;
mod hid_kbd;
mod pci;
#[allow(unsafe_code)]
mod ring;
#[allow(unsafe_code)]
mod xhci;

use cambios_libsys as sys;

const USB_HOST_ENDPOINT: u32 = 31;

/// The compositor's dedicated input endpoint (ADR-012 § Divergence
/// 2026-04-21; the Input Hub takes it over when it lands). Same
/// value virtio-input uses; writes are best-effort — on a headless
/// image nobody owns it and events are dropped.
const COMPOSITOR_INPUT_ENDPOINT: u32 = 30;

/// `InputEvent.device_id` base for boot keyboards behind this driver:
/// base + device-table index. Cosmetic until the Input Hub assigns
/// ids (ADR-012 Input-2); distinct from virtio-input's 1-based ids so
/// a mixed QEMU run tells the two apart.
const HID_KEYBOARD_DEVICE_ID: u32 = 0x100;


// ---------------------------------------------------------------------------
// Diagnostic logging
// ---------------------------------------------------------------------------

fn hex_nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

fn log_hex64(label: &[u8], v: u64) {
    sys::print(label);
    let mut buf = [b'0'; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> ((15 - i) * 4)) & 0xF) as u8;
        buf[2 + i] = hex_nibble(nib);
    }
    sys::print(&buf);
    sys::print(b"\n");
}

fn log_dec(label: &[u8], v: u32) {
    sys::print(label);
    let mut buf = [b'0'; 10];
    let mut i = 9usize;
    let mut n = v;
    if n == 0 {
        sys::print(b"0\n");
        return;
    }
    while n > 0 && i < buf.len() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if i == 0 { break; }
        i -= 1;
    }
    sys::print(&buf[i + 1..]);
    sys::print(b"\n");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

cambios_libsys_rt::service_main! {
    name: "USB-HOST",
    main: run,
}

fn run() -> ! {
    // Step 1: locate the xHCI controller via PCI class/subclass/prog_if.
    let dev = match pci::PciDeviceInfo::find_xhci() {
        Some(d) => d,
        None => {
            sys::print(b"[USB-HOST] no xHCI controller found, idling on ep 31\n");
            sys::register_endpoint(USB_HOST_ENDPOINT);
            cambios_libsys_rt::ready();
            idle_loop();
        }
    };

    // Step 2: locate the MMIO BAR. xHCI is required to expose its register
    // file via a memory BAR (xHCI 1.2 § 5.2.1); we pick the first non-zero
    // memory BAR found.
    let mut mmio_paddr: u64 = 0;
    let mut mmio_size: u32 = 0;
    for b in 0..6 {
        let bar = dev.bars[b];
        if bar.addr != 0 && !bar.is_io {
            mmio_paddr = bar.addr;
            mmio_size = bar.size;
            break;
        }
    }
    if mmio_paddr == 0 {
        sys::print(b"[USB-HOST] ERROR: xHCI found but no MMIO BAR, idling\n");
        sys::register_endpoint(USB_HOST_ENDPOINT);
        cambios_libsys_rt::ready();
        idle_loop();
    }

    // Step 3: map the BAR. xHCI register file spans capability + operational
    // + runtime + doorbell regions; map the full BAR up front so later
    // substages (B-ii operational, B-iii doorbell) don't need to re-map.
    sys::print(b"[USB-HOST] xhci detected\n");
    log_hex64(b"[USB-HOST]   MMIO paddr = ", mmio_paddr);
    log_hex64(b"[USB-HOST]   MMIO size  = ", mmio_size as u64);
    let pages = ((mmio_size as u64 + 0xFFF) / 0x1000).max(1) as u32;
    let mapped = sys::map_mmio(mmio_paddr, pages);
    if mapped < 0 {
        log_dec(b"[USB-HOST] ERROR: map_mmio failed with rc=-", (-mapped) as u32);
        sys::print(b"[USB-HOST] idling on ep 31\n");
        sys::register_endpoint(USB_HOST_ENDPOINT);
        cambios_libsys_rt::ready();
        idle_loop();
    }
    let mmio_vaddr = mapped as u64;
    log_hex64(b"[USB-HOST]   MMIO vaddr = ", mmio_vaddr);

    // Step 4: parse capability registers (xHCI 1.2 § 5.3).
    let caps = xhci::parse_capabilities(mmio_vaddr);

    // Step 5: log the cap-register dump.
    log_dec(b"[USB-HOST]   HCIVERSION = ", caps.hci_version as u32);
    log_dec(b"[USB-HOST]   CapLength  = ", caps.cap_length as u32);
    log_dec(b"[USB-HOST]   MaxSlots   = ", caps.max_slots as u32);
    log_dec(b"[USB-HOST]   MaxIntrs   = ", caps.max_intrs as u32);
    log_dec(b"[USB-HOST]   MaxPorts   = ", caps.max_ports as u32);
    log_dec(b"[USB-HOST]   MaxScrPads = ", caps.max_scratchpad_bufs);
    log_dec(b"[USB-HOST]   AC64       = ", caps.ac64 as u32);
    log_hex64(b"[USB-HOST]   DBOFF      = ", caps.doorbell_offset as u64);
    log_hex64(b"[USB-HOST]   RTSOFF     = ", caps.runtime_offset as u64);

    // Step 5b: take the controller from firmware BEFORE resetting it
    // (xHCI § 4.22.1). Real BIOSes own the xHCI for keyboard emulation
    // and get an SMI on controller events; resetting it while they own
    // it stalls the CPU in System Management Mode.
    let handoff = xhci::bios_handoff(mmio_vaddr, &caps);
    sys::print(b"[USB-HOST] BIOS handoff: ");
    sys::print(match handoff {
        xhci::Handoff::NoLegacyCapability => b"no legacy-support capability\n" as &[u8],
        xhci::Handoff::NotOwnedByBios => b"firmware did not own it; OS owner now\n",
        xhci::Handoff::Released => b"firmware released it; OS owner now\n",
        xhci::Handoff::ForcedAfterTimeout => b"firmware did not release in time; taken anyway, SMIs disabled\n",
    });

    // Step 6 (B-ii): HCRESET → CONFIG → DCBAA (+ scratchpads) → command
    // ring → event ring → ERST → RUN. Either the full sequence succeeds
    // and we land at HCH=0 with rings live, or we log the failure mode
    // and idle. Idle-on-fail still pings init ready so dependents
    // (ccid) still spawn.
    let live_ctl = match xhci::XhciController::bring_up(mmio_vaddr, caps) {
        Ok(mut ctl) => {
            sys::print(b"[USB-HOST] controller bring-up OK\n");
            log_dec(b"[USB-HOST]   scratchpad pages = ", ctl.scratchpad_pages);
            log_hex64(b"[USB-HOST]   DCBAA paddr      = ", ctl.dcbaa_paddr);
            log_hex64(b"[USB-HOST]   command ring     = ", ctl.command_ring.paddr);
            log_hex64(b"[USB-HOST]   event ring       = ", ctl.event_ring.paddr);
            log_hex64(b"[USB-HOST]   ERST paddr       = ", ctl.erst.paddr);
            log_hex64(b"[USB-HOST]   USBSTS post-RUN  = ", ctl.read_usbsts() as u64);

            // B-iii: port enumeration + first commands.
            run_b3(&mut ctl);
            Some(ctl)
        }
        Err(e) => {
            log_bringup_error(e);
            None
        }
    };

    // Step 7: register IPC endpoint and ping init ready.
    sys::register_endpoint(USB_HOST_ENDPOINT);
    sys::print(b"[USB-HOST] ready on endpoint 31\n");
    cambios_libsys_rt::ready();

    match live_ctl {
        Some(mut ctl) => serve_loop(&mut ctl),
        None => idle_loop(),
    }
}

// ---------------------------------------------------------------------------
// B-iii sequence: port enumeration + NoOp + Enable Slot
// ---------------------------------------------------------------------------

/// A root port the scan found a device on.
#[derive(Clone, Copy)]
struct ConnectedPort {
    port_idx: u8,
    portsc: u32,
}

fn run_b3(ctl: &mut xhci::XhciController) {
    use xhci::regs::{PORTSC_CCS, PORTSC_PED, PORTSC_PP, PORTSC_PR,
                     PORTSC_SPEED_MASK, PORTSC_SPEED_SHIFT};

    // Step 1: let connect detection settle, then walk the root hub
    // ports, logging each and collecting the connected ones. The
    // table is bounded by the device table: a port beyond it could
    // not be given a slot anyway.
    sys::print(b"[USB-HOST] settling ports (connect debounce)\n");
    ctl.settle_ports();
    let max_ports = ctl.cap.max_ports;
    sys::print(b"[USB-HOST] port enumeration:\n");
    let mut connected: [Option<ConnectedPort>; xhci::MAX_DEVICES] = [None; xhci::MAX_DEVICES];
    let mut n_connected = 0usize;
    let mut overflow = false;
    for i in 0..max_ports {
        let portsc = ctl.read_portsc(i);
        let ccs = portsc & PORTSC_CCS != 0;
        let ped = portsc & PORTSC_PED != 0;
        let pp  = portsc & PORTSC_PP  != 0;
        let pr  = portsc & PORTSC_PR  != 0;
        let speed = ((portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8;

        sys::print(b"[USB-HOST]   port ");
        log_dec(b"", (i + 1) as u32);
        sys::print(b"[USB-HOST]     PORTSC = ");
        log_hex64(b"", portsc as u64);
        if ccs {
            sys::print(b"[USB-HOST]     CCS=1 PED=");
            log_dec(b"", ped as u32);
            sys::print(b"[USB-HOST]     PP=");
            log_dec(b"", pp as u32);
            sys::print(b"[USB-HOST]     PR=");
            log_dec(b"", pr as u32);
            sys::print(b"[USB-HOST]     speed=");
            log_dec(b"", speed as u32);
            if n_connected < connected.len() {
                connected[n_connected] = Some(ConnectedPort { port_idx: i, portsc });
                n_connected += 1;
            } else {
                overflow = true;
            }
        }
    }
    if overflow {
        sys::print(b"[USB-HOST] more connected ports than device-table entries; later ports skipped\n");
    }
    if n_connected == 0 {
        sys::print(b"[USB-HOST] no connected port; skipping reset + slot ops\n");
        return;
    }

    // Step 2: NoOp Command smoke test — proves command/event flow
    // independently of slot semantics. xHCI 1.2 § 4.6.2.
    sys::print(b"[USB-HOST] NoOp Command...\n");
    match ctl.noop_command() {
        Ok(()) => sys::print(b"[USB-HOST]   NoOp OK\n"),
        Err(e) => {
            log_b3_error(b"[USB-HOST] noop_command:", e);
            return;
        }
    }

    // Step 3: bring up every connected port in turn. A failure on one
    // device is logged and the next port still gets its turn.
    for port in connected.iter().flatten() {
        bring_up_device(ctl, *port);
    }
}

/// Reset (USB2) or accept (USB3) the port, give the device a slot and
/// an address, read its descriptors, and hand it to the class handler
/// its configuration names. Every failure is logged and returns; the
/// device stays wherever it got to (a slot with no class handler is
/// left addressed).
fn bring_up_device(ctl: &mut xhci::XhciController, port: ConnectedPort) {
    use xhci::regs::{PORTSC_PED, PORTSC_SPEED_MASK, PORTSC_SPEED_SHIFT};

    let port_idx = port.port_idx;
    let ped = port.portsc & PORTSC_PED != 0;
    let speed = ((port.portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8;
    sys::print(b"[USB-HOST] -- device on port ");
    log_dec(b"", (port_idx + 1) as u32);

    // USB3 ports train their link themselves: PED=1 means enabled and
    // the speed field is valid, no reset needed (xHCI 1.2 § 4.19.1.2).
    // USB2 ports need a reset to enable and to learn the speed.
    let port_speed: u8 = if speed >= 4 {
        if !ped {
            sys::print(b"[USB-HOST]   SuperSpeed port not enabled; skipping\n");
            return;
        }
        sys::print(b"[USB-HOST]   SuperSpeed port already enabled; speed = ");
        log_dec(b"", speed as u32);
        speed
    } else {
        sys::print(b"[USB-HOST] resetting port ");
        log_dec(b"", (port_idx + 1) as u32);
        match ctl.reset_port(port_idx) {
            Ok(post_portsc) => {
                let ped = post_portsc & PORTSC_PED != 0;
                let speed = ((post_portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8;
                sys::print(b"[USB-HOST]   reset OK; PED=");
                log_dec(b"", ped as u32);
                sys::print(b"[USB-HOST]   port speed = ");
                log_dec(b"", speed as u32);
                speed
            }
            Err(e) => {
                log_b3_error(b"[USB-HOST] reset_port:", e);
                return;
            }
        }
    };

    // Enable Slot Command → Slot ID.
    sys::print(b"[USB-HOST] Enable Slot Command...\n");
    let slot_id = match ctl.enable_slot() {
        Ok(slot_id) => {
            sys::print(b"[USB-HOST]   Enable Slot OK; slot_id = ");
            log_dec(b"", slot_id as u32);
            slot_id
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] enable_slot:", e);
            return;
        }
    };

    // Address Device — Input/Device Contexts + EP0 transfer ring,
    // Device Context into DCBAA, SET_ADDRESS on the bus. xHCI 1.2 § 4.6.5.
    sys::print(b"[USB-HOST] Address Device Command...\n");
    let dev = match ctl.address_device(slot_id, port_idx, port_speed) {
        Ok((dev, slot_state)) => {
            sys::print(b"[USB-HOST]   Address Device OK; slot state = ");
            log_dec(b"", slot_state as u32);
            dev
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] address_device:", e);
            return;
        }
    };

    // GET_DESCRIPTOR(Device) on EP0. USB 2.0 § 9.4.3 + xHCI 1.2 § 4.11.2.
    sys::print(b"[USB-HOST] GET_DESCRIPTOR(Device)...\n");
    let device_desc = match ctl.get_descriptor_device(dev) {
        Ok(desc) => {
            log_device_descriptor(&desc);
            desc
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] get_descriptor_device:", e);
            return;
        }
    };

    // Reconcile EP0 Max Packet Size with the device's actual value
    // (xHCI 1.2 § 4.6.7 Evaluate Context).
    let speed_default_mps = match port_speed {
        3 => 64,
        4 | 5 => 512,
        _ => 8,
    };
    // USB 3.2 § 9.6.1: for SuperSpeed devices bMaxPacketSize0 is an
    // exponent (9 → 2^9 = 512); for USB2 devices it is the size itself.
    // Taking 9 literally shrank EP0 to 9 bytes and the next descriptor
    // read timed out (Realtek 0bda:0328 on the Dell 3630, 2026-10-27).
    let actual_mps: u16 = if port_speed >= 4 {
        1u16 << (device_desc[7] & 0x0F)
    } else {
        device_desc[7] as u16
    };
    if actual_mps != speed_default_mps {
        sys::print(b"[USB-HOST] Evaluate Context: EP0 MPS ");
        log_dec(b"", speed_default_mps as u32);
        sys::print(b"[USB-HOST]                  -> ");
        log_dec(b"", actual_mps as u32);
        match ctl.evaluate_ep0_context(dev, actual_mps) {
            Ok(()) => sys::print(b"[USB-HOST]   Evaluate Context OK\n"),
            Err(e) => {
                log_b3_error(b"[USB-HOST] evaluate_ep0_context:", e);
                return;
            }
        }
    }

    // GET_DESCRIPTOR(Configuration): full nested blob. USB 2.0 § 9.4.3.
    sys::print(b"[USB-HOST] GET_DESCRIPTOR(Configuration)...\n");
    let mut blob = [0u8; xhci::MAX_CONFIG_DESCRIPTOR_SIZE];
    let blob_len = match ctl.get_descriptor_configuration(dev, &mut blob) {
        Ok(n) => {
            sys::print(b"[USB-HOST]   wTotalLength = ");
            log_dec(b"", n as u32);
            n
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] get_descriptor_configuration:", e);
            return;
        }
    };

    // Class dispatch. CCID 1.1 § 4: class 0x0B, bulk pair. HID 1.11
    // § 4: class 0x03 / Boot / Keyboard, one interrupt IN endpoint.
    if let Ok(ccid) = descriptors::find_ccid_interface(&blob[..blob_len]) {
        bring_up_ccid(ctl, dev, &ccid);
    } else if let Ok(kbd) = descriptors::find_hid_boot_keyboard(&blob[..blob_len]) {
        bring_up_hid_keyboard(ctl, dev, &kbd);
    } else {
        sys::print(b"[USB-HOST]   no class handler for this device; left addressed\n");
    }
}

/// CCID: configure, then install the bulk IN + OUT endpoints. The
/// `ccid` service drives them over IPC once boot completes.
fn bring_up_ccid(ctl: &mut xhci::XhciController, dev: usize, ccid: &descriptors::CcidEndpoints) {
    log_ccid_endpoints(ccid);

    // SET_CONFIGURATION — puts the device in Configured state. USB 2.0 § 9.4.7.
    sys::print(b"[USB-HOST] SET_CONFIGURATION; bConfigurationValue = ");
    log_dec(b"", ccid.configuration_value as u32);
    match ctl.set_configuration(dev, ccid.configuration_value) {
        Ok(()) => sys::print(b"[USB-HOST]   SET_CONFIGURATION OK\n"),
        Err(e) => {
            log_b3_error(b"[USB-HOST] set_configuration:", e);
            return;
        }
    }

    // Configure Endpoint — bulk IN + OUT contexts + transfer rings. xHCI 1.2 § 4.6.6.
    sys::print(b"[USB-HOST] Configure Endpoint Command...\n");
    match ctl.configure_endpoint(dev, ccid) {
        Ok(slot_state) => {
            sys::print(b"[USB-HOST]   Configure Endpoint OK; slot state = ");
            log_dec(b"", slot_state as u32);
            if let Some((in_dci, out_dci)) = ctl.device(dev).ok().and_then(|d| d.ccid_dcis()) {
                sys::print(b"[USB-HOST]   bulk IN  DCI=");
                log_dec(b"", in_dci as u32);
                sys::print(b"[USB-HOST]   bulk OUT DCI=");
                log_dec(b"", out_dci as u32);
            }
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] configure_endpoint:", e);
        }
    }
}

/// HID boot keyboard: configure, select Boot Protocol, idle-on-change,
/// install the interrupt IN endpoint, and queue the first report
/// transfer. Reports are then collected by `poll_keyboard` from the
/// serve loop.
fn bring_up_hid_keyboard(
    ctl: &mut xhci::XhciController,
    dev: usize,
    kbd: &descriptors::HidBootKeyboard,
) {
    sys::print(b"[USB-HOST]   HID boot keyboard interface found:\n");
    sys::print(b"[USB-HOST]     bInterfaceNumber = ");
    log_dec(b"", kbd.interface_number as u32);
    sys::print(b"[USB-HOST]     interrupt IN addr = ");
    log_hex64(b"", kbd.interrupt_in.address as u64);
    sys::print(b"[USB-HOST]              MPS  = ");
    log_dec(b"", kbd.interrupt_in.max_packet_size_bytes() as u32);
    sys::print(b"[USB-HOST]              bInterval = ");
    log_dec(b"", kbd.interrupt_in.interval as u32);

    sys::print(b"[USB-HOST] SET_CONFIGURATION; bConfigurationValue = ");
    log_dec(b"", kbd.configuration_value as u32);
    if let Err(e) = ctl.set_configuration(dev, kbd.configuration_value) {
        log_b3_error(b"[USB-HOST] set_configuration:", e);
        return;
    }
    sys::print(b"[USB-HOST] SET_PROTOCOL(Boot)...\n");
    if let Err(e) = ctl.set_protocol_boot(dev, kbd.interface_number) {
        log_b3_error(b"[USB-HOST] set_protocol_boot:", e);
        return;
    }
    sys::print(b"[USB-HOST] SET_IDLE(on change)...\n");
    if let Err(e) = ctl.set_idle_on_change(dev, kbd.interface_number) {
        // Optional for a boot keyboard; log and continue without it.
        log_b3_error(b"[USB-HOST] set_idle (ignored):", e);
    }
    sys::print(b"[USB-HOST] Configure Endpoint (interrupt IN)...\n");
    match ctl.configure_interrupt_in(dev, &kbd.interrupt_in) {
        Ok(slot_state) => {
            sys::print(b"[USB-HOST]   Configure Endpoint OK; slot state = ");
            log_dec(b"", slot_state as u32);
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] configure_interrupt_in:", e);
            return;
        }
    }
    match ctl.interrupt_in_submit(dev) {
        Ok(()) => sys::print(b"[USB-HOST]   keyboard armed; reports go to the input endpoint\n"),
        Err(e) => log_b3_error(b"[USB-HOST] interrupt_in_submit:", e),
    }
}

fn log_ccid_endpoints(ccid: &descriptors::CcidEndpoints) {
    sys::print(b"[USB-HOST]   CCID interface found:\n");
    sys::print(b"[USB-HOST]     bConfigurationValue = ");
    log_dec(b"", ccid.configuration_value as u32);
    sys::print(b"[USB-HOST]     bInterfaceNumber = ");
    log_dec(b"", ccid.interface_number as u32);
    sys::print(b"[USB-HOST]     bulk IN  addr = ");
    log_hex64(b"", ccid.bulk_in.address as u64);
    sys::print(b"[USB-HOST]              MPS  = ");
    log_dec(b"", ccid.bulk_in.max_packet_size_bytes() as u32);
    sys::print(b"[USB-HOST]     bulk OUT addr = ");
    log_hex64(b"", ccid.bulk_out.address as u64);
    sys::print(b"[USB-HOST]              MPS  = ");
    log_dec(b"", ccid.bulk_out.max_packet_size_bytes() as u32);
}

/// Pretty-print the 18-byte Device Descriptor (USB 2.0 § 9.6.1).
///
/// Field layout (offsets):
///   0   bLength
///   1   bDescriptorType
///   2-3 bcdUSB           (little-endian)
///   4   bDeviceClass
///   5   bDeviceSubClass
///   6   bDeviceProtocol
///   7   bMaxPacketSize0
///   8-9 idVendor         (little-endian)
///   10-11 idProduct      (little-endian)
///   12-13 bcdDevice      (little-endian)
///   14  iManufacturer
///   15  iProduct
///   16  iSerialNumber
///   17  bNumConfigurations
///
/// `bMaxPacketSize0` is compared against the speed-default the
/// driver set in `address_device`. If the device reports a different
/// MPS, an Evaluate Context command is required to update the EP0
/// context — not implemented today; for QEMU usb-ccid at Full Speed
/// the default of 8 is spec-correct, so the warning won't fire in
/// the bring-up path.
/// Revisit when: a device reports `bMaxPacketSize0` != the
/// driver's address_device default (warn-log fires), at which
/// point Evaluate Context implementation becomes load-bearing.
fn log_device_descriptor(desc: &[u8; 18]) {
    let bcd_usb = u16::from_le_bytes([desc[2], desc[3]]);
    let id_vendor = u16::from_le_bytes([desc[8], desc[9]]);
    let id_product = u16::from_le_bytes([desc[10], desc[11]]);
    let bcd_device = u16::from_le_bytes([desc[12], desc[13]]);

    sys::print(b"[USB-HOST]   bLength = ");
    log_dec(b"", desc[0] as u32);
    sys::print(b"[USB-HOST]   bDescriptorType = ");
    log_dec(b"", desc[1] as u32);
    sys::print(b"[USB-HOST]   bcdUSB = ");
    log_hex64(b"", bcd_usb as u64);
    sys::print(b"[USB-HOST]   bDeviceClass = ");
    log_dec(b"", desc[4] as u32);
    sys::print(b"[USB-HOST]   bDeviceSubClass = ");
    log_dec(b"", desc[5] as u32);
    sys::print(b"[USB-HOST]   bDeviceProtocol = ");
    log_dec(b"", desc[6] as u32);
    sys::print(b"[USB-HOST]   bMaxPacketSize0 = ");
    log_dec(b"", desc[7] as u32);
    sys::print(b"[USB-HOST]   idVendor = ");
    log_hex64(b"", id_vendor as u64);
    sys::print(b"[USB-HOST]   idProduct = ");
    log_hex64(b"", id_product as u64);
    sys::print(b"[USB-HOST]   bcdDevice = ");
    log_hex64(b"", bcd_device as u64);
    sys::print(b"[USB-HOST]   bNumConfigurations = ");
    log_dec(b"", desc[17] as u32);
}

fn log_bringup_error(e: xhci::XhciError) {
    match e {
        xhci::XhciError::HaltTimeout =>
            sys::print(b"[USB-HOST] ERROR: HCH never set; controller did not halt\n"),
        xhci::XhciError::ResetTimeout =>
            sys::print(b"[USB-HOST] ERROR: HCRST never cleared; controller did not reset\n"),
        xhci::XhciError::NotReadyTimeout =>
            sys::print(b"[USB-HOST] ERROR: CNR never cleared; controller stayed not-ready\n"),
        xhci::XhciError::RunTimeout =>
            sys::print(b"[USB-HOST] ERROR: HCH never cleared after RUN; controller did not start\n"),
        xhci::XhciError::DmaAllocFailed =>
            sys::print(b"[USB-HOST] ERROR: alloc_dma failed during ring setup\n"),
        // B-iii / B-iv / B-v variants can't reach this path —
        // `bring_up` doesn't issue commands, touch ports, or run
        // transfers. Handled explicitly so future bring-up additions
        // don't silently fall through.
        xhci::XhciError::PortResetTimeout |
        xhci::XhciError::CommandRingFull |
        xhci::XhciError::CommandTimeout |
        xhci::XhciError::CommandFailed(_) |
        xhci::XhciError::EpNotReady |
        xhci::XhciError::TransferRingFull |
        xhci::XhciError::TransferTimeout |
        xhci::XhciError::TransferFailed(_) |
        xhci::XhciError::DeviceTableFull =>
            sys::print(b"[USB-HOST] ERROR: unexpected post-bring-up error during bring-up\n"),
    }
}

fn log_b3_error(prefix: &[u8], e: xhci::XhciError) {
    sys::print(prefix);
    match e {
        xhci::XhciError::PortResetTimeout =>
            sys::print(b" port reset timeout (PRC never set)\n"),
        xhci::XhciError::CommandRingFull =>
            sys::print(b" command ring full (Link-wrap unimplemented)\n"),
        xhci::XhciError::CommandTimeout =>
            sys::print(b" command timeout (no completion event)\n"),
        xhci::XhciError::CommandFailed(code) => {
            sys::print(b" command failed, completion code = ");
            log_dec(b"", code as u32);
        }
        xhci::XhciError::EpNotReady =>
            sys::print(b" EP0 not ready (GET_DESCRIPTOR before Address Device)\n"),
        xhci::XhciError::TransferRingFull =>
            sys::print(b" EP0 transfer ring full (Link-wrap unimplemented)\n"),
        xhci::XhciError::TransferTimeout =>
            sys::print(b" transfer timeout (no Transfer Event)\n"),
        xhci::XhciError::DeviceTableFull => {
            sys::print(b" device table full\n");
        }
        xhci::XhciError::TransferFailed(code) => {
            sys::print(b" transfer failed, completion code = ");
            log_dec(b"", code as u32);
        }
        _ => sys::print(b" unexpected bring-up error during B-iii/B-iv/B-v\n"),
    }
}

// ---------------------------------------------------------------------------
// IPC ABI on USB_HOST_ENDPOINT (31)
// ---------------------------------------------------------------------------
//
// Wire format on every incoming message:
//
//     [opcode:1][slot_id:1][...payload]
//
// Reply (sent to the caller's reply endpoint):
//
//     [status:1][...result]
//
// Opcodes:
//
//   OP_BULK_OUT (0x01):
//     request payload  = bytes to send on the slot's bulk OUT
//                        endpoint (up to MAX_BULK_PAYLOAD)
//     reply            = [status:1][bytes_written:2] (LE u16)
//
//   OP_BULK_IN (0x02):
//     request payload  = [requested_len:2] (LE u16, ≤ MAX_BULK_PAYLOAD)
//     reply            = [status:1][actual_len:2][bytes:N]
//
// Status bytes (one byte, distinct from the controller's
// XhciError set so clients don't need to track xhci internals):
//
//   STATUS_OK              = 0
//   STATUS_INVALID_OPCODE  = 1
//   STATUS_TRUNCATED       = 2  (request payload too short)
//   STATUS_PAYLOAD_TOO_BIG = 3
//   STATUS_DEVICE_NOT_READY = 4 (no controller / no bulk endpoints)
//   STATUS_XHCI_ERROR      = 5  (any XhciError; details in serial log)
//
// The slot byte is carried but not consulted: usb-host enumerates
// every connected root port, and routes bulk requests to the one
// device whose class handler is CCID (`XhciController::ccid_device`).
// Revisit when: a second CCID-class device is attached at once and
// the ccid service needs to name which one.

const OP_BULK_OUT: u8 = 0x01;
const OP_BULK_IN: u8 = 0x02;

const STATUS_OK: u8 = 0;
const STATUS_INVALID_OPCODE: u8 = 1;
const STATUS_TRUNCATED: u8 = 2;
const STATUS_PAYLOAD_TOO_BIG: u8 = 3;
const STATUS_DEVICE_NOT_READY: u8 = 4;
const STATUS_XHCI_ERROR: u8 = 5;

/// SCAFFOLDING: max bytes a single bulk OUT request or IN response
/// can carry inline in an IPC message. The kernel IPC control
/// message budget is 256 bytes; minus 36-byte recv_msg envelope
/// (sender_principal:32 + from_endpoint:4) minus our [opcode][slot]
/// header (2 bytes) minus the reply's [status][actual_len] header
/// (3 bytes), we have ~215 bytes of headroom. 192 = round-down to
/// the next power of two below that, comfortably above CCID
/// PC_to_RDR_GetSlotStatus (10 bytes) + extended APDU (~270 bytes
/// is over budget but extended APDUs need the channel substrate
/// regardless, so no point pushing this higher).
/// Replace when: extended APDUs land and ccid switches to the
/// channel substrate for >MAX_BULK_PAYLOAD transfers.
const MAX_BULK_PAYLOAD: usize = 192;

/// Receive-buffer size: 36-byte envelope + 2-byte header + up to
/// MAX_BULK_PAYLOAD inline data, rounded up. The kernel IPC layer
/// caps recv_msg at 256 anyway.
const RECV_BUF_SIZE: usize = 256;

/// Keyboard side of the serve loop. `Armed` while a report transfer
/// is queued or re-queued after each completion; `Dead` after a
/// transfer error (device gone, STALL), logged once.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyboardPump {
    Absent,
    Armed,
    Dead,
}

struct KeyboardSession {
    pump: KeyboardPump,
    state: hid_kbd::BootKeyboardState,
    seq: u16,
    reports_seen: u32,
}

impl KeyboardSession {
    fn for_device(ctl: &xhci::XhciController, dev: usize) -> Self {
        let is_keyboard = ctl.device(dev).map(|d| d.is_keyboard()).unwrap_or(false);
        Self {
            pump: if is_keyboard { KeyboardPump::Armed } else { KeyboardPump::Absent },
            state: hid_kbd::BootKeyboardState::new(),
            seq: 0,
            reports_seen: 0,
        }
    }
}

#[allow(unsafe_code)]
fn serve_loop(ctl: &mut xhci::XhciController) -> ! {
    let mut recv_buf = [0u8; RECV_BUF_SIZE];
    // One session per device-table entry; only keyboards are Armed.
    let mut sessions: [KeyboardSession; xhci::MAX_DEVICES] =
        core::array::from_fn(|dev| KeyboardSession::for_device(ctl, dev));
    loop {
        // Anonymous callers (None return path) get silently dropped —
        // no auth, no reply. This is the "no identity, no
        // participation" floor: the bulk transport is downstream of
        // the vault's authority check (ADR-033), and refusing
        // anonymous senders here closes the bypass path that would
        // otherwise let a process skip the vault and drive the
        // hardware token directly. Non-blocking so the keyboard pump
        // below keeps running between requests.
        if let Some(msg) = sys::try_recv_verified(USB_HOST_ENDPOINT, &mut recv_buf) {
            handle_request(ctl, msg.from_endpoint(), msg.payload());
        }
        for (dev, session) in sessions.iter_mut().enumerate() {
            if session.pump == KeyboardPump::Armed {
                poll_keyboard(ctl, dev, session);
            }
        }
        sys::yield_now();
    }
}

/// Collect a completed report, turn it into key transitions, send
/// each as an ADR-012 `InputEvent`, and re-arm the transfer.
fn poll_keyboard(ctl: &mut xhci::XhciController, dev: usize, kbd: &mut KeyboardSession) {
    use cambios_libinput_proto::{
        encode_event, hid_to_ascii_us, EventType, InputEvent, KeyboardPayload, EVENT_SIZE,
    };
    use hid_kbd::{KeyTransition, BOOT_REPORT_LEN, MAX_TRANSITIONS};

    let report = match ctl.interrupt_in_poll(dev) {
        Ok(Some(r)) => r,
        Ok(None) => return,
        Err(e) => {
            log_b3_error(b"[USB-HOST] keyboard transfer failed; keyboard stopped:", e);
            kbd.pump = KeyboardPump::Dead;
            return;
        }
    };
    if kbd.reports_seen == 0 {
        sys::print(b"[USB-HOST] keyboard: first report received\n");
    }
    kbd.reports_seen = kbd.reports_seen.wrapping_add(1);

    if report.len >= BOOT_REPORT_LEN {
        let mut boot = [0u8; BOOT_REPORT_LEN];
        boot.copy_from_slice(&report.data[..BOOT_REPORT_LEN]);
        let mut transitions = [KeyTransition::Up(0); MAX_TRANSITIONS];
        let n = kbd.state.apply(&boot, &mut transitions);
        let modifiers = kbd.state.modifiers() as u16;
        for t in transitions.iter().take(n) {
            let (event_type, usage) = match *t {
                KeyTransition::Down(u) => (EventType::KeyDown, u),
                KeyTransition::Up(u) => (EventType::KeyUp, u),
            };
            let payload = KeyboardPayload {
                keycode: usage as u32,
                modifiers,
                unicode: hid_to_ascii_us(usage as u32, modifiers),
            };
            kbd.seq = kbd.seq.wrapping_add(1);
            let event = InputEvent::key(
                event_type,
                HID_KEYBOARD_DEVICE_ID + dev as u32,
                kbd.seq,
                sys::get_time(),
                payload,
            );
            let mut buf = [0u8; EVENT_SIZE];
            if let Some(len) = encode_event(&mut buf, &event) {
                // Best-effort: input is lossy by nature, and on a
                // headless image nobody owns the endpoint.
                let _ = sys::write(COMPOSITOR_INPUT_ENDPOINT, &buf[..len]);
            }
        }
    }

    if let Err(e) = ctl.interrupt_in_submit(dev) {
        log_b3_error(b"[USB-HOST] keyboard re-arm failed; keyboard stopped:", e);
        kbd.pump = KeyboardPump::Dead;
    }
}

#[allow(unsafe_code)]
fn handle_request(
    ctl: &mut xhci::XhciController,
    reply_ep: u32,
    payload: &[u8],
) {
    if payload.len() < 2 {
        reply_status(reply_ep, STATUS_TRUNCATED);
        return;
    }
    let opcode = payload[0];
    let _slot = payload[1]; // usb-host routes to its one CCID device (see Revisit-when above)
    let rest = &payload[2..];
    match opcode {
        OP_BULK_OUT => handle_bulk_out(ctl, reply_ep, rest),
        OP_BULK_IN => handle_bulk_in(ctl, reply_ep, rest),
        _ => reply_status(reply_ep, STATUS_INVALID_OPCODE),
    }
}

#[allow(unsafe_code)]
fn handle_bulk_out(
    ctl: &mut xhci::XhciController,
    reply_ep: u32,
    bytes: &[u8],
) {
    if bytes.len() > MAX_BULK_PAYLOAD {
        reply_status(reply_ep, STATUS_PAYLOAD_TOO_BIG);
        return;
    }
    let dev = match ctl.ccid_device() {
        Some(d) => d,
        None => {
            reply_status(reply_ep, STATUS_DEVICE_NOT_READY);
            return;
        }
    };
    // Copy payload into a DMA page, then issue bulk OUT.
    let (paddr, vaddr) = match xhci::XhciController::alloc_zeroed_page() {
        Ok(p) => p,
        Err(_) => {
            reply_status(reply_ep, STATUS_XHCI_ERROR);
            return;
        }
    };
    // SAFETY: vaddr is the freshly-allocated DMA page, owned
    // exclusively here; bytes.len() ≤ MAX_BULK_PAYLOAD ≪ 4 KiB.
    unsafe {
        let dst = vaddr as *mut u8;
        for (i, b) in bytes.iter().enumerate() {
            core::ptr::write_volatile(dst.add(i), *b);
        }
    }
    let written = match ctl.bulk_transfer(dev, xhci::BulkDir::Out, paddr, bytes.len() as u32) {
        Ok(n) => n,
        Err(_) => {
            reply_status(reply_ep, STATUS_XHCI_ERROR);
            return;
        }
    };
    // Reply: [status:1][bytes_written:2 LE].
    let mut reply = [0u8; 3];
    reply[0] = STATUS_OK;
    reply[1] = (written & 0xFF) as u8;
    reply[2] = ((written >> 8) & 0xFF) as u8;
    sys::write(reply_ep, &reply);
}

#[allow(unsafe_code)]
fn handle_bulk_in(
    ctl: &mut xhci::XhciController,
    reply_ep: u32,
    args: &[u8],
) {
    if args.len() < 2 {
        reply_status(reply_ep, STATUS_TRUNCATED);
        return;
    }
    let requested_len = u16::from_le_bytes([args[0], args[1]]) as usize;
    if requested_len > MAX_BULK_PAYLOAD {
        reply_status(reply_ep, STATUS_PAYLOAD_TOO_BIG);
        return;
    }
    let dev = match ctl.ccid_device() {
        Some(d) => d,
        None => {
            reply_status(reply_ep, STATUS_DEVICE_NOT_READY);
            return;
        }
    };
    let (paddr, vaddr) = match xhci::XhciController::alloc_zeroed_page() {
        Ok(p) => p,
        Err(_) => {
            reply_status(reply_ep, STATUS_XHCI_ERROR);
            return;
        }
    };
    let actual = match ctl.bulk_transfer(dev, xhci::BulkDir::In, paddr, requested_len as u32) {
        Ok(n) => n as usize,
        Err(_) => {
            reply_status(reply_ep, STATUS_XHCI_ERROR);
            return;
        }
    };
    // Reply: [status:1][actual_len:2 LE][bytes:actual]
    let mut reply = [0u8; 3 + MAX_BULK_PAYLOAD];
    reply[0] = STATUS_OK;
    reply[1] = (actual & 0xFF) as u8;
    reply[2] = ((actual >> 8) & 0xFF) as u8;
    // SAFETY: vaddr is the DMA page the controller wrote into;
    // `actual` ≤ requested_len ≤ MAX_BULK_PAYLOAD ≪ 4 KiB.
    unsafe {
        let src = vaddr as *const u8;
        for i in 0..actual {
            reply[3 + i] = core::ptr::read_volatile(src.add(i));
        }
    }
    sys::write(reply_ep, &reply[..3 + actual]);
}

fn reply_status(reply_ep: u32, status: u8) {
    sys::write(reply_ep, &[status]);
}

/// Idle for boots where no xHCI controller was found / bring-up
/// failed. usb-host still registers its endpoint and pings init ready
/// so dependents still spawn, but every incoming request gets
/// `STATUS_DEVICE_NOT_READY`.
fn idle_loop() -> ! {
    let mut recv_buf = [0u8; RECV_BUF_SIZE];
    loop {
        // Same recv_verified posture as serve_loop — anonymous
        // callers get dropped before any reply. Verified callers
        // get a typed `STATUS_DEVICE_NOT_READY` so they know the
        // service is up but no controller is attached.
        let msg = match sys::recv_verified(USB_HOST_ENDPOINT, &mut recv_buf) {
            Some(m) => m,
            None => continue,
        };
        reply_status(msg.from_endpoint(), STATUS_DEVICE_NOT_READY);
    }
}
