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
//! line and idles cleanly so the boot gate still releases the next
//! module.
//!
//! ## IPC protocol
//!
//! Endpoint 31 is registered but accepts no commands yet. Incoming
//! messages are read and dropped. Command surface lands at B-vii
//! (CCID class driver split) as the stack grows.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

mod descriptors;
mod pci;
#[allow(unsafe_code)]
mod ring;
#[allow(unsafe_code)]
mod xhci;

use cambios_libsys as sys;

const USB_HOST_ENDPOINT: u32 = 31;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[USB-HOST] PANIC!\n");
    sys::exit(1);
}

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

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Step 1: locate the xHCI controller via PCI class/subclass/prog_if.
    let dev = match pci::PciDeviceInfo::find_xhci() {
        Some(d) => d,
        None => {
            sys::print(b"[USB-HOST] no xHCI controller found, idling on ep 31\n");
            sys::register_endpoint(USB_HOST_ENDPOINT);
            sys::module_ready();
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
        sys::module_ready();
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
        sys::module_ready();
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

    // Step 6 (B-ii): HCRESET → CONFIG → DCBAA → command ring →
    // event ring → ERST → RUN. Either the full sequence succeeds and
    // we land at HCH=0 with rings live, or we log the failure mode
    // and idle. Idle-on-fail keeps the boot gate happy so downstream
    // modules still load.
    match xhci::XhciController::bring_up(mmio_vaddr, caps) {
        Ok(mut ctl) => {
            sys::print(b"[USB-HOST] controller bring-up OK\n");
            log_hex64(b"[USB-HOST]   DCBAA paddr      = ", ctl.dcbaa_paddr);
            log_hex64(b"[USB-HOST]   command ring     = ", ctl.command_ring.paddr);
            log_hex64(b"[USB-HOST]   event ring       = ", ctl.event_ring.paddr);
            log_hex64(b"[USB-HOST]   ERST paddr       = ", ctl.erst.paddr);
            log_hex64(b"[USB-HOST]   USBSTS post-RUN  = ", ctl.read_usbsts() as u64);

            // B-iii: port enumeration + first commands.
            run_b3(&mut ctl);
        }
        Err(e) => {
            log_bringup_error(e);
        }
    }

    // Step 7: register IPC endpoint and release boot gate.
    sys::register_endpoint(USB_HOST_ENDPOINT);
    sys::print(b"[USB-HOST] ready on endpoint 31\n");
    sys::module_ready();

    idle_loop();
}

// ---------------------------------------------------------------------------
// B-iii sequence: port enumeration + NoOp + Enable Slot
// ---------------------------------------------------------------------------

fn run_b3(ctl: &mut xhci::XhciController) {
    use xhci::regs::{PORTSC_CCS, PORTSC_PED, PORTSC_PP, PORTSC_PR,
                     PORTSC_SPEED_MASK, PORTSC_SPEED_SHIFT};

    // Step 1: walk the root hub ports, log each.
    let max_ports = ctl.cap.max_ports;
    sys::print(b"[USB-HOST] port enumeration:\n");
    let mut first_connected: Option<u8> = None;
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
            if first_connected.is_none() {
                first_connected = Some(i);
            }
        }
    }

    // Step 2: reset the first connected port (if any).
    let port_idx = match first_connected {
        Some(idx) => idx,
        None => {
            sys::print(b"[USB-HOST] no connected port; skipping reset + slot ops\n");
            return;
        }
    };

    sys::print(b"[USB-HOST] resetting port ");
    log_dec(b"", (port_idx + 1) as u32);
    let port_speed: u8 = match ctl.reset_port(port_idx) {
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
    };

    // Step 3: NoOp Command smoke test — proves command/event flow
    // independently of slot semantics. xHCI 1.2 § 4.6.2.
    sys::print(b"[USB-HOST] NoOp Command...\n");
    match ctl.noop_command() {
        Ok(()) => sys::print(b"[USB-HOST]   NoOp OK\n"),
        Err(e) => {
            log_b3_error(b"[USB-HOST] noop_command:", e);
            return;
        }
    }

    // Step 4: Enable Slot Command → log returned Slot ID.
    sys::print(b"[USB-HOST] Enable Slot Command...\n");
    match ctl.enable_slot() {
        Ok(slot_id) => {
            sys::print(b"[USB-HOST]   Enable Slot OK; slot_id = ");
            log_dec(b"", slot_id as u32);
            // B-iv consumes this via XhciController state.
            ctl.slot_id = Some(slot_id);
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] enable_slot:", e);
            return;
        }
    }

    // Step 5 (B-iv): Address Device — set up Input/Device Contexts +
    // EP0 transfer ring, install Device Context into DCBAA, issue
    // Address Device. xHCI 1.2 § 4.6.5.
    sys::print(b"[USB-HOST] Address Device Command...\n");
    match ctl.address_device(port_idx, port_speed) {
        Ok(slot_state) => {
            sys::print(b"[USB-HOST]   Address Device OK; slot state = ");
            log_dec(b"", slot_state as u32);
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] address_device:", e);
            return;
        }
    }

    // Step 6 (B-v): GET_DESCRIPTOR(Device) on EP0 — 3-TRB control
    // transfer (Setup / Data / Status). USB 2.0 § 9.4.3 + xHCI 1.2
    // § 4.11.2.
    sys::print(b"[USB-HOST] GET_DESCRIPTOR(Device)...\n");
    let device_desc = match ctl.get_descriptor_device() {
        Ok(desc) => {
            log_device_descriptor(&desc);
            desc
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] get_descriptor_device:", e);
            return;
        }
    };

    // Reconcile EP0 Max Packet Size with the device's actual value.
    // `address_device` set a speed-default (FS=8, HS=64, SS/SS+=512)
    // because the real value can't be known until GET_DESCRIPTOR
    // returns. xHCI 1.2 § 4.6.7's Evaluate Context Command updates
    // the EP0 endpoint context in place.
    let speed_default_mps = match port_speed {
        3 => 64,
        4 | 5 => 512,
        _ => 8,
    };
    let actual_mps = device_desc[7] as u16;
    if actual_mps != speed_default_mps {
        sys::print(b"[USB-HOST] Evaluate Context: EP0 MPS ");
        log_dec(b"", speed_default_mps as u32);
        sys::print(b"[USB-HOST]                  -> ");
        log_dec(b"", actual_mps as u32);
        match ctl.evaluate_ep0_context(actual_mps) {
            Ok(()) => sys::print(b"[USB-HOST]   Evaluate Context OK\n"),
            Err(e) => {
                log_b3_error(b"[USB-HOST] evaluate_ep0_context:", e);
                return;
            }
        }
    }

    // GET_DESCRIPTOR(Configuration): two-pass read of the full nested
    // descriptor blob (Configuration + Interface + Endpoint + class-
    // specific). USB 2.0 § 9.4.3.
    sys::print(b"[USB-HOST] GET_DESCRIPTOR(Configuration)...\n");
    let mut blob = [0u8; xhci::MAX_CONFIG_DESCRIPTOR_SIZE];
    let blob_len = match ctl.get_descriptor_configuration(&mut blob) {
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

    // Walk the blob for the CCID interface and its bulk IN + OUT
    // endpoints. CCID 1.1 § 4: bInterfaceClass = 0x0B identifies the
    // smart-card / CCID class; the interface is followed by class-
    // specific descriptors then the bulk endpoint pair.
    let ccid = match descriptors::find_ccid_interface(&blob[..blob_len]) {
        Ok(ccid) => {
            log_ccid_endpoints(&ccid);
            ccid
        }
        Err(_) => {
            sys::print(b"[USB-HOST]   no CCID interface found in config blob\n");
            return;
        }
    };

    // SET_CONFIGURATION standard request — 2-TRB no-data control
    // transfer that puts the device in Configured state. USB 2.0
    // § 9.4.7.
    sys::print(b"[USB-HOST] SET_CONFIGURATION; bConfigurationValue = ");
    log_dec(b"", ccid.configuration_value as u32);
    match ctl.set_configuration(ccid.configuration_value) {
        Ok(()) => sys::print(b"[USB-HOST]   SET_CONFIGURATION OK\n"),
        Err(e) => {
            log_b3_error(b"[USB-HOST] set_configuration:", e);
            return;
        }
    }

    // Configure Endpoint Command — installs the CCID bulk IN + bulk
    // OUT endpoint contexts in the Device Context and allocates the
    // per-endpoint transfer rings. xHCI 1.2 § 4.6.6.
    sys::print(b"[USB-HOST] Configure Endpoint Command...\n");
    match ctl.configure_endpoint(&ccid) {
        Ok(slot_state) => {
            sys::print(b"[USB-HOST]   Configure Endpoint OK; slot state = ");
            log_dec(b"", slot_state as u32);
        }
        Err(e) => {
            log_b3_error(b"[USB-HOST] configure_endpoint:", e);
        }
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
        xhci::XhciError::SlotNotEnabled |
        xhci::XhciError::EpNotReady |
        xhci::XhciError::TransferRingFull |
        xhci::XhciError::TransferTimeout |
        xhci::XhciError::TransferFailed(_) =>
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
        xhci::XhciError::SlotNotEnabled =>
            sys::print(b" slot not enabled (Address Device before Enable Slot)\n"),
        xhci::XhciError::EpNotReady =>
            sys::print(b" EP0 not ready (GET_DESCRIPTOR before Address Device)\n"),
        xhci::XhciError::TransferRingFull =>
            sys::print(b" EP0 transfer ring full (Link-wrap unimplemented)\n"),
        xhci::XhciError::TransferTimeout =>
            sys::print(b" transfer timeout (no Transfer Event)\n"),
        xhci::XhciError::TransferFailed(code) => {
            sys::print(b" transfer failed, completion code = ");
            log_dec(b"", code as u32);
        }
        _ => sys::print(b" unexpected bring-up error during B-iii/B-iv/B-v\n"),
    }
}

fn idle_loop() -> ! {
    // B-i has no IPC command surface yet. Drain any incoming message and
    // sleep; commands arrive at B-iii / B-v.
    let mut recv_buf = [0u8; 256];
    loop {
        let n = sys::try_recv_msg(USB_HOST_ENDPOINT, &mut recv_buf);
        if n <= 0 {
            sys::yield_now();
        }
    }
}
