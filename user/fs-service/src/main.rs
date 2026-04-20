// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS Filesystem Service — user-space ObjectStore gateway
//!
//! Runs as a ring-3 process. Registers IPC endpoint 16, receives requests
//! from clients over IPC, enforces ownership via `sender_principal`, and
//! delegates to kernel ObjectStore syscalls.
//!
//! # Two dispatch layers
//!
//! - **Hash-addressed** (pre-existing): PUT, GET, DELETE, LIST — callers
//!   hold the 32-byte content hash themselves.
//! - **Name-binding** (Phase 3 stub): GET_BY_NAME, PUT_BY_NAME, STAT,
//!   LIST_NAMED, REMOVE, RENAME, GRANT, TRANSFER — a fixed-size in-memory
//!   name→hash table lets clients refer to objects by human-readable
//!   names. This is the forward contract; persistence, ACLs, and
//!   ownership-transfer join later without changing the wire format.
//!
//! See `arcos-libfs::proto` for the wire constants.

#![no_std]
#![no_main]

use arcos_libfs_proto as proto;
use arcos_libsys as sys;

// ============================================================================
// Panic handler (required for no_std)
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[FS] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// Key Store interaction (endpoint 17)
// ============================================================================

const KS_ENDPOINT: u32 = 17;
const KS_CMD_SIGN: u8 = 1;
const FS_ENDPOINT: u32 = proto::FS_ENDPOINT;

/// Request a signature from the key-store service.
/// Returns Some(signature) on success, None if key-store is unavailable.
fn request_sign(content: &[u8]) -> Option<[u8; 64]> {
    if content.is_empty() || content.len() > 254 {
        return None;
    }

    let mut req = [0u8; 256];
    req[0] = KS_CMD_SIGN;
    req[1..1 + content.len()].copy_from_slice(content);
    let req_len = 1 + content.len();

    let ret = sys::write(KS_ENDPOINT, &req[..req_len]);
    if ret < 0 {
        return None;
    }

    let mut resp_buf = [0u8; 256];
    for _ in 0..20 {
        let n = sys::recv_msg(FS_ENDPOINT, &mut resp_buf);
        if n > 0 {
            let total = n as usize;
            if total >= 36 + 65 {
                let status = resp_buf[36];
                if status == 0 {
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&resp_buf[37..101]);
                    return Some(sig);
                }
            }
            return None;
        }
        sys::yield_now();
    }
    None
}

// ============================================================================
// Name table (Phase 3 in-memory stub)
// ============================================================================
//
// SCAFFOLDING: fixed-size in-memory name→hash index. Upgrades to a
// persistent, disk-backed index when the real filesystem layer lands;
// wire protocol stays identical.
// Why: lets the shell and nano-style editor address objects by name today
// without blocking on persistent storage.
// Replace when: persistent name index ships (tracked in plan phase
// post-libfs).

const MAX_NAMES: usize = 64;

#[derive(Clone, Copy)]
struct NameEntry {
    used: bool,
    name_len: u8,
    name: [u8; proto::MAX_NAME_LEN],
    hash: [u8; 32],
    size: u32,
    author: [u8; 32],
    owner: [u8; 32],
    content_type: u8,
    has_lineage: bool,
    lineage_parent: [u8; 32],
}

impl NameEntry {
    const EMPTY: Self = Self {
        used: false,
        name_len: 0,
        name: [0; proto::MAX_NAME_LEN],
        hash: [0; 32],
        size: 0,
        author: [0; 32],
        owner: [0; 32],
        content_type: 0,
        has_lineage: false,
        lineage_parent: [0; 32],
    };

    fn as_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// Single-threaded user process: access via a zero-cost wrapper to keep
// `unsafe` local to one module.
mod table {
    use super::{NameEntry, MAX_NAMES};

    #[allow(unsafe_code)]
    static mut NAMES: [NameEntry; MAX_NAMES] = [NameEntry::EMPTY; MAX_NAMES];

    /// # Safety
    /// fs-service is single-threaded; all callers are inside the same
    /// service loop and never re-enter. No aliasing possible.
    #[allow(unsafe_code)]
    pub fn entries() -> &'static mut [NameEntry; MAX_NAMES] {
        // SAFETY: single-threaded userspace service. The service loop
        // processes one request at a time, so there is no possible
        // overlapping borrow.
        unsafe { &mut *core::ptr::addr_of_mut!(NAMES) }
    }
}

fn find_by_name(name: &[u8]) -> Option<usize> {
    let entries = table::entries();
    let mut i = 0;
    while i < MAX_NAMES {
        if entries[i].used && entries[i].as_name() == name {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_free() -> Option<usize> {
    let entries = table::entries();
    let mut i = 0;
    while i < MAX_NAMES {
        if !entries[i].used {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Bind `name` to `hash`, overwriting any existing entry with the same name.
fn bind_name(
    name: &[u8],
    hash: &[u8; 32],
    size: u32,
    author: &[u8; 32],
    owner: &[u8; 32],
    content_type: u8,
    parent: Option<&[u8; 32]>,
) -> bool {
    let slot = find_by_name(name).or_else(find_free);
    let slot = match slot {
        Some(i) => i,
        None => return false,
    };
    let entries = table::entries();
    let e = &mut entries[slot];
    e.used = true;
    e.name_len = name.len() as u8;
    e.name[..name.len()].copy_from_slice(name);
    e.hash = *hash;
    e.size = size;
    e.author = *author;
    e.owner = *owner;
    e.content_type = content_type;
    if let Some(p) = parent {
        e.has_lineage = true;
        e.lineage_parent = *p;
    } else {
        e.has_lineage = false;
        e.lineage_parent = [0; 32];
    }
    true
}

// ============================================================================
// Handlers — hash-addressed (existing, unchanged)
// ============================================================================

use proto::{
    CMD_DELETE, CMD_GET, CMD_GET_BY_NAME, CMD_GRANT, CMD_LIST, CMD_LIST_NAMED, CMD_PUT,
    CMD_PUT_BY_NAME, CMD_REMOVE, CMD_RENAME, CMD_STAT, CMD_TRANSFER, MAX_CONTENT_LEN, MAX_NAME_LEN,
    STATUS_ALREADY_EXISTS, STATUS_DENIED, STATUS_FULL, STATUS_INVALID, STATUS_NOT_FOUND,
    STATUS_NOT_IMPLEMENTED, STATUS_OK, STAT_FIXED_LEN, STAT_OFF_ACL_IS_PUBLIC, STAT_OFF_AUTHOR,
    STAT_OFF_CONTENT_TYPE, STAT_OFF_HAS_LINEAGE, STAT_OFF_HASH, STAT_OFF_LINEAGE_PARENT,
    STAT_OFF_NAME, STAT_OFF_NAME_LEN, STAT_OFF_OWNER, STAT_OFF_SIZE,
};

fn handle_put(payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let sig = match request_sign(payload) {
        Some(sig) => sig,
        None => {
            response[0] = STATUS_DENIED;
            return 1;
        }
    };
    let mut hash = [0u8; 32];
    let ret = sys::obj_put_signed(payload, &sig, &mut hash);
    if ret < 0 {
        response[0] = STATUS_FULL;
        return 1;
    }
    response[0] = STATUS_OK;
    response[1..33].copy_from_slice(&hash);
    33
}

fn handle_get(payload: &[u8], response: &mut [u8]) -> usize {
    if payload.len() < 32 {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload[..32]);
    let mut content_buf = [0u8; 255];
    let ret = sys::obj_get(&hash, &mut content_buf);
    if ret < 0 {
        response[0] = STATUS_NOT_FOUND;
        return 1;
    }
    let n = ret as usize;
    response[0] = STATUS_OK;
    response[1..1 + n].copy_from_slice(&content_buf[..n]);
    1 + n
}

fn handle_delete(payload: &[u8], response: &mut [u8]) -> usize {
    if payload.len() < 32 {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload[..32]);
    let ret = sys::obj_delete(&hash);
    response[0] = match ret {
        0 => STATUS_OK,
        -2 => STATUS_DENIED,
        -4 => STATUS_NOT_FOUND,
        _ => STATUS_INVALID,
    };
    1
}

fn handle_list(response: &mut [u8]) -> usize {
    let max_hashes = (response.len() - 2) / 32;
    let buf_size = max_hashes * 32;
    let mut hash_buf = [0u8; 224];
    let actual_buf_len = core::cmp::min(buf_size, 224);
    let ret = sys::obj_list(&mut hash_buf[..actual_buf_len]);
    if ret < 0 {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let count = ret as usize;
    response[0] = STATUS_OK;
    response[1] = count as u8;
    let hash_bytes = count * 32;
    response[2..2 + hash_bytes].copy_from_slice(&hash_buf[..hash_bytes]);
    2 + hash_bytes
}

// ============================================================================
// Handlers — name-binding (Phase 3 stub)
// ============================================================================

/// Decode a `[name_len:1][name:N]` payload prefix, validating `name_len`.
fn read_name<'a>(payload: &'a [u8], off: usize) -> Option<&'a [u8]> {
    if off >= payload.len() {
        return None;
    }
    let name_len = payload[off] as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        return None;
    }
    if off + 1 + name_len > payload.len() {
        return None;
    }
    Some(&payload[off + 1..off + 1 + name_len])
}

fn handle_get_by_name(payload: &[u8], response: &mut [u8]) -> usize {
    let name = match read_name(payload, 0) {
        Some(n) => n,
        None => {
            response[0] = STATUS_INVALID;
            return 1;
        }
    };
    let idx = match find_by_name(name) {
        Some(i) => i,
        None => {
            response[0] = STATUS_NOT_FOUND;
            return 1;
        }
    };
    let entries = table::entries();
    let e = &entries[idx];
    let hash = e.hash;

    let mut content_buf = [0u8; MAX_CONTENT_LEN];
    let ret = sys::obj_get(&hash, &mut content_buf);
    if ret < 0 {
        response[0] = STATUS_NOT_FOUND;
        return 1;
    }
    let n = ret as usize;
    // Response: [STATUS_OK][size:4 LE][hash:32][content:N]
    response[0] = STATUS_OK;
    response[1..5].copy_from_slice(&(n as u32).to_le_bytes());
    response[5..37].copy_from_slice(&hash);
    response[37..37 + n].copy_from_slice(&content_buf[..n]);
    37 + n
}

fn handle_put_by_name(
    payload: &[u8],
    sender: &[u8; 32],
    response: &mut [u8],
) -> usize {
    // Request payload (after CMD byte): [name_len:1][has_parent:1][parent:32]
    //                                    [content_type:1][content_len:4]
    //                                    [name:N][content:M]
    if payload.len() < 1 + 1 + 32 + 1 + 4 {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let name_len = payload[0] as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let has_parent = payload[1] != 0;
    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(&payload[2..34]);
    let content_type = payload[34];
    let content_len = u32::from_le_bytes([payload[35], payload[36], payload[37], payload[38]])
        as usize;
    if content_len > MAX_CONTENT_LEN {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let name_off = 39;
    if payload.len() < name_off + name_len + content_len {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let name = &payload[name_off..name_off + name_len];
    let content = &payload[name_off + name_len..name_off + name_len + content_len];

    // Sign + put into the underlying ObjectStore (matches existing PUT path).
    let sig = match request_sign(content) {
        Some(sig) => sig,
        None => {
            response[0] = STATUS_DENIED;
            return 1;
        }
    };
    let mut hash = [0u8; 32];
    if sys::obj_put_signed(content, &sig, &mut hash) < 0 {
        response[0] = STATUS_FULL;
        return 1;
    }

    // Bind the name. v1 stub: author = owner = sender_principal.
    let parent_opt = if has_parent { Some(&parent_hash) } else { None };
    if !bind_name(
        name,
        &hash,
        content_len as u32,
        sender,
        sender,
        content_type,
        parent_opt,
    ) {
        response[0] = STATUS_FULL;
        return 1;
    }

    response[0] = STATUS_OK;
    response[1..33].copy_from_slice(&hash);
    33
}

fn handle_stat(payload: &[u8], response: &mut [u8]) -> usize {
    let name = match read_name(payload, 0) {
        Some(n) => n,
        None => {
            response[0] = STATUS_INVALID;
            return 1;
        }
    };
    let idx = match find_by_name(name) {
        Some(i) => i,
        None => {
            response[0] = STATUS_NOT_FOUND;
            return 1;
        }
    };
    let entries = table::entries();
    let e = &entries[idx];

    response[0] = STATUS_OK;
    response[STAT_OFF_HASH..STAT_OFF_HASH + 32].copy_from_slice(&e.hash);
    response[STAT_OFF_AUTHOR..STAT_OFF_AUTHOR + 32].copy_from_slice(&e.author);
    response[STAT_OFF_OWNER..STAT_OFF_OWNER + 32].copy_from_slice(&e.owner);
    response[STAT_OFF_SIZE..STAT_OFF_SIZE + 4].copy_from_slice(&e.size.to_le_bytes());
    response[STAT_OFF_CONTENT_TYPE] = e.content_type;
    response[STAT_OFF_HAS_LINEAGE] = if e.has_lineage { 1 } else { 0 };
    response[STAT_OFF_LINEAGE_PARENT..STAT_OFF_LINEAGE_PARENT + 32]
        .copy_from_slice(&e.lineage_parent);
    // v1: every binding is treated as public. Real ACL comes later.
    response[STAT_OFF_ACL_IS_PUBLIC] = 1;
    response[STAT_OFF_NAME_LEN] = e.name_len;
    let nl = e.name_len as usize;
    response[STAT_OFF_NAME..STAT_OFF_NAME + nl].copy_from_slice(e.as_name());
    STAT_FIXED_LEN + nl
}

fn handle_list_named(payload: &[u8], response: &mut [u8]) -> usize {
    // Request payload (after CMD byte): [cursor:4 LE][prefix_len:1][prefix:N]
    if payload.len() < 5 {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let cursor = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let prefix_len = payload[4] as usize;
    if prefix_len > MAX_NAME_LEN || payload.len() < 5 + prefix_len {
        response[0] = STATUS_INVALID;
        return 1;
    }
    let prefix = &payload[5..5 + prefix_len];

    // Iterate from `cursor` to end. Emit at most K entries (fit-driven).
    // Response: [STATUS_OK][count:1][next_cursor:4 LE][entry][entry]...
    //   entry = [name_len:1][name:N]
    response[0] = STATUS_OK;
    let mut count: u8 = 0;
    let mut off: usize = 6; // reserve byte 1 (count), bytes 2..6 (next_cursor)
    let entries = table::entries();
    let mut i = cursor;
    while i < MAX_NAMES {
        if entries[i].used {
            let e = &entries[i];
            let n = e.as_name();
            if prefix.is_empty() || (n.len() >= prefix.len() && &n[..prefix.len()] == prefix) {
                // Fit check: 1 byte for name_len + n.len() content.
                let need = 1 + n.len();
                if off + need > response.len() {
                    break;
                }
                response[off] = n.len() as u8;
                response[off + 1..off + 1 + n.len()].copy_from_slice(n);
                off += need;
                count += 1;
            }
        }
        i += 1;
    }
    // If we stopped mid-way because of space, next_cursor = i. Else 0 (done).
    let next_cursor = if i < MAX_NAMES { i as u32 } else { 0 };
    response[1] = count;
    response[2..6].copy_from_slice(&next_cursor.to_le_bytes());
    off
}

fn handle_remove(payload: &[u8], response: &mut [u8]) -> usize {
    let name = match read_name(payload, 0) {
        Some(n) => n,
        None => {
            response[0] = STATUS_INVALID;
            return 1;
        }
    };
    match find_by_name(name) {
        Some(idx) => {
            table::entries()[idx].used = false;
            response[0] = STATUS_OK;
        }
        None => {
            response[0] = STATUS_NOT_FOUND;
        }
    }
    1
}

fn handle_rename(payload: &[u8], response: &mut [u8]) -> usize {
    // Request: [old_len:1][old:N][new_len:1][new:M]
    let old = match read_name(payload, 0) {
        Some(n) => n,
        None => {
            response[0] = STATUS_INVALID;
            return 1;
        }
    };
    let old_end = 1 + old.len();
    let new_name = match read_name(payload, old_end) {
        Some(n) => n,
        None => {
            response[0] = STATUS_INVALID;
            return 1;
        }
    };
    if find_by_name(new_name).is_some() {
        response[0] = STATUS_ALREADY_EXISTS;
        return 1;
    }
    match find_by_name(old) {
        Some(idx) => {
            let entries = table::entries();
            let e = &mut entries[idx];
            e.name_len = new_name.len() as u8;
            // Zero the old name to avoid stale trailing bytes.
            for b in e.name.iter_mut() {
                *b = 0;
            }
            e.name[..new_name.len()].copy_from_slice(new_name);
            response[0] = STATUS_OK;
        }
        None => {
            response[0] = STATUS_NOT_FOUND;
        }
    }
    1
}

fn handle_grant(_payload: &[u8], response: &mut [u8]) -> usize {
    // v1 stub: validate the request shape and reject.
    response[0] = STATUS_NOT_IMPLEMENTED;
    1
}

fn handle_transfer(_payload: &[u8], response: &mut [u8]) -> usize {
    response[0] = STATUS_NOT_IMPLEMENTED;
    1
}

// ============================================================================
// Boot-time seed (demo objects)
// ============================================================================

/// Seed the name table with a handful of demo objects so the shell's
/// `ls` / `cat` / `stat` commands have something to render even before a
/// client has saved anything. v1 stub — will be replaced when real
/// persistence arrives.
fn seed_demo_objects() {
    // Use the FS-service's own Principal as author. Reading it back via
    // get_principal keeps the data self-consistent (stat will show
    // "authored by fs-service" which is honest for a boot-seeded object).
    let mut author = [0u8; 32];
    let _ = sys::get_principal(&mut author);

    let demo = [
        ("readme.txt", proto::CT_PLAIN_TEXT, &b"Welcome to CambiOS. Run `help` for a list of commands.\n"[..]),
        ("motd",       proto::CT_PLAIN_TEXT, &b"Today is a good day to build a microkernel.\n"[..]),
        ("version",    proto::CT_PLAIN_TEXT, &b"CambiOS v1 UX layer (Phase 3).\n"[..]),
    ];

    for (name, ct, content) in demo {
        if content.len() > proto::MAX_CONTENT_LEN {
            continue;
        }
        let sig = match request_sign(content) {
            Some(s) => s,
            None => {
                sys::print(b"[FS] seed: key-store unavailable, skipping\n");
                return;
            }
        };
        let mut hash = [0u8; 32];
        if sys::obj_put_signed(content, &sig, &mut hash) < 0 {
            sys::print(b"[FS] seed: obj_put failed\n");
            return;
        }
        bind_name(
            name.as_bytes(),
            &hash,
            content.len() as u32,
            &author,
            &author,
            ct,
            None,
        );
    }
    sys::print(b"[FS] seeded demo objects\n");
}

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let _pid = sys::get_pid();

    sys::register_endpoint(FS_ENDPOINT);
    sys::print(b"[FS] ready on endpoint 16\n");

    seed_demo_objects();

    sys::module_ready();

    let mut recv_buf = [0u8; 256];
    let mut resp_buf = [0u8; 256];

    loop {
        let msg = match sys::recv_verified(FS_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };

        let (cmd, cmd_data) = match msg.command() {
            Some(pair) => pair,
            None => continue,
        };
        let sender = msg.sender().as_bytes();

        let resp_len = match cmd {
            CMD_PUT => handle_put(cmd_data, &mut resp_buf),
            CMD_GET => handle_get(cmd_data, &mut resp_buf),
            CMD_DELETE => handle_delete(cmd_data, &mut resp_buf),
            CMD_LIST => handle_list(&mut resp_buf),
            CMD_GET_BY_NAME => handle_get_by_name(cmd_data, &mut resp_buf),
            CMD_PUT_BY_NAME => handle_put_by_name(cmd_data, sender, &mut resp_buf),
            CMD_STAT => handle_stat(cmd_data, &mut resp_buf),
            CMD_LIST_NAMED => handle_list_named(cmd_data, &mut resp_buf),
            CMD_REMOVE => handle_remove(cmd_data, &mut resp_buf),
            CMD_RENAME => handle_rename(cmd_data, &mut resp_buf),
            CMD_GRANT => handle_grant(cmd_data, &mut resp_buf),
            CMD_TRANSFER => handle_transfer(cmd_data, &mut resp_buf),
            _ => {
                resp_buf[0] = STATUS_INVALID;
                1
            }
        };

        sys::write(msg.from_endpoint(), &resp_buf[..resp_len]);
    }
}
