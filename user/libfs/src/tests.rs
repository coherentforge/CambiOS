// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Host-side tests for libfs's wire-format codecs.
//!
//! Each test installs a canned response handler via [`test_transport`],
//! calls the relevant libfs function, and asserts against both the
//! observed request bytes and the returned value. No real IPC happens.

use super::*;
use crate::proto::*;
use crate::test_transport::{captured_requests, set_handler};

fn fill_stat_response(
    resp: &mut [u8; MSG_CAP],
    name: &str,
    size: usize,
    author: [u8; 32],
    owner: [u8; 32],
    content_type: ContentType,
    lineage: Option<[u8; 32]>,
    is_public: bool,
) -> usize {
    resp[0] = STATUS_OK;
    let hash = {
        let mut h = [0u8; 32];
        h[0] = 0xaa;
        h
    };
    resp[STAT_OFF_HASH..STAT_OFF_HASH + 32].copy_from_slice(&hash);
    resp[STAT_OFF_AUTHOR..STAT_OFF_AUTHOR + 32].copy_from_slice(&author);
    resp[STAT_OFF_OWNER..STAT_OFF_OWNER + 32].copy_from_slice(&owner);
    put_u32_le(resp, STAT_OFF_SIZE, size as u32);
    resp[STAT_OFF_CONTENT_TYPE] = content_type.to_u8();
    if let Some(lp) = lineage {
        resp[STAT_OFF_HAS_LINEAGE] = 1;
        resp[STAT_OFF_LINEAGE_PARENT..STAT_OFF_LINEAGE_PARENT + 32].copy_from_slice(&lp);
    } else {
        resp[STAT_OFF_HAS_LINEAGE] = 0;
    }
    resp[STAT_OFF_ACL_IS_PUBLIC] = if is_public { 1 } else { 0 };
    let name_bytes = name.as_bytes();
    resp[STAT_OFF_NAME_LEN] = name_bytes.len() as u8;
    resp[STAT_OFF_NAME..STAT_OFF_NAME + name_bytes.len()].copy_from_slice(name_bytes);
    STAT_OFF_NAME + name_bytes.len()
}

#[test]
fn open_sends_correct_request_and_decodes_content() {
    set_handler(|req, resp| {
        assert_eq!(req[0], CMD_GET_BY_NAME);
        assert_eq!(req[1], b"foo".len() as u8);
        assert_eq!(&req[2..2 + 3], b"foo");
        // Response: [STATUS_OK][size:4][hash:32][content]
        resp[0] = STATUS_OK;
        put_u32_le(resp, 1, 5);
        for i in 0..32 {
            resp[5 + i] = 0xbb;
        }
        resp[37..42].copy_from_slice(b"hello");
        Ok(42)
    });
    let r = open("foo").unwrap();
    assert_eq!(r, b"hello");
}

#[test]
fn open_not_found_maps_to_error() {
    set_handler(|_, resp| {
        resp[0] = STATUS_NOT_FOUND;
        Ok(1)
    });
    assert_eq!(open("nope"), Err(FsError::NotFound));
}

#[test]
fn open_name_too_long_rejected_client_side() {
    // Verify the cap without installing a handler.
    set_handler(|_, _| panic!("should never call the server"));
    let long = "a".repeat(MAX_NAME_LEN + 1);
    assert_eq!(open(&long), Err(FsError::ArgTooLong));
}

#[test]
fn save_encodes_parent_and_content_type() {
    let parent = [7u8; 32];
    set_handler(move |req, resp| {
        assert_eq!(req[0], CMD_PUT_BY_NAME);
        assert_eq!(req[1], b"hello.txt".len() as u8);
        assert_eq!(req[2], 1); // has_parent
        assert_eq!(&req[3..3 + 32], &parent);
        assert_eq!(req[35], CT_PLAIN_TEXT);
        let content_len = get_u32_le(req, 36) as usize;
        assert_eq!(content_len, b"hi".len());
        let name_off = 40;
        assert_eq!(&req[name_off..name_off + 9], b"hello.txt");
        let content_off = name_off + 9;
        assert_eq!(&req[content_off..content_off + 2], b"hi");

        // Response: [STATUS_OK][hash:32]
        resp[0] = STATUS_OK;
        for i in 0..32 {
            resp[1 + i] = 0x11;
        }
        Ok(33)
    });
    let hash = save("hello.txt", b"hi", Some(parent), Some(ContentType::PlainText)).unwrap();
    assert_eq!(hash, [0x11; 32]);
}

#[test]
fn save_no_parent_sets_has_parent_zero() {
    set_handler(|req, resp| {
        assert_eq!(req[2], 0); // has_parent
        // parent bytes must be zeroed in the request even if unused
        assert!(req[3..3 + 32].iter().all(|&b| b == 0));
        resp[0] = STATUS_OK;
        for i in 0..32 {
            resp[1 + i] = 0;
        }
        Ok(33)
    });
    let _ = save("x", b"y", None, None).unwrap();
}

#[test]
fn save_content_too_large_rejected_client_side() {
    set_handler(|_, _| panic!("should not reach server"));
    let big = [0u8; MAX_CONTENT_LEN + 1];
    assert_eq!(
        save("x", &big, None, None),
        Err(FsError::TooLarge)
    );
}

#[test]
fn stat_decodes_full_shape() {
    let author = [0xau8; 32];
    let owner = [0xcu8; 32];
    let lineage = [0xeu8; 32];
    set_handler(move |req, resp| {
        assert_eq!(req[0], CMD_STAT);
        assert_eq!(req[1], b"foo.bin".len() as u8);
        assert_eq!(&req[2..2 + 7], b"foo.bin");
        let n = fill_stat_response(
            resp,
            "foo.bin",
            42,
            author,
            owner,
            ContentType::OctetStream,
            Some(lineage),
            false,
        );
        Ok(n)
    });
    let info = stat("foo.bin").unwrap();
    assert_eq!(info.name, "foo.bin");
    assert_eq!(info.size, 42);
    assert_eq!(info.author, author);
    assert_eq!(info.owner, owner);
    assert_eq!(info.content_type, ContentType::OctetStream);
    assert_eq!(info.lineage_parent, Some(lineage));
    assert!(!info.is_public);
    assert_eq!(info.hash[0], 0xaa);
}

#[test]
fn stat_decodes_without_lineage() {
    set_handler(|_, resp| {
        let n = fill_stat_response(
            resp,
            "a",
            1,
            [0; 32],
            [0; 32],
            ContentType::PlainText,
            None,
            true,
        );
        Ok(n)
    });
    let info = stat("a").unwrap();
    assert_eq!(info.lineage_parent, None);
    assert!(info.is_public);
    assert_eq!(info.content_type, ContentType::PlainText);
}

#[test]
fn list_loops_until_cursor_zero() {
    // Three distinct calls returning names one per batch, then a stat per
    // name. Use a stateful handler.
    use core::cell::Cell;
    let step = alloc::rc::Rc::new(Cell::new(0u32));
    let step_cb = step.clone();
    set_handler(move |req, resp| {
        if req[0] == CMD_LIST_NAMED {
            let cursor = get_u32_le(req, 1);
            let s = step_cb.get();
            step_cb.set(s + 1);
            resp[0] = STATUS_OK;
            match cursor {
                0 => {
                    resp[1] = 1; // count
                    put_u32_le(resp, 2, 100); // next cursor
                    // entry: [name_len:1][name:N]
                    resp[6] = 1;
                    resp[7] = b'a';
                    Ok(8)
                }
                100 => {
                    resp[1] = 1;
                    put_u32_le(resp, 2, 0); // last batch
                    resp[6] = 1;
                    resp[7] = b'b';
                    Ok(8)
                }
                _ => panic!("unexpected cursor {cursor}"),
            }
        } else if req[0] == CMD_STAT {
            let name = &req[2..2 + req[1] as usize];
            let n = fill_stat_response(
                resp,
                core::str::from_utf8(name).unwrap(),
                5,
                [0; 32],
                [0; 32],
                ContentType::None,
                None,
                true,
            );
            Ok(n)
        } else {
            panic!("unexpected cmd {}", req[0]);
        }
    });
    let items = list(None).unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].name, "a");
    assert_eq!(items[1].name, "b");
}

#[test]
fn remove_sends_name() {
    set_handler(|req, resp| {
        assert_eq!(req[0], CMD_REMOVE);
        assert_eq!(req[1], 3);
        assert_eq!(&req[2..5], b"bye");
        resp[0] = STATUS_OK;
        Ok(1)
    });
    assert_eq!(remove("bye"), Ok(()));
}

#[test]
fn rename_sends_both_names() {
    set_handler(|req, resp| {
        assert_eq!(req[0], CMD_RENAME);
        assert_eq!(req[1], 1);
        assert_eq!(req[2], b'a');
        assert_eq!(req[3], 1);
        assert_eq!(req[4], b'b');
        resp[0] = STATUS_OK;
        Ok(1)
    });
    assert_eq!(rename("a", "b"), Ok(()));
}

#[test]
fn grant_returns_not_implemented() {
    set_handler(|req, resp| {
        assert_eq!(req[0], CMD_GRANT);
        resp[0] = STATUS_NOT_IMPLEMENTED;
        Ok(1)
    });
    let to = [5u8; 32];
    assert_eq!(
        grant("foo", &to, ObjectRights::Read),
        Err(FsError::NotImplemented)
    );
}

#[test]
fn transfer_returns_not_implemented() {
    set_handler(|req, resp| {
        assert_eq!(req[0], CMD_TRANSFER);
        resp[0] = STATUS_NOT_IMPLEMENTED;
        Ok(1)
    });
    let to = [5u8; 32];
    assert_eq!(transfer("foo", &to), Err(FsError::NotImplemented));
}

#[test]
fn error_mapping_is_exhaustive() {
    let cases = [
        (STATUS_NOT_FOUND, FsError::NotFound),
        (STATUS_FULL, FsError::Full),
        (STATUS_DENIED, FsError::Denied),
        (STATUS_INVALID, FsError::Invalid),
        (STATUS_TOO_LARGE, FsError::TooLarge),
        (STATUS_ALREADY_EXISTS, FsError::AlreadyExists),
        (STATUS_NOT_IMPLEMENTED, FsError::NotImplemented),
    ];
    for (status, expected) in cases {
        assert_eq!(status_to_error(status), expected);
    }
}

#[test]
fn content_type_round_trip() {
    let cases = [
        ContentType::None,
        ContentType::PlainText,
        ContentType::OctetStream,
        ContentType::Unknown(99),
    ];
    for ct in cases {
        assert_eq!(ContentType::from_u8(ct.to_u8()), ct);
    }
}

#[test]
fn captured_requests_round_trip() {
    set_handler(|_, resp| {
        resp[0] = STATUS_NOT_FOUND;
        Ok(1)
    });
    let _ = open("foo");
    let _ = remove("bar");
    let reqs = captured_requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0][0], CMD_GET_BY_NAME);
    assert_eq!(reqs[1][0], CMD_REMOVE);
}
