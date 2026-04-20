// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Host-test mock for the libfs transport.
//!
//! Replaces `round_trip` with a per-thread handler closure so test cases
//! can assert against the exact bytes libfs sends and return canned
//! responses. Real IPC (`sys::write` / `sys::recv_msg`) is not used in
//! tests — those live in QEMU end-to-end.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::proto::MSG_CAP;
use crate::FsError;

type Handler = Box<dyn FnMut(&[u8], &mut [u8; MSG_CAP]) -> Result<usize, FsError>>;

thread_local! {
    static HANDLER: RefCell<Option<Handler>> = const { RefCell::new(None) };
    static CAPTURED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

pub fn set_handler<F>(f: F)
where
    F: FnMut(&[u8], &mut [u8; MSG_CAP]) -> Result<usize, FsError> + 'static,
{
    HANDLER.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    CAPTURED.with(|c| c.borrow_mut().clear());
}

/// Return (and consume) the list of request byte-slices observed so far.
pub fn captured_requests() -> Vec<Vec<u8>> {
    CAPTURED.with(|c| core::mem::take(&mut *c.borrow_mut()))
}

pub(crate) fn round_trip(
    req: &[u8],
    resp_out: &mut [u8; MSG_CAP],
) -> Result<usize, FsError> {
    CAPTURED.with(|c| c.borrow_mut().push(req.to_vec()));
    HANDLER.with(|h| {
        let mut h = h.borrow_mut();
        match h.as_mut() {
            Some(handler) => handler(req, resp_out),
            None => Err(FsError::TransportError),
        }
    })
}
