// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S OWN TABLE, CALLED AS A HOST CALLS IT: the frame-level tests build each `in`/`out` a
//! host builds (its head stating the slot and the frame's size) and call the entry the plugin's
//! door states, over the instance its `open` answered. The logic crate forbids `unsafe`, so the
//! host side of these tests lives here.

use std::ffi::c_void;
use std::mem::size_of;

use busbar_contract::abi::auth::Ops;
use busbar_contract::abi::mechanism::call::{InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::HostTables;
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};

/// An all-zero frame: every `in`/`out` here is plain C data, all-zero a valid value of each.
pub fn z<T>() -> T {
    // SAFETY: callers use only plain ABI frames with a valid all-zero representation.
    unsafe { std::mem::zeroed() }
}

/// The plugin's auth table, read off its `'static` door.
pub fn ops() -> Ops {
    // SAFETY: the real static auth door owns a static auth Ops table.
    unsafe { *busbar_auth_sigv4::door().ops().cast::<Ops>() }
}

/// An `in` head for slot `op` over a frame of `I`.
pub fn in_head<I>(op: u32) -> InHead {
    let mut h: InHead = z();
    h.size = size_of::<I>() as u32;
    h.op = op;
    h
}

/// An `out` head over a frame of `O`.
pub fn out_head<O>() -> OutHead {
    let mut h: OutHead = z();
    h.size = size_of::<O>() as u32;
    h
}

/// Call `entry` on `instance` with `input` and `out`, as the host does.
///
/// # Safety
/// `entry` must be this live instance's slot with exactly `I` and `O` as its frame types. Both
/// heads must state their complete frame sizes, and every pointer in the frames must remain valid
/// for the slot's access. Any host memory retained by `open` must outlive the opened instance.
pub unsafe fn call<I: AbiIn, O: AbiOut>(
    entry: Option<Op>,
    instance: *mut c_void,
    input: &I,
    out: &mut O,
) -> Outcome {
    let entry = entry.expect("the door states the slot");
    // SAFETY: the caller proves this exact slot/frame pair and the instance and buffer loans.
    unsafe {
        entry(
            instance,
            std::ptr::from_ref(input).cast(),
            std::ptr::from_mut(out).cast(),
        )
    }
    .outcome()
}

/// `open` at generation 1 over `host` (NULL: the host hands no tables); the instance.
///
/// # Safety
/// A non-NULL `host` and all tables/state it names must remain live until the returned instance
/// has been closed. The returned pointer must be closed exactly once through this door.
pub unsafe fn open(host: *const HostTables) -> *mut c_void {
    let mut i: OpenIn = z();
    i.head = in_head::<OpenIn>(life::OPEN);
    i.host = host;
    i.generation = 1;
    let mut o: OpenOut = z();
    o.head = out_head::<OpenOut>();
    assert_eq!(
        // SAFETY: OPEN takes these exact OpenIn/OpenOut frames, whose full heads are set above.
        // It takes no instance; the caller supplies the retained host-table lifetime.
        unsafe { call(ops().head.open, std::ptr::null_mut(), &i, &mut o) },
        Outcome::Ready
    );
    o.instance
}

/// `close` the instance.
///
/// # Safety
/// `instance` must be this door's still-live open result, exclusively retired by this call. Its
/// retained host tables/state must remain live until the call returns.
pub unsafe fn close(instance: *mut c_void) {
    let i = in_head::<InHead>(life::CLOSE);
    let mut o = out_head::<OutHead>();
    // SAFETY: CLOSE takes InHead/OutHead; their full heads are initialized and the caller owns
    // the sole close of this live instance while its retained host memory remains valid.
    assert_eq!(
        unsafe { call(ops().head.close, instance, &i, &mut o) },
        Outcome::Ready
    );
}
