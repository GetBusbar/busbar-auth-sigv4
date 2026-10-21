// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S OWN TABLE, CALLED AS A HOST CALLS IT: the frame-level tests build each `in`/`out` a
//! host builds (its head stating the slot and the frame's size) and call the entry the plugin's
//! door states, over the instance its `open` answered. Shared by the frame-level test targets.

#![allow(dead_code)] // each target uses its own share of the helpers

use std::ffi::c_void;
use std::mem::size_of;

use busbar_contract::abi::auth::Ops;
use busbar_contract::abi::mechanism::call::{InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::HostTables;

/// An all-zero frame: every `in`/`out` here is plain C data, all-zero a valid value of each.
pub fn z<T>() -> T {
    // SAFETY: as above.
    unsafe { std::mem::zeroed() }
}

/// The plugin's auth table, read off its `'static` door.
pub fn ops() -> Ops {
    // SAFETY: the plugin's door is `'static` plain data, its `ops` the auth table it states.
    unsafe { *(*busbar_auth_sigv4::door()).ops.cast::<Ops>() }
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
pub fn call<I, O>(entry: Option<Op>, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    let entry = entry.expect("the door states the slot");
    entry(
        instance,
        std::ptr::from_ref(input).cast(),
        std::ptr::from_mut(out).cast(),
    )
    .outcome()
}

/// `open` at generation 1 over `host` (NULL: the host hands no tables); the instance.
pub fn open(host: *const HostTables) -> *mut c_void {
    let mut i: OpenIn = z();
    i.head = in_head::<OpenIn>(life::OPEN);
    i.host = host;
    i.generation = 1;
    let mut o: OpenOut = z();
    o.head = out_head::<OpenOut>();
    assert_eq!(
        call(ops().head.open, std::ptr::null_mut(), &i, &mut o),
        Outcome::Ready
    );
    o.instance
}

/// `close` the instance.
pub fn close(instance: *mut c_void) {
    let i = in_head::<InHead>(life::CLOSE);
    let mut o = out_head::<OutHead>();
    assert_eq!(call(ops().head.close, instance, &i, &mut o), Outcome::Ready);
}
