// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `open_outbound` REPLY, through the door's own trampolines as a host calls them: each bind's
//! refusal text is that bind's own, kept by the instance until the host has copied it. Two kind
//! ops may run at once on one instance (busbar-contract `abi::mechanism::lifecycle`), so a bind on
//! another thread must never free or rewrite the text a reply already points at.

#![allow(unsafe_code)] // reads the plugin's raw `out` as a host does

use std::sync::{Arc, Barrier};
use std::thread;

use busbar_contract::abi::auth::{OpenOutboundIn, OpenOutboundOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::Slot;

use crate::abi::{zeroed_in, zeroed_out};
use crate::{Close, Open, OpenOutbound};

/// How many binds run at once on the one instance.
const BINDS: usize = 8;
/// How many rounds each runs.
const ROUNDS: usize = 64;

/// An instance with no host tables (`open_outbound` reads none); its address, sendable.
fn open() -> usize {
    let mut i: OpenIn = zeroed_in();
    i.generation = 1;
    let mut o: OpenOut = zeroed_out();
    assert_eq!(Open::call(std::ptr::null_mut(), &i, &mut o), Outcome::Ready);
    o.instance as usize
}

fn close(instance: usize) {
    let mut out = zeroed_out();
    Close::call(instance as *mut _, &zeroed_in(), &mut out);
}

/// `open_outbound` of `style`, no credential, no settings: the reply as the host holds it.
fn bind(instance: usize, style: &str) -> (Outcome, OpenOutboundOut) {
    let mut i: OpenOutboundIn = zeroed_in();
    i.style = AbiStr {
        ptr: style.as_ptr(),
        len: style.len(),
    };
    let mut out: OpenOutboundOut = zeroed_out();
    let outcome = OpenOutbound::call(instance as *mut _, &i, &mut out);
    (outcome, out)
}

/// The reply's error text, read as the host reads it after the call returned.
fn error_text(out: &OpenOutboundOut) -> String {
    let e = out.head.error;
    if e.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the plugin's reply names `len` bytes it keeps until the host has copied them.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(e.ptr, e.len) }).into_owned()
}

/// Every bind's reply still reads its OWN refusal after every other bind on the instance has
/// answered too: no shared envelope is cleared and refilled under a reply the host has not copied.
#[test]
fn each_concurrent_bind_reads_back_its_own_refusal_text() {
    let instance = open();
    let barrier = Arc::new(Barrier::new(BINDS));
    let workers: Vec<_> = (0..BINDS)
        .map(|n| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut wrong = Vec::new();
                for round in 0..ROUNDS {
                    // A style this plugin does not serve, distinct per bind and round, and of a
                    // length of its own: the refusal names it.
                    let style = format!("style-{n}-{round}-{}", "x".repeat(40 + n));
                    let (outcome, out) = bind(instance, &style);
                    // Every bind of this round has answered before any reply is read.
                    barrier.wait();
                    let want = format!(
                        "settings: outbound auth style `{style}` is not served by this plugin"
                    );
                    let got = error_text(&out);
                    if outcome != Outcome::Failed || got != want {
                        wrong.push((round, outcome, got, want));
                    }
                    // No bind of the next round starts before every reply of this one is read.
                    barrier.wait();
                }
                wrong
            })
        })
        .collect();
    let wrong: Vec<_> = workers
        .into_iter()
        .flat_map(|w| w.join().expect("a bind thread"))
        .collect();
    close(instance);
    assert!(
        wrong.is_empty(),
        "{} of {} replies did not read back their own refusal; first: {:?}",
        wrong.len(),
        BINDS * ROUNDS,
        wrong.first()
    );
}

/// A bind's reply outlives the next bind on the same thread too: the host copies after the call
/// returns, and the next bind must not have freed what the first reply names.
#[test]
fn the_next_bind_leaves_the_first_reply_readable() {
    let instance = open();
    let first_style = "first-style-not-served-by-this-plugin";
    let (first_outcome, first) = bind(instance, first_style);
    let (_, second) = bind(instance, "second-style-of-another-length");
    assert_eq!(first_outcome, Outcome::Failed);
    assert_eq!(
        error_text(&first),
        format!("settings: outbound auth style `{first_style}` is not served by this plugin")
    );
    assert_eq!(
        error_text(&second),
        "settings: outbound auth style `second-style-of-another-length` is not served by this \
         plugin"
    );
    close(instance);
}
