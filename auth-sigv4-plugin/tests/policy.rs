// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LOGIC CRATE'S OWN RULES, read off its production sources (`../auth-sigv4/src/**.rs` outside
//! `src/tests`). The HMAC the signer and the inbound check share is proven against RFC 4231 and
//! against ring's beside it, in the logic crate's `sigv4` unit tests.

use std::path::{Path, PathBuf};

/// Every production source of the logic crate (the test modules are not production).
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("a source is readable");
                out.push((path, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../auth-sigv4/src"),
        &mut out,
    );
    assert!(
        out.len() >= 7,
        "the logic crate's sources are read: {out:?}"
    );
    out
}

/// RED (BUSBAR-1.6.0.md THE DESIGN §2: "A plugin holds no process-global state: what it keeps is
/// per-instance ... The one owner-approved per-thread slot is the door's log-capture slot,
/// macro-expanded into each plugin"): no per-thread static holds the plugin's reply storage.
#[test]
fn no_per_thread_static_holds_reply_storage() {
    let marker = concat!("thread", "_local!");
    for (file, text) in sources() {
        assert!(
            !text.contains(marker),
            "{} declares a per-thread static: reply storage is the instance's",
            file.display()
        );
    }
}

/// RED (BUSBAR-1.6.0.md THE DESIGN §6: "auth material is zeroised"): the HMAC key state derived
/// from the `AWS4<secret>` seed and from each day key is never ring's `hmac::Key`, whose inner and
/// outer pad states ring drops unwiped.
#[test]
fn hmac_key_state_is_never_rings_unwiped_key() {
    for (file, text) in sources() {
        assert!(
            !text.contains(concat!("hmac", "::Key")) && !text.contains(concat!("ring_", "hmac")),
            "{} keys an HMAC on ring's unwiped `hmac::Key`",
            file.display()
        );
    }
}
