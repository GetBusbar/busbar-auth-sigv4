// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CRATE'S OWN RULES, read off its production sources, and the HMAC the signer and the
//! inbound check share, proven against RFC 4231 and against ring's.

/// Every production source of the crate (the test modules are not production).
const SOURCES: [(&str, &str); 7] = [
    ("lib.rs", include_str!("../lib.rs")),
    ("held.rs", include_str!("../held.rs")),
    ("inbound.rs", include_str!("../inbound.rs")),
    ("instance.rs", include_str!("../instance.rs")),
    ("signing.rs", include_str!("../signing.rs")),
    ("sigv4.rs", include_str!("../sigv4.rs")),
    ("style.rs", include_str!("../style.rs")),
];

/// RED (BUSBAR-1.6.0.md THE DESIGN §2: "A plugin holds no process-global state: what it keeps is
/// per-instance ... The one owner-approved per-thread slot is the door's log-capture slot,
/// macro-expanded into each plugin"): no per-thread static holds the plugin's reply storage.
#[test]
fn no_per_thread_static_holds_reply_storage() {
    let marker = concat!("thread", "_local!");
    for (file, text) in SOURCES {
        assert!(
            !text.contains(marker),
            "{file} declares a per-thread static: reply storage is the instance's"
        );
    }
}

/// RED (BUSBAR-1.6.0.md THE DESIGN §6: "auth material is zeroised"): the HMAC key state derived
/// from the `AWS4<secret>` seed and from each day key is never ring's `hmac::Key`, whose inner and
/// outer pad states ring drops unwiped.
#[test]
fn hmac_key_state_is_never_rings_unwiped_key() {
    for (file, text) in SOURCES {
        assert!(
            !text.contains(concat!("hmac", "::Key")) && !text.contains(concat!("ring_", "hmac")),
            "{file} keys an HMAC on ring's unwiped `hmac::Key`"
        );
    }
}

fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(&crate::sigv4::hmac(key, data)[..])
}

/// RFC 4231 HMAC-SHA256 test cases 1, 2, 6 and 7 (a key past the block size is hashed first).
#[test]
fn hmac_answers_rfc_4231() {
    assert_eq!(
        hmac_hex(&[0x0b; 20], b"Hi There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hmac_hex(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        hmac_hex(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
    assert_eq!(
        hmac_hex(
            &[0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size \
              data. The key needs to be hashed before being used by the HMAC algorithm."
        ),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    );
}

/// The HMAC agrees with ring's over every key length across the block size and every data length
/// across two blocks (each padding boundary included).
#[test]
fn hmac_agrees_with_ring_across_block_boundaries() {
    let key: Vec<u8> = (0..140_u8).collect();
    let data: Vec<u8> = (0..200_u8).map(|b| b.wrapping_mul(7)).collect();
    for k in [0, 1, 31, 32, 63, 64, 65, 127, 128, 129, 140] {
        for d in 0..data.len() {
            let want = ring::hmac::sign(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key[..k]),
                &data[..d],
            );
            assert_eq!(
                hmac_hex(&key[..k], &data[..d]),
                hex::encode(want.as_ref()),
                "key {k} bytes, data {d} bytes"
            );
        }
    }
}
