// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `sigv4` style, ported from the identity unit's `egress_auth/tests.rs` in the kernel: the assembly
//! around the signer, the refusals, and the day keys.

use super::*;

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

fn params() -> SigV4Params {
    SigV4Params {
        service: "iam".to_string(),
        region: "us-east-1".to_string(),
    }
}

fn facts<'a>(hash: &'a str) -> SignFacts<'a> {
    SignFacts {
        method: "POST",
        host: "runtime.signer.example",
        path: "/model/m/converse",
        query: None,
        content_type: Some("application/json"),
        payload_hash: hash,
        timestamp_epoch: 1_440_938_160,
    }
}

fn field(fields: &[Field], name: &str) -> String {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| panic!("{name} is sent"))
}

/// A temporary credential's session token is SENT and SIGNED over exactly the set 1.5.5's signing
/// writer signed (`content-type`, `host`, the two `x-amz-*` fields and the token), and the whole
/// `Authorization` value is the one `sign_v4` computes from arguments written out in its own
/// parameter order — so a transposed region/service or a dropped input disagrees.
#[test]
fn session_token_is_sent_and_signed_over_the_writer_header_set() {
    let hash = sigv4::sha256_hex(br#"{"messages":[]}"#);
    let b = SigV4Binding::new(
        params(),
        SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}:SESSIONTOKEN")),
    );
    let sent = b.sign(&facts(&hash));
    assert_eq!(
        sent.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
        [
            "authorization",
            "x-amz-date",
            "x-amz-content-sha256",
            "x-amz-security-token"
        ],
        "1.5.5's field order"
    );
    assert_eq!(field(&sent, "x-amz-security-token"), "SESSIONTOKEN");
    assert_eq!(field(&sent, "x-amz-content-sha256"), hash);
    let signed_over = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("host".to_string(), "runtime.signer.example".to_string()),
        ("x-amz-content-sha256".to_string(), hash.clone()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        (
            "x-amz-security-token".to_string(),
            "SESSIONTOKEN".to_string(),
        ),
    ];
    let (signature, signed_headers) = sigv4::sign_v4(
        SECRET,
        "us-east-1",
        "iam",
        "POST",
        "/model/m/converse",
        "",
        &signed_over,
        &hash,
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(
        signed_headers,
        "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    );
    assert_eq!(
        field(&sent, "authorization"),
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders={signed_headers}, Signature={signature}"
        )
    );
}

/// Every credential 1.5.5 refused to sign with signs nothing: a session token the wire cannot
/// carry, an empty secret or access key id (the split refuses those), no credential at all.
#[test]
fn unsendable_or_incomplete_signing_credentials_sign_nothing() {
    let hash = sigv4::sha256_hex(b"{}");
    for raw in [
        format!("AKIDEXAMPLE:{SECRET}:TOK\r\nEN"),
        format!("AKIDEXAMPLE:{SECRET}:TOK\u{1}EN"),
        "AKIDEXAMPLE:".to_string(),
        format!(":{SECRET}"),
    ] {
        let b = SigV4Binding::new(params(), SigningCredential::split(&raw));
        assert!(
            b.sign(&facts(&hash)).is_empty(),
            "{raw:?} must sign nothing"
        );
    }
    assert!(SigV4Binding::new(params(), None)
        .sign(&facts(&hash))
        .is_empty());
}

/// An access key id that makes the `Authorization` value illegal signs nothing.
#[test]
fn an_access_key_id_the_wire_cannot_carry_signs_nothing() {
    let hash = sigv4::sha256_hex(b"{}");
    let b = SigV4Binding::new(
        params(),
        SigningCredential::split(&format!("AKID\u{7f}:{SECRET}")),
    );
    assert!(b.sign(&facts(&hash)).is_empty());
}

/// Re-signing the same request is idempotent: the day key held after the first signature signs the
/// second exactly as a fresh derivation would.
#[test]
fn the_held_day_key_signs_exactly_as_a_fresh_derivation() {
    let hash = sigv4::sha256_hex(b"{}");
    let cred = || SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}"));
    let warm = SigV4Binding::new(params(), cred());
    let first = warm.sign(&facts(&hash));
    let second = warm.sign(&facts(&hash));
    let cold = SigV4Binding::new(params(), cred()).sign(&facts(&hash));
    assert_eq!(first, second);
    assert_eq!(first, cold);
}

/// `tick` derives the next UTC day's key within the hour before midnight, and keeps at most two.
#[test]
fn tick_prederives_tomorrows_key_ahead_of_midnight() {
    let b = SigV4Binding::new(
        params(),
        SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}")),
    );
    let midnight = 1_440_979_200; // 2015-08-31T00:00:00Z
    b.prederive(midnight - 7_200);
    assert_eq!(b.held(), ["20150830"], "two hours out: today only");
    b.prederive(midnight - 600);
    assert_eq!(
        b.held(),
        ["20150830", "20150831"],
        "ten minutes out: tomorrow too"
    );
    b.prederive(midnight + 86_400 - 600);
    assert_eq!(
        b.held(),
        ["20150831", "20150901"],
        "two kept, the oldest dropped"
    );
}

/// The day keys held are `tick`'s, relative to the instance's clock, never a request's date: a
/// request dated days ahead of today, or days behind it, signs with a key derived for that request
/// alone, exactly as a fresh derivation signs it, and today's and tomorrow's keys stay held
/// (THE DESIGN §6.5: "a daily signing key derived ahead of time").
#[test]
fn a_request_dated_off_the_held_days_never_evicts_a_day_key() {
    let cred = || SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}"));
    let b = SigV4Binding::new(params(), cred());
    let midnight = 1_440_979_200; // 2015-08-31T00:00:00Z
    b.prederive(midnight - 600);
    assert_eq!(b.held(), ["20150830", "20150831"]);
    let hash = sigv4::sha256_hex(b"{}");
    for skew in [5 * 86_400, 86_400 * 2] {
        for at in [midnight + skew, midnight - skew] {
            let off = SignFacts {
                timestamp_epoch: at,
                ..facts(&hash)
            };
            let signed = b.sign(&off);
            assert_eq!(
                b.held(),
                ["20150830", "20150831"],
                "a request dated {at} leaves today's and tomorrow's keys held"
            );
            assert_eq!(signed, SigV4Binding::new(params(), cred()).sign(&off));
        }
    }
}

/// A logged credential shows that a secret and a token are present, never either.
#[test]
fn a_logged_credential_redacts_its_secret_and_token() {
    let c = SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}:SESSIONTOKEN")).unwrap();
    let printed = format!("{c:?}");
    assert!(!printed.contains("SESSIONTOKEN"), "{printed}");
    assert!(!printed.contains("wJalr"), "{printed}");
    assert!(printed.contains("<redacted>"), "{printed}");
}
