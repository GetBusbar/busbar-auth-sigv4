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

fn field(fields: &[(String, Zeroizing<String>)], name: &str) -> String {
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
        SigningCredential::parse(&format!("AKIDEXAMPLE:{SECRET}:SESSIONTOKEN")).ok(),
    );
    let sent = b.sign_flat(&facts(&hash)).expect("signs");
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

/// OWNER RULING: a credential 1.5.5 bound to sign nothing — a session token the wire cannot carry,
/// an empty secret or access key id, an access key id no header value may carry — is refused when
/// it is parsed, naming what is wrong; and a binding with no credential of its own signs nothing
/// in own mode but says so (was: each signed an empty field set, silently).
#[test]
fn unsendable_or_incomplete_signing_credentials_are_refused_not_signed_with_nothing() {
    let hash = sigv4::sha256_hex(b"{}");
    for (raw, finding) in [
        (
            format!("AKIDEXAMPLE:{SECRET}:TOK\r\nEN"),
            SESSION_TOKEN_UNSENDABLE,
        ),
        (
            format!("AKIDEXAMPLE:{SECRET}:TOK\u{1}EN"),
            SESSION_TOKEN_UNSENDABLE,
        ),
        ("AKIDEXAMPLE:".to_string(), SECRET_EMPTY),
        (format!(":{SECRET}"), ACCESS_KEY_ID_EMPTY),
        (format!("AKID\u{7f}:{SECRET}"), ACCESS_KEY_ID_UNSENDABLE),
    ] {
        assert_eq!(
            SigningCredential::parse(&raw).map(|_| ()),
            Err(vec![finding]),
            "{raw:?}"
        );
    }
    assert_eq!(
        SigV4Binding::new(params(), None).sign_flat(&facts(&hash)),
        Err(NO_OWN_CREDENTIAL)
    );
}

/// A service or region no header value may carry makes the `Authorization` value unsendable: the
/// request FAILS with the reason, never sent unsigned.
#[test]
fn an_authorization_the_wire_cannot_carry_fails_with_its_reason() {
    let hash = sigv4::sha256_hex(b"{}");
    let b = SigV4Binding::new(
        SigV4Params {
            service: "iam\u{7f}".to_string(),
            region: "us-east-1".to_string(),
        },
        SigningCredential::parse(&format!("AKIDEXAMPLE:{SECRET}")).ok(),
    );
    assert_eq!(b.sign_flat(&facts(&hash)), Err(AUTHORIZATION_UNSENDABLE));
}

/// Re-signing the same request is idempotent: the day key held after the first signature signs the
/// second exactly as a fresh derivation would.
#[test]
fn the_held_day_key_signs_exactly_as_a_fresh_derivation() {
    let hash = sigv4::sha256_hex(b"{}");
    let cred = || SigningCredential::parse(&format!("AKIDEXAMPLE:{SECRET}")).ok();
    let warm = SigV4Binding::new(params(), cred());
    let first = warm.sign_flat(&facts(&hash)).expect("signs");
    let second = warm.sign_flat(&facts(&hash)).expect("signs");
    let cold = SigV4Binding::new(params(), cred())
        .sign_flat(&facts(&hash))
        .expect("signs");
    assert_eq!(first, second);
    assert_eq!(first, cold);
}

/// `tick` derives the next UTC day's key within the hour before midnight, and keeps at most two.
#[test]
fn tick_prederives_tomorrows_key_ahead_of_midnight() {
    let b = SigV4Binding::new(
        params(),
        SigningCredential::parse(&format!("AKIDEXAMPLE:{SECRET}")).ok(),
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

/// A logged credential shows that a secret and a token are present, never either.
#[test]
fn a_logged_credential_redacts_its_secret_and_token() {
    let c =
        SigningCredential::parse(&format!("AKIDEXAMPLE:{SECRET}:SESSIONTOKEN")).expect("parses");
    let printed = format!("{c:?}");
    assert!(!printed.contains("SESSIONTOKEN"), "{printed}");
    assert!(!printed.contains("wJalr"), "{printed}");
    assert!(printed.contains("<redacted>"), "{printed}");
}

/// A request dated before both held day keys (a skewed clock) signs as a fresh binding signs it,
/// from a key derived for that request alone, and the held keys stay as they were.
#[test]
fn a_request_older_than_both_held_keys_signs_as_a_fresh_binding_does() {
    let hash = sigv4::sha256_hex(b"{}");
    let cred = || SigningCredential::parse(&format!("AKIDEXAMPLE:{SECRET}")).ok();
    let held = SigV4Binding::new(params(), cred());
    let midnight = 1_440_979_200; // 2015-08-31T00:00:00Z
    held.prederive(midnight - 600);
    assert_eq!(held.held(), ["20150830", "20150831"]);
    let mut old = facts(&hash);
    old.timestamp_epoch = 1_440_938_160 - 2 * 86_400; // 2015-08-28
    let skewed = held.sign_flat(&old).expect("signs");
    assert_eq!(
        field(&skewed, "x-amz-date"),
        "20150828T123600Z",
        "dated by the request"
    );
    assert_eq!(
        Ok(skewed),
        SigV4Binding::new(params(), cred()).sign_flat(&old)
    );
    assert_eq!(held.held(), ["20150830", "20150831"], "no key evicted");
}
