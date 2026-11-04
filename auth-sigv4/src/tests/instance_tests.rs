// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HANDLE BOOKKEEPING AND `fields`' BODY ([`SigV4::sign`]), both credential modes — no mint,
//! no wire, no waiting ticket: a sigv4 binding signs synchronously. The frames around it (the
//! fields written under the short-buffer rule, a FAILED call's reason) are the contract kit's, driven through the real loader by the `-plugin` crate's conformance script.

use super::*;
use crate::sigv4::sha256_hex;
use crate::style;
use busbar_contract::abi::auth::{MODE_OWN, MODE_PASSTHROUGH};
use busbar_contract::abi::mechanism::call::Outcome;

const SETTINGS: &str =
    r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#;

/// Whose credential `mode` signs with: the caller's (`caller`, none when empty) in passthrough.
fn who(mode: u32, caller: &str) -> Who<'_> {
    if mode == MODE_PASSTHROUGH {
        Who::Caller((!caller.is_empty()).then_some(caller.as_bytes()))
    } else {
        Who::Own
    }
}

/// What a `fields` call answers for `signed`: its outcome, whether it set any field, and a FAILED
/// call's reason (empty otherwise).
fn answered(signed: Option<Signed>) -> (Outcome, bool, String) {
    match signed {
        None => (Outcome::Refused, false, String::new()),
        Some(Signed::Failed(reason)) => (Outcome::Failed, false, reason.into_owned()),
        Some(Signed::Fields(fields)) => (Outcome::Ready, !fields.is_empty(), String::new()),
    }
}

fn fields(s: &SigV4, handle: u64, mode: u32, caller: &str) -> (Outcome, bool) {
    let (outcome, signed, _) = fields_said(s, handle, mode, caller);
    (outcome, signed)
}

/// The facts the host lends for every call here, over `hash`.
fn facts_over(hash: &str) -> SignFacts<'_> {
    // The host lends the walked request's method on every call.
    SignFacts {
        method: "POST",
        host: "runtime.signer.example",
        path: "/model/m/converse",
        query: None,
        content_type: None,
        payload_hash: hash,
        timestamp_epoch: 1_440_938_160,
        amz_headers: &[],
    }
}

/// [`fields`], with a FAILED call's reason.
fn fields_said(s: &SigV4, handle: u64, mode: u32, caller: &str) -> (Outcome, bool, String) {
    answered(signed_as(s, handle, mode, caller))
}

/// What [`SigV4::sign`] answers on `handle` for `mode` and `caller`, unreduced.
fn signed_as(s: &SigV4, handle: u64, mode: u32, caller: &str) -> Option<Signed> {
    let hash = sha256_hex(b"");
    s.sign(handle, who(mode, caller), Ok(facts_over(&hash)))
}

/// The value of field `name` among `signed`'s fields, none when it is not set.
fn field_of(signed: Option<Signed>, name: &str) -> Option<String> {
    match signed {
        Some(Signed::Fields(fields)) => crate::fixtures::plain(fields)
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str().to_owned()),
        _ => panic!("the handle signs"),
    }
}

/// The `authorization` field among `signed`'s fields.
fn authorization_of(signed: Option<Signed>) -> String {
    match signed {
        Some(Signed::Fields(fields)) => crate::fixtures::plain(fields)
            .into_iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v)
            .expect("an authorization is set"),
        _ => panic!("the handle signs"),
    }
}

fn open(s: &SigV4, cred: Option<&str>) -> u64 {
    let binding = style::open_binding(
        style::SIGV4,
        cred.map(str::as_bytes),
        Some(SETTINGS.as_bytes()),
    )
    .expect("the binding opens");
    s.keep(binding)
}

#[test]
fn own_mode_signs_with_the_operator_credential_and_passthrough_with_the_callers() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let caller_owned = open(&s, Some("AKIDCALLER:CALLERSECRET"));
    let hash = sha256_hex(b"");
    let authorization = |handle, who| {
        authorization_of(s.sign(
            handle,
            who,
            Ok(SignFacts {
                method: "POST",
                host: "runtime.signer.example",
                path: "/model/m/converse",
                query: None,
                content_type: None,
                payload_hash: &hash,
                timestamp_epoch: 1_440_938_160,
                amz_headers: &[],
            }),
        ))
    };
    let caller = authorization(handle, Who::Caller(Some(b"AKIDCALLER:CALLERSECRET")));
    let own = authorization(handle, Who::Own);
    assert!(caller.contains("Credential=AKIDCALLER/"), "{caller}");
    assert!(own.contains("Credential=AKIDEXAMPLE/"), "{own}");
    assert_eq!(caller, authorization(caller_owned, Who::Own));
    assert_ne!(
        caller.rsplit("Signature=").next(),
        own.rsplit("Signature=").next()
    );
    assert_eq!(fields(&s, handle, MODE_OWN, ""), (Outcome::Ready, true));
    assert_eq!(
        fields(&s, handle, MODE_PASSTHROUGH, "AKIDCALLER:CALLERSECRET"),
        (Outcome::Ready, true),
        "the caller's own credential signs, independent of the operator's binding"
    );

    assert_eq!(
        fields_said(&s, handle, MODE_PASSTHROUGH, ""),
        (Outcome::Failed, false, NO_CALLER_CREDENTIAL.to_string()),
        "no caller credential: nothing to sign with, so the request fails with the reason"
    );
}

/// r1-test0-1 / r1-test1-4: in passthrough on a handle that holds its own operator credential, the
/// CALLER's credential signs: its access key id in the scope, its own signature (the one a fresh
/// binding over that caller computes), its own session token, and never the operator's. Two callers
/// on one handle share nothing.
#[test]
fn passthrough_on_a_keyed_handle_signs_with_each_callers_own_credential() {
    let s = SigV4::new(1);
    let operator = "AKIDEXAMPLE:SECRET";
    let handle = open(&s, Some(operator));
    let params = style::open_binding(
        style::SIGV4,
        Some(operator.as_bytes()),
        Some(SETTINGS.as_bytes()),
    )
    .expect("the binding opens")
    .params()
    .clone();
    let hash = sha256_hex(b"");
    let reference = |caller: &str| {
        let credential = SigningCredential::parse(caller).expect("a good caller credential");
        let fields = SigV4Binding::new(params.clone(), Some(credential))
            .sign(&facts_over(&hash))
            .expect("signs");
        crate::fixtures::plain(fields)
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.as_str().to_owned())
            .expect("an authorization")
    };

    let own = authorization_of(signed_as(&s, handle, MODE_OWN, ""));
    assert!(own.contains("Credential=AKIDEXAMPLE/"), "{own}");

    let a = "AKIDCALLER:CALLERSECRET:TOKENA";
    let b = "AKIDOTHER:OTHERSECRET:TOKENB";
    let auth_a = authorization_of(signed_as(&s, handle, MODE_PASSTHROUGH, a));
    assert!(auth_a.contains("Credential=AKIDCALLER/"), "{auth_a}");
    assert!(!auth_a.contains("AKIDEXAMPLE"), "{auth_a}");
    assert_ne!(auth_a, own, "the caller's signature is not the operator's");
    assert_eq!(
        auth_a,
        reference(a),
        "signed with exactly the caller's credential"
    );

    let auth_b = authorization_of(signed_as(&s, handle, MODE_PASSTHROUGH, b));
    assert!(auth_b.contains("Credential=AKIDOTHER/"), "{auth_b}");
    assert_ne!(auth_b, auth_a, "two callers do not share a day key");
    assert_ne!(auth_b, own);
    assert_eq!(auth_b, reference(b));

    assert_eq!(
        field_of(
            signed_as(&s, handle, MODE_PASSTHROUGH, b),
            "x-amz-security-token"
        )
        .as_deref(),
        Some("TOKENB"),
        "the caller's own session token"
    );
    assert_eq!(
        field_of(
            signed_as(&s, handle, MODE_PASSTHROUGH, a),
            "x-amz-security-token"
        )
        .as_deref(),
        Some("TOKENA")
    );
    // The operator binding is undisturbed afterwards.
    assert_eq!(authorization_of(signed_as(&s, handle, MODE_OWN, "")), own);
}

/// Owner-signed 2026-10-30 (OWNER-QUEUE.md): "sigv4 with no credential is a passthrough-only
/// binding and is allowed; a malformed credential is still refused at open." So `open_outbound`
/// with NO credential answers a READY handle; own-mode `fields` on it FAILS with the reason (was:
/// READY with no field); passthrough with a good caller credential signs; and a malformed own
/// credential is refused at open, never bound.
#[test]
fn a_keyless_binding_fails_in_own_mode_but_still_serves_passthrough() {
    let s = SigV4::new(1);
    let handle = open(&s, None);
    assert!(
        <SigV4 as busbar_contract::abi::sdk::auth_outbound::OutboundPlugin>::outbound_ready(
            &s, handle
        ),
        "the keyless binding is a READY handle"
    );
    assert_eq!(
        fields_said(&s, handle, MODE_OWN, ""),
        (
            Outcome::Failed,
            false,
            crate::signing::NO_OWN_CREDENTIAL.to_string()
        ),
        "no operator credential: the request is not sent unsigned"
    );
    assert_eq!(
        fields(&s, handle, MODE_PASSTHROUGH, "AKIDCALLER:CALLERSECRET"),
        (Outcome::Ready, true)
    );
    let refused = style::open_binding(
        style::SIGV4,
        Some(b"not-a-valid-key"),
        Some(SETTINGS.as_bytes()),
    )
    .expect_err("a malformed own credential is refused at open");
    assert_eq!(
        refused.iter().map(style::Refusal::line).collect::<Vec<_>>(),
        ["credential: expected ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]"]
    );
}

#[test]
fn an_unsendable_or_malformed_credential_is_refused_at_open_or_fails_its_request() {
    for operator in ["AKID:SECRET:TOK\r\nEN", "not-a-valid-key"] {
        assert!(
            style::open_binding(
                style::SIGV4,
                Some(operator.as_bytes()),
                Some(SETTINGS.as_bytes())
            )
            .is_err(),
            "{operator:?} is refused at open"
        );
    }
    let s = SigV4::new(1);
    let quiet = open(&s, Some("AKID:SECRET:CLEAN"));
    assert_eq!(fields(&s, quiet, MODE_OWN, ""), (Outcome::Ready, true));
    for (caller, reason) in [
        (
            "AKID:SECRET:TOK\r\nEN",
            "caller credential: the session token holds a byte no header value may carry",
        ),
        (
            "not-a-valid-key",
            "caller credential: expected ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]",
        ),
        (
            ":",
            "caller credential: the access key id is empty; caller credential: the secret \
             access key is empty",
        ),
    ] {
        assert_eq!(
            fields_said(&s, quiet, MODE_PASSTHROUGH, caller),
            (Outcome::Failed, false, reason.to_string()),
            "{caller:?}"
        );
    }
    assert_eq!(
        answered(s.sign(
            quiet,
            Who::Caller(Some(&[0xff_u8][..])),
            Ok(SignFacts {
                method: "POST",
                host: "h",
                path: "/p",
                query: None,
                content_type: None,
                payload_hash: &sha256_hex(b""),
                timestamp_epoch: 1,
                amz_headers: &[],
            })
        )),
        (
            Outcome::Failed,
            false,
            "caller credential: the credential is not UTF-8".to_string()
        )
    );
}

#[test]
fn retire_drops_the_generations_handles() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    s.retire(1);
    assert_eq!(fields(&s, handle, MODE_OWN, ""), (Outcome::Refused, false));
}

#[test]
fn tick_answers_its_next_tick_with_or_without_an_open_binding() {
    let s = SigV4::new(1);
    let minute = 60 * 1_000_000_000;
    assert_eq!(
        s.tick_at(1_000, None),
        1_000 + minute,
        "no binding open yet: the schedule goes on, a minute on"
    );
    open(&s, Some("AKIDEXAMPLE:SECRET"));
    assert_eq!(s.tick_at(1_000, None), 1_000 + minute);
    assert_eq!(s.tick_at(1_000, Some(1_440_938_160)), 1_000 + minute);
    assert_eq!(s.tick_at(u64::MAX - 1, None), u64::MAX, "saturates");
}

/// The walked request a `fields` call is lent: its method, path (as sent) and query, and the
/// header envelope it is sent with (`STYLE_NEEDS_HEADERS`).
struct Walked {
    method: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    content_type: Option<&'static str>,
}

/// The `authorization` field `fields` sets for `walked` on the operator's binding `handle`.
fn authorization(s: &SigV4, handle: u64, walked: &Walked) -> String {
    let hash = sha256_hex(b"");
    let headers: Vec<(&[u8], &[u8])> = walked
        .content_type
        .map(|ct| (&b"Content-Type"[..], ct.as_bytes()))
        .into_iter()
        .collect();
    let facts = SignFacts {
        method: walked.method,
        host: "runtime.signer.example",
        path: walked.path,
        query: walked.query.filter(|q| !q.is_empty()),
        content_type: crate::sent_content_type(headers).expect("text"),
        payload_hash: &hash,
        timestamp_epoch: 1_440_938_160,
        amz_headers: &[],
    };
    authorization_of(s.sign(handle, Who::Own, Ok(facts)))
}

/// The `authorization` AWS computes for a request with this canonical method, URI and query over
/// `signed` (beside `host` and the two `x-amz-*` fields), its empty body signed.
fn expected(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    signed: &[(&str, &str)],
) -> String {
    let hash = crate::sigv4::sha256_hex(b"");
    let mut headers: Vec<(String, String)> = signed
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    headers.push(("host".to_string(), "runtime.signer.example".to_string()));
    headers.push(("x-amz-content-sha256".to_string(), hash.clone()));
    headers.push(("x-amz-date".to_string(), "20150830T123600Z".to_string()));
    let (signature, signed_headers) = crate::fixtures::sign_v4(
        "SECRET",
        "us-east-1",
        "svc",
        method,
        canonical_uri,
        canonical_query,
        &headers,
        &hash,
        "20150830T123600Z",
        "20150830",
    );
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/svc/aws4_request, \
         SignedHeaders={signed_headers}, Signature={signature}"
    )
}

#[test]
fn fields_signs_the_walked_requests_method_and_query() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let walked = Walked {
        method: "GET",
        path: "/foundation-models",
        query: Some("byProvider=anthropic&byOutputModality=TEXT"),
        content_type: Some("application/json"),
    };
    assert_eq!(
        authorization(&s, handle, &walked),
        expected(
            "GET",
            "/foundation-models",
            "byOutputModality=TEXT&byProvider=anthropic",
            &[("content-type", "application/json")],
        )
    );
}

#[test]
fn fields_signs_the_double_encoded_canonical_uri() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let walked = Walked {
        method: "POST",
        path: "/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse",
        query: None,
        content_type: Some("application/json"),
    };
    assert_eq!(
        authorization(&s, handle, &walked),
        expected(
            "POST",
            "/model/anthropic.claude-3-haiku-20240307-v1%253A0/converse",
            "",
            &[("content-type", "application/json")],
        )
    );
}

#[test]
fn an_s3_binding_signs_the_path_encoded_once() {
    let s = SigV4::new(1);
    let settings = r#"{"service":"s3","region":"us-east-1"}"#;
    let binding = style::open_binding(
        style::SIGV4,
        Some(b"AKIDEXAMPLE:SECRET"),
        Some(settings.as_bytes()),
    )
    .expect("the binding opens");
    let handle = s.keep(binding);
    let hash = sha256_hex(b"");
    for (wire, canonical) in [
        ("/bucket/key%3A1", "/bucket/key%3A1"),
        ("/bucket/a%2fb c", "/bucket/a%2Fb%20c"),
        ("/bucket//a/./b", "/bucket//a/./b"),
    ] {
        let facts = SignFacts {
            method: "GET",
            host: "bucket.s3.amazonaws.com",
            path: wire,
            query: None,
            content_type: None,
            payload_hash: &hash,
            timestamp_epoch: 1_440_938_160,
            amz_headers: &[],
        };
        let headers = [
            ("host".to_string(), "bucket.s3.amazonaws.com".to_string()),
            ("x-amz-content-sha256".to_string(), hash.clone()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let (signature, signed_headers) = crate::fixtures::sign_v4(
            "SECRET",
            "us-east-1",
            "s3",
            "GET",
            canonical,
            "",
            &headers,
            &hash,
            "20150830T123600Z",
            "20150830",
        );
        assert_eq!(
            authorization_of(s.sign(handle, Who::Own, Ok(facts))),
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, \
                 SignedHeaders={signed_headers}, Signature={signature}"
            ),
            "{wire}"
        );
    }
}

/// The outbound signer reaches the same S3 rule as the inbound check: a binding scoped to each
/// S3 signing name signs the path encoded once, never normalized; one scoped to a name that only
/// opens with `s3` signs it normalized and encoded twice.
#[test]
fn every_s3_signing_name_binding_signs_the_path_encoded_once() {
    let hash = sha256_hex(b"");
    let wire = "/bucket//./key%3A1";
    for (service, canonical) in [
        ("s3", wire),
        ("s3-outposts", wire),
        ("s3-object-lambda", wire),
        ("s3express", wire),
        ("s3control", "/bucket/key%253A1"),
    ] {
        let s = SigV4::new(1);
        let settings = format!(r#"{{"service":"{service}","region":"us-east-1"}}"#);
        let binding = style::open_binding(
            style::SIGV4,
            Some(b"AKIDEXAMPLE:SECRET"),
            Some(settings.as_bytes()),
        )
        .expect("the binding opens");
        let handle = s.keep(binding);
        let facts = SignFacts {
            method: "GET",
            host: "bucket.s3.amazonaws.com",
            path: wire,
            query: None,
            content_type: None,
            payload_hash: &hash,
            timestamp_epoch: 1_440_938_160,
            amz_headers: &[],
        };
        let headers = [
            ("host".to_string(), "bucket.s3.amazonaws.com".to_string()),
            ("x-amz-content-sha256".to_string(), hash.clone()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let (signature, signed_headers) = crate::fixtures::sign_v4(
            "SECRET",
            "us-east-1",
            service,
            "GET",
            canonical,
            "",
            &headers,
            &hash,
            "20150830T123600Z",
            "20150830",
        );
        assert_eq!(
            authorization_of(s.sign(handle, Who::Own, Ok(facts))),
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/{service}/aws4_request, \
                 SignedHeaders={signed_headers}, Signature={signature}"
            ),
            "{service}"
        );
    }
}

#[test]
fn fields_signs_the_content_type_only_as_sent() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let mut walked = Walked {
        method: "POST",
        path: "/model/m/converse",
        query: None,
        content_type: None,
    };
    assert_eq!(
        authorization(&s, handle, &walked),
        expected("POST", "/model/m/converse", "", &[]),
        "none sent, none signed"
    );
    walked.content_type = Some("application/x-amz-json-1.1");
    assert_eq!(
        authorization(&s, handle, &walked),
        expected(
            "POST",
            "/model/m/converse",
            "",
            &[("content-type", "application/x-amz-json-1.1")],
        ),
        "the sent value, signed"
    );
}

#[test]
fn fields_signs_the_query_in_its_canonical_encoding() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let walked = Walked {
        method: "GET",
        path: "/foundation-models",
        query: Some("prefix=a/b:c&marker=x%2fy&k=%7E&flag"),
        content_type: None,
    };
    assert_eq!(
        authorization(&s, handle, &walked),
        expected(
            "GET",
            "/foundation-models",
            "flag=&k=~&marker=x%2Fy&prefix=a%2Fb%3Ac",
            &[],
        )
    );
}

/// An already canonical query is signed unchanged: encoding is idempotent over the canonical form.
#[test]
fn fields_signs_an_already_canonical_query_unchanged() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let walked = Walked {
        method: "GET",
        path: "/foundation-models",
        query: Some("marker=x%2Fy&prefix=a%2Fb%3Ac"),
        content_type: None,
    };
    assert_eq!(
        authorization(&s, handle, &walked),
        expected(
            "GET",
            "/foundation-models",
            "marker=x%2Fy&prefix=a%2Fb%3Ac",
            &[],
        )
    );
}

#[test]
fn the_head_the_transport_completes_signs_to_1_5_5s_bytes() {
    const VECTOR: &str = "AWS4-HMAC-SHA256 \
        Credential=AKIDEXAMPLE/20150830/us-east-1/svc/aws4_request, \
        SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
        Signature=758de1b14d97b1d58b6307ff4c2924f7bdb3cbe3773ed02f7329925faee62472";
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let body: &[u8] = br#"{"messages":[]}"#;
    let hash = sha256_hex(body);
    let line = |name: &'static str, value: &'static str| (name.as_bytes(), value.as_bytes());
    let sign = |head: &[(&'static [u8], &'static [u8])]| {
        let facts = SignFacts {
            method: "POST",
            host: "runtime.signer.example",
            path: "/model/m/converse",
            query: None,
            content_type: crate::sent_content_type(head.iter().copied()).expect("text"),
            payload_hash: &hash,
            timestamp_epoch: 1_440_938_160,
            amz_headers: &[],
        };
        authorization_of(s.sign(handle, Who::Own, Ok(facts)))
    };
    let plane_only = [line("content-type", "application/json")];
    let completed = [
        line("content-type", "application/json"),
        line("host", "runtime.signer.example"),
        line("accept", "*/*"),
    ];
    assert_eq!(sign(&plane_only), VECTOR, "1.5.5's signature");
    assert_eq!(
        sign(&completed),
        VECTOR,
        "the transport's host and accept lines leave the signature 1.5.5's"
    );
}

/// `outbound_ready` is true for a handle this generation holds and for no other: not for one never
/// opened, not for one whose generation was retired.
#[test]
fn outbound_ready_is_false_for_an_unknown_or_retired_handle() {
    use busbar_contract::abi::sdk::auth_outbound::OutboundPlugin;
    let s = SigV4::new(1);
    assert!(!s.outbound_ready(7), "never opened");
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    assert!(s.outbound_ready(handle));
    assert!(!s.outbound_ready(handle + 1), "a handle never handed out");
    s.retire(1);
    assert!(!s.outbound_ready(handle), "its generation was retired");
}

/// `tick` pre-derives each live binding's key for today, so the first request of the day finds it
/// held rather than deriving it on the request path; within the hour before UTC midnight, tomorrow's
/// too. The wall-clock time is passed explicitly (N, audit round 1: never the test's own clock, so
/// the answer does not depend on when the test runs).
#[test]
fn tick_holds_todays_day_key_on_each_open_binding() {
    const NOON: u64 = 1_440_938_160;
    const LATE: u64 = 1_440_977_400;
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let binding = s.binding(handle).expect("the binding is held");
    assert!(binding.held().is_empty(), "nothing derived before a tick");
    s.tick_at(1_000, Some(NOON));
    assert_eq!(binding.held(), ["20150830"]);
    s.tick_at(2_000, Some(LATE));
    assert_eq!(binding.held(), ["20150830", "20150831"]);
}

#[test]
fn a_multibyte_service_is_refused_at_open() {
    let settings = r#"{"service":"ébedrock","region":"us-east-1"}"#;
    let refused =
        crate::style::open_binding("sigv4", Some(b"AKID:SECRET"), Some(settings.as_bytes()))
            .expect_err("the binding is refused");
    assert_eq!(
        refused.iter().map(style::Refusal::line).collect::<Vec<_>>(),
        ["settings.service: not an AWS service name (1 to 64 of a-z, 0-9 and -)"]
    );
}

#[test]
fn no_length_line_is_ever_signed() {
    const VECTOR: &str = "AWS4-HMAC-SHA256 \
        Credential=AKIDEXAMPLE/20150830/us-east-1/svc/aws4_request, \
        SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
        Signature=758de1b14d97b1d58b6307ff4c2924f7bdb3cbe3773ed02f7329925faee62472";
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let hash = sha256_hex(br#"{"messages":[]}"#);
    let line = |name: &'static str, value: &'static str| (name.as_bytes(), value.as_bytes());
    let heads: [&[(&[u8], &[u8])]; 4] = [
        &[line("content-type", "application/json")],
        &[
            line("content-type", "application/json"),
            line("content-length", "15"),
        ],
        &[
            line("content-type", "application/json"),
            line("content-length", "0"),
        ],
        &[
            line("content-type", "application/json"),
            line("host", "runtime.signer.example"),
            line("accept", "*/*"),
            line("content-length", "15"),
        ],
    ];
    for head in heads {
        let facts = SignFacts {
            method: "POST",
            host: "runtime.signer.example",
            path: "/model/m/converse",
            query: None,
            content_type: crate::sent_content_type(head.iter().copied()).expect("text"),
            payload_hash: &hash,
            timestamp_epoch: 1_440_938_160,
            amz_headers: &[],
        };
        let authorization = authorization_of(s.sign(handle, Who::Own, Ok(facts)));
        let signed = authorization
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|r| r.split(',').next())
            .expect("a SignedHeaders list");
        assert!(
            !signed.split(';').any(|h| h == "content-length"),
            "no length line is signed: {authorization}"
        );
        assert_eq!(
            authorization, VECTOR,
            "a head with or without a length line signs to 1.5.5's bytes"
        );
    }
}

#[test]
fn a_failed_fields_call_is_logged_once_without_the_credential() {
    let s = SigV4::new(1);
    let h = open(&s, None);
    let cap = crate::diagnostics::Log::new(tracing::Level::DEBUG);
    tracing::subscriber::with_default(cap.subscriber(), || {
        fields(&s, h, MODE_PASSTHROUGH, "AKIDLOGGED:SECRETLOGGED:TOK\r\nEN");
        fields(&s, h, MODE_OWN, "");
        fields(&s, h, MODE_PASSTHROUGH, "AKIDCLEAN:SECRETCLEAN");
    });
    let logged = cap.messages();
    assert_eq!(logged.len(), 2, "{logged:?}");
    assert!(
        logged.iter().all(|l| l.contains("module=\"sigv4\"")),
        "{logged:?}"
    );
    assert!(
        logged[0].contains("caller credential: the session token holds a byte"),
        "{logged:?}"
    );
    assert!(
        logged[1].contains("holds no credential of its own"),
        "{logged:?}"
    );
    for secret in ["AKIDLOGGED", "SECRETLOGGED", "SECRETCLEAN"] {
        assert!(
            !logged.join("\n").contains(secret),
            "{secret} leaked: {logged:?}"
        );
    }
}

#[test]
fn a_non_s3_binding_signs_the_normalized_path() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    for (wire, canonical) in [
        ("//example//", "/example/"),
        ("/example/..", "/"),
        ("/example1/example2/../..", "/"),
        ("/./", "/"),
        ("/./example", "/example"),
        ("//", "/"),
        ("/a/b/../c%3A", "/a/c%253A"),
        ("/a/b/.", "/a/b/"),
    ] {
        let walked = Walked {
            method: "GET",
            path: wire,
            query: None,
            content_type: None,
        };
        assert_eq!(
            authorization(&s, handle, &walked),
            expected("GET", canonical, "", &[]),
            "{wire}"
        );
    }
}

#[test]
fn a_clock_that_cannot_be_read_skips_the_prederive_and_warns_once() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let binding = s.binding(handle).expect("the binding is held");
    let cap = crate::diagnostics::Log::new(tracing::Level::WARN);
    let next = tracing::subscriber::with_default(cap.subscriber(), || {
        let next = s.tick_at(1_000, None);
        s.tick_at(2_000, None);
        next
    });
    assert!(next > 1_000, "the schedule goes on");
    assert!(
        binding.held().is_empty(),
        "no key derived: {:?}",
        binding.held()
    );
    let warned = cap.messages();
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("module=\"sigv4\""), "{warned:?}");
}

#[test]
fn a_clock_that_recovers_then_fails_again_warns_again() {
    let s = SigV4::new(1);
    open(&s, Some("AKIDEXAMPLE:SECRET"));
    let cap = crate::diagnostics::Log::new(tracing::Level::WARN);
    tracing::subscriber::with_default(cap.subscriber(), || {
        s.tick_at(1_000, None);
        s.tick_at(2_000, None);
        s.tick_at(3_000, Some(1_440_938_160));
        s.tick_at(4_000, None);
        s.tick_at(5_000, None);
    });
    let warned = cap.messages();
    assert_eq!(warned.len(), 2, "one WARN per outage: {warned:?}");
    assert!(
        warned
            .iter()
            .all(|w| w.contains("wall clock is unavailable")),
        "{warned:?}"
    );
}

#[test]
fn a_fields_call_on_an_unknown_or_retired_handle_is_logged() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    s.retire(1);
    let cap = crate::diagnostics::Log::new(tracing::Level::DEBUG);
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert_eq!(fields(&s, 999, MODE_OWN, ""), (Outcome::Refused, false));
        assert_eq!(fields(&s, handle, MODE_OWN, ""), (Outcome::Refused, false));
    });
    let logged = cap.messages();
    assert_eq!(logged.len(), 2, "{logged:?}");
    assert!(
        logged[0].contains("module=\"sigv4\"") && logged[0].contains("handle=999"),
        "{logged:?}"
    );
    assert!(
        logged[1].contains(&format!("handle={handle}")),
        "{logged:?}"
    );
}

#[test]
fn a_handle_kept_while_the_generation_moves_takes_the_new_generation() {
    let s = Arc::new(SigV4::new(1));
    let guard = s.handles.write().unwrap();
    let kept = {
        let s = s.clone();
        std::thread::spawn(move || {
            let binding = style::open_binding(
                style::SIGV4,
                Some(b"AKIDEXAMPLE:SECRET"),
                Some(SETTINGS.as_bytes()),
            )
            .unwrap();
            s.keep(binding)
        })
    };
    while s.next_handle.load(Ordering::Relaxed) == 1 && !kept.is_finished() {
        std::thread::yield_now();
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!kept.is_finished(), "keep() waits on the held handles lock");
    s.generation.store(2, Ordering::Release);
    drop(guard);
    let handle = kept.join().unwrap();
    s.retire(1);
    assert!(
        s.binding(handle).is_some(),
        "kept after the move: generation 2's"
    );
    s.retire(2);
    assert!(s.binding(handle).is_none());
}

#[test]
fn keep_refresh_retire_are_ordered() {
    use busbar_contract::abi::sdk::auth_outbound::OutboundPlugin;
    let s = SigV4::new(1);
    let a = open(&s, Some("AKIDEXAMPLE:SECRET"));
    s.refresh(b"{}", &[], 2).unwrap();
    let b = open(&s, Some("AKIDEXAMPLE:SECRET"));
    s.retire(1);
    let held: Vec<u64> = s
        .handles
        .read()
        .unwrap()
        .values()
        .map(|(g, _)| *g)
        .collect();
    assert_eq!(held, [2]);
    assert!(s.binding(a).is_none() && s.binding(b).is_some());
}
