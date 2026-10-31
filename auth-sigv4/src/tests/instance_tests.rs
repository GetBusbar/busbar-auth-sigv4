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

/// [`fields`], with a FAILED call's reason.
fn fields_said(s: &SigV4, handle: u64, mode: u32, caller: &str) -> (Outcome, bool, String) {
    let hash = sha256_hex(b"");
    // The host lends the walked request's method on every call.
    let facts = SignFacts {
        method: "POST",
        host: "runtime.signer.example",
        path: "/model/m/converse",
        query: None,
        content_type: None,
        payload_hash: &hash,
        timestamp_epoch: 1_440_938_160,
        amz_headers: &[],
    };
    answered(s.sign(handle, who(mode, caller), Ok(facts)))
}

/// The `authorization` field among `signed`'s fields.
fn authorization_of(signed: Option<Signed>) -> String {
    match signed {
        Some(Signed::Fields(fields)) => fields
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.as_str().to_owned())
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
    assert_eq!(fields(&s, handle, MODE_OWN, ""), (Outcome::Ready, true));
    assert_eq!(
        fields(&s, handle, MODE_PASSTHROUGH, "AKIDCALLER:CALLERSECRET"),
        (Outcome::Ready, true),
        "the caller's own credential signs, independent of the operator's binding"
    );
    // OWNER RULING (was: READY with no field): the request is not sent unsigned.
    assert_eq!(
        fields_said(&s, handle, MODE_PASSTHROUGH, ""),
        (Outcome::Failed, false, NO_CALLER_CREDENTIAL.to_string()),
        "no caller credential: nothing to sign with, so the request fails with the reason"
    );
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

/// OWNER RULING (was: a credential whose session token no header value may carry opened, and each
/// request signed nothing beside a WARN note): the operator's is refused at open, and a caller's
/// FAILS its request, each naming the finding, never the credential's bytes.
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

/// RED (BUSBAR-1.6.0.md THE DESIGN §6.5, "a daily signing key derived ahead of time"; `0` = never,
/// `TickOut::next_tick_ns`): THE DAY-KEY SCHEDULE NEVER ENDS. The host starts it at the instance's
/// open, before any binding exists, so an answer of `0` there ends it for good; `tick` answers its
/// next tick whether or not a binding is open, and pre-derives every live binding's key.
#[test]
fn tick_answers_its_next_tick_with_or_without_an_open_binding() {
    let s = SigV4::new(1);
    assert!(
        s.tick(1_000) > 1_000,
        "no binding open yet: the schedule goes on"
    );
    open(&s, Some("AKIDEXAMPLE:SECRET"));
    assert!(s.tick(1_000) > 1_000);
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
    let (signature, signed_headers) = crate::sigv4::sign_v4(
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

/// RED (BUSBAR-1.6.0.md THE DESIGN §6, the per-request auth call on the route walk: "SigV4 signs
/// the real method and query of the walked request"): a GET with a query is signed as a GET over
/// its sorted query, not as a POST with none.
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

/// RED (AWS SigV4, every service but S3: the canonical URI is the path URI-encoded twice; 1.5.5
/// `proxy/egress.rs::sign_and_wire_path_parts`): a model id's `:` is sent as `%3A` and signed as
/// `%253A`, as 1.5.5 signed it and as AWS recomputes it.
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

/// V3 (audit round 1 @57f7ef5, lead-confirmed; the AWS SigV4 spec): S3 is the one service whose
/// canonical URI is the path encoded ONCE (and never normalized). A binding scoped to `s3` signs
/// the key's `:` (sent `%3A`) as `%3A`, a space sent raw as `%20`, and keeps `//` and `.` segments;
/// was: double-encoded as every other service, so every S3 key with a reserved byte failed at AWS.
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
        let (signature, signed_headers) = crate::sigv4::sign_v4(
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

/// RED (the signed set is the sent set): the content type a signature covers is the one the
/// request is sent with, and a request sent with none signs none — never the binding's setting.
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

/// RED (contract `abi/auth/inbound.rs`, the request's query "For `fields`: as it will be sent (a
/// signing style sorts and encodes it)"; AWS SigV4's canonical query string: each name and value
/// URI-encoded over the unreserved set with uppercase hex, then sorted): a query the plane sends
/// with reserved bytes, a lowercase escape, an escaped unreserved byte and a bare name is signed in
/// the canonical form AWS recomputes, not as sent. The expected string is written out by hand here,
/// never computed by the code under test.
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

/// THE 1.5.5 SIGNATURE, WHATEVER ELSE THE HEAD CARRIES (busbar Q128 transport-http, §6 step 5,
/// OWNER-LOCKED: the transport's own lines, `host` and the default `accept: */*`, join the head
/// BEFORE the auth runs, so the auth sees the exact head that is sent). Seeing a line is not signing
/// it: this style signs 1.5.5's set (v1.5.5 `proto/bedrock/writer.rs`: the sent content type, the
/// host, `x-amz-content-sha256`, `x-amz-date`), so a head that also carries `host` and `accept`
/// signs to the same bytes. The vector is 1.5.5's algorithm (v1.5.5 `sigv4.rs::sign_v4`) computed
/// outside this crate: canonical request
/// `POST\n/model/m/converse\n\ncontent-type:application/json\nhost:runtime.signer.example\n
/// x-amz-content-sha256:5e4c…e30a\nx-amz-date:20150830T123600Z\n\n
/// content-type;host;x-amz-content-sha256;x-amz-date\n5e4c…e30a`.
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
    // 2015-08-30 12:36:00 UTC, and 23:30:00 UTC the same day.
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

/// A service that opens with a multi-byte character is no AWS service name: since L2 (audit round
/// 1, the scope settings checked at open) it is refused by name, never bound (and nothing panics on
/// its multi-byte first character).
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

/// THE LENGTH LINE IS NEVER SIGNED (busbar Q128 transport-http, ruling (D)). The one line a framing
/// adds after the auth, HTTP/2's `content-length: 0` for an empty payload-method body (as 1.5.5's
/// client added it), is signed by no auth: this style signs 1.5.5's fixed set (v1.5.5
/// `proto/bedrock/writer.rs`), so a head carrying a length line, any length or none, signs to the
/// same bytes, with `SignedHeaders` never naming `content-length`.
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

/// S5: a `fields` call that FAILS is logged once at `info` (module `sigv4`, its reason), never
/// with the caller's credential bytes; a call that signs logs nothing.
#[test]
fn a_failed_fields_call_is_logged_once_without_the_credential() {
    let s = SigV4::new(1);
    let h = open(&s, None);
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        fields(&s, h, MODE_PASSTHROUGH, "AKIDLOGGED:SECRETLOGGED:TOK\r\nEN");
        fields(&s, h, MODE_OWN, "");
        fields(&s, h, MODE_PASSTHROUGH, "AKIDCLEAN:SECRETCLEAN");
    });
    let logged = cap.messages();
    assert_eq!(logged.len(), 2, "{logged:?}");
    assert!(
        logged.iter().all(|l| l.contains("module=sigv4")),
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

/// L1 (audit round 1 @57f7ef5, lead-confirmed; the AWS SigV4 spec): every service but S3 signs
/// its path NORMALIZED (`//` collapsed, `.` and `..` segments resolved) before it is encoded. The
/// cases are the AWS SigV4 test suite's normalize-path set (`get-slashes`, `get-relative`,
/// `get-relative-relative`, `get-slash-dot-slash`, `get-slash-pointless-dot`, `get-slash`).
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

/// L6 (audit round 1 @57f7ef5, lead-confirmed): a wall clock that cannot be read (before the
/// epoch) is no time to derive keys for: `tick` skips the pre-derivation (never 1970's keys) and
/// warns once, not on every tick, and still answers its next tick.
#[test]
fn a_clock_that_cannot_be_read_skips_the_prederive_and_warns_once() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let binding = s.binding(handle).expect("the binding is held");
    let cap = busbar_test_kit::warn_capture::WarnCapture::default();
    let next = tracing::subscriber::with_default(cap.clone(), || {
        let next = s.tick_at(1_000, None);
        s.tick_at(2_000, None);
        next
    });
    assert!(next > 1_000, "the schedule goes on");
    assert!(binding.held().is_empty(), "no key derived: {:?}", binding.held());
    let warned = cap.messages();
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("module=sigv4"), "{warned:?}");
}
