// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HANDLE BOOKKEEPING AND `fields`' BODY ([`SigV4::sign`]), both credential modes — no mint,
//! no wire, no waiting ticket: a sigv4 binding signs synchronously. The frames around it are the
//! contract kit's, driven through the real loader in the `-plugin` crate's tests.

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

/// What a `fields` call answers for `signed`: its outcome, whether it set any field, and how many
/// diagnostics it reported.
fn answered(signed: Option<Signed>) -> (Outcome, bool, usize) {
    match signed {
        None => (Outcome::Refused, false, 0),
        Some(Signed::NoFacts) => (Outcome::Failed, false, 0),
        Some(Signed::Fields { fields, note }) => (
            Outcome::Ready,
            !fields.is_empty(),
            usize::from(note.is_some()),
        ),
    }
}

fn fields(s: &SigV4, handle: u64, mode: u32, caller: &str) -> (Outcome, bool) {
    let (outcome, signed, _) = fields_noted(s, handle, mode, caller);
    (outcome, signed)
}

/// [`fields`], with how many diagnostics the call reported.
fn fields_noted(s: &SigV4, handle: u64, mode: u32, caller: &str) -> (Outcome, bool, usize) {
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
    };
    answered(s.sign(handle, who(mode, caller), Some(facts)))
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
    assert_eq!(
        fields(&s, handle, MODE_PASSTHROUGH, ""),
        (Outcome::Ready, false),
        "no caller credential: nothing to sign with, no fields"
    );
}

#[test]
fn a_keyless_binding_signs_nothing_in_own_mode_but_still_serves_passthrough() {
    let s = SigV4::new(1);
    let handle = open(&s, None);
    assert_eq!(
        fields(&s, handle, MODE_OWN, ""),
        (Outcome::Ready, false),
        "no operator credential: no header, not a fault"
    );
    assert_eq!(
        fields(&s, handle, MODE_PASSTHROUGH, "AKIDCALLER:CALLERSECRET"),
        (Outcome::Ready, true)
    );
}

/// A credential whose session token no header value may carry signs nothing, and EACH request
/// reports the signer's line on its `fields` envelope (1.5.5 logged it per request; the open
/// reports nothing, as 1.5.5's boot did not), in either mode; a merely malformed one reports none.
#[test]
fn an_unsendable_session_token_is_noted_on_each_fields_call() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKID:SECRET:TOK\r\nEN"));
    for _ in 0..2 {
        assert_eq!(
            fields_noted(&s, handle, MODE_OWN, ""),
            (Outcome::Ready, false, 1)
        );
    }
    let quiet = open(&s, Some("AKID:SECRET:CLEAN"));
    assert_eq!(
        fields_noted(&s, quiet, MODE_OWN, ""),
        (Outcome::Ready, true, 0)
    );
    assert_eq!(
        fields_noted(&s, quiet, MODE_PASSTHROUGH, "AKID:SECRET:TOK\r\nEN"),
        (Outcome::Ready, false, 1)
    );
    let malformed = open(&s, Some("not-a-valid-key"));
    assert_eq!(
        fields_noted(&s, malformed, MODE_OWN, ""),
        (Outcome::Ready, false, 0)
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
    let head: Vec<(&[u8], &[u8])> = walked
        .content_type
        .map(|ct| (&b"Content-Type"[..], ct.as_bytes()))
        .into_iter()
        .collect();
    let facts = SignFacts {
        method: walked.method,
        host: "runtime.signer.example",
        path: walked.path,
        query: walked.query.filter(|q| !q.is_empty()),
        content_type: crate::sent_content_type(head),
        payload_hash: &hash,
        timestamp_epoch: 1_440_938_160,
    };
    the_authorization(s.sign(handle, Who::Own, Some(facts)))
}

/// The `authorization` value among the fields a READY `fields` set.
fn the_authorization(signed: Option<Signed>) -> String {
    let Some(Signed::Fields { fields, .. }) = signed else {
        panic!("fields answers READY");
    };
    fields
        .into_iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str().to_owned())
        .expect("an authorization is set")
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
    let sign = |head: &[(&'static str, &'static str)]| {
        let facts = SignFacts {
            method: "POST",
            host: "runtime.signer.example",
            path: "/model/m/converse",
            query: None,
            content_type: crate::sent_content_type(
                head.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())),
            ),
            payload_hash: &hash,
            timestamp_epoch: 1_440_938_160,
        };
        the_authorization(s.sign(handle, Who::Own, Some(facts)))
    };
    let plane_only = [("content-type", "application/json")];
    let completed = [
        ("content-type", "application/json"),
        ("host", "runtime.signer.example"),
        ("accept", "*/*"),
    ];
    assert_eq!(sign(&plane_only), VECTOR, "1.5.5's signature");
    assert_eq!(
        sign(&completed),
        VECTOR,
        "the transport's host and accept lines leave the signature 1.5.5's"
    );
}

/// The host lent no method, host or path: nothing is signed, and the call FAILS on a held handle
/// (an unheld one is REFUSED first).
#[test]
fn a_request_with_no_facts_fails_on_a_held_handle() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    assert_eq!(
        answered(s.sign(handle, Who::Own, None)),
        (Outcome::Failed, false, 0)
    );
    assert_eq!(
        answered(s.sign(999, Who::Own, None)),
        (Outcome::Refused, false, 0)
    );
}
