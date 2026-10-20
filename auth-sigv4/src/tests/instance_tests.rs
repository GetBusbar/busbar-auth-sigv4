// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HANDLE BOOKKEEPING AND `fields` SLOT, both credential modes, over the trampoline the door
//! macro builds — no mint, no wire, no waiting ticket: a sigv4 binding signs synchronously.

use super::*;
use crate::style;
use crate::Fields;
use busbar_contract::abi::auth::{FieldSpan, FieldsIn, FieldsOut, MODE_OWN, MODE_PASSTHROUGH};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::sdk::door::Slot;
use std::ffi::c_void;

fn auth_span() -> busbar_contract::abi::mechanism::call::Span {
    busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 }
}

const SETTINGS: &str =
    r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#;

fn fields(s: &SigV4, handle: u64, mode: u32, caller: &str) -> (Outcome, bool) {
    let (outcome, signed, _) = fields_noted(s, handle, mode, caller);
    (outcome, signed)
}

/// [`fields`], with how many diagnostics the call's envelope carried.
fn fields_noted(s: &SigV4, handle: u64, mode: u32, caller: &str) -> (Outcome, bool, usize) {
    let mut buf = [0_u8; 1024];
    let mut spans = [FieldSpan {
        name: auth_span(),
        value: auth_span(),
        flags: 0,
        _reserved: 0,
    }; 8];
    let mut i: FieldsIn = crate::abi::zeroed_in();
    i.handle = handle;
    i.mode = mode;
    i.request.authority = busbar_contract::abi::mechanism::call::AbiStr {
        ptr: "runtime.signer.example".as_ptr(),
        len: "runtime.signer.example".len(),
    };
    i.request.canonical_path = busbar_contract::abi::mechanism::call::AbiStr {
        ptr: "/model/m/converse".as_ptr(),
        len: "/model/m/converse".len(),
    };
    // The host lends the walked request's method on every call.
    i.request.method = busbar_contract::abi::mechanism::call::AbiStr {
        ptr: "POST".as_ptr(),
        len: "POST".len(),
    };
    i.request.timestamp = 1_440_938_160;
    i.caller_credential = if caller.is_empty() {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: 0,
            flags: 0,
        }
    } else {
        Blob {
            ptr: caller.as_ptr(),
            len: caller.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    };
    (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
    (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 8);
    let mut out: FieldsOut = crate::abi::zeroed_out();
    let inst = std::ptr::from_ref(s).cast_mut().cast::<c_void>();
    let outcome = Fields::call(inst, &i, &mut out);
    (outcome, out.fields_len > 0, out.head.envelope.diags_len)
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
    let s = SigV4::new(1, None);
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
    let s = SigV4::new(1, None);
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
    let s = SigV4::new(1, None);
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
    let s = SigV4::new(1, None);
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
    let s = SigV4::new(1, None);
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
    use busbar_contract::abi::auth::NamedValue;
    use busbar_contract::abi::mechanism::call::AbiStr;
    let at = |t: &'static str| AbiStr {
        ptr: t.as_ptr(),
        len: t.len(),
    };
    let mut buf = [0_u8; 1024];
    let mut spans = [FieldSpan {
        name: auth_span(),
        value: auth_span(),
        flags: 0,
        _reserved: 0,
    }; 8];
    let headers: Vec<NamedValue> = walked
        .content_type
        .map(|ct| NamedValue {
            name: at("Content-Type"),
            value: Blob {
                ptr: ct.as_ptr(),
                len: ct.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            },
        })
        .into_iter()
        .collect();
    let mut i: FieldsIn = crate::abi::zeroed_in();
    i.handle = handle;
    i.mode = MODE_OWN;
    i.request.method = at(walked.method);
    i.request.authority = at("runtime.signer.example");
    i.request.canonical_path = at(walked.path);
    if let Some(q) = walked.query {
        i.request.query = at(q);
    }
    i.request.timestamp = 1_440_938_160;
    (i.headers, i.headers_len) = (headers.as_ptr(), headers.len());
    (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
    (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 8);
    let mut out: FieldsOut = crate::abi::zeroed_out();
    let inst = std::ptr::from_ref(s).cast_mut().cast::<c_void>();
    assert_eq!(Fields::call(inst, &i, &mut out), Outcome::Ready);
    let text = |sp: busbar_contract::abi::mechanism::call::Span| {
        String::from_utf8_lossy(&buf[sp.offset as usize..(sp.offset + sp.len) as usize])
            .into_owned()
    };
    (0..out.fields_len as usize)
        .map(|k| spans[k])
        .find(|f| text(f.name) == "authorization")
        .map(|f| text(f.value))
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
    let s = SigV4::new(1, None);
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
    let s = SigV4::new(1, None);
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
    let s = SigV4::new(1, None);
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
    let s = SigV4::new(1, None);
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
    let s = SigV4::new(1, None);
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
    use busbar_contract::abi::auth::NamedValue;
    use busbar_contract::abi::mechanism::call::AbiStr;
    const VECTOR: &str = "AWS4-HMAC-SHA256 \
        Credential=AKIDEXAMPLE/20150830/us-east-1/svc/aws4_request, \
        SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
        Signature=758de1b14d97b1d58b6307ff4c2924f7bdb3cbe3773ed02f7329925faee62472";
    let s = SigV4::new(1, None);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let body: &[u8] = br#"{"messages":[]}"#;
    let at = |t: &'static str| AbiStr {
        ptr: t.as_ptr(),
        len: t.len(),
    };
    let line = |name: &'static str, value: &'static str| NamedValue {
        name: at(name),
        value: Blob {
            ptr: value.as_ptr(),
            len: value.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        },
    };
    let sign = |head: &[NamedValue]| {
        let mut buf = [0_u8; 1024];
        let mut spans = [FieldSpan {
            name: auth_span(),
            value: auth_span(),
            flags: 0,
            _reserved: 0,
        }; 8];
        let mut i: FieldsIn = crate::abi::zeroed_in();
        i.handle = handle;
        i.mode = MODE_OWN;
        i.request.method = at("POST");
        i.request.authority = at("runtime.signer.example");
        i.request.canonical_path = at("/model/m/converse");
        i.request.timestamp = 1_440_938_160;
        i.body = Blob {
            ptr: body.as_ptr(),
            len: body.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        (i.headers, i.headers_len) = (head.as_ptr(), head.len());
        (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
        (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 8);
        let mut out: FieldsOut = crate::abi::zeroed_out();
        let inst = std::ptr::from_ref(&s).cast_mut().cast::<c_void>();
        assert_eq!(Fields::call(inst, &i, &mut out), Outcome::Ready);
        let text = |sp: busbar_contract::abi::mechanism::call::Span| {
            String::from_utf8_lossy(&buf[sp.offset as usize..(sp.offset + sp.len) as usize])
                .into_owned()
        };
        (0..out.fields_len as usize)
            .map(|k| spans[k])
            .find(|f| text(f.name) == "authorization")
            .map(|f| text(f.value))
            .expect("an authorization is set")
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

/// THE LENGTH LINE IS NEVER SIGNED (busbar Q128 transport-http, ruling (D)). The fleet's one auth
/// style handed the head (`STYLE_NEEDS_HEADERS`) is this one; every other style is handed none. So
/// the one line a framing adds after the auth, HTTP/2's `content-length: 0` for an empty
/// payload-method body (as 1.5.5's client added it), is signed by no auth: this style signs 1.5.5's
/// fixed set (v1.5.5 `proto/bedrock/writer.rs`), and a head carrying a length line, any length or
/// none, signs to the same bytes, with `SignedHeaders` never naming `content-length`.
#[test]
fn no_length_line_is_ever_signed() {
    use busbar_contract::abi::auth::NamedValue;
    use busbar_contract::abi::mechanism::call::AbiStr;
    const VECTOR: &str = "AWS4-HMAC-SHA256 \
        Credential=AKIDEXAMPLE/20150830/us-east-1/svc/aws4_request, \
        SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
        Signature=758de1b14d97b1d58b6307ff4c2924f7bdb3cbe3773ed02f7329925faee62472";
    let s = SigV4::new(1, None);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    let body: &[u8] = br#"{"messages":[]}"#;
    let at = |t: &'static str| AbiStr {
        ptr: t.as_ptr(),
        len: t.len(),
    };
    let line = |name: &'static str, value: &'static str| NamedValue {
        name: at(name),
        value: Blob {
            ptr: value.as_ptr(),
            len: value.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        },
    };
    let sign = |head: &[NamedValue]| {
        let mut buf = [0_u8; 1024];
        let mut spans = [FieldSpan {
            name: auth_span(),
            value: auth_span(),
            flags: 0,
            _reserved: 0,
        }; 8];
        let mut i: FieldsIn = crate::abi::zeroed_in();
        i.handle = handle;
        i.mode = MODE_OWN;
        i.request.method = at("POST");
        i.request.authority = at("runtime.signer.example");
        i.request.canonical_path = at("/model/m/converse");
        i.request.timestamp = 1_440_938_160;
        i.body = Blob {
            ptr: body.as_ptr(),
            len: body.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        (i.headers, i.headers_len) = (head.as_ptr(), head.len());
        (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
        (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 8);
        let mut out: FieldsOut = crate::abi::zeroed_out();
        let inst = std::ptr::from_ref(&s).cast_mut().cast::<c_void>();
        assert_eq!(Fields::call(inst, &i, &mut out), Outcome::Ready);
        let text = |sp: busbar_contract::abi::mechanism::call::Span| {
            String::from_utf8_lossy(&buf[sp.offset as usize..(sp.offset + sp.len) as usize])
                .into_owned()
        };
        (0..out.fields_len as usize)
            .map(|k| spans[k])
            .find(|f| text(f.name) == "authorization")
            .map(|f| text(f.value))
            .expect("an authorization is set")
    };
    let heads: [&[NamedValue]; 4] = [
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
        let authorization = sign(head);
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
