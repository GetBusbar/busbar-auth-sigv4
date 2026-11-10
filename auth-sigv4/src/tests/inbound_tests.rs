// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `inbound.rs`: busbar-kernel-identity's `ingress_sigv4_tests.rs` ported verbatim (the
//! parse, the date window, the recomputed signature), the kernel's own SigV4 wiring tests
//! (`busbar-kernel/src/auth/tests/tests.rs`: the entry gate, the canonical query, the body binding,
//! `UNSIGNED-PAYLOAD`, an unknown or disabled key), now over [`judge`] with a fake secret source in
//! place of the governance store, and the host-read rules (the dummy secret never admits, not-live
//! never admits, a pending or unavailable read).

use super::*;
use crate::fixtures::sign_v4;
use crate::sigv4::{format_amz_time, sha256_hex, uri_encode_path};

#[test]
fn test_uri_encode_path_dotted_colon_model_id() {
    assert_eq!(
        uri_encode_path("/model/acme.model-1:0/converse"),
        "/model/acme.model-1%3A0/converse"
    );
}

#[test]
fn test_uri_encode_path_assorted_bytes() {
    assert_eq!(uri_encode_path(" "), "%20");
    assert_eq!(uri_encode_path("?a=b&c"), "%3Fa%3Db%26c");
    assert_eq!(uri_encode_path("/"), "/");
    assert_eq!(uri_encode_path("aZ0-_.~"), "aZ0-_.~");

    assert_eq!(uri_encode_path("\u{00c3}"), "%C3%83");
}

/// Verify, through the production verifier (the owner's sealed SigV4 recipe), a request whose
/// `x-amz-meta-tag` was SIGNED as `signed_value` but is SENT as `sent_value`.
fn verify_header_value(signed_value: &str, sent_value: &str) -> Result<(), VerifyError> {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let payload_hash = sha256_hex(b"{\"x\":1}");
    let mut signing_view = vec![
        ("host".to_string(), "svc.example".to_string()),
        ("x-amz-meta-tag".to_string(), signed_value.to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
    ];
    let (sig, signed_headers) = sign_v4(
        secret,
        "us-east-1",
        "svc",
        "POST",
        "/v1/x",
        "",
        &signing_view,
        &payload_hash,
        amzdate,
        "20150830",
    );
    let parsed = ParsedAuthHeader {
        access_key_id: "AKIAEXAMPLE1234567890".to_string(),
        datestamp: "20150830".to_string(),
        region: "us-east-1".to_string(),
        service: "svc".to_string(),
        signed_headers,
        signature: sig,
    };
    signing_view[1].1 = sent_value.to_string();
    let req = InboundRequest {
        method: "POST",
        canonical_uri: "/v1/x",
        canonical_querystring: "",
        headers: &signing_view,
        payload_hash: &payload_hash,
        amzdate,
    };
    verify_inbound_sigv4(&parsed, &req, secret, now)
}

/// Header-value canonicalization as the PRODUCTION verifier applies it: ASCII spaces are trimmed
/// and each run collapsed to one; tabs, NBSP and newlines are kept verbatim (AWS does the same).
#[test]
fn test_verify_header_value_canonicalizes_ascii_space_only() {
    for (signed, sent) in [
        ("a b c", "a   b    c"),
        ("a b c", "  a b c  "),
        ("", ""),
        ("", "   "),
        ("single", "single"),
        ("a\tb", "a\tb"),
        ("a\u{00a0}b", "a\u{00a0}b"),
        ("a \t b", "a  \t  b"),
        ("\u{00a0}a", "\u{00a0}a"),
    ] {
        assert_eq!(
            verify_header_value(signed, sent),
            Ok(()),
            "{sent:?} canonicalizes to {signed:?}"
        );
    }
    for (signed, sent) in [
        ("a b", "a\tb"),
        ("a b", "a\u{00a0}b"),
        ("a b", "a\nb"),
        ("a", "\u{00a0}a"),
    ] {
        assert_eq!(
            verify_header_value(signed, sent),
            Err(VerifyError::SignatureMismatch),
            "{sent:?} must not fold into {signed:?}"
        );
    }
}

/// Build a self-consistent inbound request + parsed header by SIGNING with a known secret.
fn signed_fixture(
    secret: &str,
    region: &str,
    service: &str,
    amzdate: &str,
    datestamp: &str,
) -> (ParsedAuthHeader, Vec<(String, String)>, String) {
    let payload_hash = sha256_hex(b"{\"x\":1}");
    let headers = vec![
        ("host".to_string(), "acme-svc.amazonaws.com".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
    ];
    let (sig, signed_headers) = sign_v4(
        secret,
        region,
        service,
        "POST",
        "/model/acme.model-1/converse",
        "",
        &headers,
        &payload_hash,
        amzdate,
        datestamp,
    );
    let parsed = ParsedAuthHeader {
        access_key_id: "AKIAEXAMPLE1234567890".to_string(),
        datestamp: datestamp.to_string(),
        region: region.to_string(),
        service: service.to_string(),
        signed_headers,
        signature: sig,
    };
    (parsed, headers, payload_hash)
}

fn inbound<'a>(
    headers: &'a [(String, String)],
    payload_hash: &'a str,
    amzdate: &'a str,
) -> InboundRequest<'a> {
    InboundRequest {
        method: "POST",
        canonical_uri: "/model/acme.model-1/converse",
        canonical_querystring: "",
        headers,
        payload_hash,
        amzdate,
    }
}

#[test]
fn test_parse_authorization_header_roundtrip() {
    let v = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/acme-svc/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc123";
    let p = parse_authorization_header(v).expect("must parse");
    assert_eq!(p.access_key_id, "AKID");
    assert_eq!(p.datestamp, "20150830");
    assert_eq!(p.region, "us-east-1");
    assert_eq!(p.service, "acme-svc");
    assert_eq!(p.signed_headers, "host;x-amz-content-sha256;x-amz-date");
    assert_eq!(p.signature, "abc123");
}

#[test]
fn test_parse_authorization_header_rejections() {
    assert_eq!(
        parse_authorization_header("Bearer xyz"),
        Err(VerifyError::MissingAuthorization)
    );
    assert_eq!(
        parse_authorization_header(""),
        Err(VerifyError::MissingAuthorization)
    );
    for bad in [
        "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/acme-svc, SignedHeaders=host, Signature=x",
        "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=x",
        "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/acme-svc/aws4_request, Signature=x",
        "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/acme-svc/aws4_request, SignedHeaders=host",
        "AWS4-HMAC-SHA256 Credential=//us-east-1/acme-svc/aws4_request, SignedHeaders=host, Signature=x",
        "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/acme-svc/aws4_request, SignedHeaders=, Signature=x",
    ] {
        assert_eq!(
            parse_authorization_header(bad),
            Err(VerifyError::MalformedAuthorization),
            "must be malformed: {bad}"
        );
    }
}

#[test]
fn repeated_authorization_sections_are_ambiguous_and_refused() {
    let valid = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/svc/aws4_request, SignedHeaders=host, Signature=abc123";
    for repeated in [
        "Credential=OTHER/20150830/us-east-1/svc/aws4_request",
        "SignedHeaders=host;x-amz-date",
        "Signature=def456",
    ] {
        assert_eq!(
            parse_authorization_header(&format!("{valid}, {repeated}")),
            Err(VerifyError::MalformedAuthorization),
            "{repeated}"
        );
    }
}

#[test]
fn an_impossible_calendar_date_cannot_verify_as_a_later_day() {
    for (invalid, actual) in [
        ("20260231T120000Z", "20260303T120000Z"),
        ("21000229T000000Z", "21000301T000000Z"),
    ] {
        let now = parse_amz_date(actual).expect("valid comparison date");
        let (parsed, headers, hash) =
            signed_fixture(SECRET, "us-east-1", "svc", invalid, &invalid[..8]);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &inbound(&headers, &hash, invalid), SECRET, now),
            Err(VerifyError::MissingDate),
            "{invalid} must not normalize into {actual}"
        );
    }
    for invalid in ["20250229T000000Z", "20260431T000000Z", "20260631T000000Z"] {
        assert_eq!(parse_amz_date(invalid), None, "{invalid}");
    }
    assert!(parse_amz_date("20000229T000000Z").is_some());
    assert!(parse_amz_date("20280229T000000Z").is_some());
}

#[test]
fn sigv4_claims_the_whole_scheme_before_decoding_its_parameters() {
    for (authorization, expected) in [
        (
            &b"AWS4-HMAC-SHA256 Credential=bad\xff"[..],
            Judgement::Reject,
        ),
        (&b"AWS4-HMAC-SHA256X token"[..], Judgement::Pass),
        (&b"AWS4-HMAC-SHA256-OTHER token"[..], Judgement::Pass),
    ] {
        let req = Request {
            lines: vec![(b"authorization", authorization)],
            ..Request::default()
        };
        let mut source = Fake::default();
        assert_eq!(judge(&req, &mut source), expected);
        assert!(source.reads.is_empty());
        assert_eq!(carries_sigv4(&req), expected == Judgement::Reject);
    }
}

#[test]
fn test_parse_amz_date_roundtrips_with_format_amz_time() {
    let epoch = 1_440_938_160u64;
    let (amz, _date) = format_amz_time(epoch);
    assert_eq!(parse_amz_date(&amz), Some(epoch));
    assert_eq!(parse_amz_date("20150830T123600"), None);
    assert_eq!(parse_amz_date("2015-08-30T12:36:00Z"), None);
    assert_eq!(parse_amz_date("20150830X123600Z"), None);
    assert_eq!(parse_amz_date("20151330T123600Z"), None);
    assert_eq!(parse_amz_date(""), None);
}

#[test]
fn test_parse_amz_date_known_epochs_table() {
    let cases: &[(u64, &str)] = &[
        (0, "19700101T000000Z"),
        (86_399, "19700101T235959Z"),
        (5_097_600, "19700301T000000Z"),
        (951_782_400, "20000229T000000Z"),
        (1_609_459_199, "20201231T235959Z"),
        (1_717_200_000, "20240601T000000Z"),
        (4_102_444_800, "21000101T000000Z"),
        (1_078_012_800, "20040229T000000Z"),
    ];
    for (epoch, amzdate) in cases {
        assert_eq!(parse_amz_date(amzdate), Some(*epoch), "amzdate {amzdate}");
    }
}

/// r2-prod0-6: a day the month does not have is not normalised into the next month.
#[test]
fn test_parse_amz_date_refuses_days_the_month_does_not_have() {
    for bad in [
        "20240230T000000Z",
        "20230229T000000Z",
        "19000229T000000Z",
        "20210431T000000Z",
        "20210931T000000Z",
    ] {
        assert_eq!(parse_amz_date(bad), None, "{bad} must be rejected");
    }
    for ok in [
        "20240229T000000Z",
        "20000229T000000Z",
        "20230228T000000Z",
        "20210430T000000Z",
        "20211231T000000Z",
    ] {
        assert!(parse_amz_date(ok).is_some(), "{ok} must be valid");
    }
}

#[test]
fn test_parse_amz_date_componentwise_boundaries() {
    for ok in [
        "20150830T235959Z",
        "20150830T005959Z",
        "20150830T000059Z",
        "20150801T000000Z",
        "20150831T000000Z",
        "20150101T000000Z",
        "20151201T000000Z",
    ] {
        assert!(parse_amz_date(ok).is_some(), "{ok} must be valid");
    }
    for bad in [
        "20150830T240000Z",
        "20150830T006000Z",
        "20150830T000060Z",
        "20150830T235960Z",
        "20150830T000061Z",
        "20150800T000000Z",
        "20150832T000000Z",
        "20150001T000000Z",
        "20151300T000000Z",
    ] {
        assert_eq!(parse_amz_date(bad), None, "{bad} must be rejected");
    }
}

#[test]
fn test_verify_inbound_sigv4_roundtrip_accepts() {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(verify_inbound_sigv4(&parsed, &req, secret, now), Ok(()));
}

#[test]
fn test_verify_inbound_sigv4_repeated_signed_header_is_its_values_comma_joined() {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let payload_hash = sha256_hex(b"{\"x\":1}");
    let check = |signed_value: &str| {
        let signing_view = vec![
            (
                "host".to_string(),
                "example-service.amazonaws.com".to_string(),
            ),
            ("x-amz-meta-tag".to_string(), signed_value.to_string()),
            (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
            (X_AMZ_DATE.to_string(), amzdate.to_string()),
        ];
        let (sig, signed_headers) = sign_v4(
            secret,
            "us-east-1",
            "example-service",
            "POST",
            "/v1/example/invoke",
            "",
            &signing_view,
            &payload_hash,
            amzdate,
            "20150830",
        );
        let parsed = ParsedAuthHeader {
            access_key_id: "AKIAEXAMPLE1234567890".to_string(),
            datestamp: "20150830".to_string(),
            region: "us-east-1".to_string(),
            service: "example-service".to_string(),
            signed_headers,
            signature: sig,
        };
        let wire = vec![
            (
                "host".to_string(),
                "example-service.amazonaws.com".to_string(),
            ),
            ("x-amz-meta-tag".to_string(), " a ".to_string()),
            ("x-amz-meta-tag".to_string(), "b  c".to_string()),
            (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
            (X_AMZ_DATE.to_string(), amzdate.to_string()),
        ];
        let req = InboundRequest {
            method: "POST",
            canonical_uri: "/v1/example/invoke",
            canonical_querystring: "",
            headers: &wire,
            payload_hash: &payload_hash,
            amzdate,
        };
        verify_inbound_sigv4(&parsed, &req, secret, now)
    };

    assert_eq!(check("a,b c"), Ok(()));

    assert_eq!(check("a"), Err(VerifyError::SignatureMismatch));
}

/// The AWS SigV4 test suite (aws-sig-v4-test-suite, credential AKIDEXAMPLE /
/// wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, us-east-1, service `service`, 20150830T123600Z):
/// `get-header-key-duplicate`, `get-header-value-order` and `get-header-value-trim` verify at
/// AWS's published signatures over the request lines exactly as the suite sends them.
#[test]
fn the_aws_suite_repeated_and_trimmed_header_vectors_verify() {
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let empty = sha256_hex(b"");
    let cases = [
        (
            "get-header-key-duplicate",
            "c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea",
            vec![
                ("My-Header1", "value2"),
                ("My-Header1", "value2"),
                ("My-Header1", "value1"),
            ],
        ),
        (
            "get-header-value-order",
            "08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01",
            vec![
                ("My-Header1", "value4"),
                ("My-Header1", "value1"),
                ("My-Header1", "value3"),
                ("My-Header1", "value2"),
            ],
        ),
        (
            "get-header-value-trim",
            "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
            vec![("My-Header1", " value1"), ("My-Header2", " \"a   b   c\"")],
        ),
    ];
    for (name, signature, mine) in cases {
        let mut wire: Vec<(String, String)> =
            vec![("Host".to_string(), "example.amazonaws.com".to_string())];
        wire.extend(
            mine.iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
        );
        wire.push(("X-Amz-Date".to_string(), amzdate.to_string()));
        let mut names: Vec<String> = mine.iter().map(|(k, _)| k.to_lowercase()).collect();
        names.dedup();
        let parsed = ParsedAuthHeader {
            access_key_id: "AKIDEXAMPLE".to_string(),
            datestamp: "20150830".to_string(),
            region: "us-east-1".to_string(),
            service: "service".to_string(),
            signed_headers: format!("host;{};x-amz-date", names.join(";")),
            signature: signature.to_string(),
        };
        let req = InboundRequest {
            method: "GET",
            canonical_uri: "/",
            canonical_querystring: "",
            headers: &wire,
            payload_hash: &empty,
            amzdate,
        };
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, SECRET, now),
            Ok(()),
            "{name}"
        );
    }
}

/// Quoted runs of ASCII spaces collapse too (AWS and botocore do not treat quotes specially),
/// through the production verifier.
#[test]
fn test_verify_inbound_sigv4_quoted_spaces_are_signed_collapsed() {
    for (signed, sent) in [
        (
            "attachment; filename=\"my file.txt\"",
            "attachment; filename=\"my  file.txt\"",
        ),
        ("a b \"c d\" e", "  a   b  \"c   d\"   e  "),
        ("x \"a b\"", "x \"a  b\""),
        ("x \"y z\" w", "x  \"y  z\"  w"),
        ("abc\"", "abc\"  "),
    ] {
        assert_eq!(
            verify_header_value(signed, sent),
            Ok(()),
            "{sent:?} canonicalizes to {signed:?}"
        );
    }
}

#[test]
fn test_verify_inbound_sigv4_wrong_secret_rejected() {
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(
        "the-real-secret",
        "us-east-1",
        "acme-svc",
        amzdate,
        "20150830",
    );
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, "a-DIFFERENT-secret", now),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_tampered_signature_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    let mut sig = parsed.signature.clone();
    let last = sig.pop().unwrap();
    sig.push(if last == '0' { '1' } else { '0' });
    parsed.signature = sig;
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_tampered_body_payload_hash_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, mut headers, _ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    let tampered = sha256_hex(b"{\"evil\":true}");
    for h in headers.iter_mut() {
        if h.0 == X_AMZ_CONTENT_SHA256 {
            h.1 = tampered.clone();
        }
    }
    let req = inbound(&headers, &tampered, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_expired_date_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let signed_epoch = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    let req = inbound(&headers, &ph, amzdate);
    let now = signed_epoch + CLOCK_SKEW_SECS + 60;
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::Expired)
    );
    let now2 = signed_epoch.saturating_sub(CLOCK_SKEW_SECS + 60);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now2),
        Err(VerifyError::Expired)
    );
    let now3 = signed_epoch + CLOCK_SKEW_SECS - 1;
    assert_eq!(verify_inbound_sigv4(&parsed, &req, secret, now3), Ok(()));
}

#[test]
fn test_verify_inbound_sigv4_signed_header_missing_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    let pruned: Vec<(String, String)> = headers
        .into_iter()
        .filter(|(k, _)| k != X_AMZ_DATE)
        .collect();
    let req = inbound(&pruned, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignedHeadersMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_host_must_be_signed() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let payload_hash = sha256_hex(b"");
    let headers = vec![
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
    ];
    let (sig, signed_headers) = sign_v4(
        secret,
        "us-east-1",
        "acme-svc",
        "POST",
        "/x",
        "",
        &headers,
        &payload_hash,
        amzdate,
        "20150830",
    );
    let parsed = ParsedAuthHeader {
        access_key_id: "AKID".to_string(),
        datestamp: "20150830".to_string(),
        region: "us-east-1".to_string(),
        service: "acme-svc".to_string(),
        signed_headers,
        signature: sig,
    };
    let req = InboundRequest {
        method: "POST",
        canonical_uri: "/x",
        canonical_querystring: "",
        headers: &headers,
        payload_hash: &payload_hash,
        amzdate,
    };
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignedHeadersMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_datestamp_must_match_amzdate() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    parsed.datestamp = "20150831".to_string();
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::MalformedAuthorization)
    );
}

#[test]
fn test_verify_inbound_sigv4_unknown_key_dummy_secret_is_signature_mismatch() {
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(
        "a-real-tenant-secret",
        "us-east-1",
        "acme-svc",
        amzdate,
        "20150830",
    );
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, DUMMY_SECRET, now),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn test_parse_authorization_header_skips_unknown_sections() {
    let v = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/acme-svc/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature=abc123, X-Future-Extension=whatever";
    let p = parse_authorization_header(v).expect("unknown section must be skipped, not rejected");
    assert_eq!(p.access_key_id, "AKID");
    assert_eq!(p.signed_headers, "host;x-amz-date");
    assert_eq!(p.signature, "abc123");
    let missing_sig = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/acme-svc/aws4_request, \
                           SignedHeaders=host, X-Extra=1";
    assert_eq!(
        parse_authorization_header(missing_sig),
        Err(VerifyError::MalformedAuthorization)
    );
}

#[test]
fn test_parse_authorization_header_rejects_five_part_credential_with_wrong_termination() {
    let v = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/acme-svc/aws4_bogus, \
                 SignedHeaders=host, Signature=x";
    assert_eq!(
        parse_authorization_header(v),
        Err(VerifyError::MalformedAuthorization)
    );
}

#[test]
fn test_verify_inbound_sigv4_signed_headers_claim_stripped_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    parsed.signed_headers = "host;x-amz-date".to_string();
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_signed_headers_wrong_sort_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    parsed.signed_headers = "x-amz-date;x-amz-content-sha256;host".to_string();
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignedHeadersMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_exact_skew_boundary_accepted() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let signed_epoch = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, signed_epoch + CLOCK_SKEW_SECS),
        Ok(())
    );
    assert_eq!(
        verify_inbound_sigv4(
            &parsed,
            &req,
            secret,
            signed_epoch.saturating_sub(CLOCK_SKEW_SECS)
        ),
        Ok(())
    );
}

#[test]
fn test_verify_inbound_sigv4_missing_date_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    let req = InboundRequest {
        method: "POST",
        canonical_uri: "/model/acme.model-1/converse",
        canonical_querystring: "",
        headers: &headers,
        payload_hash: &ph,
        amzdate: "not-a-date",
    };
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::MissingDate)
    );
}

#[test]
fn test_canonical_query_string_decodes_and_reencodes_each_name_and_value() {
    assert_eq!(crate::sigv4::canonical_query(None), "");
    assert_eq!(crate::sigv4::canonical_query(Some("")), "");
    assert_eq!(crate::sigv4::canonical_query(Some("b=2&a=1")), "a=1&b=2");
    assert_eq!(crate::sigv4::canonical_query(Some("flag")), "flag=");
    assert_eq!(
        crate::sigv4::canonical_query(Some("t=abc==")),
        "t=abc%3D%3D"
    );
    assert_eq!(crate::sigv4::canonical_query(Some("p=a%2Fb")), "p=a%2Fb");
    assert_eq!(crate::sigv4::canonical_query(Some("p=a%2fb")), "p=a%2Fb");
    assert_eq!(
        crate::sigv4::canonical_query(Some("p=a/b:c")),
        "p=a%2Fb%3Ac"
    );
    assert_eq!(crate::sigv4::canonical_query(Some("k=%7E")), "k=~");

    assert_eq!(
        crate::sigv4::canonical_query(Some("&b=2&&a=2&a=1&")),
        "a=1&a=2&b=2"
    );

    assert_eq!(
        crate::sigv4::canonical_query(Some("Param2=value2&Param1=value1")),
        "Param1=value1&Param2=value2",
        "get-vanilla-query-order-key-case"
    );
    assert_eq!(
        crate::sigv4::canonical_query(Some("Param1=value2&Param1=Value1")),
        "Param1=Value1&Param1=value2",
        "get-vanilla-query-order-key"
    );
    assert_eq!(
        crate::sigv4::canonical_query(Some("\u{1234}=bar")),
        "%E1%88%B4=bar",
        "get-vanilla-utf8-query"
    );
}

/// The AWS SigV4 test suite's `get-vanilla-query-order-key-case` (`GET
/// /?Param2=value2&Param1=value1`) and `get-vanilla-utf8-query` (`GET /?ሴ=bar`) verify at AWS's
/// published signatures over the query exactly as the suite sends it.
#[test]
fn the_aws_suite_query_vectors_verify_over_the_received_query() {
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let empty = sha256_hex(b"");
    let wire = vec![
        ("Host".to_string(), "example.amazonaws.com".to_string()),
        ("X-Amz-Date".to_string(), amzdate.to_string()),
    ];
    for (name, query, signature) in [
        (
            "get-vanilla-query-order-key-case",
            "Param2=value2&Param1=value1",
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
        ),
        (
            "get-vanilla-utf8-query",
            "\u{1234}=bar",
            "2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04",
        ),
    ] {
        let parsed = ParsedAuthHeader {
            access_key_id: "AKIDEXAMPLE".to_string(),
            datestamp: "20150830".to_string(),
            region: "us-east-1".to_string(),
            service: "service".to_string(),
            signed_headers: "host;x-amz-date".to_string(),
            signature: signature.to_string(),
        };
        let canonical = crate::sigv4::canonical_query(Some(query));
        let req = InboundRequest {
            method: "GET",
            canonical_uri: "/",
            canonical_querystring: &canonical,
            headers: &wire,
            payload_hash: &empty,
            amzdate,
        };
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, SECRET, now),
            Ok(()),
            "{name}"
        );
    }
}

/// A client signs the canonical query (`p=a%2Fb%3Ac`) and its wire carries the reserved bytes raw
/// (`p=a/b:c`), as a URL library may send them: the judge recomputes the canonical form and admits.
#[test]
fn a_query_sent_with_reserved_bytes_raw_is_judged_over_its_canonical_form() {
    let s = sign(SECRET, AKID, Some("p=a%2Fb%3Ac"), b"", None);
    assert_eq!(
        run(&s.lines, Some("p=a/b:c"), Some(b""), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );
}

/// The access key id and secret of the one LIVE credential the fake host holds.
const AKID: &str = "BBAKLIVE0000000000001";
const SECRET: &str = "live/secret+KEY0000000000000000000000000";
/// A credential the host holds that is NOT live (its key disabled or revoked, or the credential
/// itself revoked or expired).
const DEAD_AKID: &str = "BBAKDEAD0000000000002";
const DEAD_SECRET: &str = "dead/secret+KEY0000000000000000000000000";
/// The request's wall clock: AWS's example timestamp.
const NOW: u64 = 1_440_938_160;
const PATH: &str = "/model/vendor.model/converse";

/// The host's `records.secret`, faked: the live and dead credentials by id, an empty secret (not
/// live) for any other id, and every read recorded (kind, id).
#[derive(Default)]
struct Fake {
    reads: Vec<(String, String)>,
    /// Answer this instead of a secret, when set.
    answer: Option<fn() -> Read>,
    /// Answer these secret bytes for the live id instead of [`SECRET`].
    raw: Option<Vec<u8>>,
}

impl SecretSource for Fake {
    type Secret = Zeroizing<Vec<u8>>;

    fn read(&mut self, kind: &str, id: &str) -> Read {
        self.reads.push((kind.to_string(), id.to_string()));
        if let Some(a) = self.answer {
            return a();
        }
        let (secret, live): (Vec<u8>, bool) = match id {
            AKID => (
                self.raw
                    .clone()
                    .unwrap_or_else(|| SECRET.as_bytes().to_vec()),
                true,
            ),
            DEAD_AKID => (DEAD_SECRET.as_bytes().to_vec(), false),
            _ => (Vec::new(), false),
        };
        Read::Secret {
            secret: Zeroizing::new(secret),
            live,
        }
    }
}

/// A client's signed POST: the `Authorization` value and the header lines it sends, signed with
/// the owner recipe the outbound signer uses (`fixtures::sign_v4`), over `query` (the wire query, signed
/// unchanged) and `body`, declaring `declared` as its `x-amz-content-sha256` (the body's hash
/// unless a test overrides it).
struct Signed {
    auth: String,
    lines: Vec<(String, String)>,
}

fn sign(
    secret: &str,
    akid: &str,
    query: Option<&str>,
    body: &[u8],
    declared: Option<&str>,
) -> Signed {
    sign_for_host(
        "svc.us-east-1.amazonaws.com",
        secret,
        akid,
        query,
        body,
        declared,
    )
}

/// [`sign`], signing `host` as the `host` header.
fn sign_for_host(
    host: &str,
    secret: &str,
    akid: &str,
    query: Option<&str>,
    body: &[u8],
    declared: Option<&str>,
) -> Signed {
    let (amzdate, datestamp) = format_amz_time(NOW);
    let payload_hash = declared.map_or_else(|| sha256_hex(body), str::to_string);
    let headers = vec![
        ("host".to_string(), host.to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.clone()),
    ];
    let (sig, signed_headers) = sign_v4(
        secret,
        "us-east-1",
        "svc",
        "POST",
        &uri_encode_path(PATH),
        query.unwrap_or(""),
        &headers,
        &payload_hash,
        &amzdate,
        &datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={akid}/{datestamp}/us-east-1/svc/aws4_request, \
         SignedHeaders={signed_headers}, Signature={sig}"
    );
    let mut lines = vec![("authorization".to_string(), auth.clone())];
    lines.extend(headers);
    Signed { auth, lines }
}

/// `judge` over `lines`, `query` and `body`, at [`NOW`], against `fake`.
fn run(
    lines: &[(String, String)],
    query: Option<&str>,
    body: Option<&[u8]>,
    fake: &mut Fake,
) -> Judgement {
    run_with_authority(lines, query, body, b"", fake)
}

/// [`run`], the host lending `authority` as the request's HTTP/2 `:authority`.
fn run_with_authority(
    lines: &[(String, String)],
    query: Option<&str>,
    body: Option<&[u8]>,
    authority: &[u8],
    fake: &mut Fake,
) -> Judgement {
    let req = Request {
        method: b"POST",
        path: PATH.as_bytes(),
        query: query.map(str::as_bytes),
        lines: lines
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect(),
        body,
        now: NOW,
        authority,
    };
    judge(&req, fake)
}

#[test]
fn a_signed_request_over_a_live_credential_is_its_access_key_id() {
    let s = sign(SECRET, AKID, None, b"", None);
    let mut fake = Fake::default();
    assert_eq!(
        run(&s.lines, None, Some(b""), &mut fake),
        Judgement::Identity(AKID.to_string())
    );
    assert_eq!(
        fake.reads,
        [("sigv4".to_string(), AKID.to_string())],
        "one read, kind sigv4, id the AccessKeyId"
    );
}

#[test]
fn a_signed_body_that_matches_its_hash_is_admitted() {
    let body = br#"{"max_tokens":16}"#;
    let s = sign(SECRET, AKID, None, body, None);
    assert_eq!(
        run(&s.lines, None, Some(body), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );
}

#[test]
fn an_already_canonical_escaped_query_param_is_judged_unchanged() {
    let s = sign(SECRET, AKID, Some("p=a%2Fb"), b"", None);
    assert_eq!(
        run(&s.lines, Some("p=a%2Fb"), Some(b""), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );
}

#[test]
fn header_names_match_case_insensitively() {
    let s = sign(SECRET, AKID, None, b"", None);
    let upper: Vec<(String, String)> = s
        .lines
        .iter()
        .map(|(n, v)| (n.to_ascii_uppercase(), v.clone()))
        .collect();
    assert_eq!(
        run(&upper, None, Some(b""), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );
}

#[test]
fn an_uppercase_declared_hash_binds_the_body_case_insensitively() {
    let body = b"payload";
    let upper = sha256_hex(body).to_ascii_uppercase();
    let s = sign(SECRET, AKID, None, body, Some(&upper));
    assert_eq!(
        run(&s.lines, None, Some(body), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );
}

#[test]
fn a_wrong_secret_rejects() {
    let s = sign("not-the-secret", AKID, None, b"", None);
    assert_eq!(
        run(&s.lines, None, Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
}

/// r2-prod0-1: a line of a SIGNED name whose value is not visible ASCII is not left out of the
/// verified set: a valid signed request plus such a second line is rejected, not admitted over
/// the subset of lines the signature covers.
#[test]
fn a_signed_header_line_that_is_not_visible_ascii_rejects() {
    let s = sign(SECRET, AKID, None, b"", None);
    let mut fake = Fake::default();
    assert_eq!(
        run(&s.lines, None, Some(b""), &mut fake),
        Judgement::Identity(AKID.to_string()),
        "control: the captured request is admitted"
    );
    let mut replay = s.lines.clone();
    replay.push(("host".to_string(), "\u{e9}vil".to_string()));
    assert_eq!(
        run(&replay, None, Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
    // An unsigned name with such a value is still ignored.
    let mut other = s.lines.clone();
    other.push(("x-other".to_string(), "\u{e9}vil".to_string()));
    assert_eq!(
        run(&other, None, Some(b""), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );
}

#[test]
fn an_unknown_access_key_id_runs_the_full_check_and_rejects() {
    let s = sign(SECRET, "BBAKUNKNOWN000000000", None, b"", None);
    let mut fake = Fake::default();
    assert_eq!(run(&s.lines, None, Some(b""), &mut fake), Judgement::Reject);
    assert_eq!(
        fake.reads,
        [("sigv4".to_string(), "BBAKUNKNOWN000000000".to_string())]
    );
}

#[test]
fn the_dummy_secret_never_admits_even_when_it_verifies() {
    let s = sign(DUMMY_SECRET, "BBAKUNKNOWN000000000", None, b"", None);
    assert_eq!(
        run(&s.lines, None, Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
}

#[test]
fn a_credential_that_is_not_live_never_admits() {
    let s = sign(DEAD_SECRET, DEAD_AKID, None, b"", None);
    let mut fake = Fake::default();
    assert_eq!(run(&s.lines, None, Some(b""), &mut fake), Judgement::Reject);
    assert_eq!(fake.reads.len(), 1);
}

#[test]
fn an_expired_signature_rejects() {
    let s = sign(SECRET, AKID, None, b"", None);
    let req = Request {
        method: b"POST",
        path: PATH.as_bytes(),
        query: None,
        lines: s
            .lines
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect(),
        body: Some(b""),
        now: NOW + CLOCK_SKEW_SECS + 60,
        authority: b"",
    };
    assert_eq!(judge(&req, &mut Fake::default()), Judgement::Reject);
}

#[test]
fn a_tampered_body_rejects_before_any_read() {
    let signed_body = br#"{"max_tokens":16}"#;
    let tampered_body = br#"{"max_tokens":999999}"#;
    let s = sign(SECRET, AKID, None, signed_body, None);
    let mut fake = Fake::default();
    assert_eq!(
        run(&s.lines, None, Some(tampered_body), &mut fake),
        Judgement::Reject
    );
    assert!(
        fake.reads.is_empty(),
        "the body bind precedes the read, as in the kernel"
    );
}

#[test]
fn unsigned_payload_is_refused() {
    let body = b"some-body";
    // Any case of the sentinel. The refusal and its audited reason are pinned: the later
    // payload-hash-mismatch check would reject the same request under another reason.
    for sentinel in ["UNSIGNED-PAYLOAD", "unsigned-payload"] {
        let s = sign(SECRET, AKID, None, body, Some(sentinel));
        let mut fake = Fake::default();
        let cap = crate::diagnostics::Log::new(tracing::Level::DEBUG);
        let judged = tracing::subscriber::with_default(cap.subscriber(), || {
            run(&s.lines, None, Some(body), &mut fake)
        });
        assert_eq!(judged, Judgement::Reject, "{sentinel}");
        let logged = cap.messages().join("\n");
        assert!(
            logged.contains("reason=\"unsigned payload refused\""),
            "{sentinel}: {logged}"
        );
        assert!(fake.reads.is_empty(), "{sentinel}");
    }
}

#[test]
fn a_body_the_host_did_not_lend_rejects() {
    let s = sign(SECRET, AKID, None, b"", None);
    let mut fake = Fake::default();
    assert_eq!(run(&s.lines, None, None, &mut fake), Judgement::Reject);
    assert!(fake.reads.is_empty());
}

#[test]
fn a_bearer_or_no_authorization_is_not_this_plugins_credential() {
    let mut fake = Fake::default();
    let bearer = [("authorization".to_string(), "Bearer tok".to_string())];
    assert_eq!(run(&bearer, None, Some(b""), &mut fake), Judgement::Pass);
    assert_eq!(run(&[], None, Some(b""), &mut fake), Judgement::Pass);

    let s = sign(SECRET, AKID, None, b"", None);
    let mut two = vec![("authorization".to_string(), "Bearer tok".to_string())];
    two.extend(s.lines.iter().cloned());
    assert_eq!(run(&two, None, Some(b""), &mut fake), Judgement::Pass);

    let odd = [("authorization".to_string(), format!("{}\u{00e9}", s.auth))];
    assert_eq!(run(&odd, None, Some(b""), &mut fake), Judgement::Reject);
    assert!(fake.reads.is_empty());
}

#[test]
fn a_leading_space_before_the_algorithm_is_still_sigv4() {
    let s = sign(SECRET, AKID, None, b"", None);
    let mut lines = s.lines.clone();
    lines[0].1 = format!("  {}", s.auth);
    assert_eq!(
        run(&lines, None, Some(b""), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );
}

#[test]
fn the_structural_gate_rejects_before_any_read() {
    let mut fake = Fake::default();

    let trivial = [
        (
            "authorization".to_string(),
            "AWS4-HMAC-SHA256 x".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), sha256_hex(b"")),
        (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
    ];
    assert_eq!(run(&trivial, None, Some(b""), &mut fake), Judgement::Reject);

    let s = sign(SECRET, AKID, None, b"", None);
    for missing in [X_AMZ_DATE, X_AMZ_CONTENT_SHA256] {
        let pruned: Vec<(String, String)> = s
            .lines
            .iter()
            .filter(|(n, _)| n != missing)
            .cloned()
            .collect();
        assert_eq!(run(&pruned, None, Some(b""), &mut fake), Judgement::Reject);
    }
    assert!(fake.reads.is_empty());
}

#[test]
fn a_tampered_path_query_or_method_rejects() {
    let s = sign(SECRET, AKID, Some("a=1"), b"", None);
    assert_eq!(
        run(&s.lines, Some("a=2"), Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
    let req = Request {
        method: b"PUT",
        path: PATH.as_bytes(),
        query: Some(b"a=1"),
        lines: s
            .lines
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect(),
        body: Some(b""),
        now: NOW,
        authority: b"",
    };
    assert_eq!(judge(&req, &mut Fake::default()), Judgement::Reject);
    let req = Request {
        method: b"POST",
        path: b"/model/other/converse",
        ..req
    };
    assert_eq!(judge(&req, &mut Fake::default()), Judgement::Reject);
}

#[test]
fn a_pending_read_pends_and_an_unavailable_one_rejects() {
    let s = sign(SECRET, AKID, None, b"", None);
    let mut fake = Fake {
        answer: Some(|| Read::Pending),
        ..Fake::default()
    };
    assert_eq!(
        run(&s.lines, None, Some(b""), &mut fake),
        Judgement::Pending
    );
    fake.answer = Some(|| Read::Unavailable("declined"));
    assert_eq!(run(&s.lines, None, Some(b""), &mut fake), Judgement::Reject);
}

/// r1-test1-10: a `records.secret` outage is operator-actionable: the reject is logged at WARN
/// naming the service's error, never silently.
#[test]
fn an_unavailable_secret_read_rejects_with_a_warn_naming_the_service_error() {
    let s = sign(SECRET, AKID, None, b"", None);
    let mut fake = Fake {
        answer: Some(|| Read::Unavailable("declined")),
        ..Fake::default()
    };
    let warns = crate::diagnostics::Log::new(tracing::Level::WARN);
    let judged = tracing::subscriber::with_default(warns.subscriber(), || {
        run(&s.lines, None, Some(b""), &mut fake)
    });
    assert_eq!(judged, Judgement::Reject);
    let logged = warns.messages();
    assert_eq!(logged.len(), 1, "one WARN: {logged:?}");
    for want in [
        "module=\"sigv4\"",
        "reason=\"credential-unavailable\"",
        "service_error=\"declined\"",
    ] {
        assert!(logged[0].contains(want), "{want}: {logged:?}");
    }
}

/// r1-test1-10: a host that lent no body broke its own rule: the reject is an operator matter,
/// logged at WARN.
#[test]
fn a_host_that_lent_no_body_rejects_with_a_warn() {
    let s = sign(SECRET, AKID, None, b"", None);
    let warns = crate::diagnostics::Log::new(tracing::Level::WARN);
    let judged = tracing::subscriber::with_default(warns.subscriber(), || {
        run(&s.lines, None, None, &mut Fake::default())
    });
    assert_eq!(judged, Judgement::Reject);
    let logged = warns.messages();
    assert_eq!(logged.len(), 1, "one WARN: {logged:?}");
    assert!(logged[0].contains("module=\"sigv4\""), "{logged:?}");
    assert!(logged[0].contains("the host lent no body"), "{logged:?}");
}

/// r1-test1-1: an HTTP/2 request carries its host as `:authority`, never a `host` line. A signed
/// `host` with no `host` line is judged over the authority the host lends.
#[test]
fn a_signed_host_with_no_host_line_is_judged_over_the_http2_authority() {
    let host = "runtime.example";
    let s = sign_for_host(host, SECRET, AKID, None, b"", None);
    let wire: Vec<(String, String)> = s
        .lines
        .iter()
        .filter(|(n, _)| n != "host")
        .cloned()
        .collect();
    assert_eq!(
        run_with_authority(
            &wire,
            None,
            Some(b""),
            host.as_bytes(),
            &mut Fake::default()
        ),
        Judgement::Identity(AKID.to_string()),
        "the authority stands in for the missing host line"
    );
    assert_eq!(
        run_with_authority(&wire, None, Some(b""), b"", &mut Fake::default()),
        Judgement::Reject,
        "no host line and no authority: the signed host cannot be rebuilt"
    );
    assert_eq!(
        run_with_authority(
            &wire,
            None,
            Some(b""),
            b"other.example",
            &mut Fake::default()
        ),
        Judgement::Reject,
        "a different authority is a different signed host"
    );
    // A host line, when present, wins over the authority.
    assert_eq!(
        run_with_authority(
            &s.lines,
            None,
            Some(b""),
            b"other.example",
            &mut Fake::default()
        ),
        Judgement::Identity(AKID.to_string()),
        "the host line wins"
    );
}

#[test]
fn a_secret_that_is_not_utf8_never_admits() {
    let s = sign(DUMMY_SECRET, AKID, None, b"", None);
    let mut fake = Fake {
        raw: Some(vec![0xff, 0xfe]),
        ..Fake::default()
    };
    assert_eq!(run(&s.lines, None, Some(b""), &mut fake), Judgement::Reject);

    let mut utf8 = Fake {
        raw: Some(DUMMY_SECRET.as_bytes().to_vec()),
        ..Fake::default()
    };
    assert_eq!(
        run(&s.lines, None, Some(b""), &mut utf8),
        Judgement::Identity(AKID.to_string())
    );
}

/// The wire path holds a reserved byte (`%3A`); a client signs its canonical URI, the wire path
/// encoded again (`%253A`), and the judge admits it.
#[test]
fn a_path_with_a_reserved_byte_is_judged_over_its_double_encoded_canonical_uri() {
    let wire = "/model/acme.model-1%3A0/converse";
    assert_eq!(uri_encode_path(wire), "/model/acme.model-1%253A0/converse");
    let (amzdate, datestamp) = format_amz_time(NOW);
    let payload_hash = sha256_hex(b"");
    let headers = vec![
        (
            "host".to_string(),
            "svc.us-east-1.amazonaws.com".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.clone()),
    ];
    let (sig, signed_headers) = sign_v4(
        SECRET,
        "us-east-1",
        "svc",
        "POST",
        "/model/acme.model-1%253A0/converse",
        "",
        &headers,
        &payload_hash,
        &amzdate,
        &datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={AKID}/{datestamp}/us-east-1/svc/aws4_request, \
         SignedHeaders={signed_headers}, Signature={sig}"
    );
    let mut lines = vec![("authorization".to_string(), auth)];
    lines.extend(headers);
    let req = |path: &'static str| Request {
        method: b"POST",
        path: path.as_bytes(),
        query: None,
        lines: lines
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect(),
        body: Some(b""),
        now: NOW,
        authority: b"",
    };
    assert_eq!(
        judge(&req(wire), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );

    assert_eq!(
        judge(&req("/model/acme.model-1:0/converse"), &mut Fake::default()),
        Judgement::Reject
    );
}

/// A request judged against a client signature over `canonical_uri`, scoped to `service`, its
/// wire path `wire`.
fn judge_path(service: &str, canonical_uri: &str, wire: &str) -> Judgement {
    let (amzdate, datestamp) = format_amz_time(NOW);
    let payload_hash = sha256_hex(b"");
    let headers = vec![
        ("host".to_string(), "bucket.s3.amazonaws.com".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.clone()),
    ];
    let (sig, signed_headers) = sign_v4(
        SECRET,
        "us-east-1",
        service,
        "GET",
        canonical_uri,
        "",
        &headers,
        &payload_hash,
        &amzdate,
        &datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={AKID}/{datestamp}/us-east-1/{service}/aws4_request, \
         SignedHeaders={signed_headers}, Signature={sig}"
    );
    let mut lines = vec![("authorization".to_string(), auth)];
    lines.extend(headers);
    let req = Request {
        method: b"GET",
        path: wire.as_bytes(),
        query: None,
        lines: lines
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect(),
        body: Some(b""),
        now: NOW,
        authority: b"",
    };
    judge(&req, &mut Fake::default())
}

#[test]
fn an_s3_scoped_request_is_judged_over_its_path_encoded_once() {
    let admitted = Judgement::Identity(AKID.to_string());
    assert_eq!(
        judge_path("s3", "/bucket/key%3A1", "/bucket/key%3A1"),
        admitted
    );
    assert_eq!(
        judge_path("s3", "/bucket/a%2Fb%20c", "/bucket/a%2fb%20c"),
        admitted,
        "a lowercase escape on the wire is the same key"
    );
    assert_eq!(
        judge_path("s3", "/bucket//a/./b", "/bucket//a/./b"),
        admitted,
        "S3 keeps `//` and `.` segments"
    );
    assert_eq!(
        judge_path("s3", "/bucket/key%253A1", "/bucket/key%3A1"),
        Judgement::Reject,
        "S3 is never double-encoded"
    );
    assert_eq!(
        judge_path("svc", "/bucket/key%253A1", "/bucket/key%3A1"),
        admitted,
        "every other service is double-encoded"
    );
}

#[test]
fn a_repeated_signed_header_is_judged_over_all_its_values() {
    let (amzdate, datestamp) = format_amz_time(NOW);
    let payload_hash = sha256_hex(b"");
    let lines_for = |signed_value: &str| {
        let signing_view = vec![
            ("host".to_string(), "svc.example".to_string()),
            ("x-amz-meta-tag".to_string(), signed_value.to_string()),
            (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
            (X_AMZ_DATE.to_string(), amzdate.clone()),
        ];
        let (sig, signed_headers) = sign_v4(
            SECRET,
            "us-east-1",
            "svc",
            "POST",
            &uri_encode_path(PATH),
            "",
            &signing_view,
            &payload_hash,
            &amzdate,
            &datestamp,
        );
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={AKID}/{datestamp}/us-east-1/svc/aws4_request, \
             SignedHeaders={signed_headers}, Signature={sig}"
        );
        vec![
            ("authorization".to_string(), auth),
            ("host".to_string(), "svc.example".to_string()),
            ("x-amz-meta-tag".to_string(), "a".to_string()),
            (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
            ("x-amz-meta-tag".to_string(), "b".to_string()),
            (X_AMZ_DATE.to_string(), amzdate.clone()),
        ]
    };

    assert_eq!(
        run(&lines_for("a,b"), None, Some(b""), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );

    assert_eq!(
        run(&lines_for("a"), None, Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
}

#[test]
fn an_unreadable_duplicate_of_a_signed_name_is_never_dropped_from_verification() {
    let (amzdate, datestamp) = format_amz_time(NOW);
    let hash = sha256_hex(b"");
    let signed_lines = vec![
        ("host".to_string(), "svc.example".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.clone()),
        ("x-signed".to_string(), "original".to_string()),
    ];
    let (signature, names) = sign_v4(
        SECRET,
        "us-east-1",
        "svc",
        "POST",
        PATH,
        "",
        &signed_lines,
        &hash,
        &amzdate,
        &datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={AKID}/{datestamp}/us-east-1/svc/aws4_request, \
         SignedHeaders={names}, Signature={signature}"
    );
    let mut lines = vec![(b"authorization".as_slice(), auth.as_bytes())];
    lines.extend(
        signed_lines
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes())),
    );
    let request = Request {
        method: b"POST",
        path: PATH.as_bytes(),
        lines,
        body: Some(b""),
        now: NOW,
        ..Request::default()
    };
    assert_eq!(
        judge(&request, &mut Fake::default()),
        Judgement::Identity(AKID.into())
    );
    for value in [b"\x80".as_slice(), "é".as_bytes(), b"bad\x7f"] {
        for first in [false, true] {
            let mut tampered = request.clone();
            if first {
                tampered.lines.insert(1, (b"X-Signed", value));
            } else {
                tampered.lines.push((b"X-Signed", value));
            }
            let mut source = Fake::default();
            assert_eq!(judge(&tampered, &mut source), Judgement::Reject);
            assert!(
                source.reads.is_empty(),
                "unreadable signed bytes refuse before a secret read"
            );
        }
        let mut unsigned = request.clone();
        unsigned.lines.push((b"x-unsigned", value));
        assert_eq!(
            judge(&unsigned, &mut Fake::default()),
            Judgement::Identity(AKID.into()),
            "unsigned header policy stays the same"
        );
    }
}

/// r2-prod0-3: the host answers an EMPTY, not-live secret for an id it does not hold (and the
/// kernel leaves the dummy to the verifier), so the plugin verifies over its own dummy whenever the
/// credential is not live or its secret is not text; a live text secret is verified as is.
#[test]
fn the_verification_runs_over_the_dummy_unless_the_credential_is_live_text() {
    assert_eq!(verification_text(b"", false), (DUMMY_SECRET, true));
    assert_eq!(
        verification_text(SECRET.as_bytes(), false),
        (DUMMY_SECRET, true)
    );
    assert_eq!(verification_text(SECRET.as_bytes(), true), (SECRET, true));
    assert_eq!(
        verification_text(&[0xff, 0xfe], true),
        (DUMMY_SECRET, false)
    );
    assert_eq!(
        verification_text(&[0xff, 0xfe], false),
        (DUMMY_SECRET, false)
    );
}

/// A request signed over `claimed` (the SignedHeaders list as the client writes it) whose
/// canonical headers are `canon` (name, value) in the order verify recomputes them, with a real
/// signature over that canonical form. The wire carries `wire`.
fn forged_signed_headers(
    claimed: &str,
    canon: &[(&str, &str)],
    wire: &[(&str, &str)],
) -> (ParsedAuthHeader, Vec<(String, String)>, String, String) {
    let amzdate = "20150830T123600Z".to_string();
    let payload_hash = sha256_hex(b"{\"x\":1}");
    let own = |v: &[(&str, &str)]| -> Vec<(String, String)> {
        v.iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    };

    let (sig, _) = sign_v4(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "svc",
        "POST",
        "/v1/x",
        "",
        &own(canon),
        &payload_hash,
        &amzdate,
        "20150830",
    );
    let parsed = ParsedAuthHeader {
        access_key_id: "AKIAEXAMPLE1234567890".to_string(),
        datestamp: "20150830".to_string(),
        region: "us-east-1".to_string(),
        service: "svc".to_string(),
        signed_headers: claimed.to_string(),
        signature: sig,
    };
    (parsed, own(wire), payload_hash, amzdate)
}

#[test]
fn a_signed_headers_list_that_repeats_a_name_is_refused_before_any_copying() {
    let ph = sha256_hex(b"{\"x\":1}");
    let wire = [
        ("host", "svc.example"),
        (X_AMZ_CONTENT_SHA256, ph.as_str()),
        (X_AMZ_DATE, "20150830T123600Z"),
        ("x-dup", "v"),
    ];

    let canon = [
        ("host", "svc.example"),
        (X_AMZ_CONTENT_SHA256, ph.as_str()),
        (X_AMZ_DATE, "20150830T123600Z"),
        ("x-dup", "v"),
        ("x-dup", "v"),
    ];
    let claimed = "host;x-amz-content-sha256;x-amz-date;x-dup;x-dup";
    let (parsed, headers, payload_hash, amzdate) = forged_signed_headers(claimed, &canon, &wire);
    let now = parse_amz_date(&amzdate).unwrap();
    let req = InboundRequest {
        method: "POST",
        canonical_uri: "/v1/x",
        canonical_querystring: "",
        headers: &headers,
        payload_hash: &payload_hash,
        amzdate: &amzdate,
    };
    assert_eq!(
        verify_inbound_sigv4(
            &parsed,
            &req,
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            now
        ),
        Err(VerifyError::SignedHeadersMismatch)
    );
}

#[test]
fn a_repeated_name_signed_headers_list_is_rejected_by_judge() {
    let (amzdate, datestamp) = format_amz_time(NOW);
    let ph = sha256_hex(b"");
    let canon = vec![
        ("host".to_string(), "svc.example".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), ph.clone()),
        (X_AMZ_DATE.to_string(), amzdate.clone()),
        ("x-dup".to_string(), "v".to_string()),
        ("x-dup".to_string(), "v".to_string()),
    ];
    let (sig, _) = sign_v4(
        SECRET,
        "us-east-1",
        "svc",
        "POST",
        &uri_encode_path(PATH),
        "",
        &canon,
        &ph,
        &amzdate,
        &datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={AKID}/{datestamp}/us-east-1/svc/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-dup;x-dup, Signature={sig}"
    );
    let lines = vec![
        ("authorization".to_string(), auth),
        ("host".to_string(), "svc.example".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), ph),
        (X_AMZ_DATE.to_string(), amzdate),
        ("x-dup".to_string(), "v".to_string()),
    ];
    assert_eq!(
        run(&lines, None, Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
}

#[test]
fn a_mixed_case_signed_headers_list_is_refused_before_the_signature_compare() {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "acme-svc", amzdate, "20150830");
    parsed.signed_headers = "Host;x-amz-content-sha256;x-amz-date".to_string();
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignedHeadersMismatch)
    );
}

/// A `Request`'s `Debug` names its header lines and never prints their values: the Authorization
/// signature and the session token ride in them.
#[test]
fn a_requests_debug_names_its_lines_but_prints_no_value() {
    let req = Request {
        method: b"POST",
        path: PATH.as_bytes(),
        query: Some(b"X-Amz-Credential=AKID&X-Amz-Signature=QUERYSECRET"),
        lines: vec![
            (
                &b"authorization"[..],
                &b"AWS4-HMAC-SHA256 Signature=SIGSECRET"[..],
            ),
            (&b"x-amz-security-token"[..], &b"SECRETTOK"[..]),
        ],
        body: Some(b"BODYSECRET"),
        now: NOW,
        authority: b"",
    };
    let printed = format!("{req:?}");
    for secret in ["SECRETTOK", "SIGSECRET", "BODYSECRET", "QUERYSECRET"] {
        assert!(!printed.contains(secret), "{secret} leaked: {printed}");
    }
    assert!(printed.contains("x-amz-security-token"), "{printed}");
    assert!(printed.contains("POST"), "{printed}");
}

/// The info lines `judge` logs over `lines` at `now`, and its judgement.
fn logged_judging(lines: &[(String, String)], now: u64) -> (Judgement, String) {
    let req = Request {
        method: b"POST",
        path: PATH.as_bytes(),
        query: None,
        lines: lines
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect(),
        body: Some(b""),
        now,
        authority: b"",
    };
    let cap = crate::diagnostics::Log::new(tracing::Level::DEBUG);
    let judged =
        tracing::subscriber::with_default(cap.subscriber(), || judge(&req, &mut Fake::default()));
    (judged, cap.messages().join("\n"))
}

/// `lines` with the value of every line named `name` replaced by `value`.
fn with_line(lines: &[(String, String)], name: &str, value: &str) -> Vec<(String, String)> {
    lines
        .iter()
        .map(|(n, v)| {
            if n == name {
                (n.clone(), value.to_string())
            } else {
                (n.clone(), v.clone())
            }
        })
        .collect()
}

#[test]
fn each_verification_reject_is_logged_with_its_expected_reason() {
    let s = sign(SECRET, AKID, None, b"", None);
    let (tomorrow, _) = format_amz_time(NOW + 86_400);
    let auth = s.lines[0].1.clone();
    let cases = [
        ("expired", s.lines.clone(), NOW + CLOCK_SKEW_SECS + 60),
        (
            "missing-date",
            with_line(&s.lines, X_AMZ_DATE, "not-a-date"),
            NOW,
        ),
        (
            "malformed",
            with_line(&s.lines, X_AMZ_DATE, &tomorrow),
            NOW + 86_400,
        ),
        (
            "signed-headers",
            with_line(
                &s.lines,
                "authorization",
                &auth.replace("SignedHeaders=host;", "SignedHeaders="),
            ),
            NOW,
        ),
        (
            "signature",
            sign("not-the-secret", AKID, None, b"", None).lines,
            NOW,
        ),
        (
            "signature",
            sign(SECRET, "BBAKNOBODY0000000000", None, b"", None).lines,
            NOW,
        ),
        (
            "signature",
            sign(DEAD_SECRET, DEAD_AKID, None, b"", None).lines,
            NOW,
        ),
        (
            "signature",
            sign(DUMMY_SECRET, "BBAKNOBODY0000000000", None, b"", None).lines,
            NOW,
        ),
        (
            "unparseable SigV4 authorization",
            with_line(&s.lines, "authorization", "AWS4-HMAC-SHA256 malformed"),
            NOW,
        ),
        (
            "unsigned payload refused",
            with_line(&s.lines, X_AMZ_CONTENT_SHA256, "UNSIGNED-PAYLOAD"),
            NOW,
        ),
        (
            "payload hash mismatch",
            with_line(&s.lines, X_AMZ_CONTENT_SHA256, &"0".repeat(64)),
            NOW,
        ),
        (
            "no x-amz-content-sha256 or x-amz-date line",
            s.lines
                .iter()
                .filter(|(name, _)| name != X_AMZ_DATE)
                .cloned()
                .collect(),
            NOW,
        ),
    ];
    for (word, lines, now) in cases {
        let (judged, logged) = logged_judging(&lines, now);
        assert_eq!(judged, Judgement::Reject, "{word}");
        assert_eq!(logged.lines().count(), 1, "logged once: {logged}");
        assert!(
            logged.contains(&format!("reason=\"{word}\" "))
                || logged.ends_with(&format!("reason=\"{word}\"")),
            "{word}: {logged}"
        );
    }
}

#[test]
fn missing_body_and_unreadable_request_facts_are_audited_before_secret_lookup() {
    let s = sign(SECRET, AKID, None, b"", None);
    for (reason, method, path, query, body) in [
        (
            "the host lent no body",
            &b"POST"[..],
            PATH.as_bytes(),
            None,
            None,
        ),
        (
            "the method or path is not UTF-8",
            &b"\xff"[..],
            PATH.as_bytes(),
            None,
            Some(&b""[..]),
        ),
        (
            "the method or path is not UTF-8",
            &b"POST"[..],
            &b"\xff"[..],
            None,
            Some(&b""[..]),
        ),
        (
            "the query is not UTF-8",
            &b"POST"[..],
            PATH.as_bytes(),
            Some(&b"\xff"[..]),
            Some(&b""[..]),
        ),
    ] {
        let request = Request {
            method,
            path,
            query,
            body,
            now: NOW,
            authority: b"",
            lines: s
                .lines
                .iter()
                .map(|(name, value)| (name.as_bytes(), value.as_bytes()))
                .collect(),
        };
        let mut source = Fake::default();
        let cap = crate::diagnostics::Log::new(tracing::Level::DEBUG);
        let judged =
            tracing::subscriber::with_default(cap.subscriber(), || judge(&request, &mut source));
        assert_eq!(judged, Judgement::Reject);
        assert!(source.reads.is_empty());
        let messages = cap.messages();
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(messages[0].contains(reason), "{messages:?}");
        assert!(!messages[0].contains(SECRET));
        assert!(!messages[0].contains(&s.auth));
    }
}

/// A rejected SigV4 request is logged (module `sigv4`, its reason), never with the signature or
/// the secret; the client still gets the one opaque 401.
#[test]
fn a_bad_signature_reject_is_logged_without_the_signature() {
    let s = sign("not-the-secret", AKID, None, b"", None);
    let signature = s.auth.rsplit("Signature=").next().unwrap().to_string();
    let cap = crate::diagnostics::Log::new(tracing::Level::DEBUG);
    let judged = tracing::subscriber::with_default(cap.subscriber(), || {
        run(&s.lines, None, Some(b""), &mut Fake::default())
    });
    assert_eq!(judged, Judgement::Reject);
    let logged = cap.messages().join("\n");
    assert!(logged.contains("module=\"sigv4\""), "{logged:?}");
    assert!(logged.contains("reason=\"signature\""), "{logged:?}");
    assert!(
        !logged.contains(&signature),
        "the signature leaked: {logged:?}"
    );
    assert!(!logged.contains(SECRET), "the secret leaked: {logged:?}");
}

#[test]
fn a_parsed_authorization_debug_withholds_the_signature() {
    let parsed = parse_authorization_header(
        "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/svc/aws4_request, \
         SignedHeaders=host;x-amz-date, Signature=deadbeefcafe0123",
    )
    .expect("parses");
    let printed = format!("{parsed:?}");
    assert!(!printed.contains("deadbeefcafe0123"), "{printed}");
    assert!(
        printed.contains("AKID") && printed.contains("host;x-amz-date"),
        "{printed}"
    );
}

#[test]
fn a_logged_access_key_id_is_escaped_and_capped() {
    assert_eq!(shown_id(&"A".repeat(129)), "A".repeat(128));
    let akid = format!("AKID\t\"x\"{}", "A".repeat(300));
    let s = sign(SECRET, &akid, None, b"", None);
    let (judged, logged) = logged_judging(&s.lines, NOW);
    assert_eq!(judged, Judgement::Reject);
    assert!(logged.contains("access_key_id="), "{logged}");
    assert!(!logged.contains('\t'), "a raw tab: {logged}");
    assert!(logged.contains("AKID\\t\\\"x\\\""), "escaped: {logged}");
    // 128 characters kept before escaping: the 8-character raw prefix, then exactly 120 A's.
    assert!(
        logged.contains(&format!("AKID\\t\\\"x\\\"{}", "A".repeat(120))),
        "the head is kept: {logged}"
    );
    assert!(
        !logged.contains(&"A".repeat(121)),
        "capped at 128 characters: {logged}"
    );
}

#[test]
fn a_non_s3_request_is_judged_over_its_normalized_path() {
    let admitted = Judgement::Identity(AKID.to_string());
    for (wire, canonical) in [
        ("//example//", "/example/"),
        ("/example/..", "/"),
        ("/example1/example2/../..", "/"),
        ("/./", "/"),
        ("/./example", "/example"),
        ("/a/b/../c%3A", "/a/c%253A"),
    ] {
        assert_eq!(judge_path("svc", canonical, wire), admitted, "{wire}");
    }
    assert_eq!(
        judge_path("s3", "/example/", "//example//"),
        Judgement::Reject,
        "S3 is never normalized"
    );
}

#[test]
fn a_stored_secret_that_is_not_utf8_rejects_with_one_warn() {
    let s = sign(DUMMY_SECRET, AKID, None, b"", None);
    let mut fake = Fake {
        raw: Some(vec![0xff, 0xfe]),
        ..Fake::default()
    };
    let all = crate::diagnostics::Log::new(tracing::Level::DEBUG);
    let judged = tracing::subscriber::with_default(all.subscriber(), || {
        run(&s.lines, None, Some(b""), &mut fake)
    });
    assert_eq!(judged, Judgement::Reject);
    let logged = all.messages();
    assert_eq!(logged.len(), 1, "logged once: {logged:?}");
    assert!(
        logged[0].contains("module=\"sigv4\"") && logged[0].contains("reason=\"secret-not-utf8\""),
        "{logged:?}"
    );
    let warns = crate::diagnostics::Log::new(tracing::Level::WARN);
    tracing::subscriber::with_default(warns.subscriber(), || {
        run(&s.lines, None, Some(b""), &mut fake)
    });
    assert_eq!(warns.messages().len(), 1, "at WARN: {:?}", warns.messages());
}

/// Accepted framing must retain fields the verifier authenticated, including framing headers
/// and fields named by Connection. A post-auth response-header filter would delete signed input.
#[test]
fn test_verify_inbound_sigv4_authenticates_retained_request_framing_fields() {
    let secret = "fixture-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, mut headers, hash) =
        signed_fixture(secret, "us-east-1", "svc", amzdate, "20150830");
    headers.extend([
        ("content-length".into(), "7".into()),
        ("connection".into(), "close, x-proof".into()),
        ("x-proof".into(), "first".into()),
        ("x-proof".into(), "second".into()),
    ]);
    (parsed.signature, parsed.signed_headers) = sign_v4(
        secret,
        "us-east-1",
        "svc",
        "POST",
        "/model/acme.model-1/converse",
        "",
        &headers,
        &hash,
        amzdate,
        "20150830",
    );
    for name in ["content-length", "connection", "x-proof"] {
        assert!(parsed
            .signed_headers
            .split(';')
            .any(|signed| signed == name));
    }
    assert_eq!(
        verify_inbound_sigv4(&parsed, &inbound(&headers, &hash, amzdate), secret, now),
        Ok(())
    );
    for name in ["content-length", "connection", "x-proof"] {
        let mut removed = headers.clone();
        removed.retain(|(field, _)| field != name);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &inbound(&removed, &hash, amzdate), secret, now),
            Err(VerifyError::SignedHeadersMismatch),
            "missing {name}"
        );
        let mut changed = headers.clone();
        changed
            .iter_mut()
            .find(|(field, _)| field == name)
            .unwrap()
            .1
            .push_str("-changed");
        assert_eq!(
            verify_inbound_sigv4(&parsed, &inbound(&changed, &hash, amzdate), secret, now),
            Err(VerifyError::SignatureMismatch),
            "changed {name}"
        );
    }
    assert_eq!(
        verify_inbound_sigv4(
            &parsed,
            &inbound(&headers, &hash, amzdate),
            "wrong-secret",
            now
        ),
        Err(VerifyError::SignatureMismatch)
    );
}

/// r1-prod0-1: the pre-auth prefilter must not rescan the whole client-supplied `SignedHeaders`
/// once per request line. A huge list with many lines still judges as before (here: a REJECT, the
/// signature cannot match) and in time proportional to lines + names, not their product. The
/// sizes put the two orders far apart so the bound holds on a loaded debug runner: 10^5 lines x
/// 10^5 names is 10^10 compares if scanned per line (minutes), about 2 x 10^6 if not (well under
/// a second); the 10 s bound sits more than 10x away from both.
#[test]
fn a_huge_signed_headers_list_with_many_lines_is_judged_without_a_quadratic_scan() {
    let (amzdate, datestamp) = format_amz_time(NOW);
    let ph = sha256_hex(b"");
    let names: Vec<String> = (0..100_000).map(|i| format!("x-pad-{i:06}")).collect();
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={AKID}/{datestamp}/us-east-1/svc/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date;{}, Signature=00",
        names.join(";")
    );
    let mut lines = vec![
        ("authorization".to_string(), auth),
        ("host".to_string(), "svc.example".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), ph),
        (X_AMZ_DATE.to_string(), amzdate),
    ];
    // Lines the list does not name: each is a miss, the worst case for a linear scan.
    lines.extend((0..100_000).map(|i| (format!("x-other-{i}"), "v".to_string())));
    let started = std::time::Instant::now();
    assert_eq!(
        run(&lines, None, Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_secs(10),
        "the prefilter took {took:?}"
    );
}

/// The inbound check reaches the same S3 rule as the signer ([`canonical_uri`], over the
/// credential scope's service): every S3 signing name is judged over its path encoded once, and a
/// name merely opening with `s3` over its path encoded twice.
#[test]
fn every_s3_signing_name_is_judged_over_its_path_encoded_once() {
    let admitted = Judgement::Identity(AKID.to_string());
    for service in ["s3", "s3-outposts", "s3-object-lambda", "s3express"] {
        assert_eq!(
            judge_path(service, "/bucket//./key%3A1", "/bucket//./key%3A1"),
            admitted,
            "{service}"
        );
        assert_eq!(
            judge_path(service, "/bucket/key%253A1", "/bucket/key%3A1"),
            Judgement::Reject,
            "{service} is never double-encoded"
        );
    }
    assert_eq!(
        judge_path("s3control", "/bucket/key%253A1", "/bucket//./key%3A1"),
        admitted,
        "a name that only opens with `s3` is normalized and double-encoded"
    );
}

/// The signed headers are selected from the request in time that grows with the request, not with
/// the product of the signed names and the header lines: an unauthenticated request naming tens of
/// thousands of signed headers is selected (and here, being correctly signed, verified) quickly.
/// The wire carries the lines in reverse order and in upper case; each signed value is still found.
#[test]
fn many_signed_headers_are_selected_in_near_linear_time() {
    const N: usize = 20_000;
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let payload_hash = sha256_hex(b"{\"x\":1}");
    let mut headers: Vec<(String, String)> = (0..N)
        .map(|i| (format!("X-H{i:05}"), format!("v{i}")))
        .collect();
    headers.push(("host".to_string(), "svc.example".to_string()));
    headers.push((X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()));
    headers.push((X_AMZ_DATE.to_string(), amzdate.to_string()));
    headers.reverse();
    let (sig, signed_headers) = sign_v4(
        secret,
        "us-east-1",
        "svc",
        "POST",
        "/v1/x",
        "",
        &headers,
        &payload_hash,
        amzdate,
        "20150830",
    );
    let parsed = ParsedAuthHeader {
        access_key_id: "AKIAEXAMPLE1234567890".to_string(),
        datestamp: "20150830".to_string(),
        region: "us-east-1".to_string(),
        service: "svc".to_string(),
        signed_headers,
        signature: sig,
    };
    let req = InboundRequest {
        method: "POST",
        canonical_uri: "/v1/x",
        canonical_querystring: "",
        headers: &headers,
        payload_hash: &payload_hash,
        amzdate,
    };
    let started = std::time::Instant::now();
    assert_eq!(verify_inbound_sigv4(&parsed, &req, secret, now), Ok(()));
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "selecting {N} signed headers took {elapsed:?}"
    );
}

/// A `SignedHeaders` name that is not ASCII is refused, even when the signature is real: the
/// signer lowercases it (Unicode), so the list the client states is not the list it signed.
#[test]
fn a_non_ascii_signed_header_name_is_refused() {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let payload_hash = sha256_hex(b"{\"x\":1}");
    let headers = vec![
        ("host".to_string(), "svc.example".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
        ("x\u{c4}".to_string(), "v".to_string()),
    ];
    let (sig, signed_by_signer) = sign_v4(
        secret,
        "us-east-1",
        "svc",
        "POST",
        "/v1/x",
        "",
        &headers,
        &payload_hash,
        amzdate,
        "20150830",
    );
    assert_eq!(
        signed_by_signer,
        "host;x-amz-content-sha256;x-amz-date;x\u{e4}"
    );
    let parsed = ParsedAuthHeader {
        access_key_id: "AKIAEXAMPLE1234567890".to_string(),
        datestamp: "20150830".to_string(),
        region: "us-east-1".to_string(),
        service: "svc".to_string(),
        signed_headers: "host;x-amz-content-sha256;x-amz-date;x\u{c4}".to_string(),
        signature: sig,
    };
    let req = InboundRequest {
        method: "POST",
        canonical_uri: "/v1/x",
        canonical_querystring: "",
        headers: &headers,
        payload_hash: &payload_hash,
        amzdate,
    };
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignedHeadersMismatch)
    );
}
