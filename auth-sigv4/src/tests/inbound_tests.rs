// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `inbound.rs`: busbar-kernel-identity's `ingress_sigv4_tests.rs` ported verbatim (the
//! parse, the date window, the recomputed signature), the kernel's own SigV4 wiring tests
//! (`busbar-kernel/src/auth/tests/tests.rs`: the entry gate, the canonical query, the body binding,
//! `UNSIGNED-PAYLOAD`, an unknown or disabled key), now over [`judge`] with a fake secret source in
//! place of the governance store, and the host-read rules (the dummy secret never admits, not-live
//! never admits, a pending or unavailable read).

use super::*;
use crate::sigv4::format_amz_time;

// ====================== ingress_sigv4_tests.rs, ported ======================

#[test]
fn test_uri_encode_path_dotted_colon_model_id() {
    // Vendor-style model IDs contain ':' and '.' — must encode ':' as %3A, keep '.' and '/'.
    assert_eq!(
        uri_encode_path("/model/acme.model-1:0/converse"),
        "/model/acme.model-1%3A0/converse"
    );
}

#[test]
fn test_uri_encode_path_assorted_bytes() {
    // Uppercase two-digit hex for every reserved byte.
    assert_eq!(uri_encode_path(" "), "%20"); // 0x20
    assert_eq!(uri_encode_path("?a=b&c"), "%3Fa%3Db%26c");
    assert_eq!(uri_encode_path("/"), "/"); // slash preserved
    assert_eq!(uri_encode_path("aZ0-_.~"), "aZ0-_.~"); // unreserved set untouched
                                                       // A high byte (0xC3 from the UTF-8 of 'Ã') still encodes uppercase, padded.
    assert_eq!(uri_encode_path("\u{00c3}"), "%C3%83");
}

#[test]
fn test_canonicalize_header_value_ascii_space_only() {
    // Runs of ASCII space (0x20) collapse to one; leading/trailing ASCII space is trimmed.
    assert_eq!(canonicalize_header_value("a   b    c"), "a b c");
    assert_eq!(canonicalize_header_value("  a b c  "), "a b c");
    assert_eq!(canonicalize_header_value(""), "");
    assert_eq!(canonicalize_header_value("   "), "");
    assert_eq!(canonicalize_header_value("single"), "single");
    // ASCII space ONLY. Tab, NBSP and newline pass through verbatim.
    assert_eq!(canonicalize_header_value("a\tb"), "a\tb");
    assert_eq!(canonicalize_header_value("a\u{00a0}b"), "a\u{00a0}b");
    assert_eq!(canonicalize_header_value("a\nb"), "a\nb");
    assert_eq!(canonicalize_header_value("a  \t  b"), "a \t b");
    assert_eq!(canonicalize_header_value("\u{00a0}a"), "\u{00a0}a");
}

#[test]
fn test_sign_v4_collapses_ascii_space_in_header_value() {
    let payload_hash = sha256_hex(b"");
    let mk = |v: &str| {
        sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
            "GET",
            "/",
            "",
            &[
                ("host".to_string(), "iam.amazonaws.com".to_string()),
                (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
                ("x-custom".to_string(), v.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };
    let (sig_single, _) = mk("a b c");
    let (sig_double, _) = mk("a   b  c");
    assert_eq!(sig_single, sig_double);
    let (sig_padded, _) = mk("  a b c  ");
    assert_eq!(sig_single, sig_padded);
}

#[test]
fn test_sign_v4_does_not_fold_nbsp_or_tab_in_header_value() {
    let payload_hash = sha256_hex(b"");
    let mk = |v: &str| {
        sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
            "GET",
            "/",
            "",
            &[
                ("host".to_string(), "iam.amazonaws.com".to_string()),
                (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
                ("x-custom".to_string(), v.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };
    let (sig_space, _) = mk("a b");
    assert_ne!(sig_space, mk("a\u{00a0}b").0, "NBSP is kept verbatim");
    assert_ne!(sig_space, mk("a\tb").0, "tab is kept verbatim");
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
    // A non-AWS4 scheme is "missing" (so a Bearer falls through cleanly), not malformed.
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
fn test_parse_amz_date_roundtrips_with_format_amz_time() {
    let epoch = 1_440_938_160u64; // 2015-08-30T12:36:00Z
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

#[test]
fn test_parse_amz_date_componentwise_boundaries() {
    for ok in [
        "20150830T235960Z",
        "20150830T005960Z",
        "20150830T000060Z",
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
fn test_verify_inbound_sigv4_duplicate_signed_header_values_are_combined() {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let payload_hash = sha256_hex(b"{\"x\":1}");
    let signing_view = vec![
        (
            "host".to_string(),
            "example-service.amazonaws.com".to_string(),
        ),
        ("x-amz-meta-tag".to_string(), "a,b".to_string()),
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
        ("x-amz-meta-tag".to_string(), "a".to_string()),
        ("x-amz-meta-tag".to_string(), "b".to_string()),
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
    assert_eq!(verify_inbound_sigv4(&parsed, &req, secret, now), Ok(()));
}

#[test]
fn test_canonicalize_header_value_preserves_spaces_inside_quotes() {
    assert_eq!(
        canonicalize_header_value("attachment; filename=\"my  file.txt\""),
        "attachment; filename=\"my  file.txt\""
    );
    assert_eq!(
        canonicalize_header_value("  a   b  \"c   d\"   e  "),
        "a b \"c   d\" e"
    );
    let once = canonicalize_header_value("x  \"y  z\"  w");
    assert_eq!(canonicalize_header_value(&once), once);
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

/// AWS published worked example — GET iam ListUsers, 2015-08-30: the inbound recomputation
/// reproduces AWS's documented signature.
#[test]
fn test_sign_v4_matches_aws_published_example() {
    let headers = vec![
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        ),
        ("host".to_string(), "iam.amazonaws.com".to_string()),
        (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
    ];
    let payload_hash = sha256_hex(b"");
    let (sig, signed) = sign_v4(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "iam",
        "GET",
        "/",
        "Action=ListUsers&Version=2010-05-08",
        &headers,
        &payload_hash,
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(signed, "content-type;host;x-amz-date");
    assert_eq!(
        sig,
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
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
        Err(VerifyError::SignatureMismatch)
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

// ====================== the kernel's wiring tests, over `judge` ======================

#[test]
fn test_canonical_query_string_sorts_but_does_not_reencode() {
    assert_eq!(canonical_query_string(None), "");
    assert_eq!(canonical_query_string(Some("")), "");
    assert_eq!(canonical_query_string(Some("b=2&a=1")), "a=1&b=2");
    assert_eq!(canonical_query_string(Some("flag")), "flag=");
    assert_eq!(canonical_query_string(Some("p=a%2Fb")), "p=a%2Fb");
    assert_eq!(canonical_query_string(Some("p=a/b")), "p=a/b");
    // Empty pairs drop; equal keys sort by value.
    assert_eq!(
        canonical_query_string(Some("&b=2&&a=2&a=1&")),
        "a=1&a=2&b=2"
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

/// The host's `records.secret`, faked: the live and dead credentials by id, the fixed dummy (not
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
            _ => (DUMMY_SECRET.as_bytes().to_vec(), false),
        };
        Read::Secret {
            secret: Zeroizing::new(secret),
            live,
        }
    }
}

/// A client's signed POST: the `Authorization` value and the header lines it sends, signed with
/// the OUTBOUND signer a client uses (`sigv4::sign_v4`), over `query` (the wire query, signed
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
    let (amzdate, datestamp) = format_amz_time(NOW);
    let payload_hash = declared.map_or_else(|| sha256_hex(body), str::to_string);
    let headers = vec![
        (
            "host".to_string(),
            "svc.us-east-1.amazonaws.com".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.clone()),
    ];
    let (sig, signed_headers) = crate::sigv4::sign_v4(
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
fn an_escaped_query_param_is_signed_as_sent_never_reencoded() {
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
    // The kernel compared the body's hash to the declared value LOWERCASED, and verified the
    // signature over the declared value as sent.
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

#[test]
fn an_unknown_access_key_id_runs_the_full_check_and_rejects() {
    // The host answers its dummy secret for an id it does not hold; the read is made and the
    // verification runs over it (no short-circuit), and it rejects like a bad signature.
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
    // A request signed WITH the dummy secret verifies against it, cryptographically; the host
    // called it not live, so it never admits.
    let s = sign(DUMMY_SECRET, "BBAKUNKNOWN000000000", None, b"", None);
    assert_eq!(
        run(&s.lines, None, Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
}

#[test]
fn a_credential_that_is_not_live_never_admits() {
    // Signed with the credential's REAL secret: the signature verifies, the credential is not live.
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
    let s = sign(SECRET, AKID, None, body, Some("UNSIGNED-PAYLOAD"));
    let mut fake = Fake::default();
    assert_eq!(
        run(&s.lines, None, Some(body), &mut fake),
        Judgement::Reject
    );
    // Any case of the sentinel.
    let s = sign(SECRET, AKID, None, body, Some("unsigned-payload"));
    assert_eq!(
        run(&s.lines, None, Some(body), &mut fake),
        Judgement::Reject
    );
    assert!(fake.reads.is_empty());
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
    // Only the FIRST authorization line is read (the kernel's `HeaderMap::get`).
    let s = sign(SECRET, AKID, None, b"", None);
    let mut two = vec![("authorization".to_string(), "Bearer tok".to_string())];
    two.extend(s.lines.iter().cloned());
    assert_eq!(run(&two, None, Some(b""), &mut fake), Judgement::Pass);
    // A value that is not visible ASCII reads as absent.
    let odd = [("authorization".to_string(), format!("{}\u{00e9}", s.auth))];
    assert_eq!(run(&odd, None, Some(b""), &mut fake), Judgement::Pass);
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
    // An algorithm token and nothing a SigV4 credential needs.
    let trivial = [
        (
            "authorization".to_string(),
            "AWS4-HMAC-SHA256 x".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), sha256_hex(b"")),
        (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
    ];
    assert_eq!(run(&trivial, None, Some(b""), &mut fake), Judgement::Reject);
    // A well-formed Authorization without x-amz-date, or without x-amz-content-sha256.
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
    fake.answer = Some(|| Read::NotNow);
    assert_eq!(run(&s.lines, None, Some(b""), &mut fake), Judgement::NotNow);
    fake.answer = Some(|| Read::Unavailable);
    assert_eq!(run(&s.lines, None, Some(b""), &mut fake), Judgement::Reject);
}

#[test]
fn a_secret_that_is_not_utf8_never_admits() {
    let s = sign(SECRET, AKID, None, b"", None);
    let mut fake = Fake {
        raw: Some(vec![0xff, 0xfe]),
        ..Fake::default()
    };
    assert_eq!(run(&s.lines, None, Some(b""), &mut fake), Judgement::Reject);
}

#[test]
fn a_duplicate_signed_header_is_comma_joined_in_request_order() {
    let (amzdate, datestamp) = format_amz_time(NOW);
    let payload_hash = sha256_hex(b"");
    let signing_view = vec![
        ("host".to_string(), "svc.example".to_string()),
        ("x-amz-meta-tag".to_string(), "a,b".to_string()),
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
    let lines = vec![
        ("authorization".to_string(), auth),
        ("host".to_string(), "svc.example".to_string()),
        ("x-amz-meta-tag".to_string(), "a".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash),
        ("x-amz-meta-tag".to_string(), "b".to_string()),
        (X_AMZ_DATE.to_string(), amzdate),
    ];
    assert_eq!(
        run(&lines, None, Some(b""), &mut Fake::default()),
        Judgement::Identity(AKID.to_string())
    );
    // Reordered values sign differently.
    let mut swapped = lines.clone();
    swapped[2].1 = "b".to_string();
    swapped[4].1 = "a".to_string();
    assert_eq!(
        run(&swapped, None, Some(b""), &mut Fake::default()),
        Judgement::Reject
    );
}

/// The fake's bookkeeping is itself what the other tests lean on: any id it does not hold answers
/// the dummy secret, not live.
#[test]
fn the_fake_source_answers_the_dummy_for_any_other_id() {
    let mut fake = Fake::default();
    let Read::Secret { secret, live } = fake.read("sigv4", "nobody") else {
        panic!("a secret");
    };
    assert_eq!(&secret[..], DUMMY_SECRET.as_bytes());
    assert!(!live);
}
