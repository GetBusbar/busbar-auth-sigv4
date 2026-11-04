// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::fixtures::{hmac, sign_v4, sign_v4_with_key, signing_key};

#[test]
fn format_amz_time_known_epoch() {
    let (amz, date) = format_amz_time(1_440_938_160);
    assert_eq!(amz, "20150830T123600Z");
    assert_eq!(date, "20150830");
}

#[test]
fn format_amz_time_leap_days_and_century_boundary() {
    for (epoch, amz, date) in [
        (951_782_400, "20000229T000000Z", "20000229"),
        (1_078_012_800, "20040229T000000Z", "20040229"),
        (1_609_459_199, "20201231T235959Z", "20201231"),
        (4_102_444_800, "21000101T000000Z", "21000101"),
    ] {
        assert_eq!(format_amz_time(epoch), (amz.to_string(), date.to_string()));
    }
}

#[test]
fn format_amz_time_known_epochs_table() {
    let cases: &[(u64, &str)] = &[
        (0, "19700101T000000Z"),
        (86_399, "19700101T235959Z"),
        (5_097_600, "19700301T000000Z"),
        (951_782_400, "20000229T000000Z"),
        (1_078_012_800, "20040229T000000Z"),
        (1_609_459_199, "20201231T235959Z"),
        (1_609_459_200, "20210101T000000Z"),
        (1_717_200_000, "20240601T000000Z"),
        (4_102_444_800, "21000101T000000Z"),
        (4_107_542_400, "21000301T000000Z"),
    ];
    for (epoch, amzdate) in cases {
        let (amz, date) = format_amz_time(*epoch);
        assert_eq!(&amz, amzdate, "epoch {epoch}");
        assert_eq!(date, amzdate[..8], "datestamp of epoch {epoch}");
    }
}

#[test]
fn canonicalize_header_value_ascii_space_only() {
    use ring::{digest, hmac};
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let payload_hash = sha256_hex(b"");

    let mac = |key: &[u8], bytes: &[u8]| hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), bytes);
    let date = mac(format!("AWS4{secret}").as_bytes(), b"20150830");
    let region = mac(date.as_ref(), b"us-east-1");
    let service = mac(region.as_ref(), b"iam");
    let key = mac(service.as_ref(), b"aws4_request");
    for (raw, canonical) in [
        ("a   b    c", "a b c"),
        ("  a b c  ", "a b c"),
        ("", ""),
        ("   ", ""),
        ("single", "single"),
        ("a\tb", "a\tb"),
        ("a\u{00a0}b", "a\u{00a0}b"),
        ("a\nb", "a\nb"),
        ("a  \t  b", "a \t b"),
        ("\u{00a0}a", "\u{00a0}a"),
    ] {
        let request = format!(
            "GET\n/\n\nhost:iam.amazonaws.com\nx-custom:{canonical}\n\nhost;x-custom\n{payload_hash}"
        );
        let hash = hex::encode(digest::digest(&digest::SHA256, request.as_bytes()));
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\n{hash}"
        );
        let expected = hex::encode(mac(key.as_ref(), to_sign.as_bytes()).as_ref());
        let (actual, names) = sign_v4(
            secret,
            "us-east-1",
            "iam",
            "GET",
            "/",
            "",
            &[
                ("host".to_string(), "iam.amazonaws.com".to_string()),
                ("x-custom".to_string(), raw.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        );
        assert_eq!(actual, expected, "header value {raw:?}");
        assert_eq!(names, "host;x-custom");
    }
}

#[test]
fn sign_v4_collapses_ascii_space_in_header_value() {
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
                ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
                ("x-custom".to_string(), v.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };
    let (sig_single, _) = mk("a b");
    let (sig_padded, _) = mk("a    b");
    assert_eq!(sig_single, sig_padded);
}

#[test]
fn sign_v4_does_not_fold_nbsp_or_tab_in_header_value() {
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
                ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
                ("x-custom".to_string(), v.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };
    let (sig_tab, _) = mk("a\tb");
    let (sig_nbsp, _) = mk("a\u{00a0}b");
    let (sig_space, _) = mk("a b");
    assert_ne!(
        sig_tab, sig_space,
        "a tab must not be folded into a space by the signer"
    );
    assert_ne!(
        sig_nbsp, sig_space,
        "an NBSP must not be folded into a space by the signer"
    );
}

/// Per the SigV4 canonicalisation rule, a header name that appears twice is not two lines in the
/// canonical headers block and not two entries in `SignedHeaders` — it is ONE entry whose value is
/// the comma-joined, individually-trimmed values, in their original order. Proven by comparing
/// against the header handed over pre-merged: if the signer folds them the same way itself, the two
/// signatures and `SignedHeaders` strings must match exactly.
#[test]
fn sign_v4_merges_a_duplicate_header_name_by_comma_joining_its_values() {
    let payload_hash = sha256_hex(b"");
    let common = [
        ("host".to_string(), "iam.amazonaws.com".to_string()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
    ];
    let sign = |headers: &[(String, String)]| {
        sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
            "GET",
            "/",
            "",
            headers,
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };

    let mut duplicated = common.to_vec();
    duplicated.push(("x-custom".to_string(), "  foo  ".to_string()));
    duplicated.push(("x-custom".to_string(), "bar".to_string()));
    let (sig_duplicated, signed_duplicated) = sign(&duplicated);

    let mut premerged = common.to_vec();
    premerged.push(("x-custom".to_string(), "foo,bar".to_string()));
    let (sig_premerged, signed_premerged) = sign(&premerged);

    assert_eq!(
        signed_duplicated, "host;x-amz-date;x-custom",
        "the duplicate name appears once in SignedHeaders, not twice"
    );
    assert_eq!(signed_duplicated, signed_premerged);
    assert_eq!(
        sig_duplicated, sig_premerged,
        "a duplicated header must sign identically to its comma-joined, pre-trimmed equivalent"
    );
}

/// AWS published worked example — GET iam ListUsers, 2015-08-30. If our canonical-request ->
/// string-to-sign -> signature chain reproduces AWS's documented signature, the algorithm is
/// correct.
/// (the AWS General Reference, "Examples of signed Signature Version 4 requests")
#[test]
fn sign_v4_matches_aws_published_example() {
    let headers = vec![
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        ),
        ("host".to_string(), "iam.amazonaws.com".to_string()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
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

/// THE AWS PUBLISHED VECTOR WITH A SESSION TOKEN (BUSBAR-1.6.0.md THE DESIGN, §6's proof: "the AWS SigV4 published
/// vector with a session token"): `post-sts-header-before` from the AWS signing test suite
/// (awslabs/aws-c-auth, tests/aws-signing-test-suite/v4/post-sts-header-before), where the token is
/// sent AND signed. Driven through the request path's own split — the day key from
/// [`signing_key`], then [`sign_v4_with_key`] — so the pre-derived key is what the vector pins.
#[test]
fn the_day_key_path_matches_the_aws_published_session_token_vector() {
    const TOKEN: &str = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";
    let key = signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20150830",
        "us-east-1",
        "service",
    );
    let headers = vec![
        ("host".to_string(), "example.amazonaws.com".to_string()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ("x-amz-security-token".to_string(), TOKEN.to_string()),
    ];
    let (sig, signed) = sign_v4_with_key(
        &key,
        "us-east-1",
        "service",
        "POST",
        "/",
        "",
        &headers,
        &sha256_hex(b""),
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(signed, "host;x-amz-date;x-amz-security-token");
    assert_eq!(
        sig,
        "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead"
    );
}

/// The outbound canonical query: names and values decoded once and re-encoded over the unreserved
/// set (uppercase hex), sorted by name then value; a `+` is a literal byte (RFC 3986), a `%` that
/// opens no two hex digits is a literal `%`, and a decoded multi-byte character is re-escaped.
#[test]
fn canonical_query_encodes_each_name_and_value() {
    assert_eq!(canonical_query(None), "");
    assert_eq!(canonical_query(Some("")), "");
    assert_eq!(canonical_query(Some("b=2&a=1&&a=0")), "a=0&a=1&b=2");
    assert_eq!(canonical_query(Some("q=1+2")), "q=1%2B2");
    assert_eq!(canonical_query(Some("t=abc==")), "t=abc%3D%3D");
    assert_eq!(canonical_query(Some("p=%zz&r=%4")), "p=%25zz&r=%254");
    assert_eq!(canonical_query(Some("u=%e1%88%b4")), "u=%E1%88%B4");
    assert_eq!(canonical_query(Some("s=a b,c")), "s=a%20b%2Cc");
    assert_eq!(
        canonical_query(Some("x%2Fy=1&x/z=2")),
        "x%2Fy=1&x%2Fz=2",
        "a name is encoded too"
    );
}

/// RFC 4231's HMAC-SHA-256 vectors: a short key (case 1) and a key past the block size, hashed
/// first (case 6).
#[test]
fn the_hmac_answers_rfc_4231() {
    assert_eq!(
        hex::encode(&hmac(&[0x0b; 20], b"Hi There")[..]),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex::encode(
            &hmac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )[..]
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

/// THE AWS SIGV4 TEST SUITE (aws-sig-v4-test-suite: credential AKIDEXAMPLE /
/// wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, us-east-1, service `service`, 20150830T123600Z, the
/// signed set `host;x-amz-date`, an empty body): each request, path and query exactly as the suite
/// sends them, canonicalized by [`canonical_uri`] and [`canonical_query`] and signed, answers AWS's
/// published signature.
#[test]
fn the_aws_suite_requests_sign_to_the_published_signatures() {
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let headers = [
        ("host".to_string(), "example.amazonaws.com".to_string()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
    ];
    let empty = sha256_hex(b"");
    const VANILLA: &str = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
    for (name, path, query, signature) in [
        ("get-vanilla", "/", None, VANILLA),
        ("get-slash", "//", None, VANILLA),
        ("get-relative", "/example/..", None, VANILLA),
        (
            "get-relative-relative",
            "/example1/example2/../..",
            None,
            VANILLA,
        ),
        ("get-slash-dot-slash", "/./", None, VANILLA),
        (
            "get-slashes",
            "//example//",
            None,
            "9a624bd73a37c9a373b5312afbebe7a714a789de108f0bdfe846570885f57e84",
        ),
        (
            "get-space",
            "/example space/",
            None,
            "652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741",
        ),
        (
            "get-utf8",
            "/\u{1234}",
            None,
            "8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85",
        ),
        (
            "get-unreserved",
            "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            None,
            "07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f",
        ),
        (
            "get-vanilla-query-order-key-case",
            "/",
            Some("Param2=value2&Param1=value1"),
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
        ),
        (
            "get-vanilla-query-order-key",
            "/",
            Some("Param1=value2&Param1=Value1"),
            "eedbc4e291e521cf13422ffca22be7d2eb8146eecf653089df300a15b2382bd1",
        ),
        (
            "get-vanilla-utf8-query",
            "/",
            Some("\u{1234}=bar"),
            "2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04",
        ),
    ] {
        let (got, signed) = sign_v4(
            SECRET,
            "us-east-1",
            "service",
            "GET",
            &canonical_uri(path, "service"),
            &canonical_query(query),
            &headers,
            &empty,
            "20150830T123600Z",
            "20150830",
        );
        assert_eq!(signed, "host;x-amz-date", "{name}");
        assert_eq!(got, signature, "{name}");
    }
}

/// The S3 signing names the AWS SDKs sign with `disableDoubleEncoding` (the S3 endpoint
/// ruleset's `s3`, `s3-outposts`, `s3-object-lambda` and `s3express`) each sign the path encoded
/// ONCE and never normalized; a name merely opening with `s3`, or any other service, signs it
/// normalized and encoded twice. The list is exact: no prefix, no case folding.
#[test]
fn the_s3_signing_names_encode_the_path_once_and_no_other_name_does() {
    let wire = "/bucket//./key%3Aa b";
    for service in ["s3", "s3-outposts", "s3-object-lambda", "s3express"] {
        assert_eq!(
            canonical_uri(wire, service),
            "/bucket//./key%3Aa%20b",
            "{service} encodes once, never normalized"
        );
        assert_eq!(
            canonical_uri("/bucket/a%2fb", service),
            "/bucket/a%2Fb",
            "{service} keeps an escaped `/` escaped"
        );
    }
    for service in [
        "s3control",
        "s3-control",
        "s3x",
        "s3express-control",
        "S3",
        "bedrock",
    ] {
        assert_eq!(
            canonical_uri(wire, service),
            "/bucket/key%253Aa%20b",
            "{service} is normalized and encoded twice"
        );
    }
}
