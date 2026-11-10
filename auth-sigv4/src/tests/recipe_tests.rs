// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn credential(bytes: &[u8]) -> Cred {
    Cred::captured(Zeroizing::new(bytes.to_vec()))
}

fn request(headers: &[(String, String)]) -> Aws4Request<'_> {
    Aws4Request {
        region: "us-east-1",
        service: "service",
        method: "GET",
        canonical_uri: "/",
        canonical_query: "",
        headers,
        payload_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        amzdate: "20150830T123600Z",
        datestamp: "20150830",
    }
}

#[test]
fn published_get_vanilla_vector_and_verification_preserve_key_custody() {
    let secret = credential(b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").require_secure();
    let headers = vec![
        ("Host".into(), "example.amazonaws.com".into()),
        ("X-Amz-Date".into(), "20150830T123600Z".into()),
    ];
    let request = request(&headers);
    let key = day_key(&secret, request.datestamp, request.region, request.service);
    assert!(key.secure_required());
    let signed = sign(&key, &request, None).expect("signs");
    let expected = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
    assert!(signed.signature.verify_eq(expected.as_bytes()));
    assert!(signed.signature.secure_required());
    assert_eq!(signed.signed_headers, "host;x-amz-date");
    assert!(verify(&secret, &request, expected));
    assert!(!verify(&secret, &request, "00"));
}

#[test]
fn opaque_session_token_replaces_headers_and_propagates_secure_requirement() {
    let key = day_key(&credential(b"secret"), "20150830", "us-east-1", "service");
    let token = credential(b"  token  with   spaces  ").require_secure();
    let supplied = vec![
        ("HOST".into(), "example.amazonaws.com".into()),
        ("X-Amz-Security-Token".into(), "stale".into()),
        ("x-amz-security-token".into(), "another stale token".into()),
    ];
    let expected = vec![
        ("host".into(), "example.amazonaws.com".into()),
        ("x-amz-security-token".into(), "token with spaces".into()),
    ];
    let actual = sign(&key, &request(&supplied), Some(&token)).expect("signs");
    let (expected, _) = crate::fixtures::sign_v4_with_key(
        &key,
        "us-east-1",
        "service",
        "GET",
        "/",
        "",
        &expected,
        request(&supplied).payload_hash,
        "20150830T123600Z",
        "20150830",
    );
    assert!(actual.signature.verify_eq(expected.as_bytes()));
    assert_eq!(actual.signed_headers, "host;x-amz-security-token");
    assert!(actual.signature.secure_required());
    assert!(sign(&key, &request(&supplied), Some(&credential(&[0xff]))).is_err());
}
