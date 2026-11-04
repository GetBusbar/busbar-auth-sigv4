// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use sha2::{Digest, Sha256};

/// Independent fixture signer. Callers provide fixed, already canonical, unique header names
/// and values: this deliberately does not use the production SDK's canonicalizer or signer.
#[allow(clippy::too_many_arguments)]
pub fn sign_v4<H: AsRef<str>>(
    secret: &str,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(H, H)],
    payload_hash: &str,
    amzdate: &str,
    datestamp: &str,
) -> (String, String) {
    let mut headers = headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_ref()))
        .collect::<Vec<_>>();
    headers.sort_by_key(|(name, _)| *name);
    let names = headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();
    let request = format!("{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{names}\n{payload_hash}");
    let request_hash = hex::encode(Sha256::digest(request.as_bytes()));
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{datestamp}/{region}/{service}/aws4_request\n{request_hash}"
    );
    let date = hmac(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let region_key = hmac(&date, region.as_bytes());
    let service_key = hmac(&region_key, service.as_bytes());
    let key = hmac(&service_key, b"aws4_request");
    (hex::encode(hmac(&key, to_sign.as_bytes())), names)
}

/// RFC 2104, the same independent SHA-256 construction as the binary both-ways fixture.
fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut key = if key.len() > 64 {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    key.resize(64, 0);
    let inner_pad = key.iter().map(|byte| byte ^ 0x36).collect::<Vec<_>>();
    let outer_pad = key.iter().map(|byte| byte ^ 0x5c).collect::<Vec<_>>();
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner)
        .finalize()
        .to_vec()
}

#[test]
fn fixture_signer_matches_the_existing_aws_iam_vector() {
    let hash = hex::encode(Sha256::digest(b""));
    let (signature, names) = sign_v4(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "iam",
        "GET",
        "/",
        "Action=ListUsers&Version=2010-05-08",
        &[
            (
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
            ("host", "iam.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ],
        &hash,
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(names, "content-type;host;x-amz-date");
    assert_eq!(
        signature,
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    );
}
