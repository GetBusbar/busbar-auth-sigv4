// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-only fixture helpers shared by the side-file test modules: the SDK's HMAC and day key,
//! a fixture signer over the shared SDK recipe, and a reader of the fields a binding signs. They
//! live here, not in the production modules, so production source carries no test code.

use busbar_contract::abi::sdk::chip::aws4::Aws4Request;
use busbar_contract::abi::sdk::cred::{Cred, Parts, SealedWrite};
use zeroize::Zeroizing;

use crate::signing::{Field, FieldValue};

/// HMAC-SHA256 of `data` under `key`: the contract SDK's ONE wiped HMAC.
pub(crate) fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    busbar_contract::abi::sdk::hmac::hmac_sha256(key, data)
}

/// The test fixture's day key, derived by the shared SDK recipe.
pub(crate) fn signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> Cred {
    Cred::captured(Zeroizing::new(secret.as_bytes().to_vec()))
        .aws4_day_key(datestamp, region, service)
}

/// Every byte a sealed SDK value writes, read through the dev-only wire sink.
fn unseal(parts: Parts) -> Vec<u8> {
    let mut wire = SealedWrite::new(parts);
    let mut bytes = Vec::new();
    let answer =
        busbar_contract::abi::sdk::test_support::chip::drive_sealed::<()>(&mut wire, |part| {
            bytes.extend_from_slice(part);
            std::task::Poll::Ready(Ok(part.len()))
        });
    assert!(answer.is_ready());
    bytes
}

/// Compute the SigV4 signature hex + the `SignedHeaders` string for a request through the shared
/// SDK recipe (`headers` as (name, value) pairs; the SDK canonicalizes them).
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_v4<H: AsRef<str>>(
    secret: &str,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_querystring: &str,
    headers: &[(H, H)],
    payload_hash: &str,
    amzdate: &str,
    datestamp: &str,
) -> (String, String) {
    let headers = headers
        .iter()
        .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned()))
        .collect::<Vec<_>>();
    let key = signing_key(secret, datestamp, region, service);
    sign_v4_with_key(
        &key,
        region,
        service,
        method,
        canonical_uri,
        canonical_querystring,
        &headers,
        payload_hash,
        amzdate,
        datestamp,
    )
}

/// Read a shared SDK signature under a pre-derived day `key` for fixture comparisons.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_v4_with_key(
    key: &Cred,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_querystring: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    amzdate: &str,
    datestamp: &str,
) -> (String, String) {
    let signed = key
        .aws4_sign(
            &Aws4Request {
                region,
                service,
                method,
                canonical_uri,
                canonical_query: canonical_querystring,
                headers,
                payload_hash,
                amzdate,
                datestamp,
            },
            None,
        )
        .expect("the fixture signs");
    let bytes = unseal(Parts::new().sealed(signed.signature));
    (
        String::from_utf8(bytes).expect("hex signature"),
        signed.signed_headers,
    )
}

/// The fields a binding signed, each value as the text the host would write.
pub(crate) fn plain(fields: Vec<Field>) -> Vec<(String, String)> {
    fields
        .into_iter()
        .map(|(name, value)| {
            let text = match value {
                FieldValue::Public(value) => value,
                FieldValue::Sealed(parts) => {
                    String::from_utf8(unseal(parts)).expect("a signed field is text")
                }
            };
            (name, text)
        })
        .collect()
}
