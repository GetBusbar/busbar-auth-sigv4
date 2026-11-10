// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SigV4 framing and key derivation owned by this auth plugin. All computed credential
//! material stays in the SDK's guarded values, including canonicalized session tokens.

use busbar_contract::abi::sdk::chip::{CredentialPart as Part, Digest, Refused, SealedValue};
use busbar_contract::abi::sdk::cred::Cred;
use zeroize::Zeroizing;

use crate::inbound::X_AMZ_SECURITY_TOKEN;
use crate::sigv4::{SIGNATURE_TERMINATION, SIGV4_ALGORITHM};

pub(crate) struct Aws4Request<'a> {
    pub region: &'a str,
    pub service: &'a str,
    pub method: &'a str,
    pub canonical_uri: &'a str,
    pub canonical_query: &'a str,
    pub headers: &'a [(String, String)],
    pub payload_hash: &'a str,
    pub amzdate: &'a str,
    pub datestamp: &'a str,
}

pub(crate) struct Signature {
    pub signature: SealedValue,
    pub signed_headers: String,
}

fn public(bytes: &[u8]) -> SealedValue {
    SealedValue::compose(&[Part::Public(bytes)])
}

pub(crate) fn day_key(secret: &Cred, date: &str, region: &str, service: &str) -> SealedValue {
    let mut key = SealedValue::compose(&[Part::Public(b"AWS4"), Part::Credential(secret)]);
    for component in [date, region, service, SIGNATURE_TERMINATION] {
        key = key.hmac_sha256(&public(component.as_bytes()));
    }
    key
}

fn string_to_sign(
    r: &Aws4Request<'_>,
    token: Option<&Cred>,
) -> Result<(SealedValue, String), Refused> {
    let mut headers: Vec<(String, SealedValue)> = r
        .headers
        .iter()
        .filter(|(name, _)| token.is_none() || !name.eq_ignore_ascii_case(X_AMZ_SECURITY_TOKEN))
        .map(|(name, value)| {
            let value = Cred::captured(Zeroizing::new(value.as_bytes().to_vec()));
            (name.to_lowercase(), value.normalize_ascii_spaces())
        })
        .collect();
    if let Some(token) = token {
        if !token.is_text() {
            return Err(Refused("the session token is not text"));
        }
        headers.push((
            X_AMZ_SECURITY_TOKEN.to_owned(),
            token.normalize_ascii_spaces(),
        ));
    }
    // Stable order preserves duplicate header values in their wire order.
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let mut canonical = Vec::with_capacity(headers.len() * 4 + 1);
    let mut signed_headers = String::new();
    let mut previous = None;
    for (name, value) in &headers {
        if previous == Some(name) {
            canonical.push(Part::Public(b","));
        } else {
            if previous.is_some() {
                canonical.push(Part::Public(b"\n"));
                signed_headers.push(';');
            }
            canonical.push(Part::Public(name.as_bytes()));
            canonical.push(Part::Public(b":"));
            signed_headers.push_str(name);
        }
        canonical.push(Part::Value(value));
        previous = Some(name);
    }
    if previous.is_some() {
        canonical.push(Part::Public(b"\n"));
    }
    let canonical_headers = SealedValue::compose(&canonical);
    let request = SealedValue::compose(&[
        Part::Public(r.method.as_bytes()),
        Part::Public(b"\n"),
        Part::Public(r.canonical_uri.as_bytes()),
        Part::Public(b"\n"),
        Part::Public(r.canonical_query.as_bytes()),
        Part::Public(b"\n"),
        Part::Value(&canonical_headers),
        Part::Public(b"\n"),
        Part::Public(signed_headers.as_bytes()),
        Part::Public(b"\n"),
        Part::Public(r.payload_hash.as_bytes()),
    ]);
    let hash = request.digest(Digest::Sha256).hex_lower();
    let prefix = format!(
        "{SIGV4_ALGORITHM}\n{}\n{}/{}/{}/{SIGNATURE_TERMINATION}\n",
        r.amzdate, r.datestamp, r.region, r.service
    );
    let text = SealedValue::compose(&[Part::Public(prefix.as_bytes()), Part::Value(&hash)]);
    Ok((text, signed_headers))
}

pub(crate) fn sign(
    key: &SealedValue,
    request: &Aws4Request<'_>,
    token: Option<&Cred>,
) -> Result<Signature, Refused> {
    let (text, signed_headers) = string_to_sign(request, token)?;
    Ok(Signature {
        signature: key.hmac_sha256(&text).hex_lower(),
        signed_headers,
    })
}

pub(crate) fn verify(secret: &Cred, request: &Aws4Request<'_>, presented: &str) -> bool {
    let key = day_key(secret, request.datestamp, request.region, request.service);
    sign(&key, request, None).is_ok_and(|signed| signed.signature.verify_eq(presented.as_bytes()))
}

#[cfg(test)]
#[path = "tests/recipe_tests.rs"]
mod tests;
