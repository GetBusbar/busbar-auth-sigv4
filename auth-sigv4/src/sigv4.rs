// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS Signature Version 4 request signing — no AWS SDK: SHA-256 on ring's digest, the keyed HMAC
//! the contract SDK's one wiped HMAC-SHA256 ([`hmac`]). The canonical-request -> string-to-sign ->
//! signature chain is verified against AWS's own published worked example (GET iam ListUsers,
//! 2015-08-30) in the tests.
//!
//! * The daily key: [`sign_v4`] is split into [`signing_key`] (the HMAC chain over date, region,
//!   service) and [`sign_v4_with_key`] (the per-request part), so a caller holding the day's key
//!   signs without re-deriving it. [`sign_v4`] is the two composed.
//! * The secret is zeroised: the `AWS4<secret>` key material, every derived key, and the HMAC's own key state (the padded
//!   key blocks and the chaining state after each) are [`Zeroizing`] buffers, wiped on drop. A
//!   library HMAC keeps its key's inner and outer pad states in a value it frees unwiped, so the
//!   contract's wiped HMAC holds them.
//!
//! The signer's chain is shared with the INBOUND check ([`crate::inbound`]): it recomputes a client's signature through [`hmac`], [`signing_key`] and [`sha256_hex`],
//! and derives the canonical URI with [`uri_encode_path`], keeping its own canonical signing (a
//! quoted header value's interior spaces are kept verbatim there).

use ring::digest;
use zeroize::{Zeroize, Zeroizing};

const SECS_PER_DAY: u64 = 86_400;
const SECS_PER_HOUR: u64 = 3_600;

/// The SigV4 algorithm token that appears in the `Authorization` header and the string-to-sign.
pub const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The terminating scope component appended to every Credential scope and fed to the HMAC chain.
pub const SIGNATURE_TERMINATION: &str = "aws4_request";
const SIGNATURE_KEY_PREFIX: &str = "AWS4";

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, data))
}

/// HMAC-SHA256 of `data` under `key`: the contract SDK's ONE wiped HMAC
/// ([`busbar_contract::abi::sdk::hmac::hmac_sha256`]), every key-derived state wiped on drop.
pub(crate) fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    busbar_contract::abi::sdk::hmac::hmac_sha256(key, data)
}

/// Derive the SigV4 signing key: HMAC chain over date -> region -> service -> "aws4_request".
/// Every intermediate key, and the `AWS4<secret>` seed, is wiped on drop.
pub(crate) fn signing_key(
    secret: &str,
    datestamp: &str,
    region: &str,
    service: &str,
) -> Zeroizing<Vec<u8>> {
    let seed = Zeroizing::new(format!("{SIGNATURE_KEY_PREFIX}{secret}"));
    let k_date = hmac(seed.as_bytes(), datestamp.as_bytes());
    let k_region = hmac(&k_date[..], region.as_bytes());
    let k_service = hmac(&k_region[..], service.as_bytes());
    Zeroizing::new(hmac(&k_service[..], SIGNATURE_TERMINATION.as_bytes()).to_vec())
}

/// Wipe every value of a header list (a session token rides in one), then drop the entries
/// (auth material is zeroised).
pub(crate) fn wipe(headers: &mut Vec<(String, String)>) {
    for (_, v) in headers.iter_mut() {
        v.zeroize();
    }
    headers.clear();
}

/// Append `b` URI-encoded per SigV4: a byte of the unreserved set (`A-Z a-z 0-9 - _ . ~`), or `/`
/// when `keep_slash`, as itself; every other byte as `%XX` (uppercase hex).
fn push_encoded(out: &mut String, b: u8, keep_slash: bool) {
    match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
        b'/' if keep_slash => out.push('/'),
        _ => {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
}

/// SigV4 URI-encode a request path: every byte outside the unreserved set (`A-Z a-z 0-9 - _ . ~`)
/// and `/` becomes `%XX` (uppercase hex). The inbound check derives the canonical URI with it
/// over the received path.
pub fn uri_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        push_encoded(&mut out, b, true);
    }
    out
}

/// One query name or value in SigV4's canonical form: its `%XX` escapes decoded once (a `%` that
/// does not open two hex digits is a literal `%`), then every byte URI-encoded over the unreserved
/// set with uppercase hex. Idempotent over the canonical form.
fn canonical_query_component(raw: &str) -> String {
    let b = raw.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16);
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let escaped = if b[i] == b'%' && i + 2 < b.len() {
            hex(b[i + 1])
                .zip(hex(b[i + 2]))
                .map(|(high, low)| ((high << 4) | low) as u8)
        } else {
            None
        };
        match escaped {
            Some(byte) => {
                push_encoded(&mut out, byte, false);
                i += 3;
            }
            None => {
                push_encoded(&mut out, b[i], false);
                i += 1;
            }
        }
    }
    out
}

/// The CANONICAL QUERY STRING an outbound request is signed over, from the query as it will be
/// sent (without `?`): each `name=value` pair (a bare name has the empty value) with its name and
/// value in canonical form ([`canonical_query_component`]), sorted by name then value, joined with
/// `&`; `""` for none. The server recomputes it from what it receives the same way, so a reserved
/// byte sent raw (`:`, `/`), a lowercase escape or an escaped unreserved byte signs as AWS checks
/// it. The inbound check recomputes a client's canonical query with it too
/// ([`crate::inbound::canonical_query_string`]).
pub fn canonical_query(query: Option<&str>) -> String {
    let Some(q) = query.filter(|q| !q.is_empty()) else {
        return String::new();
    };
    let mut pairs: Vec<(String, String)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (canonical_query_component(k), canonical_query_component(v))
        })
        .collect();
    pairs.sort();
    let mut out = String::with_capacity(q.len() + pairs.len());
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// Convert seconds since the epoch (1970-01-01 UTC) to (amzdate `YYYYMMDDTHHMMSSZ`, datestamp
/// `YYYYMMDD`). Pure UTC, no external date crate (a public-domain civil-from-days algorithm).
pub fn format_amz_time(epoch_secs: u64) -> (String, String) {
    let days = (epoch_secs / SECS_PER_DAY) as i64;
    let sod = epoch_secs % SECS_PER_DAY;
    let (h, mi, s) = (sod / SECS_PER_HOUR, (sod % SECS_PER_HOUR) / 60, sod % 60);

    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    (
        format!("{year:04}{month:02}{day:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{year:04}{month:02}{day:02}"),
    )
}

/// Canonicalize a (non-quoted) signed-header value per AWS SigV4: trim leading/trailing ASCII
/// spaces (0x20) and collapse each run of sequential ASCII spaces to a single space. Only the ASCII
/// space character is treated as whitespace — tabs, NBSP, newlines and every other Unicode
/// whitespace codepoint pass through verbatim, because AWS does the same.
fn canonicalize_header_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut prev_space = false;
    for ch in v.chars() {
        if ch == ' ' {
            prev_space = true;
        } else {
            if prev_space && !out.is_empty() {
                out.push(' ');
            }
            prev_space = false;
            out.push(ch);
        }
    }
    out
}

/// Compute the SigV4 signature hex + the `SignedHeaders` string for a request. `headers` is the
/// full set of headers to sign (names case-insensitive); they are lowercased + sorted internally.
/// `canonical_uri` must already be URI-encoded; `canonical_querystring` sorted + encoded (or
/// empty). The day's key derived here, then [`sign_v4_with_key`]: the composition the published
/// vector pins (the request path holds the day's key and calls [`sign_v4_with_key`] itself).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn sign_v4(
    secret: &str,
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
    let key = signing_key(secret, datestamp, region, service);
    sign_v4_with_key(
        &key,
        region,
        service,
        method,
        canonical_uri,
        canonical_querystring,
        headers,
        payload_hash,
        amzdate,
        datestamp,
    )
}

/// [`sign_v4`] under an already-derived [`signing_key`] for the request's date, region and service:
/// the signature hex + the `SignedHeaders` string for a request. `headers` is the
/// full set of headers to sign (names case-insensitive); they are lowercased + sorted internally.
/// `canonical_uri` must already be URI-encoded; `canonical_querystring` sorted + encoded (or
/// empty).
#[allow(clippy::too_many_arguments)]
pub fn sign_v4_with_key(
    key: &[u8],
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
    let mut h: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), canonicalize_header_value(v)))
        .collect();
    h.sort_by(|a, b| a.0.cmp(&b.0));

    // The SigV4 canonicalisation rule does not sort the values of a header that appears more than
    // once; it combines them into one comma-separated list under that header's single entry. A
    // caller CAN hand this function the same name twice (`decorate` builds its header list by
    // pushing onto whatever the envelope already carries), so merging here rather than assuming the
    // caller never repeats a name is what keeps `SignedHeaders` and the canonical headers block in
    // the one-entry-per-name shape AWS's servers expect. The sort above already made same-named
    // entries adjacent, so a single pass merges them in their original relative order.
    let mut merged: Vec<(String, String)> = Vec::with_capacity(h.len());
    for (k, mut v) in h {
        match merged.last_mut() {
            Some((last_k, last_v)) if *last_k == k => {
                last_v.push(',');
                last_v.push_str(&v);
                v.zeroize();
            }
            _ => merged.push((k, v)),
        }
    }
    let mut h = merged;

    // The canonical headers carry a session token's value: they and the canonical request built
    // from them are sized once (no growth leaves a copy behind) and wiped on drop, as is every
    // per-header copy.
    let mut canonical_headers = Zeroizing::new(String::with_capacity(
        h.iter().map(|(k, v)| k.len() + v.len() + 2).sum(),
    ));
    for (k, v) in &h {
        canonical_headers.push_str(k);
        canonical_headers.push(':');
        canonical_headers.push_str(v);
        canonical_headers.push('\n');
    }
    let signed_headers = h
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    wipe(&mut h);

    let parts = [
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers.as_str(),
        signed_headers.as_str(),
        payload_hash,
    ];
    let mut canonical_request = Zeroizing::new(String::with_capacity(
        parts.iter().map(|p| p.len() + 1).sum(),
    ));
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            canonical_request.push('\n');
        }
        canonical_request.push_str(part);
    }
    let scope = format!("{datestamp}/{region}/{service}/{SIGNATURE_TERMINATION}");
    let string_to_sign = format!(
        "{SIGV4_ALGORITHM}\n{amzdate}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signature = hex::encode(&hmac(key, string_to_sign.as_bytes())[..]);
    (signature, signed_headers)
}

/// Split a signing lane's configured credential, `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]`, into its
/// three parts: the non-secret access key id, the signing secret, and the optional session token
/// (everything after the second `:`, colons included). `None` — sign nothing — when either of the
/// first two is missing or empty, the same misconfiguration rule the dialect writer applied when it
/// parsed this string itself.
pub fn split_credential(raw: &str) -> Option<(&str, &str, Option<&str>)> {
    let mut parts = raw.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(access), Some(secret), token) if !access.is_empty() && !secret.is_empty() => {
            Some((access, secret, token))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/sigv4_tests.rs"]
mod tests;
