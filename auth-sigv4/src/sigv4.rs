// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS Signature Version 4 request signing — hand-rolled, no AWS SDK: SHA-256 on ring's digest, the
//! keyed HMAC over SHA-256's compression function with every key-derived state in this crate's own
//! wiped buffers ([`hmac`]). MOVED VERBATIM from the identity unit's `egress_auth/sigv4/mod.rs` in the kernel, staged
//! `busbar-auth-outbound::sigv4` (KERNEL<>PLUGINS step 22), then here (AUTH-SPLIT: sigv4 is its
//! own mechanism, its own crate): the canonical-request -> string-to-sign -> signature chain is
//! verified against AWS's own published worked example (GET iam ListUsers, 2015-08-30) in the
//! tests, so correctness does not rely on trusting the move.
//!
//! Two changes, both at the edge of the chain and neither touching a signed byte:
//!
//! * THE DAILY KEY (BUSBAR-1.6.0.md THE DESIGN, §6.5: "SigV4 signs per request with a daily signing key derived
//!   ahead of time"): [`sign_v4`] is split into [`signing_key`] (the HMAC chain over date, region,
//!   service) and [`sign_v4_with_key`] (the per-request part), so a caller holding the day's key
//!   signs without re-deriving it. [`sign_v4`] is the two composed, exactly the old function.
//! * THE SECRET IS ZEROISED (TODO item 586, #53/#54; THE DESIGN §6: "auth material is zeroised"):
//!   the `AWS4<secret>` key material, every derived key, and the HMAC's own key state (the padded
//!   key blocks and the chaining state after each) are [`Zeroizing`] buffers, wiped on drop. A
//!   library HMAC keeps its key's inner and outer pad states in a value it frees unwiped, so
//!   [`hmac`] holds them itself.
//!
//! The signer's chain is shared with the INBOUND check ([`crate::inbound`], moved here from the
//! kernel): it recomputes a client's signature through [`hmac`], [`signing_key`] and [`sha256_hex`],
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

/// SHA-256's block size, in bytes.
const BLOCK: usize = 64;

/// SHA-256's initial chaining state (FIPS 180-4, 5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256's round constants (FIPS 180-4, 4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Run SHA-256's compression function (FIPS 180-4, 6.2.2) over one whole `block` into `state`.
/// Written here rather than taken from a library's feature: the message schedule and the working
/// variables carry key-derived words, so they live in wiped buffers too, and the binary's
/// unified dependency features stay the ones every linked plugin declares.
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK]) {
    let mut w = Zeroizing::new([0_u32; 64]);
    for (t, word) in block.as_chunks::<4>().0.iter().enumerate() {
        w[t] = u32::from_be_bytes(*word);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let mut v = Zeroizing::new(*state);
    for t in 0..64 {
        let [a, b, c, d, e, f, g, h] = *v;
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        *v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for (s, x) in state.iter_mut().zip(v.iter()) {
        *s = s.wrapping_add(*x);
    }
}

/// SHA-256 of `prefix` (one whole block, or none) followed by `data`. The chaining state and the
/// padded final blocks (which carry `data`'s tail) are wiped on drop, and so is the digest.
fn sha256_wiped(prefix: Option<&[u8; BLOCK]>, data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut state = Zeroizing::new(SHA256_IV);
    let mut total = data.len() as u64;
    if let Some(p) = prefix {
        compress(&mut state, p);
        total += BLOCK as u64;
    }
    let (blocks, rest) = data.as_chunks::<BLOCK>();
    for c in blocks {
        compress(&mut state, c);
    }
    let mut tail = Zeroizing::new([0_u8; 2 * BLOCK]);
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let end = if rest.len() + 9 <= BLOCK {
        BLOCK
    } else {
        2 * BLOCK
    };
    tail[end - 8..end].copy_from_slice(&total.wrapping_mul(8).to_be_bytes());
    for c in tail[..end].as_chunks::<BLOCK>().0 {
        compress(&mut state, c);
    }
    let mut out = Zeroizing::new([0_u8; 32]);
    for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(state.iter()) {
        *o = w.to_be_bytes();
    }
    out
}

/// HMAC-SHA256 of `data` under `key` (RFC 2104; a key past the block size is hashed first). HMAC
/// accepts a key of any length, so there is no error arm. Every key-derived value — the padded key,
/// the inner and outer pad blocks, the chaining states and the inner digest — lives in a buffer
/// wiped on drop, and so does the answer: no key state outlives the call unwiped.
pub(crate) fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k0 = Zeroizing::new([0_u8; BLOCK]);
    if key.len() > BLOCK {
        k0[..32].copy_from_slice(&sha256_wiped(None, key)[..]);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut pad = Zeroizing::new([0_u8; BLOCK]);
    for (p, k) in pad.iter_mut().zip(k0.iter()) {
        *p = k ^ 0x36;
    }
    let inner = sha256_wiped(Some(&*pad), data);
    for (p, k) in pad.iter_mut().zip(k0.iter()) {
        *p = k ^ 0x5c;
    }
    sha256_wiped(Some(&*pad), &inner[..])
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
/// (THE DESIGN §6: "auth material is zeroised").
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
/// and `/` becomes `%XX` (uppercase hex). MOVED VERBATIM from the kernel's
/// `egress_auth/sigv4::uri_encode_path`, the encoder the inbound check derives the canonical URI
/// with (1.5.5's ingress verify called it over the received path).
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
/// it. (The inbound check keeps its own builder: a client's query is already canonical there.)
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

/// Convert a epoch (1970-01-01 UTC) (seconds) to (amzdate `YYYYMMDDTHHMMSSZ`, datestamp `YYYYMMDD`). Pure UTC,
/// no external date crate (a public-domain civil-from-days algorithm).
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
