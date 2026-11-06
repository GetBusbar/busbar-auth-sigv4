// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Public SigV4 path, query and time canonicalization. Credential derivation and signatures
//! use the shared SDK's sealed AWS4 recipes. Test fixtures (`tests/fixtures.rs`) read signatures
//! only through its dev-only wire sink.

use ring::digest;
use zeroize::Zeroizing;

/// The seconds in a day: the one constant the date arithmetic and the day-key schedule share.
pub(crate) const SECS_PER_DAY: u64 = 86_400;
/// The seconds in an hour.
pub(crate) const SECS_PER_HOUR: u64 = 3_600;

/// The SigV4 algorithm token that appears in the `Authorization` header and the string-to-sign.
pub const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The terminating scope component appended to every Credential scope and fed to the HMAC chain.
pub const SIGNATURE_TERMINATION: &str = "aws4_request";

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, data))
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

/// The S3 signing names whose canonical URI is the path encoded once, never normalized: the ones
/// the AWS S3 endpoint ruleset signs with `disableDoubleEncoding` (S3 itself, S3 on Outposts, S3
/// Object Lambda and S3 Express One Zone). An exact list, never a prefix: any other name that
/// opens with `s3` (`s3control`, say) is signed as every other service is.
const SINGLE_ENCODED_SERVICES: [&str; 4] = ["s3", "s3-outposts", "s3-object-lambda", "s3express"];

/// The CANONICAL URI a request scoped to `service` is signed over, from its path as sent (already
/// percent-encoded once): for an S3 signing name ([`SINGLE_ENCODED_SERVICES`]), the path encoded
/// ONCE — each `%XX` escape decoded and every byte re-encoded over the unreserved set and `/` with
/// uppercase hex (an escaped `/` stays `%2F`, a separator never a key byte), never normalized; for every other service, the path as sent
/// NORMALIZED ([`normalize_path`]) then encoded once more ([`uri_encode_path`], AWS's double
/// encoding). The outbound signer and the inbound check both derive it here.
pub fn canonical_uri(path: &str, service: &str) -> String {
    if SINGLE_ENCODED_SERVICES.contains(&service) {
        encode_path_once(path)
    } else {
        uri_encode_path(&normalize_path(path))
    }
}

/// `path` normalized as AWS normalizes a non-S3 canonical URI: empty and `.` segments dropped (so
/// `//` collapses), each `..` removing the segment before it (never above the root), the result
/// rooted at `/` and keeping a trailing `/` when the path ends in one (or in `.` / `..`). An empty
/// path is `/`.
fn normalize_path(path: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                kept.pop();
            }
            s => kept.push(s),
        }
    }
    let last = path.rsplit('/').next().unwrap_or("");
    let trailing = path.contains('/') && matches!(last, "" | "." | "..");
    let mut out = String::with_capacity(path.len() + 1);
    for s in &kept {
        out.push('/');
        out.push_str(s);
    }
    if out.is_empty() || trailing {
        out.push('/');
    }
    out
}

/// `path` in its single-encoded canonical form: every `%XX` escape decoded (an escaped `/` kept
/// escaped) and every byte encoded over the unreserved set and `/`. Idempotent over the canonical
/// form.
fn encode_path_once(path: &str) -> String {
    let b = path.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match escaped_byte(b, i) {
            Some(byte) => {
                push_encoded(&mut out, byte, byte != b'/');
                i += 3;
            }
            None => {
                push_encoded(&mut out, b[i], true);
                i += 1;
            }
        }
    }
    out
}

/// The byte a `%XX` escape at `b[i]` stands for; `None` when `b[i]` opens no escape (a `%` not
/// followed by two hex digits is a literal `%`).
fn escaped_byte(b: &[u8], i: usize) -> Option<u8> {
    let hex = |c: u8| (c as char).to_digit(16);
    if b[i] == b'%' && i + 2 < b.len() {
        hex(b[i + 1])
            .zip(hex(b[i + 2]))
            .map(|(high, low)| ((high << 4) | low) as u8)
    } else {
        None
    }
}

/// One query name or value in SigV4's canonical form: its `%XX` escapes decoded once (a `%` that
/// does not open two hex digits is a literal `%`), then every byte URI-encoded over the unreserved
/// set with uppercase hex. Idempotent over the canonical form.
fn canonical_query_component(raw: &str) -> Zeroizing<String> {
    let b = raw.as_bytes();

    let mut out = Zeroizing::new(String::with_capacity(b.len().saturating_mul(3)));
    let mut i = 0;
    while i < b.len() {
        match escaped_byte(b, i) {
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
/// it. The inbound check recomputes a client's canonical query with it too.
pub fn canonical_query(query: Option<&str>) -> String {
    let Some(q) = query.filter(|q| !q.is_empty()) else {
        return String::new();
    };
    let mut pairs: Vec<(Zeroizing<String>, Zeroizing<String>)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (canonical_query_component(k), canonical_query_component(v))
        })
        .collect();
    pairs.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    let capacity = pairs
        .iter()
        .map(|(k, v)| k.len() + v.len() + 1)
        .sum::<usize>()
        + pairs.len().saturating_sub(1);

    let mut out = String::with_capacity(capacity);
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

#[cfg(test)]
#[path = "tests/sigv4_tests.rs"]
mod tests;
