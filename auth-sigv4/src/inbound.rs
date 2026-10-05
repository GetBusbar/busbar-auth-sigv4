// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! INBOUND AWS Signature Version 4 verification: the check a CLIENT's signature against busbar
//! passes before the request is admitted. MOVED HERE FROM THE KERNEL (BUSBAR-1.6.0.md THE DESIGN,
//! §6 "Inbound verify": "its inbound SigV4 reads through a host store service"; Appendix A, B.3:
//! "Inbound SigV4 moves into an auth plugin's verify over a store-read host service, keeping the
//! dummy-secret timing equivalence for an unknown AccessKeyId").
//!
//! Two sources, each ported verbatim:
//!
//! * `busbar-kernel-identity/src/ingress_sigv4.rs`: the `Authorization` parse, the `x-amz-date`
//!   window, and the canonical signing the check recomputes ([`sign_v4`], which keeps a quoted
//!   header value's interior spaces verbatim, unlike the outbound signer). The HMAC chain, the key
//!   derivation and the algorithm tokens are the outbound signer's ([`crate::sigv4`]), shared.
//! * `busbar-kernel/src/auth/mod.rs`: `has_sigv4_authorization`, `canonical_query_string`, the
//!   structural gate `auth_middleware` ran before buffering the body, and
//!   `verify_sigv4_ingress_credential` (the signed-header prefilter, `UNSIGNED-PAYLOAD` refused, the
//!   body hash against the signed `x-amz-content-sha256` in constant time, the dummy-secret rule).
//!
//! What changed is only WHERE THE SECRET COMES FROM: the kernel looked the AccessKeyId up in its
//! governance store; this check reads it through the host's `records.secret` service
//! ([`SecretSource`]), which answers a fixed dummy secret, not live, for an id it does not hold, in
//! the time it answers a known one. The full constant-time verification ALWAYS runs over whatever
//! secret came back, and only (signature verified AND live) admits: an unknown id, a disabled or
//! revoked key and a bad signature reject alike.
//!
//! EVERY FAILURE IS ONE ANSWER ([`Judgement::Reject`]): the kernel maps it to its one opaque 401.
//! The reason ([`VerifyError`]) never leaves this module, and nothing here logs: no secret, no
//! signature, no body is ever written anywhere.

use zeroize::Zeroizing;

use busbar_contract::redacted::constant_time_eq;

use crate::sigv4::{
    hmac, sha256_hex, signing_key, uri_encode_path, SIGNATURE_TERMINATION, SIGV4_ALGORITHM,
};

/// The canonical lowercase name of the `x-amz-date` header.
pub const X_AMZ_DATE: &str = "x-amz-date";
/// The canonical lowercase name of the `x-amz-content-sha256` header.
pub const X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";
/// The `authorization` header: the one carrier this plugin's `verify` reads its credential from.
pub const AUTHORIZATION: &str = "authorization";
/// The credential kind the host holds SigV4 credentials under (`records.secret`'s `kind`).
pub const CREDENTIAL_KIND: &str = "sigv4";

/// The AWS sentinel for "I did not hash my body": refused for governed ingress.
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The secret a NON-UTF-8 host answer is verified against (never admitted): the kernel's
/// `auth::DUMMY_SECRET`, the same bytes the host answers for an unknown id, so the work matches.
const DUMMY_SECRET: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";

/// Canonicalize a signed-header value per AWS SigV4: trim leading/trailing ASCII spaces (0x20) and
/// collapse each run of sequential ASCII spaces to a single space — EXCEPT inside a quoted string,
/// whose spaces are significant and pass through verbatim. ONLY the ASCII space character is treated
/// as whitespace — tabs, NBSP (U+00A0), newlines, and every other Unicode whitespace codepoint are
/// preserved verbatim, because AWS does the same. (This is intentionally NOT `split_whitespace`,
/// which would also fold tabs/NBSP/newlines and break the signature.)
///
/// The quote state matters because a header whose value carries a quoted string (a `user-agent`
/// comment, a `content-disposition` filename) is signed by the client with those interior spaces
/// intact; folding them here produced a canonical value the client never signed, so a correctly
/// signed request was rejected.
fn canonicalize_header_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut prev_space = false;
    let mut in_quotes = false;
    for ch in v.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
        }
        if ch == ' ' && !in_quotes {
            // Defer emitting until we know it is not a trailing run; mark that a space is pending.
            prev_space = true;
        } else {
            // Emit a single collapsed space before this non-space char, but only if we have already
            // emitted at least one char (i.e. drop any leading run).
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
/// `canonical_uri` must already be URI-encoded; `canonical_querystring` sorted + encoded (or empty).
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
    let mut h: Vec<(String, String)> = headers
        .iter()
        // AWS SigV4 canonicalization of a (non-quoted) header value: trim leading/trailing ASCII
        // spaces (0x20) AND collapse runs of sequential ASCII spaces to a single space. AWS operates
        // on ASCII space ONLY — NBSP (U+00A0), tabs, and other Unicode whitespace are NOT treated as
        // whitespace and must pass through verbatim, byte-for-byte, into the signed value.
        .map(|(k, v)| (k.to_lowercase(), canonicalize_header_value(v)))
        .collect();
    h.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = h
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{datestamp}/{region}/{service}/{SIGNATURE_TERMINATION}");
    let string_to_sign = format!(
        "{SIGV4_ALGORITHM}\n{amzdate}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = signing_key(secret, datestamp, region, service);
    let signature = hex::encode(hmac(&key, string_to_sign.as_bytes()));
    (signature, signed_headers)
}

/// Allowed clock skew (seconds) between the inbound request's `x-amz-date` and the verifier's clock.
/// AWS itself uses a 5-minute window; matching it rejects replay of a signature captured more than
/// `±CLOCK_SKEW_SECS` ago while tolerating ordinary client/server clock drift. Bounding the age of an
/// accepted signature is the replay defense (busbar does not track nonces).
pub const CLOCK_SKEW_SECS: u64 = 300;

/// Why an inbound SigV4 verification was rejected. EVERY variant is the SAME answer on the wire
/// ([`Judgement::Reject`]): the distinction stays inside this module, or it becomes an oracle (e.g.
/// distinguishing "unknown AccessKeyId" from "bad signature" would let an attacker enumerate valid
/// AccessKeyIds). The variants carry NO secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// No `Authorization` header, or it is not an `AWS4-HMAC-SHA256` credential.
    MissingAuthorization,
    /// The `Authorization` header is present but structurally malformed (bad Credential/SignedHeaders/
    /// Signature, or a Credential scope that is not `.../aws4_request`).
    MalformedAuthorization,
    /// No usable `x-amz-date` (absent, unparseable, or wrong format).
    MissingDate,
    /// `x-amz-date` is outside the ±`CLOCK_SKEW_SECS` window (stale → possible replay, or far future).
    Expired,
    /// A header named in `SignedHeaders` is not present on the request (cannot reconstruct the
    /// canonical headers the client signed), or the mandatory `host` header is not signed.
    SignedHeadersMismatch,
    /// The recomputed signature did not match the one in the `Authorization` header (wrong secret,
    /// tampered request, or — indistinguishably — an unknown AccessKeyId verified against a dummy
    /// secret).
    SignatureMismatch,
}

/// The parsed components of an inbound SigV4 `Authorization` header. All fields are non-secret (the
/// AccessKeyId and signature both travel in plaintext on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuthHeader {
    /// The Credential scope's AccessKeyId: which key the client claims to sign with.
    pub access_key_id: String,
    /// The Credential scope's `YYYYMMDD` date.
    pub datestamp: String,
    /// The Credential scope's region.
    pub region: String,
    /// The Credential scope's service.
    pub service: String,
    /// The lowercase, `;`-joined SignedHeaders list, e.g. `host;x-amz-content-sha256;x-amz-date`.
    pub signed_headers: String,
    /// The hex signature the client computed.
    pub signature: String,
}

/// Parse an inbound `Authorization: AWS4-HMAC-SHA256 Credential=.../..., SignedHeaders=..., Signature=...`
/// header into its components. Returns `MissingAuthorization` when the value is not an AWS4-HMAC-SHA256
/// credential at all (so a Bearer/Basic header falls through cleanly), and `MalformedAuthorization`
/// when it claims to be SigV4 but is structurally broken.
///
/// The `Credential` field is `AccessKeyId/datestamp/region/service/aws4_request` — five `/`-separated
/// parts, the last of which MUST be `aws4_request`. The three comma-separated sections
/// (Credential / SignedHeaders / Signature) may carry optional surrounding whitespace, which we trim.
///
/// # Errors
///
/// [`VerifyError::MissingAuthorization`] or [`VerifyError::MalformedAuthorization`], as above.
pub fn parse_authorization_header(value: &str) -> Result<ParsedAuthHeader, VerifyError> {
    // The algorithm token and the rest are split on the FIRST space. Match the algorithm
    // case-sensitively against the single spelling AWS uses; anything else is "not SigV4".
    let value = value.trim();
    let Some((algo, rest)) = value.split_once(' ') else {
        return Err(VerifyError::MissingAuthorization);
    };
    if algo != SIGV4_ALGORITHM {
        return Err(VerifyError::MissingAuthorization);
    }

    // Collect the comma-separated key=value sections into a small map. We do NOT rely on order
    // (AWS emits Credential, SignedHeaders, Signature in that order, but tolerate any order here).
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for section in rest.split(',') {
        let section = section.trim();
        let Some((k, v)) = section.split_once('=') else {
            return Err(VerifyError::MalformedAuthorization);
        };
        match k.trim() {
            "Credential" => credential = Some(v.trim().to_string()),
            "SignedHeaders" => signed_headers = Some(v.trim().to_string()),
            "Signature" => signature = Some(v.trim().to_string()),
            // An unknown section key is SKIPPED, not rejected: AWS SigV4 clients may legitimately emit
            // extra/unknown sections in the Authorization header, and the signature itself binds the
            // request (an attacker cannot forge a valid one by adding sections). The three MANDATORY
            // sections (Credential, SignedHeaders, Signature) are still required below.
            _ => continue,
        }
    }
    let (Some(credential), Some(signed_headers), Some(signature)) =
        (credential, signed_headers, signature)
    else {
        return Err(VerifyError::MalformedAuthorization);
    };
    if signature.is_empty() || signed_headers.is_empty() {
        return Err(VerifyError::MalformedAuthorization);
    }

    // Credential = AccessKeyId/datestamp/region/service/aws4_request (exactly five parts).
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[4] != SIGNATURE_TERMINATION {
        return Err(VerifyError::MalformedAuthorization);
    }
    let access_key_id = parts[0].to_string();
    let datestamp = parts[1].to_string();
    let region = parts[2].to_string();
    let service = parts[3].to_string();
    if access_key_id.is_empty() || datestamp.is_empty() || region.is_empty() || service.is_empty() {
        return Err(VerifyError::MalformedAuthorization);
    }

    Ok(ParsedAuthHeader {
        access_key_id,
        datestamp,
        region,
        service,
        signed_headers,
        signature,
    })
}

/// Parse an `x-amz-date` value (`YYYYMMDDTHHMMSSZ`, basic ISO-8601 UTC) into a Unix epoch (seconds).
/// Returns `None` on any format deviation. Self-contained (a civil-date computation, the inverse of
/// `format_amz_time`); no external date crate. Used to bound the signature's age (clock-skew check).
fn parse_amz_date(amzdate: &str) -> Option<u64> {
    // Exact shape: 8 digits, 'T', 6 digits, 'Z' — 16 chars total. Reject anything else.
    let b = amzdate.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    // The slices below index by char position; guard against a non-ASCII multi-byte char straddling a
    // boundary (`amzdate[0..4]` etc. would panic). The valid format is pure ASCII (digits + 'T'/'Z'),
    // so any non-ASCII byte is already invalid.
    if !amzdate.is_ascii() {
        return None;
    }
    let digits = |s: &str| -> Option<i64> {
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse::<i64>().ok()
        } else {
            None
        }
    };
    let year = digits(&amzdate[0..4])?;
    let month = digits(&amzdate[4..6])?;
    let day = digits(&amzdate[6..8])?;
    let hour = digits(&amzdate[9..11])?;
    let min = digits(&amzdate[11..13])?;
    let sec = digits(&amzdate[13..15])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // days_from_civil (public-domain, inverse of format_amz_time's civil_from_days).
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let epoch = days * 86_400 + hour * 3_600 + min * 60 + sec;
    if epoch < 0 {
        return None;
    }
    Some(epoch as u64)
}

/// The fully-assembled inputs for verifying ONE inbound SigV4 request. `canonical_uri` MUST already
/// be URI-encoded the SAME way the signer encodes it ([`uri_encode_path`]); `canonical_querystring`
/// MUST be [`canonical_query_string`]'s (or empty). `headers` carries the ACTUAL request header
/// values for (at least) every name in the parsed `SignedHeaders` list; extra headers are ignored
/// (only the signed ones enter the canonical request).
pub struct InboundRequest<'a> {
    /// The request method, as sent.
    pub method: &'a str,
    /// The URI-encoded request path.
    pub canonical_uri: &'a str,
    /// The sorted, encoded query string (or empty).
    pub canonical_querystring: &'a str,
    /// (name, value) pairs from the request; names case-insensitive. Must include every signed header.
    pub headers: &'a [(String, String)],
    /// The hex SHA-256 payload hash the client signed (its `x-amz-content-sha256` header value).
    pub payload_hash: &'a str,
    /// The request's `x-amz-date` (`YYYYMMDDTHHMMSSZ`).
    pub amzdate: &'a str,
}

/// Verify an inbound SigV4 signature against a candidate `secret`, at wall-clock `now` (Unix seconds).
///
/// This is the SECURITY-CRITICAL core. It:
///   1. validates `x-amz-date` is within ±`CLOCK_SKEW_SECS` of `now` (replay/skew bound),
///   2. confirms the Credential's `datestamp` agrees with `x-amz-date`'s date (a signer always
///      derives the scope datestamp from the same timestamp),
///   3. selects EXACTLY the headers named in `SignedHeaders` from the request (rejecting if any is
///      absent, or if `host` is not among them — `host` MUST be signed),
///   4. recomputes the signature via [`sign_v4`] (NO duplicate canonicalization), and
///   5. constant-time-compares the recomputed signature to the client's, AND constant-time-compares
///      the recomputed SignedHeaders string to the client's claimed one.
///
/// Returns `Ok(())` only when every check passes. The caller MUST invoke this even for an UNKNOWN
/// AccessKeyId (with the host's dummy secret) so the unknown-key and bad-signature paths are
/// timing/response indistinguishable (no AccessKeyId-enumeration oracle).
///
/// # Errors
///
/// The [`VerifyError`] that rejected the request (never surfaced past this module).
pub fn verify_inbound_sigv4(
    parsed: &ParsedAuthHeader,
    req: &InboundRequest<'_>,
    secret: &str,
    now: u64,
) -> Result<(), VerifyError> {
    // (1) Clock-skew / replay bound on x-amz-date.
    let Some(req_epoch) = parse_amz_date(req.amzdate) else {
        return Err(VerifyError::MissingDate);
    };
    let skew = req_epoch.abs_diff(now);
    if skew > CLOCK_SKEW_SECS {
        return Err(VerifyError::Expired);
    }

    // (2) The Credential scope datestamp must match x-amz-date's date (YYYYMMDD prefix).
    if req.amzdate.len() < 8 || parsed.datestamp != req.amzdate[0..8] {
        return Err(VerifyError::MalformedAuthorization);
    }

    // (3) Select exactly the signed headers, in the order the client listed them, taking each value
    // from the request. `host` MUST be signed (AWS requires it; an unsigned host would let a
    // signature be replayed against a different target).
    let signed: Vec<&str> = parsed.signed_headers.split(';').collect();
    if !signed.iter().any(|h| h.eq_ignore_ascii_case("host")) {
        return Err(VerifyError::SignedHeadersMismatch);
    }
    // A header name may legally appear SEVERAL times in one request. AWS canonicalizes such a name
    // to ONE entry whose value is every occurrence's value joined with a comma, in the order the
    // values appear in the request.
    let mut selected: Vec<(String, String)> = Vec::with_capacity(signed.len());
    for name in &signed {
        let lname = name.to_ascii_lowercase();
        let mut values = req
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(&lname))
            .map(|(_, v)| v.as_str())
            .peekable();
        if values.peek().is_none() {
            return Err(VerifyError::SignedHeadersMismatch);
        }
        // Canonicalize each occurrence BEFORE joining: AWS trims and collapses each value, then
        // joins. `sign_v4` canonicalizes again, which is idempotent.
        let joined = values
            .map(canonicalize_header_value)
            .collect::<Vec<_>>()
            .join(",");
        selected.push((lname, joined));
    }

    // (4) Recompute — same canonicalization, byte-for-byte.
    let (computed_sig, computed_signed_headers) = sign_v4(
        secret,
        &parsed.region,
        &parsed.service,
        req.method,
        req.canonical_uri,
        req.canonical_querystring,
        &selected,
        req.payload_hash,
        req.amzdate,
        &parsed.datestamp,
    );

    // (5) Constant-time compare BOTH the SignedHeaders string the client claimed and the signature.
    // Run BOTH compares unconditionally (no `&&` short-circuit) and fold, so the work — and thus the
    // timing — does not depend on WHICH check failed; only the final all-pass boolean is observable.
    let headers_ok = constant_time_eq(&computed_signed_headers, &parsed.signed_headers);
    let sig_ok = constant_time_eq(&computed_sig, &parsed.signature);
    if std::hint::black_box(u8::from(headers_ok) & u8::from(sig_ok)) == 1 {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Canonicalize the request query string for SigV4: split into key=value pairs, sort by (encoded)
/// key then (encoded) value, and join with `&`. An empty/absent query yields `""`. A bare key
/// (`?foo`) canonicalizes to `foo=` (AWS signs a missing value as empty).
///
/// Deliberately does NOT run each key/value through an AWS URI-encoder. `query` here is the RAW
/// wire query string — already percent-encoded exactly once by the client, since a compliant SigV4
/// client uses the SAME single URI-encoding pass to build both the CanonicalQueryString it signs AND
/// the query string it puts on the wire. Re-encoding would double-encode it (a client's correct
/// `a%2Fb` becomes `a%252Fb`), so every request with a query parameter needing escaping would fail
/// verification. Sorting is done on the RAW (already-encoded) bytes, which is equivalent to sorting
/// on the encoded key/value per the AWS spec.
pub fn canonical_query_string(query: Option<&str>) -> String {
    let Some(q) = query.filter(|q| !q.is_empty()) else {
        return String::new();
    };
    let mut pairs: Vec<(&str, &str)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// A header value as the kernel's `HeaderValue::to_str` read it: the text when every byte is
/// visible ASCII (or a tab), else `None` (the kernel then treated the value as absent).
fn header_str(v: &[u8]) -> Option<&str> {
    if v.iter().all(|&b| b == b'\t' || (0x20..0x7f).contains(&b)) {
        std::str::from_utf8(v).ok()
    } else {
        None
    }
}

/// One `verify`'s request, as the check reads it: the facts the host hands in, raw as received.
#[derive(Debug, Clone, Default)]
pub struct Request<'a> {
    /// The method, as given.
    pub method: &'a [u8],
    /// The path, raw as received.
    pub path: &'a [u8],
    /// The query without `?`, raw as received; `None` = none.
    pub query: Option<&'a [u8]>,
    /// Every field line, in the order presented: (name, value).
    pub lines: Vec<(&'a [u8], &'a [u8])>,
    /// The whole body; `None` = the host lent none.
    pub body: Option<&'a [u8]>,
    /// Wall-clock seconds, read once by the host for this call.
    pub now: u64,
}

impl Request<'_> {
    /// The FIRST line named `name` (ASCII case-insensitive): what the kernel's `HeaderMap::get`
    /// answered.
    fn first(&self, name: &str) -> Option<&[u8]> {
        self.lines
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| *v)
    }

    /// Whether any line is named `name` (the kernel's `HeaderMap::contains_key`).
    fn has(&self, name: &str) -> bool {
        self.first(name).is_some()
    }
}

/// Does the request carry an inbound AWS SigV4 `Authorization` header (`AWS4-HMAC-SHA256 ...`)?
/// The kernel's `has_sigv4_authorization`: the FIRST `authorization` line, read as visible ASCII,
/// trimmed at the start, opens with the algorithm token. Everything else (bearer, no Authorization)
/// is not this plugin's credential.
fn sigv4_authorization<'r>(req: &'r Request<'_>) -> Option<&'r str> {
    req.first(AUTHORIZATION)
        .and_then(header_str)
        .filter(|v| v.trim_start().starts_with(SIGV4_ALGORITHM))
}

/// What the host's `records.secret` answered for one credential.
pub enum Read {
    /// The secret (span `0`'s bytes, wiped on drop), and whether the credential is live. For an id
    /// the host does not hold, its fixed dummy secret, not live.
    Secret {
        /// The secret's bytes.
        secret: Zeroizing<Vec<u8>>,
        /// `SECRET_LIVE`.
        live: bool,
    },
    /// The host holds the call on the op's ticket: answer PENDING and re-issue the same handle.
    Pending,
    /// The read cannot be made on this call (a ticket-less `verify`: `records.secret` may pend, so
    /// the host refuses it there): answer REFUSED, and the host submits the same `verify` on a
    /// ticket.
    NotNow,
    /// The host serves no `records.secret`, refused or failed it, or broke its rules: fail closed.
    Unavailable,
}

/// Where the check reads a credential's secret: the host's `records.secret` on the request path, a
/// fake in the unit tests.
pub trait SecretSource {
    /// The secret of credential `id` of `kind`.
    fn read(&mut self, kind: &str, id: &str) -> Read;
}

/// The check's answer for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judgement {
    /// Not this plugin's credential (no SigV4 `Authorization`): the kernel tries its next path.
    Pass,
    /// A SigV4 credential that does not verify, for ANY reason: the one opaque 401.
    Reject,
    /// Verified, and the credential is live: the identity's subject is the AccessKeyId.
    Identity(String),
    /// The secret read pends on the op's ticket.
    Pending,
    /// The secret cannot be read on this (ticket-less) call.
    NotNow,
}

/// Judge one request: the kernel's SigV4 pre-step and `verify_sigv4_ingress_credential`, in its
/// order, the secret read through `source`.
pub fn judge(req: &Request<'_>, source: &mut impl SecretSource) -> Judgement {
    // ENTRY (the kernel's `has_sigv4_authorization`): not a SigV4 Authorization is not ours.
    let Some(auth_value) = sigv4_authorization(req) else {
        return Judgement::Pass;
    };
    // THE STRUCTURAL GATE, before the body is read: the Authorization parses as SigV4 and the
    // `x-amz-content-sha256` / `x-amz-date` lines are present. All three are attacker-known, so this
    // is not an oracle: it never depends on whether an AccessKeyId is valid.
    let Ok(parsed) = parse_authorization_header(auth_value) else {
        return Judgement::Reject;
    };
    if !req.has(X_AMZ_CONTENT_SHA256) || !req.has(X_AMZ_DATE) {
        return Judgement::Reject;
    }
    // The kernel buffered the body here, a buffering failure the same opaque 401: a body the host
    // did not lend cannot be bound to the signed hash.
    let Some(body) = req.body else {
        return Judgement::Reject;
    };

    // PREFILTER: only the headers named in `SignedHeaders`, names lowercased, each value read as the
    // kernel's `HeaderValue::to_str` read it (a value that is not visible ASCII is left out).
    let signed_names: std::collections::HashSet<String> = parsed
        .signed_headers
        .split(';')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    let headers: Vec<(String, String)> = req
        .lines
        .iter()
        .filter_map(|(name, value)| {
            let lname = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
            if !signed_names.contains(&lname) {
                return None;
            }
            header_str(value).map(|v| (lname, v.to_string()))
        })
        .collect();

    // The payload hash the client signed is its (signed) `x-amz-content-sha256` value.
    let Some(payload_hash) = headers
        .iter()
        .find(|(k, _)| k == X_AMZ_CONTENT_SHA256)
        .map(|(_, v)| v.clone())
    else {
        return Judgement::Reject;
    };
    // BODY INTEGRITY: `UNSIGNED-PAYLOAD` is refused for governed ingress, and the body's own hash
    // must equal the signed declared hash (lowercase hex, constant time).
    if payload_hash.eq_ignore_ascii_case(UNSIGNED_PAYLOAD) {
        return Judgement::Reject;
    }
    let actual_body_hash = sha256_hex(body);
    if !constant_time_eq(&actual_body_hash, &payload_hash.to_ascii_lowercase()) {
        return Judgement::Reject;
    }
    let Some(amzdate) = headers
        .iter()
        .find(|(k, _)| k == X_AMZ_DATE)
        .map(|(_, v)| v.clone())
    else {
        return Judgement::Reject;
    };

    // The request's own facts, as the kernel read them off its `Uri` and `Method`.
    let (Ok(method), Ok(path)) = (
        std::str::from_utf8(req.method),
        std::str::from_utf8(req.path),
    ) else {
        return Judgement::Reject;
    };
    let query = match req.query.map(std::str::from_utf8) {
        None => None,
        Some(Ok(q)) => Some(q),
        Some(Err(_)) => return Judgement::Reject,
    };
    // `Uri::path` never answers an empty path: it reads `/` for one.
    let path = if path.is_empty() { "/" } else { path };
    let canonical_uri = uri_encode_path(path);
    let canonical_qs = canonical_query_string(query);
    let inbound = InboundRequest {
        method,
        canonical_uri: &canonical_uri,
        canonical_querystring: &canonical_qs,
        headers: &headers,
        payload_hash: &payload_hash,
        amzdate: &amzdate,
    };

    // THE SECRET, from the host. An UNKNOWN AccessKeyId does NOT short-circuit: the host answers its
    // fixed dummy secret (not live) in equal time, and the full constant-time verification runs over
    // whatever came back.
    let (secret, live) = match source.read(CREDENTIAL_KIND, &parsed.access_key_id) {
        Read::Secret { secret, live } => (secret, live),
        Read::Pending => return Judgement::Pending,
        Read::NotNow => return Judgement::NotNow,
        Read::Unavailable => return Judgement::Reject,
    };
    let (text, utf8) = match std::str::from_utf8(&secret) {
        Ok(s) => (s, true),
        Err(_) => (DUMMY_SECRET, false),
    };
    let verified = verify_inbound_sigv4(&parsed, &inbound, text, req.now).is_ok();
    // Admission: the signature verified AND the host called the credential live (its key enabled,
    // not revoked, the credential neither revoked nor expired). Any one failing rejects alike.
    if std::hint::black_box(u8::from(verified) & u8::from(live) & u8::from(utf8)) == 1 {
        Judgement::Identity(parsed.access_key_id)
    } else {
        Judgement::Reject
    }
}

#[cfg(test)]
#[path = "tests/inbound_tests.rs"]
mod tests;
