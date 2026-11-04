// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Inbound AWS Signature Version 4 verification: the check a CLIENT's signature against busbar
//! passes before the request is admitted. The secret is read through a host store service, keeping
//! the dummy-secret timing equivalence for an unknown AccessKeyId.
//!
//! The pieces: the `Authorization` parse, the `x-amz-date` window, and the canonical signing the
//! check recomputes ([`Cred::aws4_verify`], which trims and collapses ASCII space runs in every signed
//! value, quoted or not, as the outbound signer does); the structural gate before the body is
//! checked; and the credential check (the signed-header prefilter, `UNSIGNED-PAYLOAD` refused, the
//! body hash against the signed `x-amz-content-sha256` in constant time, the dummy-secret rule).
//! The HMAC chain and the key derivation are the contract SDK's; the canonical URI and query and
//! the algorithm tokens are the outbound signer's (`crate::sigv4`), shared.
//!
//! The AccessKeyId is looked up through the host's `records.secret` service
//! ([`SecretSource`]), which answers an empty secret, not live, for an id it does not hold, in
//! the time it answers a known one. The full constant-time verification ALWAYS runs, over the
//! plugin's own dummy for a secret that is not live, and only (signature verified AND live)
//! admits: an unknown id, a disabled or revoked key and a bad signature reject alike.
//!
//! Every failure is one answer ([`Judgement::Reject`]): the kernel maps it to its one opaque 401.
//! The reason never reaches the client: [`judge`] names a coarse category in the plugin's OWN log
//! (module `sigv4`; an end-user decline at `info`, a host read failure at `warn`). Pre-secret
//! structural and body gates use fixed descriptive reasons; secret-read and signature-stage
//! failures include the escaped, capped AccessKeyId. The signature-stage reasons share one category,
//! so the log does not tell an unknown AccessKeyId from a bad signature either. No secret, no
//! signature, no token, no body is ever written anywhere.

use zeroize::Zeroizing;

use busbar_contract::abi::sdk::chip::aws4::Aws4Request;
use busbar_contract::abi::sdk::cred::Cred;
use busbar_contract::constant_time_eq;

use crate::sigv4::{canonical_uri, SIGNATURE_TERMINATION, SIGV4_ALGORITHM};

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

/// The secret a not-live or NON-UTF-8 host answer is verified against (never admitted): the
/// plugin's own dummy, as the kernel's `auth::DUMMY_SECRET`. The host answers an empty, not-live
/// secret for an unknown id and the verifier swaps this in, so the work matches.
const DUMMY_SECRET: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";

/// The text the verification runs over, and whether the host's secret was UTF-8. The host answers
/// an empty, not-live secret for an id it does not hold and leaves the dummy to the verifier, so
/// the plugin swaps in [`DUMMY_SECRET`] whenever the credential is not live or its secret is not
/// text: the work is the same for every id, and the admission mask is unchanged.
fn verification_text(secret: &[u8], live: bool) -> (&str, bool) {
    match std::str::from_utf8(secret) {
        Ok(s) if live => (s, true),
        Ok(_) => (DUMMY_SECRET, true),
        Err(_) => (DUMMY_SECRET, false),
    }
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

impl VerifyError {
    /// The one reason word the plugin's log names this cause by (never sent to the client).
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::MissingAuthorization | Self::MalformedAuthorization => "malformed",
            Self::MissingDate => "missing-date",
            Self::Expired => "expired",
            Self::SignedHeadersMismatch => "signed-headers",
            Self::SignatureMismatch => "signature",
        }
    }
}

/// The parsed components of an inbound SigV4 `Authorization` header. Its `Debug` withholds the
/// signature (a log line never carries one).
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for ParsedAuthHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedAuthHeader")
            .field("access_key_id", &self.access_key_id)
            .field("datestamp", &self.datestamp)
            .field("region", &self.region)
            .field("service", &self.service)
            .field("signed_headers", &self.signed_headers)
            .field("signature", &"<withheld>")
            .finish()
    }
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
    let value = value.trim();
    let Some((algo, rest)) = value.split_once(' ') else {
        return Err(VerifyError::MissingAuthorization);
    };
    if algo != SIGV4_ALGORITHM {
        return Err(VerifyError::MissingAuthorization);
    }

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for section in rest.split(',') {
        let section = section.trim();
        let Some((k, v)) = section.split_once('=') else {
            return Err(VerifyError::MalformedAuthorization);
        };
        let slot = match k.trim() {
            "Credential" => &mut credential,
            "SignedHeaders" => &mut signed_headers,
            "Signature" => &mut signature,

            _ => continue,
        };
        if slot.replace(v.trim()).is_some() {
            return Err(VerifyError::MalformedAuthorization);
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

    let mut parts = credential.split('/');
    let (Some(access_key_id), Some(datestamp), Some(region), Some(service), Some(termination)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(VerifyError::MalformedAuthorization);
    };
    if parts.next().is_some() || termination != SIGNATURE_TERMINATION {
        return Err(VerifyError::MalformedAuthorization);
    }
    if access_key_id.is_empty() || datestamp.is_empty() || region.is_empty() || service.is_empty() {
        return Err(VerifyError::MalformedAuthorization);
    }

    Ok(ParsedAuthHeader {
        access_key_id: access_key_id.to_string(),
        datestamp: datestamp.to_string(),
        region: region.to_string(),
        service: service.to_string(),
        signed_headers: signed_headers.to_string(),
        signature: signature.to_string(),
    })
}

/// Parse an `x-amz-date` value (`YYYYMMDDTHHMMSSZ`, basic ISO-8601 UTC) into a Unix epoch (seconds).
/// Returns `None` on an invalid shape or calendar date (a second of 60 included: no leap
/// second is admitted). Self-contained (a civil-date computation, the inverse of
/// `format_amz_time`); no external date crate. Used to bound the signature's age (clock-skew check).
fn parse_amz_date(amzdate: &str) -> Option<u64> {
    let b = amzdate.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }

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
    if !(1..=12).contains(&month) || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=month_days).contains(&day) {
        return None;
    }

    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let epoch = days * crate::sigv4::SECS_PER_DAY as i64 + hour * 3_600 + min * 60 + sec;
    if epoch < 0 {
        return None;
    }
    Some(epoch as u64)
}

/// The fully-assembled inputs for verifying ONE inbound SigV4 request. `canonical_uri` MUST already
/// be URI-encoded the SAME way the signer encodes it (`crate::sigv4::canonical_uri`); `canonical_querystring`
/// MUST be [`canonical_query_string`]'s (or empty). `headers` carries the ACTUAL request header
/// values for (at least) every name in the parsed `SignedHeaders` list; extra headers are ignored
/// (only the signed ones enter the canonical request).
pub struct InboundRequest<'a, H = String> {
    /// The request method, as sent.
    pub method: &'a str,
    /// The URI-encoded request path.
    pub canonical_uri: &'a str,
    /// The sorted, encoded query string (or empty).
    pub canonical_querystring: &'a str,
    /// (name, value) pairs from the request; names case-insensitive. Must include every signed header.
    pub headers: &'a [(H, H)],
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
///   4. recomputes the signature via [`Cred::aws4_verify`] (NO duplicate canonicalization), and
///   5. constant-time-compares the recomputed signature to the client's, AND constant-time-compares
///      the recomputed SignedHeaders string to the client's claimed one.
///
/// Returns `Ok(())` only when every check passes. The caller MUST invoke this even for an UNKNOWN
/// AccessKeyId (with the plugin's dummy secret) so the unknown-key and bad-signature paths are
/// timing/response indistinguishable (no AccessKeyId-enumeration oracle).
///
/// # Errors
///
/// The [`VerifyError`] that rejected the request (never surfaced past this module).
pub fn verify_inbound_sigv4<H: AsRef<str>>(
    parsed: &ParsedAuthHeader,
    req: &InboundRequest<'_, H>,
    secret: &str,
    now: u64,
) -> Result<(), VerifyError> {
    let Some(req_epoch) = parse_amz_date(req.amzdate) else {
        return Err(VerifyError::MissingDate);
    };
    let skew = req_epoch.abs_diff(now);
    if skew > CLOCK_SKEW_SECS {
        return Err(VerifyError::Expired);
    }

    if req.amzdate.len() < 8 || parsed.datestamp != req.amzdate[0..8] {
        return Err(VerifyError::MalformedAuthorization);
    }

    let signed: Vec<&str> = parsed.signed_headers.split(';').collect();
    if !signed.iter().any(|h| h.eq_ignore_ascii_case("host")) {
        return Err(VerifyError::SignedHeadersMismatch);
    }

    let mut prev: Option<&str> = None;
    for name in &signed {
        if name.bytes().any(|b| b.is_ascii_uppercase()) || prev.is_some_and(|p| p >= *name) {
            return Err(VerifyError::SignedHeadersMismatch);
        }
        prev = Some(name);
    }

    let mut selected = Zeroizing::new(Vec::with_capacity(req.headers.len()));
    for name in &signed {
        let before = selected.len();
        for (_, value) in req
            .headers
            .iter()
            .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case(name))
        {
            selected.push(((*name).to_owned(), value.as_ref().to_owned()));
        }
        if selected.len() == before {
            return Err(VerifyError::SignedHeadersMismatch);
        }
    }

    let credential = Cred::captured(Zeroizing::new(secret.as_bytes().to_vec()));
    let request = Aws4Request {
        region: &parsed.region,
        service: &parsed.service,
        method: req.method,
        canonical_uri: req.canonical_uri,
        canonical_query: req.canonical_querystring,
        headers: &selected,
        payload_hash: req.payload_hash,
        amzdate: req.amzdate,
        datestamp: &parsed.datestamp,
    };

    let mut computed_names: Vec<String> = signed.iter().map(|name| name.to_lowercase()).collect();
    computed_names.sort();
    let computed_signed_headers = computed_names.join(";");
    let headers_ok = constant_time_eq(&computed_signed_headers, &parsed.signed_headers);
    let sig_ok = credential.aws4_verify(&request, &parsed.signature);
    if std::hint::black_box(u8::from(headers_ok) & u8::from(sig_ok)) == 1 {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Canonicalize the received query string for SigV4, the AWS rule and the outbound signer's
/// (`crate::sigv4::canonical_query`, shared): each `name=value` pair (a bare name has the empty
/// value) has its `%XX` escapes decoded once and every byte re-encoded over the unreserved set with
/// uppercase hex, the pairs sorted by encoded name then value and joined with `&`; `""` for none.
/// A client's already-canonical query is unchanged (the encoding is idempotent over the canonical
/// form), and one sent with a reserved byte raw or a lowercase escape verifies as AWS recomputes it.
pub fn canonical_query_string(query: Option<&str>) -> String {
    crate::sigv4::canonical_query(query)
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
/// Its `Debug` prints the method, the path, the field NAMES and the body's length only: the
/// `authorization` and `x-amz-security-token` values (and the query and body) carry credentials.
#[derive(Clone, Default)]
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
    /// The request's authority (`host[:port]`), as the host lends it: an HTTP/2 request carries
    /// its host here (`:authority`), never as a `host` line. Empty = none lent.
    pub authority: &'a [u8],
}

impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<std::borrow::Cow<'_, str>> = self
            .lines
            .iter()
            .map(|(n, _)| String::from_utf8_lossy(n))
            .collect();
        f.debug_struct("Request")
            .field("method", &String::from_utf8_lossy(self.method))
            .field("path", &String::from_utf8_lossy(self.path))
            .field("query", &self.query.map(|_| "<redacted>"))
            .field("lines", &names)
            .field("body_len", &self.body.map(<[u8]>::len))
            .field("now", &self.now)
            .field("authority", &String::from_utf8_lossy(self.authority))
            .finish()
    }
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

/// Whether the request's credential is this plugin's: a SigV4 `authorization` line, which `verify`
/// names for the transport to strip whatever its verdict.
pub(crate) fn carries_sigv4(req: &Request<'_>) -> bool {
    req.first(AUTHORIZATION).is_some_and(|value| {
        let value = value.trim_ascii_start();
        value
            .strip_prefix(SIGV4_ALGORITHM.as_bytes())
            .is_some_and(|rest| {
                rest.is_empty()
                    || rest
                        .first()
                        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
            })
    })
}

/// The request's inbound AWS SigV4 `Authorization` value (`AWS4-HMAC-SHA256 ...`), the kernel's
/// `has_sigv4_authorization`: the FIRST `authorization` line, read as visible ASCII, trimmed at the
/// start, opens with the algorithm token. Everything else (bearer, no Authorization) is not this
/// plugin's credential.
fn sigv4_authorization<'r>(req: &'r Request<'_>) -> Option<&'r str> {
    carries_sigv4(req)
        .then(|| req.first(AUTHORIZATION).and_then(header_str))
        .flatten()
}

/// A secret's bytes, as the check reads them: the host's answer (the contract's
/// `CredentialSecret`, wiped on drop) on the request path, a wiped buffer in the unit tests.
pub trait SecretBytes {
    /// The secret's bytes.
    fn bytes(&self) -> &[u8];
}

impl SecretBytes for Zeroizing<Vec<u8>> {
    fn bytes(&self) -> &[u8] {
        self
    }
}

impl SecretBytes for busbar_contract::abi::sdk::services::CredentialSecret {
    fn bytes(&self) -> &[u8] {
        self.secret()
    }
}

/// What the host's `records.secret` answered for one credential.
pub enum Read<S: SecretBytes = Zeroizing<Vec<u8>>> {
    /// The secret (wiped on drop), and whether the credential is live. For an id the host does not
    /// hold, an empty secret, not live.
    Secret {
        /// The secret's bytes.
        secret: S,
        /// `SECRET_LIVE`.
        live: bool,
    },
    /// The read pends: on the op's ticket (answer PENDING; the resumed call re-issues the same
    /// handle and reads the stored answer), or on none (`records.secret` may pend, so a ticket-less
    /// `verify` cannot make it: the door answers REFUSED, and the host submits the same `verify` on
    /// a ticket).
    Pending,
    /// The host serves no `records.secret`, refused or failed it, or broke its rules: fail closed.
    /// The word names the service's error (`unserved`, `refused`, `failed`, `declined`, `broken`,
    /// `short`), for the log.
    Unavailable(&'static str),
}

/// Where the check reads a credential's secret: the host's `records.secret` on the request path, a
/// fake in the unit tests. Read on EVERY check: nothing is cached between two.
pub trait SecretSource {
    /// The secret's holder.
    type Secret: SecretBytes;

    /// The secret of credential `id` of `kind`.
    fn read(&mut self, kind: &str, id: &str) -> Read<Self::Secret>;
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
    /// The secret read pends (on the op's ticket, or on none: the door answers REFUSED).
    Pending,
}

/// The longest AccessKeyId AWS issues: a logged id is capped here.
const ACCESS_KEY_ID_LOG_CAP: usize = 128;

/// The client's AccessKeyId as the log carries it: its first [`ACCESS_KEY_ID_LOG_CAP`] characters,
/// escaped (`char::escape_debug`), so a tab, a quote or a megabyte of text in the header cannot
/// forge a field or flood the log.
fn shown_id(id: &str) -> String {
    id.chars()
        .take(ACCESS_KEY_ID_LOG_CAP)
        .flat_map(char::escape_debug)
        .collect()
}

/// A REJECT, its reason logged at `info` in the plugin's own log (module `sigv4`): an end-user
/// decline. The client still gets the one opaque 401; no signature, secret or token is logged.
fn reject(reason: &'static str) -> Judgement {
    tracing::info!(module = "sigv4", reason, "sigv4 inbound request rejected");
    Judgement::Reject
}

/// Judge one request: the kernel's SigV4 pre-step and `verify_sigv4_ingress_credential`, in its
/// order, the secret read through `source`. Every REJECT names its reason in the plugin's log.
pub fn judge(req: &Request<'_>, source: &mut impl SecretSource) -> Judgement {
    if !carries_sigv4(req) {
        return Judgement::Pass;
    }
    let Some(auth_value) = sigv4_authorization(req) else {
        return reject("unparseable SigV4 authorization");
    };

    let Ok(parsed) = parse_authorization_header(auth_value) else {
        return reject("unparseable SigV4 authorization");
    };
    if !req.has(X_AMZ_CONTENT_SHA256) || !req.has(X_AMZ_DATE) {
        return reject("no x-amz-content-sha256 or x-amz-date line");
    }

    let Some(body) = req.body else {
        tracing::warn!(
            module = "sigv4",
            reason = "the host lent no body",
            "sigv4 inbound request rejected: the signed payload hash cannot be checked"
        );
        return Judgement::Reject;
    };

    // PREFILTER: only the headers named in `SignedHeaders`, names lowercased, each value read as the
    // kernel's `HeaderValue::to_str` read it (a signed name's value that is not visible ASCII rejects).
    // Borrowed from the request: every name match below is ASCII case-insensitive.
    // The client-supplied list is parsed ONCE (sorted, so each query is a binary search): scanning
    // it per request line would cost lines x names on a request that is rejected anyway.
    let mut signed_names: Vec<String> = parsed
        .signed_headers
        .split(';')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    signed_names.sort_unstable();
    signed_names.dedup();
    let signed = |name: &str| {
        signed_names
            .binary_search_by(|h| h.bytes().cmp(name.bytes().map(|b| b.to_ascii_lowercase())))
            .is_ok()
    };
    let mut headers: Vec<(&str, &str)> = Vec::new();
    for (name, value) in &req.lines {
        let Some(name) = std::str::from_utf8(name).ok().filter(|n| signed(n)) else {
            continue;
        };
        // A line of a signed name must enter the verified set: leaving one out would verify the
        // signature over fewer lines than the request carries (and such a value cannot verify).
        let Some(value) = header_str(value) else {
            return reject("a signed header value is not visible ASCII");
        };
        headers.push((name, value));
    }
    // An HTTP/2 request carries its host as `:authority`, never a `host` line: with no `host` line,
    // the signed `host` is the request's authority as the host lends it.
    if signed("host") && !req.has("host") {
        if let Some(authority) = header_str(req.authority).filter(|a| !a.is_empty()) {
            headers.push(("host", authority));
        }
    }
    let signed_value = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };

    let Some(payload_hash) = signed_value(X_AMZ_CONTENT_SHA256) else {
        return reject("x-amz-content-sha256 is not signed");
    };

    if payload_hash.eq_ignore_ascii_case(UNSIGNED_PAYLOAD) {
        return reject("unsigned payload refused");
    }

    let mut actual = [0_u8; 64];
    let mut declared = [0_u8; 64];
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    let hashed =
        hex::encode_to_slice(digest, &mut actual).is_ok() && payload_hash.len() == declared.len();
    if hashed {
        declared.copy_from_slice(payload_hash.as_bytes());
        declared.make_ascii_lowercase();
    }
    if !(hashed && constant_time_eq(&actual, &declared)) {
        return reject("payload hash mismatch");
    }
    let Some(amzdate) = signed_value(X_AMZ_DATE) else {
        return reject("x-amz-date is not signed");
    };

    let (Ok(method), Ok(path)) = (
        std::str::from_utf8(req.method),
        std::str::from_utf8(req.path),
    ) else {
        return reject("the method or path is not UTF-8");
    };
    let query = match req.query.map(std::str::from_utf8) {
        None => None,
        Some(Ok(q)) => Some(q),
        Some(Err(_)) => return reject("the query is not UTF-8"),
    };

    let path = if path.is_empty() { "/" } else { path };

    let canonical_uri = canonical_uri(path, &parsed.service);
    let canonical_qs = Zeroizing::new(canonical_query_string(query));
    let inbound = InboundRequest {
        method,
        canonical_uri: &canonical_uri,
        canonical_querystring: &canonical_qs,
        headers: &headers,
        payload_hash,
        amzdate,
    };

    // THE SECRET, from the host. An UNKNOWN AccessKeyId does NOT short-circuit: the host answers an
    // empty secret (not live) in equal time, and the full constant-time verification runs over the
    // plugin's own dummy for it (`verification_text`).
    let (secret, live) = match source.read(CREDENTIAL_KIND, &parsed.access_key_id) {
        Read::Secret { secret, live } => (secret, live),
        Read::Pending => return Judgement::Pending,
        Read::Unavailable(service_error) => {
            tracing::warn!(
                module = "sigv4",
                reason = "credential-unavailable",
                service_error,
                access_key_id = %shown_id(&parsed.access_key_id),
                "sigv4 inbound request rejected: the host's records.secret did not answer"
            );
            return Judgement::Reject;
        }
    };
    let (text, utf8) = verification_text(secret.bytes(), live);
    let checked = verify_inbound_sigv4(&parsed, &inbound, text, req.now);
    let verified = checked.is_ok();

    if std::hint::black_box(u8::from(verified) & u8::from(live) & u8::from(utf8)) == 1 {
        Judgement::Identity(parsed.access_key_id)
    } else if !utf8 {
        tracing::warn!(
            module = "sigv4",
            reason = "secret-not-utf8",
            access_key_id = %shown_id(&parsed.access_key_id),
            "sigv4 inbound request rejected: the stored secret is not UTF-8"
        );
        Judgement::Reject
    } else {
        let reason = match checked {
            Err(e) => e.word(),
            Ok(()) => VerifyError::SignatureMismatch.word(),
        };
        tracing::info!(
            module = "sigv4",
            reason,
            access_key_id = %shown_id(&parsed.access_key_id),
            "sigv4 inbound request rejected"
        );
        Judgement::Reject
    }
}

#[cfg(test)]
#[path = "tests/inbound_tests.rs"]
mod tests;
