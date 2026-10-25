// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `sigv4` STYLE: per-request AWS Signature Version 4 over the request, the credential being
//! `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]`. MOVED VERBATIM from the `Scheme::SigV4` arm of
//! the identity unit's `egress_auth/mod.rs::decorate` in the kernel and the `EgressScheme::SigV4` arm of
//! `.../declared.rs::present`, staged `busbar-auth-outbound::signing` (KERNEL<>PLUGINS step 22),
//! then here (AUTH-SPLIT): the same checks before signing, the same SET-never-append over the
//! signed set, the same `Authorization` value and the same field order.
//!
//! THE DAILY KEY (BUSBAR-1.6.0.md THE DESIGN, §6.5). The HMAC chain over date, region and service is derived once per
//! UTC day and held here, wiped on drop; `tick` derives the next day's key ahead of midnight
//! ([`SigV4Binding::prederive`]), so a request signs with a key already in hand. A binding built for
//! the CALLER's credential (`STYLE_CALLER_CREDENTIAL` passthrough mode, ARCHITECT ruling
//! 2026-09-29) is instead constructed fresh per request in `crate::instance::SigV4::sign` and never enters this
//! cache — the caller's key varies request to request, so there is nothing to hold ahead of time.
//!
//! THE REQUEST IT SIGNS (BUSBAR-1.6.0.md THE DESIGN §6, "the per-request auth call on the route
//! walk": "SigV4 signs the real method and query of the walked request"): the method, the query
//! and the content type are the walked request's own, as the host lends them; the canonical URI is
//! the wire path URI-encoded once more (SigV4's non-S3 rule, 1.5.5's `sign_and_wire_path_parts`,
//! `proxy/egress.rs`, v1.5.5). For the request 1.5.5 signed — a POST of a JSON body to its path,
//! no query — every signed byte is 1.5.5's.

use std::sync::RwLock;

use busbar_contract::header::is_legal_header_value;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::held::Held;
use crate::sigv4;

/// The seconds in a day.
const DAY_SECS: u64 = 86_400;
/// How long before UTC midnight `tick` derives the next day's key.
const PREDERIVE_AHEAD_SECS: u64 = 3_600;

/// A `sigv4` binding's settings: the service and region the signature is scoped to. The kernel
/// resolves them at seal (the region from the provider's host through the plane's declared
/// function). The content type the signature covers is the one the
/// request is sent with ([`SignFacts::content_type`]), never a setting.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SigV4Params {
    /// The AWS service name.
    pub service: String,
    /// The AWS region.
    pub region: String,
}

/// The request facts a signature covers: the walked request's own.
#[derive(Debug, Clone, Copy)]
pub struct SignFacts<'a> {
    /// The method.
    pub method: &'a str,
    /// The host the request is sent to (the `host` field the signature covers).
    pub host: &'a str,
    /// The path exactly as it is sent (already percent-encoded once); the canonical URI is it
    /// encoded once more.
    pub path: &'a str,
    /// The query as it is sent, without `?`; `None` = none.
    pub query: Option<&'a str>,
    /// The `content-type` the request is sent with; `None` = none is sent, and none is signed.
    pub content_type: Option<&'a str>,
    /// Lowercase hex SHA-256 of the body.
    pub payload_hash: &'a str,
    /// Seconds since the epoch (1970-01-01 UTC).
    pub timestamp_epoch: u64,
}

/// The credential is not `ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]` (no `:` at all).
pub(crate) const CREDENTIAL_SHAPE: &str =
    "expected ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]";
/// The access key id is empty.
pub(crate) const ACCESS_KEY_ID_EMPTY: &str = "the access key id is empty";
/// The access key id cannot ride in the `Authorization` value.
pub(crate) const ACCESS_KEY_ID_UNSENDABLE: &str =
    "the access key id holds a byte no header value may carry";
/// The secret access key is empty.
pub(crate) const SECRET_EMPTY: &str = "the secret access key is empty";
/// A session token is present but empty.
pub(crate) const SESSION_TOKEN_EMPTY: &str = "the session token is empty";
/// The session token cannot ride in `x-amz-security-token`.
pub(crate) const SESSION_TOKEN_UNSENDABLE: &str =
    "the session token holds a byte no header value may carry";

/// What `fields` answers in own mode on a binding opened with no credential of its own.
pub(crate) const NO_OWN_CREDENTIAL: &str = "sigv4: this binding holds no credential of its own \
     (passthrough-only); the request is not sent unsigned";
/// What `fields` answers when the signed `Authorization` value is no legal header value: the one
/// input the credential checks do not cover is the service and region the scope names.
const AUTHORIZATION_UNSENDABLE: &str = "sigv4: the signed Authorization value holds a byte no \
     header value may carry (check the service and region settings); the request is not sent \
     unsigned";

/// One field the signer sets: its name and its value, the value wiped on drop (a session token
/// rides in one).
pub type Field = (String, Zeroizing<String>);

/// A credential split for signing: the secret and the session token are each held redacted
/// (`Held`) and wiped on drop ([`Zeroizing`]).
pub struct SigningCredential {
    access_key_id: String,
    secret: Held<Zeroizing<String>>,
    session_token: Option<Held<Zeroizing<String>>>,
}

impl std::fmt::Debug for SigningCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningCredential")
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl SigningCredential {
    /// Parse `raw`, `ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]`, into a credential that can
    /// sign (OWNER RULING: a credential that cannot is refused, never bound to sign nothing).
    ///
    /// # Errors
    ///
    /// Every finding, in order ([`CREDENTIAL_SHAPE`] alone when there is no `:` at all), each
    /// naming what is wrong and never the credential's bytes.
    pub fn parse(raw: &str) -> Result<Self, Vec<&'static str>> {
        let mut parts = raw.splitn(3, ':');
        let (Some(access), Some(secret), token) = (parts.next(), parts.next(), parts.next()) else {
            return Err(vec![CREDENTIAL_SHAPE]);
        };
        let mut findings = Vec::new();
        if access.is_empty() {
            findings.push(ACCESS_KEY_ID_EMPTY);
        } else if !is_legal_header_value(access) {
            // The access key id rides verbatim in the `Authorization` value.
            findings.push(ACCESS_KEY_ID_UNSENDABLE);
        }
        if secret.is_empty() {
            findings.push(SECRET_EMPTY);
        }
        match token {
            Some("") => findings.push(SESSION_TOKEN_EMPTY),
            // Signing over a token the wire cannot carry is a guaranteed mismatch.
            Some(t) if !is_legal_header_value(t) => findings.push(SESSION_TOKEN_UNSENDABLE),
            _ => {}
        }
        if !findings.is_empty() {
            return Err(findings);
        }
        // The split the signer always took: every finding it folds into `None` is checked above.
        let Some((access, secret, token)) = sigv4::split_credential(raw) else {
            return Err(vec![CREDENTIAL_SHAPE]);
        };
        Ok(Self {
            access_key_id: access.to_string(),
            secret: Held::new(Zeroizing::new(secret.to_string())),
            session_token: token.map(|t| Held::new(Zeroizing::new(t.to_string()))),
        })
    }
}

/// Set (or replace) one header in an envelope vector, case-insensitively — the envelope is a small
/// `Vec`, not a map, because the wire request preserves the order fields were set in.
fn set_header(envelope: &mut Vec<(String, String)>, name: &str, value: String) {
    if let Some(existing) = envelope
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        existing.1 = value;
    } else {
        envelope.push((name.to_string(), value));
    }
}

/// One day's derived key.
struct DayKey {
    datestamp: String,
    key: Zeroizing<Vec<u8>>,
}

/// A `sigv4` binding: the params, the credential, and the day keys derived for it.
pub struct SigV4Binding {
    params: SigV4Params,
    credential: Option<SigningCredential>,
    /// Today's key and, ahead of midnight, tomorrow's.
    keys: RwLock<Vec<DayKey>>,
}

impl std::fmt::Debug for SigV4Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigV4Binding")
            .field("params", &self.params)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl SigV4Binding {
    /// A binding of `params` to `credential` (`None`: a passthrough-only binding, which signs only
    /// with a caller's credential).
    pub fn new(params: SigV4Params, credential: Option<SigningCredential>) -> Self {
        Self {
            params,
            credential,
            keys: RwLock::new(Vec::new()),
        }
    }

    /// The params this binding signs under — read back to build a fresh per-request binding for
    /// the caller's credential in passthrough mode (`crate::instance::SigV4::sign`).
    pub fn params(&self) -> &SigV4Params {
        &self.params
    }

    /// Derive (and keep) the key for `datestamp` unless held; at most two days are kept.
    fn derive(&self, datestamp: &str) {
        let Some(cred) = &self.credential else {
            return;
        };
        let held = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|k| k.datestamp == datestamp);
        if held {
            return;
        }
        let key = sigv4::signing_key(
            cred.secret.reveal(),
            datestamp,
            &self.params.region,
            &self.params.service,
        );
        let mut keys = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if keys.iter().any(|k| k.datestamp == datestamp) {
            return;
        }
        keys.push(DayKey {
            datestamp: datestamp.to_string(),
            key,
        });
        keys.sort_by(|a, b| a.datestamp.cmp(&b.datestamp));
        while keys.len() > 2 {
            keys.remove(0);
        }
    }

    /// The datestamps whose keys are held, oldest first.
    #[cfg(test)]
    pub fn held(&self) -> Vec<String> {
        self.keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|k| k.datestamp.clone())
            .collect()
    }

    /// `tick`: hold today's key, and tomorrow's once within [`PREDERIVE_AHEAD_SECS`] of midnight.
    pub fn prederive(&self, now_epoch: u64) {
        let (_, today) = sigv4::format_amz_time(now_epoch);
        self.derive(&today);
        if DAY_SECS - now_epoch % DAY_SECS <= PREDERIVE_AHEAD_SECS {
            let (_, tomorrow) = sigv4::format_amz_time(now_epoch + DAY_SECS);
            self.derive(&tomorrow);
        }
    }

    /// Sign one request: the fields to set, in order. Every per-request copy of the session token
    /// is wiped on drop. The credential was checked when it was parsed
    /// ([`SigningCredential::parse`]): an empty part or a token the wire cannot carry never gets
    /// here.
    ///
    /// # Errors
    ///
    /// The reason nothing is signed — the binding holds no credential of its own, or the
    /// `Authorization` value would be no legal header value — so the request is FAILED, never sent
    /// unsigned.
    pub fn sign(&self, facts: &SignFacts<'_>) -> Result<Vec<Field>, &'static str> {
        let Some(cred) = &self.credential else {
            return Err(NO_OWN_CREDENTIAL);
        };
        let region = self.params.region.as_str();
        let service = self.params.service.as_str();
        let (amzdate, datestamp) = sigv4::format_amz_time(facts.timestamp_epoch);
        let payload_hash = facts.payload_hash.to_string();
        // The set 1.5.5's signing writer signed (`proto/bedrock/writer.rs`, v1.5.5): the content
        // type the request is sent with (none sent, none signed) and the host, then SET, never
        // appended, the fields it writes.
        let mut headers: Vec<(String, String)> = Vec::with_capacity(5);
        if let Some(content_type) = facts.content_type {
            headers.push(("content-type".to_string(), content_type.to_string()));
        }
        headers.push(("host".to_string(), facts.host.to_string()));
        set_header(&mut headers, "x-amz-date", amzdate.clone());
        set_header(&mut headers, "x-amz-content-sha256", payload_hash.clone());
        if let Some(t) = &cred.session_token {
            set_header(
                &mut headers,
                "x-amz-security-token",
                t.reveal().as_str().to_owned(),
            );
        }
        let canonical_uri = sigv4::uri_encode_path(facts.path);
        let canonical_query = sigv4::canonical_query(facts.query);
        self.derive(&datestamp);
        let sign_with = |key: &[u8]| {
            sigv4::sign_v4_with_key(
                key,
                region,
                service,
                facts.method,
                &canonical_uri,
                &canonical_query,
                &headers,
                &payload_hash,
                &amzdate,
                &datestamp,
            )
        };
        let held = {
            let keys = self
                .keys
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            keys.iter()
                .find(|k| k.datestamp == datestamp)
                .map(|k| sign_with(&k.key))
        };
        // A date older than both held keys (a skewed request clock) is derived for this request
        // alone rather than evicting a day key.
        let (signature, signed_headers) = held.unwrap_or_else(|| {
            sign_with(&sigv4::signing_key(
                cred.secret.reveal(),
                &datestamp,
                region,
                service,
            ))
        });
        sigv4::wipe(&mut headers);
        let credential_scope = format!(
            "{datestamp}/{region}/{service}/{}",
            sigv4::SIGNATURE_TERMINATION
        );
        let authorization = format!(
            "{} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            sigv4::SIGV4_ALGORITHM,
            cred.access_key_id,
        );
        // The access key id was checked at parse; the service and region (settings) ride in this
        // value verbatim too, and the date and the hash are always legal.
        if !is_legal_header_value(&authorization) {
            return Err(AUTHORIZATION_UNSENDABLE);
        }
        let mut fields: Vec<Field> = vec![
            ("authorization".to_string(), Zeroizing::new(authorization)),
            ("x-amz-date".to_string(), Zeroizing::new(amzdate)),
            (
                "x-amz-content-sha256".to_string(),
                Zeroizing::new(payload_hash),
            ),
        ];
        if let Some(t) = &cred.session_token {
            fields.push(("x-amz-security-token".to_string(), t.reveal().clone()));
        }
        Ok(fields)
    }
}

#[cfg(test)]
#[path = "tests/signing_tests.rs"]
mod tests;
