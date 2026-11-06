// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `sigv4` style: per-request AWS Signature Version 4 over the request, the credential being
//! `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]`. The checks run before signing, the signed set is SET
//! never appended, and the `Authorization` value and field order are fixed.
//!
//! The daily key: the HMAC chain over date, region and service is derived once per
//! UTC day and held here, wiped on drop; `tick` derives the next day's key ahead of midnight
//! ([`SigV4Binding::prederive`]), so a request signs with a key already in hand. A binding built for
//! the CALLER's credential (`STYLE_CALLER_CREDENTIAL` passthrough mode) is instead constructed fresh per request in
//! `crate::instance::SigV4::sign` and never enters this cache — the caller's key varies request to
//! request, so there is nothing to hold ahead of time.
//!
//! The request it signs: the method, the query and the content type are the walked request's own,
//! as the host lends them; the canonical URI is [`sigv4::canonical_uri`]'s for the configured
//! service (the wire path encoded once more, or for an S3 signing name encoded once).

use std::sync::RwLock;

use busbar_contract::abi::sdk::chip::aws4::Aws4Request;
use busbar_contract::abi::sdk::cred::{Cred, Parts};
use busbar_contract::header::is_legal_header_value;
use zeroize::Zeroizing;

use crate::inbound::{X_AMZ_CONTENT_SHA256, X_AMZ_DATE, X_AMZ_SECURITY_TOKEN};
use crate::sigv4;
use crate::sigv4::SECS_PER_DAY;

/// How long before UTC midnight `tick` derives the next day's key.
const PREDERIVE_AHEAD_SECS: u64 = 3_600;

/// A `sigv4` binding's settings: the service and region the signature is scoped to. The kernel
/// resolves them at seal (the region from the provider's host through the plane's declared
/// function). The content type the signature covers is the one the
/// request is sent with ([`SignFacts::content_type`]), never a setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Params {
    /// The AWS service name.
    pub service: String,
    /// The AWS region.
    pub region: String,
    /// The warning to log with each signature, set when the kernel resolved [`Self::region`] at seal
    /// to the dialect's default because the provider's host names none (its `region_unread`): the
    /// dialect's own words. `None`: the host
    /// named the region, and nothing is logged.
    pub region_unread: Option<String>,
}

/// The request facts a signature covers: the walked request's own. No `Debug`: `amz_headers` can carry
/// a forwarded `x-amz-security-token` value.
#[derive(Clone, Copy)]
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
    /// The first `content-type` the request is sent with; `None` = none is sent.
    pub content_type: Option<&'a str>,
    /// Every `x-amz-*` line the request is sent with (name, value), in order: each is signed
    /// (AWS signs every `x-amz-*` header sent), but for the date, the payload hash and (when the
    /// credential carries one) the session token, which the signer SETS over any sent. Also
    /// carries any additional `content-type` values, in their original order.
    pub amz_headers: &'a [(&'a str, &'a str)],
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
pub type Field = (String, FieldValue);

/// Public request metadata or opaque credential-derived field pieces.
pub enum FieldValue {
    /// A public date or payload hash.
    Public(String),
    /// An authorization value or session token, kept sealed until the SDK writes it.
    Sealed(Parts),
}

impl std::fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A credential split for signing: the secret and the session token are each held redacted
/// by the shared SDK and wiped on drop.
pub struct SigningCredential {
    access_key_id: String,
    secret: Cred,
    session_token: Option<Cred>,
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
    /// sign (a credential that cannot is refused, never bound to sign nothing).
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
            findings.push(ACCESS_KEY_ID_UNSENDABLE);
        }
        if secret.is_empty() {
            findings.push(SECRET_EMPTY);
        }
        match token {
            Some("") => findings.push(SESSION_TOKEN_EMPTY),

            Some(t) if !is_legal_header_value(t) => findings.push(SESSION_TOKEN_UNSENDABLE),
            _ => {}
        }
        if !findings.is_empty() {
            return Err(findings);
        }
        Ok(Self {
            access_key_id: access.to_string(),
            secret: Cred::captured(Zeroizing::new(secret.as_bytes().to_vec())),
            session_token: token.map(|t| Cred::captured(Zeroizing::new(t.as_bytes().to_vec()))),
        })
    }
}

/// One day's derived key.
struct DayKey {
    datestamp: String,
    key: Cred,
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
        let key = cred
            .secret
            .aws4_day_key(datestamp, &self.params.region, &self.params.service);
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

    /// `tick`: hold today's key, and tomorrow's once within [`PREDERIVE_AHEAD_SECS`] of midnight.
    pub fn prederive(&self, now_epoch: u64) {
        let (_, today) = sigv4::format_amz_time(now_epoch);
        self.derive(&today);
        if SECS_PER_DAY - now_epoch % SECS_PER_DAY <= PREDERIVE_AHEAD_SECS {
            let (_, tomorrow) = sigv4::format_amz_time(now_epoch + SECS_PER_DAY);
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
        if let Some(unread) = &self.params.region_unread {
            // Warn on every signature scoped to the default region (after the credential split,
            // before signing), naming the host the request goes to. The line goes to this plugin's
            // own log, and the host copies a WARN line to busbar's.
            tracing::warn!(module = "sigv4", host = %facts.host, "{unread}");
        }
        let region = self.params.region.as_str();
        let service = self.params.service.as_str();
        let (amzdate, datestamp) = sigv4::format_amz_time(facts.timestamp_epoch);
        let payload_hash = facts.payload_hash.to_string();

        let mut headers = Zeroizing::new(Vec::with_capacity(5 + facts.amz_headers.len()));
        if let Some(content_type) = facts.content_type {
            headers.push(("content-type".to_string(), content_type.to_string()));
        }
        headers.push(("host".to_string(), facts.host.to_string()));
        for (name, value) in facts.amz_headers {
            let set_here = name.eq_ignore_ascii_case(X_AMZ_DATE)
                || name.eq_ignore_ascii_case(X_AMZ_CONTENT_SHA256)
                || (cred.session_token.is_some()
                    && name.eq_ignore_ascii_case(X_AMZ_SECURITY_TOKEN));
            if !set_here {
                headers.push(((*name).to_string(), (*value).to_string()));
            }
        }
        // The sent date and payload hash lines were left out above: the signer's own are signed.
        headers.push((X_AMZ_DATE.to_string(), amzdate.clone()));
        headers.push((X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()));
        let canonical_uri = sigv4::canonical_uri(facts.path, service);
        let canonical_query = Zeroizing::new(sigv4::canonical_query(facts.query));
        self.derive(&datestamp);
        let sign_with = |key: &Cred| {
            key.aws4_sign(
                &Aws4Request {
                    region,
                    service,
                    method: facts.method,
                    canonical_uri: &canonical_uri,
                    canonical_query: &canonical_query,
                    headers: &headers,
                    payload_hash: &payload_hash,
                    amzdate: &amzdate,
                    datestamp: &datestamp,
                },
                cred.session_token.as_ref(),
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

        let signed = held
            .unwrap_or_else(|| sign_with(&cred.secret.aws4_day_key(&datestamp, region, service)))
            .map_err(|_| SESSION_TOKEN_UNSENDABLE)?;
        let signed_headers = signed.signed_headers;
        let credential_scope = format!(
            "{datestamp}/{region}/{service}/{}",
            sigv4::SIGNATURE_TERMINATION
        );
        let authorization = format!(
            "{} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature=",
            sigv4::SIGV4_ALGORITHM,
            cred.access_key_id,
        );

        if !is_legal_header_value(&authorization) {
            return Err(AUTHORIZATION_UNSENDABLE);
        }
        let mut fields: Vec<Field> = vec![
            (
                "authorization".to_string(),
                FieldValue::Sealed(
                    Parts::new()
                        .public(authorization.as_bytes())
                        .sealed(signed.signature),
                ),
            ),
            (X_AMZ_DATE.to_string(), FieldValue::Public(amzdate)),
            (
                X_AMZ_CONTENT_SHA256.to_string(),
                FieldValue::Public(payload_hash),
            ),
        ];
        if let Some(t) = &cred.session_token {
            fields.push((
                X_AMZ_SECURITY_TOKEN.to_string(),
                FieldValue::Sealed(Parts::new().sealed(t.field())),
            ));
        }
        Ok(fields)
    }
}

#[cfg(test)]
#[path = "tests/signing_tests.rs"]
mod tests;
