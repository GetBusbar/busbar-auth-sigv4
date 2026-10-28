// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body for `sigv4`: bind the style to its credential and settings
//! ([`open_binding`]). Never touches the network. The per-request presentation, both credential
//! modes, is [`crate::signing::SigV4Binding::sign`] through the door kit's `fields`
//! (`crate::instance::SigV4::sign`).
//!
//! THE SETTINGS SCHEMA (ARCHITECT ruling 2026-09-28): `{service, region}`. A `content_type` key is
//! read past (1.5.5 configs carry it): the content type a signature covers is the one the request
//! is sent with (the style declares `STYLE_NEEDS_HEADERS` and signs the sent value), never a
//! setting. `region_unread` is the kernel's warning for a region it defaulted at seal, logged with
//! each signature as 1.5.5's signer logged it. Any other key is refused by name
//! (``settings: unknown key `<k>` ``), never ignored.
//!
//! THE CREDENTIAL (OWNER RULING): `ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]`, checked here,
//! at open (`SigningCredential::parse`): one that is not UTF-8, has no `:`, has an empty access
//! key id or secret, an access key id or session token no header value may carry, or an empty
//! session token, is refused — never bound to sign nothing. No credential at all opens: the
//! contract defines that as a passthrough-only binding, which signs only with a caller's
//! credential (own-mode `fields` on it FAILS, never sends the request unsigned).
//!
//! THE REFUSALS (ARCHITECT ruling 2026-09-28): a binding that cannot open answers FAILED with one
//! line per finding, each `credential: <text>` or `settings: <text>`. The kernel composes the 1.5.5
//! sentence — `provider '<p>' <style> credential (from <src>) is invalid: <text>`, or
//! `provider '<p>' <text>`. No line ever carries the credential's bytes.

use serde_json::{Map, Value};

use crate::signing::{SigV4Binding, SigV4Params, SigningCredential};

/// AWS Signature Version 4.
pub const SIGV4: &str = "sigv4";

/// One finding that refuses a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The credential is invalid: the kernel wraps it in `<style> credential (from <src>) is
    /// invalid:`.
    Credential(String),
    /// The settings are: the kernel prefixes `provider '<p>' `.
    Settings(String),
}

impl Refusal {
    /// The line `open_outbound` answers.
    pub fn line(&self) -> String {
        match self {
            Refusal::Credential(t) => format!("credential: {t}"),
            Refusal::Settings(t) => format!("settings: {t}"),
        }
    }
}

/// The settings object (`{}` when absent).
fn object(settings: Option<&[u8]>) -> Result<Map<String, Value>, Refusal> {
    let Some(bytes) = settings.filter(|b| !b.is_empty()) else {
        return Ok(Map::new());
    };
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(Refusal::Settings(
            "outbound auth settings must be a JSON object".to_string(),
        )),
        Err(e) => Err(Refusal::Settings(format!(
            "outbound auth settings are not JSON: {e}"
        ))),
    }
}

/// A non-blank string setting.
fn text(m: &Map<String, Value>, key: &str) -> Result<Option<String>, Refusal> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.clone())),
        Some(Value::String(_)) => Ok(None),
        Some(_) => Err(Refusal::Settings(format!(
            "outbound auth setting `{key}` is invalid: expected a string"
        ))),
    }
}

/// The style settings this plugin reads, and `content_type`, read past (1.5.5 configs carry it).
/// `region_unread` is the kernel's: the warning it hands in when it resolved `region` at seal to the
/// dialect's default (see [`SigV4Params::region_unread`]).
const KNOWN_KEYS: [&str; 4] = ["service", "region", "region_unread", "content_type"];

/// One refusal per key the style settings name that this plugin does not read.
fn unknown_keys(m: &Map<String, Value>) -> Vec<Refusal> {
    m.keys()
        .filter(|k| !KNOWN_KEYS.contains(&k.as_str()))
        .map(|k| Refusal::Settings(format!("unknown key `{k}`")))
        .collect()
}

fn sigv4_params(m: &Map<String, Value>) -> Result<SigV4Params, Refusal> {
    let missing = |k: &str| Refusal::Settings(format!("uses auth: sigv4 but has no `{k}`"));
    Ok(SigV4Params {
        service: text(m, "service")?.ok_or_else(|| missing("service"))?,
        region: text(m, "region")?.ok_or_else(|| missing("region"))?,
        region_unread: text(m, "region_unread")?,
    })
}

/// Bind `style` (`sigv4`) to `credential` under `settings` — `open_outbound`'s body.
///
/// # Errors
///
/// Every finding that refuses the binding: the settings first (an unknown key, then a missing or
/// invalid param), then each finding of the credential.
pub fn open_binding(
    style: &str,
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
) -> Result<SigV4Binding, Vec<Refusal>> {
    if style != SIGV4 {
        return Err(vec![Refusal::Settings(format!(
            "outbound auth style `{style}` is not served by this plugin"
        ))]);
    }
    let m = object(settings).map_err(|r| vec![r])?;
    let unknown = unknown_keys(&m);
    if !unknown.is_empty() {
        return Err(unknown);
    }
    let params = sigv4_params(&m).map_err(|r| vec![r])?;
    let Some(credential) = credential else {
        // A passthrough-only binding (the contract's `None`): it signs only a caller's credential.
        return Ok(SigV4Binding::new(params, None));
    };
    let Ok(text) = std::str::from_utf8(credential) else {
        return Err(vec![Refusal::Credential(
            "the credential is not UTF-8".to_string(),
        )]);
    };
    let cred = SigningCredential::parse(text).map_err(|findings| {
        findings
            .into_iter()
            .map(|f| Refusal::Credential(f.to_string()))
            .collect::<Vec<_>>()
    })?;
    Ok(SigV4Binding::new(params, Some(cred)))
}

#[cfg(test)]
#[path = "tests/style_tests.rs"]
mod tests;
