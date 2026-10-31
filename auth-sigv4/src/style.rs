// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body for `sigv4`: bind the style to its credential and settings
//! ([`open_binding`]). Never touches the network. The per-request presentation, both credential
//! modes, is [`crate::signing::SigV4Binding::sign`] through the door kit's `fields`
//! (`crate::instance::SigV4::sign`).
//!
//! The settings schema: `{service, region}`, each trimmed and 1 to 64 of `[a-z0-9-]` (refused at
//! open otherwise, `settings.<key>: <reason>`). A `content_type` key is
//! read past (older configs carry it): the content type a signature covers is the one the request
//! is sent with (the style declares `STYLE_NEEDS_HEADERS` and signs the sent value), never a
//! setting. `region_unread` is the kernel's warning for a region it defaulted at seal, logged with
//! each signature. The keys core forwards from its shared provider schema (`token_url`,
//! `token_uri`, `scope`, `subject`) are ignored with one WARN each at the bind. Any other key is
//! refused by name (``settings: unknown key `<k>` ``), never ignored.
//!
//! The credential: `ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]`, checked here,
//! at open (`SigningCredential::parse`): one that is not UTF-8, has no `:`, has an empty access
//! key id or secret, an access key id or session token no header value may carry, or an empty
//! session token, is refused — never bound to sign nothing. No credential at all opens: the
//! contract defines that as a passthrough-only binding, which signs only with a caller's
//! credential (own-mode `fields` on it FAILS, never sends the request unsigned).
//!
//! The refusals: a binding that cannot open answers FAILED with one
//! line per finding, each `credential: <text>` or `settings: <text>`. The kernel composes the
//! sentence — `provider '<p>' <style> credential (from <src>) is invalid: <text>`, or
//! `provider '<p>' <text>`. No line ever carries the credential's bytes.

use busbar_contract::abi::sdk::auth_kit::json_error;
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
    /// One setting is: `settings.<key>: <reason>`, the contract's instance-relative form (S2).
    Setting {
        /// The setting's key.
        key: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
}

impl Refusal {
    /// The line `open_outbound` answers.
    pub fn line(&self) -> String {
        match self {
            Refusal::Credential(t) => format!("credential: {t}"),
            Refusal::Settings(t) => format!("settings: {t}"),
            Refusal::Setting { key, reason } => format!("settings.{key}: {reason}"),
        }
    }
}

/// Why a `service` setting is refused.
const SERVICE_SHAPE: &str = "not an AWS service name (1 to 64 of a-z, 0-9 and -)";
/// Why a `region` setting is refused.
const REGION_SHAPE: &str = "not an AWS region (1 to 64 of a-z, 0-9 and -)";

/// Whether `s` (already trimmed) has the shape of an AWS service name or region: 1 to 64 of
/// `[a-z0-9-]`. Both ride verbatim in the credential scope the signature and the `Authorization`
/// value carry.
fn scope_shaped(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The scope settings, `service` and `region`, wherever they are present in `m`: each a string,
/// trimmed, of [`scope_shaped`]'s shape. One refusal per setting that is not (a non-string one
/// keeps its `expected a string` refusal). The plugin-level settings (`validate`, `open`, `refresh`) and the
/// bind check them alike.
pub(crate) fn scope_findings(m: &Map<String, Value>) -> Vec<Refusal> {
    let mut findings = Vec::new();
    for (key, shape) in [("service", SERVICE_SHAPE), ("region", REGION_SHAPE)] {
        match text(m, key) {
            Err(r) => findings.push(r),
            Ok(Some(v)) if !scope_shaped(v.trim()) => findings.push(Refusal::Setting {
                key,
                reason: shape,
            }),
            Ok(_) => {}
        }
    }
    findings
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
        Err(e) => Err(Refusal::Settings(json_error(
            "outbound auth settings are not JSON",
        )(e))),
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

/// The style settings this plugin reads, and `content_type`, read past (older configs carry it).
/// `region_unread` is the kernel's: the warning it hands in when it resolved `region` at seal to the
/// dialect's default (see [`SigV4Params::region_unread`]).
const KNOWN_KEYS: [&str; 4] = ["service", "region", "region_unread", "content_type"];

/// The keys core forwards from its shared provider/style schema (its `StyleParams`) to every
/// style's instance open and bind. They mean nothing to sigv4 and are ignored, never refused
/// (lead ruling 2026-10-30): a 1.5.5 config carrying one on a sigv4 provider booted.
const FORWARDED_KEYS: [&str; 4] = ["token_url", "token_uri", "scope", "subject"];

/// One refusal per key the style settings name that this plugin does not read and core does not
/// forward from its shared schema.
pub(crate) fn unknown_keys(m: &Map<String, Value>) -> Vec<Refusal> {
    m.keys()
        .filter(|k| !KNOWN_KEYS.contains(&k.as_str()) && !FORWARDED_KEYS.contains(&k.as_str()))
        .map(|k| Refusal::Settings(format!("unknown key `{k}`")))
        .collect()
}

/// One WARN per forwarded key the bind ignores.
fn warn_ignored(m: &Map<String, Value>) {
    for key in m.keys().filter(|k| FORWARDED_KEYS.contains(&k.as_str())) {
        tracing::warn!(
            module = "sigv4",
            "settings.{key}: not used by the sigv4 style; ignored"
        );
    }
}

fn sigv4_params(m: &Map<String, Value>) -> Result<SigV4Params, Vec<Refusal>> {
    let missing = |k: &str| Refusal::Settings(format!("uses auth: sigv4 but has no `{k}`"));
    let one = |r: Refusal| vec![r];
    let service = text(m, "service").map_err(one)?;
    let region = text(m, "region").map_err(one)?;
    let service = service.ok_or_else(|| one(missing("service")))?;
    let region = region.ok_or_else(|| one(missing("region")))?;
    let shaped = scope_findings(m);
    if !shaped.is_empty() {
        return Err(shaped);
    }
    Ok(SigV4Params {
        service: service.trim().to_string(),
        region: region.trim().to_string(),
        region_unread: text(m, "region_unread").map_err(one)?,
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
    let bound = bind(style, credential, settings);
    if let Err(refusals) = &bound {
        let reason = refusals
            .iter()
            .map(Refusal::line)
            .collect::<Vec<_>>()
            .join("; ");
        tracing::info!(
            module = "sigv4",
            reason = reason.as_str(),
            "sigv4 outbound binding refused"
        );
    }
    bound
}

/// [`open_binding`]'s findings, unlogged.
fn bind(
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
    warn_ignored(&m);
    let params = sigv4_params(&m)?;
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
