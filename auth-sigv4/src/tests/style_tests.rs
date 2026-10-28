// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body: `sigv4` binds from its settings, and every refusal is 1.5.5's own words
//! in the `credential:` / `settings:` lines the kernel composes (ARCHITECT ruling Q5).

use super::*;
use crate::signing::SignFacts;
use crate::sigv4;

fn open(
    style: &str,
    credential: Option<&str>,
    settings: &str,
) -> Result<SigV4Binding, Vec<Refusal>> {
    open_binding(
        style,
        credential.map(str::as_bytes),
        Some(settings.as_bytes()),
    )
}

fn lines(r: Result<SigV4Binding, Vec<Refusal>>) -> Vec<String> {
    r.expect_err("the binding is refused")
        .iter()
        .map(Refusal::line)
        .collect()
}

/// The two params are needed; the content type is no param (the signature covers the one sent),
/// and a `content_type` key is read past.
#[test]
fn sigv4_needs_its_two_params_and_notes_an_unsendable_token() {
    assert_eq!(
        lines(open(SIGV4, Some("A:S"), r#"{"region":"us-east-1"}"#)),
        ["settings: uses auth: sigv4 but has no `service`"]
    );
    assert_eq!(
        lines(open(SIGV4, Some("A:S"), r#"{"service":"svc"}"#)),
        ["settings: uses auth: sigv4 but has no `region`"]
    );
    assert!(open(
        SIGV4,
        Some("A:S"),
        r#"{"service":"svc","region":"us-east-1"}"#
    )
    .is_ok());
    let r = open(
        SIGV4,
        Some("A:S:T\r\nX"),
        r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#,
    );
    assert!(r
        .expect("an unsendable token opens")
        .session_token_unsendable());
}

#[test]
fn a_keyless_binding_opens_but_signs_nothing() {
    let r = open(
        SIGV4,
        None,
        r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#,
    );
    let binding = r.expect("a keyless sigv4 binding still opens: the caller's credential may sign");
    assert!(!binding.session_token_unsendable());
    let hash = sigv4::sha256_hex(b"{}");
    let facts = SignFacts {
        method: "POST",
        host: "h",
        path: "/p",
        query: None,
        content_type: None,
        payload_hash: &hash,
        timestamp_epoch: 1,
    };
    assert!(binding.sign(&facts).is_empty());
}

#[test]
fn an_unknown_style_or_malformed_settings_is_refused() {
    assert_eq!(
        lines(open("kerberos", Some("k"), "{}")),
        ["settings: outbound auth style `kerberos` is not served by this plugin"]
    );
    assert_eq!(
        lines(open(SIGV4, Some("k"), "[1]")),
        ["settings: outbound auth settings must be a JSON object"]
    );
    assert_eq!(
        lines(open("bearer", Some("k"), "{}")),
        ["settings: outbound auth style `bearer` is not served by this plugin"],
        "bearer is a different mechanism, busbar-auth-header"
    );
}

/// The warning the kernel hands in as `region_unread` when the provider's host names no region and
/// the scope falls back to the dialect's default: 1.5.5's signer's own words
/// (`proto/bedrock/writer.rs`, v1.5.5).
const REGION_UNREAD: &str = "could not derive AWS region from Bedrock endpoint host; defaulting \
                             SigV4 scope to us-east-1 (set a \
                             bedrock-runtime[-fips].<region>.amazonaws.com host)";

/// The WARN lines logged while `binding` signs one request to `host` `times` times.
fn warned_signing(binding: &SigV4Binding, host: &str, times: usize) -> Vec<String> {
    let hash = sigv4::sha256_hex(b"{}");
    let facts = SignFacts {
        method: "POST",
        host,
        path: "/model/m-cap/converse",
        query: None,
        content_type: Some("application/json"),
        payload_hash: &hash,
        timestamp_epoch: 1_440_938_160,
    };
    let cap = busbar_contract::testkit::WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        for _ in 0..times {
            assert!(!binding.sign(&facts).is_empty(), "a clean credential signs");
        }
    });
    cap.messages()
        .into_iter()
        .map(|m| m.trim_end().to_string())
        .collect()
}

/// A BEDROCK HOST WITH NO DERIVABLE REGION WARNS ON EVERY SIGNATURE, as 1.5.5's signer did: the
/// kernel resolved the region at seal to the default and handed the dialect's warning in as
/// `region_unread`, which this plugin reads and logs, word for word, with the request's `host`, on
/// each request it signs under that default. 1.5.5 wrote it to busbar's own log,
/// `<TS>  WARN could not derive AWS region ... host=127.0.0.1:<PORT>` (the oracle's
/// `egress.image-detail|high|bedrock` golden); a plugin's WARN line reaches that log through its
/// own. A host whose region reads is handed no warning and logs none.
#[test]
fn a_bedrock_host_with_no_derivable_region_warns_on_every_signature() {
    let settings = serde_json::json!({
        "service": "bedrock",
        "region": "us-east-1",
        "content_type": "application/json",
        "region_unread": REGION_UNREAD,
    })
    .to_string();
    let defaulted = open(SIGV4, Some("AKIDORACLEDETAIL0001:SECRET"), &settings).expect("opens");
    let want = format!("{REGION_UNREAD} host=127.0.0.1:41234");
    assert_eq!(
        warned_signing(&defaulted, "127.0.0.1:41234", 2),
        vec![want.clone(), want]
    );
    let named = open(
        SIGV4,
        Some("AKIDORACLEDETAIL0001:SECRET"),
        r#"{"service":"bedrock","region":"eu-west-1"}"#,
    )
    .expect("opens");
    assert!(
        warned_signing(&named, "bedrock-runtime.eu-west-1.amazonaws.com", 2).is_empty(),
        "a host whose region reads warns nothing"
    );
}
