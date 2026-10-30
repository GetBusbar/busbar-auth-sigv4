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
/// and a `content_type` key is read past. OWNER RULING: a session token no header value may carry
/// is refused at open, naming the finding (was: it opened, and each request signed nothing).
#[test]
fn sigv4_needs_its_two_params_and_refuses_an_unsendable_token() {
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
    assert_eq!(
        lines(r),
        ["credential: the session token holds a byte no header value may carry"]
    );
}

/// A binding opened with no credential is the contract's passthrough-only binding: it opens (the
/// caller's credential may sign), and own-mode signing on it FAILS with the reason, never signing
/// nothing silently (OWNER RULING; was: an empty field set).
#[test]
fn a_keyless_binding_opens_but_refuses_to_sign_in_own_mode() {
    let r = open(
        SIGV4,
        None,
        r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#,
    );
    let binding = r.expect("a keyless sigv4 binding still opens: the caller's credential may sign");
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
    assert_eq!(binding.sign(&facts), Err(crate::signing::NO_OWN_CREDENTIAL));
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

/// A blank (empty or whitespace) `service` or `region` is no value: the same refusal as one absent.
#[test]
fn a_blank_service_or_region_is_refused_as_missing() {
    assert_eq!(
        lines(open(
            SIGV4,
            Some("A:S"),
            r#"{"service":"","region":"us-east-1"}"#
        )),
        ["settings: uses auth: sigv4 but has no `service`"]
    );
    assert_eq!(
        lines(open(
            SIGV4,
            Some("A:S"),
            r#"{"service":"svc","region":"  \t"}"#
        )),
        ["settings: uses auth: sigv4 but has no `region`"]
    );
}

/// A `service` or `region` that is not a string is refused as invalid, not coerced.
#[test]
fn a_non_string_service_or_region_is_refused_as_invalid() {
    assert_eq!(
        lines(open(
            SIGV4,
            Some("A:S"),
            r#"{"service":5,"region":"us-east-1"}"#
        )),
        ["settings: outbound auth setting `service` is invalid: expected a string"]
    );
    assert_eq!(
        lines(open(
            SIGV4,
            Some("A:S"),
            r#"{"service":"svc","region":["x"]}"#
        )),
        ["settings: outbound auth setting `region` is invalid: expected a string"]
    );
}

/// A credential that is not UTF-8 is refused, not read as keyless.
#[test]
fn a_credential_that_is_not_utf8_is_refused() {
    let r = open_binding(
        SIGV4,
        Some(&[0xff]),
        Some(br#"{"service":"svc","region":"us-east-1"}"#),
    );
    assert_eq!(lines(r), ["credential: the credential is not UTF-8"]);
}

/// OWNER RULING: a credential that is present but cannot sign is refused at open, one
/// `credential: ...` line per finding, never echoing the credential's bytes (it used to open and
/// sign nothing, silently).
#[test]
fn a_malformed_credential_is_refused_at_open() {
    const SETTINGS: &str = r#"{"service":"svc","region":"us-east-1"}"#;
    let shape = "credential: expected ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]";
    for (credential, expected) in [
        ("AKID", vec![shape]),
        ("", vec![shape]),
        (":sk", vec!["credential: the access key id is empty"]),
        ("AK:", vec!["credential: the secret access key is empty"]),
        (
            ":",
            vec![
                "credential: the access key id is empty",
                "credential: the secret access key is empty",
            ],
        ),
        (
            "AK\u{7f}:SK",
            vec!["credential: the access key id holds a byte no header value may carry"],
        ),
        (
            "AK:SK:bad\ntok",
            vec!["credential: the session token holds a byte no header value may carry"],
        ),
        ("AK:SK:", vec!["credential: the session token is empty"]),
    ] {
        let refused = lines(open(SIGV4, Some(credential), SETTINGS));
        assert_eq!(refused, expected, "{credential:?}");
        for line in &refused {
            for secret in ["SK", "sk", "bad", "AK:", "\u{7f}"] {
                assert!(
                    !line.contains(secret),
                    "{credential:?}: a refusal echoes credential bytes: {line}"
                );
            }
        }
    }
    // No credential at all is a passthrough-only binding: it opens.
    assert!(open(SIGV4, None, SETTINGS).is_ok());
}

/// A style setting this plugin does not read is refused by name, not ignored (a typo such as
/// `regoin` would otherwise go unnoticed); `content_type` is still read past (1.5.5 configs).
#[test]
fn an_unknown_settings_key_is_refused_by_name() {
    assert_eq!(
        lines(open(
            SIGV4,
            Some("A:S"),
            r#"{"service":"s3","region":"x","regoin":"y"}"#
        )),
        ["settings: unknown key `regoin`"]
    );
    assert!(open(
        SIGV4,
        Some("A:S"),
        r#"{"service":"s3","region":"x","content_type":"application/json"}"#
    )
    .is_ok());
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
    let cap = busbar_test_kit::warn_capture::WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        for _ in 0..times {
            binding.sign(&facts).expect("a clean credential signs");
        }
    });
    cap.messages()
        .into_iter()
        .map(|m| m.trim_end().to_string())
        .collect()
}

/// A BEDROCK HOST WITH NO DERIVABLE REGION WARNS ON EVERY SIGNATURE, as 1.5.5's signer did: the
/// kernel resolved the region at seal to the default and handed the dialect's warning in as
/// `region_unread`, which this plugin reads (never refuses as unknown) and logs, word for word, with
/// the request's `host`, on each request it signs under that default. 1.5.5 wrote it to busbar's own
/// log, `<TS>  WARN could not derive AWS region ... host=127.0.0.1:<PORT>` (the oracle's
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
    let defaulted = open(SIGV4, Some("AKIDORACLEDETAIL0001:SECRET"), &settings)
        .expect("`region_unread` is the kernel's to hand in, not an unknown key");
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

/// `region_unread` is read; every other key this plugin does not read is still refused by name.
#[test]
fn an_unknown_setting_other_than_region_unread_is_still_refused() {
    assert_eq!(
        lines(open(
            SIGV4,
            Some("A:S"),
            r#"{"service":"s3","region":"x","region_unread":"w","regoin":"y"}"#
        )),
        ["settings: unknown key `regoin`"]
    );
    assert!(open(
        SIGV4,
        Some("A:S"),
        r#"{"service":"s3","region":"x","region_unread":"w"}"#
    )
    .is_ok());
}

/// S1/SZ-P13: style settings that do not parse answer the auth kit's `json_error` line (the class
/// of failure and where), never the decoder's own text, whose input may carry a pasted secret.
#[test]
fn style_settings_that_do_not_parse_withhold_the_decoders_text() {
    assert_eq!(
        lines(open(SIGV4, Some("A:S"), r#"{"service": "wJalrXUtnFEMI"#)),
        [
            "settings: outbound auth settings are not JSON: it ends before the JSON does (line 1, \
          column 26; the decoder's text is withheld)"
        ]
    );
}

/// S5: a refused binding is logged once at `info` (module `sigv4`, each line), never with the
/// credential's bytes.
#[test]
fn a_refused_binding_is_logged_once_without_the_credential() {
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        assert!(open(
            SIGV4,
            Some("AKIDNOCOLONSECRET"),
            r#"{"service":"s","region":"r"}"#
        )
        .is_err());
        assert!(open(
            SIGV4,
            Some("AKID:SECRETOK"),
            r#"{"service":"s","region":"r"}"#
        )
        .is_ok());
    });
    let logged = cap.messages();
    assert_eq!(logged.len(), 1, "{logged:?}");
    assert!(logged[0].contains("module=sigv4"), "{logged:?}");
    assert!(
        logged[0].contains("credential: expected ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]"),
        "{logged:?}"
    );
    assert!(!logged[0].contains("AKIDNOCOLONSECRET"), "{logged:?}");
}
