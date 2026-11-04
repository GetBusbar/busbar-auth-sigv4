// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared SDK HMAC, proven against RFC 4231 and against ring.

fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(&crate::fixtures::hmac(key, data)[..])
}

/// RFC 4231 HMAC-SHA256 test cases 1, 2, 6 and 7 (a key past the block size is hashed first).
#[test]
fn hmac_answers_rfc_4231() {
    assert_eq!(
        hmac_hex(&[0x0b; 20], b"Hi There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hmac_hex(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        hmac_hex(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
    assert_eq!(
        hmac_hex(
            &[0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size \
              data. The key needs to be hashed before being used by the HMAC algorithm."
        ),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    );
}

/// The HMAC agrees with ring's over every key length across the block size and every data length
/// across two blocks (each padding boundary included).
#[test]
fn hmac_agrees_with_ring_across_block_boundaries() {
    let key: Vec<u8> = (0..140_u8).collect();
    let data: Vec<u8> = (0..200_u8).map(|b| b.wrapping_mul(7)).collect();
    for k in [0, 1, 31, 32, 63, 64, 65, 127, 128, 129, 140] {
        for d in 0..data.len() {
            let want = ring::hmac::sign(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key[..k]),
                &data[..d],
            );
            assert_eq!(
                hmac_hex(&key[..k], &data[..d]),
                hex::encode(want.as_ref()),
                "key {k} bytes, data {d} bytes"
            );
        }
    }
}

/// `validate` answers settings that are not a JSON object with the same outcome `open` and
/// `refresh` do: FAILED (it answered REFUSED, which says "not this plugin's call").
#[test]
fn validate_fails_settings_that_are_not_an_object() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::sdk::auth_outbound::OutboundPlugin;
    let refusal = <crate::instance::SigV4 as OutboundPlugin>::validate(b"[]")
        .expect_err("an array is not the settings object");
    assert_eq!(refusal.outcome(), Outcome::Failed);
}

#[test]
fn present_blank_scope_settings_are_refused_at_validate_open_and_refresh() {
    use busbar_contract::abi::mechanism::call::Outcome;
    let want = Some((
        Outcome::Failed,
        "settings.service: required for sigv4 signing\nsettings.region: required for sigv4 signing"
            .to_string(),
    ));
    assert_eq!(
        plugin_level(br#"{"service":" ","region":"\t"}"#),
        [want.clone(), want.clone(), want]
    );
}

/// The plugin-level settings `validate`, `open` and `refresh` read, the one rule for all three.
fn plugin_level(
    settings: &[u8],
) -> [Option<(busbar_contract::abi::mechanism::call::Outcome, String)>; 3] {
    use crate::instance::SigV4;
    use busbar_contract::abi::sdk::auth_outbound::OutboundPlugin;
    let said = |r: busbar_contract::abi::sdk::life::Refusal| {
        (r.outcome(), r.text().unwrap_or_default().to_string())
    };
    let opened = SigV4::new(1);
    [
        <SigV4 as OutboundPlugin>::validate(settings)
            .err()
            .map(said),
        <SigV4 as OutboundPlugin>::open(settings, &[], 1)
            .err()
            .map(said),
        <SigV4 as OutboundPlugin>::refresh(&opened, settings, &[], 2)
            .err()
            .map(said),
    ]
}

#[test]
fn an_unknown_plugin_level_key_is_refused_by_name_at_validate_open_and_refresh() {
    use busbar_contract::abi::mechanism::call::Outcome;
    let want = Some((
        Outcome::Failed,
        "settings: unknown key `regoin`\nsettings: unknown key `serivce`".to_string(),
    ));
    assert_eq!(
        plugin_level(br#"{"regoin":"x","serivce":"y"}"#),
        [want.clone(), want.clone(), want]
    );
    for ok in [
        &b""[..],
        b"{}",
        br#"{"service":"bedrock","region":"us-east-1","region_unread":"w","content_type":"a/b"}"#,
    ] {
        assert_eq!(plugin_level(ok), [None, None, None]);
    }
}

#[test]
fn plugin_level_settings_that_are_not_an_object_answer_the_settings_line() {
    use busbar_contract::abi::mechanism::call::Outcome;
    let want = Some((
        Outcome::Failed,
        "settings: must be a JSON object".to_string(),
    ));
    assert_eq!(plugin_level(b"[]"), [want.clone(), want.clone(), want]);
}

#[test]
fn a_key_core_forwards_from_its_shared_schema_opens_the_instance() {
    assert_eq!(
        plugin_level(
            br#"{"token_url":"https://t","token_uri":"https://u","scope":"s","subject":"x"}"#
        ),
        [None, None, None]
    );
    let want = Some((
        busbar_contract::abi::mechanism::call::Outcome::Failed,
        "settings: unknown key `regoin`".to_string(),
    ));
    assert_eq!(
        plugin_level(br#"{"scope":"s","regoin":"x"}"#),
        [want.clone(), want.clone(), want]
    );
}

#[test]
fn a_present_service_or_region_is_checked_at_validate_open_and_refresh() {
    use busbar_contract::abi::mechanism::call::Outcome;
    let failed = |text: &str| Some((Outcome::Failed, text.to_string()));
    let service = failed("settings.service: not an AWS service name (1 to 64 of a-z, 0-9 and -)");
    assert_eq!(
        plugin_level(br#"{"service":"Bedrock"}"#),
        [service.clone(), service.clone(), service]
    );
    let region = failed("settings.region: not an AWS region (1 to 64 of a-z, 0-9 and -)");
    assert_eq!(
        plugin_level(br#"{"region":"us east 1"}"#),
        [region.clone(), region.clone(), region]
    );
    let typed = failed("settings.service: expected a string");
    assert_eq!(
        plugin_level(br#"{"service":5}"#),
        [typed.clone(), typed.clone(), typed]
    );
    assert_eq!(
        plugin_level(br#"{"service":" s3 ","region":"eu-west-1"}"#),
        [None, None, None],
        "a well-shaped pair, padded, opens"
    );
}

/// r2-prod0-4: the host's refusal of `records.secret` (config, an undeclared kind) and its failure
/// (a backend outage) are different operator matters: each outcome has its own word in the WARN.
#[test]
fn a_declined_secret_read_names_what_the_host_answered() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::sdk::services::ServiceError;
    let word = |o| crate::service_error_word(ServiceError::Declined(o));
    assert_eq!(word(Outcome::Refused), "refused");
    assert_eq!(word(Outcome::Failed), "failed");
    assert_eq!(word(Outcome::Fault), "declined");
    assert_eq!(word(Outcome::Ready), "declined");
    assert_eq!(word(Outcome::Pending), "declined");
    assert_eq!(
        crate::service_error_word(ServiceError::Unserved),
        "unserved"
    );
    assert_eq!(crate::service_error_word(ServiceError::Broken), "broken");
    assert_eq!(
        crate::service_error_word(ServiceError::Short { bytes: 1, items: 1 }),
        "short"
    );
}
