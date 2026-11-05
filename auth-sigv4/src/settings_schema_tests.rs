// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("valid settings schema");
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    for (settings, accepted) in cases {
        let bytes = serde_json::to_vec(settings).expect("settings JSON");
        assert_eq!(
            validator.is_valid(settings),
            *accepted,
            "schema: {settings}"
        );
        assert_eq!(
            plugin_settings(&bytes).is_ok(),
            *accepted,
            "lifecycle: {settings}"
        );
    }
}

#[test]
fn settings_schema_matches_sigv4_lifecycle() {
    check(&[
        (json!({}), true),
        (json!({"service":null,"region":null}), true),
        (
            json!({"service":"\u{2003} s3 \t","region":"us-east-1"}),
            true,
        ),
        (json!({"service":"a".repeat(64)}), true),
        (
            json!({"region_unread":42,"token_url":false,"scope":{}}),
            true,
        ),
        (json!({"service":"a".repeat(65)}), false),
        (json!({"service":"S3"}), false),
        (json!({"service":"s3/other"}), false),
        (json!({"region":"\u{2003} "}), false),
        (json!({"region":42}), false),
        (json!({"content_type":"application/json"}), false),
        (json!({"content_type":[]}), false),
        (json!({"content_type":null}), false),
        (json!({"access_key":"secret"}), false),
        (Value::Null, false),
    ]);
}
