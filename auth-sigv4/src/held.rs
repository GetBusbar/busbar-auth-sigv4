// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Own`] — THIS PLUGIN'S OWN SEAL over the credentials it holds in its own memory: the SigV4
//! secret access key and the session token of a split signing credential.
//!
//! They are the contract's `Secret<T>` (BUSBAR-1.6.0.md Part 2 #54: "secret material is `Secret<T>`;
//! raw access only via the sealed accessor"), owned by this crate: `Secret<T, Own>`, wrapped with
//! `Secret::held` and read with `Secret::expose_own(&Own::here())`. No other crate can name or
//! construct `Own`, so no other crate can read them. The contract keeps the hygiene for every
//! owner: `Debug`/`Display` print `"[REDACTED]"`, nothing serializes, the backing memory is
//! zeroized on drop, and equality is constant-time. Every `expose_own` call site is an audit point
//! where the plaintext escapes on purpose.

busbar_contract::own_seal!(Own);

#[cfg(test)]
mod tests {
    use super::Own;
    use busbar_contract::Secret;

    #[test]
    fn debug_and_display_print_only_the_redaction_marker() {
        let h: Secret<String, Own> = Secret::held(String::from("sk-live-plaintext"));
        assert_eq!(format!("{h:?}"), "[REDACTED]");
        assert_eq!(format!("{h}"), "[REDACTED]");
        assert_eq!(format!("{:?}", Some(&h)), "Some([REDACTED])");
        assert_eq!(h.expose_own(&Own::here()), "sk-live-plaintext");
    }

    #[test]
    fn equality_compares_the_held_bytes() {
        let a: Secret<String, Own> = Secret::held(String::from("same"));
        assert_eq!(a, a.clone());
        assert_ne!(a, Secret::held(String::from("other")));
        assert_ne!(a, Secret::held(String::from("sam")));
    }
}
