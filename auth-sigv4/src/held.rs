// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Own`] — THIS PLUGIN'S OWN SEAL over the credentials it holds in its own memory: the SigV4
//! secret access key and the session token of a split signing credential.
//!
//! They are the contract's `Secret<T>` (BUSBAR-1.6.0.md Part 2 #54: "secret material is `Secret<T>`;
//! raw access only via the sealed accessor"), owned by this crate: `Secret<T, Own>`, wrapped with
//! `Secret::held` and read with `Secret::expose_own(&Own::here())`. No other crate can name or
//! construct `Own`, so no other crate can read them. The contract keeps the hygiene for every
//! owner: `Debug`/`Display` print `"[REDACTED]"`, nothing serializes, the backing memory is zeroized
//! on drop, and equality is constant-time.
//!
//! The signing credential's `secret` and `session_token` are typed `Secret<Zeroizing<String>, Own>`:
//! [`zeroize::Zeroizing`] is named in the field's own type, so a reader (and busbar's secret-hygiene
//! gate, which judges a field by its declared type) sees the material is wiped without opening this
//! module. Every `expose_own` call site is an audit point where the plaintext escapes on purpose.

busbar_contract::own_seal!(Own);

#[cfg(test)]
#[path = "tests/held_tests.rs"]
mod tests;
