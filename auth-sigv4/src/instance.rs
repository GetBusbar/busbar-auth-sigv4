// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE INSTANCE: the handles (generation data). No token cache, no waker: a sigv4 binding never
//! mints and never pends — `tick` only pre-derives day keys ahead of midnight. Nothing of `verify`'s is kept here: no secret, no
//! verdict, no per-ticket state (the kernel never cached a SigV4 verdict, and the secret is the
//! host's `records.secret` answer, read on every call). The answers' memory, the instance pointer
//! and the host tables are the contract kit's (`busbar_contract::auth_door!`), so this crate holds
//! no per-thread or process-global store.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use crate::signing::{Field, SigV4Binding, SignFacts, SigningCredential};

/// How often `tick` re-checks the SigV4 day keys while a binding is open.
const PREDERIVE_TICK_NS: u64 = 60 * 1_000_000_000;

/// One handle: its generation and its binding.
type Handle = (u64, Arc<SigV4Binding>);

/// What `fields` answers in passthrough mode when the host lent no caller credential.
pub(crate) const NO_CALLER_CREDENTIAL: &str =
    "sigv4 passthrough: the caller presented no credential; the request is not sent unsigned";

/// Whose credential one `fields` call signs with. No `Debug`: it carries the caller's credential.
#[derive(Clone, Copy)]
pub(crate) enum Who<'a> {
    /// The operator's own bound credential (`MODE_OWN`).
    Own,
    /// The caller's verified credential, passed per request (`MODE_PASSTHROUGH`); `None` when the
    /// host lent none.
    Caller(Option<&'a [u8]>),
}

/// What one `fields` call on a held handle answers. No `Debug`: its fields carry credential
/// material.
pub(crate) enum Signed {
    /// The fields to set, in order (never none: a request with nothing to sign with FAILS).
    Fields(Vec<Field>),
    /// Nothing can be signed, for this reason: no credential of the binding's own (own mode), no
    /// caller credential or a malformed one (passthrough), or an `Authorization` value no header
    /// may carry. The request FAILS; it is never sent unsigned.
    Failed(Cow<'static, str>),
    /// The host lent no method, host or path: nothing can be signed.
    NoFacts,
}

/// One plugin instance: the `VerifyPlugin` and `OutboundPlugin` the door kit serves (`crate`).
pub struct SigV4 {
    generation: AtomicU64,
    next_handle: AtomicU64,
    /// Each handle: its generation and its binding (kept until retire).
    handles: RwLock<HashMap<u64, Handle>>,
}

impl SigV4 {
    /// An instance at `generation`.
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            generation: AtomicU64::new(generation),
            next_handle: AtomicU64::new(1),
            handles: RwLock::new(HashMap::new()),
        }
    }

    /// `refresh`: the generation later handles belong to.
    pub(crate) fn set_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::Release);
    }

    /// Keep `binding` under a new handle of the current generation.
    pub(crate) fn keep(&self, binding: SigV4Binding) -> u64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let generation = self.generation.load(Ordering::Acquire);
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle, (generation, Arc::new(binding)));
        handle
    }

    /// The binding behind `handle`.
    pub(crate) fn binding(&self, handle: u64) -> Option<Arc<SigV4Binding>> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|(_, b)| b.clone())
    }

    /// `fields`' body: sign one request on `handle` for `who` over `facts` (`None`: the host lent
    /// no method, host or path). `None` when this generation holds no such handle (REFUSED).
    pub(crate) fn sign(
        &self,
        handle: u64,
        who: Who<'_>,
        facts: Option<SignFacts<'_>>,
    ) -> Option<Signed> {
        let signed = self.sign_unlogged(handle, who, facts);
        let reason = match &signed {
            Some(Signed::Failed(reason)) => reason.as_ref(),
            Some(Signed::NoFacts) => "the host lent no method, host or path",
            _ => return signed,
        };
        tracing::info!(module = "sigv4", reason, "sigv4 request not signed: FAILED");
        signed
    }

    /// [`Self::sign`]'s answer, unlogged.
    fn sign_unlogged(
        &self,
        handle: u64,
        who: Who<'_>,
        facts: Option<SignFacts<'_>>,
    ) -> Option<Signed> {
        let binding = self.binding(handle)?;
        let Some(facts) = facts else {
            return Some(Signed::NoFacts);
        };
        let fresh;
        let signer = match who {
            Who::Own => &*binding,
            Who::Caller(None) => {
                return Some(Signed::Failed(Cow::Borrowed(NO_CALLER_CREDENTIAL)));
            }
            Who::Caller(Some(caller)) => {
                let parsed = std::str::from_utf8(caller)
                    .map_err(|_| vec!["the credential is not UTF-8"])
                    .and_then(SigningCredential::parse);
                let credential = match parsed {
                    Ok(c) => c,
                    Err(findings) => {
                        let reason = findings
                            .iter()
                            .map(|f| format!("caller credential: {f}"))
                            .collect::<Vec<_>>()
                            .join("; ");
                        return Some(Signed::Failed(Cow::Owned(reason)));
                    }
                };
                // A FRESH binding, per request: the caller's key varies request to request, so it
                // never enters the operator binding's day-key cache (`signing` module doc).
                fresh = SigV4Binding::new(binding.params().clone(), Some(credential));
                &fresh
            }
        };
        Some(match signer.sign(&facts) {
            Ok(fields) => Signed::Fields(fields),
            Err(reason) => Signed::Failed(Cow::Borrowed(reason)),
        })
    }

    /// `retire`: drop the handles opened at `generation`.
    pub(crate) fn retire(&self, generation: u64) {
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (g, _)| *g != generation);
    }

    /// `tick`: pre-derive every live binding's day keys ahead of midnight. Answers the next tick,
    /// ALWAYS: the schedule runs from the instance's open, before any binding exists, and a `0`
    /// would end it for good (`TickOut::next_tick_ns`), leaving a later binding's day keys to be
    /// derived on the request path (a daily signing key is derived ahead of time).
    pub(crate) fn tick(&self, now_ns: u64) -> u64 {
        let bindings: Vec<Arc<SigV4Binding>> = self
            .handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|(_, b)| b.clone())
            .collect();
        let now = crate::now_epoch();
        for b in &bindings {
            b.prederive(now);
        }
        now_ns.saturating_add(PREDERIVE_TICK_NS)
    }
}

#[cfg(test)]
#[path = "tests/instance_tests.rs"]
mod tests;
