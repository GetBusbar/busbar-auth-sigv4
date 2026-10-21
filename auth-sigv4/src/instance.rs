// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE INSTANCE: the handles (generation data, each with the unsendable-token line its `fields`
//! reports). No token cache, no waker: a sigv4 binding never mints and never pends — a bind and
//! `tick` only pre-derive day keys ahead of midnight. Nothing of `verify`'s is kept here: no
//! secret, no verdict, no per-ticket state (the kernel never cached a SigV4 verdict, and the
//! secret is the host's `records.secret` answer on every call). The answers' memory, the instance
//! pointer and the host tables are the contract kit's (`busbar_contract::auth_door!`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use crate::signing::{Field, SigV4Binding, SignFacts, SigningCredential};

/// The index of each diagnostic id in the Statement (`crate::DIAG_IDS`).
pub(crate) mod diag {
    /// A signing credential's session token is not a legal header value.
    pub const SESSION_TOKEN_INVALID_BYTES: u32 = 0;
}

/// The severity of the unsendable-token line: WARN, as 1.5.5 logged it.
pub(crate) const WARN: u8 = 1;

/// How often `tick` re-checks the SigV4 day keys while a binding is open.
const PREDERIVE_TICK_NS: u64 = 60 * 1_000_000_000;

/// One handle: its generation, its binding, and its `fields` note ([`SigV4::note_unsendable`]).
type Handle = (u64, Arc<SigV4Binding>, Arc<str>);

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
    /// The fields to set, in order (none: the credential signs nothing), and the line the request
    /// reports when the signer's session token is no legal header value.
    Fields {
        /// The signed fields.
        fields: Vec<Field>,
        /// The unsendable-token line, when the signer's session token is unsendable.
        note: Option<Box<str>>,
    },
    /// The host lent no method, host or path: nothing can be signed.
    NoFacts,
}

/// One plugin instance: the `VerifyPlugin` and `OutboundPlugin` the door kit serves (`crate`).
pub struct SigV4 {
    generation: AtomicU64,
    next_handle: AtomicU64,
    /// Each handle: its generation, its binding, and the line its `fields` reports when the signing
    /// credential's session token is unsendable (built once at open, kept until retire).
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
        // The line a request signed with nothing reports names the binding's service, the one
        // input it varies on: built here, once.
        let note = Self::note_unsendable(&binding.params().service);
        // Today's key (and tomorrow's near midnight) is held from the bind on, not first at the
        // next `tick` (THE DESIGN §6.5: "a daily signing key derived ahead of time").
        binding.prederive(crate::now_epoch());
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle, (generation, Arc::new(binding), note.into()));
        handle
    }

    /// The binding behind `handle`.
    pub(crate) fn binding(&self, handle: u64) -> Option<Arc<SigV4Binding>> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|(_, b, _)| b.clone())
    }

    /// `fields`' body: sign one request on `handle` for `who` over `facts` (`None`: the host lent
    /// no method, host or path). `None` when this generation holds no such handle (REFUSED).
    pub(crate) fn sign(
        &self,
        handle: u64,
        who: Who<'_>,
        facts: Option<SignFacts<'_>>,
    ) -> Option<Signed> {
        let (binding, note) = self
            .handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|(_, b, n)| (b.clone(), n.clone()))?;
        let Some(facts) = facts else {
            return Some(Signed::NoFacts);
        };
        let fresh;
        let signer = match who {
            Who::Own => &*binding,
            Who::Caller(caller) => {
                let caller = caller
                    .and_then(|c| std::str::from_utf8(c).ok())
                    .unwrap_or("");
                // A FRESH binding, per request: the caller's key varies request to request, so it
                // never enters the operator binding's day-key cache (`signing` module doc).
                fresh =
                    SigV4Binding::new(binding.params().clone(), SigningCredential::split(caller));
                &fresh
            }
        };
        let fields = signer.sign(&facts);
        let note = signer
            .session_token_unsendable()
            .then(|| Box::<str>::from(&*note));
        Some(Signed::Fields { fields, note })
    }

    /// `retire`: drop the handles opened at `generation`.
    pub(crate) fn retire(&self, generation: u64) {
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (g, _, _)| *g != generation);
    }

    /// The line a request signed with nothing because its credential's session token is no legal
    /// header value reports, in the words 1.5.5's signer logged on each such request, naming
    /// `service`.
    pub(crate) fn note_unsendable(service: &str) -> String {
        let (initial, rest) = service.split_at(service.len().min(1));
        format!(
            "{}{rest} lane session token contains a byte rejected by HeaderValue; \
             skipping signing to avoid a signed-but-absent x-amz-security-token header.",
            initial.to_uppercase()
        )
    }

    /// `tick`: pre-derive every live binding's day keys ahead of midnight. Answers the next tick,
    /// ALWAYS: the schedule runs from the instance's open, before any binding exists, and a `0`
    /// would end it for good (`TickOut::next_tick_ns`), leaving a later binding's day keys to be
    /// derived on the request path (THE DESIGN §6.5: "a daily signing key derived ahead of time").
    pub(crate) fn tick(&self, now_ns: u64) -> u64 {
        let bindings: Vec<Arc<SigV4Binding>> = self
            .handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|(_, b, _)| b.clone())
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
