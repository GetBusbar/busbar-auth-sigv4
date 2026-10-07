// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE INSTANCE: the handles (generation data), the per-op envelope storage the host copies
//! after each control-lane call, the host services `open` was handed, and the inbound `verify`'s
//! per-ticket state. No token cache, no waker: a sigv4 binding never mints and never pends — `tick`
//! only pre-derives day keys ahead of midnight. Only `verify` may pend, on the host's
//! `records.secret` read; it keeps the completion handle it issued under the ticket until the read
//! answers, and nothing else (never a secret, never a verdict cache: the kernel never cached a SigV4
//! verdict).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use busbar_contract::abi::mechanism::call::{AbiStr, Diag};
use busbar_contract::abi::mechanism::ticket::Ticket;

use crate::abi::{abi, Host};
use crate::signing::SigV4Binding;

/// The index of each diagnostic id in the Statement (`crate::DIAG_IDS`).
pub(crate) mod diag {
    /// A signing credential's session token is not a legal header value.
    pub const SESSION_TOKEN_INVALID_BYTES: u32 = 0;
}

const WARN: u8 = 1;

/// One op's envelope storage: the diagnostics and the texts they point into, kept until the next
/// call of the same op (the host copies them before it makes any other call on that thread).
#[derive(Default)]
pub(crate) struct EnvStore {
    texts: Vec<String>,
    diags: Vec<Diag>,
    /// The error text of the last FAILED/REFUSED answer.
    pub(crate) error: String,
}

impl EnvStore {
    /// Start a call: drop what the previous call left.
    pub(crate) fn clear(&mut self) {
        self.diags.clear();
        self.texts.clear();
        self.error.clear();
    }

    /// Add one diagnostic.
    pub(crate) fn push(&mut self, id: u32, severity: u8, text: String) {
        self.texts.push(text);
        let t = self.texts.last().map_or(
            AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            |t| abi(t),
        );
        self.diags.push(Diag {
            id_idx: id,
            severity,
            _reserved: [0; 3],
            text: t,
        });
    }

    /// The diagnostics, as the envelope carries them.
    pub(crate) fn diags(&self) -> &[Diag] {
        &self.diags
    }
}

/// How often `tick` re-checks the SigV4 day keys while a binding is open.
const PREDERIVE_TICK_NS: u64 = 60 * 1_000_000_000;

/// What `verify` keeps for a ticket between two calls on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Held {
    /// The `records.secret` read pends under this completion handle's `seq`: the resumed call
    /// re-issues the SAME handle and reads the stored answer.
    Pending(u32),
    /// The identity this ticket reached did not fit the host's buffer: the host's one re-call is
    /// served from it, the work never repeated. The subject is the AccessKeyId (not secret).
    Reached(String),
}

/// One plugin instance.
pub(crate) struct SigV4 {
    generation: AtomicU64,
    next_handle: AtomicU64,
    handles: RwLock<HashMap<u64, (u64, Arc<SigV4Binding>)>>,
    /// `open_outbound`'s envelope and error.
    pub(crate) open_env: Mutex<EnvStore>,
    /// The host services `open` was handed (`records.secret`); `None` when the host offers none.
    pub(crate) host: Option<Host>,
    /// The next completion-handle `seq` a fresh `records.secret` read issues: unique per instance,
    /// so two reads under one ticket never share a handle.
    next_seq: AtomicU32,
    /// `verify`'s per-ticket state ([`Held`]); an entry lives from a PENDING or short answer to the
    /// call that consumes it, or the ticket's `cancel`.
    held: Mutex<HashMap<Ticket, Held>>,
}

impl SigV4 {
    /// An instance at `generation`, calling the host services `host`.
    pub(crate) fn new(generation: u64, host: Option<Host>) -> Self {
        Self {
            generation: AtomicU64::new(generation),
            next_handle: AtomicU64::new(1),
            handles: RwLock::new(HashMap::new()),
            open_env: Mutex::default(),
            host,
            next_seq: AtomicU32::new(0),
            held: Mutex::new(HashMap::new()),
        }
    }

    /// A fresh completion-handle `seq`.
    pub(crate) fn issue_seq(&self) -> u32 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Keep `held` for `ticket` until its next call.
    pub(crate) fn hold(&self, ticket: Ticket, held: Held) {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(ticket, held);
    }

    /// Take what `ticket` holds, if anything.
    pub(crate) fn take(&self, ticket: Ticket) -> Option<Held> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket)
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

    /// `retire`: drop the handles opened at `generation`.
    pub(crate) fn retire(&self, generation: u64) {
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (g, _)| *g != generation);
    }

    /// Report into `env` a request signed with nothing because its credential's session token is
    /// no legal header value, in the line 1.5.5's signer logged on each such request, naming
    /// `service`.
    pub(crate) fn note_unsendable(env: &mut EnvStore, service: &str) {
        let (initial, rest) = service.split_at(service.len().min(1));
        env.push(
            diag::SESSION_TOKEN_INVALID_BYTES,
            WARN,
            format!(
                "{}{rest} lane session token contains a byte rejected by HeaderValue; \
                 skipping signing to avoid a signed-but-absent x-amz-security-token header.",
                initial.to_uppercase()
            ),
        );
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
