// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-sigv4 — AWS SigV4, outbound and inbound, one auth-kind plugin
//!
//! BUSBAR-1.6.0.md THE DESIGN, §6 (OWNER-LOCKED 2026-09-27, split by mechanism per ARCHITECT ruling 2026-09-29):
//! AWS Signature Version 4 is its own mechanism — a per-request signature over the request, not a
//! credential carried verbatim — and lives in its own plugin, `busbar-auth-sigv4`, loaded when
//! some provider uses `auth: sigv4`. It speaks the auth kind's memory ABI
//! (`busbar_contract::abi::auth`, v3):
//!
//! * `open_outbound` binds the style to its credential and settings and answers a handle
//!   (generation data). It never touches the network.
//! * `fields` is the ONE per-request call the kernel makes (BUSBAR-1.6.0.md §6.4, §11.6): the request is signed
//!   for this attempt, the fields written into the host's buffer, which join the head before the
//!   framer encodes it. It serves BOTH credential modes `sigv4` declares
//!   ([`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]): the operator's own bound
//!   credential ([`busbar_contract::abi::auth::MODE_OWN`], the day-key-cached
//!   [`signing::SigV4Binding`]), and the caller's verified credential passed per-request
//!   ([`busbar_contract::abi::auth::MODE_PASSTHROUGH`]) — ARCHITECT ruling 2026-09-29: a
//!   credential SOURCE is not a mechanism, so there is no separate `caller-credential` style; a
//!   passthrough binding is built fresh, per request, from the caller's credential, exactly the
//!   code path the operator-credential binding signs with, minus the day-key cache (the caller's
//!   key varies request to request, so there is nothing to hold ahead of time).
//! * `outbound_ready` is the handle's `ready` fact for the health prober: always ready — a sigv4
//!   binding never mints.
//! * `tick` pre-derives the SigV4 day keys ahead of UTC midnight (BUSBAR-1.6.0.md §6.5).
//!
//! The style logic is `egress_auth/*` MOVED VERBATIM (KERNEL<>PLUGINS step 22), staged
//! `busbar-auth-outbound::{sigv4,signing,style}` (step 22), then split here by mechanism
//! (AUTH-SPLIT): each module names the file it came from.
//!
//! ## Inbound: SigV4 verification, moved here from the kernel
//!
//! BUSBAR-1.6.0.md THE DESIGN, §6 "Inbound verify": the kernel's inbound SigV4 "reads through a
//! host store service"; Appendix A, B.3: "Inbound SigV4 moves into an auth plugin's verify over a
//! store-read host service, keeping the dummy-secret timing equivalence for an unknown
//! AccessKeyId". The kernel's pre-step and `verify_sigv4_ingress_credential` (and
//! `busbar-kernel-identity`'s `ingress_sigv4`) are [`inbound`], verbatim; `verify` serves them at
//! the `HeadBody` point ([`CAP_INBOUND`], every header line, the body):
//!
//! * no `authorization` line, or one that does not open with `AWS4-HMAC-SHA256`: PASS (not this
//!   plugin's credential: the kernel goes on to its bearer path);
//! * a SigV4 `Authorization` that does not parse, or no `x-amz-content-sha256` / `x-amz-date`
//!   line: REJECT (the kernel's structural gate);
//! * otherwise the kernel's check, in its order: the signed-header prefilter, `UNSIGNED-PAYLOAD`
//!   refused, the body's hash against the signed `x-amz-content-sha256` (constant time), then the
//!   secret read through the host's `records.secret` (kind `sigv4`, id the AccessKeyId; an unknown
//!   id answers the host's fixed dummy secret, not live, in equal time) and the full constant-time
//!   signature check over whatever came back. Only a verified signature over a LIVE credential
//!   admits: an IDENTITY whose subject is the AccessKeyId (the kernel resolves the governance key
//!   from the credential kind and the subject), no TTL (never cached: the kernel never cached a
//!   SigV4 verdict), no replay claim, no credential, no strips. Every failure is the one REJECT,
//!   the kernel's one opaque 401.
//!
//! The login pair is not served and answers REFUSED (the tail does not declare `CAP_LOGIN`).

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod abi;
pub mod inbound;
mod instance;
mod signing;
mod sigv4;
mod style;

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
    OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, StyleDecl, VerifyIn,
    CANCEL_ABANDONED, CAP_INBOUND, CAP_OUTBOUND, FACT_INBOUND_ALL_HEADERS, FACT_READS_CREDENTIALS,
    LOGIN_KIND_NONE, MODE_OWN, MODE_PASSTHROUGH, POINT_HEAD_BODY, STYLE_CALLER_CREDENTIAL,
    STYLE_NEEDS_HEADERS, VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Envelope, InHead, OutHead, Outcome, FLAG_RESUME,
};
use busbar_contract::abi::mechanism::door::{KindTailHead, MarkWord, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::auth_door::carrier;
use busbar_contract::abi::sdk::door::{abi_str, statement, Slot};

use crate::abi::{abi, blob, text};
use crate::abi::{Crossed, Host};
use crate::inbound::{Judgement, Read, SecretSource};
use crate::instance::{EnvStore, Held, SigV4};
use crate::signing::{SigV4Binding, SignFacts, SigningCredential};

thread_local! {
    /// `fields`' envelope storage, per calling thread: the host copies a call's envelope before it
    /// makes any other call on that thread, and `fields` is called from many at once.
    static FIELDS_ENV: std::cell::RefCell<EnvStore> = std::cell::RefCell::default();
}

/// `fields` for `signer`: its signed fields, and — when its session token is no legal header
/// value, so it signs nothing — the signer's line on this call's envelope, as 1.5.5 logged it on
/// each such request.
fn sign_into(
    signer: &SigV4Binding,
    input: &FieldsIn,
    hash: &str,
    out: &mut FieldsOut,
    write: impl Fn(&[signing::Field], &mut FieldsOut) -> Outcome,
) -> Outcome {
    let Some(facts) = sign_facts(input, hash) else {
        return Outcome::Failed;
    };
    let outcome = write(&signer.sign(&facts), out);
    if signer.session_token_unsendable() {
        FIELDS_ENV.with(|env| {
            let mut env = env.borrow_mut();
            env.clear();
            SigV4::note_unsendable(&mut env, &signer.params().service);
            envelope(&mut out.head, &env);
        });
    }
    outcome
}

/// The flags every field this plugin writes carries: NONE. 1.5.5 sent its credential headers
/// indexable, and an h2 encoder that honoured `FIELD_SENSITIVE` would send them never-indexed —
/// different bytes (ARCHITECT ruling 2026-09-28, Q4: the 1.5.5 bytes win; TODO item 583's
/// sensitive marking is a behaviour change not taken without the owner).
const FIELD_FLAGS: u32 = 0;

/// The one style this plugin serves: it signs the body, so it needs the `HeadBody` point (THE
/// DESIGN, "Auth points and guest lists") and hashes the body itself; it signs the content type
/// the request is sent with, so it needs the header envelope; it serves the caller's credential
/// too.
const STYLE_DECLS: [StyleDecl; 1] = [StyleDecl {
    name: abi_str(style::SIGV4),
    flags: STYLE_CALLER_CREDENTIAL | STYLE_NEEDS_HEADERS,
    points: POINT_HEAD_BODY,
}];

/// The credential kinds `verify` reads through the host's `records.secret`: the host-held SigV4
/// credentials (a busbar key's AccessKeyId and secret).
const CREDENTIAL_KINDS: [AbiStr; 1] = [abi_str(inbound::CREDENTIAL_KIND)];

/// THE AUTH STATEMENT TAIL: the outbound `sigv4` style, and the inbound SigV4 check at the
/// `HeadBody` point (it hashes the body against the signed `x-amz-content-sha256`), reading EVERY
/// header line (the signed set varies per request) and the host-held `sigv4` credentials. No login.
const TAIL: &AuthTail = &AuthTail {
    head: KindTailHead {
        size: size_of::<AuthTail>() as u32,
        _reserved: 0,
    },
    caps: CAP_OUTBOUND | CAP_INBOUND,
    facts: FACT_INBOUND_ALL_HEADERS | FACT_READS_CREDENTIALS,
    login_kind: LOGIN_KIND_NONE,
    inbound_points: POINT_HEAD_BODY,
    styles: STYLE_DECLS.as_ptr(),
    styles_len: STYLE_DECLS.len(),
    operator_principal: abi_str(""),
    credential_kinds: CREDENTIAL_KINDS.as_ptr(),
    credential_kinds_len: CREDENTIAL_KINDS.len(),
};

/// The carrier `verify` reads its credential from, the Statement's one carrier word mark.
const CARRIERS: [MarkWord; 1] = [carrier(inbound::AUTHORIZATION)];

/// The diagnostic ids, in [`instance::diag`] order: 1.5.5's catalog codes where the line had one.
const DIAG_IDS: [AbiStr; 1] = [abi_str("auth.sigv4-session-token-invalid-bytes")];

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::auth::Ops,
    statement: Statement {
        kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement("busbar-auth-sigv4", env!("CARGO_PKG_VERSION"), 1024)
    },
    lifecycle: {
        validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
        drive: Drive, cancel: Cancel, release: Release, close: Close,
    },
    kind_ops: {
        verify: Verify, begin_login: BeginLogin, complete_login: CompleteLogin,
        open_outbound: OpenOutbound, outbound_ready: OutboundReady, fields: Fields,
    },
}

/// THE COMPILED-IN ENTRY a composition root's `auths` row names: the door at
/// `compiled_in::door::door`, the same [`door`] the dropped-in build exports (compiled-in =
/// dropped-in).
pub mod compiled_in {
    /// The door.
    pub mod door {
        pub use crate::door;
    }
}

// The dropped door's one symbol, under `dropped-in` only: a build linking this crate beside other
// plugins must not carry a second `busbar_plugin_door`.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)] // `export_door!` emits the one exported door symbol
mod dropped {
    busbar_contract::export_door!(crate::door);
}

/// Wall-clock seconds since the epoch (1970-01-01 UTC) — the clock `tick`'s day-key pre-derivation
/// reads against.
pub(crate) fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn inst<'a>(p: *mut c_void) -> Option<&'a SigV4> {
    abi::instance::<SigV4>(p)
}

/// Point `head` at `env`'s diagnostics and error text.
fn envelope(head: &mut OutHead, env: &EnvStore) {
    let d = env.diags();
    head.envelope = Envelope {
        metrics: ptr::null(),
        metrics_len: 0,
        diags: if d.is_empty() {
            ptr::null()
        } else {
            d.as_ptr()
        },
        diags_len: d.len(),
    };
    if !env.error.is_empty() {
        head.error = abi(&env.error);
    }
}

/// The plugin's own settings: none are read; present settings must be a JSON object.
fn settings_ok(b: Option<&[u8]>) -> bool {
    b.is_none_or(|b| {
        matches!(
            serde_json::from_slice::<serde_json::Value>(b),
            Ok(serde_json::Value::Object(_))
        )
    })
}

const SETTINGS_NOT_OBJECT: &str = "busbar-auth-sigv4 settings must be a JSON object";

/// `validate`.
pub struct Validate;
impl Slot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, input: &ValidateIn, out: &mut OutHead) -> Outcome {
        if settings_ok(blob(&input.settings)) {
            Outcome::Ready
        } else {
            out.error = abi_str(SETTINGS_NOT_OBJECT);
            Outcome::Refused
        }
    }
}

/// `open`.
pub struct Open;
impl Slot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    fn call(_: *mut c_void, input: &OpenIn, out: &mut OpenOut) -> Outcome {
        if !settings_ok(blob(&input.settings)) {
            out.head.error = abi_str(SETTINGS_NOT_OBJECT);
            // Settings `open` refuses are FAILED with the reason (the lifecycle's rule, and the
            // inbound conformance script's).
            return Outcome::Failed;
        }
        let s = SigV4::new(input.generation, Host::of(input.host));
        out.instance = abi::into_instance(Box::new(s));
        Outcome::Ready
    }
}

/// `refresh`: the new generation.
pub struct Refresh;
impl Slot for Refresh {
    type In = RefreshIn;
    type Out = OutHead;
    fn call(instance: *mut c_void, input: &RefreshIn, out: &mut OutHead) -> Outcome {
        let Some(s) = inst(instance) else {
            return Outcome::Fault;
        };
        if !settings_ok(blob(&input.settings)) {
            out.error = abi_str(SETTINGS_NOT_OBJECT);
            return Outcome::Failed;
        }
        s.set_generation(input.generation);
        Outcome::Ready
    }
}

/// `retire`: the generation's handles go.
pub struct Retire;
impl Slot for Retire {
    type In = GenIn;
    type Out = OutHead;
    fn call(instance: *mut c_void, input: &GenIn, _: &mut OutHead) -> Outcome {
        let Some(s) = inst(instance) else {
            return Outcome::Fault;
        };
        s.retire(input.generation);
        Outcome::Ready
    }
}

/// `tick`: pre-derive the SigV4 day keys ahead of UTC midnight.
pub struct Tick;
impl Slot for Tick {
    type In = TickIn;
    type Out = TickOut;
    fn call(instance: *mut c_void, input: &TickIn, out: &mut TickOut) -> Outcome {
        let Some(s) = inst(instance) else {
            return Outcome::Fault;
        };
        out.next_tick_ns = s.tick(input.now_ns);
        Outcome::Ready
    }
}

/// `drive`: no driver ticket is held.
pub struct Drive;
impl Slot for Drive {
    type In = DriveIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &DriveIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

/// `cancel`: a sigv4 binding never pends; a `verify` waiting on its `records.secret` read is
/// abandoned, and what it held for the ticket goes.
pub struct Cancel;
impl Slot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    fn call(instance: *mut c_void, input: &CancelIn, out: &mut CancelOut) -> Outcome {
        if let Some(s) = inst(instance) {
            s.take(input.ticket);
        }
        out.disposition = CANCEL_ABANDONED;
        Outcome::Ready
    }
}

/// `release`: no lease is handed out.
pub struct Release;
impl Slot for Release {
    type In = ReleaseIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &ReleaseIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

/// `close`.
pub struct Close;
impl Slot for Close {
    type In = InHead;
    type Out = OutHead;
    fn call(instance: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        abi::drop_instance::<SigV4>(instance);
        Outcome::Ready
    }
}

/// The secret source `verify` reads through: the host's `records.secret`, under a completion
/// handle on the op's ticket.
struct HostSecret<'a> {
    s: &'a SigV4,
    ticket: Ticket,
    /// The call RESUMES one that answered PENDING ([`FLAG_RESUME`]).
    resume: bool,
}

/// The most bytes a host may name for one secret on a short answer: well above any SigV4 secret.
const SECRET_MAX_BYTES: u64 = 64 * 1024;

impl SecretSource for HostSecret<'_> {
    fn read(&mut self, kind: &str, id: &str) -> Read {
        // `records.secret` may pend, so the host refuses it ticket-less: a ticket-less `verify`
        // answers REFUSED and the host submits it on a ticket (the auth ABI's "verify ON THE SPOT").
        if self.ticket.is_none() {
            return Read::NotNow;
        }
        let Some(host) = self.s.host else {
            return Read::Unavailable;
        };
        // A resumed call re-issues the SAME handle and reads the stored answer; a fresh one issues
        // a new handle.
        let seq = match self.s.take(self.ticket) {
            Some(Held::Pending(seq)) if self.resume => seq,
            _ => self.s.issue_seq(),
        };
        let handle = CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        };
        let mut sizes = (256, 1);
        // At most two crossings: the call, and the ONE re-call a short answer asks for.
        for _ in 0..2 {
            match host.records_secret(handle, kind, id, sizes) {
                Crossed::Secret(secret, live) => return Read::Secret { secret, live },
                Crossed::Pending => {
                    self.s.hold(self.ticket, Held::Pending(seq));
                    return Read::Pending;
                }
                Crossed::Short { bytes, items } if bytes <= SECRET_MAX_BYTES && items <= 16 => {
                    sizes = ((bytes as usize).max(sizes.0), (items as usize).max(sizes.1));
                }
                Crossed::Short { .. } | Crossed::Unavailable => return Read::Unavailable,
            }
        }
        Read::Unavailable
    }
}

/// `verify` at the `HeadBody` point: the inbound SigV4 check ([`inbound::judge`]), its secret read
/// through the host's `records.secret`.
pub struct Verify;
impl Slot for Verify {
    type In = VerifyIn;
    type Out = IdentifyOut;
    fn call(instance: *mut c_void, input: &VerifyIn, out: &mut IdentifyOut) -> Outcome {
        let Some(s) = inst(instance) else {
            return Outcome::Fault;
        };
        let ticket = input.head.ticket;
        let resume = input.head.flags & FLAG_RESUME != 0;
        // THE SHORT-BUFFER RE-CALL: a fresh call on a ticket whose identity did not fit is served
        // from the identity reached, never by repeating the work.
        // (A fresh call finding a stale PENDING handle drops it: it issues its own.)
        if !ticket.is_none() && !resume {
            if let Some(Held::Reached(subject)) = s.take(ticket) {
                return abi::write_verdict(input, out, VERDICT_IDENTITY, Some(&subject));
            }
        }
        let request = abi::request(input);
        let mut source = HostSecret { s, ticket, resume };
        match inbound::judge(&request, &mut source) {
            Judgement::Pass => abi::write_verdict(input, out, VERDICT_PASS, None),
            Judgement::Reject => abi::write_verdict(input, out, VERDICT_REJECT, None),
            Judgement::Identity(subject) => {
                let outcome = abi::write_verdict(input, out, VERDICT_IDENTITY, Some(&subject));
                if outcome == Outcome::Failed && !ticket.is_none() {
                    s.hold(ticket, Held::Reached(subject));
                }
                outcome
            }
            Judgement::Pending => Outcome::Pending,
            Judgement::NotNow => Outcome::Refused,
        }
    }
}

/// `begin_login`: not served.
pub struct BeginLogin;
impl Slot for BeginLogin {
    type In = BeginLoginIn;
    type Out = BeginLoginOut;
    fn call(_: *mut c_void, _: &BeginLoginIn, _: &mut BeginLoginOut) -> Outcome {
        Outcome::Refused
    }
}

/// `complete_login`: not served.
pub struct CompleteLogin;
impl Slot for CompleteLogin {
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    fn call(_: *mut c_void, _: &CompleteLoginIn, _: &mut IdentifyOut) -> Outcome {
        Outcome::Refused
    }
}

/// `open_outbound`: bind `sigv4`; FAILED carries one `credential: …` / `settings: …` line per
/// finding (ARCHITECT ruling 2026-09-28).
pub struct OpenOutbound;
impl Slot for OpenOutbound {
    type In = OpenOutboundIn;
    type Out = OpenOutboundOut;
    fn call(instance: *mut c_void, input: &OpenOutboundIn, out: &mut OpenOutboundOut) -> Outcome {
        let Some(s) = inst(instance) else {
            return Outcome::Fault;
        };
        let mut env = s
            .open_env
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        env.clear();
        let Some(style) = text(&input.style) else {
            env.error = "settings: no outbound auth style was named".to_string();
            envelope(&mut out.head, &env);
            return Outcome::Refused;
        };
        let opened = style::open_binding(style, blob(&input.credential), blob(&input.settings));
        let outcome = match opened {
            Ok(binding) => {
                out.handle = s.keep(binding);
                Outcome::Ready
            }
            Err(refusals) => {
                env.error = refusals
                    .iter()
                    .map(style::Refusal::line)
                    .collect::<Vec<_>>()
                    .join("\n");
                Outcome::Failed
            }
        };
        envelope(&mut out.head, &env);
        outcome
    }
}

/// `outbound_ready`: always ready — a sigv4 binding never mints.
pub struct OutboundReady;
impl Slot for OutboundReady {
    type In = OutboundReadyIn;
    type Out = OutboundReadyOut;
    fn call(instance: *mut c_void, input: &OutboundReadyIn, out: &mut OutboundReadyOut) -> Outcome {
        let Some(s) = inst(instance) else {
            return Outcome::Fault;
        };
        if s.binding(input.handle).is_none() {
            return Outcome::Refused;
        }
        out.ready = 1;
        Outcome::Ready
    }
}

/// The SigV4 facts of a `fields` call: the walked request's method, host, path, query and sent
/// content type (BUSBAR-1.6.0.md THE DESIGN §6: "SigV4 signs the real method and query of the
/// walked request"); `None` when the host sent no method, host or path.
fn sign_facts<'a>(input: &'a FieldsIn, hash: &'a str) -> Option<SignFacts<'a>> {
    Some(SignFacts {
        method: text(&input.request.method)?,
        host: text(&input.request.authority)?,
        path: text(&input.request.canonical_path)?,
        query: text(&input.request.query).filter(|q| !q.is_empty()),
        content_type: abi::sent_header(input, "content-type"),
        payload_hash: hash,
        timestamp_epoch: input.request.timestamp,
    })
}

/// `fields`: THE ONE PER-REQUEST CALL, both credential modes.
pub struct Fields;
impl Slot for Fields {
    type In = FieldsIn;
    type Out = FieldsOut;
    fn call(instance: *mut c_void, input: &FieldsIn, out: &mut FieldsOut) -> Outcome {
        let Some(s) = inst(instance) else {
            return Outcome::Fault;
        };
        let write = |fields: &[signing::Field], out: &mut FieldsOut| {
            let f: Vec<(&str, &str)> = fields
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            abi::write_fields(input, out, &f, FIELD_FLAGS)
        };
        // The payload hash over the body the host lent at `HeadBody`; none lent is the empty body.
        let hash = crate::sigv4::sha256_hex(blob(&input.body).unwrap_or_default());
        match input.mode {
            MODE_OWN => {
                let Some(b) = s.binding(input.handle) else {
                    return Outcome::Refused;
                };
                sign_into(&b, input, &hash, out, write)
            }
            MODE_PASSTHROUGH => {
                let Some(b) = s.binding(input.handle) else {
                    return Outcome::Refused;
                };
                let caller = blob(&input.caller_credential)
                    .and_then(|c| std::str::from_utf8(c).ok())
                    .unwrap_or("");
                // A FRESH binding, per request: the caller's key varies request to request, so it
                // never enters the operator binding's day-key cache (`signing` module doc).
                let signer =
                    SigV4Binding::new(b.params().clone(), SigningCredential::split(caller));
                sign_into(&signer, input, &hash, out, write)
            }
            _ => Outcome::Refused,
        }
    }
}

#[cfg(test)]
#[path = "tests/verify_door_tests.rs"]
mod verify_door_tests;
