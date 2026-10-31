// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-sigv4 — AWS SigV4, outbound and inbound, one auth-kind plugin
//!
//! AWS Signature Version 4 is its own mechanism — a per-request signature over the request, not a
//! credential carried verbatim — and lives in its own plugin, `busbar-auth-sigv4`, loaded when
//! some provider uses `auth: sigv4`. It speaks the auth kind's memory ABI
//! (`busbar_contract::abi::auth`, v3):
//!
//! * `open_outbound` binds the style to its credential and settings and answers a handle
//!   (generation data). It never touches the network.
//! * `fields` is the call the binding's transport makes through the host auth handle at the
//!   style's `HeadBody` point: the request is
//!   signed for this attempt, the fields written into the host's buffer, which join the head before
//!   the framer encodes it. It serves BOTH credential modes `sigv4` declares
//!   ([`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]): the operator's own bound
//!   credential ([`busbar_contract::abi::auth::MODE_OWN`], the day-key-cached
//!   `signing::SigV4Binding`), and the caller's verified credential passed per-request
//!   ([`busbar_contract::abi::auth::MODE_PASSTHROUGH`]). A credential SOURCE is not a
//!   mechanism, so there is no separate `caller-credential` style; a passthrough binding is built
//!   fresh, per request, from the caller's credential, exactly the code path the
//!   operator-credential binding signs with, minus the day-key cache (the caller's key varies
//!   request to request, so there is nothing to hold ahead of time).
//!   `fields` never answers READY with no field: own mode on a binding opened with
//!   no credential (passthrough-only), a passthrough with no caller credential or a malformed one,
//!   and a signature whose `Authorization` value no header may carry each FAIL with the reason —
//!   the request is never sent unsigned. A malformed operator credential never gets that far:
//!   `open_outbound` refuses it, one `credential: ...` line per finding.
//! * `outbound_ready` is the handle's `ready` fact for the health prober: true for a handle this
//!   generation holds — a sigv4 binding never mints, so there is nothing else to wait for.
//! * `tick` pre-derives the SigV4 day keys ahead of UTC midnight.
//!
//! ## Inbound: SigV4 verification
//!
//! The inbound SigV4 check reads through a host store service, keeping the dummy-secret timing
//! equivalence for an unknown AccessKeyId. It is [`inbound`]; `verify` serves it at
//! the `HeadBody` point (`CAP_INBOUND`, every header line, the body):
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
//!   SigV4 verdict), no replay claim, no credential. Whatever the verdict, a SigV4 `authorization`
//!   line is named for the transport to strip. Every failure is the one REJECT,
//!   the kernel's one opaque 401; the plugin's own log names its reason (module `sigv4`), never
//!   the signature, the secret or a token.
//!
//! Nothing of `verify`'s is cached. Every `verify` reads the secret through the host's
//! `records.secret` (the contract SDK's `VerifyOp::records_secret`): a `verify` whose read pends
//! answers PENDING on its ticket, and the host re-enters it from the top, where the re-issued handle
//! reads the stored answer. A ticket-less `verify` that needs the read answers REFUSED, and the host
//! submits it on a ticket. Neither the secret nor a verdict outlives the call.
//!
//! The login pair is not served and answers REFUSED (the tail does not declare `CAP_LOGIN`).
//!
//! The door is the contract SDK's safe auth kit (`auth_door!(verify_and_outbound: ..)` over
//! `instance::SigV4`, a `VerifyPlugin` and an `OutboundPlugin` over one instance): the kit reads the
//! host's frames, writes the fields and the verdict under the short-buffer rule, calls the host's
//! services and keeps every answer's memory in the answering instance. So this crate is
//! `#![forbid(unsafe_code)]` and holds no per-thread or process-global state. The one exported symbol is the sibling `-plugin` cdylib's.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod held;
pub mod inbound;
mod instance;
mod signing;
mod sigv4;
mod style;

use std::mem::size_of;
use std::task::Poll;
use std::time::{SystemTime, UNIX_EPOCH};

use busbar_contract::abi::auth::{
    AuthTail, StyleDecl, CAP_INBOUND, CAP_OUTBOUND, FACT_INBOUND_ALL_HEADERS,
    FACT_READS_CREDENTIALS, FIELD_SENSITIVE, LOGIN_KIND_NONE, POINT_HEAD_BODY,
    STYLE_CALLER_CREDENTIAL, STYLE_NEEDS_HEADERS,
};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{
    KindTailHead, MarkWord, Statement, MARK_WORD_ISSUED_ID_ALPHABET, MARK_WORD_ISSUED_ID_LENGTH,
    MARK_WORD_ISSUED_ID_PREFIX, MARK_WORD_ISSUED_SECRET_ALPHABET, MARK_WORD_ISSUED_SECRET_LENGTH,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::{
    carrier, with_tail, Answer, Strip, Verdict, VerifiedIdentity, VerifyOp, VerifyPlugin,
    VerifyView,
};
use busbar_contract::abi::sdk::auth_outbound::{
    Diags, Driven, FieldsAnswer, FieldsView, FieldsWriter, Mode, OpenRefusal, OutboundPlugin,
};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::life::{self, Refusal};
use busbar_contract::abi::sdk::services::{CredentialSecret, ServiceError};

use crate::inbound::{Judgement, Read, SecretSource};
use crate::instance::{SigV4, Signed, Who};
use crate::signing::SignFacts;

/// The fields that carry credential material: `FIELD_SENSITIVE` (an h2 encoder sends them
/// never-indexed; lead-signed 2026-10-30). The date and the payload hash carry none.
const SENSITIVE_FIELDS: [&str; 2] = ["authorization", "x-amz-security-token"];

/// The flags field `name` is written with.
fn field_flags(name: &str) -> u32 {
    if SENSITIVE_FIELDS.contains(&name) {
        FIELD_SENSITIVE
    } else {
        0
    }
}

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

/// One issued-credential shape word mark of `class`.
const fn issued(class: u32, word: &'static str) -> MarkWord {
    MarkWord {
        class,
        _reserved: 0,
        word: abi_str(word),
    }
}

/// The Statement's word marks: the carrier `verify` reads its credential from, and the shape of
/// the `sigv4` credential the host issues for it (the AWS long-term key shape: an AccessKeyId
/// of `AKIA` then 16 of [A-Z0-9], 20 in all, and a 40-character secret access key over the base64
/// alphabet). The host draws every symbol from the OS CSPRNG over these alphabets and names no
/// format of its own.
const MARKS: [MarkWord; 6] = [
    carrier(inbound::AUTHORIZATION),
    issued(MARK_WORD_ISSUED_ID_PREFIX, "AKIA"),
    issued(MARK_WORD_ISSUED_ID_LENGTH, "20"),
    issued(
        MARK_WORD_ISSUED_ID_ALPHABET,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    ),
    issued(MARK_WORD_ISSUED_SECRET_LENGTH, "40"),
    issued(
        MARK_WORD_ISSUED_SECRET_ALPHABET,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    ),
];

/// What the plugin states: its name, version, concurrency, marks and auth tail. It states no
/// diagnostic ids (a credential that cannot sign is refused at open, or its request FAILS with the
/// reason; nothing is noted beside a request sent unsigned).
const STATEMENT: Statement = with_tail(
    statement("busbar-auth-sigv4", env!("CARGO_PKG_VERSION"), 1024).with_mark_words(&MARKS),
    TAIL,
);

busbar_contract::auth_door!(verify_and_outbound: SigV4, STATEMENT);

/// THE COMPILED-IN ENTRY a composition root's `auths` row names: the door at
/// `compiled_in::door::door`, the same [`door`] the dropped-in build (the sibling `-plugin`
/// cdylib) exports (compiled-in = dropped-in).
pub mod compiled_in {
    /// The door and its `MACRO_DOOR` (the `plugin_door!` door a linked table names).
    pub mod door {
        pub use crate::{door, MACRO_DOOR};
    }
}

/// Wall-clock seconds since the epoch (1970-01-01 UTC) — the clock `tick`'s day-key pre-derivation
/// reads against.
pub(crate) fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The plugin-level settings `validate`, `open` and `refresh` answer alike: a JSON object (none
/// lent reads as `{}`) naming only the style's own keys (the host opens the instance over the
/// binding's settings). Every other key is refused by name, one `settings: ...` line each, and a
/// `service` or `region` present is checked as the bind checks it (`settings.<key>: ...`).
fn plugin_settings(settings: &[u8]) -> Result<(), Refusal> {
    let m = life::settings_object(settings)?;
    let lines: Vec<String> = style::unknown_keys(&m)
        .iter()
        .chain(style::scope_findings(&m).iter())
        .map(style::Refusal::line)
        .collect();
    if lines.is_empty() {
        Ok(())
    } else {
        Err(Refusal::failed(lines.join("\n")))
    }
}

/// `VerifyPlugin::open`'s static refusal (the combined door opens through `OutboundPlugin::open`,
/// which names each key).
const SETTINGS_REFUSED: &str = "settings: not a JSON object of the sigv4 style's keys";

/// The refusal `open_outbound` answers for a bind that names no style.
const NO_STYLE: &str = "settings: no outbound auth style was named";

/// The reasons `fields` answers FAILED with when a request fact the host lent cannot be signed,
/// one per fact and fault: the request is never sent unsigned, nor signed over facts it is not
/// sent with.
const NO_METHOD: &str = "sigv4 cannot sign: the host lent no method";
const METHOD_NOT_UTF8: &str = "sigv4 cannot sign: the method is not UTF-8";
const NO_AUTHORITY: &str = "sigv4 cannot sign: the host lent no authority";
const AUTHORITY_NOT_UTF8: &str = "sigv4 cannot sign: the authority is not UTF-8";
const NO_PATH: &str = "sigv4 cannot sign: the host lent no path";
const PATH_NOT_UTF8: &str = "sigv4 cannot sign: the path is not UTF-8";
const QUERY_NOT_UTF8: &str = "sigv4 cannot sign: the query is not UTF-8";
const CONTENT_TYPE_NOT_UTF8: &str = "sigv4 cannot sign: the content-type value is not UTF-8";
const NO_BODY: &str = "sigv4 cannot sign: the host lent no body";

/// A request fact as text: `absent` when the host lent none (empty), `not_utf8` when it is not
/// text.
fn fact<'a>(
    b: &'a [u8],
    absent: &'static str,
    not_utf8: &'static str,
) -> Result<&'a str, &'static str> {
    if b.is_empty() {
        return Err(absent);
    }
    std::str::from_utf8(b).map_err(|_| not_utf8)
}

/// The value of the first `content-type` line (ASCII case-insensitive) in the header envelope the
/// host lent `fields` (the style declares `STYLE_NEEDS_HEADERS`); `None` when none is sent.
///
/// # Errors
///
/// [`CONTENT_TYPE_NOT_UTF8`] when the value sent is not text: it is sent, so it cannot go unsigned.
pub(crate) fn sent_content_type<'a>(
    headers: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Option<&'a str>, &'static str> {
    headers
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(b"content-type"))
        .map(|(_, v)| std::str::from_utf8(v).map_err(|_| CONTENT_TYPE_NOT_UTF8))
        .transpose()
}

/// The reason `fields` answers FAILED with when an `x-amz-*` line the request is sent with is not
/// UTF-8: AWS signs every one, and this one cannot be.
const AMZ_NOT_UTF8: &str = "sigv4 cannot sign: an x-amz-* line's value is not UTF-8";

/// Every `x-amz-*` line in the header envelope the host lent `fields`, in order (all of them are
/// signed); `Err` when one is not text.
fn sent_amz_headers<'a>(view: &FieldsView<'a>) -> Result<Vec<(&'a str, &'a str)>, &'static str> {
    let mut out = Vec::new();
    for (name, value) in view.headers() {
        if name.len() > 6 && name[..6].eq_ignore_ascii_case(b"x-amz-") {
            match (std::str::from_utf8(name), std::str::from_utf8(value)) {
                (Ok(n), Ok(v)) => out.push((n, v)),
                _ => return Err(AMZ_NOT_UTF8),
            }
        }
    }
    Ok(out)
}

/// The SigV4 facts of a `fields` call: the walked request's method, host, path, query, sent
/// content type and sent `x-amz-*` lines (SigV4 signs the real method and query of the
/// walked request); `Err` names why the facts the host lent cannot be signed.
fn sign_facts<'a>(
    view: &FieldsView<'a>,
    amz_headers: &'a [(&'a str, &'a str)],
    hash: &'a str,
) -> Result<SignFacts<'a>, &'static str> {
    let query = match view.query().map(std::str::from_utf8) {
        None => None,
        Some(Ok(q)) => Some(q).filter(|q| !q.is_empty()),
        Some(Err(_)) => return Err(QUERY_NOT_UTF8),
    };
    let facts = SignFacts {
        method: fact(view.method(), NO_METHOD, METHOD_NOT_UTF8)?,
        host: fact(view.authority(), NO_AUTHORITY, AUTHORITY_NOT_UTF8)?,
        path: fact(view.path(), NO_PATH, PATH_NOT_UTF8)?,
        query,
        content_type: sent_content_type(view.headers())?,
        amz_headers,
        payload_hash: hash,
        timestamp_epoch: view.timestamp(),
    };
    // The host lends the body at `HeadBody`, an empty one included: none lent cannot be bound to a
    // payload hash, and is never signed as the empty body.
    if view.body().is_none() {
        return Err(NO_BODY);
    }
    Ok(facts)
}

impl OutboundPlugin for SigV4 {
    /// `validate`: what `open` and `refresh` refuse ([`plugin_settings`]), FAILED.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        plugin_settings(settings)
    }

    fn open(settings: &[u8], _: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        plugin_settings(settings)?;
        Ok(SigV4::new(generation))
    }

    /// Bind `sigv4`; FAILED carries one `credential: …` / `settings: …` line per finding.
    fn open_outbound(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
        _: Option<&Host>,
        _: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        if style.is_empty() {
            return Err(OpenRefusal::new(NO_STYLE));
        }
        match style::open_binding(style, credential, settings) {
            Ok(binding) => Ok(self.keep(binding)),
            Err(refusals) => {
                let mut lines = refusals.iter().map(style::Refusal::line);
                let first = OpenRefusal::new(lines.next().unwrap_or_default());
                Err(lines.fold(first, |r, line| r.and(line)))
            }
        }
    }

    /// THE ONE PER-REQUEST CALL, both credential modes.
    fn fields(
        &self,
        view: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        _: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        // The payload hash over the body the host lent at `HeadBody` (none lent FAILS, in
        // `sign_facts`).
        let hash = crate::sigv4::sha256_hex(view.body().unwrap_or_default());
        let amz = sent_amz_headers(view);
        let who = match view.mode() {
            Mode::Own => Who::Own,
            Mode::Passthrough => Who::Caller(view.caller_credential()),
        };
        Poll::Ready(
            match self.sign(
                view.handle(),
                who,
                amz.as_deref()
                    .map_err(|e| *e)
                    .and_then(|amz| sign_facts(view, amz, &hash)),
            ) {
                None => FieldsAnswer::Refused,
                Some(Signed::Failed(reason)) => FieldsAnswer::Failed(reason),
                Some(Signed::Fields(fields)) => {
                    for (name, value) in &fields {
                        out.push(name.as_bytes(), value.as_bytes(), field_flags(name));
                    }
                    FieldsAnswer::Ready
                }
            },
        )
    }

    /// True for a handle this generation holds, false for any other: a sigv4 binding never mints,
    /// so a held handle has nothing to wait for (whether a request can be signed is `fields`'
    /// answer, per request).
    fn outbound_ready(&self, handle: u64) -> bool {
        self.binding(handle).is_some()
    }

    /// The new generation.
    fn refresh(&self, settings: &[u8], _: &[&[u8]], generation: u64) -> Result<(), Refusal> {
        plugin_settings(settings)?;
        self.set_generation(generation);
        Ok(())
    }

    /// The generation's handles go.
    fn retire(&self, generation: u64) {
        SigV4::retire(self, generation);
    }

    /// Pre-derive the SigV4 day keys ahead of UTC midnight.
    fn tick(&self, now_ns: u64, _: Option<&Host>, _: Ticket, _: &mut Diags) -> u64 {
        SigV4::tick(self, now_ns)
    }

    /// No driver ticket is held, and nothing waits on one: READY.
    fn drive(&self, _: Option<&Host>, _: Ticket, _: &mut Diags) -> Driven {
        Driven::Ready
    }
}

/// The secret source `verify` reads through: the host's `records.secret`, on the op's ticket, on
/// every call.
impl SecretSource for &VerifyOp {
    type Secret = CredentialSecret;

    fn read(&mut self, kind: &str, id: &str) -> Read<CredentialSecret> {
        match self.records_secret(kind, id) {
            // On no ticket too, with no crossing: the kit answers that `verify` REFUSED and the
            // host submits it on a ticket.
            Poll::Pending => Read::Pending,
            Poll::Ready(Ok(secret)) => {
                let live = secret.live();
                Read::Secret { secret, live }
            }
            Poll::Ready(Err(e)) => Read::Unavailable(match e {
                ServiceError::Unserved => "unserved",
                ServiceError::Declined(_) => "declined",
                ServiceError::Broken => "broken",
                ServiceError::Short { .. } => "short",
            }),
        }
    }
}

impl VerifyPlugin for SigV4 {
    /// The kit opens the one instance through [`OutboundPlugin::open`]; this builds the same.
    fn open(settings: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        plugin_settings(settings).map_err(|_| SETTINGS_REFUSED)?;
        Ok(SigV4::new(0))
    }

    /// `verify` at the `HeadBody` point: the inbound SigV4 check ([`inbound::judge`]), its secret
    /// read through the host's `records.secret` on every call.
    fn verify_ticketed(&self, view: &VerifyView<'_>, op: &VerifyOp) -> Poll<Answer> {
        let request = inbound::Request {
            method: view.method(),
            path: view.path(),
            query: view.query(),
            lines: view.lines().collect(),
            body: view.body(),
            now: view.timestamp(),
            authority: view.authority(),
        };
        let mut source = op;
        let verdict = match inbound::judge(&request, &mut source) {
            Judgement::Pass => Verdict::Pass,
            Judgement::Reject => Verdict::Reject,
            Judgement::Identity(subject) => Verdict::Identity(VerifiedIdentity {
                subject,
                ..VerifiedIdentity::default()
            }),
            Judgement::Pending => return Poll::Pending,
        };
        let mut answer = Answer::from(verdict);
        // The credential line is named whatever the verdict: a SigV4 `authorization` line is this plugin's, and the plane never sees it.
        if inbound::carries_sigv4(&request) {
            answer.strips = vec![Strip::field(inbound::AUTHORIZATION)];
        }
        Poll::Ready(answer)
    }
}

#[cfg(test)]
#[path = "tests/policy_tests.rs"]
mod policy_tests;
