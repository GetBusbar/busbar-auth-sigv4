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
//! * `fields` is the call the binding's transport makes through the host auth handle at the
//!   style's `HeadBody` point (THE DESIGN §6, "Auth points and guest lists"; §11.6): the request is
//!   signed for this attempt, the fields written into the host's buffer, which join the head before
//!   the framer encodes it. It serves BOTH credential modes `sigv4` declares
//!   ([`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]): the operator's own bound
//!   credential ([`busbar_contract::abi::auth::MODE_OWN`], the day-key-cached
//!   `signing::SigV4Binding`), and the caller's verified credential passed per-request
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
//! `busbar-kernel-identity`'s `ingress_sigv4`) are `inbound`, verbatim; `verify` serves them at
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
//!   line is named for the transport to strip (THE DESIGN §6). Every failure is the one REJECT,
//!   the kernel's one opaque 401.
//!
//! NOTHING OF `verify`'S IS CACHED. Every `verify` reads the secret through the host's
//! `records.secret` (the contract SDK's [`VerifyOp::records_secret`]): a `verify` whose read
//! pends answers PENDING on its ticket, and the host re-enters it from the top, where the
//! re-issued handle reads the stored answer. A ticket-less `verify` that needs the read answers
//! REFUSED, and the host submits it on a ticket. Neither the secret nor a verdict outlives the
//! call, so a rotated or revoked credential is judged by the host's answer of the moment.
//!
//! The login pair is not served and answers REFUSED (the tail does not declare `CAP_LOGIN`).
//!
//! THE DOOR is the contract SDK's safe auth kit (`auth_door!(verify_and_outbound: ..)` over
//! `instance::SigV4`, a `VerifyPlugin` and an `OutboundPlugin` over one instance): the kit
//! reads the host's frames, writes the fields and the verdict under the short-buffer rule, calls
//! the host's services and keeps every answer's memory in the answering instance, so this crate is
//! `#![forbid(unsafe_code)]` and holds no per-thread or process-global state (THE DESIGN §2).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod held;
mod inbound;
mod instance;
mod signing;
mod sigv4;
mod style;

use std::borrow::Cow;
use std::task::Poll;
use std::time::{SystemTime, UNIX_EPOCH};

use busbar_contract::abi::auth::{
    AuthPoints, AuthTail, StyleDecl, FACT_INBOUND_ALL_HEADERS, STYLE_CALLER_CREDENTIAL,
    STYLE_NEEDS_HEADERS,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{
    MarkWord, Statement, MARK_WORD_ISSUED_ID_ALPHABET, MARK_WORD_ISSUED_ID_LENGTH,
    MARK_WORD_ISSUED_ID_PREFIX, MARK_WORD_ISSUED_SECRET_ALPHABET, MARK_WORD_ISSUED_SECRET_LENGTH,
};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::{
    carrier, with_credential_kinds, with_tail, Answer, Strip, Verdict, VerifiedIdentity, VerifyOp,
    VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::auth_outbound::{
    outbound_tail, style as declare, with_inbound, Diags, Driven, FieldsAnswer, FieldsView,
    FieldsWriter, Mode, OpenRefusal, OutboundPlugin,
};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::services::CredentialSecret;

use crate::inbound::{Judgement, Read, SecretSource};
use crate::instance::{diag, SigV4, Signed, Who, WARN};
use crate::signing::SignFacts;

/// The flags every field this plugin writes carries: NONE. 1.5.5 sent its credential headers
/// indexable, and an h2 encoder that honoured `FIELD_SENSITIVE` would send them never-indexed —
/// different bytes (ARCHITECT ruling 2026-09-28, Q4: the 1.5.5 bytes win; TODO item 583's
/// sensitive marking is a behaviour change not taken without the owner).
const FIELD_FLAGS: u32 = 0;

/// The one style this plugin serves: it signs the body, so it needs the `HeadBody` point (THE
/// DESIGN, "Auth points and guest lists") and hashes the body itself; it signs the content type
/// the request is sent with, so it needs the header envelope; it serves the caller's credential
/// too.
const STYLE_DECLS: &[StyleDecl] = &[declare(
    style::SIGV4,
    STYLE_CALLER_CREDENTIAL | STYLE_NEEDS_HEADERS,
    AuthPoints::HEAD_BODY,
)];

/// The credential kinds `verify` reads through the host's `records.secret`: the host-held SigV4
/// credentials (a busbar key's AccessKeyId and secret).
const CREDENTIAL_KINDS: &[AbiStr] = &[abi_str(inbound::CREDENTIAL_KIND)];

/// THE AUTH STATEMENT TAIL: the outbound `sigv4` style, and the inbound SigV4 check at the
/// `HeadBody` point (it hashes the body against the signed `x-amz-content-sha256`), reading EVERY
/// header line (the signed set varies per request) and the host-held `sigv4` credentials. No login.
const TAIL: &AuthTail = &with_credential_kinds(
    with_inbound(
        outbound_tail(FACT_INBOUND_ALL_HEADERS, STYLE_DECLS),
        AuthPoints::HEAD_BODY,
    ),
    CREDENTIAL_KINDS,
);

/// One issued-credential shape word mark of `class`.
const fn issued(class: u32, word: &'static str) -> MarkWord {
    MarkWord {
        class,
        _reserved: 0,
        word: abi_str(word),
    }
}

/// The Statement's word marks: the carrier `verify` reads its credential from, and the shape of
/// the `sigv4` credential the host issues for it (1.5.5's AWS long-term key shape: an AccessKeyId
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

/// The diagnostic ids, in [`instance::diag`] order: 1.5.5's catalog codes where the line had one.
const DIAG_IDS: [AbiStr; 1] = [abi_str("auth.sigv4-session-token-invalid-bytes")];

/// The key the `declares` document rides under in the Statement's extensions (busbar #1399's
/// `EXT_DECLARES`, the same word).
const EXT_DECLARES: &str = "declares";

/// This plugin's whole `declares` document (BUSBAR-1.6.0.md l.246).
const DECLARES: &[u8] = include_bytes!("../declares.json");

/// The Statement's extensions: the `declares` document, one entry, encoded as the contract's
/// `extensions::entry` writes it. The SAME BYTES `statement_extensions!` wrote for this one entry
/// (busbar #1399, not at this pin: the macro and `EXT_DECLARES` ride a busbar PR of their own);
/// back onto the macro when it reaches a pin.
const EXTENSIONS: Blob = {
    const BYTES: &[u8] = &extensions::entry::<{ extensions::entry_len(EXT_DECLARES, DECLARES) }>(
        EXT_DECLARES,
        DECLARES,
    );
    Blob {
        ptr: BYTES.as_ptr(),
        len: BYTES.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
};

/// What the plugin states: its name, version, concurrency, diagnostics, marks, extensions and auth
/// tail.
const STATEMENT: Statement = with_tail(
    Statement {
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        mark_words: MARKS.as_ptr(),
        mark_words_len: MARKS.len(),
        extensions: EXTENSIONS,
        ..statement("busbar-auth-sigv4", env!("CARGO_PKG_VERSION"), 1024)
    },
    TAIL,
);

busbar_contract::auth_door!(verify_and_outbound: SigV4, STATEMENT);

/// Wall-clock seconds since the epoch (1970-01-01 UTC) — the clock `tick`'s day-key pre-derivation
/// reads against.
pub(crate) fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The plugin's own settings: none are read; present settings must be a JSON object (none lent
/// reads as empty, and takes none).
fn settings_ok(b: &[u8]) -> bool {
    b.is_empty()
        || matches!(
            serde_json::from_slice::<serde_json::Value>(b),
            Ok(serde_json::Value::Object(_))
        )
}

const SETTINGS_NOT_OBJECT: &str = "busbar-auth-sigv4 settings must be a JSON object";

/// The refusal `open_outbound` answers for a bind that names no style.
const NO_STYLE: &str = "settings: no outbound auth style was named";

/// A request fact as text: UTF-8 and not empty; `None` when the host lent none.
fn fact(b: &[u8]) -> Option<&str> {
    std::str::from_utf8(b).ok().filter(|s| !s.is_empty())
}

/// The value of the first `content-type` line (ASCII case-insensitive) in the header envelope the
/// host lent `fields` (the style declares `STYLE_NEEDS_HEADERS`); `None` when none is sent, or its
/// value is not text.
pub(crate) fn sent_content_type<'a>(
    headers: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Option<&'a str> {
    headers
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(b"content-type"))
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
}

/// The SigV4 facts of a `fields` call: the walked request's method, host, path, query and sent
/// content type (BUSBAR-1.6.0.md THE DESIGN §6: "SigV4 signs the real method and query of the
/// walked request"); `None` when the host sent no method, host or path.
fn sign_facts<'v: 'h, 'h>(view: &FieldsView<'v>, hash: &'h str) -> Option<SignFacts<'h>> {
    Some(SignFacts {
        method: fact(view.method())?,
        host: fact(view.authority())?,
        path: fact(view.path())?,
        query: view.query().and_then(fact),
        content_type: sent_content_type(view.headers()),
        payload_hash: hash,
        timestamp_epoch: view.timestamp(),
    })
}

impl OutboundPlugin for SigV4 {
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        if settings_ok(settings) {
            Ok(())
        } else {
            Err(Refusal::refused(SETTINGS_NOT_OBJECT))
        }
    }

    fn open(settings: &[u8], _: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        if !settings_ok(settings) {
            // Settings `open` refuses are FAILED with the reason (the lifecycle's rule, and the
            // inbound conformance script's).
            return Err(Refusal::failed(SETTINGS_NOT_OBJECT));
        }
        Ok(SigV4::new(generation))
    }

    /// Bind `sigv4`; FAILED carries one `credential: …` / `settings: …` line per finding
    /// (ARCHITECT ruling 2026-09-28).
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
        // The payload hash over the body the host lent at `HeadBody`; none lent is the empty body.
        let hash = crate::sigv4::sha256_hex(view.body().unwrap_or_default());
        let who = match view.mode() {
            Mode::Own => Who::Own,
            Mode::Passthrough => Who::Caller(view.caller_credential()),
        };
        Poll::Ready(
            match self.sign(view.handle(), who, sign_facts(view, &hash)) {
                None => FieldsAnswer::Refused,
                Some(Signed::NoFacts) => FieldsAnswer::Failed(Cow::Borrowed("")),
                Some(Signed::Fields { fields, note }) => {
                    for (name, value) in &fields {
                        out.push(name.as_bytes(), value.as_bytes(), FIELD_FLAGS);
                    }
                    // The signer's line, as 1.5.5 logged it on each such request.
                    if let Some(note) = note {
                        out.diag(diag::SESSION_TOKEN_INVALID_BYTES, WARN, note);
                    }
                    FieldsAnswer::Ready
                }
            },
        )
    }

    /// Always ready — a sigv4 binding never mints — for a handle this generation holds.
    fn outbound_ready(&self, handle: u64) -> bool {
        self.binding(handle).is_some()
    }

    /// The new generation.
    fn refresh(&self, settings: &[u8], _: &[&[u8]], generation: u64) -> Result<(), Refusal> {
        if !settings_ok(settings) {
            return Err(Refusal::failed(SETTINGS_NOT_OBJECT));
        }
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
            Poll::Ready(Err(_)) => Read::Unavailable,
        }
    }
}

impl VerifyPlugin for SigV4 {
    fn open(settings: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        if !settings_ok(settings) {
            return Err(SETTINGS_NOT_OBJECT);
        }
        Ok(SigV4::new(0))
    }

    /// `verify` at the `HeadBody` point: the inbound SigV4 check (`inbound::judge`), its secret
    /// read through the host's `records.secret` on every call.
    fn verify_ticketed(&self, view: &VerifyView<'_>, op: &VerifyOp) -> Poll<Answer> {
        let request = inbound::Request {
            method: view.method(),
            path: view.path(),
            query: view.query(),
            lines: view.lines().collect(),
            body: view.body(),
            now: view.timestamp(),
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
        // THE CREDENTIAL LINE, named whatever the verdict (THE DESIGN §6, "Auth points and guest
        // lists"): a SigV4 `authorization` line is this plugin's, and the plane never sees it.
        if inbound::carries_sigv4(&request) {
            answer.strips = vec![Strip::field(inbound::AUTHORIZATION)];
        }
        Poll::Ready(answer)
    }
}
