// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOUNDARY: every raw pointer this plugin reads or writes, in one module.
//!
//! The auth kind has no typed SDK wrapper yet (KERNEL<>PLUGINS ABI-b3, `busbar-contract/src/abi/sdk/`),
//! so the reads of the host's `in` structs, the writes into the host's field buffer, the instance
//! pointer and the host tables are done here, each `unsafe` block stating the contract it relies
//! on. Everything outside this module is safe code. When ABI-b3 lands the auth wrappers, this module
//! is what moves into `abi/sdk/` and the crate becomes `#![forbid(unsafe_code)]` (BUSBAR-1.6.0.md THE DESIGN, §2).

#![allow(unsafe_code)]

use std::ffi::c_void;

use std::mem::size_of;

use busbar_contract::abi::auth::{
    FieldSpan, FieldsIn, FieldsOut, IdentifyOut, VerifyIn, DECISION_CONTINUE, DECISION_STOP,
    SPAN_ABSENT, VERDICT_REJECT,
};
use busbar_contract::abi::host::service::{
    check_records_secret, op, HostSlots, ItemSpan, RecordsSecretIn, ServiceBufs, ServiceHead,
    ServiceOut, SECRET_LIVE,
};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::check::Filled;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables};
use zeroize::Zeroizing;

use crate::inbound::Request;

/// Borrowed bytes of an [`AbiStr`] the host handed in for this call; `None` when absent.
pub(crate) fn text(s: &AbiStr) -> Option<&str> {
    if s.ptr.is_null() {
        return None;
    }
    // SAFETY: a non-NULL `AbiStr` in a host `in` addresses `len` readable bytes for the call (the
    // mechanism's call convention); the borrow does not outlive the `in` it was read from.
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    std::str::from_utf8(bytes).ok()
}

/// Borrowed bytes of a [`Blob`] the host handed in for this call; `None` when absent.
pub(crate) fn blob(b: &Blob) -> Option<&[u8]> {
    if b.ptr.is_null() || b.fmt == BLOB_ABSENT {
        return None;
    }
    // SAFETY: a present `Blob` in a host `in` addresses `len` readable bytes for the call.
    Some(unsafe { std::slice::from_raw_parts(b.ptr, b.len) })
}

/// An [`AbiStr`] over bytes this plugin holds.
pub(crate) fn abi(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The instance behind the pointer `open` answered.
pub(crate) fn instance<'a, T>(p: *mut c_void) -> Option<&'a T> {
    // SAFETY: a non-NULL instance pointer is the `Box::into_raw` of this plugin's `open`, live until
    // `close` (the host never calls an instance after `close`).
    unsafe { p.cast::<T>().as_ref() }
}

/// Hand `value` to the host as the instance pointer.
pub(crate) fn into_instance<T>(value: Box<T>) -> *mut c_void {
    Box::into_raw(value).cast()
}

/// Take the instance back at `close` and drop it.
pub(crate) fn drop_instance<T>(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: `close` is the instance's last call; the pointer came from `into_instance`.
    drop(unsafe { Box::from_raw(p.cast::<T>()) });
}

/// Write `fields` into the host's field buffer and array (`FieldsIn::field_buf`/`fields`) under
/// the SHORT-BUFFER rule: when they do not fit, write nothing and answer FAILED with the FULL sizes.
pub(crate) fn write_fields(
    input: &FieldsIn,
    out: &mut FieldsOut,
    fields: &[(&str, &str)],
    flags: u32,
) -> Outcome {
    let bytes: usize = fields.iter().map(|(n, v)| n.len() + v.len()).sum();
    let count = fields.len();
    let fits = count <= input.fields_cap as usize
        && bytes <= input.field_buf_cap
        && (count == 0 || (!input.fields.is_null() && !input.field_buf.is_null()));
    if !fits {
        out.needed_fields = u32::try_from(count).unwrap_or(u32::MAX);
        out.needed_bytes = bytes as u64;
        return Outcome::Failed;
    }
    let mut at = 0_usize;
    for (i, (name, value)) in fields.iter().enumerate() {
        let name_span = put(input, &mut at, name.as_bytes());
        let value_span = put(input, &mut at, value.as_bytes());
        let span = FieldSpan {
            name: name_span,
            value: value_span,
            flags,
            _reserved: 0,
        };
        // SAFETY: `fields` addresses `fields_cap >= count > i` writable spans for the call.
        unsafe { input.fields.add(i).write_unaligned(span) };
    }
    out.fields_len = count as u32;
    Outcome::Ready
}

/// The value of the first `name` line (ASCII case-insensitive) in the header envelope the host
/// lent `fields` (the style declares `STYLE_NEEDS_HEADERS`); `None` when none is sent, the
/// envelope is absent, or the value is not text.
pub(crate) fn sent_header<'a>(input: &'a FieldsIn, name: &str) -> Option<&'a str> {
    if input.headers.is_null() || input.headers_len == 0 {
        return None;
    }
    // SAFETY: a non-NULL `headers` in the host's `FieldsIn` addresses `headers_len` named values
    // for the call (the auth ABI's `FieldsIn::headers`); the borrow does not outlive the `in`.
    let all = unsafe { std::slice::from_raw_parts(input.headers, input.headers_len) };
    all.iter()
        .find(|h| raw(&h.name).is_some_and(|n| n.eq_ignore_ascii_case(name.as_bytes())))
        .and_then(|h| lent(&h.value))
        .and_then(|v| std::str::from_utf8(v).ok())
}

/// Copy `b` into the host's field buffer at `*at`, answering its span.
fn put(input: &FieldsIn, at: &mut usize, b: &[u8]) -> Span {
    let span = Span {
        offset: *at as u32,
        len: b.len() as u32,
    };
    // SAFETY: `write_fields` checked the whole write fits `field_buf_cap`, and `field_buf` addresses
    // that many writable bytes for the call; `b` is this plugin's own memory, not overlapping it.
    unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), input.field_buf.add(*at), b.len()) };
    *at += b.len();
    span
}

// ── verify: the request the host lent, and the answer written into the host's buffers ─────────

/// The bytes `ptr`/`len` address for the call: `None` for NULL with a length; NULL with none is
/// the empty slice.
fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return (len == 0).then_some(&[][..]);
    }
    // SAFETY: a non-NULL range in a host `in` addresses `len` readable bytes for the call (the
    // mechanism's call convention); the borrow does not outlive the `in` it was read from.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// A string the host handed in, raw; `None` when absent (NULL).
fn raw(s: &AbiStr) -> Option<&[u8]> {
    if s.ptr.is_null() {
        return None;
    }
    bytes(s.ptr, s.len)
}

/// A blob the host handed in, raw; `None` when absent ([`BLOB_ABSENT`], or NULL with a length).
fn lent(b: &Blob) -> Option<&[u8]> {
    if b.fmt == BLOB_ABSENT {
        return None;
    }
    bytes(b.ptr, b.len)
}

/// `verify`'s request as [`crate::inbound`] reads it: method, path and query raw as received,
/// every field line in order (one whose name or value the host did not lend is left out), the body
/// the host lent at `HeadBody`, and the host's clock reading.
pub(crate) fn request(input: &VerifyIn) -> Request<'_> {
    let lines = if input.lines.is_null() || input.lines_len == 0 {
        Vec::new()
    } else {
        // SAFETY: a non-NULL `lines` in the host's `VerifyIn` addresses `lines_len` field lines
        // for the call.
        let all = unsafe { std::slice::from_raw_parts(input.lines, input.lines_len) };
        all.iter()
            .filter_map(|l| Some((raw(&l.name)?, lent(&l.value)?)))
            .collect()
    };
    Request {
        method: raw(&input.request.method).unwrap_or_default(),
        path: raw(&input.request.canonical_path).unwrap_or_default(),
        query: raw(&input.request.query),
        lines,
        body: lent(&input.body),
        now: input.request.timestamp,
    }
}

/// An absent span.
const ABSENT: Span = Span {
    offset: SPAN_ABSENT,
    len: 0,
};

/// Write `verify`'s answer: `verdict` (with its default decision: STOP for a reject, CONTINUE
/// otherwise), no strips, and for an identity its `subject`, copied into the host's identity buffer
/// with every other identity field absent (no TTL, no replay claim, no credential). When the
/// subject does not fit, the SHORT answer: FAILED with `needed_bytes` and nothing written.
pub(crate) fn write_verdict(
    input: &VerifyIn,
    out: &mut IdentifyOut,
    verdict: u32,
    subject: Option<&str>,
) -> Outcome {
    out.needed_bytes = 0;
    out.needed_groups = 0;
    out.needed_strip = 0;
    if let Some(subject) = subject {
        let buf = input.out_buf;
        if subject.len() > buf.buf_cap || buf.buf.is_null() || subject.len() > u32::MAX as usize {
            out.needed_bytes = subject.len() as u64;
            return Outcome::Failed;
        }
        // SAFETY: `out_buf.buf` addresses `buf_cap >= subject.len()` writable bytes for the call;
        // `subject` is this plugin's own memory, not overlapping it.
        unsafe { std::ptr::copy_nonoverlapping(subject.as_ptr(), buf.buf, subject.len()) };
        let id = &mut out.identity;
        id.subject = Span {
            offset: 0,
            len: subject.len() as u32,
        };
        (id.key_id, id.key_name, id.user, id.provider, id.name) =
            (ABSENT, ABSENT, ABSENT, ABSENT, ABSENT);
        (id.claims, id.claims_fmt) = (ABSENT, BLOB_ABSENT);
        (id.flags, id.ttl_secs, id.groups_len) = (0, 0, 0);
        (id.replay_key, id.replay_ttl_secs, id.credential) = (ABSENT, 0, ABSENT);
    }
    out.decision = if verdict == VERDICT_REJECT {
        DECISION_STOP
    } else {
        DECISION_CONTINUE
    };
    out.strip_len = 0;
    out.verdict = verdict;
    Outcome::Ready
}

// ── the host services: `records.secret` ──────────────────────────────────────────────────────

/// The host services table `open` handed the instance, and the context every call is made with.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Host {
    ctx: HostCtx,
    table: *const HostSlots,
}

// SAFETY: the table is the host's static and the context the host's per-instance state; the host
// states both are callable from any thread for the instance's life (`abi/host/service.rs`).
unsafe impl Send for Host {}
// SAFETY: as above.
unsafe impl Sync for Host {}

/// One `records.secret` crossing's answer.
pub(crate) enum Crossed {
    /// READY: the secret (span `0`), and whether it is live.
    Secret(Zeroizing<Vec<u8>>, bool),
    /// The host holds the call on the handle's ticket.
    Pending,
    /// The buffers were short: re-call ONCE, same handle, with at least these.
    Short { bytes: u64, items: u64 },
    /// No slot, declined, or an answer that broke the service's rules.
    Unavailable,
}

impl Host {
    /// The host services in the tables `open` was handed; `None` when there are none.
    pub(crate) fn of(tables: *const HostTables) -> Option<Self> {
        if tables.is_null() {
            return None;
        }
        // SAFETY: a non-NULL `OpenIn.host` addresses the host's `HostTables` for the call; it is
        // read whole only when its stated size covers the layout this plugin knows.
        let size = unsafe { std::ptr::addr_of!((*tables).size).read_unaligned() };
        if (size as usize) < size_of::<HostTables>() {
            return None;
        }
        // SAFETY: as above, the size covers the whole struct.
        let t = unsafe { tables.read_unaligned() };
        (!t.services.is_null()).then_some(Self {
            ctx: t.ctx,
            table: t.services,
        })
    }

    /// The host's `records.secret` slot, when its table is long enough to hold one and fills it.
    fn records_secret_slot(&self) -> Option<busbar_contract::abi::host::service::ServiceFn> {
        // SAFETY: `table` is the host's live table, non-NULL by construction, its head read first.
        let slots = unsafe { std::ptr::addr_of!((*self.table).slots).read_unaligned() };
        if slots <= op::RECORDS_SECRET {
            return None;
        }
        // SAFETY: `slots` covers `records_secret`, so the table holds it.
        unsafe { std::ptr::addr_of!((*self.table).records_secret).read_unaligned() }
    }

    /// `records.secret`: the secret of credential `id` of `kind`, under `handle`, written into a
    /// buffer of `cap` bytes and `items` spans this plugin owns (wiped on drop). The answer is
    /// judged by the service's own check before it is read.
    pub(crate) fn records_secret(
        &self,
        handle: CompletionHandle,
        kind: &str,
        id: &str,
        (cap, items): (usize, usize),
    ) -> Crossed {
        let Some(slot) = self.records_secret_slot() else {
            return Crossed::Unavailable;
        };
        let mut buf = Zeroizing::new(vec![0_u8; cap]);
        let mut spans = vec![
            ItemSpan {
                key: ABSENT,
                value: ABSENT,
            };
            items
        ];
        let input = RecordsSecretIn {
            head: ServiceHead {
                size: size_of::<RecordsSecretIn>() as u32,
                op: op::RECORDS_SECRET,
                handle,
            },
            kind: abi(kind),
            id: abi(id),
            into: ServiceBufs {
                buf: buf.as_mut_ptr(),
                cap: buf.len(),
                spans: spans.as_mut_ptr(),
                spans_cap: spans.len(),
            },
        };
        let mut out = ServiceOut {
            size: size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(Outcome::Fault),
            _reserved: [0; 3],
            value: 0,
            len: 0,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        };
        let ret = slot(
            self.ctx,
            std::ptr::from_ref(&input).cast::<c_void>(),
            &mut out,
        );
        let Ok(filled) = check_records_secret(&input, ret, &out) else {
            return Crossed::Unavailable;
        };
        match (ret.outcome(), filled) {
            (Outcome::Ready, _) => {
                // The check held `items` within the spans and every span inside `len`; READY writes
                // the secret into span `0`, and one without it broke the rule.
                let Some(s) = spans
                    .get(..out.items as usize)
                    .and_then(<[ItemSpan]>::first)
                else {
                    return Crossed::Unavailable;
                };
                if s.value.offset == SPAN_ABSENT {
                    return Crossed::Unavailable;
                }
                let at = s.value.offset as usize;
                let Some(secret) = buf.get(at..at + s.value.len as usize) else {
                    return Crossed::Unavailable;
                };
                Crossed::Secret(Zeroizing::new(secret.to_vec()), out.value == SECRET_LIVE)
            }
            (Outcome::Pending, _) => Crossed::Pending,
            (Outcome::Failed, Filled::Short) => Crossed::Short {
                bytes: out.needed_bytes,
                items: out.needed_items,
            },
            _ => Crossed::Unavailable,
        }
    }
}

/// An all-zero `in` (the unit tests build frames as a host does).
#[cfg(test)]
pub(crate) fn zeroed_in<T: busbar_contract::abi::sdk::door::AbiIn>() -> T {
    // SAFETY: `AbiIn` promises every bit pattern, all-zero included, is a valid value.
    unsafe { std::mem::zeroed() }
}

/// An all-zero `out`.
#[cfg(test)]
pub(crate) fn zeroed_out<T: busbar_contract::abi::sdk::door::AbiOut>() -> T {
    // SAFETY: `AbiOut` promises every bit pattern, all-zero included, is a valid value.
    unsafe { std::mem::zeroed() }
}
