// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `verify` SLOT, through the door's own table as a host calls it (moved here from the logic
//! crate's `src/tests/verify_door_tests.rs`: that crate forbids `unsafe`, and playing the host
//! needs it): an instance opened over a host table whose `records.secret` serves one live
//! credential, one that is not live, and the fixed dummy (not live) for any other id; the tail and
//! Statement it states; every answer judged by the kind's own `check_identify`.

mod frames;

mod signature;

use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::Mutex;

use busbar_auth_sigv4::inbound::{X_AMZ_CONTENT_SHA256, X_AMZ_DATE};
use busbar_contract::abi::auth::{
    check_identify, slot as auth_slot, AuthTail, IdentifyOut, IdentityBuf, NamedValue, StripName,
    VerifyIn, CANCEL_ABANDONED, CAP_INBOUND, CAP_OUTBOUND, DECISION_CONTINUE, DECISION_STOP,
    FACT_INBOUND_ALL_HEADERS, FACT_READS_CREDENTIALS, POINT_HEAD_BODY, SPAN_ABSENT,
    VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::host::service::{
    op, HostSlots, ItemSpan, RecordsSecretIn, ServiceOut, SECRET_LIVE, SECRET_NOT_LIVE, SERVICES,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Outcome, RawOutcome, Span, BLOB_OCTETS, FLAG_RESUME,
};
use busbar_contract::abi::mechanism::door::{
    DoorFn, Statement, MARK_WORD_CARRIER, MARK_WORD_ISSUED_ID_ALPHABET, MARK_WORD_ISSUED_ID_LENGTH,
    MARK_WORD_ISSUED_ID_PREFIX, MARK_WORD_ISSUED_SECRET_ALPHABET, MARK_WORD_ISSUED_SECRET_LENGTH,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelIn, CancelOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use frames::{call, in_head, ops, out_head, z};
use sha2::{Digest, Sha256};

const AKID: &str = "BBAKLIVE0000000000001";
const SECRET: &str = "live/secret+KEY0000000000000000000000000";
const DEAD_AKID: &str = "BBAKDEAD0000000000002";
const DEAD_SECRET: &str = "dead/secret+KEY0000000000000000000000000";
/// A live credential whose secret is longer than the plugin's first buffer: the host answers
/// short and the plugin re-calls once.
const LONG_AKID: &str = "BBAKLONG0000000000003";
const DUMMY: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";
const NOW: u64 = 1_440_938_160;
/// [`NOW`] as SigV4 states it: the `x-amz-date` and the credential scope's date.
const AMZDATE: &str = "20150830T123600Z";
const DATESTAMP: &str = "20150830";
const PATH: &str = "/model/vendor.model/converse";
const TICKET: Ticket = Ticket {
    slot: 7,
    generation: 3,
};

fn long_secret() -> String {
    "L".repeat(300)
}

/// Lowercase hex SHA-256 of `b`.
fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// One completion handle, as the host keys it: the ticket's slot and generation, and the seq.
type Handle = (u32, u32, u32);

/// The fake host's state, behind `HostCtx` (its handle is the state's address): whether a fresh
/// handle pends once (keyed as a host keys it, by ticket and seq), and every read (handle, kind, id)
/// it served.
#[derive(Default)]
struct FakeHost {
    pend_first: bool,
    /// Once set, the live credential answers not live (revoked between two calls).
    revoked: std::sync::atomic::AtomicBool,
    pended: Mutex<HashSet<Handle>>,
    reads: Mutex<Vec<(Handle, String, String)>>,
    /// Every `records.secret` call whose head broke the ABI, noted instead of panicking (a panic
    /// cannot unwind out of the `extern "C"` service) and asserted empty when [`Opened`] drops.
    broken: Mutex<Vec<String>>,
}

fn text(s: AbiStr) -> String {
    // SAFETY: the plugin's own `in`, live for the call.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

extern "C" fn fake_records_secret(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the fake's own context, and the plugin's `RecordsSecretIn` / `ServiceOut`.
    let (host, i, out) = unsafe {
        (
            &*std::ptr::with_exposed_provenance::<FakeHost>(
                usize::try_from(ctx.handle).expect("the fake's handle is an address"),
            ),
            input.cast::<RecordsSecretIn>().read_unaligned(),
            &mut *out,
        )
    };
    if i.head.op != op::RECORDS_SECRET || i.head.size as usize != size_of::<RecordsSecretIn>() {
        if let Ok(mut broken) = host.broken.lock() {
            broken.push(format!(
                "records.secret head: op {} size {}",
                i.head.op, i.head.size
            ));
        }
        out.outcome = RawOutcome::of(Outcome::Failed);
        return RawOutcome::of(Outcome::Failed);
    }
    let (kind, id) = (text(i.kind), text(i.id));
    let h = i.head.handle;
    let handle = (h.ticket.slot, h.ticket.generation, h.seq);
    host.reads
        .lock()
        .unwrap()
        .push((handle, kind.clone(), id.clone()));
    let mut answer = |o: Outcome| {
        out.outcome = RawOutcome::of(o);
        RawOutcome::of(o)
    };
    if kind != "sigv4" {
        return answer(Outcome::Refused);
    }
    if host.pend_first && host.pended.lock().unwrap().insert(handle) {
        return answer(Outcome::Pending);
    }
    let long = long_secret();
    let (secret, live) = match id.as_str() {
        AKID if host.revoked.load(std::sync::atomic::Ordering::SeqCst) => (SECRET, SECRET_NOT_LIVE),
        AKID => (SECRET, SECRET_LIVE),
        DEAD_AKID => (DEAD_SECRET, SECRET_NOT_LIVE),
        LONG_AKID => (long.as_str(), SECRET_LIVE),
        _ => (DUMMY, SECRET_NOT_LIVE),
    };
    if secret.len() > i.into.cap || i.into.spans_cap < 1 {
        out.needed_bytes = secret.len() as u64;
        out.needed_items = 1;
        return answer(Outcome::Failed);
    }
    // SAFETY: the plugin's buffers, `cap` bytes and `spans_cap` spans, checked above.
    unsafe {
        std::ptr::copy_nonoverlapping(secret.as_ptr(), i.into.buf, secret.len());
        i.into.spans.write_unaligned(ItemSpan {
            key: Span {
                offset: SPAN_ABSENT,
                len: 0,
            },
            value: Span {
                offset: 0,
                len: secret.len() as u32,
            },
        });
    }
    out.value = live;
    out.len = secret.len() as u64;
    out.items = 1;
    answer(Outcome::Ready)
}

/// A host services table with only `records.secret` (or none at all).
fn slots(records_secret: bool) -> HostSlots {
    // SAFETY: `HostSlots` is integers and nullable function pointers: all-zero is every slot NULL.
    let mut t: HostSlots = unsafe { std::mem::zeroed() };
    t.size = size_of::<HostSlots>() as u32;
    t.slots = SERVICES;
    if records_secret {
        t.records_secret = Some(fake_records_secret);
    }
    t
}

/// One opened instance over a fake host; the host and its table outlive it.
struct Opened {
    instance: *mut c_void,
    _tables: Box<HostTables>,
    _slots: Box<HostSlots>,
    host: Box<FakeHost>,
}

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: Opened owns the only close of this door's open result. Rust drops these boxed
        // host tables and their state only after this Drop body has returned.
        unsafe { frames::close(self.instance) };
        if !std::thread::panicking() {
            let broken = self.host.broken.lock().unwrap();
            assert!(
                broken.is_empty(),
                "the plugin's records.secret calls broke the ABI: {broken:?}"
            );
        }
    }
}

fn open_with(host: FakeHost, records_secret: bool, tables: bool) -> Opened {
    let host = Box::new(host);
    let slots = Box::new(slots(records_secret));
    let t = Box::new(HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,

        ctx: HostCtx {
            handle: u64::try_from(std::ptr::from_ref(&*host).expose_provenance())
                .expect("an address fits a handle"),
        },
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::from_ref(&*slots),

        io: std::ptr::null(),
    });
    // SAFETY: these boxed host tables, slots and context are moved unchanged into Opened below
    // and outlive its single CLOSE in Drop. OPEN takes no other borrowed host state.
    let instance = unsafe {
        frames::open(if tables {
            std::ptr::from_ref(&*t)
        } else {
            std::ptr::null()
        })
    };
    Opened {
        instance,
        _tables: t,
        _slots: slots,
        host,
    }
}

fn open() -> Opened {
    open_with(FakeHost::default(), true, true)
}

/// A client's signed request: its header lines, and its body.
struct Req {
    lines: Vec<(String, String)>,
    body: Vec<u8>,
}

fn signed(secret: &str, akid: &str, body: &[u8]) -> Req {
    signed_as(secret, akid, body, "POST", "")
}

/// [`signed`] for `method` over the canonical query `query` (signed as given).
fn signed_as(secret: &str, akid: &str, body: &[u8], method: &str, query: &str) -> Req {
    let (amzdate, datestamp) = (AMZDATE.to_string(), DATESTAMP.to_string());
    let payload_hash = sha256_hex(body);
    let headers = vec![
        ("host".to_string(), "busbar.example".to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.clone()),
    ];

    let (sig, signed_headers) = signature::sign_v4(
        secret,
        "us-east-1",
        "bedrock",
        method,
        PATH,
        query,
        &headers,
        &payload_hash,
        &amzdate,
        &datestamp,
    );
    let mut lines = vec![(
        "Authorization".to_string(),
        format!(
            "AWS4-HMAC-SHA256 Credential={akid}/{datestamp}/us-east-1/bedrock/aws4_request, \
             SignedHeaders={signed_headers}, Signature={sig}"
        ),
    )];
    lines.extend(headers);
    Req {
        lines,
        body: body.to_vec(),
    }
}

fn abi_str(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The host's buffers for one `verify`.
struct Bufs {
    bytes: Vec<u8>,
    groups: Vec<Span>,
    strips: Vec<StripName>,
}

impl Bufs {
    fn new(cap: usize) -> Self {
        Self {
            bytes: vec![0; cap],
            groups: vec![Span { offset: 0, len: 0 }; 4],
            strips: vec![
                StripName {
                    name: Span { offset: 0, len: 0 },
                    place: 0,
                    _reserved: 0,
                };
                4
            ],
        }
    }
}

/// What one `verify` answered: the outcome, the `out`, and the subject an identity names.
struct Answer {
    outcome: Outcome,
    out: IdentifyOut,
    subject: Option<String>,
    /// The strip names the answer wrote, as text.
    strips: Vec<String>,
}

/// `verify` on `ticket` with `flags`, at `HeadBody`, over `req`, into buffers of `cap` bytes; the
/// answer judged by the kind's `check_identify`.
fn verify(o: &Opened, req: &Req, ticket: Ticket, flags: u32, cap: usize) -> Answer {
    verify_as(o, req, ticket, flags, cap, "POST", None)
}

/// [`verify`] for a request received with `method` and the raw `query` (none = absent).
fn verify_as(
    o: &Opened,
    req: &Req,
    ticket: Ticket,
    flags: u32,
    cap: usize,
    method: &str,
    query: Option<&str>,
) -> Answer {
    verify_at(o, req, ticket, flags, cap, method, query, NOW)
}

#[allow(clippy::too_many_arguments)]
fn verify_at(
    o: &Opened,
    req: &Req,
    ticket: Ticket,
    flags: u32,
    cap: usize,
    method: &str,
    query: Option<&str>,
    now: u64,
) -> Answer {
    let names: Vec<(String, String)> = req.lines.clone();
    let lines: Vec<NamedValue> = names
        .iter()
        .map(|(n, v)| NamedValue {
            name: abi_str(n),
            value: Blob {
                ptr: v.as_ptr(),
                len: v.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            },
        })
        .collect();
    let mut bufs = Bufs::new(cap);
    let mut i: VerifyIn = z();
    i.head = in_head::<VerifyIn>(auth_slot::VERIFY);
    i.head.ticket = ticket;
    i.head.flags = flags;
    i.lines = lines.as_ptr();
    i.lines_len = lines.len();
    i.request.method = abi_str(method);
    i.request.authority = abi_str("busbar.example");
    i.request.canonical_path = abi_str(PATH);

    if let Some(q) = query {
        i.request.query = abi_str(q);
    }
    i.request.timestamp = now;
    i.point = POINT_HEAD_BODY;
    i.body = Blob {
        ptr: req.body.as_ptr(),
        len: req.body.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    i.out_buf = IdentityBuf {
        buf: bufs.bytes.as_mut_ptr(),
        buf_cap: bufs.bytes.len(),
        groups: bufs.groups.as_mut_ptr(),
        groups_cap: bufs.groups.len() as u32,
        _reserved: 0,
    };
    i.strip = bufs.strips.as_mut_ptr();
    i.strip_cap = bufs.strips.len() as u32;
    let mut out: IdentifyOut = z();
    out.head = out_head::<IdentifyOut>();
    // SAFETY: this door's VERIFY takes VerifyIn/IdentifyOut with complete initialized heads.
    // The opened instance and host tables remain live through `o`; names, lines, req.body and
    // bufs own every frame loan for the full call, including all output capacities stated above.
    let outcome = unsafe { call(ops().verify, o.instance, &i, &mut out) };
    let strips = &bufs.strips[..(out.strip_len as usize).min(bufs.strips.len())];
    let groups = &bufs.groups[..(out.identity.groups_len as usize).min(bufs.groups.len())];
    check_identify(outcome, &out, &i.out_buf, groups, i.strip_cap, strips)
        .unwrap_or_else(|f| panic!("verify broke the kind's answer rules: {f:?}"));
    let subject = (outcome == Outcome::Ready && out.verdict == VERDICT_IDENTITY).then(|| {
        let s = out.identity.subject;
        String::from_utf8_lossy(&bufs.bytes[s.offset as usize..(s.offset + s.len) as usize])
            .into_owned()
    });
    let strips = strips
        .iter()
        .map(|n| {
            assert_eq!(n.place, busbar_contract::abi::auth::STRIP_FIELD);
            String::from_utf8_lossy(
                &bufs.bytes[n.name.offset as usize..(n.name.offset + n.name.len) as usize],
            )
            .into_owned()
        })
        .collect();
    Answer {
        outcome,
        out,
        subject,
        strips,
    }
}

fn reads(o: &Opened) -> Vec<(Handle, String, String)> {
    o.host.reads.lock().unwrap().clone()
}

#[test]
fn the_tail_states_inbound_sigv4_at_head_body_beside_the_outbound_style() {
    let door = busbar_auth_sigv4::door();
    // SAFETY: the door is this crate's `'static` plain data.
    let (st, tail): (Statement, AuthTail) = unsafe {
        let st: *const Statement = door.statement();
        let st = st.read_unaligned();
        (st, st.kind_tail.cast::<AuthTail>().read_unaligned())
    };
    assert_eq!(tail.caps, CAP_OUTBOUND | CAP_INBOUND);
    assert_eq!(
        tail.facts,
        FACT_INBOUND_ALL_HEADERS | FACT_READS_CREDENTIALS
    );
    assert_eq!(tail.inbound_points, POINT_HEAD_BODY);
    assert_eq!(tail.styles_len, 1);
    // SAFETY: `'static` tail arrays of the stated lengths.
    let (kinds, words) = unsafe {
        (
            std::slice::from_raw_parts(tail.credential_kinds, tail.credential_kinds_len),
            std::slice::from_raw_parts(st.mark_words, st.mark_words_len),
        )
    };
    assert_eq!(
        kinds.iter().map(|k| text(*k)).collect::<Vec<_>>(),
        ["sigv4"]
    );
    let owned: Vec<(u32, String)> = words.iter().map(|w| (w.class, text(w.word))).collect();
    let marks: Vec<(u32, &str)> = owned.iter().map(|(c, w)| (*c, w.as_str())).collect();
    assert_eq!(
        marks,
        [
            (MARK_WORD_CARRIER, "authorization"),
            (MARK_WORD_ISSUED_ID_PREFIX, "AKIA"),
            (MARK_WORD_ISSUED_ID_LENGTH, "20"),
            (
                MARK_WORD_ISSUED_ID_ALPHABET,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            ),
            (MARK_WORD_ISSUED_SECRET_LENGTH, "40"),
            (
                MARK_WORD_ISSUED_SECRET_ALPHABET,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            ),
        ],
        "the carrier, then the issued credential's shape: 1.5.5's AccessKeyId and secret"
    );

    let (entry, door): (DoorFn, DoorFn) = (
        busbar_auth_sigv4::compiled_in::door::door,
        busbar_auth_sigv4::door,
    );
    assert!(std::ptr::fn_addr_eq(entry, door));
}

#[test]
fn a_signed_request_over_the_live_credential_identifies_its_access_key_id() {
    let o = open();
    let a = verify(&o, &signed(SECRET, AKID, b"{\"x\":1}"), TICKET, 0, 256);
    assert_eq!(a.outcome, Outcome::Ready);
    assert_eq!(a.out.verdict, VERDICT_IDENTITY);
    assert_eq!(a.subject.as_deref(), Some(AKID));
    assert_eq!(a.out.decision, DECISION_CONTINUE);

    assert_eq!(a.strips, ["authorization"]);
    let id = a.out.identity;
    assert_eq!((id.flags, id.ttl_secs), (0, 0), "no TTL: never cached");
    assert_eq!(id.replay_key.offset, SPAN_ABSENT, "no replay claim");
    assert_eq!(id.credential.len, 0, "no credential");
    assert_eq!(id.key_id.offset, SPAN_ABSENT);
    assert_eq!(
        reads(&o),
        [((7, 3, 0), "sigv4".to_string(), AKID.to_string())],
        "one read on the call's ticket, kind sigv4, id the AccessKeyId"
    );
}

#[test]
fn the_door_applies_the_clock_window_in_both_directions() {
    let o = open();
    let req = signed(SECRET, AKID, b"");
    for (now, verdict) in [
        (NOW - 301, VERDICT_REJECT),
        (NOW - 300, VERDICT_IDENTITY),
        (NOW + 300, VERDICT_IDENTITY),
        (NOW + 301, VERDICT_REJECT),
    ] {
        let a = verify_at(&o, &req, TICKET, 0, 512, "POST", None, now);
        assert_eq!(a.outcome, Outcome::Ready);
        assert_eq!(a.out.verdict, verdict, "now={now}");
    }
}

#[test]
fn a_signed_host_with_no_host_line_is_the_requests_authority() {
    let o = open();
    let mut req = signed(SECRET, AKID, b"");
    req.lines.retain(|(n, _)| n != "host");
    let a = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(a.out.verdict, VERDICT_IDENTITY);
    assert_eq!(a.subject.as_deref(), Some(AKID));
}

/// The door lends the received method and raw query to the check: a GET signed over a query is
/// admitted, and the same request received with another query or as a POST is not.
#[test]
fn a_signed_get_with_a_query_is_admitted_through_the_door() {
    let o = open();
    let req = signed_as(SECRET, AKID, b"", "GET", "a=1&b=2");
    let a = verify_as(&o, &req, TICKET, 0, 256, "GET", Some("a=1&b=2"));
    assert_eq!(a.outcome, Outcome::Ready);
    assert_eq!(a.out.verdict, VERDICT_IDENTITY);
    assert_eq!(a.subject.as_deref(), Some(AKID));
    for (method, query) in [
        ("GET", None),
        ("GET", Some("a=1&b=3")),
        ("POST", Some("a=1&b=2")),
    ] {
        let a = verify_as(&o, &req, TICKET, 0, 256, method, query);
        assert_eq!(a.out.verdict, VERDICT_REJECT, "{method} {query:?}");
    }
}

#[test]
fn a_bearer_authorization_passes_without_a_read() {
    let o = open();
    let req = Req {
        lines: vec![
            (
                "authorization".to_string(),
                "Bearer sk-busbar-1".to_string(),
            ),
            (
                "x-amz-security-token".to_string(),
                "other-scheme-token".to_string(),
            ),
        ],
        body: Vec::new(),
    };
    let a = verify(&o, &req, TICKET, 0, 256);
    assert_eq!((a.outcome, a.out.verdict), (Outcome::Ready, VERDICT_PASS));
    assert_eq!(a.out.decision, DECISION_CONTINUE);
    assert!(
        a.strips.is_empty(),
        "a Bearer line is not this auth's credential"
    );

    let a = verify(&o, &req, Ticket::NONE, 0, 256);
    assert_eq!((a.outcome, a.out.verdict), (Outcome::Ready, VERDICT_PASS));
    assert!(reads(&o).is_empty());
}

#[test]
fn sigv4_session_tokens_are_stripped_with_the_authorization() {
    let o = open();
    for secret in [SECRET, "wrong-secret"] {
        let mut req = signed(secret, AKID, b"");
        req.lines
            .push(("X-Amz-Security-Token".into(), "caller-session-token".into()));
        let a = verify(&o, &req, TICKET, 0, 512);
        assert_eq!(a.outcome, Outcome::Ready);
        assert_eq!(
            a.out.verdict,
            if secret == SECRET {
                VERDICT_IDENTITY
            } else {
                VERDICT_REJECT
            }
        );
        assert_eq!(a.strips, ["authorization", "x-amz-security-token"]);
    }
}

#[test]
fn an_obs_text_duplicate_of_a_signed_header_rejects_through_the_door() {
    let o = open();
    let mut req = signed(SECRET, AKID, b"");
    let mut signed_lines: Vec<_> = req.lines.iter().skip(1).cloned().collect();
    signed_lines.push(("content-type".to_string(), "application/json".to_string()));
    let hash = sha256_hex(b"");
    let (signature, names) = signature::sign_v4(
        SECRET,
        "us-east-1",
        "bedrock",
        "POST",
        PATH,
        "",
        &signed_lines,
        &hash,
        AMZDATE,
        DATESTAMP,
    );
    req.lines[0].1 = format!(
        "AWS4-HMAC-SHA256 Credential={AKID}/{DATESTAMP}/us-east-1/bedrock/aws4_request, \
         SignedHeaders={names}, Signature={signature}"
    );
    req.lines
        .push(("content-type".into(), "application/json".into()));
    assert_eq!(
        verify(&o, &req, TICKET, 0, 512).out.verdict,
        VERDICT_IDENTITY
    );
    let before = reads(&o).len();

    req.lines.push(("Content-Type".into(), "é".into()));
    let rejected = verify(&o, &req, TICKET, 0, 512);
    assert_eq!(rejected.outcome, Outcome::Ready);
    assert_eq!(rejected.out.verdict, VERDICT_REJECT);
    assert_eq!(rejected.strips, ["authorization"]);
    assert_eq!(
        reads(&o).len(),
        before,
        "rejected before the secret service"
    );
    req.lines.last_mut().unwrap().0 = "x-unsigned".into();
    assert_eq!(
        verify(&o, &req, TICKET, 0, 512).out.verdict,
        VERDICT_IDENTITY
    );
}

#[test]
fn scheme_ownership_controls_the_door_verdict_and_stripping() {
    let o = open();
    for (value, verdict) in [
        ("AWS4-HMAC-SHA256 Credential=bad\u{0080}", VERDICT_REJECT),
        ("AWS4-HMAC-SHA256X token", VERDICT_PASS),
        ("AWS4-HMAC-SHA256-OTHER token", VERDICT_PASS),
    ] {
        let req = Req {
            lines: vec![("authorization".into(), value.into())],
            body: vec![],
        };
        let a = verify(&o, &req, TICKET, 0, 512);
        assert_eq!(a.outcome, Outcome::Ready);
        assert_eq!(a.out.verdict, verdict, "{value:?}");
        if verdict == VERDICT_REJECT {
            assert_eq!(a.strips, ["authorization"]);
        } else {
            assert!(a.strips.is_empty());
        }
    }
    assert!(reads(&o).is_empty());
}

#[test]
fn an_unknown_access_key_id_is_read_verified_and_rejected() {
    let o = open();
    let a = verify(&o, &signed(SECRET, "BBAKNOBODY", b""), TICKET, 0, 256);
    assert_eq!((a.outcome, a.out.verdict), (Outcome::Ready, VERDICT_REJECT));
    assert_eq!(a.out.decision, DECISION_STOP);
    assert_eq!(
        reads(&o).len(),
        1,
        "the dummy secret is read and verified over"
    );

    let a = verify(&o, &signed(DUMMY, "BBAKNOBODY", b""), TICKET, 0, 256);
    assert_eq!(a.out.verdict, VERDICT_REJECT);
}

#[test]
fn a_credential_that_is_not_live_is_rejected() {
    let o = open();
    let a = verify(&o, &signed(DEAD_SECRET, DEAD_AKID, b""), TICKET, 0, 256);
    assert_eq!((a.outcome, a.out.verdict), (Outcome::Ready, VERDICT_REJECT));
}

#[test]
fn a_wrong_signature_or_a_tampered_body_is_rejected() {
    let o = open();
    let a = verify(&o, &signed("not-the-secret", AKID, b""), TICKET, 0, 256);
    assert_eq!(a.out.verdict, VERDICT_REJECT);
    assert_eq!(a.strips, ["authorization"], "named whatever the verdict");
    let mut req = signed(SECRET, AKID, b"{\"x\":1}");
    req.body = b"{\"x\":2}".to_vec();
    let a = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(a.out.verdict, VERDICT_REJECT);
}

#[test]
fn on_the_spot_a_sigv4_credential_is_refused_for_the_ticketed_call() {
    let o = open();
    let a = verify(&o, &signed(SECRET, AKID, b""), Ticket::NONE, 0, 256);
    assert_eq!(a.outcome, Outcome::Refused);
    let trivial = Req {
        lines: vec![(
            "authorization".to_string(),
            "AWS4-HMAC-SHA256 x".to_string(),
        )],
        body: Vec::new(),
    };
    let a = verify(&o, &trivial, Ticket::NONE, 0, 256);
    assert_eq!((a.outcome, a.out.verdict), (Outcome::Ready, VERDICT_REJECT));
    assert!(reads(&o).is_empty());
}

#[test]
fn a_pending_read_pends_and_the_resumed_call_reissues_the_same_handle() {
    let o = open_with(
        FakeHost {
            pend_first: true,
            ..FakeHost::default()
        },
        true,
        true,
    );
    let req = signed(SECRET, AKID, b"");
    let first = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(first.outcome, Outcome::Pending);
    let resumed = verify(&o, &req, TICKET, FLAG_RESUME, 256);
    assert_eq!(resumed.outcome, Outcome::Ready);
    assert_eq!(resumed.subject.as_deref(), Some(AKID));
    let handles: Vec<Handle> = reads(&o).iter().map(|r| r.0).collect();
    assert_eq!(
        handles,
        [(7, 3, 0), (7, 3, 0)],
        "the resumed call re-issues the SAME handle"
    );

    let ticket = Ticket {
        slot: 8,
        generation: 1,
    };
    assert_eq!(verify(&o, &req, ticket, 0, 256).outcome, Outcome::Pending);
    assert_eq!(reads(&o).last().unwrap().0, (8, 1, 0));

    let mut ci: CancelIn = z();
    ci.head = in_head::<CancelIn>(life::CANCEL);
    ci.ticket = ticket;
    let mut co: CancelOut = z();
    co.head = out_head::<CancelOut>();
    assert_eq!(
        // SAFETY: this door's CANCEL takes these complete CancelIn/CancelOut frames on the
        // same still-open instance, whose host tables/state remain owned by `o`.
        unsafe { call(ops().head.cancel, o.instance, &ci, &mut co) },
        Outcome::Ready
    );
    assert_eq!(co.disposition, CANCEL_ABANDONED);
}

#[test]
fn a_long_secret_is_re_read_once_with_the_size_the_host_named() {
    let o = open();
    let a = verify(&o, &signed(&long_secret(), LONG_AKID, b""), TICKET, 0, 256);
    assert_eq!(a.subject.as_deref(), Some(LONG_AKID));
    let r = reads(&o);
    assert_eq!(r.len(), 2, "the call and its ONE re-call");
    assert_eq!(r[0].0, r[1].0, "the re-call is on the same handle");
    assert_eq!(r[0].0, (7, 3, 0));
}

/// The short answer writes nothing, and the host's one re-call (a fresh call on the same ticket)
/// judges again: the secret is read on the call's same handle, never kept by the plugin between
/// the two (nothing of `verify`'s is cached), so a credential revoked in between is rejected.
#[test]
fn a_short_identity_buffer_answers_short_and_the_recall_judges_again() {
    let o = open();
    let req = signed(SECRET, AKID, b"");
    let short = verify(&o, &req, TICKET, 0, 4);
    assert_eq!(short.outcome, Outcome::Failed);
    assert_eq!(
        short.out.needed_bytes,
        (AKID.len() + "authorization".len()) as u64,
        "the subject and the named line"
    );

    o.host
        .revoked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let again = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(
        (again.out.verdict, again.subject.as_deref()),
        (VERDICT_REJECT, None),
        "revoked in between: the re-call judges again and rejects"
    );
    let handles: Vec<Handle> = reads(&o).iter().map(|r| r.0).collect();
    assert_eq!(
        handles,
        [(7, 3, 0), (7, 3, 0)],
        "the re-call reads on the same handle"
    );
}

#[test]
fn no_records_secret_slot_or_no_host_services_fails_closed() {
    for (slot, tables) in [(false, true), (true, false)] {
        let o = open_with(FakeHost::default(), slot, tables);
        let a = verify(&o, &signed(SECRET, AKID, b""), TICKET, 0, 256);
        assert_eq!(
            (a.outcome, a.out.verdict),
            (Outcome::Ready, VERDICT_REJECT),
            "slot={slot} tables={tables}"
        );

        let bearer = Req {
            lines: vec![("authorization".to_string(), "Bearer x".to_string())],
            body: Vec::new(),
        };
        assert_eq!(
            verify(&o, &bearer, TICKET, 0, 256).out.verdict,
            VERDICT_PASS
        );
    }
}
