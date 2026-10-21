// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `verify` SLOT, through the door's own table as a host calls it: an instance opened over a
//! host table whose `records.secret` serves one live credential, one that is not live, and the
//! fixed dummy (not live) for any other id, recording every crossing (its handle, kind and id); the
//! tail and Statement it states; every answer judged by the kind's own `check_identify`.
//!
//! The door is the contract kit's (`auth_door!(verify_and_outbound: ..)`): `verify` reads the
//! secret through the SDK's `records.secret` on the call's ticket, each entry issuing its handles
//! from `0`, so a RESUME (or the host's re-call after a short answer) re-issues the SAME handle and
//! the host serves the answer it stored. THE PLUGIN KEEPS NOTHING between two calls: no secret, no
//! verdict, no handle.

mod frames;

use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use busbar_contract::abi::auth::{
    check_identify, slot, AuthTail, IdentifyOut, IdentityBuf, NamedValue, StripName, VerifyIn,
    CANCEL_ABANDONED, CAP_INBOUND, CAP_OUTBOUND, DECISION_CONTINUE, DECISION_STOP,
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
    Statement, MARK_WORD_CARRIER, MARK_WORD_ISSUED_ID_ALPHABET, MARK_WORD_ISSUED_ID_LENGTH,
    MARK_WORD_ISSUED_ID_PREFIX, MARK_WORD_ISSUED_SECRET_ALPHABET, MARK_WORD_ISSUED_SECRET_LENGTH,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelIn, CancelOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::redacted::sha256_hex;

use frames::{call, in_head, ops, out_head, z};

const AKID: &str = "BBAKLIVE0000000000001";
const SECRET: &str = "live/secret+KEY0000000000000000000000000";
const DEAD_AKID: &str = "BBAKDEAD0000000000002";
const DEAD_SECRET: &str = "dead/secret+KEY0000000000000000000000000";
/// A live credential whose secret is longer than the SDK's first buffer: the host answers short
/// and the SDK re-calls once.
const LONG_AKID: &str = "BBAKLONG0000000000003";
const DUMMY: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";
/// The request's clock, and the `x-amz-date` it is signed at: AWS's example timestamp.
const NOW: u64 = 1_440_938_160;
const AMZDATE: &str = "20150830T123600Z";
const PATH: &str = "/model/vendor.model/converse";
const TICKET: Ticket = Ticket {
    slot: 7,
    generation: 3,
};

fn long_secret() -> String {
    "L".repeat(300)
}

/// One `records.secret` crossing the host served: its handle (ticket, seq), the kind and the id.
type Crossing = (Ticket, u32, String, String);

/// The fake host's state, behind `HostCtx` (its handle is the state's address): whether a fresh
/// handle pends once, whether the live credential has since been REVOKED (it then answers not
/// live), and every crossing it served.
#[derive(Default)]
struct FakeHost {
    pend_first: bool,
    revoked: AtomicBool,
    pended: Mutex<HashSet<(Ticket, u32)>>,
    reads: Mutex<Vec<Crossing>>,
}

fn text(s: AbiStr) -> String {
    // SAFETY: the plugin's own `in`, live for the call.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr(), s.len()) }).into_owned()
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
    assert_eq!(i.head.op, op::RECORDS_SECRET);
    assert_eq!(i.head.size as usize, size_of::<RecordsSecretIn>());
    let (kind, id) = (text(i.kind), text(i.id));
    let handle = (i.head.handle.ticket, i.head.handle.seq);
    host.reads
        .lock()
        .unwrap()
        .push((handle.0, handle.1, kind.clone(), id.clone()));
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
        AKID if host.revoked.load(Ordering::SeqCst) => (SECRET, SECRET_NOT_LIVE),
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
    let mut t: HostSlots = z();
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
        frames::close(self.instance);
    }
}

fn open_with(host: FakeHost, records_secret: bool, tables: bool) -> Opened {
    let host = Box::new(host);
    let slots = Box::new(slots(records_secret));
    let t = Box::new(HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        // The fake's handle is its state's address: the host side here is this test's own.
        ctx: HostCtx {
            handle: u64::try_from(std::ptr::from_ref(&*host).expose_provenance())
                .expect("an address fits a handle"),
        },
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::from_ref(&*slots),
        // The host I/O table: this host offers none (the door reads no handle).
        io: std::ptr::null(),
    });
    let instance = frames::open(if tables {
        std::ptr::from_ref(&*t)
    } else {
        std::ptr::null()
    });
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

/// The client-side SigV4 signature of a POST to [`PATH`] (region `us-east-1`, service `bedrock`,
/// no query) over `headers`, at [`AMZDATE`], as the AWS SDKs compute it: `(signature hex,
/// SignedHeaders)`. The test signs on its own: the logic crate's only public item is its door.
fn sign_v4(secret: &str, headers: &[(String, String)], payload_hash: &str) -> (String, String) {
    use sha2::{Digest, Sha256};
    fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut k = if key.len() > 64 {
            Sha256::digest(key).to_vec()
        } else {
            key.to_vec()
        };
        k.resize(64, 0);
        let inner = Sha256::new()
            .chain_update(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>())
            .chain_update(msg)
            .finalize();
        Sha256::new()
            .chain_update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>())
            .chain_update(inner)
            .finalize()
            .to_vec()
    }
    let mut h: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.trim().to_string()))
        .collect();
    h.sort();
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = h
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request =
        format!("POST\n{PATH}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let datestamp = &AMZDATE[..8];
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{AMZDATE}\n{datestamp}/us-east-1/bedrock/aws4_request\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac(&k_date, b"us-east-1");
    let k_service = hmac(&k_region, b"bedrock");
    let k_signing = hmac(&k_service, b"aws4_request");
    (
        hex::encode(hmac(&k_signing, string_to_sign.as_bytes())),
        signed_headers,
    )
}

fn signed(secret: &str, akid: &str, body: &[u8]) -> Req {
    let payload_hash = sha256_hex(body);
    let headers = vec![
        ("host".to_string(), "busbar.example".to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), AMZDATE.to_string()),
    ];
    let (sig, signed_headers) = sign_v4(secret, &headers, &payload_hash);
    let mut lines = vec![(
        "Authorization".to_string(),
        format!(
            "AWS4-HMAC-SHA256 Credential={akid}/{}/us-east-1/bedrock/aws4_request, \
             SignedHeaders={signed_headers}, Signature={sig}",
            &AMZDATE[..8]
        ),
    )];
    lines.extend(headers);
    Req {
        lines,
        body: body.to_vec(),
    }
}

fn abi_str(s: &str) -> AbiStr {
    // SAFETY: `s` outlives the `in` this view is stated in (a test-owned buffer).
    unsafe { AbiStr::from_raw_parts(s.as_ptr(), s.len()) }
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

/// The lines `a` named for the transport to strip (all fields).
fn strip_names(a: &Answer) -> Vec<String> {
    a.strips.clone()
}

/// `verify` on `ticket` with `flags`, at `HeadBody`, over `req`, into buffers of `cap` bytes; the
/// answer judged by the kind's `check_identify`.
fn verify(o: &Opened, req: &Req, ticket: Ticket, flags: u32, cap: usize) -> Answer {
    let names: Vec<(String, String)> = req.lines.clone();
    let lines: Vec<NamedValue> = names
        .iter()
        .map(|(n, v)| NamedValue {
            name: abi_str(n),
            // SAFETY: `v` is owned by `names`, which outlives the `in` this view is stated in.
            value: unsafe { Blob::from_raw_parts(v.as_ptr(), v.len(), BLOB_OCTETS, 0) },
        })
        .collect();
    let mut bufs = Bufs::new(cap);
    let mut i: VerifyIn = z();
    i.head = in_head::<VerifyIn>(slot::VERIFY);
    i.head.ticket = ticket;
    i.head.flags = flags;
    i.lines = lines.as_ptr();
    i.lines_len = lines.len();
    i.request.method = abi_str("POST");
    i.request.authority = abi_str("busbar.example");
    i.request.canonical_path = abi_str(PATH);
    i.request.timestamp = NOW;
    i.point = POINT_HEAD_BODY;
    // SAFETY: `req` outlives the `in` this view is stated in.
    i.body = unsafe { Blob::from_raw_parts(req.body.as_ptr(), req.body.len(), BLOB_OCTETS, 0) };
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
    let outcome = call(ops().verify, o.instance, &i, &mut out);
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

fn reads(o: &Opened) -> Vec<Crossing> {
    o.host.reads.lock().unwrap().clone()
}

/// The handle (ticket, seq) of every crossing so far.
fn handles(o: &Opened) -> Vec<(Ticket, u32)> {
    reads(o).iter().map(|r| (r.0, r.1)).collect()
}

#[test]
fn the_tail_states_inbound_sigv4_at_head_body_beside_the_outbound_style() {
    // SAFETY: the door is this crate's own `'static` door; the block is needed once busbar #1469
    // makes `door` an `unsafe fn`, and unused (allowed) before it.
    #[allow(unused_unsafe)]
    let door = unsafe { busbar_auth_sigv4::door() };
    // SAFETY: the door is the plugin's `'static` plain data.
    let (st, tail): (Statement, AuthTail) = unsafe {
        let st: *const Statement = std::ptr::addr_of!((*door).statement).read_unaligned();
        let st = st.read_unaligned();
        (st, st.kind_tail().cast::<AuthTail>().read_unaligned())
    };
    assert_eq!(tail.caps, CAP_OUTBOUND | CAP_INBOUND);
    assert_eq!(
        tail.facts,
        FACT_INBOUND_ALL_HEADERS | FACT_READS_CREDENTIALS
    );
    assert_eq!(tail.inbound_points, POINT_HEAD_BODY);
    assert_eq!(tail.styles_len(), 1);
    // SAFETY: `'static` tail arrays of the stated lengths.
    let (kinds, words) = unsafe {
        (
            std::slice::from_raw_parts(tail.credential_kinds_ptr(), tail.credential_kinds_len()),
            std::slice::from_raw_parts(st.mark_words_ptr(), st.mark_words_len()),
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
}

#[test]
fn a_signed_request_over_the_live_credential_identifies_its_access_key_id() {
    let o = open();
    let a = verify(&o, &signed(SECRET, AKID, b"{\"x\":1}"), TICKET, 0, 256);
    assert_eq!(a.outcome, Outcome::Ready);
    assert_eq!(a.out.verdict, VERDICT_IDENTITY);
    assert_eq!(a.subject.as_deref(), Some(AKID));
    assert_eq!(a.out.decision, DECISION_CONTINUE);
    // THE CREDENTIAL LINE IS NAMED (THE DESIGN §6, "Auth points and guest lists": every auth
    // called names its credential lines whatever its verdict): the SigV4 `authorization` line.
    assert_eq!(strip_names(&a), ["authorization"]);
    let id = a.out.identity;
    assert_eq!((id.flags, id.ttl_secs), (0, 0), "no TTL: never cached");
    assert_eq!(id.replay_key.offset, SPAN_ABSENT, "no replay claim");
    assert_eq!(id.credential.len, 0, "no credential");
    assert_eq!(id.key_id.offset, SPAN_ABSENT);
    assert_eq!(
        reads(&o),
        [(TICKET, 0, "sigv4".to_string(), AKID.to_string())],
        "one read, kind sigv4, id the AccessKeyId"
    );
}

#[test]
fn a_bearer_authorization_passes_without_a_read() {
    let o = open();
    let req = Req {
        lines: vec![(
            "authorization".to_string(),
            "Bearer sk-busbar-1".to_string(),
        )],
        body: Vec::new(),
    };
    let a = verify(&o, &req, TICKET, 0, 256);
    assert_eq!((a.outcome, a.out.verdict), (Outcome::Ready, VERDICT_PASS));
    assert_eq!(a.out.decision, DECISION_CONTINUE);
    assert!(
        strip_names(&a).is_empty(),
        "a Bearer line is not this auth's credential"
    );
    // On the spot (ticket-less) too.
    let a = verify(&o, &req, Ticket::NONE, 0, 256);
    assert_eq!((a.outcome, a.out.verdict), (Outcome::Ready, VERDICT_PASS));
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
    // Even a request signed WITH the dummy secret never admits.
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
    assert_eq!(
        strip_names(&a),
        ["authorization"],
        "named whatever the verdict"
    );
    let mut req = signed(SECRET, AKID, b"{\"x\":1}");
    req.body = b"{\"x\":2}".to_vec();
    let a = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(a.out.verdict, VERDICT_REJECT);
}

#[test]
fn on_the_spot_a_sigv4_credential_is_refused_for_the_ticketed_call() {
    // `records.secret` may pend, so a ticket-less `verify` answers REFUSED and the host submits it
    // on a ticket; the structural gate still answers on the spot.
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
    assert_eq!(
        handles(&o),
        [(TICKET, 0), (TICKET, 0)],
        "the resumed call re-issues the SAME handle"
    );
    // A fresh verify on another ticket issues a new handle: its own ticket's first.
    let ticket = Ticket {
        slot: 8,
        generation: 1,
    };
    assert_eq!(verify(&o, &req, ticket, 0, 256).outcome, Outcome::Pending);
    assert_eq!(handles(&o).last(), Some(&(ticket, 0)));
    assert_ne!((ticket, 0), (TICKET, 0), "a new handle");
    // `cancel` of the ticket: nothing of the plugin's waits on it (the pending read is the host's,
    // dropped with the ticket), so it answers ABANDONED and keeps nothing for the next call, which
    // runs from the top and issues the ticket's first handle again.
    let mut ci: CancelIn = z();
    ci.head = in_head::<CancelIn>(life::CANCEL);
    ci.ticket = ticket;
    let mut co: CancelOut = z();
    co.head = out_head::<CancelOut>();
    assert_eq!(
        call(ops().head.cancel, o.instance, &ci, &mut co),
        Outcome::Ready
    );
    assert_eq!(co.disposition, CANCEL_ABANDONED);
    let again = verify(&o, &req, ticket, FLAG_RESUME, 256);
    assert_eq!(again.subject.as_deref(), Some(AKID));
    assert_eq!(handles(&o).last(), Some(&(ticket, 0)));
    assert_eq!(reads(&o).len(), 4, "every call crossed to the host");
}

#[test]
fn a_long_secret_is_re_read_once_with_the_size_the_host_named() {
    let o = open();
    let a = verify(&o, &signed(&long_secret(), LONG_AKID, b""), TICKET, 0, 256);
    assert_eq!(a.subject.as_deref(), Some(LONG_AKID));
    let r = handles(&o);
    assert_eq!(r.len(), 2, "the call and its ONE re-call");
    assert_eq!(r[0], r[1], "the re-call is on the same handle");
}

/// The short answer writes nothing, and the host's one re-call (a fresh call on the same ticket)
/// judges again: the secret is read on the call's same handle, never kept by the plugin between
/// the two (nothing of `verify`'s is cached), so a credential revoked in between is rejected.
#[test]
fn a_short_identity_buffer_answers_short_and_the_recall_reads_the_same_handle() {
    let o = open();
    let req = signed(SECRET, AKID, b"");
    let short = verify(&o, &req, TICKET, 0, 4);
    assert_eq!(short.outcome, Outcome::Failed);
    assert_eq!(
        short.out.needed_bytes,
        (AKID.len() + "authorization".len()) as u64,
        "the subject and the named line"
    );
    let again = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(again.subject.as_deref(), Some(AKID));
    // The re-call judges again from the top: it re-issues the call's first handle, where a host
    // serves the answer it stored (nothing of the plugin's is kept between the two).
    assert_eq!(handles(&o), [(TICKET, 0), (TICKET, 0)]);
}

/// RED (HIGH1: no secret cache, no verdict cache; `verify` reads through the host's
/// `records.secret` every time). The SECOND `verify` for the same AccessKeyId calls the host again,
/// whether it is a fresh call or the host's re-call after a short answer, and its verdict is the
/// host's answer of that crossing: a credential revoked between the two is REJECTED on the second.
/// Before the contract kit, the plugin held the identity a short answer reached under its ticket
/// and served the re-call from it without asking the host: the revoked credential was admitted.
#[test]
fn red_the_second_verify_for_one_key_id_calls_the_host_again() {
    let o = open();
    let req = signed(SECRET, AKID, b"");
    let first = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(first.subject.as_deref(), Some(AKID));
    let second = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(second.subject.as_deref(), Some(AKID));
    assert_eq!(
        reads(&o).len(),
        2,
        "the second verify for one key id read the host again"
    );

    // The identity a short answer reached is not kept for the re-call: the credential is revoked
    // in between, the re-call crosses to the host again and is rejected.
    let o = open();
    let short = verify(&o, &req, TICKET, 0, 4);
    assert_eq!(short.outcome, Outcome::Failed, "the identity does not fit");
    o.host.revoked.store(true, Ordering::SeqCst);
    let recall = verify(&o, &req, TICKET, 0, 256);
    assert_eq!(
        reads(&o).len(),
        2,
        "the re-call read the host again: no identity was kept"
    );
    assert_eq!(
        (recall.outcome, recall.out.verdict, recall.subject),
        (Outcome::Ready, VERDICT_REJECT, None),
        "judged by the host's answer of the moment: revoked"
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
        // A bearer still passes.
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
