// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises SigV4 auth operations through the linked and dropped-in doors.

mod signature;

use std::ffi::c_void;
use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use std::time::Duration;

use busbar_contract::abi::auth::{
    self, slot, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, IdentityBuf, NamedValue,
    OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, RequestFacts, StripName,
    VerifyIn, FIELD_SENSITIVE, MODE_OWN, MODE_PASSTHROUGH, POINT_HEAD_BODY, SPAN_ABSENT,
    VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::host::service::{ItemSpan, SECRET_LIVE, SECRET_NOT_LIVE};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Op, Outcome, RawOutcome, Span, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::redacted::sha256_hex;
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, NestAsk, RecordsList, TrustKeyRef, UNSERVED,
};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, now_ns, out_head, rendering_of, Bind, Diagnostic,
    DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, Later, LinkedRow, Metric, Plugin,
    Ran, Reading, Stored,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &'static str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &'static str, fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

fn json(b: &'static str) -> Blob {
    blob(b, BLOB_JSON, 0)
}

fn secret(b: &'static str) -> Blob {
    blob(b, BLOB_OCTETS, BLOB_SECRET)
}

#[derive(Default)]
struct Folds(
    Mutex<Vec<String>>,
    Mutex<Vec<Vec<u8>>>,
    std::sync::atomic::AtomicBool,
);

impl EnvelopeSink for Folds {
    fn metric(&self, m: Metric<'_>) {
        let mut all = self.1.lock().unwrap();
        all.push(format!("{} {} {}", m.family, m.kind, m.value).into_bytes());
        all.extend(m.labels.iter().map(|label| label.to_vec()));
        self.0.lock().unwrap().push(format!("metric {}", m.family));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.1.lock().unwrap().extend([
            format!("diagnostic {} severity={}", d.id, d.severity).into_bytes(),
            d.name.to_vec(),
            d.text.to_vec(),
        ]);
        self.0.lock().unwrap().push(format!(
            "diag {} sev={} {}",
            d.id,
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: Dropped) {
        self.2.store(true, std::sync::atomic::Ordering::SeqCst);
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

fn bind(folds: &Arc<Folds>, dispatcher: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("conformance"),
        max_inflight_cap: 64,
        sink: folds.clone(),
        dispatcher: dispatcher.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    }
}

/// The compiled-in row `door` states: its Statement rendering and the door.
fn row(door: DoorFn) -> LinkedRow {
    LinkedRow::of(door).expect("the door states its Statement")
}

fn linked(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    load_linked::<Auth>(&row(busbar_auth_sigv4::door), bind(folds, d))
        .expect("the linked door loads")
}

fn dropped(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    let path = built_plugin_image();
    let stated = rendering_of(busbar_auth_sigv4::door).expect("the door renders its Statement");
    load_dropped::<Auth>(&path, &stated, bind(folds, d)).expect("the dropped door loads")
}

fn err(e: &Option<Vec<u8>>) -> String {
    if let Some(bytes) = e {
        record_answer(bytes);
    }
    e.as_deref()
        .map(|e| String::from_utf8_lossy(e).replace('\n', " | "))
        .unwrap_or_default()
}

struct Buffers {
    buf: Vec<u8>,
    spans: Vec<FieldSpan>,
}

impl Buffers {
    fn new(bytes: usize, fields: usize) -> Self {
        Self {
            buf: vec![0; bytes],
            spans: vec![z(); fields],
        }
    }

    fn read(&self, n: u32) -> String {
        record_answer(&self.buf);
        let answer = (0..n as usize)
            .map(|i| {
                let f = self.spans[i];
                let at = |sp: busbar_contract::abi::mechanism::call::Span| {
                    String::from_utf8_lossy(
                        &self.buf[sp.offset as usize..sp.offset as usize + sp.len as usize],
                    )
                    .into_owned()
                };
                format!("{}: {} [flags={}]", at(f.name), at(f.value), f.flags)
            })
            .collect::<Vec<_>>()
            .join(" ; ");
        record_answer(answer.as_bytes());
        answer
    }
}

fn facts() -> RequestFacts {
    RequestFacts {
        method: s("POST"),
        authority: s("runtime.signer.example"),
        canonical_path: s("/model/m/converse"),
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        timestamp: 1_440_938_160,
    }
}

/// One `fields` call at `HeadBody`, lending the empty body (the host lends the body at `HeadBody`,
/// an empty one included).
fn fields(p: &Plugin<Auth>, handle: u64, mode: u32, caller: Blob, cap: (usize, usize)) -> String {
    fields_over(p, handle, mode, caller, cap, Some(""))
}

/// One `fields` call at `HeadBody`, lending `body` (`None`: the host lent none).
fn fields_over(
    p: &Plugin<Auth>,
    handle: u64,
    mode: u32,
    caller: Blob,
    cap: (usize, usize),
    body: Option<&'static str>,
) -> String {
    fields_for(p, handle, mode, caller, cap, body, facts())
}

/// [`fields_over`] for the walked request `request`.
fn fields_for(
    p: &Plugin<Auth>,
    handle: u64,
    mode: u32,
    caller: Blob,
    cap: (usize, usize),
    body: Option<&'static str>,
    request: RequestFacts,
) -> String {
    let mut b = Buffers::new(cap.0, cap.1);
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    f.input.mode = mode;
    f.input.request = request;

    let sent = [NamedValue {
        name: s("content-type"),
        value: blob("application/json", BLOB_OCTETS, 0),
    }];
    (f.input.headers, f.input.headers_len) = (sent.as_ptr(), sent.len());
    f.input.point = POINT_HEAD_BODY;
    f.input.body = body.map_or(z(), |b| blob(b, BLOB_OCTETS, 0));
    f.input.caller_credential = caller;
    (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
    (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
    let c = checked_call(p, slot::FIELDS, &mut f);
    let mut line = format!("fields {:?} {}", c.outcome, err(&c.error));
    let mut outcome = c.outcome;
    if let Some(token) = c.recall {
        line.push_str(&format!(
            " short(needed_fields={} needed_bytes={})",
            f.out.needed_fields, f.out.needed_bytes
        ));
        b = Buffers::new(f.out.needed_bytes as usize, f.out.needed_fields as usize);
        (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
        (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
        f.out = z();
        f.out.head = out_head();
        let c = p.recall(token, slot::FIELDS, &mut f);
        line.push_str(&format!(" -> recall {:?}", c.outcome));
        outcome = c.outcome;
    }
    if outcome == Outcome::Ready {
        line.push_str(&format!(" {}", b.read(f.out.fields_len)));
    }
    line
}

fn open_outbound(
    p: &Plugin<Auth>,
    style: &'static str,
    credential: Option<&'static str>,
    settings: &'static str,
) -> (String, u64) {
    let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.style = s(style);
    f.input.credential = credential.map_or(z(), secret);
    f.input.settings = json(settings);
    let c = checked_call(p, slot::OPEN_OUTBOUND, &mut f);
    (
        format!("open_outbound {style} {:?} {}", c.outcome, err(&c.error)),
        f.out.handle,
    )
}

fn ready(p: &Plugin<Auth>, handle: u64) -> String {
    let mut f: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    let c = checked_call(p, slot::OUTBOUND_READY, &mut f);
    format!("ready {:?} {}", c.outcome, f.out.ready)
}

/// The live credential the host holds.
const AKID: &str = "BBAKCONFORMANCE000001";
const LIVE_SECRET: &str = "conformance/live+SECRET0000000000000000000";
/// A credential the host holds that is not live.
const DEAD_AKID: &str = "BBAKCONFORMANCE000002";
const DEAD_SECRET: &str = "conformance/dead+SECRET0000000000000000000";
/// The host's fixed dummy for an id it does not hold (the kernel's `auth::DUMMY_SECRET`).
const DUMMY: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";
/// The request's clock and the path signed: AWS's example timestamp.
const NOW: u64 = 1_440_938_160;
const AMZDATE: &str = "20150830T123600Z";
const PATH: &str = "/model/m/converse";

/// What the vectors' host serves for credential `id` of `kind`: the entry of `conformance.json`'s
/// `host_credentials` (`rotated_host_credentials` once `rotated`), or the fixed dummy, not live, for
/// an id it does not hold. The vector file, not a copy of it here, is what the host serves.
fn vector_secret(kind: &str, id: &str, rotated: bool) -> (String, u64) {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("conformance.json")).unwrap();
    let held = if rotated {
        "rotated_host_credentials"
    } else {
        "host_credentials"
    };
    vectors["auth"][held]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"].as_str() == Some(kind) && c["id"].as_str() == Some(id))
        .map_or_else(
            || (DUMMY.to_owned(), SECRET_NOT_LIVE),
            |c| {
                let live = if c["live"].as_bool().unwrap() {
                    SECRET_LIVE
                } else {
                    SECRET_NOT_LIVE
                };
                (c["secret"].as_str().unwrap().to_owned(), live)
            },
        )
}

/// THE HOST: every service refused but `records.secret`, which serves the credentials above (and
/// the dummy, not live, for any other id) at once, and records each read.
#[derive(Default)]
struct Creds(
    Mutex<Vec<String>>,
    std::sync::atomic::AtomicBool,
    std::sync::atomic::AtomicBool,
);

impl Creds {
    fn drain(&self) -> String {
        std::mem::take(&mut *self.0.lock().unwrap()).join(", ")
    }
}

impl HostServices for Creds {
    fn dest_judge(&self, _dest: &str, _class: u32, _flags: u32, _later: Option<Later>) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_get(&self, _caller: &Caller, _kind: &str, _key: &[u8], _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_list(&self, _caller: &Caller, _list: RecordsList, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_claim(
        &self,
        _caller: &Caller,
        _kind: &str,
        _key: &[u8],
        _ttl_ms: u64,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn sign(&self, _caller: &Caller, _data: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _hash: &str,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_unreached(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight_item(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: &str,
        _digest: &str,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_decide(
        &self,
        _caller: &Caller,
        _ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        _key: TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_state(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_serves(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: Option<&str>,
        _digest: Option<&str>,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_due(&self, _caller: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_verify(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _payload: &[u8],
        _signatures: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn entitlement_check(&self, _caller: &Caller, _unit: Option<u64>, _target: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn session_emit(&self, _caller: &Caller, _session: u64, _bytes: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn ticket_mint(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn ticket_take(&self, _caller: &Caller, _unit: Option<u64>) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn random_fill(&self, _len: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_open(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _kind: &str,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_find(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _reference: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_settle(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_resume(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn disk_append(&self, _dest: &DiskDest, _bytes: Vec<u8>, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_lookup(&self, _caller: &Caller, _key: &[u8], _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_store(&self, _caller: &Caller, _key: &[u8], _entry: &[u8], _ttl_ms: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn content_scan(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _content: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn hook_call(&self, _caller: &Caller, _unit: Option<u64>, _ask: HookAsk, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn snapshot_read(&self, _caller: &Caller, _scope: u32, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }

    fn now(&self) -> Reading {
        Reading {
            wall_ns: NOW * 1_000_000_000,
            mono_ns: 0,
        }
    }
    fn records_secret(&self, kind: &str, id: &str, _: Later) -> Ran {
        self.0.lock().unwrap().push(format!("{kind}:{id}"));
        let (secret, live) = if self.1.load(std::sync::atomic::Ordering::SeqCst) {
            vector_secret(kind, id, self.2.load(std::sync::atomic::Ordering::SeqCst))
        } else {
            match id {
                AKID => (LIVE_SECRET.to_owned(), SECRET_LIVE),
                DEAD_AKID => (DEAD_SECRET.to_owned(), SECRET_NOT_LIVE),
                _ => (DUMMY.to_owned(), SECRET_NOT_LIVE),
            }
        };
        let mut stored = Stored::ready(live);
        stored.bytes = secret.as_bytes().to_vec();
        stored.spans = vec![ItemSpan {
            key: Span {
                offset: SPAN_ABSENT,
                len: 0,
            },
            value: Span {
                offset: 0,
                len: secret.len() as u32,
            },
        }];
        Ran::Now(stored)
    }
}

/// One inbound request as the host presents it at `HeadBody`, owning every byte its frame points
/// at, with the host's identity buffer and strip array.
struct Inbound {
    lines: Vec<(String, String)>,
    named: Vec<NamedValue>,
    body: Vec<u8>,
    bytes: Vec<u8>,
    groups: Vec<Span>,
    strips: Vec<StripName>,
}

impl Inbound {
    fn new(lines: Vec<(String, String)>, body: &[u8]) -> Self {
        let mut i = Self {
            lines,
            named: Vec::new(),
            body: body.to_vec(),
            bytes: vec![0; auth::IDENTITY_BUF_BYTES],
            groups: vec![Span { offset: 0, len: 0 }; 8],
            strips: vec![
                StripName {
                    name: Span { offset: 0, len: 0 },
                    place: 0,
                    _reserved: 0,
                };
                auth::FIELDS_MAX as usize
            ],
        };
        i.named = i
            .lines
            .iter()
            .map(|(n, v)| NamedValue {
                name: AbiStr {
                    ptr: n.as_ptr(),
                    len: n.len(),
                },
                value: Blob {
                    ptr: v.as_ptr(),
                    len: v.len(),
                    fmt: BLOB_OCTETS,
                    flags: 0,
                },
            })
            .collect();
        i
    }

    /// A client's request signed with `secret` as `akid` (over the body `signed_body`), carrying
    /// `body`.
    fn signed(secret: &str, akid: &str, signed_body: &[u8], body: &[u8]) -> Self {
        let payload_hash = sha256_hex(signed_body);
        let headers = vec![
            ("host".to_string(), "busbar.example".to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), AMZDATE.to_string()),
        ];
        let (sig, signed_headers) = signature::sign_v4(
            secret,
            "us-east-1",
            "bedrock",
            "POST",
            PATH,
            "",
            &headers,
            &payload_hash,
            AMZDATE,
            &AMZDATE[..8],
        );
        let mut lines = vec![(
            "authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={akid}/{}/us-east-1/bedrock/aws4_request, \
                 SignedHeaders={signed_headers}, Signature={sig}",
                &AMZDATE[..8]
            ),
        )];
        lines.extend(headers);
        Self::new(lines, body)
    }

    fn frame(&mut self) -> Frame<VerifyIn, IdentifyOut> {
        let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
        f.input.head = in_head();
        f.out.head = out_head();
        f.input.lines = self.named.as_ptr();
        f.input.lines_len = self.named.len();
        f.input.request = RequestFacts {
            method: s("POST"),
            authority: s("busbar.example"),
            canonical_path: s(PATH),
            query: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            timestamp: NOW,
        };
        f.input.point = POINT_HEAD_BODY;
        f.input.body = Blob {
            ptr: self.body.as_ptr(),
            len: self.body.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        f.input.out_buf = IdentityBuf {
            buf: self.bytes.as_mut_ptr(),
            buf_cap: self.bytes.len(),
            groups: self.groups.as_mut_ptr(),
            groups_cap: self.groups.len() as u32,
            _reserved: 0,
        };
        f.input.strip = self.strips.as_mut_ptr();
        f.input.strip_cap = self.strips.len() as u32;
        f
    }

    fn verdict(&self, outcome: Outcome, out: &IdentifyOut) -> String {
        record_answer(&self.bytes);
        record_answer(
            format!(
                "needed={}/{}/{} groups={} lease={}",
                out.needed_bytes,
                out.needed_groups,
                out.needed_strip,
                out.identity.groups_len,
                out.head.lease
            )
            .as_bytes(),
        );
        if outcome != Outcome::Ready {
            return format!("{outcome:?}");
        }
        let v = match out.verdict {
            VERDICT_IDENTITY => {
                let sp = out.identity.subject;
                format!(
                    "Identity({}) ttl={} replay={} credential={}",
                    String::from_utf8_lossy(
                        &self.bytes[sp.offset as usize..(sp.offset + sp.len) as usize]
                    ),
                    out.identity.flags,
                    out.identity.replay_key.offset != SPAN_ABSENT,
                    out.identity.credential.len
                )
            }
            VERDICT_REJECT => "Reject".to_string(),
            VERDICT_PASS => "Pass".to_string(),
            other => format!("verdict={other}"),
        };
        let answer = format!(
            "Ready {v} decision={} strips={}",
            out.decision, out.strip_len
        );
        record_answer(answer.as_bytes());
        answer
    }
}

/// `verify` ON THE SPOT, ticket-less.
fn verify_now(p: &Plugin<Auth>, req: &mut Inbound) -> String {
    let mut f = req.frame();
    let c = checked_call(p, slot::VERIFY, &mut f);
    req.verdict(c.outcome, &f.out)
}

/// `verify` SUBMITTED on a ticket, awaited, the ticket recycled.
fn verify_submitted(p: &Plugin<Auth>, d: &Dispatcher, req: &mut Inbound) -> String {
    let before = first_crossings(p);
    let ticket = d.mint(0).expect("a ticket is free");
    let deadline = now_ns().saturating_add(10_000_000_000);
    let reply = d.submit(
        p,
        ticket,
        slot::VERIFY,
        req.frame(),
        DeadlineClass::Call,
        deadline,
    );
    let done = reply.wait(Duration::from_secs(10));
    drop(reply);
    d.recycle(ticket);
    assert!(d.retirement_barrier(ticket, Duration::from_secs(10)));
    assert_eq!(
        first_crossings(p) - before,
        1,
        "one submitted verify crossing"
    );
    let done = done.expect("the submitted verify answers");
    if let Some(bytes) = &done.error {
        record_answer(bytes);
    }
    match &done.frame {
        Some(f) => req.verdict(done.outcome, &f.out),
        None => format!("{:?} frame=none", done.outcome),
    }
}

fn bearer() -> Inbound {
    Inbound::new(
        vec![(
            "authorization".to_string(),
            "Bearer sk-busbar-1".to_string(),
        )],
        b"",
    )
}

/// THE INBOUND STEPS, on an open instance: on the spot, then (with a host) submitted.
fn inbound_steps(p: &Plugin<Auth>, host: Option<(&Dispatcher, &Creds)>, t: &mut Vec<String>) {
    let body = br#"{"messages":[]}"#;
    t.push(format!(
        "verify bearer now {}",
        verify_now(p, &mut bearer())
    ));
    t.push(format!(
        "verify sigv4 now {}",
        verify_now(p, &mut Inbound::signed(LIVE_SECRET, AKID, body, body))
    ));
    let mut trivial = Inbound::new(
        vec![(
            "authorization".to_string(),
            "AWS4-HMAC-SHA256 x".to_string(),
        )],
        b"",
    );
    t.push(format!(
        "verify trivial now {}",
        verify_now(p, &mut trivial)
    ));
    let Some((d, creds)) = host else {
        return;
    };
    t.push(format!("reads now [{}]", creds.drain()));
    let cases = [
        ("live", Inbound::signed(LIVE_SECRET, AKID, body, body)),
        (
            "unknown",
            Inbound::signed(LIVE_SECRET, "BBAKNOBODY", body, body),
        ),
        (
            "dummy-signed",
            Inbound::signed(DUMMY, "BBAKNOBODY", body, body),
        ),
        (
            "not live",
            Inbound::signed(DEAD_SECRET, DEAD_AKID, body, body),
        ),
        ("wrong secret", Inbound::signed("not-it", AKID, body, body)),
        (
            "tampered body",
            Inbound::signed(LIVE_SECRET, AKID, body, b"{}"),
        ),
        ("bearer", bearer()),
    ];
    for (label, mut req) in cases {
        t.push(format!(
            "verify {label} submitted {} reads=[{}]",
            verify_submitted(p, d, &mut req),
            creds.drain()
        ));
    }
}

const SIGV4_SETTINGS: &str = r#"{"service":"svc","region":"us-east-1"}"#;

fn script(p: &Plugin<Auth>, host: Option<(&Dispatcher, &Creds)>) -> Vec<String> {
    let mut t = Vec::new();

    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json("[1]"),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    let c = checked_call(p, life::VALIDATE, &mut v);
    t.push(format!("validate [1] {:?} {}", c.outcome, err(&c.error)));
    v.input.settings = json("{}");
    t.push(format!(
        "validate {:?}",
        checked_call(p, life::VALIDATE, &mut v).outcome
    ));

    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    t.push(format!(
        "open {:?}",
        checked_call(p, life::OPEN, &mut o).outcome
    ));

    let (l, sigv4) = open_outbound(p, "sigv4", Some("AKIDEXAMPLE:SECRET:TOKEN"), SIGV4_SETTINGS);
    t.push(l);
    let (l, keyless) = open_outbound(p, "sigv4", None, SIGV4_SETTINGS);
    t.push(l);
    t.push(open_outbound(p, "bearer", Some("k"), "{}").0);
    t.push(open_outbound(p, "kerberos", Some("k"), "{}").0);

    t.push(fields(p, sigv4, MODE_OWN, z(), (1024, 4)));
    t.push(fields(p, sigv4, MODE_OWN, z(), (8, 0)));
    t.push(fields(
        p,
        keyless,
        MODE_PASSTHROUGH,
        secret("AKIDCALLER:CALLERSECRET"),
        (1024, 4),
    ));
    t.push(fields(p, keyless, MODE_OWN, z(), (1024, 4)));
    t.push(fields(p, 999, MODE_OWN, z(), (1024, 4)));

    t.push(fields_over(p, sigv4, MODE_OWN, z(), (1024, 4), Some("{}")));

    for h in [sigv4, keyless] {
        t.push(ready(p, h));
    }

    let mut k = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 1_000,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    let c = checked_call(p, life::TICK, &mut k);
    t.push(format!(
        "tick {:?} next>1000={}",
        c.outcome,
        k.out.next_tick_ns > 1_000
    ));

    inbound_steps(p, host, &mut t);

    let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
    x.input.head = in_head();
    x.out.head = out_head();
    let c = checked_call(p, life::CANCEL, &mut x);
    t.push(format!("cancel {:?}", c.outcome));

    let mut r: Frame<RefreshIn, _> = Frame::new(z(), out_head());
    r.input.head = in_head();
    r.input.generation = 2;
    t.push(format!(
        "refresh {:?}",
        checked_call(p, life::REFRESH, &mut r).outcome
    ));
    let (l, sigv4_2) = open_outbound(p, "sigv4", Some("AKIDEXAMPLE:SECRET:TOKEN"), SIGV4_SETTINGS);
    t.push(l);
    let mut g = Frame::new(
        GenIn {
            head: in_head(),
            generation: 1,
        },
        out_head(),
    );
    t.push(format!(
        "retire 1 {:?}",
        checked_call(p, life::RETIRE, &mut g).outcome
    ));
    t.push(format!(
        "after retire {}",
        fields(p, sigv4, MODE_OWN, z(), (1024, 4))
    ));
    let after_retire_gen2 = fields(p, sigv4_2, MODE_OWN, z(), (1024, 4));
    t.push(format!(
        "gen 2 fields ready with a signature: {}",
        after_retire_gen2.starts_with("fields Ready  authorization: AWS4-HMAC-SHA256")
    ));

    let mut e = Frame::new(in_head(), out_head());
    t.push(format!(
        "close {:?}",
        checked_call(p, life::CLOSE, &mut e).outcome
    ));
    t
}

const EXPECTED: &[&str] = &[
    "validate [1] Failed settings: must be a JSON object",
    "validate Ready",
    "open Ready",
    "open_outbound sigv4 Ready ",
    "open_outbound sigv4 Ready ",
    "open_outbound bearer Failed settings: outbound auth style `bearer` is not served by this \
     plugin",
    "open_outbound kerberos Failed settings: outbound auth style `kerberos` is not served by this \
     plugin",
    "fields Ready  authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/\
     svc/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;\
     x-amz-security-token, Signature=SIGNATURE [flags=1] ; x-amz-date: 20150830T123600Z [flags=0] ; \
     x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
     [flags=0] ; x-amz-security-token: TOKEN [flags=1]",
    "fields Failed  short(needed_fields=4 needed_bytes=385) -> recall Ready authorization: \
     AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/svc/aws4_request, \
     SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, \
     Signature=SIGNATURE [flags=1] ; x-amz-date: 20150830T123600Z [flags=0] ; \
     x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
     [flags=0] ; x-amz-security-token: TOKEN [flags=1]",
    "fields Ready  authorization: AWS4-HMAC-SHA256 Credential=AKIDCALLER/20150830/us-east-1/svc/\
     aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
     Signature=SIGNATURE [flags=1] ; x-amz-date: 20150830T123600Z [flags=0] ; \
     x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
     [flags=0]",
    "fields Failed sigv4: this binding holds no credential of its own (passthrough-only); the \
     request is not sent unsigned",
    "fields Refused the auth plugin refused the request's fields and gave no reason",
    "fields Ready  authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/\
     svc/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;\
     x-amz-security-token, Signature=SIGNATURE [flags=1] ; x-amz-date: 20150830T123600Z [flags=0] ; \
     x-amz-content-sha256: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a \
     [flags=0] ; x-amz-security-token: TOKEN [flags=1]",
    "ready Ready 1",
    "ready Ready 1",
    "tick Ready next>1000=true",
    "verify bearer now Ready Pass decision=1 strips=0",
    "verify sigv4 now Refused",
    "verify trivial now Ready Reject decision=2 strips=1",
    "reads now []",
    "verify live submitted Ready Identity(BBAKCONFORMANCE000001) ttl=0 replay=false credential=0 \
     decision=1 strips=1 reads=[sigv4:BBAKCONFORMANCE000001]",
    "verify unknown submitted Ready Reject decision=2 strips=1 reads=[sigv4:BBAKNOBODY]",
    "verify dummy-signed submitted Ready Reject decision=2 strips=1 reads=[sigv4:BBAKNOBODY]",
    "verify not live submitted Ready Reject decision=2 strips=1 \
     reads=[sigv4:BBAKCONFORMANCE000002]",
    "verify wrong secret submitted Ready Reject decision=2 strips=1 \
     reads=[sigv4:BBAKCONFORMANCE000001]",
    "verify tampered body submitted Ready Reject decision=2 strips=1 reads=[]",
    "verify bearer submitted Ready Pass decision=1 strips=0 reads=[]",
    "cancel Ready",
    "refresh Ready",
    "open_outbound sigv4 Ready ",
    "retire 1 Ready",
    "after retire fields Refused the auth plugin refused the request's fields and gave no reason",
    "gen 2 fields ready with a signature: true",
    "close Ready",
];

/// The plugin's own log, folded into the host's: each inbound REJECT names its reason (module
/// `sigv4`, at info), the AccessKeyId where one parsed, never the signature or the secret.
const EXPECTED_FOLDS: &[&str] = &[
    "diag 4294967295 sev=0 busbar_auth_sigv4::style: sigv4 outbound binding refused module=\"sigv4\" reason=\"settings: outbound auth style `bearer` is not served by this plugin\"",
    "diag 4294967295 sev=0 busbar_auth_sigv4::style: sigv4 outbound binding refused module=\"sigv4\" reason=\"settings: outbound auth style `kerberos` is not served by this plugin\"",
    "diag 4294967295 sev=0 busbar_auth_sigv4::instance: sigv4 request not signed: FAILED module=\"sigv4\" reason=\"sigv4: this binding holds no credential of its own (passthrough-only); the request is not sent unsigned\"",
    "diag 4294967295 sev=0 busbar_auth_sigv4::instance: sigv4 request not signed: REFUSED, no such handle (never opened, or retired) module=\"sigv4\" handle=999",
    "diag 4294967295 sev=0 busbar_auth_sigv4::inbound: sigv4 inbound request rejected module=\"sigv4\" reason=\"unparseable SigV4 authorization\"",
    "diag 4294967295 sev=0 busbar_auth_sigv4::inbound: sigv4 inbound request rejected module=\"sigv4\" reason=\"signature\" access_key_id=BBAKNOBODY",
    "diag 4294967295 sev=0 busbar_auth_sigv4::inbound: sigv4 inbound request rejected module=\"sigv4\" reason=\"signature\" access_key_id=BBAKNOBODY",
    "diag 4294967295 sev=0 busbar_auth_sigv4::inbound: sigv4 inbound request rejected module=\"sigv4\" reason=\"signature\" access_key_id=BBAKCONFORMANCE000002",
    "diag 4294967295 sev=0 busbar_auth_sigv4::inbound: sigv4 inbound request rejected module=\"sigv4\" reason=\"signature\" access_key_id=BBAKCONFORMANCE000001",
    "diag 4294967295 sev=0 busbar_auth_sigv4::inbound: sigv4 inbound request rejected module=\"sigv4\" reason=\"payload hash mismatch\"",
    "diag 4294967295 sev=0 busbar_auth_sigv4::instance: sigv4 request not signed: REFUSED, no such handle (never opened, or retired) module=\"sigv4\" handle=1",
];

/// The SigV4 signature depends on nothing but its inputs; it is replaced by a marker so the
/// transcript reads, and pinned separately by `signing_tests` and the AWS vectors.
fn mask_signature(t: Vec<String>) -> Vec<String> {
    t.into_iter()
        .map(|l| match l.find("Signature=") {
            Some(i) => {
                let end = l[i..].find(' ').map_or(l.len(), |e| i + e);
                format!("{}Signature=SIGNATURE{}", &l[..i], &l[end..])
            }
            None => l,
        })
        .collect()
}

fn run(
    p: &Plugin<Auth>,
    folds: &Folds,
    d: &Dispatcher,
    creds: &Creds,
) -> (Vec<String>, Vec<String>) {
    let t = script(p, Some((d, creds)));
    (t, std::mem::take(&mut *folds.0.lock().unwrap()))
}

#[test]
fn compiled_in_and_dropped_in_answer_every_op_identically() {
    let creds = Arc::new(Creds::default());
    let d = Dispatcher::with_services(
        DispatchConfig::default(),
        creds.clone(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let (linked_t, linked_f) = run(&linked(&folds, &d), &folds, &d, &creds);
    assert_eq!(
        mask_signature(linked_t.clone()),
        EXPECTED,
        "the linked door"
    );
    assert_eq!(linked_f, EXPECTED_FOLDS, "the linked door's folds");
    let folds = Arc::new(Folds::default());
    {
        let p = dropped(&folds, &d);
        let (dropped_t, dropped_f) = run(&p, &folds, &d, &creds);
        assert_eq!(dropped_t, linked_t, "the dropped door, signature included");
        assert_eq!(dropped_f, linked_f, "the dropped door's folds");
        println!(
            "PROOF auth-sigv4: linked and dropped answered {} ops and {} folds identically",
            linked_t.len(),
            linked_f.len()
        );
    }
}

#[test]
fn signed_obs_text_duplicates_refuse_on_the_real_loader_in_both_legs() {
    let creds = Arc::new(Creds::default());
    let d = Dispatcher::with_services(
        DispatchConfig::default(),
        creds.clone(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    for p in [linked(&folds, &d), dropped(&folds, &d)] {
        let mut opened: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
        opened.input.head = in_head();
        opened.out.head = out_head();
        assert_eq!(
            checked_call(&p, life::OPEN, &mut opened).outcome,
            Outcome::Ready
        );
        let hash = sha256_hex(b"");
        let signed_lines = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("host".to_string(), "busbar.example".to_string()),
            ("x-amz-content-sha256".to_string(), hash.clone()),
            ("x-amz-date".to_string(), AMZDATE.to_string()),
        ];
        let (sig, names) = signature::sign_v4(
            LIVE_SECRET,
            "us-east-1",
            "bedrock",
            "POST",
            PATH,
            "",
            &signed_lines,
            &hash,
            AMZDATE,
            &AMZDATE[..8],
        );
        let mut lines = vec![(
            "authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={AKID}/{}/us-east-1/bedrock/aws4_request, \
             SignedHeaders={names}, Signature={sig}",
                &AMZDATE[..8]
            ),
        )];
        lines.extend(signed_lines);
        let good = verify_submitted(&p, &d, &mut Inbound::new(lines.clone(), b""));
        assert!(good.starts_with("Ready Identity("), "{good}");
        assert_eq!(creds.drain(), format!("sigv4:{AKID}"));
        lines.push(("Content-Type".into(), "é".into()));
        let bad = verify_submitted(&p, &d, &mut Inbound::new(lines.clone(), b""));
        assert!(bad.starts_with("Ready Reject"), "{bad}");
        assert!(creds.drain().is_empty(), "refused before records.secret");
        lines.last_mut().unwrap().0 = "x-unsigned".into();
        let unsigned = verify_submitted(&p, &d, &mut Inbound::new(lines, b""));
        assert!(unsigned.starts_with("Ready Identity("), "{unsigned}");
        assert_eq!(creds.drain(), format!("sigv4:{AKID}"));
        let mut close = Frame::new(in_head(), out_head());
        assert_eq!(
            checked_call(&p, life::CLOSE, &mut close).outcome,
            Outcome::Ready
        );
    }
}

fn door_with_fields(op: Op) -> &'static Door {
    // SAFETY: the plugin's `'static` door and its auth table.
    let (d, ops) = unsafe {
        let d = busbar_auth_sigv4::door();
        (d, *d.ops().cast::<auth::Ops>())
    };
    let mut ops = ops;
    ops.fields = Some(op);
    let ops: &'static auth::Ops = Box::leak(Box::new(ops));
    // SAFETY: the plugin's own door parts, with `ops` at a `'static` auth table whose every slot is
    // the plugin's or one of this file's call-convention ops.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ops: std::ptr::from_ref(ops).cast(),
            ..d.parts()
        })
    }))
}

fn real_fields() -> Op {
    // SAFETY: the plugin's `'static` door and its auth table.
    unsafe {
        (*busbar_auth_sigv4::door().ops().cast::<auth::Ops>())
            .fields
            .unwrap()
    }
}

unsafe extern "C" fn sensitive_fields(
    inst: *mut c_void,
    i: *const c_void,
    o: *mut c_void,
) -> RawOutcome {
    // SAFETY: door_with_fields installs this wrapper only in FIELDS, retaining the original
    // door's OPEN/CLOSE and instance implementation. The real FIELDS therefore receives its
    // own live instance and the same initialized, aligned FieldsIn/FieldsOut frames the loader
    // lent this wrapper. Their headers and backing request/output buffers remain live for the
    // synchronous forwarding call; this wrapper retains no instance or frame pointers.
    let r = unsafe { real_fields()(inst, i, o) };
    // SAFETY: these are those same live typed frames. Only a READY reply is inspected below;
    // the real FIELDS producer guarantees fields_len <= fields_cap, so each modified row lies
    // within the host's writable, aligned field array. The wrapper retains no buffer pointer.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &*o.cast::<FieldsOut>());
        if r.outcome() == Outcome::Ready {
            for k in 0..o.fields_len as usize {
                (*i.fields.add(k)).flags = FIELD_SENSITIVE;
            }
        }
    }
    r
}

extern "C" fn sensitive_door() -> &'static Door {
    door_with_fields(sensitive_fields)
}

#[test]
fn red_a_writer_that_flags_every_field_is_not_the_pinned_bytes() {
    let creds = Arc::new(Creds::default());
    let d = Dispatcher::with_services(
        DispatchConfig::default(),
        creds.clone(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let red = load_linked::<Auth>(&row(sensitive_door), bind(&folds, &d)).expect("the door loads");
    let t = mask_signature(script(&red, Some((&d, &creds))));
    assert_ne!(
        t, EXPECTED,
        "a flag on a field that carries no credential must not pass as the pinned bytes"
    );
    assert!(
        t.iter()
            .any(|l| l.contains("x-amz-date: 20150830T123600Z [flags=1]")),
        "the kind's check admits the flag; only the pinned transcript refuses it"
    );
}

extern "C" fn overrunning_fields(_: *mut c_void, i: *const c_void, o: *mut c_void) -> RawOutcome {
    // SAFETY: the host's live `FieldsOut` for this call; nothing is written past its `out`.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &mut *o.cast::<FieldsOut>());
        o.fields_len = i.fields_cap + 1;
        o.head.outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn overrunning_door() -> &'static Door {
    door_with_fields(overrunning_fields)
}

#[test]
fn red_a_writer_that_ignores_the_host_capacity_faults() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let red =
        load_linked::<Auth>(&row(overrunning_door), bind(&folds, &d)).expect("the door loads");
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    assert_eq!(red.call(life::OPEN, &mut o).outcome, Outcome::Ready);
    let (_, h) = open_outbound(&red, "sigv4", Some("AKIDEXAMPLE:SECRET"), SIGV4_SETTINGS);
    assert!(fields(&red, h, MODE_OWN, z(), (1024, 4)).starts_with("fields Fault"));
}

/// An opened linked instance over the inbound cell's host, with one sigv4 handle on `credential`.
fn open_signing(credential: &'static str) -> (Arc<Folds>, Plugin<Auth>, u64) {
    let creds = Arc::new(Creds::default());
    let d = Dispatcher::with_services(
        DispatchConfig::default(),
        creds,
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let p = linked(&folds, &d);
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    assert_eq!(checked_call(&p, life::OPEN, &mut o).outcome, Outcome::Ready);
    let (line, handle) = open_outbound(&p, "sigv4", Some(credential), SIGV4_SETTINGS);
    assert_eq!(line, "open_outbound sigv4 Ready ");
    (folds, p, handle)
}

/// The walked request's method and query reach the signer: a GET with a query is signed over that
/// query, so its signature is not the one of the same GET without it, nor of the POST.
#[test]
fn fields_signs_the_walked_requests_query_and_method_through_the_door() {
    let (_, p, handle) = open_signing("AKIDEXAMPLE:SECRET");
    let sign = |method: &'static str, query: Option<&'static str>| {
        let mut request = facts();
        request.method = s(method);
        if let Some(q) = query {
            request.query = s(q);
        }
        fields_for(&p, handle, MODE_OWN, z(), (1024, 4), Some(""), request)
    };
    let get_with_query = sign("GET", Some("a=1&b=2"));
    assert!(
        get_with_query.starts_with("fields Ready  authorization: AWS4-HMAC-SHA256"),
        "{get_with_query}"
    );
    assert_ne!(get_with_query, sign("GET", None), "the query is signed");
    assert_ne!(
        get_with_query,
        sign("GET", Some("a=1&b=3")),
        "its value too"
    );
    assert_ne!(
        get_with_query,
        sign("POST", Some("a=1&b=2")),
        "the method too"
    );
    assert_eq!(
        get_with_query,
        sign("GET", Some("b=2&a=1")),
        "sorted, as signed"
    );
}

#[test]
fn an_unsendable_session_token_is_refused_at_open_through_the_door() {
    let creds = Arc::new(Creds::default());
    let d = Dispatcher::with_services(
        DispatchConfig::default(),
        creds,
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let p = linked(&folds, &d);
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    assert_eq!(checked_call(&p, life::OPEN, &mut o).outcome, Outcome::Ready);
    let (line, _) = open_outbound(&p, "sigv4", Some("AKID:SECRET:bad\x01tok"), SIGV4_SETTINGS);
    assert_eq!(
        line,
        "open_outbound sigv4 Failed credential: the session token holds a byte no header value \
         may carry"
    );
    let noted = std::mem::take(&mut *folds.0.lock().unwrap());
    assert_eq!(
        noted,
        [
            "diag 4294967295 sev=0 busbar_auth_sigv4::style: sigv4 outbound binding refused \
          module=\"sigv4\" reason=\"credential: the session token holds a byte no header value \
          may carry\""
        ],
        "the refusal never exposes the token"
    );
}

/// A `fields` call the host lends no authority cannot be signed: FAILED, and the failure says why
/// (a refusal with an empty reason leaves the operator nothing to act on).
#[test]
fn a_fields_call_without_an_authority_fails_with_its_reason() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let p = linked(&folds, &d);
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    assert_eq!(checked_call(&p, life::OPEN, &mut o).outcome, Outcome::Ready);
    let (_, h) = open_outbound(&p, "sigv4", Some("AKIDEXAMPLE:SECRET"), SIGV4_SETTINGS);
    let mut b = Buffers::new(1024, 4);
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = h;
    f.input.mode = MODE_OWN;
    f.input.request = facts();
    f.input.request.authority = s("");
    f.input.point = POINT_HEAD_BODY;
    (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
    (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
    let c = checked_call(&p, slot::FIELDS, &mut f);
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(
        err(&c.error),
        "sigv4 cannot sign: the host lent no authority"
    );
}

#[test]
fn a_fields_call_with_nothing_to_sign_with_fails_with_its_reason() {
    let creds = Arc::new(Creds::default());
    let d = Dispatcher::with_services(
        DispatchConfig::default(),
        creds,
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let p = linked(&folds, &d);
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    assert_eq!(checked_call(&p, life::OPEN, &mut o).outcome, Outcome::Ready);
    let (line, keyless) = open_outbound(&p, "sigv4", None, SIGV4_SETTINGS);
    assert_eq!(line, "open_outbound sigv4 Ready ");
    assert_eq!(
        fields(&p, keyless, MODE_OWN, z(), (1024, 4)),
        "fields Failed sigv4: this binding holds no credential of its own (passthrough-only); \
         the request is not sent unsigned"
    );
    assert_eq!(
        fields(&p, keyless, MODE_PASSTHROUGH, z(), (1024, 4)),
        "fields Failed sigv4 passthrough: the caller presented no credential; the request is \
         not sent unsigned"
    );
    for (caller, reason) in [
        (
            "AKIDCALLER",
            "caller credential: expected ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]",
        ),
        (
            "AKIDCALLER:",
            "caller credential: the secret access key is empty",
        ),
        (
            "AKIDCALLER:CALLERSECRET:bad\x01tok",
            "caller credential: the session token holds a byte no header value may carry",
        ),
    ] {
        let line = fields(&p, keyless, MODE_PASSTHROUGH, secret(caller), (1024, 4));
        assert_eq!(line, format!("fields Failed {reason}"), "{caller:?}");
    }
}

#[test]
fn an_unserved_secret_read_rejects_and_logs_the_service_error() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let p = linked(&folds, &d);
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    assert_eq!(checked_call(&p, life::OPEN, &mut o).outcome, Outcome::Ready);
    let body = br#"{"messages":[]}"#;
    let verdict = verify_submitted(&p, &d, &mut Inbound::signed(LIVE_SECRET, AKID, body, body));
    assert!(verdict.starts_with("Ready Reject"), "{verdict}");
    let folds = std::mem::take(&mut *folds.0.lock().unwrap());
    assert!(
        folds
            .iter()
            .any(|l| l.contains("reason=\"credential-unavailable\"")
                && l.contains("service_error=\"refused\"")),
        "{folds:#?}"
    );
}

/// The `fields` line `request` answers on a fresh own-credential handle, its body lent (`{}`).
fn fields_answer(request: RequestFacts) -> String {
    let (_, p, handle) = open_signing("AKIDEXAMPLE:SECRET");
    fields_for(&p, handle, MODE_OWN, z(), (1024, 4), Some("{}"), request)
}

#[test]
fn a_query_that_is_not_utf8_fails_the_fields_call() {
    const QUERY: &[u8] = b"a=\xff";
    let mut request = facts();
    request.query = AbiStr {
        ptr: QUERY.as_ptr(),
        len: QUERY.len(),
    };
    assert_eq!(
        fields_answer(request),
        "fields Failed sigv4 cannot sign: the query is not UTF-8"
    );
}

#[test]
fn every_x_amz_line_the_head_carries_is_signed() {
    let (_, p, handle) = open_signing("AKIDEXAMPLE:SECRET");
    let sent = [
        NamedValue {
            name: s("content-type"),
            value: blob("application/x-amz-json-1.1", BLOB_OCTETS, 0),
        },
        NamedValue {
            name: s("Content-Type"),
            value: blob("  application/json  ", BLOB_OCTETS, 0),
        },
        NamedValue {
            name: s("host"),
            value: blob("untrusted-header.example", BLOB_OCTETS, 0),
        },
        NamedValue {
            name: s("content-length"),
            value: blob("2", BLOB_OCTETS, 0),
        },
        NamedValue {
            name: s("accept"),
            value: blob("*/*", BLOB_OCTETS, 0),
        },
        NamedValue {
            name: s("X-Amz-Target"),
            value: blob("AmazonSSM.GetParameter", BLOB_OCTETS, 0),
        },
        NamedValue {
            name: s("x-amz-meta-note"),
            value: blob("  a   b ", BLOB_OCTETS, 0),
        },
        NamedValue {
            name: s("x-amz-date"),
            value: blob("19700101T000000Z", BLOB_OCTETS, 0),
        },
        NamedValue {
            name: s("x-amzn-trace-id"),
            value: blob("Root=1", BLOB_OCTETS, 0),
        },
    ];
    let mut b = Buffers::new(1024, 4);
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    f.input.mode = MODE_OWN;
    f.input.request = facts();
    (f.input.headers, f.input.headers_len) = (sent.as_ptr(), sent.len());
    f.input.point = POINT_HEAD_BODY;
    f.input.body = blob("{}", BLOB_OCTETS, 0);
    (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
    (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
    let c = checked_call(&p, slot::FIELDS, &mut f);
    assert_eq!(c.outcome, Outcome::Ready, "{}", err(&c.error));
    let hash = sha256_hex(b"{}");
    let (signature, signed_headers) = signature::sign_v4(
        "SECRET",
        "us-east-1",
        "svc",
        "POST",
        "/model/m/converse",
        "",
        &[
            (
                "content-type",
                "application/x-amz-json-1.1,application/json",
            ),
            ("host", "runtime.signer.example"),
            ("x-amz-content-sha256", hash.as_str()),
            ("x-amz-date", "20150830T123600Z"),
            ("x-amz-meta-note", "a b"),
            ("x-amz-target", "AmazonSSM.GetParameter"),
        ],
        &hash,
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(
        signed_headers,
        "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-note;x-amz-target"
    );
    let written = b.read(f.out.fields_len);
    assert!(
        written.starts_with(&format!(
            "authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/svc/\
             aws4_request, SignedHeaders={signed_headers}, Signature={signature} [flags=1] ; \
             x-amz-date: 20150830T123600Z [flags=0]"
        )),
        "{written}"
    );
}

/// The `fields` line a fresh own-credential handle answers for `request`, sent with `sent`, the
/// body `body` lent (`None`: none).
fn fields_raw(request: RequestFacts, sent: &[NamedValue], body: Option<&'static [u8]>) -> String {
    let (_, p, handle) = open_signing("AKIDEXAMPLE:SECRET");
    let mut b = Buffers::new(1024, 4);
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    f.input.mode = MODE_OWN;
    f.input.request = request;
    (f.input.headers, f.input.headers_len) = (sent.as_ptr(), sent.len());
    f.input.point = POINT_HEAD_BODY;
    f.input.body = body.map_or(z(), |b| Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    });
    (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
    (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
    let c = checked_call(&p, slot::FIELDS, &mut f);
    format!("fields {:?} {}", c.outcome, err(&c.error))
}

#[test]
fn each_request_fact_that_cannot_be_signed_fails_with_its_own_reason() {
    const BAD: &[u8] = b"\xff";
    let bad = AbiStr {
        ptr: BAD.as_ptr(),
        len: BAD.len(),
    };
    let json = [NamedValue {
        name: s("content-type"),
        value: blob("application/json", BLOB_OCTETS, 0),
    }];
    let failed = |why: &str| format!("fields Failed sigv4 cannot sign: {why}");
    let with = |field: usize, value: AbiStr| {
        let mut r = facts();
        match field {
            0 => r.method = value,
            1 => r.authority = value,
            _ => r.canonical_path = value,
        }
        r
    };
    let cases = [
        (with(0, s("")), "the host lent no method"),
        (with(0, bad), "the method is not UTF-8"),
        (with(1, s("")), "the host lent no authority"),
        (with(1, bad), "the authority is not UTF-8"),
        (with(2, s("")), "the host lent no path"),
        (with(2, bad), "the path is not UTF-8"),
    ];
    for (request, why) in cases {
        assert_eq!(
            fields_raw(request, &json, Some(b"{}")),
            failed(why),
            "{why}"
        );
    }
    let bad_type = [NamedValue {
        name: s("Content-Type"),
        value: Blob {
            ptr: BAD.as_ptr(),
            len: BAD.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        },
    }];
    assert_eq!(
        fields_raw(facts(), &bad_type, Some(b"{}")),
        failed("the content-type value is not UTF-8")
    );
    let repeated_bad_type = [json[0], bad_type[0]];
    assert_eq!(
        fields_raw(facts(), &repeated_bad_type, Some(b"{}")),
        failed("the content-type value is not UTF-8")
    );
    let bad_amz = [NamedValue {
        name: s("x-amz-meta"),
        value: Blob {
            ptr: BAD.as_ptr(),
            len: BAD.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        },
    }];
    assert_eq!(
        fields_raw(facts(), &bad_amz, Some(b"{}")),
        failed("an x-amz-* line's value is not UTF-8")
    );
    assert_eq!(
        fields_raw(facts(), &json, None),
        failed("the host lent no body")
    );
    assert!(fields_raw(facts(), &json, Some(b"")).starts_with("fields Ready"));
}

fn built_plugin_image() -> std::path::PathBuf {
    let image = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let test_binary = std::env::current_exe().expect("test binary path");
            test_binary
                .parent()
                .and_then(std::path::Path::parent)
                .expect("target profile directory")
                .join(format!(
                    "{}busbar_auth_sigv4_plugin{}",
                    std::env::consts::DLL_PREFIX,
                    std::env::consts::DLL_SUFFIX
                ))
        });
    assert!(
        image.is_absolute(),
        "BUSBAR_PLUGIN_CDYLIB must name an absolute path to the built product image: {}",
        image.display()
    );
    assert!(
        image.is_file(),
        "build the actual dropped-in plugin before running this test: {}",
        image.display()
    );
    image
}

/// The fixed vectors formerly driven by the macro are ordinary tests over each real door.
#[test]
fn fixed_vectors_rotation_short_identity_and_closed_instances() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("conformance.json")).unwrap();
    let served: Vec<&serde_json::Value> = ["host_credentials", "rotated_host_credentials"]
        .iter()
        .flat_map(|held| vectors["auth"][*held].as_array().unwrap())
        .map(|c| &c["secret"])
        .collect();
    assert_eq!(
        vectors["auth"]["never_echoed"]
            .as_array()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        served,
        "never_echoed names exactly the secrets the vectors' host serves"
    );
    let mut door_answers = Vec::new();
    for dropped_leg in [false, true] {
        ANSWERS.with(|answers| answers.borrow_mut().clear());
        let creds = Arc::new(Creds::default());
        let d = Dispatcher::with_services(
            DispatchConfig::default(),
            creds.clone(),
            busbar_contract::services::test_caller_binding(),
        );
        let folds = Arc::new(Folds::default());
        let p = if dropped_leg {
            dropped(&folds, &d)
        } else {
            linked(&folds, &d)
        };
        let mut request = Inbound::signed(LIVE_SECRET, AKID, b"", b"");
        assert!(!verify_now(&p, &mut request).starts_with("Ready"));
        for bad in vectors["auth"]["bad_settings"].as_array().unwrap() {
            let bytes = bad.as_str().unwrap().as_bytes();
            let mut f: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
            f.input.head = in_head();
            f.out.head = out_head();
            f.input.settings = Blob {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                fmt: BLOB_JSON,
                flags: 0,
            };
            let mut validate: Frame<ValidateIn, _> = Frame::new(z(), out_head());
            validate.input.head = in_head();
            validate.input.settings = f.input.settings;
            let before = first_crossings(&p);
            let refused = checked_call(&p, life::VALIDATE, &mut validate);
            assert_eq!(refused.outcome, Outcome::Failed);
            assert!(!err(&refused.error).is_empty());
            assert_eq!(first_crossings(&p) - before, 1);
            let before = first_crossings(&p);
            let answer = checked_call(&p, life::OPEN, &mut f);
            assert_eq!(answer.outcome, Outcome::Failed);
            assert!(!err(&answer.error).is_empty());
            assert_eq!(first_crossings(&p) - before, 1);
        }
        let mut open: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
        open.input.head = in_head();
        open.out.head = out_head();
        open.input.generation = 1;
        assert_eq!(
            checked_call(&p, life::OPEN, &mut open).outcome,
            Outcome::Ready
        );
        let before = first_crossings(&p);
        p.ready(&d, Duration::from_secs(10))
            .expect("the real boot readiness");
        assert_eq!(first_crossings(&p) - before, u64::from(p.has_ready()));
        let mut begin: Frame<auth::BeginLoginIn, auth::BeginLoginOut> = Frame::new(z(), z());
        begin.input.head = in_head();
        begin.out.head = out_head();
        assert_eq!(
            checked_call(&p, slot::BEGIN_LOGIN, &mut begin).outcome,
            Outcome::Refused
        );
        let mut complete: Frame<auth::CompleteLoginIn, IdentifyOut> = Frame::new(z(), z());
        complete.input.head = in_head();
        complete.out.head = out_head();
        assert_eq!(
            checked_call(&p, slot::COMPLETE_LOGIN, &mut complete).outcome,
            Outcome::Refused
        );
        creds.1.store(true, std::sync::atomic::Ordering::SeqCst);
        for c in vectors["auth"]["cases"].as_array().unwrap() {
            let lines = c["lines"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
                .collect();
            let mut req = Inbound::new(lines, c["body"].as_str().unwrap_or("").as_bytes());
            // These vectors deliberately use the macro's credential source and authority.
            let mut frame = req.frame();
            frame.input.request.authority = s("conformance.invalid");
            frame.input.request.timestamp = c["timestamp"].as_u64().unwrap();
            let before = first_crossings(&p);
            let now = checked_call(&p, slot::VERIFY, &mut frame);
            assert_eq!(first_crossings(&p) - before, 1);
            assert!(
                creds.drain().is_empty(),
                "ticketless reads cannot cross host custody"
            );
            let now_answer = req.verdict(now.outcome, &frame.out);
            let expected = c["verdict"].as_str().unwrap();
            let mut frame = req.frame();
            frame.input.request.authority = s("conformance.invalid");
            frame.input.request.timestamp = c["timestamp"].as_u64().unwrap();
            let ticket = d.mint(0).unwrap();
            let before = first_crossings(&p);
            let reply = d.submit(
                &p,
                ticket,
                slot::VERIFY,
                frame,
                DeadlineClass::Call,
                now_ns().saturating_add(10_000_000_000),
            );
            let done = reply
                .wait(Duration::from_secs(10))
                .expect("vector verify answers");
            if let Some(bytes) = &done.error {
                record_answer(bytes);
            }
            let answer = req.verdict(done.outcome, &done.frame.unwrap().out);
            drop(reply);
            d.recycle(ticket);
            assert!(d.retirement_barrier(ticket, Duration::from_secs(10)));
            assert_eq!(first_crossings(&p) - before, 1);
            for word in vectors["auth"]["never_echoed"].as_array().unwrap() {
                assert!(!answer.contains(word.as_str().unwrap()));
            }
            let reads = creds.drain();
            if now.outcome == Outcome::Refused {
                assert!(!reads.is_empty());
            }
            match expected {
                "reject" => assert!(answer.starts_with("Ready Reject"), "{answer}"),
                "pass" => assert!(answer.starts_with("Ready Pass"), "{answer}"),
                _ => assert!(
                    answer.starts_with(&format!(
                        "Ready Identity({})",
                        expected.strip_prefix("identity:").unwrap()
                    )),
                    "{answer}"
                ),
            }
            if now.outcome == Outcome::Ready {
                assert_eq!(now_answer, answer);
            } else {
                assert_eq!(now.outcome, Outcome::Refused);
            }
            if expected.starts_with("identity:") {
                creds.2.store(true, std::sync::atomic::Ordering::SeqCst);
                assert!(verify_submitted(&p, &d, &mut req).starts_with("Ready Reject"));
                creds.2.store(false, std::sync::atomic::Ordering::SeqCst);
                creds.drain();
            }
        }
        creds.1.store(false, std::sync::atomic::Ordering::SeqCst);
        let outbound = &vectors["auth"]["outbound"][0];
        assert_eq!(
            outbound["settings"],
            serde_json::from_str::<serde_json::Value>(SIGV4_SETTINGS).unwrap(),
            "the vector's settings are the ones bound"
        );
        assert_eq!(
            outbound["head"],
            serde_json::json!({
                "method": "POST",
                "authority": "runtime.signer.example",
                "target": PATH,
                "timestamp": NOW,
                "fields": [["content-type", "application/json"]],
                "body": "{}",
            }),
            "the vector's head is the request `fields_over` lends"
        );
        assert_eq!(outbound["style"], "sigv4");
        assert_eq!(outbound["credential"], "AKIDEXAMPLE:SECRET:TOKEN");
        let (line, handle) = open_outbound(
            &p,
            "sigv4",
            Some("AKIDEXAMPLE:SECRET:TOKEN"),
            SIGV4_SETTINGS,
        );
        assert_eq!(line, "open_outbound sigv4 Ready ");
        let expected = outbound["expect_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| {
                format!(
                    "{}: {} [flags={}]",
                    field[0].as_str().unwrap(),
                    field[1].as_str().unwrap(),
                    field
                        .get(2)
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                )
            })
            .collect::<Vec<_>>()
            .join(" ; ");
        for _ in 0..2 {
            let before = first_crossings(&p);
            assert_eq!(
                fields_over(&p, handle, MODE_OWN, z(), (1024, 4), Some("{}")),
                format!("fields Ready  {expected}")
            );
            assert_eq!(first_crossings(&p) - before, 1);
        }
        assert_eq!(ready(&p, handle), "ready Ready 1");
        assert!(verify_submitted(&p, &d, &mut request).starts_with("Ready Identity("));
        let before_short = first_crossings(&p);
        let mut short = request.frame();
        short.input.out_buf.buf_cap = 0;
        let ticket = d.mint(0).unwrap();
        let reply = d.submit(
            &p,
            ticket,
            slot::VERIFY,
            short,
            DeadlineClass::Call,
            now_ns().saturating_add(10_000_000_000),
        );
        let done = reply
            .wait(Duration::from_secs(10))
            .expect("short verify answers");
        if let Some(bytes) = &done.error {
            record_answer(bytes);
        }
        assert!(done.short, "the identity requires host output storage");
        let mut frame = done.frame.expect("short verify returns its frame");
        assert_ne!(
            frame.out.head.lease, 0,
            "the retained short answer has a lease"
        );
        drop(reply);
        frame.input.out_buf.buf_cap = request.bytes.len();
        let reply = d.submit(
            &p,
            ticket,
            slot::VERIFY,
            frame,
            DeadlineClass::Call,
            now_ns().saturating_add(10_000_000_000),
        );
        let done = reply
            .wait(Duration::from_secs(10))
            .expect("short recall answers");
        if let Some(bytes) = &done.error {
            record_answer(bytes);
        }
        assert!(request
            .verdict(done.outcome, &done.frame.unwrap().out)
            .starts_with("Ready Identity("));
        drop(reply);
        d.recycle(ticket);
        assert!(d.retirement_barrier(ticket, Duration::from_secs(10)));
        assert_eq!(
            first_crossings(&p) - before_short,
            3,
            "verify, recall, release"
        );
        let mut refresh: Frame<RefreshIn, _> = Frame::new(z(), out_head());
        refresh.input.head = in_head();
        refresh.input.generation = 2;
        assert_eq!(
            checked_call(&p, life::REFRESH, &mut refresh).outcome,
            Outcome::Ready
        );
        assert!(verify_submitted(&p, &d, &mut request).starts_with("Ready Identity("));
        let mut close = Frame::new(in_head(), out_head());
        assert_eq!(
            checked_call(&p, life::CLOSE, &mut close).outcome,
            Outcome::Ready
        );
        assert!(!verify_now(&p, &mut request).starts_with("Ready"));
        assert!(!fields(&p, handle, MODE_OWN, z(), (1024, 4)).starts_with("fields Ready"));
        assert!(
            !folds.2.load(std::sync::atomic::Ordering::SeqCst),
            "all envelopes must be captured without drops"
        );
        let mut captured = ANSWERS.with(|answers| std::mem::take(&mut *answers.borrow_mut()));
        captured.extend(folds.1.lock().unwrap().iter().cloned());
        for word in vectors["auth"]["never_echoed"].as_array().unwrap() {
            let word = word.as_str().unwrap().as_bytes();
            for emitted in &captured {
                assert!(
                    !emitted.windows(word.len()).any(|bytes| bytes == word),
                    "a planted host secret appeared in an operation answer or envelope"
                );
            }
        }
        door_answers.push(captured);
    }
    assert_eq!(
        door_answers[0], door_answers[1],
        "every ordinary response and complete envelope agrees across the two real images"
    );
}

static RESTATED: std::sync::atomic::AtomicPtr<Door> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
extern "C" fn restated_door() -> &'static Door {
    let door = RESTATED.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        !door.is_null(),
        "the sole metadata test installs its door first"
    );
    // SAFETY: the sole metadata test installs a complete leaked door before entering the loader.
    unsafe { &*door }
}
fn restate(parts: DoorParts) {
    // SAFETY: all parts come from the real static door, with only the explicitly tested
    // scalar or a leaked static Statement/table changed. No product implementation is copied.
    RESTATED.store(
        Box::into_raw(Box::new(unsafe { Door::__from_parts(parts) })),
        std::sync::atomic::Ordering::SeqCst,
    );
}

#[test]
fn real_door_rejects_changed_abi_layout_statement_and_every_other_kind() {
    use busbar_contract::abi::mechanism::door::Statement;
    use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_plugin_loader::dispatch::kinds::{
        export::Export, hook::Hook, plane::Plane, secret::Secret, store_v4::StoreV4 as Store,
        transport::Transport,
    };
    use busbar_plugin_loader::dispatch::{Kind, LoadError};
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let path = built_plugin_image();
    let real = busbar_auth_sigv4::door().parts();
    let honest = row(busbar_auth_sigv4::door);
    let _linked = load_linked::<Auth>(&honest, bind(&folds, &d)).unwrap();
    let _dropped = load_dropped::<Auth>(&path, &honest.statement, bind(&folds, &d)).unwrap();
    for abi in [real.kind_abi + 1, real.kind_abi.wrapping_sub(1)] {
        restate(DoorParts {
            kind_abi: abi,
            ..real
        });
        let expected = LoadError::KindAbi {
            kind: KindCode::Auth,
            door: abi,
            host: real.kind_abi,
        };
        assert_eq!(rendering_of(restated_door).unwrap_err(), expected);
        assert_eq!(LinkedRow::of(restated_door).unwrap_err(), expected);
        assert!(expected.to_string().contains("rebuild"));
        let mut stated = honest.statement.clone();
        let at = RENDERING_MAGIC.len() + 8;
        stated[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped::<Auth>(&path, &stated, bind(&folds, &d)).err(),
            Some(LoadError::ManifestKindAbi {
                stated: abi,
                host: real.kind_abi
            })
        );
    }
    for layout in [real.layout ^ 1, 0] {
        restate(DoorParts { layout, ..real });
        let error = rendering_of(restated_door).unwrap_err();
        assert!(
            matches!(error, LoadError::KindLayout { stated, host, .. } if stated == layout && host == real.layout)
        );
        assert!(error
            .to_string()
            .contains("rebuild against this busbar-contract"));
        let mut stated = honest.clone();
        stated.door = busbar_plugin_loader::dispatch::load::raw(restated_door);
        assert_eq!(
            load_linked::<Auth>(&stated, bind(&folds, &d)).err(),
            Some(error)
        );
    }
    // SAFETY: the admitted real door's Statement is a complete static value.
    let statement = unsafe { real.statement.read_unaligned() };
    let other = Box::leak(Box::new(Statement {
        version: s("0.0.0-conformance-restated"),
        ..statement
    }));
    restate(DoorParts {
        statement: other,
        ..real
    });
    let lying = rendering_of(restated_door).unwrap();
    assert_ne!(lying, honest.statement);
    let mut lying_row = honest.clone();
    lying_row.statement = lying.clone();
    assert_eq!(
        load_linked::<Auth>(&lying_row, bind(&folds, &d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Auth>(&path, &lying, bind(&folds, &d)).err(),
        Some(LoadError::StatementMismatch)
    );
    lying_row = honest.clone();
    lying_row.door = busbar_plugin_loader::dispatch::load::raw(restated_door);
    assert_eq!(
        load_linked::<Auth>(&lying_row, bind(&folds, &d)).err(),
        Some(LoadError::StatementMismatch)
    );
    fn wrong<K: Kind>(path: &std::path::Path, row: &LinkedRow, folds: &Arc<Folds>, d: &Dispatcher) {
        let linked = load_linked::<K>(row, bind(folds, d)).err().unwrap();
        let dropped = load_dropped::<K>(path, &row.statement, bind(folds, d))
            .err()
            .unwrap();
        assert_eq!(
            linked,
            LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: K::CODE
            }
        );
        assert_eq!(linked, dropped);
    }
    wrong::<Export>(&path, &honest, &folds, &d);
    wrong::<Plane>(&path, &honest, &folds, &d);
    wrong::<Secret>(&path, &honest, &folds, &d);
    wrong::<Store>(&path, &honest, &folds, &d);
    wrong::<Transport>(&path, &honest, &folds, &d);
    wrong::<Hook>(&path, &honest, &folds, &d);
    restate(DoorParts {
        ready: Some(failed_ready),
        ..real
    });
    let p = load_linked::<Auth>(&row(restated_door), bind(&folds, &d)).unwrap();
    let mut open: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    open.input.head = in_head();
    open.out.head = out_head();
    assert_eq!(
        checked_call(&p, life::OPEN, &mut open).outcome,
        Outcome::Ready
    );
    assert!(p.has_ready());
    let before = first_crossings(&p);
    assert_eq!(
        p.ready(&d, Duration::from_secs(10)).unwrap_err(),
        format!(
            "plugin '{}' ready failed: conformance: discovery refused",
            p.name()
        )
    );
    assert_eq!(first_crossings(&p) - before, 1);
    assert_eq!(READY_CALLS.load(std::sync::atomic::Ordering::SeqCst), 1);
}

fn first_crossings(p: &Plugin<Auth>) -> u64 {
    p.test_invocations().0 - p.test_invocations().1
}
static READY_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
extern "C" fn failed_ready(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    READY_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // SAFETY: READY lends a writable OutHead; the static error outlives its copy by the host.
    unsafe {
        let head = &mut *out.cast::<busbar_contract::abi::mechanism::call::OutHead>();
        head.outcome = RawOutcome::of(Outcome::Failed);
        head.error = s("conformance: discovery refused");
    }
    RawOutcome::of(Outcome::Failed)
}

/// Pin each ordinary synchronous product invocation, including the loader's zero-crossing
/// refusal of unopened/closed instances. Submitted calls pin their counts after retirement.
fn checked_call<
    I: busbar_plugin_loader::dispatch::InFrame,
    O: busbar_plugin_loader::dispatch::OutFrame,
>(
    p: &Plugin<Auth>,
    slot: u32,
    frame: &mut Frame<I, O>,
) -> busbar_plugin_loader::dispatch::Called {
    let expected = u64::from(p.is_open() || matches!(slot, life::OPEN | life::VALIDATE));
    let before = first_crossings(p);
    let answer = p.call(slot, frame);
    record_answer(format!("slot {slot} {:?} lease={}", answer.outcome, answer.lease).as_bytes());
    if let Some(bytes) = &answer.error {
        record_answer(bytes);
    }
    assert_eq!(
        first_crossings(p) - before,
        expected,
        "slot {slot} first invocations"
    );
    answer
}

#[test]
fn declared_needs_and_requested_profile_match_the_real_product() {
    let declares: serde_json::Value =
        serde_json::from_str(include_str!("../../auth-sigv4/declares.json")).unwrap();
    assert!(declares
        .get("needs")
        .is_none_or(|needs| needs.as_array().unwrap().is_empty()));
    let statement = rendering_of(busbar_auth_sigv4::door).unwrap();
    assert!(busbar_contract::abi::mechanism::rendering::read(&statement)
        .unwrap()
        .needs
        .is_empty());
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "BUSBAR_EXPECT_RELEASE requires --release"
    );
}

// Plain byte records of this test thread's ordinary operation responses. Envelopes may arrive
// on dispatcher workers, so their complete byte records stay with the bound Folds above.
thread_local! {
    static ANSWERS: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}
fn record_answer(bytes: &[u8]) {
    ANSWERS.with(|answers| answers.borrow_mut().push(bytes.to_vec()));
}
