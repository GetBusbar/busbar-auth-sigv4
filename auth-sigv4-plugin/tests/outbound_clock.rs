// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod frames;

use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicUsize, Ordering};

use busbar_contract::abi::auth::{
    slot, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut,
};
use busbar_contract::abi::host::service::{
    ClockNowIn, ClockReading, HostSlots, ServiceOut, SERVICES,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, OutHead, Outcome, RawOutcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, GenIn, RefreshIn, TickIn, TickOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use frames::{call, in_head, ops, out_head, z};

extern "C" fn clock(ctx: HostCtx, input: *const c_void, output: *mut ServiceOut) -> RawOutcome {
    // SAFETY: this test owns the context counter and the SDK lends these clock frames.
    let (reads, input, output) = unsafe {
        (
            &*std::ptr::with_exposed_provenance::<AtomicUsize>(ctx.handle as usize),
            &*input.cast::<ClockNowIn>(),
            &mut *output,
        )
    };
    let n = reads.fetch_add(1, Ordering::SeqCst);
    let reading = ClockReading {
        size: size_of::<ClockReading>() as u32,
        _reserved: 0,
        wall_ns: (1_440_938_160 + n as u64 * 86_400) * 1_000_000_000,
        mono_ns: n as u64,
    };
    // SAFETY: the SDK lends one writable reading for this synchronous call.
    unsafe {
        input.reading.write(reading);
    }
    output.outcome = RawOutcome::of(Outcome::Ready);
    RawOutcome::of(Outcome::Ready)
}

fn bytes(value: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: value.as_ptr(),
        len: value.len(),
        fmt,
        flags: 0,
    }
}

/// # Safety
/// `instance` is this door's live open result, with its host tables/state still live.
unsafe fn bind(instance: *mut c_void, credential: &[u8]) -> u64 {
    let mut input: OpenOutboundIn = z();
    input.head = in_head::<OpenOutboundIn>(slot::OPEN_OUTBOUND);
    input.style = AbiStr {
        ptr: b"sigv4".as_ptr(),
        len: 5,
    };
    input.credential = bytes(credential, BLOB_OCTETS);
    input.credential.flags = BLOB_SECRET;
    input.settings = bytes(br#"{"region":"us-east-1","service":"iam"}"#, BLOB_JSON);
    let mut output: OpenOutboundOut = z();
    output.head = out_head::<OpenOutboundOut>();
    assert_eq!(
        // SAFETY: OPEN_OUTBOUND takes these full OpenOutboundIn/OpenOutboundOut frames. The
        // credential borrow and static style/settings remain live for the complete call; the
        // caller supplies the live instance and retained host-table lifetime.
        unsafe { call(ops().open_outbound, instance, &input, &mut output) },
        Outcome::Ready
    );
    output.handle
}

/// # Safety
/// `instance` is this door's live open result, with its host tables/state still live.
unsafe fn ready(instance: *mut c_void, handle: u64) -> bool {
    let mut input: OutboundReadyIn = z();
    input.head = in_head::<OutboundReadyIn>(slot::OUTBOUND_READY);
    input.handle = handle;
    let mut output: OutboundReadyOut = z();
    output.head = out_head::<OutboundReadyOut>();
    assert_eq!(
        // SAFETY: OUTBOUND_READY takes these full OutboundReadyIn/OutboundReadyOut frames,
        // which contain only this handle and scalar fields. The caller proves instance custody.
        unsafe { call(ops().outbound_ready, instance, &input, &mut output) },
        Outcome::Ready
    );
    output.ready != 0
}

#[test]
fn outbound_ticks_read_the_host_clock_on_each_day() {
    let reads = AtomicUsize::new(0);
    let mut slots: HostSlots = z();
    slots.size = size_of::<HostSlots>() as u32;
    slots.slots = SERVICES;
    slots.clock_now = Some(clock);
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            handle: std::ptr::from_ref(&reads).expose_provenance() as u64,
        },
        wake: None,
        conns: std::ptr::null(),
        services: &slots,
        io: std::ptr::null(),
    };
    // SAFETY: reads, slots and tables remain at these stack addresses until after the explicit
    // CLOSE below, and this test is the sole owner of the returned instance.
    let instance = unsafe { frames::open(&tables) };
    // SAFETY: the instance is still open over those live tables and the credential is static.
    let handle = unsafe { bind(instance, b"ACCESS:never-echo-signing-secret") };
    for n in 0..2 {
        let mut input: TickIn = z();
        input.head = in_head::<TickIn>(life::TICK);
        input.head.ticket = Ticket {
            slot: 7,
            generation: 1,
        };
        input.now_ns = 1000 + n;
        let mut output: TickOut = z();
        output.head = out_head::<TickOut>();
        assert_eq!(
            // SAFETY: TICK takes these full TickIn/TickOut frames. The instance and its
            // stack-owned host tables, slots and clock counter remain live through the call.
            unsafe { call(ops().head.tick, instance, &input, &mut output) },
            Outcome::Ready
        );
        assert!(output.next_tick_ns > input.now_ns);
        // SAFETY: the same instance is still open and all its host state remains live.
        assert!(unsafe { ready(instance, handle) });
    }
    // SAFETY: this is the only CLOSE; all stack-owned host memory remains live until return.
    unsafe { frames::close(instance) };
    assert_eq!(
        reads.load(Ordering::SeqCst),
        2,
        "pre-derivation must use host clock.now"
    );
}

#[test]
fn rejected_refresh_preserves_binding_and_never_echoes_values_then_rotation_retires_old_generation()
{
    // SAFETY: this instance retains no host tables, and the sole CLOSE is below.
    let instance = unsafe { frames::open(std::ptr::null()) };
    // SAFETY: this is the live instance just opened; the credential bytes are static.
    let old = unsafe { bind(instance, b"ACCESS:never-echo-signing-secret") };
    let mut input: RefreshIn = z();
    input.head = in_head::<RefreshIn>(life::REFRESH);
    input.generation = 2;
    input.settings = bytes(
        br#"{"service":{"secret":"never-echo-settings"},"region":"us-east-1"}"#,
        BLOB_JSON,
    );
    let mut output: OutHead = out_head::<OutHead>();
    assert_eq!(
        // SAFETY: REFRESH takes these full RefreshIn/OutHead frames; settings is static and
        // this instance remains open. This call lends no additional retained host state.
        unsafe { call(ops().head.refresh, instance, &input, &mut output) },
        Outcome::Failed
    );
    assert!(
        !output.error.ptr.is_null() && output.error.len > 0,
        "a FAILED refresh says why"
    );
    // SAFETY: the instance retains the reply's text (non-null, `len` bytes) until its next call.
    let error = unsafe { std::slice::from_raw_parts(output.error.ptr, output.error.len) };
    assert!(
        error
            .windows(b"settings.service".len())
            .any(|w| w == b"settings.service"),
        "{}",
        String::from_utf8_lossy(error)
    );
    assert!(!error
        .windows(b"never-echo".len())
        .any(|w| w == b"never-echo"));
    // SAFETY: this is the same still-open instance, retaining no host tables.
    assert!(unsafe { ready(instance, old) });
    input.settings = bytes(b"{}", BLOB_JSON);
    output = out_head::<OutHead>();
    assert_eq!(
        // SAFETY: REFRESH takes these full RefreshIn/OutHead frames; settings is static and
        // this instance remains open. This call lends no additional retained host state.
        unsafe { call(ops().head.refresh, instance, &input, &mut output) },
        Outcome::Ready
    );
    // SAFETY: this instance remains live after REFRESH; the replacement credential is static.
    let new = unsafe { bind(instance, b"ROTATED:replacement-signing-secret") };
    let mut retire: GenIn = z();
    retire.head = in_head::<GenIn>(life::RETIRE);
    retire.generation = 1;
    output = out_head::<OutHead>();
    assert_eq!(
        // SAFETY: RETIRE takes these full GenIn/OutHead frames. It retires generation 1
        // within this still-live instance, not the instance itself.
        unsafe { call(ops().head.retire, instance, &retire, &mut output) },
        Outcome::Ready
    );
    // SAFETY: RETIRE did not close the instance; these are scalar handle queries on it.
    assert!(!unsafe { ready(instance, old) });
    // SAFETY: as above, for the generation-2 handle.
    assert!(unsafe { ready(instance, new) });
    // SAFETY: this is the sole CLOSE of this host-less instance.
    unsafe { frames::close(instance) };
}
