use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ops_light_secrets_server::clock::{
    BootOverrideAudit, BootOverrideAuditError, CheckpointRequest, ClockMonitor, ClockReading,
};
use ops_light_secrets_server::startup::{
    ClockState, DirectoryState, LifecycleState, LockState, MarkerState, ReserveState, SchemaState,
    StartupCode, StartupSnapshot, StoreIdentity, TransportState, assess_startup_clock,
    validate_startup,
};
use ops_light_secrets_server::store::{Lifecycle, MetaRecord, Store, StoreId};

struct NoAudit;

impl BootOverrideAudit for NoAudit {
    fn commit_boot_override(
        &mut self,
        _event: ops_light_secrets_server::clock::BootOverrideEvent,
    ) -> Result<(), BootOverrideAuditError> {
        Ok(())
    }
}

fn reading(wall: u64, monotonic: u64) -> ClockReading {
    ClockReading {
        wall_unix_seconds: wall,
        monotonic: Duration::from_secs(monotonic),
    }
}

fn meta(mark: u64) -> MetaRecord {
    MetaRecord {
        store_id: StoreId([7; 16]),
        format_version: 1,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: mark,
        pending_anchor: None,
    }
}

fn snapshot(clock: ClockState) -> StartupSnapshot {
    StartupSnapshot {
        key_material_configured: true,
        initialized: true,
        listener: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        transport: TransportState::Plaintext,
        directory: DirectoryState::Safe,
        store_identity: StoreIdentity::matching([7; 16]),
        schema: SchemaState::Current,
        lifecycle: LifecycleState::Ready,
        marker: MarkerState::None,
        pending_anchor: None,
        clock,
        lock: LockState::Acquired,
        reserve: ReserveState::Healthy,
    }
}

#[test]
fn real_store_mark_drives_pre_bind_refusal_and_checkpoint_crash_bound() {
    let base = 1_700_000_000;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let store = Store::create(&path, &meta(base)).unwrap();

    let clear = store.meta().unwrap();
    let sound = assess_startup_clock(reading(base, 0), clear.high_water_unix_seconds);
    assert!(validate_startup(&snapshot(sound)).is_ok());

    let mut monitor = ClockMonitor::boot(
        reading(base, 0),
        clear.high_water_unix_seconds,
        false,
        &mut NoAudit,
    )
    .unwrap();
    monitor.observe(reading(base + 30, 30));
    let checkpoint = match monitor.idle_checkpoint(Duration::from_secs(30)).unwrap() {
        CheckpointRequest::Submit(command) => command,
        other => panic!("unexpected checkpoint state: {other:?}"),
    };

    // Crash before commit leaves the old bound, never a future observation.
    drop(store);
    let store = Store::open(&path).unwrap();
    assert_eq!(store.meta().unwrap().high_water_unix_seconds, base);
    assert_eq!(
        checkpoint.replacement_high_water_unix_seconds - base,
        30,
        "pre-checkpoint crash exposure stays inside the published 32.1 second bound"
    );

    store.commit_clock_watermark(&checkpoint).unwrap();
    monitor.complete_watermark(checkpoint, true).unwrap();
    drop(store);

    // Crash after commit means a rolled-back wall clock refuses before bind.
    let store = Store::open(&path).unwrap();
    let persisted = store.meta().unwrap().high_water_unix_seconds;
    assert_eq!(persisted, base + 30);
    assert_eq!(
        checkpoint.replacement_high_water_unix_seconds - persisted,
        0
    );
    let behind = assess_startup_clock(reading(base, 0), persisted);
    let refusal = validate_startup(&snapshot(behind)).unwrap_err();
    assert_eq!(refusal.code(), StartupCode::ClockUnsafe);
}

#[test]
fn poisoned_future_mark_is_distinct_and_refused_without_mutation() {
    let base = 1_700_000_000;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let store = Store::create(&path, &meta(base + 24 * 60 * 60 + 1)).unwrap();
    let before = store.meta().unwrap();
    let state = assess_startup_clock(reading(base, 0), before.high_water_unix_seconds);
    assert_eq!(state, ClockState::ImplausiblyAhead);
    assert_eq!(
        validate_startup(&snapshot(state)).unwrap_err().code(),
        StartupCode::ClockUnsafe
    );
    assert_eq!(store.meta().unwrap(), before);
}
