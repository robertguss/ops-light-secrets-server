//! Non-regressing effective time and durable clock-watermark policy.

use std::fmt;
use std::io::Write;
use std::os::fd::AsFd;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::init::validate_secret_sink;

pub const CLOCK_TOLERANCE: Duration = Duration::from_secs(2);
pub const CLOCK_SETTLE_PERIOD: Duration = Duration::from_secs(10);
pub const IDLE_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);
pub const CHECKPOINT_COMMIT_DEADLINE: Duration = Duration::from_millis(100);
pub const MAX_PLAUSIBLE_FUTURE_MARK: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_RESTART_TTL_EXTENSION: Duration = Duration::from_millis(32_100);
pub const MAX_REPAIR_REASON_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockReading {
    pub wall_unix_seconds: u64,
    pub monotonic: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockSafety {
    Ready,
    Recovering,
    Unsafe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockAnomaly {
    WallBehind,
    WallAhead,
    MonotonicRegressed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockObservation {
    pub effective_unix_seconds: u64,
    pub safety: ClockSafety,
    pub anomaly: Option<ClockAnomaly>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootOverrideEvent {
    pub observed_wall_unix_seconds: u64,
    pub persisted_high_water_unix_seconds: u64,
    pub effective_unix_seconds: u64,
}

pub trait BootOverrideAudit {
    fn commit_boot_override(
        &mut self,
        event: BootOverrideEvent,
    ) -> Result<(), BootOverrideAuditError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootOverrideAuditError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    BehindPersistedMark,
    PersistedMarkImplausiblyAhead,
    OverrideAuditFailed,
    Unsafe,
    StaleCommand,
    PersistenceFailed,
    InvalidRepair,
    StaleRepair,
    UnsafeCredentialSink,
    RepairPreparationFailed,
    DisclosureFailed,
    RepairCommitFailed,
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BehindPersistedMark => "clock_refused code=behind_persisted_mark",
            Self::PersistedMarkImplausiblyAhead => {
                "clock_refused code=persisted_mark_implausibly_ahead remediation='clock repair'"
            }
            Self::OverrideAuditFailed => "clock_refused code=override_audit_failed",
            Self::Unsafe => "clock_refused code=runtime_clock_unsafe",
            Self::StaleCommand => "clock_refused code=stale_watermark_command",
            Self::PersistenceFailed => "clock_refused code=watermark_persistence_failed",
            Self::InvalidRepair => "clock_repair_refused code=invalid_request",
            Self::StaleRepair => "clock_repair_refused code=old_mark_mismatch",
            Self::UnsafeCredentialSink => "clock_repair_refused code=unsafe_credential_sink",
            Self::RepairPreparationFailed => "clock_repair_refused code=preparation_failed",
            Self::DisclosureFailed => "clock_repair_refused code=disclosure_failed",
            Self::RepairCommitFailed => "clock_repair_refused code=commit_failed",
        })
    }
}

impl std::error::Error for ClockError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatermarkKind {
    ApplicationCommit,
    IdleCheckpoint,
    CleanShutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatermarkCommand {
    pub expected_high_water_unix_seconds: u64,
    pub replacement_high_water_unix_seconds: u64,
    pub effective_unix_seconds: u64,
    pub kind: WatermarkKind,
    issued_at: Duration,
    deadline: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointRequest {
    NotDue,
    Coalesced,
    Submit(WatermarkCommand),
}

pub struct ClockMonitor {
    anchor_wall: u64,
    anchor_monotonic: Duration,
    effective: u64,
    persisted: u64,
    safety: ClockSafety,
    agreement_since: Option<Duration>,
    last_durable_monotonic: Duration,
    pending_checkpoint: Option<WatermarkCommand>,
}

impl ClockMonitor {
    pub fn boot<A: BootOverrideAudit>(
        reading: ClockReading,
        persisted_high_water_unix_seconds: u64,
        allow_behind_mark_once: bool,
        audit: &mut A,
    ) -> Result<Self, ClockError> {
        let ahead = persisted_high_water_unix_seconds.saturating_sub(reading.wall_unix_seconds);
        if ahead > MAX_PLAUSIBLE_FUTURE_MARK.as_secs() {
            return Err(ClockError::PersistedMarkImplausiblyAhead);
        }
        if ahead > CLOCK_TOLERANCE.as_secs() {
            if !allow_behind_mark_once {
                return Err(ClockError::BehindPersistedMark);
            }
            let event = BootOverrideEvent {
                observed_wall_unix_seconds: reading.wall_unix_seconds,
                persisted_high_water_unix_seconds,
                effective_unix_seconds: persisted_high_water_unix_seconds,
            };
            audit
                .commit_boot_override(event)
                .map_err(|_| ClockError::OverrideAuditFailed)?;
        }
        Ok(Self {
            anchor_wall: reading.wall_unix_seconds,
            anchor_monotonic: reading.monotonic,
            effective: reading
                .wall_unix_seconds
                .max(persisted_high_water_unix_seconds),
            persisted: persisted_high_water_unix_seconds,
            safety: ClockSafety::Ready,
            agreement_since: None,
            last_durable_monotonic: reading.monotonic,
            pending_checkpoint: None,
        })
    }

    pub fn observe(&mut self, reading: ClockReading) -> ClockObservation {
        let Some(elapsed) = reading.monotonic.checked_sub(self.anchor_monotonic) else {
            self.safety = ClockSafety::Unsafe;
            self.agreement_since = None;
            return self.observation(Some(ClockAnomaly::MonotonicRegressed));
        };
        let expected_wall = self.anchor_wall.saturating_add(elapsed.as_secs());
        self.effective = self.effective.max(expected_wall);
        let difference = reading.wall_unix_seconds.abs_diff(expected_wall);
        if difference > CLOCK_TOLERANCE.as_secs() {
            self.safety = ClockSafety::Unsafe;
            self.agreement_since = None;
            let anomaly = if reading.wall_unix_seconds < expected_wall {
                ClockAnomaly::WallBehind
            } else {
                ClockAnomaly::WallAhead
            };
            return self.observation(Some(anomaly));
        }

        self.effective = self.effective.max(reading.wall_unix_seconds);
        if self.safety != ClockSafety::Ready {
            let since = *self.agreement_since.get_or_insert(reading.monotonic);
            self.safety = if reading.monotonic.saturating_sub(since) >= CLOCK_SETTLE_PERIOD {
                self.agreement_since = None;
                ClockSafety::Ready
            } else {
                ClockSafety::Recovering
            };
        }
        self.observation(None)
    }

    pub fn effective_unix_seconds(&self) -> u64 {
        self.effective
    }

    pub fn persisted_high_water_unix_seconds(&self) -> u64 {
        self.persisted
    }

    pub fn safety(&self) -> ClockSafety {
        self.safety
    }

    pub fn application_commit(&self, now: Duration) -> Result<WatermarkCommand, ClockError> {
        self.command(WatermarkKind::ApplicationCommit, now)
    }

    pub fn clean_shutdown(&self, now: Duration) -> Result<WatermarkCommand, ClockError> {
        self.command(WatermarkKind::CleanShutdown, now)
    }

    pub fn idle_checkpoint(&mut self, now: Duration) -> Result<CheckpointRequest, ClockError> {
        self.poll_checkpoint_deadline(now)?;
        if self.pending_checkpoint.is_some() {
            return Ok(CheckpointRequest::Coalesced);
        }
        if now.saturating_sub(self.last_durable_monotonic) < IDLE_CHECKPOINT_INTERVAL {
            return Ok(CheckpointRequest::NotDue);
        }
        let command = self.command(WatermarkKind::IdleCheckpoint, now)?;
        self.pending_checkpoint = Some(command);
        Ok(CheckpointRequest::Submit(command))
    }

    pub fn poll_checkpoint_deadline(&mut self, now: Duration) -> Result<(), ClockError> {
        if self
            .pending_checkpoint
            .is_some_and(|command| now > command.deadline)
        {
            self.safety = ClockSafety::Unsafe;
            return Err(ClockError::PersistenceFailed);
        }
        Ok(())
    }

    pub fn complete_watermark(
        &mut self,
        command: WatermarkCommand,
        committed: bool,
    ) -> Result<(), ClockError> {
        if command.expected_high_water_unix_seconds != self.persisted
            || command.replacement_high_water_unix_seconds < self.persisted
        {
            self.safety = ClockSafety::Unsafe;
            return Err(ClockError::StaleCommand);
        }
        if command.kind == WatermarkKind::IdleCheckpoint && self.pending_checkpoint != Some(command)
        {
            self.safety = ClockSafety::Unsafe;
            return Err(ClockError::StaleCommand);
        }
        if !committed {
            self.safety = ClockSafety::Unsafe;
            return Err(ClockError::PersistenceFailed);
        }
        self.persisted = command.replacement_high_water_unix_seconds;
        self.last_durable_monotonic = command.issued_at;
        if self
            .pending_checkpoint
            .is_some_and(|pending| pending.replacement_high_water_unix_seconds <= self.persisted)
        {
            self.pending_checkpoint = None;
        }
        Ok(())
    }

    fn command(&self, kind: WatermarkKind, now: Duration) -> Result<WatermarkCommand, ClockError> {
        if self.safety != ClockSafety::Ready {
            return Err(ClockError::Unsafe);
        }
        Ok(WatermarkCommand {
            expected_high_water_unix_seconds: self.persisted,
            replacement_high_water_unix_seconds: self.persisted.max(self.effective),
            effective_unix_seconds: self.effective,
            kind,
            issued_at: now,
            deadline: now.saturating_add(CHECKPOINT_COMMIT_DEADLINE),
        })
    }

    fn observation(&self, anomaly: Option<ClockAnomaly>) -> ClockObservation {
        ClockObservation {
            effective_unix_seconds: self.effective,
            safety: self.safety,
            anomaly,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockRepairRequest {
    pub exact_old_high_water_unix_seconds: u64,
    pub replacement_unix_seconds: u64,
    pub reason: String,
}

pub struct PreparedClockRepair<T> {
    pub replacement_credential: Zeroizing<Vec<u8>>,
    pub replacement_epoch: u64,
    pub transaction: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockRepairBackendError;

pub trait ClockRepairBackend {
    type Transaction;

    fn current_high_water_unix_seconds(&mut self) -> Result<u64, ClockRepairBackendError>;
    fn prepare_clock_repair(
        &mut self,
        request: &ClockRepairRequest,
    ) -> Result<PreparedClockRepair<Self::Transaction>, ClockRepairBackendError>;
    fn commit_clock_repair(
        &mut self,
        transaction: Self::Transaction,
    ) -> Result<(), ClockRepairBackendError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockRepairReceipt {
    pub replacement_high_water_unix_seconds: u64,
    pub replacement_epoch: u64,
}

pub fn repair_clock<B: ClockRepairBackend, W: Write + AsFd>(
    request: &ClockRepairRequest,
    observed_wall_unix_seconds: u64,
    sink: &mut W,
    backend: &mut B,
) -> Result<ClockRepairReceipt, ClockError> {
    validate_repair(request, observed_wall_unix_seconds)?;
    validate_secret_sink(sink.as_fd()).map_err(|_| ClockError::UnsafeCredentialSink)?;
    let current = backend
        .current_high_water_unix_seconds()
        .map_err(|_| ClockError::RepairPreparationFailed)?;
    if current != request.exact_old_high_water_unix_seconds {
        return Err(ClockError::StaleRepair);
    }
    let prepared = backend
        .prepare_clock_repair(request)
        .map_err(|_| ClockError::RepairPreparationFailed)?;
    sink.write_all(&prepared.replacement_credential)
        .and_then(|()| sink.write_all(b"\n"))
        .and_then(|()| sink.flush())
        .map_err(|_| ClockError::DisclosureFailed)?;
    let receipt = ClockRepairReceipt {
        replacement_high_water_unix_seconds: request.replacement_unix_seconds,
        replacement_epoch: prepared.replacement_epoch,
    };
    backend
        .commit_clock_repair(prepared.transaction)
        .map_err(|_| ClockError::RepairCommitFailed)?;
    Ok(receipt)
}

pub fn validate_repair(
    request: &ClockRepairRequest,
    observed_wall_unix_seconds: u64,
) -> Result<(), ClockError> {
    if request.reason.is_empty()
        || request.reason.len() > MAX_REPAIR_REASON_BYTES
        || request.reason.chars().any(char::is_control)
        || request.replacement_unix_seconds
            > observed_wall_unix_seconds.saturating_add(CLOCK_TOLERANCE.as_secs())
    {
        return Err(ClockError::InvalidRepair);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read};
    use std::os::unix::net::UnixStream;

    #[derive(Default)]
    struct Audit {
        events: Vec<BootOverrideEvent>,
        fail: bool,
    }

    impl BootOverrideAudit for Audit {
        fn commit_boot_override(
            &mut self,
            event: BootOverrideEvent,
        ) -> Result<(), BootOverrideAuditError> {
            if self.fail {
                Err(BootOverrideAuditError)
            } else {
                self.events.push(event);
                Ok(())
            }
        }
    }

    fn reading(wall: u64, monotonic_seconds: u64) -> ClockReading {
        ClockReading {
            wall_unix_seconds: wall,
            monotonic: Duration::from_secs(monotonic_seconds),
        }
    }

    fn boot(wall: u64, mark: u64) -> ClockMonitor {
        ClockMonitor::boot(reading(wall, 0), mark, false, &mut Audit::default()).unwrap()
    }

    #[test]
    fn startup_boundaries_and_override_are_fail_closed() {
        let base = 1_700_000_000;
        for difference in [CLOCK_TOLERANCE.as_secs() - 1, CLOCK_TOLERANCE.as_secs()] {
            assert!(
                ClockMonitor::boot(
                    reading(base, 0),
                    base + difference,
                    false,
                    &mut Audit::default(),
                )
                .is_ok()
            );
        }
        assert_eq!(
            ClockMonitor::boot(
                reading(base, 0),
                base + CLOCK_TOLERANCE.as_secs() + 1,
                false,
                &mut Audit::default(),
            )
            .err(),
            Some(ClockError::BehindPersistedMark)
        );
        let mut audit = Audit::default();
        let monitor = ClockMonitor::boot(reading(base, 0), base + 10, true, &mut audit).unwrap();
        assert_eq!(monitor.effective_unix_seconds(), base + 10);
        assert_eq!(monitor.persisted_high_water_unix_seconds(), base + 10);
        assert_eq!(audit.events.len(), 1);

        let poisoned = base + MAX_PLAUSIBLE_FUTURE_MARK.as_secs() + 1;
        assert_eq!(
            ClockMonitor::boot(reading(base, 0), poisoned, true, &mut Audit::default()).err(),
            Some(ClockError::PersistedMarkImplausiblyAhead)
        );
        let mut failing = Audit {
            fail: true,
            ..Audit::default()
        };
        assert_eq!(
            ClockMonitor::boot(reading(base, 0), base + 10, true, &mut failing).err(),
            Some(ClockError::OverrideAuditFailed)
        );
    }

    #[test]
    fn runtime_steps_never_regress_or_poison_the_mark_and_recover_after_settle() {
        let base = 1_700_000_000;
        for anomalous_wall in [base - 100, base + 1_000] {
            let mut monitor = boot(base, base);
            let before = monitor.effective_unix_seconds();
            let observation = monitor.observe(reading(anomalous_wall, 1));
            assert_eq!(observation.safety, ClockSafety::Unsafe);
            assert!(observation.effective_unix_seconds >= before);
            assert_eq!(monitor.persisted_high_water_unix_seconds(), base);
            assert_eq!(
                monitor.application_commit(Duration::from_secs(1)).err(),
                Some(ClockError::Unsafe)
            );
            assert_eq!(
                monitor.observe(reading(base + 2, 2)).safety,
                ClockSafety::Recovering
            );
            assert_eq!(
                monitor
                    .observe(reading(base + 11, 11))
                    .effective_unix_seconds,
                base + 11
            );
            assert_eq!(
                monitor.observe(reading(base + 12, 12)).safety,
                ClockSafety::Ready
            );
        }
    }

    #[test]
    fn runtime_drift_boundary_is_frozen_at_n_minus_one_n_n_plus_one() {
        let base = 1_700_000_000;
        for drift in [CLOCK_TOLERANCE.as_secs() - 1, CLOCK_TOLERANCE.as_secs()] {
            let mut monitor = boot(base, base);
            let observation = monitor.observe(reading(base + 10 + drift, 10));
            assert_eq!(observation.safety, ClockSafety::Ready);
            assert_eq!(observation.anomaly, None);
        }
        let mut monitor = boot(base, base);
        let observation = monitor.observe(reading(base + 10 + CLOCK_TOLERANCE.as_secs() + 1, 10));
        assert_eq!(observation.safety, ClockSafety::Unsafe);
        assert_eq!(observation.anomaly, Some(ClockAnomaly::WallAhead));
    }

    #[test]
    fn override_preserves_mark_and_does_not_extend_pre_rollback_ttl() {
        let base = 1_700_000_000;
        let mark = base + 100;
        let mut monitor =
            ClockMonitor::boot(reading(base, 0), mark, true, &mut Audit::default()).unwrap();
        assert_eq!(monitor.effective_unix_seconds(), mark);
        monitor.observe(reading(base + 10, 10));
        assert_eq!(monitor.effective_unix_seconds(), mark);
        assert!(monitor.effective_unix_seconds() >= mark);
        let command = monitor.application_commit(Duration::from_secs(10)).unwrap();
        assert_eq!(command.replacement_high_water_unix_seconds, mark);
        monitor.complete_watermark(command, true).unwrap();
        assert_eq!(monitor.persisted_high_water_unix_seconds(), mark);
    }

    #[test]
    fn idle_checkpoint_is_bounded_coalesced_and_failure_trips_readiness() {
        let base = 1_700_000_000;
        let mut monitor = boot(base, base);
        monitor.observe(reading(base + 30, 30));
        let command = match monitor.idle_checkpoint(Duration::from_secs(30)).unwrap() {
            CheckpointRequest::Submit(command) => command,
            other => panic!("unexpected request: {other:?}"),
        };
        assert_eq!(
            monitor.idle_checkpoint(Duration::from_secs(30)).unwrap(),
            CheckpointRequest::Coalesced
        );
        assert_eq!(command.replacement_high_water_unix_seconds, base + 30);
        monitor.complete_watermark(command, true).unwrap();
        assert_eq!(monitor.persisted_high_water_unix_seconds(), base + 30);
        assert_eq!(
            monitor.idle_checkpoint(Duration::from_secs(31)).unwrap(),
            CheckpointRequest::NotDue
        );

        monitor.observe(reading(base + 60, 60));
        let pending = match monitor.idle_checkpoint(Duration::from_secs(60)).unwrap() {
            CheckpointRequest::Submit(command) => command,
            other => panic!("unexpected request: {other:?}"),
        };
        assert_eq!(
            monitor
                .poll_checkpoint_deadline(pending.deadline + Duration::from_millis(1))
                .err(),
            Some(ClockError::PersistenceFailed)
        );
        assert_eq!(monitor.safety(), ClockSafety::Unsafe);
    }

    #[test]
    fn application_and_shutdown_commits_advance_only_accepted_time() {
        let base = 1_700_000_000;
        let mut monitor = boot(base, base);
        monitor.observe(reading(base + 5, 5));
        let application = monitor.application_commit(Duration::from_secs(5)).unwrap();
        monitor.complete_watermark(application, true).unwrap();
        assert_eq!(monitor.persisted_high_water_unix_seconds(), base + 5);
        monitor.observe(reading(base + 8, 8));
        let shutdown = monitor.clean_shutdown(Duration::from_secs(8)).unwrap();
        assert_eq!(shutdown.kind, WatermarkKind::CleanShutdown);
        monitor.complete_watermark(shutdown, true).unwrap();
        assert_eq!(monitor.persisted_high_water_unix_seconds(), base + 8);
    }

    struct RepairBackend {
        mark: u64,
        epoch: u64,
        committed: bool,
    }

    impl ClockRepairBackend for RepairBackend {
        type Transaction = (u64, u64);

        fn current_high_water_unix_seconds(&mut self) -> Result<u64, ClockRepairBackendError> {
            Ok(self.mark)
        }

        fn prepare_clock_repair(
            &mut self,
            request: &ClockRepairRequest,
        ) -> Result<PreparedClockRepair<Self::Transaction>, ClockRepairBackendError> {
            Ok(PreparedClockRepair {
                replacement_credential: Zeroizing::new(b"replacement-control-credential".to_vec()),
                replacement_epoch: self.epoch + 1,
                transaction: (request.replacement_unix_seconds, self.epoch + 1),
            })
        }

        fn commit_clock_repair(
            &mut self,
            transaction: Self::Transaction,
        ) -> Result<(), ClockRepairBackendError> {
            self.mark = transaction.0;
            self.epoch = transaction.1;
            self.committed = true;
            Ok(())
        }
    }

    #[test]
    fn repair_requires_exact_mark_and_discloses_replacement_before_atomic_epoch_commit() {
        let request = ClockRepairRequest {
            exact_old_high_water_unix_seconds: 2_000,
            replacement_unix_seconds: 1_000,
            reason: "operator corrected poisoned RTC".into(),
        };
        let mut backend = RepairBackend {
            mark: 2_000,
            epoch: 7,
            committed: false,
        };
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let receipt = repair_clock(&request, 1_000, &mut writer, &mut backend).unwrap();
        assert!(backend.committed);
        assert_eq!(backend.mark, 1_000);
        assert_eq!(backend.epoch, 8);
        assert_eq!(receipt.replacement_epoch, 8);
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let mut disclosed = String::new();
        reader.read_to_string(&mut disclosed).unwrap();
        assert_eq!(disclosed, "replacement-control-credential\n");

        let mut stale = RepairBackend {
            mark: 2_001,
            epoch: 8,
            committed: false,
        };
        let (mut writer, _) = UnixStream::pair().unwrap();
        assert_eq!(
            repair_clock(&request, 1_000, &mut writer, &mut stale).err(),
            Some(ClockError::StaleRepair)
        );
        assert!(!stale.committed);
    }

    struct ShortWriter(UnixStream);

    impl Write for ShortWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl AsFd for ShortWriter {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            self.0.as_fd()
        }
    }

    #[test]
    fn repair_short_write_never_commits() {
        let request = ClockRepairRequest {
            exact_old_high_water_unix_seconds: 2_000,
            replacement_unix_seconds: 1_000,
            reason: "repair".into(),
        };
        let (socket, _) = UnixStream::pair().unwrap();
        let mut writer = ShortWriter(socket);
        let mut backend = RepairBackend {
            mark: 2_000,
            epoch: 7,
            committed: false,
        };
        assert_eq!(
            repair_clock(&request, 1_000, &mut writer, &mut backend).err(),
            Some(ClockError::DisclosureFailed)
        );
        assert!(!backend.committed);
        assert_eq!(backend.epoch, 7);
    }
}
