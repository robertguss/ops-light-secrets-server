//! Bounded blocking storage execution with explicit admission lanes.

use std::collections::BTreeMap;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

pub const WRITER_THREAD_NAME: &str = "olss-storage-writer";
pub const DEFAULT_DATA_CAPACITY: usize = 64;
pub const DEFAULT_RECOVERY_CAPACITY: usize = 16;
pub const DEFAULT_RECOVERY_WEIGHT: u8 = 3;
pub const DEFAULT_OVERLOAD_BUCKETS: usize = 64;
pub const MAX_OVERLOAD_COUNT: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationClass {
    DataPlane,
    ClockWatermark,
    Checkpoint,
    Backup,
    Diagnostics,
    AuditQuery,
    AuditExport,
    ReserveStatus,
    ReserveRelease,
    ReserveRecreate,
    Shutdown,
    IdentityDisable,
    GrantReduction,
    CredentialRevocation,
}

impl OperationClass {
    fn is_recovery(self) -> bool {
        self != Self::DataPlane
    }

    fn is_urgent(self) -> bool {
        matches!(
            self,
            Self::ClockWatermark
                | Self::ReserveStatus
                | Self::ReserveRelease
                | Self::ReserveRecreate
                | Self::Shutdown
                | Self::IdentityDisable
                | Self::GrantReduction
                | Self::CredentialRevocation
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AdmissionLane {
    Data,
    Recovery,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OverloadBucket {
    pub lane: AdmissionLane,
    pub operation: OperationClass,
    pub class: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverloadCount {
    pub bucket: Option<OverloadBucket>,
    pub count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OverloadSnapshot {
    pub counts: Vec<OverloadCount>,
}

#[derive(Debug)]
struct OverloadAccumulator {
    buckets: BTreeMap<OverloadBucket, u64>,
    overflow: u64,
    max_buckets: usize,
}

impl OverloadAccumulator {
    fn new(max_buckets: usize) -> Self {
        Self {
            buckets: BTreeMap::new(),
            overflow: 0,
            max_buckets,
        }
    }

    fn record(&mut self, bucket: OverloadBucket) {
        if let Some(count) = self.buckets.get_mut(&bucket) {
            *count = count.saturating_add(1);
        } else if self.buckets.len() < self.max_buckets {
            self.buckets.insert(bucket, 1);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    fn take(&mut self) -> OverloadSnapshot {
        let mut counts = std::mem::take(&mut self.buckets)
            .into_iter()
            .map(|(bucket, count)| OverloadCount {
                bucket: Some(bucket),
                count,
            })
            .collect::<Vec<_>>();
        if self.overflow != 0 {
            counts.push(OverloadCount {
                bucket: None,
                count: std::mem::take(&mut self.overflow),
            });
        }
        OverloadSnapshot { counts }
    }

    fn merge(&mut self, snapshot: OverloadSnapshot) {
        for count in snapshot.counts {
            match count.bucket {
                Some(bucket) => {
                    if let Some(current) = self.buckets.get_mut(&bucket) {
                        *current = current.saturating_add(count.count);
                    } else if self.buckets.len() < self.max_buckets {
                        self.buckets.insert(bucket, count.count);
                    } else {
                        self.overflow = self.overflow.saturating_add(count.count);
                    }
                }
                None => self.overflow = self.overflow.saturating_add(count.count),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorConfig {
    pub data_capacity: usize,
    pub recovery_capacity: usize,
    pub recovery_weight: u8,
    pub overload_buckets: usize,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            data_capacity: DEFAULT_DATA_CAPACITY,
            recovery_capacity: DEFAULT_RECOVERY_CAPACITY,
            recovery_weight: DEFAULT_RECOVERY_WEIGHT,
            overload_buckets: DEFAULT_OVERLOAD_BUCKETS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorConfigError {
    ZeroDataCapacity,
    RecoveryCapacityTooSmall,
    ZeroRecoveryWeight,
    ZeroOverloadBuckets,
}

impl ExecutorConfig {
    fn validate(self) -> Result<Self, ExecutorConfigError> {
        if self.data_capacity == 0 {
            return Err(ExecutorConfigError::ZeroDataCapacity);
        }
        if self.recovery_capacity < 2 {
            return Err(ExecutorConfigError::RecoveryCapacityTooSmall);
        }
        if self.recovery_weight == 0 {
            return Err(ExecutorConfigError::ZeroRecoveryWeight);
        }
        if self.overload_buckets == 0 {
            return Err(ExecutorConfigError::ZeroOverloadBuckets);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CommandState {
    Accepted = 0,
    Cancelled = 1,
    Started = 2,
    Committed = 3,
    Aborted = 4,
    Replied = 5,
    WorkerFailed = 6,
}

impl CommandState {
    fn load(value: u8) -> Self {
        match value {
            0 => Self::Accepted,
            1 => Self::Cancelled,
            2 => Self::Started,
            3 => Self::Committed,
            4 => Self::Aborted,
            5 => Self::Replied,
            _ => Self::WorkerFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitError {
    Overloaded,
    WrongLane,
    WorkerUnavailable,
    WatermarkPending,
    WatermarkDeadlineMissed,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Overloaded => "storage_overloaded",
            Self::WrongLane => "storage_wrong_admission_lane",
            Self::WorkerUnavailable => "storage_worker_unavailable",
            Self::WatermarkPending => "clock_watermark_already_pending",
            Self::WatermarkDeadlineMissed => "clock_watermark_deadline_missed",
        })
    }
}

impl std::error::Error for SubmitError {}

#[derive(Debug, Eq, PartialEq)]
pub enum ReceiveError<E> {
    Backend(E),
    WorkerUnavailable,
}

pub struct Submission<R, E> {
    receiver: oneshot::Receiver<Result<R, E>>,
    state: Arc<AtomicU8>,
}

impl<R, E> Submission<R, E> {
    pub fn state(&self) -> CommandState {
        CommandState::load(self.state.load(Ordering::Acquire))
    }

    pub async fn receive(self) -> Result<R, ReceiveError<E>> {
        match self.receiver.await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(ReceiveError::Backend(error)),
            Err(_) => Err(ReceiveError::WorkerUnavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionContext {
    pub operation: OperationClass,
}

pub trait StorageBackend<C, R, E>: Send + 'static {
    /// The implementation commits `overloads` atomically with `command`.
    fn execute(
        &mut self,
        context: ExecutionContext,
        command: C,
        overloads: &OverloadSnapshot,
    ) -> Result<R, E>;
}

struct WorkerMessage<C, R, E> {
    operation: OperationClass,
    command: C,
    reply: oneshot::Sender<Result<R, E>>,
    state: Arc<AtomicU8>,
    watermark: bool,
}

struct WorkerInputs<C, R, E> {
    data: Receiver<WorkerMessage<C, R, E>>,
    urgent: Receiver<WorkerMessage<C, R, E>>,
    recovery: Receiver<WorkerMessage<C, R, E>>,
    recovery_weight: u8,
    stopping: Arc<AtomicBool>,
    overloads: Arc<Mutex<OverloadAccumulator>>,
    watermark: Arc<WatermarkGate>,
}

struct WatermarkGate {
    pending: AtomicBool,
    deadline: Mutex<Option<Instant>>,
}

impl WatermarkGate {
    fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            deadline: Mutex::new(None),
        }
    }

    fn begin(&self, deadline: Instant) -> Result<(), SubmitError> {
        self.pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SubmitError::WatermarkPending)?;
        *self.deadline.lock().expect("watermark deadline lock") = Some(deadline);
        Ok(())
    }

    fn finish(&self) {
        *self.deadline.lock().expect("watermark deadline lock") = None;
        self.pending.store(false, Ordering::Release);
    }
}

pub struct StorageExecutor<C, R, E> {
    data: Option<SyncSender<WorkerMessage<C, R, E>>>,
    urgent: Option<SyncSender<WorkerMessage<C, R, E>>>,
    recovery: Option<SyncSender<WorkerMessage<C, R, E>>>,
    worker: thread::Thread,
    join: Option<JoinHandle<()>>,
    healthy: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    overloads: Arc<Mutex<OverloadAccumulator>>,
    watermark: Arc<WatermarkGate>,
}

impl<C, R, E> StorageExecutor<C, R, E>
where
    C: Send + 'static,
    R: Send + Zeroize + 'static,
    E: Send + 'static,
{
    pub fn start<B>(config: ExecutorConfig, backend: B) -> Result<Self, ExecutorConfigError>
    where
        B: StorageBackend<C, R, E>,
    {
        let config = config.validate()?;
        let urgent_capacity = config.recovery_capacity.div_ceil(2);
        let normal_capacity = config.recovery_capacity / 2;
        let (data_tx, data_rx) = sync_channel(config.data_capacity);
        let (urgent_tx, urgent_rx) = sync_channel(urgent_capacity);
        let (recovery_tx, recovery_rx) = sync_channel(normal_capacity);
        let healthy = Arc::new(AtomicBool::new(true));
        let stopping = Arc::new(AtomicBool::new(false));
        let overloads = Arc::new(Mutex::new(OverloadAccumulator::new(
            config.overload_buckets,
        )));
        let watermark = Arc::new(WatermarkGate::new());
        let worker_health = Arc::clone(&healthy);
        let worker_stopping = Arc::clone(&stopping);
        let worker_overloads = Arc::clone(&overloads);
        let worker_watermark = Arc::clone(&watermark);
        let join = thread::Builder::new()
            .name(WRITER_THREAD_NAME.into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    worker_loop(
                        backend,
                        WorkerInputs {
                            data: data_rx,
                            urgent: urgent_rx,
                            recovery: recovery_rx,
                            recovery_weight: config.recovery_weight,
                            stopping: worker_stopping,
                            overloads: worker_overloads,
                            watermark: worker_watermark,
                        },
                    );
                }));
                if result.is_err() {
                    worker_health.store(false, Ordering::Release);
                }
            })
            .expect("spawn named storage writer");
        let worker = join.thread().clone();
        Ok(Self {
            data: Some(data_tx),
            urgent: Some(urgent_tx),
            recovery: Some(recovery_tx),
            worker,
            join: Some(join),
            healthy,
            stopping,
            overloads,
            watermark,
        })
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    pub fn submit_data(&self, command: C, class: u16) -> Result<Submission<R, E>, SubmitError> {
        // Callers submit the authenticated wire command before performing
        // payload decryption; queue admission therefore precedes secret work.
        self.submit(OperationClass::DataPlane, command, class, None)
    }

    pub fn submit_recovery(
        &self,
        operation: OperationClass,
        command: C,
        class: u16,
    ) -> Result<Submission<R, E>, SubmitError> {
        if !operation.is_recovery() {
            return Err(SubmitError::WrongLane);
        }
        self.submit(operation, command, class, None)
    }

    pub fn submit_clock_watermark(
        &self,
        command: C,
        class: u16,
        deadline: Instant,
    ) -> Result<Submission<R, E>, SubmitError> {
        self.watermark.begin(deadline)?;
        match self.submit(
            OperationClass::ClockWatermark,
            command,
            class,
            Some(deadline),
        ) {
            Ok(submission) => Ok(submission),
            Err(error) => {
                self.watermark.finish();
                Err(error)
            }
        }
    }

    pub fn poll_clock_watermark_deadline(&self, now: Instant) -> Result<(), SubmitError> {
        let missed = self
            .watermark
            .deadline
            .lock()
            .expect("watermark deadline lock")
            .is_some_and(|deadline| now > deadline);
        if missed {
            self.healthy.store(false, Ordering::Release);
            Err(SubmitError::WatermarkDeadlineMissed)
        } else {
            Ok(())
        }
    }

    fn submit(
        &self,
        operation: OperationClass,
        command: C,
        class: u16,
        watermark_deadline: Option<Instant>,
    ) -> Result<Submission<R, E>, SubmitError> {
        if !self.is_healthy() {
            return Err(SubmitError::WorkerUnavailable);
        }
        let lane = if operation == OperationClass::DataPlane {
            AdmissionLane::Data
        } else {
            AdmissionLane::Recovery
        };
        let (reply, receiver) = oneshot::channel();
        let state = Arc::new(AtomicU8::new(CommandState::Accepted as u8));
        let message = WorkerMessage {
            operation,
            command,
            reply,
            state: Arc::clone(&state),
            watermark: watermark_deadline.is_some(),
        };
        let sender = if lane == AdmissionLane::Data {
            self.data.as_ref().expect("data sender")
        } else if operation.is_urgent() {
            self.urgent.as_ref().expect("urgent sender")
        } else {
            self.recovery.as_ref().expect("recovery sender")
        };
        match sender.try_send(message) {
            Ok(()) => {
                self.worker.unpark();
                Ok(Submission { receiver, state })
            }
            Err(TrySendError::Full(_)) => {
                self.overloads
                    .lock()
                    .expect("overload lock")
                    .record(OverloadBucket {
                        lane,
                        operation,
                        class,
                    });
                Err(SubmitError::Overloaded)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.healthy.store(false, Ordering::Release);
                Err(SubmitError::WorkerUnavailable)
            }
        }
    }
}

impl<C, R, E> Drop for StorageExecutor<C, R, E> {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.data.take();
        self.urgent.take();
        self.recovery.take();
        self.worker.unpark();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn worker_loop<C, R, E, B>(mut backend: B, inputs: WorkerInputs<C, R, E>)
where
    C: Send + 'static,
    R: Send + Zeroize + 'static,
    E: Send + 'static,
    B: StorageBackend<C, R, E>,
{
    let mut recovery_streak = 0_u8;
    loop {
        let selected = select_message(
            &inputs.data,
            &inputs.urgent,
            &inputs.recovery,
            inputs.recovery_weight,
            &mut recovery_streak,
        );
        let Some(message) = selected else {
            if inputs.stopping.load(Ordering::Acquire) {
                return;
            }
            thread::park_timeout(Duration::from_millis(1));
            continue;
        };
        if message.reply.is_closed() {
            message
                .state
                .store(CommandState::Cancelled as u8, Ordering::Release);
            if message.watermark {
                inputs.watermark.finish();
            }
            continue;
        }
        message
            .state
            .store(CommandState::Started as u8, Ordering::Release);
        let aggregate = inputs.overloads.lock().expect("overload lock").take();
        let result = backend.execute(
            ExecutionContext {
                operation: message.operation,
            },
            message.command,
            &aggregate,
        );
        if result.is_err() {
            inputs
                .overloads
                .lock()
                .expect("overload lock")
                .merge(aggregate);
        }
        message.state.store(
            if result.is_ok() {
                CommandState::Committed as u8
            } else {
                CommandState::Aborted as u8
            },
            Ordering::Release,
        );
        match message.reply.send(result) {
            Ok(()) => message
                .state
                .store(CommandState::Replied as u8, Ordering::Release),
            Err(Ok(mut response)) => response.zeroize(),
            Err(Err(_)) => {}
        }
        if message.watermark {
            inputs.watermark.finish();
        }
    }
}

fn select_message<C, R, E>(
    data: &Receiver<WorkerMessage<C, R, E>>,
    urgent: &Receiver<WorkerMessage<C, R, E>>,
    recovery: &Receiver<WorkerMessage<C, R, E>>,
    recovery_weight: u8,
    recovery_streak: &mut u8,
) -> Option<WorkerMessage<C, R, E>> {
    if *recovery_streak >= recovery_weight {
        if let Ok(message) = data.try_recv() {
            *recovery_streak = 0;
            return Some(message);
        }
    }
    if let Ok(message) = urgent.try_recv() {
        *recovery_streak = recovery_streak.saturating_add(1);
        return Some(message);
    }
    if let Ok(message) = recovery.try_recv() {
        *recovery_streak = recovery_streak.saturating_add(1);
        return Some(message);
    }
    if let Ok(message) = data.try_recv() {
        *recovery_streak = 0;
        return Some(message);
    }
    None
}

pub const SNAPSHOT_THREAD_PREFIX: &str = "olss-storage-snapshot";
pub const MAX_SNAPSHOT_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotConfig {
    pub concurrency: usize,
    pub queue_capacity: usize,
    pub max_lifetime: Duration,
    pub max_result_bytes: usize,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            concurrency: 2,
            queue_capacity: 8,
            max_lifetime: Duration::from_secs(30),
            max_result_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotConfigError {
    ZeroConcurrency,
    ZeroQueueCapacity,
    ZeroLifetime,
    LifetimeTooLong,
    ZeroResultBytes,
}

impl SnapshotConfig {
    fn validate(self) -> Result<Self, SnapshotConfigError> {
        if self.concurrency == 0 {
            return Err(SnapshotConfigError::ZeroConcurrency);
        }
        if self.queue_capacity == 0 {
            return Err(SnapshotConfigError::ZeroQueueCapacity);
        }
        if self.max_lifetime.is_zero() {
            return Err(SnapshotConfigError::ZeroLifetime);
        }
        if self.max_lifetime > MAX_SNAPSHOT_LIFETIME {
            return Err(SnapshotConfigError::LifetimeTooLong);
        }
        if self.max_result_bytes == 0 {
            return Err(SnapshotConfigError::ZeroResultBytes);
        }
        Ok(self)
    }
}

pub trait SnapshotCursor<E>: Send + 'static {
    /// Returns the next buffered chunk. Implementations must honor `deadline`
    /// and may never expose a database handle outside this call.
    fn next_chunk(
        &mut self,
        deadline: Instant,
        remaining_bytes: usize,
    ) -> Result<Option<Vec<u8>>, E>;
}

pub trait SnapshotBackend<C, E>: Send + Sync + 'static {
    type Cursor: SnapshotCursor<E>;

    fn begin_snapshot(&self, command: C) -> Result<Self::Cursor, E>;
}

pub struct SnapshotBuffer(Zeroizing<Vec<u8>>);

impl fmt::Debug for SnapshotBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SnapshotBuffer([REDACTED])")
    }
}

impl SnapshotBuffer {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SnapshotReceiveError<E> {
    Backend(E),
    ResultTooLarge,
    DeadlineExceeded,
    WorkerUnavailable,
}

enum SnapshotReply<E> {
    Complete(SnapshotBuffer),
    Backend(E),
    ResultTooLarge,
    DeadlineExceeded,
}

struct SnapshotMessage<C, E> {
    command: C,
    reply: oneshot::Sender<SnapshotReply<E>>,
    state: Arc<AtomicU8>,
}

pub struct SnapshotSubmission<E> {
    receiver: oneshot::Receiver<SnapshotReply<E>>,
    state: Arc<AtomicU8>,
}

impl<E> SnapshotSubmission<E> {
    pub fn state(&self) -> CommandState {
        CommandState::load(self.state.load(Ordering::Acquire))
    }

    pub async fn receive(self) -> Result<SnapshotBuffer, SnapshotReceiveError<E>> {
        match self.receiver.await {
            Ok(SnapshotReply::Complete(buffer)) => Ok(buffer),
            Ok(SnapshotReply::Backend(error)) => Err(SnapshotReceiveError::Backend(error)),
            Ok(SnapshotReply::ResultTooLarge) => Err(SnapshotReceiveError::ResultTooLarge),
            Ok(SnapshotReply::DeadlineExceeded) => Err(SnapshotReceiveError::DeadlineExceeded),
            Err(_) => Err(SnapshotReceiveError::WorkerUnavailable),
        }
    }
}

pub struct SnapshotService<C, E> {
    sender: Option<SyncSender<SnapshotMessage<C, E>>>,
    workers: Vec<JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
}

impl<C, E> SnapshotService<C, E>
where
    C: Send + 'static,
    E: Send + 'static,
{
    pub fn start<B>(config: SnapshotConfig, backend: B) -> Result<Self, SnapshotConfigError>
    where
        B: SnapshotBackend<C, E>,
    {
        let config = config.validate()?;
        let (sender, receiver) = sync_channel(config.queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let backend = Arc::new(backend);
        let stopping = Arc::new(AtomicBool::new(false));
        let healthy = Arc::new(AtomicBool::new(true));
        let mut workers = Vec::with_capacity(config.concurrency);
        for index in 0..config.concurrency {
            let receiver = Arc::clone(&receiver);
            let backend = Arc::clone(&backend);
            let stopping = Arc::clone(&stopping);
            let healthy = Arc::clone(&healthy);
            workers.push(
                thread::Builder::new()
                    .name(format!("{SNAPSHOT_THREAD_PREFIX}-{index}"))
                    .spawn(move || {
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            snapshot_worker(receiver, backend, config, stopping)
                        }));
                        if result.is_err() {
                            healthy.store(false, Ordering::Release);
                        }
                    })
                    .expect("spawn bounded snapshot worker"),
            );
        }
        Ok(Self {
            sender: Some(sender),
            workers,
            stopping,
            healthy,
        })
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    pub fn submit(&self, command: C) -> Result<SnapshotSubmission<E>, SubmitError> {
        if !self.is_healthy() {
            return Err(SubmitError::WorkerUnavailable);
        }
        let (reply, receiver) = oneshot::channel();
        let state = Arc::new(AtomicU8::new(CommandState::Accepted as u8));
        let message = SnapshotMessage {
            command,
            reply,
            state: Arc::clone(&state),
        };
        match self
            .sender
            .as_ref()
            .expect("snapshot sender")
            .try_send(message)
        {
            Ok(()) => Ok(SnapshotSubmission { receiver, state }),
            Err(TrySendError::Full(_)) => Err(SubmitError::Overloaded),
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::WorkerUnavailable),
        }
    }
}

impl<C, E> Drop for SnapshotService<C, E> {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn snapshot_worker<C, E, B>(
    receiver: Arc<Mutex<Receiver<SnapshotMessage<C, E>>>>,
    backend: Arc<B>,
    config: SnapshotConfig,
    stopping: Arc<AtomicBool>,
) where
    C: Send + 'static,
    E: Send + 'static,
    B: SnapshotBackend<C, E>,
{
    while !stopping.load(Ordering::Acquire) {
        let message = receiver
            .lock()
            .expect("snapshot queue lock")
            .recv_timeout(Duration::from_millis(1));
        let Ok(message) = message else {
            continue;
        };
        if message.reply.is_closed() {
            message
                .state
                .store(CommandState::Cancelled as u8, Ordering::Release);
            continue;
        }
        message
            .state
            .store(CommandState::Started as u8, Ordering::Release);
        let deadline = Instant::now() + config.max_lifetime;
        let reply = match backend.begin_snapshot(message.command) {
            Err(error) => Some(SnapshotReply::Backend(error)),
            Ok(mut cursor) => {
                let mut output = Zeroizing::new(Vec::new());
                loop {
                    if message.reply.is_closed() {
                        message
                            .state
                            .store(CommandState::Cancelled as u8, Ordering::Release);
                        break None;
                    }
                    if Instant::now() > deadline {
                        break Some(SnapshotReply::DeadlineExceeded);
                    }
                    let remaining = config.max_result_bytes.saturating_sub(output.len());
                    let next = cursor.next_chunk(deadline, remaining);
                    if Instant::now() > deadline {
                        if let Ok(Some(mut chunk)) = next {
                            chunk.zeroize();
                        }
                        break Some(SnapshotReply::DeadlineExceeded);
                    }
                    match next {
                        Err(error) => break Some(SnapshotReply::Backend(error)),
                        Ok(None) => break Some(SnapshotReply::Complete(SnapshotBuffer(output))),
                        Ok(Some(mut chunk)) if chunk.len() > remaining => {
                            chunk.zeroize();
                            break Some(SnapshotReply::ResultTooLarge);
                        }
                        Ok(Some(mut chunk)) => {
                            output.extend_from_slice(&chunk);
                            chunk.zeroize();
                        }
                    }
                }
            }
        };
        let Some(reply) = reply else {
            continue;
        };
        message.state.store(
            if matches!(reply, SnapshotReply::Complete(_)) {
                CommandState::Committed as u8
            } else {
                CommandState::Aborted as u8
            },
            Ordering::Release,
        );
        if message.reply.send(reply).is_ok() {
            message
                .state
                .store(CommandState::Replied as u8, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Condvar;

    #[derive(Clone)]
    struct Command {
        id: u8,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
        panic: bool,
        fail: bool,
    }

    impl Command {
        fn plain(id: u8) -> Self {
            Self {
                id,
                gate: None,
                panic: false,
                fail: false,
            }
        }
    }

    struct Response {
        id: u8,
        zeroized: Arc<AtomicBool>,
    }

    impl Zeroize for Response {
        fn zeroize(&mut self) {
            self.id = 0;
            self.zeroized.store(true, Ordering::Release);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct BackendError;

    struct Backend {
        order: Arc<Mutex<Vec<u8>>>,
        aggregates: Arc<Mutex<Vec<OverloadSnapshot>>>,
        zeroized: Arc<AtomicBool>,
        thread_names: Arc<Mutex<Vec<String>>>,
    }

    impl StorageBackend<Command, Response, BackendError> for Backend {
        fn execute(
            &mut self,
            _context: ExecutionContext,
            command: Command,
            overloads: &OverloadSnapshot,
        ) -> Result<Response, BackendError> {
            self.thread_names
                .lock()
                .unwrap()
                .push(thread::current().name().unwrap_or("unnamed").to_owned());
            if let Some(gate) = command.gate {
                let (lock, wake) = &*gate;
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = wake.wait(open).unwrap();
                }
            }
            if command.panic {
                panic!("injected storage worker panic");
            }
            self.order.lock().unwrap().push(command.id);
            self.aggregates.lock().unwrap().push(overloads.clone());
            if command.fail {
                Err(BackendError)
            } else {
                Ok(Response {
                    id: command.id,
                    zeroized: Arc::clone(&self.zeroized),
                })
            }
        }
    }

    type TestExecutor = StorageExecutor<Command, Response, BackendError>;

    struct Fixture {
        executor: TestExecutor,
        order: Arc<Mutex<Vec<u8>>>,
        aggregates: Arc<Mutex<Vec<OverloadSnapshot>>>,
        zeroized: Arc<AtomicBool>,
        names: Arc<Mutex<Vec<String>>>,
    }

    fn fixture(config: ExecutorConfig) -> Fixture {
        let order = Arc::new(Mutex::new(Vec::new()));
        let aggregates = Arc::new(Mutex::new(Vec::new()));
        let zeroized = Arc::new(AtomicBool::new(false));
        let names = Arc::new(Mutex::new(Vec::new()));
        let backend = Backend {
            order: Arc::clone(&order),
            aggregates: Arc::clone(&aggregates),
            zeroized: Arc::clone(&zeroized),
            thread_names: Arc::clone(&names),
        };
        Fixture {
            executor: StorageExecutor::start(config, backend).unwrap(),
            order,
            aggregates,
            zeroized,
            names,
        }
    }

    fn blocked(id: u8) -> (Command, Arc<(Mutex<bool>, Condvar)>) {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        (
            Command {
                id,
                gate: Some(Arc::clone(&gate)),
                panic: false,
                fail: false,
            },
            gate,
        )
    }

    fn release(gate: &Arc<(Mutex<bool>, Condvar)>) {
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }

    fn wait_for_state<R, E>(submission: &Submission<R, E>, expected: CommandState) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while submission.state() != expected {
            assert!(Instant::now() < deadline, "state timeout");
            thread::yield_now();
        }
    }

    #[tokio::test]
    async fn lane_boundaries_saturate_before_execution_and_recovery_remains_available() {
        let fixture = fixture(ExecutorConfig {
            data_capacity: 2,
            recovery_capacity: 2,
            ..ExecutorConfig::default()
        });
        let (first, gate) = blocked(1);
        let first = fixture.executor.submit_data(first, 1).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while first.state() != CommandState::Started {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        let second = fixture.executor.submit_data(Command::plain(2), 1).unwrap();
        let third = fixture.executor.submit_data(Command::plain(3), 1).unwrap();
        assert!(matches!(
            fixture.executor.submit_data(Command::plain(4), 1),
            Err(SubmitError::Overloaded)
        ));
        let recovery = fixture
            .executor
            .submit_recovery(OperationClass::CredentialRevocation, Command::plain(5), 1)
            .unwrap();
        assert!(matches!(
            fixture
                .executor
                .submit_recovery(OperationClass::ReserveRecreate, Command::plain(6), 1,),
            Err(SubmitError::Overloaded)
        ));
        let diagnostic = fixture
            .executor
            .submit_recovery(OperationClass::Diagnostics, Command::plain(7), 1)
            .unwrap();
        assert!(matches!(
            fixture
                .executor
                .submit_recovery(OperationClass::AuditQuery, Command::plain(8), 1,),
            Err(SubmitError::Overloaded)
        ));
        release(&gate);
        assert_eq!(first.receive().await.unwrap().id, 1);
        assert_eq!(recovery.receive().await.unwrap().id, 5);
        assert_eq!(diagnostic.receive().await.unwrap().id, 7);
        assert_eq!(second.receive().await.unwrap().id, 2);
        assert_eq!(third.receive().await.unwrap().id, 3);
        assert!(
            fixture
                .names
                .lock()
                .unwrap()
                .iter()
                .all(|name| name == WRITER_THREAD_NAME)
        );
    }

    #[tokio::test]
    async fn cancellation_before_begin_skips_and_after_begin_commits_then_zeroizes_reply() {
        let fixture = fixture(ExecutorConfig {
            data_capacity: 4,
            recovery_capacity: 2,
            ..ExecutorConfig::default()
        });
        let (first, first_gate) = blocked(1);
        let first = fixture.executor.submit_data(first, 1).unwrap();
        wait_for_state(&first, CommandState::Started);
        let cancelled = fixture.executor.submit_data(Command::plain(2), 1).unwrap();
        let cancelled_state = Arc::clone(&cancelled.state);
        drop(cancelled);
        release(&first_gate);
        first.receive().await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while CommandState::load(cancelled_state.load(Ordering::Acquire)) != CommandState::Cancelled
        {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(!fixture.order.lock().unwrap().contains(&2));

        let (after, after_gate) = blocked(3);
        let after = fixture.executor.submit_data(after, 1).unwrap();
        wait_for_state(&after, CommandState::Started);
        drop(after);
        release(&after_gate);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !fixture.zeroized.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(fixture.order.lock().unwrap().contains(&3));
    }

    #[tokio::test]
    async fn weighted_fairness_and_urgent_reserve_priority_are_bounded() {
        let fixture = fixture(ExecutorConfig {
            data_capacity: 8,
            recovery_capacity: 10,
            recovery_weight: 3,
            ..ExecutorConfig::default()
        });
        let (first, gate) = blocked(1);
        let first = fixture.executor.submit_data(first, 1).unwrap();
        wait_for_state(&first, CommandState::Started);
        let data = fixture.executor.submit_data(Command::plain(2), 1).unwrap();
        let diagnostic = fixture
            .executor
            .submit_recovery(OperationClass::Diagnostics, Command::plain(3), 1)
            .unwrap();
        let recreate = fixture
            .executor
            .submit_recovery(OperationClass::ReserveRecreate, Command::plain(4), 1)
            .unwrap();
        let revocations = (5..=8)
            .map(|id| {
                fixture
                    .executor
                    .submit_recovery(OperationClass::CredentialRevocation, Command::plain(id), 1)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        release(&gate);
        first.receive().await.unwrap();
        data.receive().await.unwrap();
        diagnostic.receive().await.unwrap();
        recreate.receive().await.unwrap();
        for submission in revocations {
            submission.receive().await.unwrap();
        }
        let order = fixture.order.lock().unwrap().clone();
        assert!(order.iter().position(|id| *id == 4) < order.iter().position(|id| *id == 3));
        let data_index = order.iter().position(|id| *id == 2).unwrap();
        assert!(
            data_index <= 4,
            "data waited behind more than recovery weight: {order:?}"
        );
    }

    #[tokio::test]
    async fn overload_buckets_are_bounded_flushed_and_requeued_after_abort() {
        let fixture = fixture(ExecutorConfig {
            data_capacity: 1,
            recovery_capacity: 2,
            overload_buckets: 2,
            ..ExecutorConfig::default()
        });
        let (first, gate) = blocked(1);
        let first = fixture.executor.submit_data(first, 1).unwrap();
        wait_for_state(&first, CommandState::Started);
        let mut queued_command = Command::plain(2);
        queued_command.fail = true;
        let queued = fixture.executor.submit_data(queued_command, 1).unwrap();
        for class in 10..15 {
            assert!(matches!(
                fixture.executor.submit_data(Command::plain(9), class),
                Err(SubmitError::Overloaded)
            ));
        }
        release(&gate);
        first.receive().await.unwrap();
        assert!(matches!(
            queued.receive().await,
            Err(ReceiveError::Backend(BackendError))
        ));
        fixture
            .executor
            .submit_data(Command::plain(4), 1)
            .unwrap()
            .receive()
            .await
            .unwrap();
        let snapshots = fixture.aggregates.lock().unwrap();
        assert!(snapshots.iter().any(|snapshot| {
            snapshot.counts.len() == 3
                && snapshot.counts.iter().map(|count| count.count).sum::<u64>() == 5
        }));
    }

    #[tokio::test]
    async fn watermark_is_coalesced_and_missed_deadline_fails_health() {
        let fixture = fixture(ExecutorConfig {
            data_capacity: 2,
            recovery_capacity: 2,
            ..ExecutorConfig::default()
        });
        let (first, gate) = blocked(1);
        let first = fixture.executor.submit_data(first, 1).unwrap();
        wait_for_state(&first, CommandState::Started);
        let deadline = Instant::now() + Duration::from_millis(20);
        let watermark = fixture
            .executor
            .submit_clock_watermark(Command::plain(2), 1, deadline)
            .unwrap();
        assert!(matches!(
            fixture
                .executor
                .submit_clock_watermark(Command::plain(3), 1, deadline),
            Err(SubmitError::WatermarkPending)
        ));
        thread::sleep(Duration::from_millis(25));
        assert_eq!(
            fixture
                .executor
                .poll_clock_watermark_deadline(Instant::now()),
            Err(SubmitError::WatermarkDeadlineMissed)
        );
        assert!(!fixture.executor.is_healthy());
        release(&gate);
        first.receive().await.unwrap();
        watermark.receive().await.unwrap();
    }

    #[tokio::test]
    async fn backend_panic_propagates_worker_failure_and_closes_waiter() {
        let fixture = fixture(ExecutorConfig::default());
        let mut command = Command::plain(1);
        command.panic = true;
        let submission = fixture.executor.submit_data(command, 1).unwrap();
        assert!(matches!(
            submission.receive().await,
            Err(ReceiveError::WorkerUnavailable)
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        while fixture.executor.is_healthy() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(matches!(
            fixture.executor.submit_data(Command::plain(2), 1),
            Err(SubmitError::WorkerUnavailable)
        ));
    }

    #[derive(Clone)]
    struct SnapshotCommand {
        chunks: Vec<Vec<u8>>,
        delay: Duration,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    }

    struct SnapshotTestBackend {
        active: Arc<std::sync::atomic::AtomicUsize>,
        maximum: Arc<std::sync::atomic::AtomicUsize>,
        begun: Arc<std::sync::atomic::AtomicUsize>,
        names: Arc<Mutex<Vec<String>>>,
    }

    struct Cursor {
        chunks: std::collections::VecDeque<Vec<u8>>,
        delay: Duration,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
        active: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for Cursor {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    impl SnapshotCursor<BackendError> for Cursor {
        fn next_chunk(
            &mut self,
            _deadline: Instant,
            _remaining_bytes: usize,
        ) -> Result<Option<Vec<u8>>, BackendError> {
            if let Some(gate) = self.gate.take() {
                let mut open = gate.0.lock().unwrap();
                while !*open {
                    open = gate.1.wait(open).unwrap();
                }
            }
            thread::sleep(self.delay);
            Ok(self.chunks.pop_front())
        }
    }

    impl SnapshotBackend<SnapshotCommand, BackendError> for SnapshotTestBackend {
        type Cursor = Cursor;

        fn begin_snapshot(&self, command: SnapshotCommand) -> Result<Self::Cursor, BackendError> {
            self.begun.fetch_add(1, Ordering::AcqRel);
            self.names
                .lock()
                .unwrap()
                .push(thread::current().name().unwrap_or("unnamed").to_owned());
            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            self.maximum.fetch_max(active, Ordering::AcqRel);
            Ok(Cursor {
                chunks: command.chunks.into(),
                delay: command.delay,
                gate: command.gate,
                active: Arc::clone(&self.active),
            })
        }
    }

    struct SnapshotFixture {
        service: SnapshotService<SnapshotCommand, BackendError>,
        active: Arc<std::sync::atomic::AtomicUsize>,
        maximum: Arc<std::sync::atomic::AtomicUsize>,
        begun: Arc<std::sync::atomic::AtomicUsize>,
        names: Arc<Mutex<Vec<String>>>,
    }

    fn snapshots(config: SnapshotConfig) -> SnapshotFixture {
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let maximum = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let begun = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let names = Arc::new(Mutex::new(Vec::new()));
        let backend = SnapshotTestBackend {
            active: Arc::clone(&active),
            maximum: Arc::clone(&maximum),
            begun: Arc::clone(&begun),
            names: Arc::clone(&names),
        };
        SnapshotFixture {
            service: SnapshotService::start(config, backend).unwrap(),
            active,
            maximum,
            begun,
            names,
        }
    }

    fn snapshot_command(chunks: &[&[u8]]) -> SnapshotCommand {
        SnapshotCommand {
            chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
            delay: Duration::ZERO,
            gate: None,
        }
    }

    #[tokio::test]
    async fn snapshot_concurrency_and_result_buffers_are_hard_bounded() {
        let fixture = snapshots(SnapshotConfig {
            concurrency: 2,
            queue_capacity: 4,
            max_lifetime: Duration::from_secs(1),
            max_result_bytes: 4,
        });
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let submissions = (0..4)
            .map(|_| {
                fixture
                    .service
                    .submit(SnapshotCommand {
                        chunks: vec![b"ab".to_vec(), b"cd".to_vec()],
                        delay: Duration::ZERO,
                        gate: Some(Arc::clone(&gate)),
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let deadline = Instant::now() + Duration::from_secs(2);
        while fixture.maximum.load(Ordering::Acquire) < 2 {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert_eq!(fixture.maximum.load(Ordering::Acquire), 2);
        release(&gate);
        for submission in submissions {
            assert_eq!(submission.receive().await.unwrap().expose(), b"abcd");
        }
        assert_eq!(fixture.active.load(Ordering::Acquire), 0);
        assert!(
            fixture
                .names
                .lock()
                .unwrap()
                .iter()
                .all(|name| { name.starts_with(SNAPSHOT_THREAD_PREFIX) })
        );

        let too_large = fixture
            .service
            .submit(snapshot_command(&[b"abc", b"de"]))
            .unwrap();
        assert!(matches!(
            too_large.receive().await,
            Err(SnapshotReceiveError::ResultTooLarge)
        ));
        assert_eq!(fixture.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn stale_and_cancelled_snapshot_cursors_release_promptly() {
        let fixture = snapshots(SnapshotConfig {
            concurrency: 1,
            queue_capacity: 3,
            max_lifetime: Duration::from_millis(15),
            max_result_bytes: 32,
        });
        let stale = fixture
            .service
            .submit(SnapshotCommand {
                chunks: vec![b"a".to_vec(), b"b".to_vec()],
                delay: Duration::from_millis(20),
                gate: None,
            })
            .unwrap();
        assert!(matches!(
            stale.receive().await,
            Err(SnapshotReceiveError::DeadlineExceeded)
        ));
        assert_eq!(fixture.active.load(Ordering::Acquire), 0);

        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let first = fixture
            .service
            .submit(SnapshotCommand {
                chunks: vec![b"ok".to_vec()],
                delay: Duration::ZERO,
                gate: Some(Arc::clone(&gate)),
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while first.state() != CommandState::Started {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        let cancelled = fixture
            .service
            .submit(snapshot_command(&[b"never-opened"]))
            .unwrap();
        drop(cancelled);
        let begun_before = fixture.begun.load(Ordering::Acquire);
        release(&gate);
        assert_eq!(first.receive().await.unwrap().expose(), b"ok");
        let deadline = Instant::now() + Duration::from_secs(2);
        while fixture.active.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert_eq!(fixture.begun.load(Ordering::Acquire), begun_before);

        let after_begin = fixture
            .service
            .submit(SnapshotCommand {
                chunks: vec![b"a".to_vec(); 16],
                delay: Duration::from_millis(2),
                gate: None,
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while after_begin.state() != CommandState::Started {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        drop(after_begin);
        let deadline = Instant::now() + Duration::from_secs(2);
        while fixture.active.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
    }
}
