use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ops_light_secrets_server::storage_executor::{ExecutorConfig, OperationClass};
use ops_light_secrets_server::store::{
    BulkTransitionKind, EncryptedTable, StateDelta, StateDeltaSet, StateDigest, StateTuple,
    WholeStateTransition,
};
use ops_light_secrets_server::transaction_coordinator::{
    AtomicTransaction, Authorization, CoordinatorError, CoordinatorResponse, CoordinatorService,
    TransactionAudit, TransactionFactory,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy)]
enum Mutation {
    SetValue(u8),
    Disable,
    Bulk(u8),
    MissingCommitment(u8),
}

struct Read {
    gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    start_probe: Option<Arc<AtomicBool>>,
}

struct Audit {
    label: &'static str,
    delta: Option<StateDeltaSet>,
    whole_state: Option<WholeStateTransition>,
}

impl TransactionAudit for Audit {
    fn state_delta(&self) -> Option<&StateDeltaSet> {
        self.delta.as_ref()
    }

    fn whole_state_transition(&self) -> Option<&WholeStateTransition> {
        self.whole_state.as_ref()
    }
}

fn audit_without_state(label: &'static str) -> Audit {
    Audit {
        label,
        delta: None,
        whole_state: None,
    }
}

fn audit_with_delta(label: &'static str, value: u8) -> Audit {
    let tuple = StateTuple::encrypted(EncryptedTable::Secrets, b"secret/1", &[value]).unwrap();
    Audit {
        label,
        delta: Some(StateDeltaSet::new([StateDelta::insert(tuple)]).unwrap()),
        whole_state: None,
    }
}

fn audit_with_whole_state(label: &'static str) -> Audit {
    Audit {
        label,
        delta: None,
        whole_state: Some(WholeStateTransition {
            kind: BulkTransitionKind::RecordRewrite,
            operation_id: b"bulk-1".to_vec(),
            before: StateDigest([1; 32]),
            after: StateDigest([2; 32]),
        }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Error {
    Injected,
}

#[repr(u8)]
enum Fault {
    None = 0,
    AfterState = 1,
    AfterAudit = 2,
    Commit = 3,
    PanicAfterPrepare = 4,
    Serialization = 5,
}

struct Reply {
    value: Vec<u8>,
    zeroized: Arc<AtomicBool>,
}

impl Zeroize for Reply {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.zeroized.store(true, Ordering::Release);
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Reply {}

#[derive(Clone, Default)]
struct Visible {
    value: u8,
    enabled: bool,
    audits: Vec<&'static str>,
}

struct Factory {
    visible: Arc<Mutex<Visible>>,
    fault: Arc<AtomicU8>,
    response_zeroized: Arc<AtomicBool>,
    read_started: Arc<AtomicBool>,
}

struct Transaction {
    visible: Arc<Mutex<Visible>>,
    pending: Visible,
    fault: Arc<AtomicU8>,
    response_zeroized: Arc<AtomicBool>,
    read_started: Arc<AtomicBool>,
}

impl TransactionFactory for Factory {
    type Mutation = Mutation;
    type Read = Read;
    type Audit = Audit;
    type MutationResponse = Reply;
    type ReadResponse = Reply;
    type Error = Error;
    type Transaction<'a> = Transaction;

    fn begin(&mut self) -> Result<Self::Transaction<'_>, Self::Error> {
        Ok(Transaction {
            visible: Arc::clone(&self.visible),
            pending: self.visible.lock().unwrap().clone(),
            fault: Arc::clone(&self.fault),
            response_zeroized: Arc::clone(&self.response_zeroized),
            read_started: Arc::clone(&self.read_started),
        })
    }
}

impl AtomicTransaction<Mutation, Read, Reply, Reply, Audit, Error> for Transaction {
    fn authorize_mutation(&mut self, _: &Mutation) -> Result<Authorization<Audit>, Error> {
        Ok(Authorization::Allowed)
    }

    fn apply_mutation(&mut self, mutation: Mutation) -> Result<(Reply, Audit), Error> {
        let audit = match mutation {
            Mutation::SetValue(value) => {
                self.pending.value = value;
                audit_with_delta("mutation", value)
            }
            Mutation::Disable => {
                self.pending.enabled = false;
                audit_with_delta("mutation", self.pending.value)
            }
            Mutation::Bulk(value) => {
                self.pending.value = value;
                audit_with_whole_state("bulk-mutation")
            }
            Mutation::MissingCommitment(value) => {
                self.pending.value = value;
                audit_without_state("invalid-mutation")
            }
        };
        if self.fault.load(Ordering::Acquire) == Fault::AfterState as u8 {
            return Err(Error::Injected);
        }
        Ok((
            Reply {
                value: vec![self.pending.value],
                zeroized: Arc::clone(&self.response_zeroized),
            },
            audit,
        ))
    }

    fn authorize_read(&mut self, read: &Read) -> Result<Authorization<Audit>, Error> {
        self.read_started.store(true, Ordering::Release);
        if let Some(probe) = &read.start_probe {
            probe.store(true, Ordering::Release);
        }
        Ok(if self.pending.enabled {
            Authorization::Allowed
        } else {
            Authorization::Denied(audit_without_state("read-denied"))
        })
    }

    fn prepare_read(&mut self, read: Read) -> Result<(Reply, Audit), Error> {
        if let Some(gate) = read.gate {
            let mut open = gate.0.lock().unwrap();
            while !*open {
                open = gate.1.wait(open).unwrap();
            }
        }
        let response = Reply {
            value: vec![self.pending.value],
            zeroized: Arc::clone(&self.response_zeroized),
        };
        if self.fault.load(Ordering::Acquire) == Fault::Serialization as u8 {
            return Err(Error::Injected);
        }
        Ok((response, audit_without_state("read-served-version-1")))
    }

    fn append_audit(
        &mut self,
        audit: Audit,
        _: &ops_light_secrets_server::storage_executor::OverloadSnapshot,
    ) -> Result<(), Error> {
        self.pending.audits.push(audit.label);
        if self.fault.load(Ordering::Acquire) == Fault::PanicAfterPrepare as u8 {
            panic!("injected coordinator panic after response preparation");
        }
        if self.fault.load(Ordering::Acquire) == Fault::AfterAudit as u8 {
            return Err(Error::Injected);
        }
        Ok(())
    }

    fn commit(self) -> Result<(), Error> {
        if self.fault.load(Ordering::Acquire) == Fault::Commit as u8 {
            return Err(Error::Injected);
        }
        *self.visible.lock().unwrap() = self.pending;
        Ok(())
    }
}

struct Fixture {
    service: CoordinatorService<Factory>,
    visible: Arc<Mutex<Visible>>,
    fault: Arc<AtomicU8>,
    zeroized: Arc<AtomicBool>,
    read_started: Arc<AtomicBool>,
}

fn fixture() -> Fixture {
    let visible = Arc::new(Mutex::new(Visible {
        value: 1,
        enabled: true,
        audits: Vec::new(),
    }));
    let fault = Arc::new(AtomicU8::new(Fault::None as u8));
    let zeroized = Arc::new(AtomicBool::new(false));
    let read_started = Arc::new(AtomicBool::new(false));
    let service = CoordinatorService::start(
        ExecutorConfig::default(),
        Factory {
            visible: Arc::clone(&visible),
            fault: Arc::clone(&fault),
            response_zeroized: Arc::clone(&zeroized),
            read_started: Arc::clone(&read_started),
        },
    )
    .unwrap();
    Fixture {
        service,
        visible,
        fault,
        zeroized,
        read_started,
    }
}

#[tokio::test]
async fn mutation_and_audit_are_one_visibility_boundary_at_every_fault() {
    for injected in [Fault::AfterState, Fault::AfterAudit, Fault::Commit] {
        let fixture = fixture();
        fixture.fault.store(injected as u8, Ordering::Release);
        let submission = fixture
            .service
            .submit_data_mutation(Mutation::SetValue(9), 1)
            .unwrap();
        assert!(submission.receive().await.is_err());
        let visible = fixture.visible.lock().unwrap();
        assert_eq!(visible.value, 1);
        assert!(visible.audits.is_empty());
    }
}

#[tokio::test]
async fn mutation_routes_enforce_the_required_state_commitment_shape() {
    let fixture = fixture();
    let missing = fixture
        .service
        .submit_data_mutation(Mutation::MissingCommitment(9), 1)
        .unwrap()
        .receive()
        .await;
    assert!(matches!(
        missing,
        Err(
            ops_light_secrets_server::storage_executor::ReceiveError::Backend(
                CoordinatorError::StateCommitment
            )
        )
    ));
    {
        let visible = fixture.visible.lock().unwrap();
        assert_eq!(visible.value, 1);
        assert!(visible.audits.is_empty());
    }

    let response = fixture
        .service
        .submit_bulk_mutation(OperationClass::Checkpoint, Mutation::Bulk(9), 1)
        .unwrap()
        .receive()
        .await
        .unwrap();
    assert!(matches!(response, CoordinatorResponse::Mutation(_)));
    let visible = fixture.visible.lock().unwrap();
    assert_eq!(visible.value, 9);
    assert_eq!(visible.audits, ["bulk-mutation"]);
}

#[tokio::test]
async fn read_secret_is_not_released_when_audit_or_commit_fails() {
    for injected in [Fault::AfterAudit, Fault::Commit] {
        let fixture = fixture();
        fixture.fault.store(injected as u8, Ordering::Release);
        let submission = fixture
            .service
            .submit_read(
                Read {
                    gate: None,
                    start_probe: None,
                },
                2,
            )
            .unwrap();
        assert!(submission.receive().await.is_err());
        assert!(fixture.zeroized.load(Ordering::Acquire));
        assert!(fixture.visible.lock().unwrap().audits.is_empty());
    }
}

#[tokio::test]
async fn committed_read_is_audited_before_reply_and_receiver_loss_zeroizes() {
    let fixture = fixture();
    let response = fixture
        .service
        .submit_read(
            Read {
                gate: None,
                start_probe: None,
            },
            2,
        )
        .unwrap()
        .receive()
        .await
        .unwrap();
    let CoordinatorResponse::Read(reply) = response else {
        panic!("read response expected");
    };
    assert_eq!(reply.value, [1]);
    assert_eq!(
        fixture.visible.lock().unwrap().audits,
        ["read-served-version-1"]
    );
    drop(reply);
    assert!(fixture.zeroized.load(Ordering::Acquire));
}

#[tokio::test]
async fn caller_disconnect_after_prepare_commits_audit_and_zeroizes_unsent_reply() {
    let fixture = fixture();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let submission = fixture
        .service
        .submit_read(
            Read {
                gate: Some(Arc::clone(&gate)),
                start_probe: None,
            },
            2,
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !fixture.read_started.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    drop(submission);
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    while !fixture.zeroized.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(
        fixture.visible.lock().unwrap().audits,
        ["read-served-version-1"]
    );
}

#[tokio::test]
async fn pre_start_cancellation_never_authorizes_decrypts_or_audits() {
    let fixture = fixture();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let first = fixture
        .service
        .submit_read(
            Read {
                gate: Some(Arc::clone(&gate)),
                start_probe: None,
            },
            2,
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !fixture.read_started.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let cancelled_started = Arc::new(AtomicBool::new(false));
    let cancelled = fixture
        .service
        .submit_read(
            Read {
                gate: None,
                start_probe: Some(Arc::clone(&cancelled_started)),
            },
            2,
        )
        .unwrap();
    drop(cancelled);
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    assert!(matches!(
        first.receive().await.unwrap(),
        CoordinatorResponse::Read(_)
    ));
    assert!(!cancelled_started.load(Ordering::Acquire));
    assert_eq!(
        fixture.visible.lock().unwrap().audits,
        ["read-served-version-1"]
    );
}

#[tokio::test]
async fn serialization_failure_releases_no_reply_and_zeroizes_prepared_bytes() {
    let fixture = fixture();
    fixture
        .fault
        .store(Fault::Serialization as u8, Ordering::Release);
    let submission = fixture
        .service
        .submit_read(
            Read {
                gate: None,
                start_probe: None,
            },
            2,
        )
        .unwrap();
    assert!(submission.receive().await.is_err());
    assert!(fixture.zeroized.load(Ordering::Acquire));
    assert!(fixture.visible.lock().unwrap().audits.is_empty());
}

#[tokio::test]
async fn panic_after_prepare_rolls_back_and_zeroizes_response() {
    let fixture = fixture();
    fixture
        .fault
        .store(Fault::PanicAfterPrepare as u8, Ordering::Release);
    let submission = fixture
        .service
        .submit_read(
            Read {
                gate: None,
                start_probe: None,
            },
            2,
        )
        .unwrap();
    assert!(submission.receive().await.is_err());
    assert!(fixture.zeroized.load(Ordering::Acquire));
    assert!(fixture.visible.lock().unwrap().audits.is_empty());
    let deadline = Instant::now() + Duration::from_secs(2);
    while fixture.service.is_healthy() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(!fixture.service.is_healthy());
}

#[tokio::test]
async fn disable_commit_linearizes_before_a_queued_authorization_start() {
    let fixture = fixture();
    let disable = fixture
        .service
        .submit_recovery_mutation(OperationClass::IdentityDisable, Mutation::Disable, 3)
        .unwrap();
    assert!(matches!(
        disable.receive().await.unwrap(),
        CoordinatorResponse::Mutation(_)
    ));
    let read = fixture
        .service
        .submit_read(
            Read {
                gate: None,
                start_probe: None,
            },
            2,
        )
        .unwrap();
    assert!(matches!(
        read.receive().await.unwrap(),
        CoordinatorResponse::Denied
    ));
    assert_eq!(
        fixture.visible.lock().unwrap().audits,
        ["mutation", "read-denied"]
    );
}

#[tokio::test]
async fn clock_watermark_uses_reserved_deadline_submission_and_atomic_audit() {
    let fixture = fixture();
    let response = fixture
        .service
        .submit_clock_watermark(
            Mutation::SetValue(8),
            4,
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap()
        .receive()
        .await
        .unwrap();
    assert!(matches!(response, CoordinatorResponse::Mutation(_)));
    let visible = fixture.visible.lock().unwrap();
    assert_eq!(visible.value, 8);
    assert_eq!(visible.audits, ["mutation"]);
    drop(visible);
    assert!(
        fixture
            .service
            .poll_clock_watermark_deadline(Instant::now())
            .is_ok()
    );
}

#[tokio::test]
async fn already_authorized_read_may_finish_before_later_disable() {
    let fixture = fixture();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let read = fixture
        .service
        .submit_read(
            Read {
                gate: Some(Arc::clone(&gate)),
                start_probe: None,
            },
            2,
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !fixture.read_started.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let disable = fixture
        .service
        .submit_recovery_mutation(OperationClass::IdentityDisable, Mutation::Disable, 3)
        .unwrap();
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    assert!(matches!(
        read.receive().await.unwrap(),
        CoordinatorResponse::Read(_)
    ));
    assert!(matches!(
        disable.receive().await.unwrap(),
        CoordinatorResponse::Mutation(_)
    ));
    assert_eq!(
        fixture.visible.lock().unwrap().audits,
        ["read-served-version-1", "mutation"]
    );
}
