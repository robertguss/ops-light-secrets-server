use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ops_light_secrets_server::storage_executor::{
    CommandState, ExecutionContext, ExecutorConfig, OperationClass, OverloadSnapshot,
    StorageBackend, StorageExecutor, SubmitError,
};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary};
use zeroize::Zeroizing;

const CANARY: &[u8] = b"executor-payload-canary-84e912";

struct Command {
    id: u8,
    encrypted_payload: Zeroizing<Vec<u8>>,
    gate: Option<Arc<(Mutex<bool>, Condvar)>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackendError;

struct Backend {
    executed: Arc<AtomicUsize>,
    operations: Arc<Mutex<Vec<OperationClass>>>,
}

impl StorageBackend<Command, Vec<u8>, BackendError> for Backend {
    fn execute(
        &mut self,
        context: ExecutionContext,
        command: Command,
        _overloads: &OverloadSnapshot,
    ) -> Result<Vec<u8>, BackendError> {
        if let Some(gate) = command.gate {
            let mut open = gate.0.lock().unwrap();
            while !*open {
                open = gate.1.wait(open).unwrap();
            }
        }
        assert!(!command.encrypted_payload.is_empty());
        self.executed.fetch_add(1, Ordering::AcqRel);
        self.operations.lock().unwrap().push(context.operation);
        Ok(vec![command.id])
    }
}

fn command(id: u8) -> Command {
    Command {
        id,
        encrypted_payload: Zeroizing::new(CANARY.to_vec()),
        gate: None,
    }
}

#[tokio::test]
async fn bounded_lanes_emit_safe_observability_and_reject_before_payload_work() {
    let harness = Harness::builder("storage-executor")
        .register_canary(CANARY)
        .build()
        .unwrap();
    let mut scenario = harness.scenario("lane-saturation", 1).unwrap();
    let executed = Arc::new(AtomicUsize::new(0));
    let operations = Arc::new(Mutex::new(Vec::new()));
    let executor = StorageExecutor::start(
        ExecutorConfig {
            data_capacity: 1,
            recovery_capacity: 2,
            recovery_weight: 3,
            overload_buckets: 4,
        },
        Backend {
            executed: Arc::clone(&executed),
            operations: Arc::clone(&operations),
        },
    )
    .unwrap();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let mut first_command = command(1);
    first_command.gate = Some(Arc::clone(&gate));
    let first = executor.submit_data(first_command, 1).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while first.state() != CommandState::Started {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let queued = executor.submit_data(command(2), 1).unwrap();
    assert!(matches!(
        executor.submit_data(command(3), 1),
        Err(SubmitError::Overloaded)
    ));
    assert_eq!(executed.load(Ordering::Acquire), 0);
    let recovery = executor
        .submit_recovery(OperationClass::CredentialRevocation, command(4), 1)
        .unwrap();
    scenario
        .step(
            "pre-decrypt-admission",
            SafeSummary::new(),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();

    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    assert_eq!(first.receive().await.unwrap(), [1]);
    assert_eq!(recovery.receive().await.unwrap(), [4]);
    assert_eq!(queued.receive().await.unwrap(), [2]);
    assert_eq!(executed.load(Ordering::Acquire), 3);
    assert_eq!(
        *operations.lock().unwrap(),
        [
            OperationClass::DataPlane,
            OperationClass::CredentialRevocation,
            OperationClass::DataPlane,
        ]
    );
    scenario
        .step(
            "reserved-lane-progress",
            SafeSummary::new(),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();
    scenario.finish_success().unwrap();
}
