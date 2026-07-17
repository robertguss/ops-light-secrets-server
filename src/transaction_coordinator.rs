//! Single typed commit boundary for state, authorization, audit, and replies.

use std::time::Instant;

use crate::storage_executor::{
    ExecutionContext, ExecutorConfig, ExecutorConfigError, OperationClass, OverloadSnapshot,
    StorageBackend, StorageExecutor, Submission, SubmitError,
};
use crate::store::{StateDeltaSet, WholeStateTransition};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub enum Authorization<A> {
    Allowed,
    Denied(A),
}

enum CoordinatorCommand<M, Q> {
    Mutation {
        value: M,
        commitment: MutationCommitment,
    },
    Read(Q),
}

#[derive(Clone, Copy)]
enum MutationCommitment {
    Delta,
    WholeState,
}

pub trait TransactionAudit: Send + 'static {
    fn state_delta(&self) -> Option<&StateDeltaSet>;
    fn whole_state_transition(&self) -> Option<&WholeStateTransition>;
}

#[derive(Debug)]
pub enum CoordinatorError<E> {
    Backend(E),
    StateCommitment,
}

impl<E> From<E> for CoordinatorError<E> {
    fn from(error: E) -> Self {
        Self::Backend(error)
    }
}

impl<E> std::fmt::Display for CoordinatorError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Backend(_) => "transaction backend failed",
            Self::StateCommitment => "transaction audit state commitment invalid",
        })
    }
}

impl<E: std::fmt::Debug> std::error::Error for CoordinatorError<E> {}

pub enum CoordinatorResponse<M, R> {
    Mutation(M),
    Read(R),
    Denied,
}

impl<M: Zeroize, R: Zeroize> Zeroize for CoordinatorResponse<M, R> {
    fn zeroize(&mut self) {
        match self {
            Self::Mutation(response) => response.zeroize(),
            Self::Read(response) => response.zeroize(),
            Self::Denied => {}
        }
    }
}

pub trait AtomicTransaction<M, Q, MR, RR, A, E>: Sized {
    /// Checks current durable authorization inside this transaction snapshot.
    fn authorize_mutation(&mut self, mutation: &M) -> Result<Authorization<A>, E>;
    /// Applies state only to this uncommitted transaction and returns its audit.
    fn apply_mutation(&mut self, mutation: M) -> Result<(MR, A), E>;
    /// Checks current durable authorization inside this transaction snapshot.
    fn authorize_read(&mut self, read: &Q) -> Result<Authorization<A>, E>;
    /// Decrypts and prepares a bounded response inside this transaction.
    fn prepare_read(&mut self, read: Q) -> Result<(RR, A), E>;
    /// Appends the operation audit and pending bounded overload aggregates.
    fn append_audit(&mut self, audit: A, overloads: &OverloadSnapshot) -> Result<(), E>;
    /// Publishes every staged state and audit change together.
    fn commit(self) -> Result<(), E>;
}

pub trait TransactionFactory: Send + 'static {
    type Mutation: Send + 'static;
    type Read: Send + 'static;
    type Audit: TransactionAudit;
    type MutationResponse: Send + Zeroize + ZeroizeOnDrop + 'static;
    type ReadResponse: Send + Zeroize + ZeroizeOnDrop + 'static;
    type Error: Send + 'static;
    type Transaction<'a>: AtomicTransaction<
            Self::Mutation,
            Self::Read,
            Self::MutationResponse,
            Self::ReadResponse,
            Self::Audit,
            Self::Error,
        >
    where
        Self: 'a;

    fn begin(&mut self) -> Result<Self::Transaction<'_>, Self::Error>;
}

struct CoordinatorBackend<F>(F);

impl<F>
    StorageBackend<
        CoordinatorCommand<F::Mutation, F::Read>,
        CoordinatorResponse<F::MutationResponse, F::ReadResponse>,
        CoordinatorError<F::Error>,
    > for CoordinatorBackend<F>
where
    F: TransactionFactory,
{
    fn execute(
        &mut self,
        _: ExecutionContext,
        command: CoordinatorCommand<F::Mutation, F::Read>,
        overloads: &OverloadSnapshot,
    ) -> Result<CoordinatorResponse<F::MutationResponse, F::ReadResponse>, CoordinatorError<F::Error>>
    {
        let mut transaction = self.0.begin()?;
        match command {
            CoordinatorCommand::Mutation { value, commitment } => {
                match transaction.authorize_mutation(&value)? {
                    Authorization::Allowed => {}
                    Authorization::Denied(audit) => {
                        validate_no_state_commitment(&audit)?;
                        transaction.append_audit(audit, overloads)?;
                        transaction.commit()?;
                        return Ok(CoordinatorResponse::Denied);
                    }
                }
                let (response, audit) = transaction.apply_mutation(value)?;
                validate_mutation_commitment(&audit, commitment)?;
                transaction.append_audit(audit, overloads)?;
                transaction.commit()?;
                Ok(CoordinatorResponse::Mutation(response))
            }
            CoordinatorCommand::Read(read) => {
                match transaction.authorize_read(&read)? {
                    Authorization::Allowed => {}
                    Authorization::Denied(audit) => {
                        validate_no_state_commitment(&audit)?;
                        transaction.append_audit(audit, overloads)?;
                        transaction.commit()?;
                        return Ok(CoordinatorResponse::Denied);
                    }
                }
                let (response, audit) = transaction.prepare_read(read)?;
                validate_no_state_commitment(&audit)?;
                transaction.append_audit(audit, overloads)?;
                transaction.commit()?;
                Ok(CoordinatorResponse::Read(response))
            }
        }
    }
}

pub type CoordinatorSubmission<F> = Submission<
    CoordinatorResponse<
        <F as TransactionFactory>::MutationResponse,
        <F as TransactionFactory>::ReadResponse,
    >,
    CoordinatorError<<F as TransactionFactory>::Error>,
>;

type CoordinatorExecutor<F> = StorageExecutor<
    CoordinatorCommand<<F as TransactionFactory>::Mutation, <F as TransactionFactory>::Read>,
    CoordinatorResponse<
        <F as TransactionFactory>::MutationResponse,
        <F as TransactionFactory>::ReadResponse,
    >,
    CoordinatorError<<F as TransactionFactory>::Error>,
>;

/// Handler-facing service. It intentionally exposes no backend or transaction.
///
/// ```compile_fail
/// use ops_light_secrets_server::transaction_coordinator::{CoordinatorService, TransactionFactory};
/// fn leak<F: TransactionFactory>(service: &CoordinatorService<F>) {
///     let _ = &service.executor;
/// }
/// ```
///
/// ```compile_fail
/// use ops_light_secrets_server::store::Store;
/// fn leak_database(store: &Store) {
///     let _ = &store.database;
/// }
/// ```
pub struct CoordinatorService<F: TransactionFactory> {
    executor: CoordinatorExecutor<F>,
}

impl<F: TransactionFactory> CoordinatorService<F> {
    pub fn start(config: ExecutorConfig, factory: F) -> Result<Self, ExecutorConfigError> {
        Ok(Self {
            executor: StorageExecutor::start(config, CoordinatorBackend(factory))?,
        })
    }

    pub fn submit_data_mutation(
        &self,
        mutation: F::Mutation,
        class: u16,
    ) -> Result<CoordinatorSubmission<F>, SubmitError> {
        self.executor.submit_data(
            CoordinatorCommand::Mutation {
                value: mutation,
                commitment: MutationCommitment::Delta,
            },
            class,
        )
    }

    pub fn submit_recovery_mutation(
        &self,
        operation: OperationClass,
        mutation: F::Mutation,
        class: u16,
    ) -> Result<CoordinatorSubmission<F>, SubmitError> {
        self.executor.submit_recovery(
            operation,
            CoordinatorCommand::Mutation {
                value: mutation,
                commitment: MutationCommitment::Delta,
            },
            class,
        )
    }

    pub fn submit_bulk_mutation(
        &self,
        operation: OperationClass,
        mutation: F::Mutation,
        class: u16,
    ) -> Result<CoordinatorSubmission<F>, SubmitError> {
        self.executor.submit_recovery(
            operation,
            CoordinatorCommand::Mutation {
                value: mutation,
                commitment: MutationCommitment::WholeState,
            },
            class,
        )
    }

    pub fn submit_read(
        &self,
        read: F::Read,
        class: u16,
    ) -> Result<CoordinatorSubmission<F>, SubmitError> {
        self.executor
            .submit_data(CoordinatorCommand::Read(read), class)
    }

    pub fn submit_clock_watermark(
        &self,
        mutation: F::Mutation,
        class: u16,
        deadline: Instant,
    ) -> Result<CoordinatorSubmission<F>, SubmitError> {
        self.executor.submit_clock_watermark(
            CoordinatorCommand::Mutation {
                value: mutation,
                commitment: MutationCommitment::Delta,
            },
            class,
            deadline,
        )
    }

    pub fn poll_clock_watermark_deadline(&self, now: Instant) -> Result<(), SubmitError> {
        self.executor.poll_clock_watermark_deadline(now)
    }

    pub fn is_healthy(&self) -> bool {
        self.executor.is_healthy()
    }
}

fn validate_mutation_commitment<A: TransactionAudit, E>(
    audit: &A,
    required: MutationCommitment,
) -> Result<(), CoordinatorError<E>> {
    let valid = match required {
        MutationCommitment::Delta => {
            audit.state_delta().is_some() && audit.whole_state_transition().is_none()
        }
        MutationCommitment::WholeState => {
            audit.state_delta().is_none() && audit.whole_state_transition().is_some()
        }
    };
    valid.then_some(()).ok_or(CoordinatorError::StateCommitment)
}

fn validate_no_state_commitment<A: TransactionAudit, E>(
    audit: &A,
) -> Result<(), CoordinatorError<E>> {
    (audit.state_delta().is_none() && audit.whole_state_transition().is_none())
        .then_some(())
        .ok_or(CoordinatorError::StateCommitment)
}
