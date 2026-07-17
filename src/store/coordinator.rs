use super::keyring::{Keyring, RandomSource};
use super::{
    AUDIT_EVENTS, AUDIT_HEAD, AUDIT_HEAD_KEY, AuditAuthMethod, AuditEnvelope, AuditError,
    AuditEvent, AuditOperation, AuditStateCommitment, Canonical, CodecError, META, META_KEY,
    MetaRecord, PROVISIONAL_META_KEY, ProvisionalMetaRecord, Sealed, Store, StoreError,
    StoredAuditEntry, audit_key,
};
use crate::clock::WatermarkCommand;
use crate::storage_executor::OverloadSnapshot;
use crate::transaction_coordinator::{AtomicTransaction, Authorization, TransactionFactory};
use redb::{ReadableTable, WriteTransaction};
use std::fmt;
use zeroize::Zeroizing;

pub(crate) enum StoreCoordinatorMutation {
    ClockWatermark {
        command: WatermarkCommand,
        event: AuditEvent,
    },
}

pub(crate) enum StoreCoordinatorRead {
    AuditHead { event: AuditEvent },
    AuditOnly { event: AuditEvent },
}

pub(crate) struct StoreCoordinatorFactory<R> {
    store: Store,
    keyring: Keyring,
    random: R,
}

impl<R> StoreCoordinatorFactory<R> {
    pub(crate) fn new(store: Store, keyring: Keyring, random: R) -> Self {
        Self {
            store,
            keyring,
            random,
        }
    }
}

pub(crate) struct StoreCoordinatorTransaction<'a, R> {
    write: WriteTransaction,
    keyring: &'a Keyring,
    random: &'a mut R,
}

#[derive(Debug)]
pub(crate) enum StoreCoordinatorError {
    Store(StoreError),
    Audit(AuditError),
    Invalid,
}

impl From<StoreError> for StoreCoordinatorError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<AuditError> for StoreCoordinatorError {
    fn from(value: AuditError) -> Self {
        Self::Audit(value)
    }
}

impl From<CodecError> for StoreCoordinatorError {
    fn from(value: CodecError) -> Self {
        Self::Store(StoreError::Codec(value))
    }
}

impl fmt::Display for StoreCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Store(_) => "coordinated store transaction failed",
            Self::Audit(_) => "coordinated audit append failed",
            Self::Invalid => "coordinated transaction rejected",
        })
    }
}

impl std::error::Error for StoreCoordinatorError {}

impl<R: RandomSource + Send + 'static> TransactionFactory for StoreCoordinatorFactory<R> {
    type Mutation = StoreCoordinatorMutation;
    type Read = StoreCoordinatorRead;
    type Audit = AuditEvent;
    type MutationResponse = Zeroizing<Vec<u8>>;
    type ReadResponse = Zeroizing<Vec<u8>>;
    type Error = StoreCoordinatorError;
    type Transaction<'a>
        = StoreCoordinatorTransaction<'a, R>
    where
        Self: 'a;

    fn begin(&mut self) -> Result<Self::Transaction<'_>, Self::Error> {
        Ok(StoreCoordinatorTransaction {
            write: self
                .store
                .database
                .begin_write()
                .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?,
            keyring: &self.keyring,
            random: &mut self.random,
        })
    }
}

impl<R: RandomSource>
    AtomicTransaction<
        StoreCoordinatorMutation,
        StoreCoordinatorRead,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        AuditEvent,
        StoreCoordinatorError,
    > for StoreCoordinatorTransaction<'_, R>
{
    fn authorize_mutation(
        &mut self,
        mutation: &StoreCoordinatorMutation,
    ) -> Result<Authorization<AuditEvent>, StoreCoordinatorError> {
        let StoreCoordinatorMutation::ClockWatermark { event, .. } = mutation;
        if event.operation != AuditOperation::ClockHighWaterCheckpoint
            || event.authentication.method != AuditAuthMethod::None
            || !event.authentication.succeeded
            || !event.authorization.allowed
        {
            return Err(StoreCoordinatorError::Invalid);
        }
        Ok(Authorization::Allowed)
    }

    fn apply_mutation(
        &mut self,
        mutation: StoreCoordinatorMutation,
    ) -> Result<(Zeroizing<Vec<u8>>, AuditEvent), StoreCoordinatorError> {
        match mutation {
            StoreCoordinatorMutation::ClockWatermark { command, event } => {
                self.stage_clock_watermark(&command, &event)?;
                Ok((Zeroizing::new(Vec::new()), event))
            }
        }
    }

    fn authorize_read(
        &mut self,
        read: &StoreCoordinatorRead,
    ) -> Result<Authorization<AuditEvent>, StoreCoordinatorError> {
        let event = match read {
            StoreCoordinatorRead::AuditHead { event }
            | StoreCoordinatorRead::AuditOnly { event } => event,
        };
        let valid_operation = match read {
            StoreCoordinatorRead::AuditHead { .. } => {
                event.operation == AuditOperation::AuditExport
            }
            StoreCoordinatorRead::AuditOnly { .. } => {
                matches!(
                    event.operation,
                    AuditOperation::InitializedStoreRefused | AuditOperation::Shutdown
                ) && event.authentication.method == AuditAuthMethod::None
            }
        };
        if !valid_operation
            || !event.authentication.succeeded
            || !event.authorization.allowed
            || !matches!(event.state, AuditStateCommitment::None)
        {
            return Err(StoreCoordinatorError::Invalid);
        }
        Ok(Authorization::Allowed)
    }

    fn prepare_read(
        &mut self,
        read: StoreCoordinatorRead,
    ) -> Result<(Zeroizing<Vec<u8>>, AuditEvent), StoreCoordinatorError> {
        match read {
            StoreCoordinatorRead::AuditHead { event } => {
                let head = read_head(&self.write)?;
                Ok((Zeroizing::new(head.encode()?), event))
            }
            StoreCoordinatorRead::AuditOnly { event } => Ok((Zeroizing::new(Vec::new()), event)),
        }
    }

    fn append_audit(
        &mut self,
        mut event: AuditEvent,
        overloads: &OverloadSnapshot,
    ) -> Result<(), StoreCoordinatorError> {
        event.attach_overloads(overloads)?;
        let head = read_head(&self.write)?;
        let entry = StoredAuditEntry::prepare(
            self.keyring,
            &event,
            head.audit_epoch,
            head.epoch_sequence
                .checked_add(1)
                .ok_or(StoreCoordinatorError::Invalid)?,
            head.chain_hash()?,
            self.random,
        )?;
        if entry.envelope.effective_timestamp_milliseconds < head.effective_timestamp_milliseconds {
            return Err(StoreCoordinatorError::Invalid);
        }
        let key = audit_key(&entry.envelope);
        let encoded = entry.encode()?;
        let encoded_head = entry.envelope.encode()?;
        {
            let mut events = self
                .write
                .open_table(AUDIT_EVENTS)
                .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?;
            if events
                .get(key.as_slice())
                .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?
                .is_some()
            {
                return Err(StoreCoordinatorError::Invalid);
            }
            events
                .insert(key.as_slice(), encoded.as_slice())
                .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?;
        }
        self.write
            .open_table(AUDIT_HEAD)
            .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?
            .insert(AUDIT_HEAD_KEY, encoded_head.as_slice())
            .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?;
        Ok(())
    }

    fn commit(self) -> Result<(), StoreCoordinatorError> {
        self.write
            .commit()
            .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))
    }
}

impl<R: RandomSource> StoreCoordinatorTransaction<'_, R> {
    fn stage_clock_watermark(
        &self,
        command: &WatermarkCommand,
        event: &AuditEvent,
    ) -> Result<(), StoreCoordinatorError> {
        let mut meta_table = self
            .write
            .open_table(META)
            .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?;
        let current_bytes = meta_table
            .get(META_KEY)
            .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?
            .ok_or(StoreCoordinatorError::Store(StoreError::Uninitialized))?
            .value()
            .to_vec();
        let current = MetaRecord::decode(&current_bytes)?;
        if current.high_water_unix_seconds != command.expected_high_water_unix_seconds
            || command.replacement_high_water_unix_seconds < current.high_water_unix_seconds
            || command.effective_unix_seconds > command.replacement_high_water_unix_seconds
            || event.effective_timestamp_milliseconds
                != command
                    .effective_unix_seconds
                    .checked_mul(1_000)
                    .ok_or(StoreCoordinatorError::Invalid)?
        {
            return Err(StoreCoordinatorError::Invalid);
        }
        let sealed_bytes = meta_table
            .get(PROVISIONAL_META_KEY)
            .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?
            .ok_or(StoreCoordinatorError::Invalid)?
            .value()
            .to_vec();
        let before = Sealed::<ProvisionalMetaRecord>::decode(&sealed_bytes)?;
        before.verify(
            self.keyring.metadata_integrity_key(),
            current.store_id,
            PROVISIONAL_META_KEY,
        )?;
        let mut replacement = current.clone();
        replacement.high_water_unix_seconds = command.replacement_high_water_unix_seconds;
        let after = self.keyring.seal_clear(
            ProvisionalMetaRecord::from_meta(&replacement),
            before
                .generation
                .checked_add(1)
                .ok_or(StoreCoordinatorError::Invalid)?,
            PROVISIONAL_META_KEY,
        )?;
        let expected = super::StateDeltaSet::new([super::StateDelta::replace(
            before.state_tuple(PROVISIONAL_META_KEY)?,
            after.state_tuple(PROVISIONAL_META_KEY)?,
        )?])?;
        if !matches!(&event.state, AuditStateCommitment::Delta(delta) if delta == &expected) {
            return Err(StoreCoordinatorError::Invalid);
        }
        meta_table
            .insert(META_KEY, replacement.encode()?.as_slice())
            .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?;
        meta_table
            .insert(PROVISIONAL_META_KEY, after.encode()?.as_slice())
            .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?;
        Ok(())
    }
}

fn read_head(write: &WriteTransaction) -> Result<AuditEnvelope, StoreCoordinatorError> {
    let table = write
        .open_table(AUDIT_HEAD)
        .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?;
    let bytes = table
        .get(AUDIT_HEAD_KEY)
        .map_err(|_| StoreCoordinatorError::Store(StoreError::Database))?
        .ok_or(StoreCoordinatorError::Invalid)?
        .value()
        .to_vec();
    Ok(AuditEnvelope::decode(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{BootOverrideAudit, BootOverrideAuditError, ClockMonitor, ClockReading};
    use crate::storage_executor::{
        AdmissionLane, OperationClass, OverloadBucket, OverloadCount, OverloadSnapshot,
    };
    use crate::store::keyring::{KeyringError, KeyringOpener, prepare_keyring_for_init};
    use crate::store::{
        AuditAuthentication, AuditAuthorization, AuditCapability, AuditOutcome, AuditReason,
        AuditResource, FORMAT_VERSION, Lifecycle, MetaRecord, StoreId,
    };
    use age::x25519;
    use secrecy::ExposeSecret;
    use std::time::Duration;

    const ACTIVE_IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    struct Counter(u8);

    struct NoAudit;

    impl BootOverrideAudit for NoAudit {
        fn commit_boot_override(
            &mut self,
            _: crate::clock::BootOverrideEvent,
        ) -> Result<(), BootOverrideAuditError> {
            Ok(())
        }
    }

    impl RandomSource for Counter {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
            self.0 = self.0.wrapping_add(1);
            output.fill(self.0);
            Ok(())
        }
    }

    fn event() -> AuditEvent {
        AuditEvent {
            event_id: [31; 16],
            request_id: [32; 16],
            authentication: AuditAuthentication {
                method: AuditAuthMethod::Token,
                identity_id: Some([33; 16]),
                credential_accessor: Some([34; 16]),
                succeeded: true,
                failure_reason: None,
            },
            authorization: AuditAuthorization {
                capability: Some(AuditCapability::AuditRead),
                allowed: true,
                reason: AuditReason::None,
            },
            consumer_instance_id: None,
            resource: Some(AuditResource::Canonical(
                "kv/private/audit-topology-canary".into(),
            )),
            operation: AuditOperation::AuditExport,
            outcome: AuditOutcome::Succeeded,
            reason: AuditReason::None,
            effective_timestamp_milliseconds: 1_800_000_001_001,
            wall_clock_observation_milliseconds: 1_700_000_000_000,
            secret_version: None,
            state: AuditStateCommitment::None,
            previous_epoch_terminal: None,
            flood: None,
            overload_counts: Vec::new(),
        }
    }

    fn system_event(operation: AuditOperation, id: u8, effective: u64) -> AuditEvent {
        AuditEvent {
            event_id: [id; 16],
            request_id: [id.wrapping_add(1); 16],
            authentication: AuditAuthentication {
                method: AuditAuthMethod::None,
                identity_id: None,
                credential_accessor: None,
                succeeded: true,
                failure_reason: None,
            },
            authorization: AuditAuthorization {
                capability: None,
                allowed: true,
                reason: AuditReason::None,
            },
            consumer_instance_id: None,
            resource: None,
            operation,
            outcome: AuditOutcome::Succeeded,
            reason: AuditReason::None,
            effective_timestamp_milliseconds: effective,
            wall_clock_observation_milliseconds: effective,
            secret_version: None,
            state: AuditStateCommitment::None,
            previous_epoch_terminal: None,
            flood: None,
            overload_counts: Vec::new(),
        }
    }

    #[test]
    fn real_redb_factory_commits_overloads_init_refusal_and_shutdown_chain() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.redb");
        let identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
        let meta = MetaRecord {
            store_id: StoreId([7; 16]),
            format_version: FORMAT_VERSION,
            lifecycle: Lifecycle::Ready,
            high_water_unix_seconds: 1_800_000_000,
            pending_anchor: None,
        };
        let mut setup_random = Counter(0);
        let prepared = prepare_keyring_for_init(
            ProvisionalMetaRecord::from_meta(&meta),
            1,
            &identity,
            None,
            &mut setup_random,
        )
        .unwrap();
        let store = Store::create_with_keyring(&path, &meta, &prepared).unwrap();
        let keyring = KeyringOpener::default()
            .open(
                meta.store_id,
                &prepared.envelope,
                &prepared.metadata,
                &identity,
            )
            .unwrap();
        let mut clock = ClockMonitor::boot(
            ClockReading {
                wall_unix_seconds: 1_800_000_000,
                monotonic: Duration::ZERO,
            },
            1_800_000_000,
            false,
            &mut NoAudit,
        )
        .unwrap();
        clock.observe(ClockReading {
            wall_unix_seconds: 1_800_000_001,
            monotonic: Duration::from_secs(1),
        });
        let command = clock.application_commit(Duration::from_secs(1)).unwrap();
        let before = prepared.provisional_meta.as_ref().unwrap();
        let mut replacement = meta.clone();
        replacement.high_water_unix_seconds = 1_800_000_001;
        let after = keyring
            .seal_clear(
                ProvisionalMetaRecord::from_meta(&replacement),
                2,
                PROVISIONAL_META_KEY,
            )
            .unwrap();
        let delta = super::super::StateDeltaSet::new([super::super::StateDelta::replace(
            before.state_tuple(PROVISIONAL_META_KEY).unwrap(),
            after.state_tuple(PROVISIONAL_META_KEY).unwrap(),
        )
        .unwrap()])
        .unwrap();
        let mut clock_event = system_event(
            AuditOperation::ClockHighWaterCheckpoint,
            29,
            1_800_000_001_000,
        );
        clock_event.state = AuditStateCommitment::Delta(delta);
        let mut factory = StoreCoordinatorFactory::new(store, keyring, Counter(40));
        {
            let mut transaction = factory.begin().unwrap();
            let mutation = StoreCoordinatorMutation::ClockWatermark {
                command,
                event: clock_event,
            };
            assert!(matches!(
                transaction.authorize_mutation(&mutation).unwrap(),
                Authorization::Allowed
            ));
            let (_, audit) = transaction.apply_mutation(mutation).unwrap();
            transaction
                .append_audit(audit, &OverloadSnapshot::default())
                .unwrap();
            transaction.commit().unwrap();
        }
        let snapshot = OverloadSnapshot {
            counts: vec![OverloadCount {
                bucket: Some(OverloadBucket {
                    lane: AdmissionLane::Data,
                    operation: OperationClass::DataPlane,
                    class: 7,
                }),
                count: 3,
            }],
        };
        {
            let mut transaction = factory.begin().unwrap();
            transaction.append_audit(event(), &snapshot).unwrap();
            transaction.commit().unwrap();
        }
        for (operation, id, effective) in [
            (
                AuditOperation::InitializedStoreRefused,
                41,
                1_800_000_001_002,
            ),
            (AuditOperation::Shutdown, 43, 1_800_000_001_003),
        ] {
            let mut transaction = factory.begin().unwrap();
            let read = StoreCoordinatorRead::AuditOnly {
                event: system_event(operation, id, effective),
            };
            assert!(matches!(
                transaction.authorize_read(&read).unwrap(),
                Authorization::Allowed
            ));
            let (_, audit) = transaction.prepare_read(read).unwrap();
            transaction
                .append_audit(audit, &OverloadSnapshot::default())
                .unwrap();
            transaction.commit().unwrap();
        }
        drop(factory);

        let file = std::fs::read(&path).unwrap();
        assert!(
            !file
                .windows(b"audit-topology-canary".len())
                .any(|window| window == b"audit-topology-canary")
        );

        let store = Store::open(&path).unwrap();
        let keyring = KeyringOpener::default()
            .open(
                meta.store_id,
                &store.keyring().unwrap().unwrap(),
                &store.keyring_metadata().unwrap().unwrap(),
                &identity,
            )
            .unwrap();
        let entries = store.audit_entries().unwrap();
        assert_eq!(store.meta().unwrap().high_water_unix_seconds, 1_800_000_001);
        assert_eq!(entries.len(), 5);
        assert_eq!(
            entries[1]
                .decrypt(&keyring)
                .unwrap()
                .expose_secret()
                .operation,
            AuditOperation::ClockHighWaterCheckpoint
        );
        let decoded = entries[2].decrypt(&keyring).unwrap();
        assert_eq!(decoded.expose_secret().overload_counts.len(), 1);
        assert_eq!(decoded.expose_secret().overload_counts[0].count, 3);
        assert_eq!(
            entries[3]
                .decrypt(&keyring)
                .unwrap()
                .expose_secret()
                .operation,
            AuditOperation::InitializedStoreRefused
        );
        assert_eq!(
            entries[4]
                .decrypt(&keyring)
                .unwrap()
                .expose_secret()
                .operation,
            AuditOperation::Shutdown
        );
    }
}
