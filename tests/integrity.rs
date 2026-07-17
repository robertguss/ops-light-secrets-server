use std::collections::{BTreeMap, BTreeSet};
use std::io;

use ops_light_secrets_server::config::{SecretInput, SecretSource};
use ops_light_secrets_server::init::prepare_keyring_init_from_source;
use ops_light_secrets_server::startup::{KeyringBootError, open_store_keyring};
use ops_light_secrets_server::store::keyring::{KeyringError, KeyringOpener, RandomSource};
use ops_light_secrets_server::store::{
    BulkTransitionKind, Canonical, ClearRecord, CodecError, EncryptedTable, FORMAT_VERSION,
    IntegrityOperation, IntegrityStatus, Lifecycle, LogicalPath, MAC_FORMAT_VERSION, MetaRecord,
    RecordClass, RotationState, Sealed, SecretKey, SecretMetadata, SecretRecord, StateDelta,
    StateDeltaSet, StateDigest, StateTuple, Store, StoreError, StoreId, VersionSetSummary,
    WholeStateTransition, mac_conformance,
};

const MAC_KEY: [u8; 32] = [0x42; 32];
const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

struct IdentityInput(Vec<u8>);

impl SecretInput for IdentityInput {
    fn read_stdin(&mut self) -> io::Result<Vec<u8>> {
        Ok(std::mem::take(&mut self.0))
    }

    fn read_file_descriptor(&mut self, _: u32) -> io::Result<Vec<u8>> {
        unreachable!()
    }

    fn read_credential(&mut self, _: &str) -> io::Result<Vec<u8>> {
        unreachable!()
    }

    fn read_tty(&mut self) -> io::Result<Vec<u8>> {
        unreachable!()
    }

    fn read_environment(&mut self, _: &str) -> io::Result<Vec<u8>> {
        unreachable!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GrantFixture {
    generation: u64,
    capability: u8,
}

impl Canonical for GrantFixture {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        Ok([
            1_u16.to_be_bytes().as_slice(),
            self.generation.to_be_bytes().as_slice(),
            &[self.capability],
        ]
        .concat())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != 11 || bytes[..2] != 1_u16.to_be_bytes() {
            return Err(CodecError::Invalid);
        }
        Ok(Self {
            generation: u64::from_be_bytes(bytes[2..10].try_into().unwrap()),
            capability: bytes[10],
        })
    }
}

impl ClearRecord for GrantFixture {
    const CLASS: RecordClass = RecordClass::Grant;
    const SCHEMA_VERSION: u16 = 1;
}

fn meta() -> MetaRecord {
    MetaRecord {
        store_id: StoreId([7; 16]),
        format_version: FORMAT_VERSION,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: 1_800_000_000,
        pending_anchor: None,
    }
}

fn metadata() -> SecretMetadata {
    SecretMetadata {
        schema_version: 1,
        custom: BTreeMap::new(),
        max_versions: 10,
        cas_required: false,
        last_completed_rotation_unix_seconds: None,
        rotation_interval_seconds: None,
        rotation_state: RotationState::Idle,
        rotation_protection: None,
        versions: VersionSetSummary::empty(),
    }
}

#[test]
fn registry_is_closed_unique_and_conformance_covers_every_negative() {
    assert_eq!(MAC_FORMAT_VERSION, 1);
    let classes = RecordClass::ALL;
    assert!(classes.len() >= 12);
    assert_eq!(
        classes
            .iter()
            .map(|class| class.code())
            .collect::<BTreeSet<_>>()
            .len(),
        classes.len()
    );
    assert_eq!(
        classes
            .iter()
            .map(|class| class.domain())
            .collect::<BTreeSet<_>>()
            .len(),
        classes.len()
    );

    let report = mac_conformance(
        &GrantFixture {
            generation: 5,
            capability: 1,
        },
        &GrantFixture {
            generation: 5,
            capability: 2,
        },
        5,
        &MAC_KEY,
        StoreId([7; 16]),
        b"grant/canary-name-do-not-log",
    )
    .unwrap();
    assert!(report.passed());
    assert!(report.edit_rejected);
    assert!(report.primary_key_transplant_rejected);
    assert!(report.store_transplant_rejected);
    assert!(report.generation_regression_rejected);
    assert!(report.wrong_class_rejected);
    assert!(report.wrong_schema_rejected);
    assert!(report.unknown_mac_version_rejected);
    assert!(report.trailing_bytes_rejected);
    assert!(report.truncated_tag_rejected);
    assert_eq!(report.comparison_work_bytes, 32);
}

#[test]
fn runtime_tamper_flips_readiness_and_only_recovery_matrix_remains() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let store = Store::create(&path, &meta()).unwrap();
    let logical = LogicalPath::new("mount/canary-secret-name").unwrap();
    let sealed = metadata()
        .seal(&MAC_KEY, meta().store_id, &logical)
        .unwrap();
    store
        .put_secret_metadata(&logical, &sealed, &MAC_KEY)
        .unwrap();
    drop(store);

    let database = redb::Database::open(&path).unwrap();
    let write = database.begin_write().unwrap();
    {
        use redb::{ReadableTable, TableDefinition};
        let table_definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new("secret_meta");
        let mut table = write.open_table(table_definition).unwrap();
        let key = logical.encode().unwrap();
        let mut bytes = table.get(key.as_slice()).unwrap().unwrap().value().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        table.insert(key.as_slice(), bytes.as_slice()).unwrap();
    }
    write.commit().unwrap();
    drop(database);

    let store = Store::open(&path).unwrap();
    assert_eq!(
        store.secret_metadata(&logical, &MAC_KEY).unwrap_err(),
        StoreError::Integrity
    );
    let IntegrityStatus::Failed(diagnostic) = store.integrity_status() else {
        panic!("integrity failure must be sticky");
    };
    assert_eq!(diagnostic.code, "clear_record_integrity_failure");
    assert_eq!(diagnostic.table, "secret_meta");
    assert_eq!(diagnostic.masked_key_id.len(), 16);
    let rendered = format!("{diagnostic:?} {diagnostic}");
    assert!(!rendered.contains("canary-secret-name"));

    for operation in [
        IntegrityOperation::Data,
        IntegrityOperation::ManagementMutation,
        IntegrityOperation::BulkMutation,
    ] {
        assert!(!store.integrity_operation_allowed(operation));
    }
    for operation in [
        IntegrityOperation::Diagnostics,
        IntegrityOperation::ReadOnlyRecovery,
        IntegrityOperation::OrderlyShutdown,
        IntegrityOperation::OfflineRestoreRepair,
    ] {
        assert!(store.integrity_operation_allowed(operation));
    }
    let record = SecretRecord {
        version: 1,
        created_unix_milliseconds: 1,
        key_id: [3; 16],
        nonce: [4; 24],
        ciphertext: vec![5; 16],
    };
    assert_eq!(
        store
            .put_secret(
                &SecretKey {
                    path: logical,
                    version: 1,
                },
                &record,
            )
            .unwrap_err(),
        StoreError::Integrity
    );
}

#[test]
fn provisional_meta_is_reverified_immediately_after_keyring_open() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let mut init_input = IdentityInput(ACTIVE_IDENTITY.as_bytes().to_vec());
    let transaction = prepare_keyring_init_from_source(
        meta(),
        &SecretSource::Stdin,
        &mut init_input,
        None,
        &mut Counter(0),
    )
    .unwrap();
    drop(transaction.commit(&path).unwrap());

    let store = Store::open(&path).unwrap();
    let mut first_boot_input = IdentityInput(ACTIVE_IDENTITY.as_bytes().to_vec());
    let keyring = open_store_keyring(
        &store,
        &SecretSource::Stdin,
        &mut first_boot_input,
        &KeyringOpener::default(),
    )
    .unwrap();
    let expected = store.meta().unwrap();
    let mut authenticated = expected.clone();
    authenticated.high_water_unix_seconds += 1;
    assert_eq!(
        store.set_meta(&expected, &authenticated).unwrap_err(),
        StoreError::Integrity
    );
    keyring
        .set_meta_authenticated(&store, &expected, &authenticated)
        .unwrap();
    drop(store);

    let store = Store::open(&path).unwrap();
    let mut second_boot_input = IdentityInput(ACTIVE_IDENTITY.as_bytes().to_vec());
    open_store_keyring(
        &store,
        &SecretSource::Stdin,
        &mut second_boot_input,
        &KeyringOpener::default(),
    )
    .unwrap();
    drop(store);

    let mut edited = authenticated;
    edited.high_water_unix_seconds += 1;
    let database = redb::Database::open(&path).unwrap();
    let write = database.begin_write().unwrap();
    {
        use redb::TableDefinition;
        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new("meta");
        let mut table = write.open_table(definition).unwrap();
        table
            .insert(b"\x01store".as_slice(), edited.encode().unwrap().as_slice())
            .unwrap();
    }
    write.commit().unwrap();
    drop(database);

    let store = Store::open(&path).unwrap();
    let mut boot_input = IdentityInput(ACTIVE_IDENTITY.as_bytes().to_vec());
    assert_eq!(
        open_store_keyring(
            &store,
            &SecretSource::Stdin,
            &mut boot_input,
            &KeyringOpener::default(),
        )
        .err()
        .unwrap(),
        KeyringBootError::Integrity
    );
    let IntegrityStatus::Failed(diagnostic) = store.integrity_status() else {
        panic!("provisional failure must make readiness false");
    };
    assert_eq!(diagnostic.table, "meta");
}

#[test]
fn keyring_metadata_mac_failure_flips_readiness_after_single_decrypt() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let mut init_input = IdentityInput(ACTIVE_IDENTITY.as_bytes().to_vec());
    let transaction = prepare_keyring_init_from_source(
        meta(),
        &SecretSource::Stdin,
        &mut init_input,
        None,
        &mut Counter(0),
    )
    .unwrap();
    drop(transaction.commit(&path).unwrap());

    let database = redb::Database::open(&path).unwrap();
    let write = database.begin_write().unwrap();
    {
        use redb::{ReadableTable, TableDefinition};
        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new("meta");
        let mut table = write.open_table(definition).unwrap();
        let key = b"\x01keyring_metadata";
        let mut bytes = table.get(key.as_slice()).unwrap().unwrap().value().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        table.insert(key.as_slice(), bytes.as_slice()).unwrap();
    }
    write.commit().unwrap();
    drop(database);

    let store = Store::open(&path).unwrap();
    let opener = KeyringOpener::default();
    let mut boot_input = IdentityInput(ACTIVE_IDENTITY.as_bytes().to_vec());
    assert_eq!(
        open_store_keyring(&store, &SecretSource::Stdin, &mut boot_input, &opener,)
            .err()
            .unwrap(),
        KeyringBootError::Keyring(KeyringError::MetadataIntegrity)
    );
    assert_eq!(opener.attempts(), 1);
    let IntegrityStatus::Failed(diagnostic) = store.integrity_status() else {
        panic!("keyring metadata failure must make readiness false");
    };
    assert_eq!(diagnostic.table, "meta");
    assert_eq!(diagnostic.masked_key_id.len(), 16);
}

#[test]
fn digest_covers_clear_and_encrypted_rows_and_reverse_delta_reconstructs_checkpoint() {
    let grant = Sealed::seal(
        GrantFixture {
            generation: 5,
            capability: 1,
        },
        5,
        &MAC_KEY,
        StoreId([7; 16]),
        b"grant/1",
    )
    .unwrap();
    let clear = grant.state_tuple(b"grant/1").unwrap();
    let encrypted = StateTuple::encrypted(
        EncryptedTable::Secrets,
        b"secret/1/version/1",
        b"canonical-header-and-nonce-and-ciphertext",
    )
    .unwrap();
    let checkpoint = StateDigest::compute([clear.clone(), encrypted.clone()]).unwrap();
    assert_eq!(
        checkpoint,
        StateDigest::compute([encrypted.clone(), clear.clone()]).unwrap()
    );
    assert_ne!(checkpoint, StateDigest::compute([clear.clone()]).unwrap());

    let newer = Sealed::seal(
        GrantFixture {
            generation: 6,
            capability: 2,
        },
        6,
        &MAC_KEY,
        StoreId([7; 16]),
        b"grant/1",
    )
    .unwrap()
    .state_tuple(b"grant/1")
    .unwrap();
    assert_ne!(
        checkpoint,
        StateDigest::compute([newer.clone(), encrypted.clone()]).unwrap()
    );

    let deltas = StateDeltaSet::new(vec![
        StateDelta::replace(clear.clone(), newer.clone()).unwrap(),
        StateDelta::delete(encrypted.clone()),
    ])
    .unwrap();
    let encoded_deltas = deltas.encode().unwrap();
    assert_eq!(StateDeltaSet::decode(&encoded_deltas).unwrap(), deltas);
    let mut trailing = encoded_deltas.clone();
    trailing.push(0);
    assert_eq!(StateDeltaSet::decode(&trailing), Err(CodecError::Trailing));
    let current = BTreeSet::from([newer]);
    let reconstructed = deltas.reverse_apply(&current).unwrap();
    assert_eq!(reconstructed, BTreeSet::from([clear, encrypted]));
    assert_eq!(StateDigest::compute(reconstructed).unwrap(), checkpoint);

    let transition = WholeStateTransition {
        kind: BulkTransitionKind::MetadataRemac,
        operation_id: b"metadata-key-job-1".to_vec(),
        before: checkpoint,
        after: StateDigest::compute(current).unwrap(),
    };
    assert_eq!(
        WholeStateTransition::decode(&transition.encode().unwrap()).unwrap(),
        transition
    );
}
