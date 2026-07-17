//! Immutable-id secret rotation lifecycle and CAS-coupled KV primitives.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::control::management::{
    ControlCommand, MANAGEMENT_OUTPUT_SCHEMA, MAX_PAGE_SIZE, ManagementCatalog, ManagementError,
    ManagementPrincipal, Page,
};
use crate::kv::{KvError, KvService};
use crate::raw_target::{EndpointKind, EndpointRequest, Resource};
use crate::store::{
    Canonical, ClearRecord, CodecError, Decoder, Encoder, RecordClass, Sealed, StoreId,
};

const MAX_IDS: usize = 10_000;
const MAX_RESOURCE: usize = 1024;
const MAX_HISTORY: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RotationLifecycle {
    Prepared = 1,
    Cutover = 2,
    Completed = 3,
    CancelledBeforeCutover = 4,
    Superseded = 5,
}

impl RotationLifecycle {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Cutover),
            3 => Ok(Self::Completed),
            4 => Ok(Self::CancelledBeforeCutover),
            5 => Ok(Self::Superseded),
            _ => Err(CodecError::Invalid),
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::CancelledBeforeCutover | Self::Superseded
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationTransition {
    pub state: RotationLifecycle,
    pub effective_unix_seconds: u64,
    pub version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationRecord {
    pub id: [u8; 16],
    pub resource: String,
    pub state: RotationLifecycle,
    pub declared_consumers: BTreeSet<[u8; 16]>,
    pub authorized_identities: BTreeSet<[u8; 16]>,
    pub active_instances: BTreeSet<[u8; 16]>,
    pub protected_version: u64,
    pub expected_cas: u64,
    pub target_version: Option<u64>,
    pub actor_identity_id: [u8; 16],
    pub prepared_unix_seconds: u64,
    pub cutover_unix_seconds: Option<u64>,
    pub history: Vec<RotationTransition>,
}

impl Canonical for RotationRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.fixed(&self.id);
        out.string(&self.resource, MAX_RESOURCE)?;
        out.u8(self.state as u8);
        encode_ids(&mut out, &self.declared_consumers)?;
        encode_ids(&mut out, &self.authorized_identities)?;
        encode_ids(&mut out, &self.active_instances)?;
        out.u64(self.protected_version);
        out.u64(self.expected_cas);
        encode_optional_u64(&mut out, self.target_version);
        out.fixed(&self.actor_identity_id);
        out.u64(self.prepared_unix_seconds);
        encode_optional_u64(&mut out, self.cutover_unix_seconds);
        out.u8(self.history.len() as u8);
        for transition in &self.history {
            out.u8(transition.state as u8);
            out.u64(transition.effective_unix_seconds);
            out.u64(transition.version);
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            id: input.fixed()?,
            resource: input.string(MAX_RESOURCE)?,
            state: RotationLifecycle::decode(input.u8()?)?,
            declared_consumers: decode_ids(&mut input)?,
            authorized_identities: decode_ids(&mut input)?,
            active_instances: decode_ids(&mut input)?,
            protected_version: input.u64()?,
            expected_cas: input.u64()?,
            target_version: decode_optional_u64(&mut input)?,
            actor_identity_id: input.fixed()?,
            prepared_unix_seconds: input.u64()?,
            cutover_unix_seconds: decode_optional_u64(&mut input)?,
            history: {
                let count = input.u8()? as usize;
                if count == 0 || count > MAX_HISTORY {
                    return Err(CodecError::Limit);
                }
                let mut history = Vec::with_capacity(count);
                for _ in 0..count {
                    history.push(RotationTransition {
                        state: RotationLifecycle::decode(input.u8()?)?,
                        effective_unix_seconds: input.u64()?,
                        version: input.u64()?,
                    });
                }
                history
            },
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl ClearRecord for RotationRecord {
    const CLASS: RecordClass = RecordClass::RotationState;
    const SCHEMA_VERSION: u16 = 1;
}

impl RotationRecord {
    fn validate(&self) -> Result<(), CodecError> {
        if self.id == [0; 16]
            || self.actor_identity_id == [0; 16]
            || endpoint_for(&self.resource).is_err()
            || self.protected_version == 0
            || self.expected_cas == 0
            || self.prepared_unix_seconds == 0
            || self.history.is_empty()
            || self.history.len() > MAX_HISTORY
            || self
                .history
                .last()
                .is_none_or(|entry| entry.state != self.state)
            || self.target_version.is_some() != self.cutover_unix_seconds.is_some()
            || matches!(
                self.state,
                RotationLifecycle::Prepared | RotationLifecycle::CancelledBeforeCutover
            ) && self.target_version.is_some()
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationView {
    pub record: RotationRecord,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotationError {
    Denied,
    Invalid,
    Conflict { state: RotationLifecycle },
    NotFound,
    StaleGeneration,
    CasConflict,
    ProtectedVersionUnavailable,
    Integrity,
    Limit,
}

impl From<ManagementError> for RotationError {
    fn from(value: ManagementError) -> Self {
        match value {
            ManagementError::Denied => Self::Denied,
            ManagementError::NotFound => Self::NotFound,
            ManagementError::StaleGeneration => Self::StaleGeneration,
            ManagementError::Limit => Self::Limit,
            ManagementError::Invalid | ManagementError::Conflict => Self::Invalid,
        }
    }
}

pub struct RotationSnapshotInput {
    pub declared_consumers: BTreeSet<[u8; 16]>,
    pub authorized_identities: BTreeSet<[u8; 16]>,
    pub active_instances: BTreeSet<[u8; 16]>,
}

pub struct RotationCatalog {
    store_id: StoreId,
    mac_key: [u8; 32],
    rows: BTreeMap<[u8; 16], Sealed<RotationRecord>>,
    completed: BTreeSet<([u8; 16], ControlCommand, [u8; 16])>,
}

impl RotationCatalog {
    pub fn new(store_id: StoreId, mac_key: [u8; 32]) -> Self {
        Self {
            store_id,
            mac_key,
            rows: BTreeMap::new(),
            completed: BTreeSet::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        resource: String,
        snapshot: RotationSnapshotInput,
        effective_unix_seconds: u64,
        kv: &KvService,
    ) -> Result<RotationView, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationCreate, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::RotationCreate, id))
        {
            return self.show_inner(id);
        }
        if id == [0; 16] || effective_unix_seconds == 0 {
            return Err(RotationError::Invalid);
        }
        if self.rows.contains_key(&id) {
            return Err(RotationError::Invalid);
        }
        if let Some(open) = self.rows.values().find(|row| {
            row.value.resource == resource
                && matches!(
                    row.value.state,
                    RotationLifecycle::Prepared | RotationLifecycle::Cutover
                )
        }) {
            return Err(RotationError::Conflict {
                state: open.value.state,
            });
        }
        validate_snapshot(&snapshot)?;
        let endpoint = endpoint_for(&resource)?;
        let current = kv.rotation_snapshot(&endpoint).map_err(map_kv)?;
        kv.set_rotation_snapshot_protection(&endpoint, current.current_version, true)
            .map_err(map_kv)?;
        let record = RotationRecord {
            id,
            resource,
            state: RotationLifecycle::Prepared,
            declared_consumers: snapshot.declared_consumers,
            authorized_identities: snapshot.authorized_identities,
            active_instances: snapshot.active_instances,
            protected_version: current.current_version,
            expected_cas: current.current_version,
            target_version: None,
            actor_identity_id: principal.identity_id,
            prepared_unix_seconds: effective_unix_seconds,
            cutover_unix_seconds: None,
            history: vec![RotationTransition {
                state: RotationLifecycle::Prepared,
                effective_unix_seconds,
                version: current.current_version,
            }],
        };
        self.install(record, 1)?;
        self.completed
            .insert((request_id, ControlCommand::RotationCreate, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::RotationCreate,
            id,
            None,
        )?;
        self.show_inner(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn refresh(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        snapshot: RotationSnapshotInput,
        effective_unix_seconds: u64,
        kv: &KvService,
    ) -> Result<RotationView, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationUpdate, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::RotationUpdate, id))
        {
            return self.show_inner(id);
        }
        validate_effective_time(effective_unix_seconds)?;
        validate_snapshot(&snapshot)?;
        let current = self.show_inner(id)?;
        require_state(&current, expected_generation, RotationLifecycle::Prepared)?;
        ensure_history_room(&current)?;
        let generation = next(expected_generation)?;
        let endpoint = endpoint_for(&current.record.resource)?;
        let live = kv.rotation_snapshot(&endpoint).map_err(map_kv)?;
        kv.set_rotation_snapshot_protection(&endpoint, live.current_version, true)
            .map_err(map_kv)?;
        let mut record = current.record;
        record.declared_consumers = snapshot.declared_consumers;
        record.authorized_identities = snapshot.authorized_identities;
        record.active_instances = snapshot.active_instances;
        record.protected_version = live.current_version;
        record.expected_cas = live.current_version;
        record.prepared_unix_seconds = effective_unix_seconds;
        record.history.push(RotationTransition {
            state: RotationLifecycle::Prepared,
            effective_unix_seconds,
            version: live.current_version,
        });
        self.install(record, generation)?;
        self.completed
            .insert((request_id, ControlCommand::RotationUpdate, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::RotationUpdate,
            id,
            None,
        )?;
        self.show_inner(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cutover(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        replacement: Map<String, Value>,
        effective_unix_seconds: u64,
        kv: &KvService,
    ) -> Result<RotationView, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationLifecycle, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::RotationLifecycle, id))
        {
            return self.show_inner(id);
        }
        validate_effective_time(effective_unix_seconds)?;
        let current = self.show_inner(id)?;
        require_state(&current, expected_generation, RotationLifecycle::Prepared)?;
        ensure_history_room(&current)?;
        let generation = next(expected_generation)?;
        let endpoint = endpoint_for(&current.record.resource)?;
        let written = kv
            .rotation_cutover(
                principal.identity_id,
                &endpoint,
                replacement,
                current.record.expected_cas,
            )
            .map_err(map_kv)?;
        let mut record = current.record;
        record.state = RotationLifecycle::Cutover;
        record.target_version = Some(written.version);
        record.cutover_unix_seconds = Some(effective_unix_seconds);
        record.history.push(RotationTransition {
            state: RotationLifecycle::Cutover,
            effective_unix_seconds,
            version: written.version,
        });
        self.install(record, generation)?;
        self.completed
            .insert((request_id, ControlCommand::RotationLifecycle, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::RotationLifecycle,
            id,
            None,
        )?;
        self.show_inner(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cancel(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        effective_unix_seconds: u64,
        reason: String,
        kv: &KvService,
    ) -> Result<RotationView, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationLifecycle, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::RotationLifecycle, id))
        {
            return self.show_inner(id);
        }
        validate_effective_time(effective_unix_seconds)?;
        validate_reason(&reason)?;
        let current = self.show_inner(id)?;
        require_state(&current, expected_generation, RotationLifecycle::Prepared)?;
        ensure_history_room(&current)?;
        let generation = next(expected_generation)?;
        let endpoint = endpoint_for(&current.record.resource)?;
        kv.set_rotation_snapshot_protection(&endpoint, current.record.protected_version, false)
            .map_err(map_kv)?;
        let mut record = current.record;
        record.state = RotationLifecycle::CancelledBeforeCutover;
        record.history.push(RotationTransition {
            state: RotationLifecycle::CancelledBeforeCutover,
            effective_unix_seconds,
            version: record.expected_cas,
        });
        self.install(record, generation)?;
        self.completed
            .insert((request_id, ControlCommand::RotationLifecycle, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::RotationLifecycle,
            id,
            Some(reason),
        )?;
        self.show_inner(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rollback(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        effective_unix_seconds: u64,
        reason: String,
        kv: &KvService,
    ) -> Result<RotationView, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationLifecycle, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::RotationLifecycle, id))
        {
            return self.show_inner(id);
        }
        validate_effective_time(effective_unix_seconds)?;
        validate_reason(&reason)?;
        let current = self.show_inner(id)?;
        require_state(&current, expected_generation, RotationLifecycle::Cutover)?;
        ensure_history_room(&current)?;
        let generation = next(expected_generation)?;
        let endpoint = endpoint_for(&current.record.resource)?;
        let live = kv.rotation_snapshot(&endpoint).map_err(map_kv)?;
        let written = kv
            .rotation_rollback_copy_forward(
                principal.identity_id,
                &endpoint,
                live.current_version,
                current.record.protected_version,
            )
            .map_err(map_kv)?;
        kv.set_rotation_snapshot_protection(&endpoint, current.record.protected_version, false)
            .map_err(map_kv)?;
        let mut record = current.record;
        record.state = RotationLifecycle::Superseded;
        record.history.push(RotationTransition {
            state: RotationLifecycle::Superseded,
            effective_unix_seconds,
            version: written.version,
        });
        self.install(record, generation)?;
        self.completed
            .insert((request_id, ControlCommand::RotationLifecycle, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::RotationLifecycle,
            id,
            Some(reason),
        )?;
        self.show_inner(id)
    }

    pub fn supersede_after_plain_write(
        &mut self,
        id: [u8; 16],
        expected_generation: u64,
        effective_unix_seconds: u64,
        kv: &KvService,
    ) -> Result<RotationView, RotationError> {
        validate_effective_time(effective_unix_seconds)?;
        let current = self.show_inner(id)?;
        require_state(&current, expected_generation, RotationLifecycle::Cutover)?;
        ensure_history_room(&current)?;
        let generation = next(expected_generation)?;
        let endpoint = endpoint_for(&current.record.resource)?;
        let live = kv.rotation_snapshot(&endpoint).map_err(map_kv)?;
        if live.current_version <= current.record.target_version.unwrap_or(0) {
            return Err(RotationError::CasConflict);
        }
        kv.set_rotation_snapshot_protection(&endpoint, current.record.protected_version, false)
            .map_err(map_kv)?;
        let mut record = current.record;
        record.state = RotationLifecycle::Superseded;
        record.history.push(RotationTransition {
            state: RotationLifecycle::Superseded,
            effective_unix_seconds,
            version: live.current_version,
        });
        self.install(record, generation)?;
        self.show_inner(id)
    }

    pub fn show(
        &self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
    ) -> Result<RotationView, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationStatus, request_id)?;
        self.show_inner(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn list(
        &self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        cursor: Option<[u8; 16]>,
        limit: usize,
        resource: Option<&str>,
        state: Option<RotationLifecycle>,
        prepared_from_unix_seconds: Option<u64>,
        prepared_to_unix_seconds: Option<u64>,
    ) -> Result<Page<RotationView>, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationCatalog, request_id)?;
        if limit == 0
            || limit > MAX_PAGE_SIZE
            || prepared_from_unix_seconds
                .zip(prepared_to_unix_seconds)
                .is_some_and(|(from, to)| from > to)
        {
            return Err(RotationError::Limit);
        }
        let mut items = Vec::new();
        for (id, row) in &self.rows {
            if cursor.is_some_and(|cursor| *id <= cursor)
                || resource.is_some_and(|value| row.value.resource != value)
                || state.is_some_and(|value| row.value.state != value)
                || prepared_from_unix_seconds
                    .is_some_and(|value| row.value.prepared_unix_seconds < value)
                || prepared_to_unix_seconds
                    .is_some_and(|value| row.value.prepared_unix_seconds > value)
            {
                continue;
            }
            row.verify(&self.mac_key, self.store_id, id)
                .map_err(|_| RotationError::Integrity)?;
            items.push(RotationView {
                record: row.value.clone(),
                generation: row.generation,
            });
            if items.len() > limit {
                break;
            }
        }
        let has_more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = has_more.then(|| encode_id(items.last().expect("non-empty").record.id));
        Ok(Page {
            schema: MANAGEMENT_OUTPUT_SCHEMA,
            items,
            next_cursor,
        })
    }

    fn install(&mut self, record: RotationRecord, generation: u64) -> Result<(), RotationError> {
        let id = record.id;
        let sealed = Sealed::seal(record, generation, &self.mac_key, self.store_id, &id)
            .map_err(|_| RotationError::Invalid)?;
        self.rows.insert(id, sealed);
        Ok(())
    }

    fn show_inner(&self, id: [u8; 16]) -> Result<RotationView, RotationError> {
        let row = self.rows.get(&id).ok_or(RotationError::NotFound)?;
        row.verify(&self.mac_key, self.store_id, &id)
            .map_err(|_| RotationError::Integrity)?;
        Ok(RotationView {
            record: row.value.clone(),
            generation: row.generation,
        })
    }
}

fn require_state(
    view: &RotationView,
    expected_generation: u64,
    state: RotationLifecycle,
) -> Result<(), RotationError> {
    if view.generation != expected_generation {
        return Err(RotationError::StaleGeneration);
    }
    if view.record.state != state {
        return Err(RotationError::Conflict {
            state: view.record.state,
        });
    }
    Ok(())
}

fn validate_snapshot(value: &RotationSnapshotInput) -> Result<(), RotationError> {
    if value.declared_consumers.len() > MAX_IDS
        || value.authorized_identities.len() > MAX_IDS
        || value.active_instances.len() > MAX_IDS
    {
        Err(RotationError::Limit)
    } else {
        Ok(())
    }
}

fn validate_reason(value: &str) -> Result<(), RotationError> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(RotationError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_effective_time(value: u64) -> Result<(), RotationError> {
    if value == 0 {
        Err(RotationError::Invalid)
    } else {
        Ok(())
    }
}

fn ensure_history_room(value: &RotationView) -> Result<(), RotationError> {
    if value.record.history.len() >= MAX_HISTORY {
        Err(RotationError::Limit)
    } else {
        Ok(())
    }
}

fn endpoint_for(resource: &str) -> Result<EndpointRequest, RotationError> {
    let mut parts = resource.split('/');
    let mount = parts.next().ok_or(RotationError::Invalid)?;
    let segments = parts.map(str::to_owned).collect::<Vec<_>>();
    if mount.is_empty() || segments.is_empty() || segments.iter().any(String::is_empty) {
        return Err(RotationError::Invalid);
    }
    Ok(EndpointRequest {
        kind: EndpointKind::Data,
        resource: Resource {
            mount: mount.into(),
            canonical_segments: segments,
        },
        version: None,
    })
}

fn map_kv(value: KvError) -> RotationError {
    match value {
        KvError::CasConflict => RotationError::CasConflict,
        KvError::NotFound | KvError::VersionUnavailable { .. } => {
            RotationError::ProtectedVersionUnavailable
        }
        KvError::Internal => RotationError::Integrity,
        _ => RotationError::Invalid,
    }
}

fn next(value: u64) -> Result<u64, RotationError> {
    value.checked_add(1).ok_or(RotationError::Limit)
}
fn encode_ids(out: &mut Encoder, values: &BTreeSet<[u8; 16]>) -> Result<(), CodecError> {
    if values.len() > MAX_IDS {
        return Err(CodecError::Limit);
    }
    out.u32(values.len() as u32);
    for value in values {
        out.fixed(value);
    }
    Ok(())
}
fn decode_ids(input: &mut Decoder<'_>) -> Result<BTreeSet<[u8; 16]>, CodecError> {
    let count = input.u32()? as usize;
    if count > MAX_IDS {
        return Err(CodecError::Limit);
    }
    let mut values = BTreeSet::new();
    for _ in 0..count {
        if !values.insert(input.fixed()?) {
            return Err(CodecError::Invalid);
        }
    }
    Ok(values)
}
fn encode_optional_u64(out: &mut Encoder, value: Option<u64>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.u64(value);
        }
    }
}
fn decode_optional_u64(input: &mut Decoder<'_>) -> Result<Option<u64>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.u64()?)),
        _ => Err(CodecError::Invalid),
    }
}
fn encode_id(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
