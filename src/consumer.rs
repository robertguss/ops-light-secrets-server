//! Declared consumer and consumer-instance system of record.

use std::collections::{BTreeMap, BTreeSet};

use crate::control::management::{
    ControlCommand, MANAGEMENT_OUTPUT_SCHEMA, MAX_PAGE_SIZE, ManagementCatalog, ManagementError,
    ManagementPrincipal, Page,
};
use crate::store::{
    Canonical, ClearRecord, CodecError, Decoder, Encoder, RecordClass, Sealed, StoreId,
};

const MAX_TEXT: usize = 256;
const MAX_NOTE: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConsumerLifecycle {
    Declared = 1,
    Migrated = 2,
    Retired = 3,
}

impl ConsumerLifecycle {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::Declared),
            2 => Ok(Self::Migrated),
            3 => Ok(Self::Retired),
            _ => Err(CodecError::Invalid),
        }
    }

    fn can_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Declared, Self::Migrated)
                | (Self::Declared, Self::Retired)
                | (Self::Migrated, Self::Retired)
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Migrated => "migrated",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRecord {
    pub id: [u8; 16],
    pub label: String,
    pub resource: String,
    pub owner: String,
    pub environment: String,
    pub source: String,
    pub identity_id: Option<[u8; 16]>,
    pub lifecycle: ConsumerLifecycle,
    pub last_verified_unix_seconds: Option<u64>,
    pub note: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerInstanceRecord {
    pub id: [u8; 16],
    pub consumer_id: [u8; 16],
    pub label: String,
    pub owner: String,
    pub environment: String,
    pub source: String,
    pub identity_id: Option<[u8; 16]>,
    pub lifecycle: ConsumerLifecycle,
    pub last_verified_unix_seconds: Option<u64>,
    pub note: String,
}

// Kept explicit because the two normalized row shapes intentionally differ.
impl Canonical for ConsumerRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        validate_common(
            self.id,
            &self.label,
            &self.owner,
            &self.environment,
            &self.source,
            &self.note,
        )?;
        if self.resource.is_empty() || self.resource.len() > MAX_TEXT {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.bool(false);
        out.fixed(&self.id);
        out.string(&self.label, MAX_TEXT)?;
        out.string(&self.resource, MAX_TEXT)?;
        out.string(&self.owner, MAX_TEXT)?;
        out.string(&self.environment, MAX_TEXT)?;
        out.string(&self.source, MAX_TEXT)?;
        encode_optional_id(&mut out, self.identity_id);
        out.u8(self.lifecycle as u8);
        encode_optional_u64(&mut out, self.last_verified_unix_seconds);
        out.string(&self.note, MAX_NOTE)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.bool()? {
            return Err(CodecError::Invalid);
        }
        let value = Self {
            id: input.fixed()?,
            label: input.string(MAX_TEXT)?,
            resource: input.string(MAX_TEXT)?,
            owner: input.string(MAX_TEXT)?,
            environment: input.string(MAX_TEXT)?,
            source: input.string(MAX_TEXT)?,
            identity_id: decode_optional_id(&mut input)?,
            lifecycle: ConsumerLifecycle::decode(input.u8()?)?,
            last_verified_unix_seconds: decode_optional_u64(&mut input)?,
            note: input.string(MAX_NOTE)?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }
}

impl ClearRecord for ConsumerRecord {
    const CLASS: RecordClass = RecordClass::ConsumerDeclaration;
    const SCHEMA_VERSION: u16 = 1;
}

impl Canonical for ConsumerInstanceRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        validate_common(
            self.id,
            &self.label,
            &self.owner,
            &self.environment,
            &self.source,
            &self.note,
        )?;
        if self.consumer_id == [0; 16] {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.bool(true);
        out.fixed(&self.id);
        out.fixed(&self.consumer_id);
        out.string(&self.label, MAX_TEXT)?;
        out.string(&self.owner, MAX_TEXT)?;
        out.string(&self.environment, MAX_TEXT)?;
        out.string(&self.source, MAX_TEXT)?;
        encode_optional_id(&mut out, self.identity_id);
        out.u8(self.lifecycle as u8);
        encode_optional_u64(&mut out, self.last_verified_unix_seconds);
        out.string(&self.note, MAX_NOTE)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if !input.bool()? {
            return Err(CodecError::Invalid);
        }
        let value = Self {
            id: input.fixed()?,
            consumer_id: input.fixed()?,
            label: input.string(MAX_TEXT)?,
            owner: input.string(MAX_TEXT)?,
            environment: input.string(MAX_TEXT)?,
            source: input.string(MAX_TEXT)?,
            identity_id: decode_optional_id(&mut input)?,
            lifecycle: ConsumerLifecycle::decode(input.u8()?)?,
            last_verified_unix_seconds: decode_optional_u64(&mut input)?,
            note: input.string(MAX_NOTE)?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }
}

impl ClearRecord for ConsumerInstanceRecord {
    const CLASS: RecordClass = RecordClass::ConsumerDeclaration;
    const SCHEMA_VERSION: u16 = 1;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumerError {
    Denied,
    Invalid,
    Conflict,
    NotFound,
    StaleGeneration,
    Integrity,
    Limit,
}

impl From<ManagementError> for ConsumerError {
    fn from(value: ManagementError) -> Self {
        match value {
            ManagementError::Denied => Self::Denied,
            ManagementError::Conflict => Self::Conflict,
            ManagementError::NotFound => Self::NotFound,
            ManagementError::StaleGeneration => Self::StaleGeneration,
            ManagementError::Limit => Self::Limit,
            ManagementError::Invalid => Self::Invalid,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerView {
    pub record: ConsumerRecord,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerInstanceView {
    pub record: ConsumerInstanceRecord,
    pub generation: u64,
}

pub struct ConsumerCatalog {
    store_id: StoreId,
    mac_key: [u8; 32],
    consumers: BTreeMap<[u8; 16], Sealed<ConsumerRecord>>,
    instances: BTreeMap<([u8; 16], [u8; 16]), Sealed<ConsumerInstanceRecord>>,
    completed: BTreeSet<([u8; 16], ControlCommand, [u8; 16])>,
}

impl ConsumerCatalog {
    pub fn new(store_id: StoreId, mac_key: [u8; 32]) -> Self {
        Self {
            store_id,
            mac_key,
            consumers: BTreeMap::new(),
            instances: BTreeMap::new(),
            completed: BTreeSet::new(),
        }
    }

    pub fn create_consumer(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        record: ConsumerRecord,
    ) -> Result<ConsumerView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerCreate, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::ConsumerCreate, record.id))
        {
            return self.show_consumer_inner(record.id);
        }
        if record.lifecycle != ConsumerLifecycle::Declared
            || self.consumers.contains_key(&record.id)
            || self
                .consumers
                .values()
                .any(|row| row.value.label == record.label)
            || record.encode().is_err()
        {
            return Err(ConsumerError::Conflict);
        }
        let id = record.id;
        let sealed = Sealed::seal(record, 1, &self.mac_key, self.store_id, &consumer_key(id))
            .map_err(|_| ConsumerError::Invalid)?;
        self.consumers.insert(id, sealed);
        self.completed
            .insert((request_id, ControlCommand::ConsumerCreate, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::ConsumerCreate,
            id,
            None,
        )?;
        self.show_consumer_inner(id)
    }

    pub fn create_instance(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        record: ConsumerInstanceRecord,
    ) -> Result<ConsumerInstanceView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerCreate, request_id)?;
        let target = record.id;
        if self
            .completed
            .contains(&(request_id, ControlCommand::ConsumerCreate, target))
        {
            return self.show_instance_inner(record.consumer_id, record.id);
        }
        if record.lifecycle != ConsumerLifecycle::Declared
            || !self.consumers.contains_key(&record.consumer_id)
            || self.instances.keys().any(|(_, id)| *id == record.id)
            || self.instances.iter().any(|((parent, _), row)| {
                *parent == record.consumer_id && row.value.label == record.label
            })
            || record.encode().is_err()
        {
            return Err(ConsumerError::Conflict);
        }
        let key = (record.consumer_id, record.id);
        let sealed = Sealed::seal(
            record,
            1,
            &self.mac_key,
            self.store_id,
            &instance_key(key.0, key.1),
        )
        .map_err(|_| ConsumerError::Invalid)?;
        self.instances.insert(key, sealed);
        self.completed
            .insert((request_id, ControlCommand::ConsumerCreate, target));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::ConsumerCreate,
            target,
            None,
        )?;
        self.show_instance_inner(key.0, key.1)
    }

    pub fn show_consumer(
        &self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
    ) -> Result<ConsumerView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerShow, request_id)?;
        self.show_consumer_inner(id)
    }

    pub fn show_instance(
        &self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        consumer_id: [u8; 16],
        id: [u8; 16],
    ) -> Result<ConsumerInstanceView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerShow, request_id)?;
        self.show_instance_inner(consumer_id, id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn list_consumers(
        &self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        cursor: Option<[u8; 16]>,
        limit: usize,
        resource: Option<&str>,
        lifecycle: Option<ConsumerLifecycle>,
        owner: Option<&str>,
    ) -> Result<Page<ConsumerView>, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerList, request_id)?;
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(ConsumerError::Limit);
        }
        let mut values = Vec::new();
        for (id, row) in self.consumers.range(cursor.unwrap_or([0; 16])..) {
            if cursor == Some(*id)
                || resource.is_some_and(|v| v != row.value.resource)
                || lifecycle.is_some_and(|v| v != row.value.lifecycle)
                || owner.is_some_and(|v| v != row.value.owner)
            {
                continue;
            }
            row.verify(&self.mac_key, self.store_id, &consumer_key(*id))
                .map_err(|_| ConsumerError::Integrity)?;
            values.push(ConsumerView {
                record: row.value.clone(),
                generation: row.generation,
            });
            if values.len() > limit {
                break;
            }
        }
        let has_more = values.len() > limit;
        values.truncate(limit);
        let next_cursor =
            has_more.then(|| encode_id(values.last().expect("non-empty page").record.id));
        Ok(Page {
            schema: MANAGEMENT_OUTPUT_SCHEMA,
            items: values,
            next_cursor,
        })
    }

    pub fn list_instances(
        &self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        consumer_id: [u8; 16],
        cursor: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<Page<ConsumerInstanceView>, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerList, request_id)?;
        if !self.consumers.contains_key(&consumer_id) {
            return Err(ConsumerError::NotFound);
        }
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(ConsumerError::Limit);
        }
        let mut values = Vec::new();
        for ((parent, id), row) in &self.instances {
            if *parent != consumer_id || cursor.is_some_and(|cursor| *id <= cursor) {
                continue;
            }
            row.verify(&self.mac_key, self.store_id, &instance_key(*parent, *id))
                .map_err(|_| ConsumerError::Integrity)?;
            values.push(ConsumerInstanceView {
                record: row.value.clone(),
                generation: row.generation,
            });
            if values.len() > limit {
                break;
            }
        }
        let has_more = values.len() > limit;
        values.truncate(limit);
        let next_cursor =
            has_more.then(|| encode_id(values.last().expect("non-empty page").record.id));
        Ok(Page {
            schema: MANAGEMENT_OUTPUT_SCHEMA,
            items: values,
            next_cursor,
        })
    }

    pub fn update_consumer(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        update: ConsumerUpdate,
    ) -> Result<ConsumerView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerUpdate, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::ConsumerUpdate, id))
        {
            return self.show_consumer_inner(id);
        }
        let current = self.show_consumer_inner(id)?;
        let replacement = update_consumer_record(current, expected_generation, update)?;
        let generation = next_generation(expected_generation)?;
        let sealed = Sealed::seal(
            replacement,
            generation,
            &self.mac_key,
            self.store_id,
            &consumer_key(id),
        )
        .map_err(|_| ConsumerError::Invalid)?;
        self.consumers.insert(id, sealed);
        self.completed
            .insert((request_id, ControlCommand::ConsumerUpdate, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::ConsumerUpdate,
            id,
            None,
        )?;
        self.show_consumer_inner(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_instance(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        consumer_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        update: ConsumerUpdate,
    ) -> Result<ConsumerInstanceView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerUpdate, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::ConsumerUpdate, id))
        {
            return self.show_instance_inner(consumer_id, id);
        }
        let current = self.show_instance_inner(consumer_id, id)?;
        if current.generation != expected_generation {
            return Err(ConsumerError::StaleGeneration);
        }
        let mut record = current.record;
        apply_update(
            &mut record.owner,
            &mut record.environment,
            &mut record.source,
            &mut record.identity_id,
            &mut record.lifecycle,
            &mut record.last_verified_unix_seconds,
            &mut record.note,
            update,
        )?;
        let generation = next_generation(expected_generation)?;
        let sealed = Sealed::seal(
            record,
            generation,
            &self.mac_key,
            self.store_id,
            &instance_key(consumer_id, id),
        )
        .map_err(|_| ConsumerError::Invalid)?;
        self.instances.insert((consumer_id, id), sealed);
        self.completed
            .insert((request_id, ControlCommand::ConsumerUpdate, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::ConsumerUpdate,
            id,
            None,
        )?;
        self.show_instance_inner(consumer_id, id)
    }

    pub fn retire_consumer(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        reason: String,
    ) -> Result<ConsumerView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerRetire, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::ConsumerRetire, id))
        {
            return self.show_consumer_inner(id);
        }
        if self.instances.iter().any(|((parent, _), row)| {
            *parent == id && row.value.lifecycle != ConsumerLifecycle::Retired
        }) {
            return Err(ConsumerError::Conflict);
        }
        self.retire_consumer_impl(
            management,
            principal,
            request_id,
            id,
            expected_generation,
            reason,
        )
    }

    fn retire_consumer_impl(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        reason: String,
    ) -> Result<ConsumerView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerRetire, request_id)?;
        validate_reason(&reason)?;
        let current = self.show_consumer_inner(id)?;
        if current.generation != expected_generation
            || !current
                .record
                .lifecycle
                .can_advance_to(ConsumerLifecycle::Retired)
        {
            return Err(ConsumerError::StaleGeneration);
        }
        let mut record = current.record;
        record.lifecycle = ConsumerLifecycle::Retired;
        let generation = next_generation(expected_generation)?;
        let sealed = Sealed::seal(
            record,
            generation,
            &self.mac_key,
            self.store_id,
            &consumer_key(id),
        )
        .map_err(|_| ConsumerError::Invalid)?;
        self.consumers.insert(id, sealed);
        self.completed
            .insert((request_id, ControlCommand::ConsumerRetire, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::ConsumerRetire,
            id,
            Some(reason),
        )?;
        self.show_consumer_inner(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn retire_instance(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        consumer_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        reason: String,
    ) -> Result<ConsumerInstanceView, ConsumerError> {
        management.authorize_command(principal, ControlCommand::ConsumerRetire, request_id)?;
        validate_reason(&reason)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::ConsumerRetire, id))
        {
            return self.show_instance_inner(consumer_id, id);
        }
        let current = self.show_instance_inner(consumer_id, id)?;
        if current.generation != expected_generation
            || !current
                .record
                .lifecycle
                .can_advance_to(ConsumerLifecycle::Retired)
        {
            return Err(ConsumerError::StaleGeneration);
        }
        let mut record = current.record;
        record.lifecycle = ConsumerLifecycle::Retired;
        let generation = next_generation(expected_generation)?;
        let sealed = Sealed::seal(
            record,
            generation,
            &self.mac_key,
            self.store_id,
            &instance_key(consumer_id, id),
        )
        .map_err(|_| ConsumerError::Invalid)?;
        self.instances.insert((consumer_id, id), sealed);
        self.completed
            .insert((request_id, ControlCommand::ConsumerRetire, id));
        management.record_command_success(
            principal,
            request_id,
            ControlCommand::ConsumerRetire,
            id,
            Some(reason),
        )?;
        self.show_instance_inner(consumer_id, id)
    }

    fn show_consumer_inner(&self, id: [u8; 16]) -> Result<ConsumerView, ConsumerError> {
        let row = self.consumers.get(&id).ok_or(ConsumerError::NotFound)?;
        row.verify(&self.mac_key, self.store_id, &consumer_key(id))
            .map_err(|_| ConsumerError::Integrity)?;
        Ok(ConsumerView {
            record: row.value.clone(),
            generation: row.generation,
        })
    }

    fn show_instance_inner(
        &self,
        consumer_id: [u8; 16],
        id: [u8; 16],
    ) -> Result<ConsumerInstanceView, ConsumerError> {
        let row = self
            .instances
            .get(&(consumer_id, id))
            .ok_or(ConsumerError::NotFound)?;
        row.verify(&self.mac_key, self.store_id, &instance_key(consumer_id, id))
            .map_err(|_| ConsumerError::Integrity)?;
        Ok(ConsumerInstanceView {
            record: row.value.clone(),
            generation: row.generation,
        })
    }

    #[doc(hidden)]
    pub fn corrupt_consumer_note_for_fixture(&mut self, id: [u8; 16]) {
        if let Some(row) = self.consumers.get_mut(&id) {
            row.value.note.push('x');
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsumerUpdate {
    pub owner: Option<String>,
    pub environment: Option<String>,
    pub source: Option<String>,
    pub identity_id: Option<Option<[u8; 16]>>,
    pub lifecycle: Option<ConsumerLifecycle>,
    pub last_verified_unix_seconds: Option<Option<u64>>,
    pub note: Option<String>,
}

fn update_consumer_record(
    current: ConsumerView,
    expected: u64,
    update: ConsumerUpdate,
) -> Result<ConsumerRecord, ConsumerError> {
    if current.generation != expected {
        return Err(ConsumerError::StaleGeneration);
    }
    let mut record = current.record;
    apply_update(
        &mut record.owner,
        &mut record.environment,
        &mut record.source,
        &mut record.identity_id,
        &mut record.lifecycle,
        &mut record.last_verified_unix_seconds,
        &mut record.note,
        update,
    )?;
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
fn apply_update(
    owner: &mut String,
    environment: &mut String,
    source: &mut String,
    identity_id: &mut Option<[u8; 16]>,
    lifecycle: &mut ConsumerLifecycle,
    last_verified: &mut Option<u64>,
    note: &mut String,
    update: ConsumerUpdate,
) -> Result<(), ConsumerError> {
    if let Some(next) = update.lifecycle {
        if !lifecycle.can_advance_to(next) || next == ConsumerLifecycle::Retired {
            return Err(ConsumerError::Invalid);
        }
        *lifecycle = next;
    }
    if let Some(value) = update.owner {
        *owner = value;
    }
    if let Some(value) = update.environment {
        *environment = value;
    }
    if let Some(value) = update.source {
        *source = value;
    }
    if let Some(value) = update.identity_id {
        *identity_id = value;
    }
    if let Some(value) = update.last_verified_unix_seconds {
        *last_verified = value;
    }
    if let Some(value) = update.note {
        *note = value;
    }
    validate_common([1; 16], "unchanged", owner, environment, source, note)
        .map_err(|_| ConsumerError::Invalid)
}

fn validate_common(
    id: [u8; 16],
    label: &str,
    owner: &str,
    environment: &str,
    source: &str,
    note: &str,
) -> Result<(), CodecError> {
    if id == [0; 16]
        || [label, owner, environment, source].iter().any(|value| {
            value.is_empty() || value.len() > MAX_TEXT || value.chars().any(char::is_control)
        })
        || note.len() > MAX_NOTE
        || note.chars().any(char::is_control)
    {
        return Err(CodecError::Invalid);
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), ConsumerError> {
    if reason.is_empty() || reason.len() > MAX_NOTE || reason.chars().any(char::is_control) {
        Err(ConsumerError::Invalid)
    } else {
        Ok(())
    }
}

fn next_generation(value: u64) -> Result<u64, ConsumerError> {
    value.checked_add(1).ok_or(ConsumerError::Limit)
}

fn consumer_key(id: [u8; 16]) -> Vec<u8> {
    let mut key = vec![b'c'];
    key.extend(id);
    key
}
fn instance_key(parent: [u8; 16], id: [u8; 16]) -> Vec<u8> {
    let mut key = vec![b'i'];
    key.extend(parent);
    key.extend(id);
    key
}
fn encode_id(id: [u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn encode_optional_id(out: &mut Encoder, value: Option<[u8; 16]>) {
    match value {
        None => out.u8(0),
        Some(id) => {
            out.u8(1);
            out.fixed(&id);
        }
    }
}
fn decode_optional_id(input: &mut Decoder<'_>) -> Result<Option<[u8; 16]>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.fixed()?)),
        _ => Err(CodecError::Invalid),
    }
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
