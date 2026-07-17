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

/// Post-cutover adoption class (R33). Language is "fetched version N", never "using".
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AdoptionClass {
    OnCurrent,
    OnPrior,
    SilentSinceWrite,
    NoInstanceObservation,
    RetiredWithoutProof,
}

impl AdoptionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnCurrent => "on-current",
            Self::OnPrior => "on-prior",
            Self::SilentSinceWrite => "silent-since-write",
            Self::NoInstanceObservation => "no-instance-observation",
            Self::RetiredWithoutProof => "retired-without-proof",
        }
    }
}

/// One audited read observation used for adoption classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadObservation {
    pub sequence: u64,
    pub identity_id: [u8; 16],
    pub consumer_instance_id: Option<[u8; 16]>,
    pub version: u64,
    pub effective_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptionMember {
    pub kind: &'static str,
    pub id: [u8; 16],
    pub class: AdoptionClass,
    pub fetched_version: Option<u64>,
    pub last_read_unix_seconds: Option<u64>,
    /// Recency annotation only — never changes class (R23 lookback is not a reclassifier).
    pub recency_lookback_exceeded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationAdoptionStatus {
    pub rotation_id: [u8; 16],
    pub resource: String,
    pub state: RotationLifecycle,
    pub target_version: u64,
    pub cutover_sequence: u64,
    pub cutoff_sequence: u64,
    pub instances: Vec<AdoptionMember>,
    pub identities: Vec<AdoptionMember>,
    pub consumers: Vec<AdoptionMember>,
}

/// Redacted closeout report (no secret values).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationCloseoutReport {
    pub rotation_id: [u8; 16],
    pub state: RotationLifecycle,
    pub acknowledged_unverified: bool,
    pub warnings: Vec<String>,
}

/// Classify post-cutover adoption from audited reads strictly after cutover through cutoff.
///
/// Lookback only annotates recency; it never demotes `on-current` to silent.
pub fn classify_adoption(
    snapshot: &RotationSnapshotInput,
    target_version: u64,
    cutover_sequence: u64,
    cutoff_sequence: u64,
    observations: &[ReadObservation],
    retired_instances: &BTreeSet<[u8; 16]>,
    lookback_unix_seconds: Option<u64>,
    now_unix_seconds: u64,
    instance_to_identity: &BTreeMap<[u8; 16], [u8; 16]>,
    identity_to_consumer: &BTreeMap<[u8; 16], [u8; 16]>,
) -> Result<Vec<AdoptionMember>, RotationError> {
    if cutoff_sequence < cutover_sequence {
        return Err(RotationError::Invalid);
    }
    let window: Vec<&ReadObservation> = observations
        .iter()
        .filter(|item| item.sequence > cutover_sequence && item.sequence <= cutoff_sequence)
        .collect();

    let mut members = Vec::new();

    // Instance granularity is authoritative (KTD5).
    for instance in &snapshot.active_instances {
        let reads: Vec<&ReadObservation> = window
            .iter()
            .copied()
            .filter(|item| item.consumer_instance_id == Some(*instance))
            .collect();
        let (class, version, last) = latest_class(&reads, target_version);
        let mut class = class;
        if retired_instances.contains(instance) && class != AdoptionClass::OnCurrent {
            class = AdoptionClass::RetiredWithoutProof;
        }
        let recency = lookback_exceeded(last, lookback_unix_seconds, now_unix_seconds);
        members.push(AdoptionMember {
            kind: "instance",
            id: *instance,
            class,
            fetched_version: version,
            last_read_unix_seconds: last,
            recency_lookback_exceeded: recency,
        });
    }

    // Identity rollup: mixed when instances disagree; no-instance principals explicit.
    for identity in &snapshot.authorized_identities {
        let instance_ids: Vec<[u8; 16]> = snapshot
            .active_instances
            .iter()
            .copied()
            .filter(|instance| instance_to_identity.get(instance) == Some(identity))
            .collect();
        if instance_ids.is_empty() {
            let reads: Vec<&ReadObservation> = window
                .iter()
                .copied()
                .filter(|item| {
                    item.identity_id == *identity && item.consumer_instance_id.is_none()
                })
                .collect();
            let (class, version, last) = if reads.is_empty() {
                (AdoptionClass::NoInstanceObservation, None, None)
            } else {
                latest_class(&reads, target_version)
            };
            members.push(AdoptionMember {
                kind: "identity",
                id: *identity,
                class,
                fetched_version: version,
                last_read_unix_seconds: last,
                recency_lookback_exceeded: lookback_exceeded(
                    last,
                    lookback_unix_seconds,
                    now_unix_seconds,
                ),
            });
            continue;
        }
        let classes: BTreeSet<AdoptionClass> = instance_ids
            .iter()
            .filter_map(|instance| {
                members
                    .iter()
                    .find(|member| member.kind == "instance" && member.id == *instance)
                    .map(|member| member.class)
            })
            .collect();
        let class = if classes.len() == 1 {
            *classes.iter().next().expect("one")
        } else if classes.contains(&AdoptionClass::OnPrior)
            || classes.contains(&AdoptionClass::SilentSinceWrite)
            || classes.contains(&AdoptionClass::RetiredWithoutProof)
        {
            // Mixed replicas: surface the least-adopted signal (never hide prior/silent).
            if classes.contains(&AdoptionClass::OnPrior) {
                AdoptionClass::OnPrior
            } else if classes.contains(&AdoptionClass::SilentSinceWrite) {
                AdoptionClass::SilentSinceWrite
            } else {
                AdoptionClass::RetiredWithoutProof
            }
        } else {
            AdoptionClass::OnCurrent
        };
        let last = instance_ids
            .iter()
            .filter_map(|instance| {
                members
                    .iter()
                    .find(|member| member.kind == "instance" && member.id == *instance)
                    .and_then(|member| member.last_read_unix_seconds)
            })
            .max();
        let version = instance_ids.iter().find_map(|instance| {
            members
                .iter()
                .find(|member| member.kind == "instance" && member.id == *instance)
                .and_then(|member| member.fetched_version)
        });
        members.push(AdoptionMember {
            kind: "identity",
            id: *identity,
            class,
            fetched_version: version,
            last_read_unix_seconds: last,
            recency_lookback_exceeded: lookback_exceeded(
                last,
                lookback_unix_seconds,
                now_unix_seconds,
            ),
        });
    }

    for consumer in &snapshot.declared_consumers {
        let identities: Vec<[u8; 16]> = snapshot
            .authorized_identities
            .iter()
            .copied()
            .filter(|identity| identity_to_consumer.get(identity) == Some(consumer))
            .collect();
        let class = if identities.is_empty() {
            AdoptionClass::SilentSinceWrite
        } else {
            let classes: BTreeSet<AdoptionClass> = identities
                .iter()
                .filter_map(|identity| {
                    members
                        .iter()
                        .find(|member| member.kind == "identity" && member.id == *identity)
                        .map(|member| member.class)
                })
                .collect();
            if classes.contains(&AdoptionClass::OnPrior) {
                AdoptionClass::OnPrior
            } else if classes.contains(&AdoptionClass::SilentSinceWrite)
                || classes.contains(&AdoptionClass::NoInstanceObservation)
            {
                AdoptionClass::SilentSinceWrite
            } else if classes.contains(&AdoptionClass::RetiredWithoutProof) {
                AdoptionClass::RetiredWithoutProof
            } else {
                AdoptionClass::OnCurrent
            }
        };
        members.push(AdoptionMember {
            kind: "consumer",
            id: *consumer,
            class,
            fetched_version: None,
            last_read_unix_seconds: None,
            recency_lookback_exceeded: false,
        });
    }

    members.sort_by(|left, right| {
        left.kind
            .cmp(right.kind)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(members)
}

fn latest_class(
    reads: &[&ReadObservation],
    target_version: u64,
) -> (AdoptionClass, Option<u64>, Option<u64>) {
    let Some(latest) = reads.iter().copied().max_by_key(|item| item.sequence) else {
        return (AdoptionClass::SilentSinceWrite, None, None);
    };
    let class = if latest.version == target_version {
        AdoptionClass::OnCurrent
    } else {
        AdoptionClass::OnPrior
    };
    (
        class,
        Some(latest.version),
        Some(latest.effective_unix_seconds),
    )
}

fn lookback_exceeded(
    last_read: Option<u64>,
    lookback_unix_seconds: Option<u64>,
    now_unix_seconds: u64,
) -> bool {
    match (last_read, lookback_unix_seconds) {
        (Some(last), Some(window)) => now_unix_seconds.saturating_sub(last) > window,
        _ => false,
    }
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

    /// Guarded rotation closeout (R33). Target must still be current; adoption
    /// must be on-current or covered by acknowledge_unverified / retirement.
    #[allow(clippy::too_many_arguments)]
    pub fn complete(
        &mut self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        current_version: u64,
        members: &[AdoptionMember],
        acknowledge_unverified: bool,
        acknowledge_reason: Option<&str>,
        effective_unix_seconds: u64,
    ) -> Result<RotationCloseoutReport, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationLifecycle, request_id)?;
        if self
            .completed
            .contains(&(request_id, ControlCommand::RotationLifecycle, id))
        {
            return Ok(RotationCloseoutReport {
                rotation_id: id,
                state: RotationLifecycle::Completed,
                acknowledged_unverified: acknowledge_unverified,
                warnings: Vec::new(),
            });
        }
        validate_effective_time(effective_unix_seconds)?;
        let current = self.show_inner(id)?;
        require_state(&current, expected_generation, RotationLifecycle::Cutover)?;
        ensure_history_room(&current)?;
        let target = current.record.target_version.ok_or(RotationError::Invalid)?;
        if current_version != target {
            // Condition (a): never overridable.
            return Err(RotationError::Conflict {
                state: current.record.state,
            });
        }
        let unresolved: Vec<&AdoptionMember> = members
            .iter()
            .filter(|member| {
                !matches!(
                    member.class,
                    AdoptionClass::OnCurrent | AdoptionClass::RetiredWithoutProof
                )
            })
            .collect();
        if !unresolved.is_empty() {
            if !acknowledge_unverified {
                return Err(RotationError::Invalid);
            }
            if acknowledge_reason.map(str::trim).unwrap_or("").is_empty() {
                return Err(RotationError::Invalid);
            }
        }
        let generation = next(expected_generation)?;
        let mut record = current.record;
        record.state = RotationLifecycle::Completed;
        record.history.push(RotationTransition {
            state: RotationLifecycle::Completed,
            effective_unix_seconds,
            version: target,
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
        Ok(RotationCloseoutReport {
            rotation_id: id,
            state: RotationLifecycle::Completed,
            acknowledged_unverified: acknowledge_unverified,
            warnings: if acknowledge_unverified {
                vec!["acknowledge-unverified".into()]
            } else {
                Vec::new()
            },
        })
    }

    /// Post-write adoption status from audited reads (R33 / AE11).
    #[allow(clippy::too_many_arguments)]
    pub fn status(
        &self,
        management: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        observations: &[ReadObservation],
        retired_instances: &BTreeSet<[u8; 16]>,
        cutover_sequence: u64,
        cutoff_sequence: u64,
        lookback_unix_seconds: Option<u64>,
        now_unix_seconds: u64,
        instance_to_identity: &BTreeMap<[u8; 16], [u8; 16]>,
        identity_to_consumer: &BTreeMap<[u8; 16], [u8; 16]>,
    ) -> Result<RotationAdoptionStatus, RotationError> {
        management.authorize_command(principal, ControlCommand::RotationStatus, request_id)?;
        let view = self.show_inner(id)?;
        if view.record.state != RotationLifecycle::Cutover
            && view.record.state != RotationLifecycle::Completed
        {
            return Err(RotationError::Conflict {
                state: view.record.state,
            });
        }
        let target_version = view.record.target_version.ok_or(RotationError::Invalid)?;
        let snapshot = RotationSnapshotInput {
            declared_consumers: view.record.declared_consumers.clone(),
            authorized_identities: view.record.authorized_identities.clone(),
            active_instances: view.record.active_instances.clone(),
        };
        let members = classify_adoption(
            &snapshot,
            target_version,
            cutover_sequence,
            cutoff_sequence,
            observations,
            retired_instances,
            lookback_unix_seconds,
            now_unix_seconds,
            instance_to_identity,
            identity_to_consumer,
        )?;
        let instances = members
            .iter()
            .filter(|member| member.kind == "instance")
            .cloned()
            .collect();
        let identities = members
            .iter()
            .filter(|member| member.kind == "identity")
            .cloned()
            .collect();
        let consumers = members
            .iter()
            .filter(|member| member.kind == "consumer")
            .cloned()
            .collect();
        Ok(RotationAdoptionStatus {
            rotation_id: view.record.id,
            resource: view.record.resource,
            state: view.record.state,
            target_version,
            cutover_sequence,
            cutoff_sequence,
            instances,
            identities,
            consumers,
        })
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

/// Server-owned rotation interval (seconds). None means no interval configured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationIntervalPolicy {
    pub interval_seconds: Option<u64>,
    pub last_completed_rotation_unix_seconds: Option<u64>,
    pub created_unix_seconds: u64,
    pub last_non_rotation_write_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretAgeView {
    pub age_seconds: u64,
    pub age_basis: &'static str,
    pub interval_seconds: Option<u64>,
    pub due: bool,
    pub changed_since_last_completed_rotation: bool,
}

/// Age is time since last COMPLETED rotation, else since creation (R12).
pub fn secret_age_view(policy: &RotationIntervalPolicy, now_unix_seconds: u64) -> SecretAgeView {
    let (basis_time, age_basis) = match policy.last_completed_rotation_unix_seconds {
        Some(completed) => (completed, "last_completed_rotation"),
        None => (policy.created_unix_seconds, "creation"),
    };
    let age_seconds = now_unix_seconds.saturating_sub(basis_time);
    let due = policy
        .interval_seconds
        .is_some_and(|interval| age_seconds >= interval);
    let changed_since_last_completed_rotation = match (
        policy.last_completed_rotation_unix_seconds,
        policy.last_non_rotation_write_unix_seconds,
    ) {
        (Some(completed), Some(written)) => written > completed,
        (None, Some(_)) => true,
        _ => false,
    };
    SecretAgeView {
        age_seconds,
        age_basis,
        interval_seconds: policy.interval_seconds,
        due,
        changed_since_last_completed_rotation,
    }
}

/// Set/clear rotation interval (control-plane only; pure policy mutation).
pub fn apply_interval_mutation(
    current: Option<u64>,
    next: Option<u64>,
) -> Result<Option<u64>, RotationError> {
    if next == Some(0) {
        return Err(RotationError::Invalid);
    }
    Ok(next.or(current.and(None)).or(next))
}

pub fn set_rotation_interval(seconds: u64) -> Result<u64, RotationError> {
    if seconds == 0 {
        Err(RotationError::Invalid)
    } else {
        Ok(seconds)
    }
}

pub fn clear_rotation_interval() -> Option<u64> {
    None
}
