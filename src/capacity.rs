//! Fail-closed capacity admission and allocated recovery-reserve protocol.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::control::management::{ControlCommand, ManagementCatalog, ManagementPrincipal};
use crate::store::{Canonical, ClearRecord, CodecError, Decoder, Encoder, RecordClass};

pub const MAX_TRANSACTION_BYTES: u64 = 9 * 1024 * 1024;
pub const DATA_LANE_DEPTH: u64 = 64;
pub const MAX_INCIDENT_INVESTIGATIONS: u64 = 8;
pub const IDLE_CLOCK_INTERVAL_SECONDS: u64 = 30;
pub const MAX_IDLE_CLOCK_EVENT_BYTES: u64 = 512;
pub const ANNUAL_IDLE_CLOCK_BYTES: u64 =
    (365 * 24 * 60 * 60 / IDLE_CLOCK_INTERVAL_SECONDS) * MAX_IDLE_CLOCK_EVENT_BYTES;
pub const RECOVERY_OPERATION_SLOTS: u64 = 16 + MAX_INCIDENT_INVESTIGATIONS * 6;
pub const RECOVERY_RESERVE_BYTES: u64 = RECOVERY_OPERATION_SLOTS * MAX_TRANSACTION_BYTES;
pub const SHUTDOWN_RELEASE_FLOOR_BYTES: u64 = 2 * MAX_TRANSACTION_BYTES;
pub const DATA_INFLIGHT_HEADROOM_BYTES: u64 = DATA_LANE_DEPTH * MAX_TRANSACTION_BYTES;
pub const MINIMAL_RECOVERY_BYTES: u64 = (RECOVERY_OPERATION_SLOTS - 2) * MAX_TRANSACTION_BYTES;
pub const DATA_STOP_FLOOR_BYTES: u64 =
    DATA_INFLIGHT_HEADROOM_BYTES + MINIMAL_RECOVERY_BYTES + SHUTDOWN_RELEASE_FLOOR_BYTES;
pub const WARNING_FLOOR_BYTES: u64 = DATA_STOP_FLOOR_BYTES + ANNUAL_IDLE_CLOCK_BYTES;

const RESERVE_FILE: &str = "recovery.reserve";
const RESERVE_TEMP: &str = ".recovery.reserve.init";
const MAX_REASON_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityBand {
    Healthy,
    Warning,
    DataStopped,
    ShutdownOnly,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityOperation {
    Data,
    Checkpoint,
    Backup,
    Diagnostic,
    AuditQuery,
    AuditExport,
    EmergencyControl,
    OutputPublication,
    OutputCompletion,
    Shutdown,
    ReserveRelease,
    ReserveRecreate,
}

impl CapacityOperation {
    fn shutdown_safe(self) -> bool {
        matches!(self, Self::Shutdown | Self::ReserveRelease)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityError {
    TransactionTooLarge,
    DataStopped,
    ControlStopped,
    PublicationUnknown,
    PublicationExists,
    Invalid,
    Unauthorized,
    UnsafeReserve,
    Allocation,
    Io,
}

impl fmt::Display for CapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TransactionTooLarge => "capacity_refused code=transaction_too_large",
            Self::DataStopped => "capacity_refused code=data_admission_stopped",
            Self::ControlStopped => "capacity_refused code=shutdown_floor",
            Self::PublicationUnknown => "capacity_refused code=publication_unknown",
            Self::PublicationExists => "capacity_refused code=publication_exists",
            Self::Invalid => "capacity_refused code=invalid_request",
            Self::Unauthorized => "capacity_refused code=unauthorized",
            Self::UnsafeReserve => "capacity_refused code=unsafe_reserve",
            Self::Allocation => "capacity_refused code=reserve_allocation",
            Self::Io => "capacity_refused code=io",
        })
    }
}

impl std::error::Error for CapacityError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapacitySnapshot {
    pub schema: u16,
    pub band: CapacityBand,
    pub observed_available_bytes: u64,
    pub held_publication_bytes: u64,
    pub data_inflight: u64,
    pub data_stop_floor_bytes: u64,
    pub shutdown_floor_bytes: u64,
    pub warning_floor_bytes: u64,
}

#[derive(Debug, Default)]
struct CapacityState {
    data_inflight: u64,
    held_publications: std::collections::BTreeMap<[u8; 16], u64>,
}

#[derive(Clone, Debug, Default)]
pub struct CapacityGuard {
    state: Arc<Mutex<CapacityState>>,
}

pub struct AdmissionPermit {
    guard: CapacityGuard,
    data: bool,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if self.data {
            let mut state = self.guard.state.lock().unwrap_or_else(|e| e.into_inner());
            state.data_inflight = state.data_inflight.saturating_sub(1);
        }
    }
}

impl CapacityGuard {
    pub fn snapshot(&self, observed_available_bytes: u64) -> CapacitySnapshot {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let held = state.held_publications.values().copied().sum::<u64>();
        CapacitySnapshot {
            schema: 1,
            band: band(observed_available_bytes.saturating_sub(held)),
            observed_available_bytes,
            held_publication_bytes: held,
            data_inflight: state.data_inflight,
            data_stop_floor_bytes: DATA_STOP_FLOOR_BYTES,
            shutdown_floor_bytes: SHUTDOWN_RELEASE_FLOOR_BYTES,
            warning_floor_bytes: WARNING_FLOOR_BYTES,
        }
    }

    pub fn admit(
        &self,
        operation: CapacityOperation,
        observed_available_bytes: u64,
        maximum_commit_bytes: u64,
    ) -> Result<AdmissionPermit, CapacityError> {
        if maximum_commit_bytes == 0 || maximum_commit_bytes > MAX_TRANSACTION_BYTES {
            return Err(CapacityError::TransactionTooLarge);
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let held = state.held_publications.values().copied().sum::<u64>();
        let available = observed_available_bytes.saturating_sub(held);
        if operation == CapacityOperation::Data {
            let next = state.data_inflight.saturating_add(1);
            let unreserved_queue_headroom = DATA_LANE_DEPTH
                .saturating_sub(next)
                .saturating_mul(MAX_TRANSACTION_BYTES);
            let required = MINIMAL_RECOVERY_BYTES
                .saturating_add(SHUTDOWN_RELEASE_FLOOR_BYTES)
                .saturating_add(unreserved_queue_headroom)
                .saturating_add(maximum_commit_bytes);
            if next > DATA_LANE_DEPTH || available <= required {
                return Err(CapacityError::DataStopped);
            }
            state.data_inflight = next;
            return Ok(AdmissionPermit {
                guard: self.clone(),
                data: true,
            });
        }
        let required = if operation.shutdown_safe() {
            maximum_commit_bytes
        } else {
            SHUTDOWN_RELEASE_FLOOR_BYTES.saturating_add(maximum_commit_bytes)
        };
        if available < required {
            return Err(CapacityError::ControlStopped);
        }
        Ok(AdmissionPermit {
            guard: self.clone(),
            data: false,
        })
    }

    pub fn hold_publication(
        &self,
        id: [u8; 16],
        observed_available_bytes: u64,
        outcome_and_abandon_bytes: u64,
    ) -> Result<(), CapacityError> {
        if id == [0; 16]
            || outcome_and_abandon_bytes == 0
            || outcome_and_abandon_bytes > 2 * MAX_TRANSACTION_BYTES
        {
            return Err(CapacityError::Invalid);
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.held_publications.contains_key(&id) {
            return Err(CapacityError::PublicationExists);
        }
        let held = state.held_publications.values().copied().sum::<u64>();
        if observed_available_bytes.saturating_sub(held)
            < SHUTDOWN_RELEASE_FLOOR_BYTES.saturating_add(outcome_and_abandon_bytes)
        {
            return Err(CapacityError::ControlStopped);
        }
        state
            .held_publications
            .insert(id, outcome_and_abandon_bytes);
        Ok(())
    }

    pub fn finish_publication(&self, id: [u8; 16]) -> Result<(), CapacityError> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .held_publications
            .remove(&id)
            .map(|_| ())
            .ok_or(CapacityError::PublicationUnknown)
    }
}

pub fn band(available_bytes: u64) -> CapacityBand {
    if available_bytes < MAX_TRANSACTION_BYTES {
        CapacityBand::Exhausted
    } else if available_bytes <= SHUTDOWN_RELEASE_FLOOR_BYTES {
        CapacityBand::ShutdownOnly
    } else if available_bytes <= DATA_STOP_FLOOR_BYTES {
        CapacityBand::DataStopped
    } else if available_bytes <= WARNING_FLOOR_BYTES {
        CapacityBand::Warning
    } else {
        CapacityBand::Healthy
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReservePhase {
    Healthy = 1,
    ReleaseRequested = 2,
    Released = 3,
    RecreateRequested = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReserveRecord {
    pub generation: u64,
    pub phase: RecoveryReservePhase,
    pub expected_bytes: u64,
    pub operation_id: [u8; 16],
}

impl RecoveryReserveRecord {
    pub fn healthy(expected_bytes: u64) -> Result<Self, CapacityError> {
        if expected_bytes == 0 {
            return Err(CapacityError::Invalid);
        }
        Ok(Self {
            generation: 1,
            phase: RecoveryReservePhase::Healthy,
            expected_bytes,
            operation_id: [0; 16],
        })
    }

    pub fn request_release(
        &self,
        expected_generation: u64,
        operation_id: [u8; 16],
    ) -> Result<Self, CapacityError> {
        if self.phase == RecoveryReservePhase::ReleaseRequested && self.operation_id == operation_id
        {
            return Ok(self.clone());
        }
        if self.phase != RecoveryReservePhase::Healthy
            || self.generation != expected_generation
            || operation_id == [0; 16]
        {
            return Err(CapacityError::Invalid);
        }
        Ok(Self {
            generation: next(self.generation)?,
            phase: RecoveryReservePhase::ReleaseRequested,
            expected_bytes: self.expected_bytes,
            operation_id,
        })
    }

    pub fn mark_released(&self) -> Result<Self, CapacityError> {
        if self.phase == RecoveryReservePhase::Released {
            return Ok(self.clone());
        }
        if self.phase != RecoveryReservePhase::ReleaseRequested {
            return Err(CapacityError::Invalid);
        }
        Ok(Self {
            generation: next(self.generation)?,
            phase: RecoveryReservePhase::Released,
            ..self.clone()
        })
    }

    pub fn request_recreate(
        &self,
        expected_generation: u64,
        operation_id: [u8; 16],
    ) -> Result<Self, CapacityError> {
        if self.phase == RecoveryReservePhase::RecreateRequested
            && self.operation_id == operation_id
        {
            return Ok(self.clone());
        }
        if self.phase != RecoveryReservePhase::Released
            || self.generation != expected_generation
            || operation_id == [0; 16]
        {
            return Err(CapacityError::Invalid);
        }
        Ok(Self {
            generation: next(self.generation)?,
            phase: RecoveryReservePhase::RecreateRequested,
            operation_id,
            ..self.clone()
        })
    }

    pub fn mark_healthy(&self) -> Result<Self, CapacityError> {
        if self.phase != RecoveryReservePhase::RecreateRequested {
            return Err(CapacityError::Invalid);
        }
        Ok(Self {
            generation: next(self.generation)?,
            phase: RecoveryReservePhase::Healthy,
            operation_id: [0; 16],
            ..self.clone()
        })
    }
}

impl Canonical for RecoveryReserveRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.generation == 0 || self.expected_bytes == 0 {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u64(self.generation);
        out.u8(self.phase as u8);
        out.u64(self.expected_bytes);
        out.fixed(&self.operation_id);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            generation: input.u64()?,
            phase: match input.u8()? {
                1 => RecoveryReservePhase::Healthy,
                2 => RecoveryReservePhase::ReleaseRequested,
                3 => RecoveryReservePhase::Released,
                4 => RecoveryReservePhase::RecreateRequested,
                _ => return Err(CodecError::Invalid),
            },
            expected_bytes: input.u64()?,
            operation_id: input.fixed()?,
        };
        input.finish()?;
        if value.generation == 0 || value.expected_bytes == 0 {
            return Err(CodecError::Invalid);
        }
        Ok(value)
    }
}

impl ClearRecord for RecoveryReserveRecord {
    const CLASS: RecordClass = RecordClass::RecoveryReserveMetadata;
    const SCHEMA_VERSION: u16 = 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileAction {
    Ready,
    FinishRelease,
    CommitReleased,
    Recreate,
    CommitHealthy,
}

pub fn reconcile(
    record: &RecoveryReserveRecord,
    final_exists: bool,
    temp_exists: bool,
) -> Result<ReconcileAction, CapacityError> {
    match (record.phase, final_exists, temp_exists) {
        (RecoveryReservePhase::Healthy, true, false) => Ok(ReconcileAction::Ready),
        (RecoveryReservePhase::ReleaseRequested, true, false) => Ok(ReconcileAction::FinishRelease),
        (RecoveryReservePhase::ReleaseRequested, false, false) => {
            Ok(ReconcileAction::CommitReleased)
        }
        (RecoveryReservePhase::Released, false, false)
        | (RecoveryReservePhase::RecreateRequested, false, false) => Ok(ReconcileAction::Recreate),
        (RecoveryReservePhase::RecreateRequested, true, false) => {
            Ok(ReconcileAction::CommitHealthy)
        }
        _ => Err(CapacityError::UnsafeReserve),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReserveFileStatus {
    pub schema: u16,
    pub expected_bytes: u64,
    pub allocated_bytes: u64,
    pub mode: u32,
    pub owner_uid: u32,
}

pub fn provision_reserve(
    directory: &Path,
    bytes: u64,
    expected_uid: u32,
) -> Result<ReserveFileStatus, CapacityError> {
    if bytes == 0 || !directory.is_dir() {
        return Err(CapacityError::Invalid);
    }
    let temporary = directory.join(RESERVE_TEMP);
    let final_path = directory.join(RESERVE_FILE);
    if fs::symlink_metadata(&final_path).is_ok() {
        return Err(CapacityError::UnsafeReserve);
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(map_io)?;
    let allocation = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, bytes as libc::off_t) };
    if allocation != 0 {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(CapacityError::Allocation);
    }
    file.sync_all().map_err(map_io)?;
    verify_file(&file, bytes, expected_uid)?;
    fs::rename(&temporary, &final_path).map_err(map_io)?;
    sync_directory(directory)?;
    inspect_reserve(directory, bytes, expected_uid)
}

pub fn inspect_reserve(
    directory: &Path,
    expected_bytes: u64,
    expected_uid: u32,
) -> Result<ReserveFileStatus, CapacityError> {
    let path = directory.join(RESERVE_FILE);
    let metadata = fs::symlink_metadata(&path).map_err(map_io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != expected_bytes
    {
        return Err(CapacityError::UnsafeReserve);
    }
    let allocated = metadata.blocks().saturating_mul(512);
    if allocated < expected_bytes {
        return Err(CapacityError::Allocation);
    }
    Ok(ReserveFileStatus {
        schema: 1,
        expected_bytes,
        allocated_bytes: allocated,
        mode: metadata.permissions().mode() & 0o777,
        owner_uid: metadata.uid(),
    })
}

pub fn release_reserve(
    directory: &Path,
    expected_bytes: u64,
    expected_uid: u32,
    operation_id: [u8; 16],
) -> Result<(), CapacityError> {
    inspect_reserve(directory, expected_bytes, expected_uid)?;
    let released = release_path(directory, operation_id);
    if fs::symlink_metadata(&released).is_ok() {
        return Err(CapacityError::UnsafeReserve);
    }
    fs::rename(directory.join(RESERVE_FILE), &released).map_err(map_io)?;
    sync_directory(directory)?;
    fs::remove_file(&released).map_err(map_io)?;
    sync_directory(directory)
}

fn release_path(directory: &Path, operation_id: [u8; 16]) -> PathBuf {
    let id = operation_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    directory.join(format!(".recovery.reserve.release-{id}"))
}

fn verify_file(file: &File, bytes: u64, expected_uid: u32) -> Result<(), CapacityError> {
    let metadata = file.metadata().map_err(map_io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != bytes
        || metadata.blocks().saturating_mul(512) < bytes
    {
        return Err(CapacityError::Allocation);
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), CapacityError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(map_io)
}

fn map_io(error: io::Error) -> CapacityError {
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOSPC) | Some(libc::EDQUOT)
    ) {
        CapacityError::Allocation
    } else {
        CapacityError::Io
    }
}

fn next(value: u64) -> Result<u64, CapacityError> {
    value.checked_add(1).ok_or(CapacityError::Invalid)
}

pub fn confirmation(
    command: &str,
    generation: u64,
    expected_bytes: u64,
    reason: &str,
) -> Result<String, CapacityError> {
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES || reason.chars().any(char::is_control)
    {
        return Err(CapacityError::Invalid);
    }
    let mut digest = blake3::Hasher::new();
    digest.update(b"ops-light-secrets-server.reserve-confirmation.v1\0");
    for field in [
        command.as_bytes(),
        &generation.to_be_bytes(),
        &expected_bytes.to_be_bytes(),
        reason.as_bytes(),
    ] {
        digest.update(&(field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Ok(digest.finalize().to_hex().to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveMutationRequest {
    pub request_id: [u8; 16],
    pub operation_id: [u8; 16],
    pub expected_generation: u64,
    pub reason: String,
    pub confirmation: String,
    pub observed_available_bytes: u64,
}

pub fn authorize_reserve_status(
    authorization: &mut ManagementCatalog,
    principal: ManagementPrincipal,
    request_id: [u8; 16],
) -> Result<(), CapacityError> {
    authorization
        .authorize_command(principal, ControlCommand::StoreReserveStatus, request_id)
        .map_err(|_| CapacityError::Unauthorized)
}

pub fn reserve_release_transition(
    authorization: &mut ManagementCatalog,
    principal: ManagementPrincipal,
    record: &RecoveryReserveRecord,
    request: &ReserveMutationRequest,
) -> Result<RecoveryReserveRecord, CapacityError> {
    authorization
        .authorize_command(
            principal,
            ControlCommand::StoreReserveRelease,
            request.request_id,
        )
        .map_err(|_| CapacityError::Unauthorized)?;
    if !matches!(
        band(request.observed_available_bytes),
        CapacityBand::DataStopped | CapacityBand::ShutdownOnly | CapacityBand::Exhausted
    ) || request.confirmation
        != confirmation(
            "release",
            request.expected_generation,
            record.expected_bytes,
            &request.reason,
        )?
    {
        return Err(CapacityError::Invalid);
    }
    let replacement = record.request_release(request.expected_generation, request.operation_id)?;
    authorization
        .record_command_success(
            principal,
            request.request_id,
            ControlCommand::StoreReserveRelease,
            request.operation_id,
            Some(request.reason.clone()),
        )
        .map_err(|_| CapacityError::Invalid)?;
    Ok(replacement)
}

pub fn reserve_recreate_transition(
    authorization: &mut ManagementCatalog,
    principal: ManagementPrincipal,
    record: &RecoveryReserveRecord,
    request: &ReserveMutationRequest,
) -> Result<RecoveryReserveRecord, CapacityError> {
    authorization
        .authorize_command(
            principal,
            ControlCommand::StoreReserveRecreate,
            request.request_id,
        )
        .map_err(|_| CapacityError::Unauthorized)?;
    if request.observed_available_bytes
        < record.expected_bytes.saturating_add(DATA_STOP_FLOOR_BYTES)
        || request.confirmation
            != confirmation(
                "recreate",
                request.expected_generation,
                record.expected_bytes,
                &request.reason,
            )?
    {
        return Err(CapacityError::Invalid);
    }
    let replacement = record.request_recreate(request.expected_generation, request.operation_id)?;
    authorization
        .record_command_success(
            principal,
            request.request_id,
            ControlCommand::StoreReserveRecreate,
            request.operation_id,
            Some(request.reason.clone()),
        )
        .map_err(|_| CapacityError::Invalid)?;
    Ok(replacement)
}
