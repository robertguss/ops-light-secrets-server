//! Named fault-injection points for the U11.4a core/recovery gate.
//!
//! Default and release builds compile [`hit`] to a no-op with no environment
//! variable reads. Enable the `fault-inject` cargo feature only for fault-suite
//! binaries. When enabled, a process aborts only if `OLSS_FAULT_POINT` exactly
//! matches an allowlisted point name passed to [`hit`].

/// Environment variable read only when the `fault-inject` feature is enabled.
#[cfg(feature = "fault-inject")]
pub const FAULT_POINT_ENV: &str = "OLSS_FAULT_POINT";

/// Marker string present only in fault-inject builds (binary inspection target).
#[cfg(feature = "fault-inject")]
pub const FAULT_INJECT_BUILD_MARKER: &str = "OLSS_FAULT_INJECT_BUILD_MARKER_v1";

/// Stable catalog of core + recovery fault points (M2 gate).
pub const CORE_RECOVERY_POINTS: &[&str] = &[
    // Core transaction
    "txn.secret_write.before_state",
    "txn.secret_write.after_state",
    "txn.secret_write.after_audit",
    "txn.secret_write.after_commit",
    "txn.credential_revoke.before_state",
    "txn.credential_revoke.after_audit",
    "txn.audit_commit.fail",
    "txn.checkpoint.prepare",
    "txn.checkpoint.sign",
    "txn.checkpoint.register",
    "txn.cancel.before_start",
    "txn.cancel.after_start",
    "txn.executor.panic",
    "storage.disk_full",
    "storage.short_write",
    "storage.torn_write_refuse",
    // Recovery / publication
    "init.disclosure_window",
    "backup.temp_create",
    "backup.temp_fsync",
    "backup.signature_write",
    "backup.publish.rename",
    "backup.publish.parent_fsync",
    "backup.reservation.publishing",
    "backup.reservation.published",
    "restore.temp_build",
    "restore.temp_fsync",
    "restore.install.rename",
    "restore.install.parent_fsync",
    "recovery.recipient_rewrap.after_envelope",
    "recovery.recipient_rewrap.after_metadata",
    "recovery.recipient_rewrap.after_audit",
    "recovery.credential_epoch.bump",
    "recovery.credential_epoch.emergency_disclosure",
    "recovery.detached_signature.write",
    "recovery.detached_signature.verify",
    "recovery.rehearsal_receipt.register",
    "recovery.rollback_fork.activate",
    "reserve.status",
    "reserve.release",
    "reserve.recreate",
];

/// True when `name` is in the core/recovery allowlist.
pub fn is_allowlisted_point(name: &str) -> bool {
    CORE_RECOVERY_POINTS.contains(&name)
}

/// Process-local fault hit. No-op without `fault-inject`.
#[inline(always)]
pub fn hit(point: &str) {
    #[cfg(feature = "fault-inject")]
    {
        hit_enabled(point);
    }
    #[cfg(not(feature = "fault-inject"))]
    {
        let _ = point;
    }
}

#[cfg(feature = "fault-inject")]
fn hit_enabled(point: &str) {
    // Keep marker live so release-feature binaries contain a searchable byte.
    let _marker = FAULT_INJECT_BUILD_MARKER;
    if !is_allowlisted_point(point) {
        return;
    }
    let Ok(active) = std::env::var(FAULT_POINT_ENV) else {
        return;
    };
    if active == point {
        // Abort rather than panic so parent suites observe a signal-style exit.
        std::process::abort();
    }
}

/// Classify IO-style storage faults for deterministic suite assertions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageFaultClass {
    DiskFull,
    Quota,
    ShortWrite,
    TornWrite,
    Other,
}

/// Map a raw errno (when available) or io kind into a storage fault class.
pub fn classify_io_error(kind: std::io::ErrorKind, raw_os_error: Option<i32>) -> StorageFaultClass {
    if let Some(code) = raw_os_error {
        if code == libc::ENOSPC {
            return StorageFaultClass::DiskFull;
        }
        if code == libc::EDQUOT {
            return StorageFaultClass::Quota;
        }
    }
    match kind {
        std::io::ErrorKind::WriteZero => StorageFaultClass::ShortWrite,
        std::io::ErrorKind::UnexpectedEof => StorageFaultClass::TornWrite,
        std::io::ErrorKind::StorageFull => StorageFaultClass::DiskFull,
        _ => StorageFaultClass::Other,
    }
}

/// Deterministic short-write / disk-full refusal helper used by storage tests.
///
/// Returns `Err` with a stable class; never produces a half-applied "success".
pub fn refuse_unreliable_write(
    planned_bytes: usize,
    written_bytes: usize,
    class: StorageFaultClass,
) -> Result<(), StorageFaultClass> {
    if written_bytes < planned_bytes {
        return Err(match class {
            StorageFaultClass::DiskFull | StorageFaultClass::Quota => class,
            StorageFaultClass::TornWrite => StorageFaultClass::TornWrite,
            _ => StorageFaultClass::ShortWrite,
        });
    }
    if matches!(
        class,
        StorageFaultClass::DiskFull
            | StorageFaultClass::Quota
            | StorageFaultClass::ShortWrite
            | StorageFaultClass::TornWrite
    ) {
        return Err(class);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_unique_and_named() {
        let mut seen = std::collections::BTreeSet::new();
        for point in CORE_RECOVERY_POINTS {
            assert!(point.contains('.'), "point must be namespaced: {point}");
            assert!(seen.insert(*point), "duplicate point {point}");
        }
        assert!(CORE_RECOVERY_POINTS.len() >= 30);
    }

    #[test]
    fn short_write_and_disk_full_are_deterministic_refusals() {
        assert_eq!(
            refuse_unreliable_write(100, 40, StorageFaultClass::ShortWrite),
            Err(StorageFaultClass::ShortWrite)
        );
        assert_eq!(
            refuse_unreliable_write(100, 100, StorageFaultClass::DiskFull),
            Err(StorageFaultClass::DiskFull)
        );
        assert_eq!(
            refuse_unreliable_write(100, 100, StorageFaultClass::Other),
            Ok(())
        );
        assert_eq!(
            classify_io_error(std::io::ErrorKind::WriteZero, None),
            StorageFaultClass::ShortWrite
        );
        assert_eq!(
            classify_io_error(std::io::ErrorKind::Other, Some(libc::ENOSPC)),
            StorageFaultClass::DiskFull
        );
    }

    #[test]
    #[cfg(not(feature = "fault-inject"))]
    fn hit_is_noop_without_feature() {
        // Would abort if hooks were live with matching env; must be a pure no-op.
        // SAFETY: test process only; we never set a live hook in default builds.
        hit("txn.executor.panic");
        hit("not-allowlisted");
    }
}
