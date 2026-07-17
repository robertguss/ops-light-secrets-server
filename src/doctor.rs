//! Operator doctor checks with stable JSON and exit codes (U12.1).
//!
//! Exit codes: 0 healthy, 1 warnings only, 2 check failure, 3 could not execute.

use serde::Serialize;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub const DOCTOR_SCHEMA: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckSeverity {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Clone, Debug, Serialize)]
pub struct DoctorCheck {
    pub id: &'static str,
    pub severity: CheckSeverity,
    pub summary: String,
    pub reason: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DoctorReport {
    pub schema: u16,
    pub mode: &'static str,
    pub checks: Vec<DoctorCheck>,
    pub exit_code: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorMode {
    Offline,
    Online,
}

impl DoctorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Online => "online",
        }
    }
}

/// Compute stable exit code from check severities.
pub fn exit_code(checks: &[DoctorCheck]) -> u8 {
    let mut has_fail = false;
    let mut has_warn = false;
    let mut has_skip_only_blocker = false;
    for check in checks {
        match check.severity {
            CheckSeverity::Fail => has_fail = true,
            CheckSeverity::Warn => has_warn = true,
            CheckSeverity::Skip if check.reason == Some("mode_unavailable") => {
                has_skip_only_blocker = true;
            }
            _ => {}
        }
    }
    if has_fail {
        2
    } else if has_skip_only_blocker && checks.iter().all(|c| {
        matches!(c.severity, CheckSeverity::Ok | CheckSeverity::Skip | CheckSeverity::Warn)
            && !(c.severity == CheckSeverity::Skip && c.reason == Some("mode_unavailable"))
            || c.severity == CheckSeverity::Skip
    }) {
        // Any Skip with mode_unavailable when required checks cannot run → 3
        // if nothing actually failed but required online-only checks were skipped offline
        // and no ok checks for required set... Keep simpler rule below.
        3
    } else if has_warn {
        1
    } else if checks.iter().any(|c| c.severity == CheckSeverity::Skip) {
        // Skipped optional checks do not force 3; only when every check is skip.
        if checks.iter().all(|c| c.severity == CheckSeverity::Skip) {
            3
        } else {
            0
        }
    } else {
        0
    }
}

/// Run offline doctor against a data directory (no secret values inspected).
pub fn run_offline(data_directory: &Path) -> DoctorReport {
    let mut checks = Vec::new();

    match fs::symlink_metadata(data_directory) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            let mode = meta.permissions().mode() & 0o777;
            let severity = if mode & 0o077 == 0 {
                CheckSeverity::Ok
            } else {
                CheckSeverity::Fail
            };
            checks.push(DoctorCheck {
                id: "data_dir_permissions",
                severity,
                summary: format!("mode={mode:o}"),
                reason: None,
            });
            let uid = meta.uid();
            let euid = unsafe { libc::geteuid() };
            checks.push(DoctorCheck {
                id: "data_dir_owner",
                severity: if uid == euid {
                    CheckSeverity::Ok
                } else {
                    CheckSeverity::Fail
                },
                summary: format!("uid={uid}"),
                reason: None,
            });
        }
        Ok(_) => checks.push(DoctorCheck {
            id: "data_dir_permissions",
            severity: CheckSeverity::Fail,
            summary: "not a regular directory".into(),
            reason: None,
        }),
        Err(_) => checks.push(DoctorCheck {
            id: "data_dir_permissions",
            severity: CheckSeverity::Fail,
            summary: "unreadable data directory".into(),
            reason: None,
        }),
    }

    let store = data_directory.join("store.redb");
    match fs::symlink_metadata(&store) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
            let mode = meta.permissions().mode() & 0o777;
            checks.push(DoctorCheck {
                id: "store_file",
                severity: if mode & 0o077 == 0 {
                    CheckSeverity::Ok
                } else {
                    CheckSeverity::Warn
                },
                summary: format!("present mode={mode:o}"),
                reason: None,
            });
        }
        Ok(_) => checks.push(DoctorCheck {
            id: "store_file",
            severity: CheckSeverity::Fail,
            summary: "store path is not a regular file".into(),
            reason: None,
        }),
        Err(_) => checks.push(DoctorCheck {
            id: "store_file",
            severity: CheckSeverity::Warn,
            summary: "store.redb absent (uninitialized)".into(),
            reason: None,
        }),
    }

    // Online-only checks are skipped offline with an explicit reason.
    for id in [
        "control_socket_peercred",
        "diagnostics_capability",
        "data_plane_readiness",
    ] {
        checks.push(DoctorCheck {
            id,
            severity: CheckSeverity::Skip,
            summary: "requires online control session".into(),
            reason: Some("mode_unavailable"),
        });
    }

    // Offline identity possession check is skipped without an approved channel.
    checks.push(DoctorCheck {
        id: "keyring_decrypt",
        severity: CheckSeverity::Skip,
        summary: "recovery identity not supplied".into(),
        reason: Some("identity_channel_required"),
    });

    let mut code = exit_code(&checks);
    // Offline mode with only skip+ok/warn for online-only is healthy-enough for
    // local preflight: demote pure mode skips when store checks ran.
    if code == 3
        && checks
            .iter()
            .any(|c| matches!(c.severity, CheckSeverity::Ok | CheckSeverity::Warn | CheckSeverity::Fail))
    {
        code = if checks.iter().any(|c| c.severity == CheckSeverity::Fail) {
            2
        } else if checks.iter().any(|c| c.severity == CheckSeverity::Warn) {
            1
        } else {
            0
        };
    }

    DoctorReport {
        schema: DOCTOR_SCHEMA,
        mode: DoctorMode::Offline.as_str(),
        checks,
        exit_code: code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(
            exit_code(&[DoctorCheck {
                id: "a",
                severity: CheckSeverity::Ok,
                summary: "ok".into(),
                reason: None,
            }]),
            0
        );
        assert_eq!(
            exit_code(&[DoctorCheck {
                id: "a",
                severity: CheckSeverity::Warn,
                summary: "w".into(),
                reason: None,
            }]),
            1
        );
        assert_eq!(
            exit_code(&[DoctorCheck {
                id: "a",
                severity: CheckSeverity::Fail,
                summary: "f".into(),
                reason: None,
            }]),
            2
        );
    }

    #[test]
    fn offline_doctor_reports_permissions_without_secrets() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let report = run_offline(directory.path());
        assert_eq!(report.schema, 1);
        assert_eq!(report.mode, "offline");
        assert!(report.checks.iter().any(|c| c.id == "data_dir_permissions"));
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("AGE-SECRET-KEY"));
        assert!(report.exit_code <= 2);
    }
}
