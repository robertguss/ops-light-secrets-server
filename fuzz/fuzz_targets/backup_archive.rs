#![no_main]

use libfuzzer_sys::fuzz_target;
use ops_light_secrets_server::backup_format::{
    ArchiveFrame, BackupContainer, DetachedBackupSignature, RecoveryManifest,
};
use ops_light_secrets_server::store::Canonical;

fuzz_target!(|data: &[u8]| {
    let _ = ArchiveFrame::decode(data);
    let _ = RecoveryManifest::decode(data);
    let _ = BackupContainer::decode(data);
    let _ = DetachedBackupSignature::decode(data);
});
