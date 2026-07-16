use super::{
    ArtifactScanner, HarnessError, SanitizedManifest, ScanAttestation, ScanRequest, collect_paths,
    find_bytes, keyed_id, path_bytes, sanitized_finding,
};
use base64::Engine;
use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

const MAX_SCAN_FILES: usize = 256;
const MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_DEPTH: usize = 4;
const MAX_ARCHIVE_MEMBERS: usize = 1024;
const MAX_ARCHIVE_MEMBER_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARCHIVE_EXPANDED_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub struct FullScanner;

struct Variant<'a> {
    check_id: &'static str,
    encoded: Vec<u8>,
    canary: &'a [u8],
}

impl ArtifactScanner for FullScanner {
    fn scan(&self, request: ScanRequest<'_>) -> Result<ScanAttestation, HarnessError> {
        let variants = variants(request.canaries);
        let mut paths = Vec::new();
        collect_paths(request.root, &mut paths)?;
        if paths.len() > MAX_SCAN_FILES {
            return Err(HarnessError::Scanner);
        }
        paths.sort();

        let mut bytes_scanned = 0_u64;
        let mut archive_state = ArchiveState::default();
        let mut tree_hasher = blake3::Hasher::new_keyed(request.run_key);
        for path in &paths {
            let before = std::fs::symlink_metadata(path)?;
            if before.file_type().is_symlink() || !before.is_file() || before.nlink() != 1 {
                return Err(HarnessError::Scanner);
            }
            bytes_scanned = bytes_scanned
                .checked_add(before.len())
                .ok_or(HarnessError::Scanner)?;
            if bytes_scanned > MAX_SCAN_BYTES {
                return Err(HarnessError::Scanner);
            }

            let relative = path
                .strip_prefix(request.root)
                .map_err(|_| HarnessError::Scanner)?;
            let relative_bytes = path_bytes(relative);
            tree_hasher.update(&relative_bytes);
            if let Some(variant) = first_match(&relative_bytes, &variants) {
                return Err(HarnessError::Quarantined(Box::new(sanitized_finding(
                    request.run_key,
                    relative,
                    filename_check_id(variant.check_id),
                    0,
                    variant.canary,
                ))));
            }

            let bytes = std::fs::read(path)?;
            tree_hasher.update(&bytes);
            if let Some((variant, offset)) = first_match_with_offset(&bytes, &variants) {
                return Err(HarnessError::Quarantined(Box::new(sanitized_finding(
                    request.run_key,
                    relative,
                    variant.check_id,
                    offset as u64,
                    variant.canary,
                ))));
            }
            scan_archive(
                &bytes,
                &relative_bytes,
                0,
                request.run_key,
                &variants,
                &mut archive_state,
            )?;

            let after = std::fs::symlink_metadata(path)?;
            if metadata_changed(&before, &after) {
                return Err(HarnessError::Scanner);
            }
        }

        Ok(ScanAttestation {
            clean: true,
            files_scanned: paths.len(),
            bytes_scanned: bytes_scanned
                .checked_add(archive_state.expanded_bytes)
                .ok_or(HarnessError::Scanner)?,
            scanner: "full-artifact-v1",
            tree_digest: tree_hasher.finalize().to_hex().to_string(),
        })
    }
}

#[derive(Default)]
struct ArchiveState {
    members: usize,
    expanded_bytes: u64,
}

fn scan_archive(
    bytes: &[u8],
    virtual_id: &[u8],
    depth: usize,
    key: &[u8; 32],
    variants: &[Variant<'_>],
    state: &mut ArchiveState,
) -> Result<(), HarnessError> {
    if depth > MAX_ARCHIVE_DEPTH {
        return Err(HarnessError::Scanner);
    }
    if is_zip(bytes) {
        return scan_zip(bytes, virtual_id, depth, key, variants, state);
    }
    if is_gzip(bytes) {
        return scan_gzip(bytes, virtual_id, depth, key, variants, state);
    }
    if is_tar(bytes) {
        return scan_tar(bytes, virtual_id, depth, key, variants, state);
    }
    Ok(())
}

fn scan_zip(
    bytes: &[u8],
    virtual_id: &[u8],
    depth: usize,
    key: &[u8; 32],
    variants: &[Variant<'_>],
    state: &mut ArchiveState,
) -> Result<(), HarnessError> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| HarnessError::Scanner)?;
    state.members = state
        .members
        .checked_add(archive.len())
        .ok_or(HarnessError::Scanner)?;
    if state.members > MAX_ARCHIVE_MEMBERS {
        return Err(HarnessError::Scanner);
    }
    let mut names = BTreeSet::new();
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).map_err(|_| HarnessError::Scanner)?;
        if member.is_symlink() || (!member.is_file() && !member.is_dir()) {
            return Err(HarnessError::Scanner);
        }
        let name = member.enclosed_name().ok_or(HarnessError::Scanner)?;
        validate_member_path(&name)?;
        let name_bytes = path_bytes(&name);
        if !names.insert(name_bytes.clone()) {
            return Err(HarnessError::Scanner);
        }
        let member_id = virtual_member_id(virtual_id, b"zip", index);
        if let Some(variant) = first_match(&name_bytes, variants) {
            return Err(archive_finding(
                key,
                &member_id,
                variant.check_id,
                0,
                variant.canary,
            ));
        }
        if member.is_dir() {
            continue;
        }
        if member.size() > MAX_ARCHIVE_MEMBER_BYTES {
            return Err(HarnessError::Scanner);
        }
        let data = read_bounded(&mut member, MAX_ARCHIVE_MEMBER_BYTES)?;
        add_expanded(state, data.len())?;
        scan_virtual_bytes(&data, &member_id, key, variants)?;
        scan_archive(&data, &member_id, depth + 1, key, variants, state)?;
    }
    Ok(())
}

fn scan_tar(
    bytes: &[u8],
    virtual_id: &[u8],
    depth: usize,
    key: &[u8; 32],
    variants: &[Variant<'_>],
    state: &mut ArchiveState,
) -> Result<(), HarnessError> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let entries = archive.entries().map_err(|_| HarnessError::Scanner)?;
    let mut names = BTreeSet::new();
    for (index, entry) in entries.enumerate() {
        state.members = state.members.checked_add(1).ok_or(HarnessError::Scanner)?;
        if state.members > MAX_ARCHIVE_MEMBERS {
            return Err(HarnessError::Scanner);
        }
        let mut entry = entry.map_err(|_| HarnessError::Scanner)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(HarnessError::Scanner);
        }
        if !entry_type.is_file() && !entry_type.is_dir() {
            return Err(HarnessError::Scanner);
        }
        let name = entry.path().map_err(|_| HarnessError::Scanner)?;
        validate_member_path(&name)?;
        let name_bytes = path_bytes(&name);
        if !names.insert(name_bytes.clone()) {
            return Err(HarnessError::Scanner);
        }
        let member_id = virtual_member_id(virtual_id, b"tar", index);
        if let Some(variant) = first_match(&name_bytes, variants) {
            return Err(archive_finding(
                key,
                &member_id,
                variant.check_id,
                0,
                variant.canary,
            ));
        }
        if entry_type.is_dir() {
            continue;
        }
        if entry.size() > MAX_ARCHIVE_MEMBER_BYTES {
            return Err(HarnessError::Scanner);
        }
        let data = read_bounded(&mut entry, MAX_ARCHIVE_MEMBER_BYTES)?;
        add_expanded(state, data.len())?;
        scan_virtual_bytes(&data, &member_id, key, variants)?;
        scan_archive(&data, &member_id, depth + 1, key, variants, state)?;
    }
    Ok(())
}

fn scan_gzip(
    bytes: &[u8],
    virtual_id: &[u8],
    depth: usize,
    key: &[u8; 32],
    variants: &[Variant<'_>],
    state: &mut ArchiveState,
) -> Result<(), HarnessError> {
    state.members = state.members.checked_add(1).ok_or(HarnessError::Scanner)?;
    if state.members > MAX_ARCHIVE_MEMBERS {
        return Err(HarnessError::Scanner);
    }
    let mut decoder = flate2::read::MultiGzDecoder::new(Cursor::new(bytes));
    let data = read_bounded(&mut decoder, MAX_ARCHIVE_MEMBER_BYTES)?;
    add_expanded(state, data.len())?;
    let member_id = virtual_member_id(virtual_id, b"gzip", 0);
    scan_virtual_bytes(&data, &member_id, key, variants)?;
    scan_archive(&data, &member_id, depth + 1, key, variants, state)
}

fn scan_virtual_bytes(
    bytes: &[u8],
    virtual_id: &[u8],
    key: &[u8; 32],
    variants: &[Variant<'_>],
) -> Result<(), HarnessError> {
    if let Some((variant, offset)) = first_match_with_offset(bytes, variants) {
        return Err(archive_finding(
            key,
            virtual_id,
            variant.check_id,
            offset as u64,
            variant.canary,
        ));
    }
    Ok(())
}

fn archive_finding(
    key: &[u8; 32],
    virtual_id: &[u8],
    check_id: &'static str,
    byte_offset: u64,
    canary: &[u8],
) -> HarnessError {
    HarnessError::Quarantined(Box::new(SanitizedManifest {
        artifact_id: keyed_id(key, &[b"archive-artifact", virtual_id].concat()),
        path_digest: keyed_id(key, &[b"archive-path", virtual_id].concat()),
        structural_parent: "archive",
        artifact_kind: "archive_member",
        check_id,
        byte_offset,
        match_id: keyed_id(key, &[b"match", canary].concat()),
    }))
}

fn read_bounded(reader: &mut impl Read, limit: u64) -> Result<Vec<u8>, HarnessError> {
    let mut data = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| HarnessError::Scanner)?;
    if u64::try_from(data.len()).map_err(|_| HarnessError::Scanner)? > limit {
        return Err(HarnessError::Scanner);
    }
    Ok(data)
}

fn add_expanded(state: &mut ArchiveState, bytes: usize) -> Result<(), HarnessError> {
    state.expanded_bytes = state
        .expanded_bytes
        .checked_add(u64::try_from(bytes).map_err(|_| HarnessError::Scanner)?)
        .ok_or(HarnessError::Scanner)?;
    if state.expanded_bytes > MAX_ARCHIVE_EXPANDED_BYTES {
        return Err(HarnessError::Scanner);
    }
    Ok(())
}

fn validate_member_path(path: &Path) -> Result<(), HarnessError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(HarnessError::Scanner);
    }
    Ok(())
}

fn virtual_member_id(parent: &[u8], format: &[u8], index: usize) -> Vec<u8> {
    let mut id = Vec::with_capacity(parent.len() + format.len() + 16);
    id.extend_from_slice(parent);
    id.push(0);
    id.extend_from_slice(format);
    id.push(0);
    id.extend_from_slice(index.to_string().as_bytes());
    id
}

fn is_zip(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08")
    )
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

fn is_tar(bytes: &[u8]) -> bool {
    bytes.get(257..262) == Some(b"ustar")
}

fn variants(canaries: &[zeroize::Zeroizing<Vec<u8>>]) -> Vec<Variant<'_>> {
    let mut output = Vec::new();
    for canary in canaries {
        let mut seen = BTreeSet::new();
        add_variant(
            &mut output,
            &mut seen,
            "raw_literal",
            canary.to_vec(),
            canary,
        );

        if let Ok(text) = std::str::from_utf8(canary) {
            if let Ok(json) = serde_json::to_string(text) {
                add_variant(
                    &mut output,
                    &mut seen,
                    "json_escape",
                    json.as_bytes()[1..json.len() - 1].to_vec(),
                    canary,
                );
            }
            add_variant(
                &mut output,
                &mut seen,
                "shell_escape",
                text.replace('\'', "'\\''").into_bytes(),
                canary,
            );
        }

        add_variant(
            &mut output,
            &mut seen,
            "percent_upper",
            percent_encode(canary, true),
            canary,
        );
        add_variant(
            &mut output,
            &mut seen,
            "percent_lower",
            percent_encode(canary, false),
            canary,
        );

        let standard = base64::engine::general_purpose::STANDARD.encode(canary);
        add_variant(
            &mut output,
            &mut seen,
            "base64_standard_padded",
            standard.as_bytes().to_vec(),
            canary,
        );
        add_variant(
            &mut output,
            &mut seen,
            "base64_standard_unpadded",
            standard.trim_end_matches('=').as_bytes().to_vec(),
            canary,
        );
        let url = base64::engine::general_purpose::URL_SAFE.encode(canary);
        add_variant(
            &mut output,
            &mut seen,
            "base64_url_padded",
            url.as_bytes().to_vec(),
            canary,
        );
        add_variant(
            &mut output,
            &mut seen,
            "base64_url_unpadded",
            url.trim_end_matches('=').as_bytes().to_vec(),
            canary,
        );

        let lower = hex(canary, false);
        add_variant(&mut output, &mut seen, "hex_lower", lower, canary);
        let upper = hex(canary, true);
        add_variant(&mut output, &mut seen, "hex_upper", upper, canary);
    }
    output
}

fn add_variant<'a>(
    output: &mut Vec<Variant<'a>>,
    seen: &mut BTreeSet<Vec<u8>>,
    check_id: &'static str,
    encoded: Vec<u8>,
    canary: &'a [u8],
) {
    if !encoded.is_empty() && seen.insert(encoded.clone()) {
        output.push(Variant {
            check_id,
            encoded,
            canary,
        });
    }
}

fn first_match<'a>(bytes: &[u8], variants: &'a [Variant<'a>]) -> Option<&'a Variant<'a>> {
    variants
        .iter()
        .find(|variant| find_bytes(bytes, &variant.encoded).is_some())
}

fn first_match_with_offset<'a>(
    bytes: &[u8],
    variants: &'a [Variant<'a>],
) -> Option<(&'a Variant<'a>, usize)> {
    variants
        .iter()
        .find_map(|variant| find_bytes(bytes, &variant.encoded).map(|offset| (variant, offset)))
}

fn percent_encode(bytes: &[u8], upper: bool) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len() * 3);
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(*byte);
        } else {
            output.push(b'%');
            let digits = if upper {
                b"0123456789ABCDEF"
            } else {
                b"0123456789abcdef"
            };
            output.push(digits[usize::from(byte >> 4)]);
            output.push(digits[usize::from(byte & 0x0f)]);
        }
    }
    output
}

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut output = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(digits[usize::from(byte >> 4)]);
        output.push(digits[usize::from(byte & 0x0f)]);
    }
    output
}

fn metadata_changed(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
}

fn filename_check_id(check_id: &'static str) -> &'static str {
    match check_id {
        "raw_literal" => "filename_raw_literal",
        "json_escape" => "filename_json_escape",
        "shell_escape" => "filename_shell_escape",
        "percent_upper" => "filename_percent_upper",
        "percent_lower" => "filename_percent_lower",
        "base64_standard_padded" => "filename_base64_standard_padded",
        "base64_standard_unpadded" => "filename_base64_standard_unpadded",
        "base64_url_padded" => "filename_base64_url_padded",
        "base64_url_unpadded" => "filename_base64_url_unpadded",
        "hex_lower" => "filename_hex_lower",
        "hex_upper" => "filename_hex_upper",
        _ => "filename_unknown",
    }
}
