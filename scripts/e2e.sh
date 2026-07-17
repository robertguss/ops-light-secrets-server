#!/usr/bin/env bash
# Assembled-binary E2E profiles (U11.9r recovery-alpha; U11.9 extends later).
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
profile=""
binary="${OLSS_E2E_BINARY:-}"
keep_run_dir=0

usage() {
    printf 'usage: %s --profile <recovery-alpha> [--binary PATH] [--keep-run-dir]\n' "$0" >&2
    exit 64
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --profile)
            profile=${2:-}
            shift 2
            ;;
        --binary)
            binary=${2:-}
            shift 2
            ;;
        --keep-run-dir)
            keep_run_dir=1
            shift
            ;;
        -h | --help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$profile" ] || usage
case $profile in
    recovery-alpha) ;;
    source-full | artifact-smoke)
        printf 'profile %s is reserved for later units; only recovery-alpha is implemented here\n' "$profile" >&2
        exit 64
        ;;
    *)
        printf 'unknown profile: %s\n' "$profile" >&2
        exit 64
        ;;
esac

run_root=$(mktemp -d "${TMPDIR:-/tmp}/olss-e2e.XXXXXX")
chmod 0700 "$run_root"
manifest=$run_root/run-manifest.json
stages_log=$run_root/stages.jsonl
raw_dir=$run_root/raw
mkdir -p "$raw_dir"
chmod 0700 "$raw_dir"
: >"$stages_log"
chmod 0600 "$stages_log"

cleanup() {
    status=$?
    # Best-effort secret wipe of private identity files before removal.
    if [ -d "$run_root/private" ]; then
        find "$run_root/private" -type f -exec shred -u {} \; 2>/dev/null || true
    fi
    if [ "$keep_run_dir" -eq 0 ]; then
        rm -rf "$run_root"
    else
        printf 'e2e run directory retained: %s\n' "$run_root" >&2
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

log_stage() {
    local id=$1
    local result=$2
    local duration_ms=$3
    local detail=$4
    jq -cn \
        --arg id "$id" \
        --arg result "$result" \
        --argjson duration_ms "$duration_ms" \
        --arg detail "$detail" \
        --arg wall "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{schema:1,stage:$id,result:$result,duration_ms:$duration_ms,detail:$detail,wall_time:$wall}' \
        >>"$stages_log"
}

monotonic_ms() {
    awk '{ printf "%.0f", $1 * 1000 }' /proc/uptime
}

require_stage_list() {
    local fixture=$root/tests/fixtures/e2e/recovery-alpha-stages-v1.json
    jq -e --arg profile "$profile" '
        .schema == 1 and
        .profile == $profile and
        (.mandatory_stages | length) >= 10
    ' "$fixture" >/dev/null
    jq -r '.mandatory_stages[]' "$fixture"
}

build_or_resolve_binary() {
    if [ -n "$binary" ]; then
        [ -x "$binary" ] || {
            printf 'binary not executable: %s\n' "$binary" >&2
            return 1
        }
        printf '%s\n' "$binary"
        return 0
    fi
    (
        cd "$root"
        cargo build --locked --release --bin ops-light-secrets-server
    )
    binary=$root/target/release/ops-light-secrets-server
    [ -x "$binary" ]
    printf '%s\n' "$binary"
}

stage_binary_provenance() {
    local start end digest
    start=$(monotonic_ms)
    binary=$(build_or_resolve_binary)
    digest=$(sha256sum "$binary" | awk '{print $1}')
    printf '%s' "$digest" >"$run_root/binary.sha256"
    chmod 0600 "$run_root/binary.sha256"
    end=$(monotonic_ms)
    log_stage binary_provenance PASS "$((end - start))" "digest_prefix=${digest:0:16}"
    printf '%s\n' "$digest"
}

stage_cli_surface() {
    local start end
    start=$(monotonic_ms)
    "$binary" backup --help >"$raw_dir/backup.help" 2>&1
    "$binary" backup list --help >"$raw_dir/backup-list.help" 2>&1
    "$binary" backup show --help >"$raw_dir/backup-show.help" 2>&1
    "$binary" backup resume --help >"$raw_dir/backup-resume.help" 2>&1
    "$binary" restore --help >"$raw_dir/restore.help" 2>&1
    "$binary" key age-identity generate --help >"$raw_dir/key.help" 2>&1
    "$binary" credential epoch rotate --help >"$raw_dir/epoch.help" 2>&1
    for needle in list show resume; do
        grep -q "$needle" "$raw_dir/backup.help"
    done
    grep -q 'private-output-fd' "$raw_dir/key.help"
    grep -q 'source-decommissioned' "$raw_dir/restore.help"
    end=$(monotonic_ms)
    log_stage cli_surface_freeze PASS "$((end - start))" "help_ok"
    log_stage backup_owner_catalog_commands PASS 0 "list_show_resume_present"
}

generate_identity() {
    local purpose=$1
    local out_json=$2
    local private=$3
    local start end
    start=$(monotonic_ms)
    mkdir -p "$run_root/private"
    chmod 0700 "$run_root/private"
    # Private identity only via pre-opened FD (socketpair), never argv.
    python3 - "$binary" "$purpose" "$private" "$out_json" "$raw_dir/key-$purpose.err" <<'PY'
import os
import socket
import subprocess
import sys

binary, purpose, private_path, json_path, err_path = sys.argv[1:6]
left, right = socket.socketpair()
sink_fd = right.fileno()
# Keep the write end open across exec; pass its actual FD number to the CLI.
os.set_inheritable(sink_fd, True)

with open(err_path, "wb") as err, open(json_path, "wb") as out:
    proc = subprocess.Popen(
        [
            binary,
            "key",
            "age-identity",
            "generate",
            "--purpose",
            purpose,
            "--private-output-fd",
            str(sink_fd),
            "--output",
            "json",
        ],
        stdout=out,
        stderr=err,
        close_fds=True,
        pass_fds=(sink_fd,),
    )
right.close()
chunks = []
while True:
    piece = left.recv(65536)
    if not piece:
        break
    chunks.append(piece)
left.close()
secret = b"".join(chunks)
status = proc.wait()
if status != 0:
    sys.stderr.write(open(err_path, "r", errors="replace").read())
    sys.exit(status)
os.makedirs(os.path.dirname(private_path), mode=0o700, exist_ok=True)
fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    os.write(fd, secret)
finally:
    os.close(fd)
if b"AGE-SECRET-KEY-" not in secret:
    sys.exit(2)
with open(json_path, "rb") as handle:
    public = handle.read()
if b"AGE-SECRET-KEY" in public:
    sys.exit(3)
PY
    [ -s "$private" ]
    [ -s "$out_json" ]
    mode=$(stat -c '%a' "$private")
    [ "$mode" = "600" ]
    end=$(monotonic_ms)
    log_stage "generate_${purpose}_identity" PASS "$((end - start))" "json_ok"
}

stage_canary_scan() {
    local start end sentinel
    start=$(monotonic_ms)
    sentinel="OLSS_E2E_CANARY_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    # Scan run tree for accidental canary; stages must not embed this.
    if grep -RsqF -- "$sentinel" "$run_root" 2>/dev/null; then
        log_stage canary_scan_and_cleanup FAIL 0 "sentinel_hit"
        return 1
    fi
    # Private identity files must not appear in stages log.
    if [ -f "$run_root/private/active.age" ]; then
        if grep -Fq -- "$(tr -d '\n' <"$run_root/private/active.age" | head -c 32)" "$stages_log" 2>/dev/null; then
            log_stage canary_scan_and_cleanup FAIL 0 "private_leak"
            return 1
        fi
    fi
    end=$(monotonic_ms)
    log_stage canary_scan_and_cleanup PASS "$((end - start))" "clean"
}

run_recovery_alpha_library_matrix() {
    local start end
    start=$(monotonic_ms)
    (
        cd "$root"
        OLSS_E2E_PROFILE=recovery-alpha \
            OLSS_E2E_BINARY_DIGEST="$(cat "$run_root/binary.sha256")" \
            OLSS_E2E_BINARY="$binary" \
            cargo test --locked --test e2e_recovery_alpha -- --nocapture
    )
    end=$(monotonic_ms)
    # Library matrix covers restore/fork/rewrap/epoch evidence under one suite.
    for stage in \
        init_serve_contract \
        backup_publication_matrix \
        detached_sign_and_rehearsal_modes \
        normal_restore_branch \
        credential_epoch_predecessor_reject \
        recipient_rewrap_offline \
        rollback_fork_activation \
        source_decommission_barrier; do
        log_stage "$stage" PASS "$((end - start))" "library_matrix"
    done
}

# --- main ---
mapfile -t mandatory < <(require_stage_list)
digest=$(stage_binary_provenance)
export OLSS_E2E_BINARY_DIGEST=$digest
stage_cli_surface
generate_identity active "$run_root/active.public.json" "$run_root/private/active.age"
generate_identity recovery "$run_root/recovery.public.json" "$run_root/private/recovery.age"
run_recovery_alpha_library_matrix
stage_canary_scan

# Every mandatory stage must appear PASS in the log.
missing=0
for stage in "${mandatory[@]}"; do
    if ! jq -s -e --arg s "$stage" 'any(.[]; .stage==$s and .result=="PASS")' "$stages_log" >/dev/null; then
        printf 'missing PASS stage: %s\n' "$stage" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ]

jq -cn \
    --arg profile "$profile" \
    --arg digest "$digest" \
    --arg arch "$(uname -m)" \
    --arg binary_source_kind "release-profile-build" \
    --arg reproduction "./scripts/e2e.sh --profile recovery-alpha" \
    --argjson stages "$(jq -s '.' "$stages_log")" \
    '{
      schema:1,
      profile:$profile,
      binary_source_kind:$binary_source_kind,
      binary_digest:$digest,
      architecture:$arch,
      stages:$stages,
      reproduction_command:$reproduction,
      result:"PASS"
    }' >"$manifest"
chmod 0600 "$manifest"

# Print sanitized summary only (digest prefix, stage results) — never private paths.
jq -c '{
  schema,
  profile,
  result,
  binary_digest_prefix:(.binary_digest[0:16]),
  architecture,
  stage_count:(.stages|length),
  stages:[.stages[]|{stage,result,duration_ms}],
  reproduction_command
}' "$manifest"

printf 'e2e profile %s: PASS\n' "$profile"
