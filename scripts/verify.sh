#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
manifest=$root/scripts/verify-checks.json

random_id() {
    od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
}

monotonic_ms() {
    awk '{ printf "%.0f", $1 * 1000 }' /proc/uptime
}

scan_literal() {
    local file=$1
    local literal=$2
    local status

    set +e
    LC_ALL=C grep -aFq -- "$literal" "$file"
    status=$?
    set -e
    case $status in
        0) return 10 ;;
        1) return 0 ;;
        *) return 11 ;;
    esac
}

command_for() {
    local check=$1
    mapfile -t command < <(
        jq -er --arg check "$check" '
            .checks[] | select(.id == $check) | .program, (.args[]?)
        ' "$manifest"
    )
    ((${#command[@]} > 0))
}

command_text() {
    local text
    printf -v text '%q ' "${command[@]}"
    printf '%s' "${text% }"
}

self_test() {
    local directory sentinel failure_raw leak_raw status scan_status mode candidate
    directory=$(mktemp -d "${TMPDIR:-/tmp}/olss-verify-self-test.XXXXXX")
    chmod 0700 "$directory"
    sentinel="OLSS_BOOTSTRAP_CANARY_$(random_id)"
    failure_raw=$directory/failure.raw
    leak_raw=$directory/leak.raw
    : >"$failure_raw"
    chmod 0600 "$failure_raw"

    set +e
    sh -c 'printf "seeded safe failure detail\n" >&2; exit 23' >"$failure_raw" 2>&1
    status=$?
    set -e
    [[ $status -eq 23 ]]
    scan_literal "$failure_raw" "$sentinel"

    : >"$leak_raw"
    chmod 0600 "$leak_raw"
    printf '\0%s\0' "$sentinel" >"$leak_raw"
    scan_status=0
    scan_literal "$leak_raw" "$sentinel" || scan_status=$?
    [[ $scan_status -eq 10 ]]

    mode=$(stat -c '%a' "$failure_raw")
    candidate='{"schema":1,"self_test":"ok"}'
    [[ $candidate != *"$sentinel"* ]]
    rm -f "$failure_raw" "$leak_raw"
    rmdir "$directory"

    jq -cn \
        --argjson status "$status" \
        --arg mode "$mode" \
        '{schema:1,self_test:"ok",seeded_failure_step:"seeded-safe-failure",seeded_failure_exit:$status,leak_detected:true,sentinel_withheld:true,raw_mode:$mode,reproduction_command:"./scripts/verify.sh --self-test"}'
}

list_checks() {
    jq -r '.checks[].id' "$manifest"
}

run_check() {
    local check=$1
    local raw summary started finished status scan_status command_line event check_toolchain

    command_for "$check" || {
        printf 'unknown verification check: %s\n' "$check" >&2
        return 64
    }
    command_line=$(command_text)
    check_toolchain=$(jq -er --arg check "$check" '.checks[] | select(.id == $check) | .toolchain' "$manifest")
    raw=$run_directory/$check.raw
    summary=$run_directory/$check.summary.json
    : >"$raw"
    chmod 0600 "$raw"

    started=$(monotonic_ms)
    jq -cn \
        --arg run_id "$run_id" \
        --arg scenario_id "$check" \
        --arg wall_time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg command "$command_line" \
        --arg toolchain "$check_toolchain" \
        --arg runner_toolchain "$toolchain" \
        --arg os "$os" \
        --arg arch "$arch" \
        '{schema:1,event:"scenario_begin",run_id:$run_id,scenario_id:$scenario_id,wall_time:$wall_time,monotonic_ms:0,command:$command,toolchain:$toolchain,runner_toolchain:$runner_toolchain,os:$os,arch:$arch}'

    set +e
    "${command[@]}" >"$raw" 2>&1
    status=$?
    set -e
    finished=$(monotonic_ms)

    scan_status=0
    scan_literal "$raw" "$sentinel" || scan_status=$?
    case $scan_status in
        0) ;;
        10)
            status=97
            preserve=1
            ;;
        *)
            status=98
            preserve=1
            ;;
    esac

    event=$(jq -cn \
        --arg run_id "$run_id" \
        --arg scenario_id "$check" \
        --arg wall_time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg command "$command_line" \
        --arg toolchain "$check_toolchain" \
        --arg runner_toolchain "$toolchain" \
        --arg os "$os" \
        --arg arch "$arch" \
        --arg diagnostics_path "$summary" \
        --argjson duration_ms "$((finished - started))" \
        --argjson exit_status "$status" \
        --argjson scan_status "$scan_status" \
        '{schema:1,event:"scenario_end",run_id:$run_id,scenario_id:$scenario_id,wall_time:$wall_time,duration_ms:$duration_ms,expected:{exit_status:0},actual:{exit_status:$exit_status},command:$command,toolchain:$toolchain,runner_toolchain:$runner_toolchain,os:$os,arch:$arch,diagnostics_path:$diagnostics_path,sentinel_scan_status:$scan_status}')
    printf '%s\n' "$event" >"$summary"
    chmod 0600 "$summary"
    printf '%s\n' "$event"

    if [[ $scan_status -eq 10 ]]; then
        printf 'sentinel hit; raw output withheld\n' >&2
        return 97
    fi
    if [[ $scan_status -ne 0 ]]; then
        printf 'sentinel scanner error; raw output withheld\n' >&2
        return 98
    fi
    if [[ $status -ne 0 ]]; then
        preserve=1
        printf 'bounded sentinel-clean tail for %s:\n' "$check" >&2
        tail -n 40 "$raw" >&2
        printf 'reproduce: %s\n' "$command_line" >&2
        return "$status"
    fi
}

case ${1:-all} in
    --list)
        list_checks
        exit 0
        ;;
    --self-test)
        self_test
        exit 0
        ;;
esac

selection=${1:-all}
umask 077
run_directory=$(mktemp -d "${TMPDIR:-/tmp}/olss-verify.XXXXXX")
chmod 0700 "$run_directory"
run_id=$(random_id)
sentinel="OLSS_BOOTSTRAP_CANARY_$(random_id)"
toolchain=$(rustc --version)
os=$(uname -s)
arch=$(uname -m)
preserve=0

cleanup() {
    find "$run_directory" -type f -name '*.raw' -delete
    if [[ $preserve -eq 0 ]]; then
        find "$run_directory" -type f -delete
        rmdir "$run_directory"
    fi
}
trap cleanup EXIT

cd "$root"
if [[ $selection == all ]]; then
    while IFS= read -r check; do
        run_check "$check"
    done < <(list_checks)
else
    run_check "$selection"
fi
