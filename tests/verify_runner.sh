#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

list=$(./scripts/verify.sh --list)
for check in lock-msrv fmt clippy test doc msrv-build msrv-test harness-clippy harness-test harness-msrv-test; do
    printf '%s\n' "$list" | grep -Fqx "$check"
done
jq -e '
    all(.checks[]; (.toolchain == "default" or .toolchain == "1.85.0")) and
    ([.checks[] | select(.id | . != "lock-msrv" and contains("msrv")) | .toolchain] | all(. == "1.85.0"))
' scripts/verify-checks.json >/dev/null

self_test=$(./scripts/verify.sh --self-test)
printf '%s\n' "$self_test" | jq -e '
    .schema == 1 and
    .self_test == "ok" and
    .seeded_failure_step == "seeded-safe-failure" and
    .seeded_failure_exit == 23 and
    .leak_detected == true and
    .sentinel_withheld == true and
    .raw_mode == "600"
' >/dev/null
if printf '%s\n' "$self_test" | grep -Fq 'OLSS_BOOTSTRAP_CANARY'; then
    printf 'self-test leaked sentinel marker\n' >&2
    exit 1
fi

grep -Fq 'actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5' .github/workflows/ci.yml
grep -Fq 'permissions:' .github/workflows/ci.yml
grep -Fq 'contents: read' .github/workflows/ci.yml
grep -Fq 'cancel-in-progress: true' .github/workflows/ci.yml
grep -Fq 'timeout-minutes:' .github/workflows/ci.yml
grep -Fq '  workflow_dispatch:' .github/workflows/ci.yml
if grep -Eq '^  (pull_request|push):' .github/workflows/ci.yml; then
    printf 'CI must remain manual-only; run verification locally\n' >&2
    exit 1
fi
# GitHub expands this expression in workflow YAML, not in this test shell.
# shellcheck disable=SC2016
matrix_invocation='./scripts/verify.sh "${{ matrix.check }}"'
grep -Fq "$matrix_invocation" .github/workflows/ci.yml
if grep -Fq 'upload-artifact' .github/workflows/ci.yml; then
    printf 'bootstrap CI must not upload raw artifacts\n' >&2
    exit 1
fi

printf 'verification runner contract: ok\n'
