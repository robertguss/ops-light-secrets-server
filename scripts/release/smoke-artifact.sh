#!/bin/sh
# U12.5: staged-artifact smoke — binary digest + --help + doctor self-check.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
binary=${1:-$root/target/release/ops-light-secrets-server}
test -x "$binary"
digest=$(sha256sum "$binary" | awk '{print $1}')
printf 'artifact digest %s\n' "$digest"
"$binary" --help >/dev/null
"$binary" doctor --help >/dev/null
# Never build when OLSS_RELEASE_ARTIFACT_ONLY=1
if [ "${OLSS_RELEASE_ARTIFACT_ONLY:-}" = 1 ]; then
  case $binary in
    *target/*) printf 'refusing in-tree target binary under artifact-only mode\n' >&2; exit 2 ;;
  esac
fi
printf 'release artifact smoke: ok\n'
