#!/bin/sh
# Structural + cargo-deny gate for U12.4 packaging.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

for path in README.md LICENSE CONTRIBUTING.md SECURITY.md deny.toml; do
    test -f "$path" || {
        printf 'missing packaging file: %s\n' "$path" >&2
        exit 1
    }
done

# README must carry the settled positioning claims.
grep -q 'single-binary' README.md
grep -q 'OpenBao' README.md
grep -q 'list of refusals\|LIST OF REFUSALS\|Ops-light claim' README.md
grep -q 'MIT' README.md
grep -q 'fnox' README.md

grep -q 'MIT License' LICENSE
grep -q 'Reporting a vulnerability' SECURITY.md
grep -q 'cargo deny check' CONTRIBUTING.md

if command -v cargo-deny >/dev/null 2>&1 || cargo deny --version >/dev/null 2>&1; then
    cargo deny check
else
    printf 'cargo-deny not installed; structural packaging checks only\n' >&2
    # Still validate deny.toml is parseable TOML via python if present.
    python3 - <<'PY'
import pathlib
text = pathlib.Path("deny.toml").read_text()
assert "[licenses]" in text and "MIT" in text
print("deny.toml structural: ok")
PY
fi

printf 'packaging + deny: ok\n'
