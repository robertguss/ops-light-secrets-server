#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

python3 -m unittest discover -s "$root/research/compat/capture" -p 'test_*.py' -v
python3 "$root/research/compat/capture/replay.py" \
    "$root/research/compat/capture/observations.json"
