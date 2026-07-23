#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

: "${BASHLUME_PACK:=bashlume-pack}"
rm -rf build
mkdir -p build .work
python3 compiler/sync.py --channel "${CHANNEL:-stable}" --checkout .work/upstream
python3 compiler/compile.py \
  --upstream .work/upstream \
  --output build/rules.json \
  --coverage build/coverage.json \
  --channel "${CHANNEL:-stable}" \
  --allow-incomplete
"$BASHLUME_PACK" build build/rules.json build/rules.blp
"$BASHLUME_PACK" verify build/rules.blp
python3 tests/coverage.py \
  --coverage build/coverage.json --spec build/rules.json --development

unsupported=$(python3 -c 'import json; print(json.load(open("build/coverage.json"))["unsupported_files"])')
if [[ $unsupported == 0 ]]; then
  python3 compiler/compile.py \
    --upstream .work/upstream \
    --output build/rules-stable.json \
    --coverage build/coverage-stable.json \
    --channel "${CHANNEL:-stable}"
  python3 tests/coverage.py \
    --coverage build/coverage-stable.json --spec build/rules-stable.json
else
  if python3 compiler/compile.py \
    --upstream .work/upstream \
    --output build/should-not-exist.json \
    --coverage build/strict-coverage.json \
    --channel "${CHANNEL:-stable}"; then
    echo 'strict compiler accepted an incomplete baseline' >&2
    exit 1
  fi
fi
