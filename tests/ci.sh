#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

: "${BASHLUME_PACK:=bashlume-pack}"
: "${BASHLUME_COMPILER_CHECKOUT:=$root/../BashLume}"
compiler_expected=$(python3 -c 'import json; print(json.load(open("rules.lock"))["compiler"]["commit"])')
compiler_actual=$(git -C "$BASHLUME_COMPILER_CHECKOUT" rev-parse HEAD)
[[ $compiler_actual == "$compiler_expected" ]] || {
  echo "pinned compiler mismatch: expected $compiler_expected, got $compiler_actual" >&2
  exit 1
}
export BASHLUME_COMPILER_COMMIT=$compiler_actual
rm -rf build
mkdir -p build .work
if [[ ${BASHLUME_REUSE_UPSTREAM:-0} == 1 ]]; then
  expected=$(python3 -c 'import json, os; data=json.load(open("rules.lock")); print(data[os.environ.get("CHANNEL", "stable")]["commit"])')
  actual=$(git -C .work/upstream rev-parse HEAD)
  [[ $actual == "$expected" ]] || {
    echo "pinned upstream mismatch: expected $expected, got $actual" >&2
    exit 1
  }
else
  python3 compiler/sync.py --channel "${CHANNEL:-stable}" --checkout .work/upstream
fi
python3 compiler/compile.py \
  --upstream .work/upstream \
  --output build/rules.json \
  --coverage build/coverage.json \
  --channel "${CHANNEL:-stable}"
printf '%s\n' '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
  > build/test-signing-key.hex
"$BASHLUME_PACK" public-key build/test-signing-key.hex > build/test-verifying-key.hex
"$BASHLUME_PACK" build build/rules.json build/rules.blp build/test-signing-key.hex
"$BASHLUME_PACK" verify-spec \
  build/rules.json build/rules.blp build/test-verifying-key.hex
: "${BASH_ORACLE:?BASH_ORACLE must name the pinned Bash 5.3.9 binary}"
[[ $BASH_ORACLE == /* && -x $BASH_ORACLE ]] || {
  echo "BASH_ORACLE must be an absolute executable file" >&2
  exit 1
}
# Expanded by the pinned Bash subprocess.
# shellcheck disable=SC2016
bash_version=$("$BASH_ORACLE" --noprofile --norc -c 'printf "%s" "$BASH_VERSION"')
[[ $bash_version == 5.3.9* ]] || {
  echo "pinned Bash oracle must be 5.3.9, got $bash_version" >&2
  exit 1
}
oracle_real=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$BASH_ORACLE")
[[ $oracle_real == /nix/store/* ]] || {
  echo "broad parity requires the pinned Nix Bash oracle, got $oracle_real" >&2
  exit 1
}
command -v nix-store unshare >/dev/null || {
  echo 'broad parity requires nix-store and unshare' >&2
  exit 1
}
unshare --user --map-root-user --mount --net --uts --ipc --pid --fork \
  --kill-child --propagation private true || {
  echo 'rootless user/mount/network namespaces are unavailable' >&2
  exit 1
}
export BASH_ORACLE
python3 tests/differential.py \
  --upstream .work/upstream --pack build/rules.blp --pack-tool "$BASHLUME_PACK" \
  --verifying-key build/test-verifying-key.hex
python3 tests/broad.py \
  --upstream .work/upstream --spec build/rules.json --pack build/rules.blp \
  --pack-tool "$BASHLUME_PACK" --verifying-key build/test-verifying-key.hex \
  --output build/broad.json
python3 tests/provider_invariance.py --upstream .work/upstream
python3 tests/evaluate_all.py \
  --spec build/rules.json --pack build/rules.blp --pack-tool "$BASHLUME_PACK" \
  --verifying-key build/test-verifying-key.hex
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
  cmp --silent build/rules.json build/rules-stable.json
  cmp --silent build/coverage.json build/coverage-stable.json
  python3 compiler/provenance.py write \
    --upstream .work/upstream --spec build/rules.json --coverage build/coverage.json \
    --pack build/rules.blp --pack-tool "$BASHLUME_PACK" \
    --compiler-checkout "$BASHLUME_COMPILER_CHECKOUT" \
    --verifying-key build/test-verifying-key.hex --output build/bash.provenance.json
  python3 compiler/provenance.py verify \
    --upstream .work/upstream --spec build/rules.json --coverage build/coverage.json \
    --pack build/rules.blp --pack-tool "$BASHLUME_PACK" \
    --compiler-checkout "$BASHLUME_COMPILER_CHECKOUT" \
    --verifying-key build/test-verifying-key.hex --output build/bash.provenance.json
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
