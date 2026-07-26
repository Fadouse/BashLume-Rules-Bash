#!/usr/bin/env python3
"""Prove Bash provider attribution preserves native completion semantics."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys


CASES = (
    ("hash", "", "completions-core/hash.bash", "command"),
    ("export", "", "completions-core/export.bash", "variable"),
    ("ssh", "", "completions-core/ssh.bash", "host"),
    ("id", "", "completions-core/id.bash", "user"),
    ("groupdel", "", "completions-core/groupdel.bash", "group"),
)


def invoke(
    oracle: pathlib.Path,
    upstream: pathlib.Path,
    case: dict[str, object],
    capture: bool,
) -> dict[str, object]:
    completed = subprocess.run(
        [
            sys.executable,
            str(oracle),
            "--upstream",
            str(upstream),
            "--case-json",
            json.dumps({**case, "capture_providers": capture}, separators=(",", ":")),
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        env=os.environ.copy(),
    )
    return json.loads(completed.stdout)


def projection(result: dict[str, object]) -> tuple[object, ...]:
    return (
        result.get("candidates"),
        result.get("completion_status"),
        result.get("path_completion"),
        result.get("quote_behavior"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--oracle", type=pathlib.Path, default=pathlib.Path("tests/oracle.py"))
    arguments = parser.parse_args()
    upstream = arguments.upstream.resolve()
    oracle = arguments.oracle.resolve()
    working_directory = pathlib.Path(".work/provider-invariance-empty").resolve()
    shutil.rmtree(working_directory, ignore_errors=True)
    working_directory.mkdir(parents=True)
    for command, prefix, source, expected_provider in CASES:
        context = {
            "command": command,
            "current_word": prefix,
            "words": [command, prefix],
            "word_index": 1,
            "working_directory": str(working_directory),
            "environment": {},
        }
        case = {"source": source, "path": "/usr/bin:/bin", "context": context}
        baseline = invoke(oracle, upstream, case, False)
        captured = invoke(oracle, upstream, case, True)
        if projection(baseline) != projection(captured):
            raise SystemExit(f"provider capture changed native completion for {command!r}")
        providers = set(map(str, captured.get("provider_categories", [])))
        if expected_provider not in providers:
            raise SystemExit(
                f"provider capture did not attribute {command!r} to {expected_provider!r}: "
                f"{sorted(providers)!r}"
            )
        native_values = {
            str(candidate.get("value", "")) for candidate in captured.get("candidates", [])
        }
        attributed = {
            str(value)
            for values in captured.get("provider_candidates", {}).values()
            for value in values
        }
        if not attributed.issubset(native_values):
            raise SystemExit(f"provider attribution escaped native candidates for {command!r}")
    print(f"Bash provider invariance passed for {len(CASES)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
