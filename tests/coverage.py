#!/usr/bin/env python3
"""Enforce source-file, registration, and unsupported/stale coverage gates."""

from __future__ import annotations

import argparse
import json
import pathlib


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage", type=pathlib.Path, required=True)
    parser.add_argument("--spec", type=pathlib.Path, required=True)
    parser.add_argument("--development", action="store_true")
    arguments = parser.parse_args()

    coverage = json.loads(arguments.coverage.read_text(encoding="utf-8"))
    spec = json.loads(arguments.spec.read_text(encoding="utf-8"))
    if coverage["source_files"] != coverage["compiled_files"]:
        raise SystemExit("source files were omitted from conversion coverage")

    registrations: list[str] = []
    for command in spec["commands"]:
        registrations.extend(command["registrations"])
    if len(registrations) != len(set(registrations)):
        raise SystemExit("generated command registrations are not unique")
    if len(registrations) != coverage["registrations"]:
        raise SystemExit("coverage registration count does not match generated spec")

    unsupported = int(coverage["unsupported_files"])
    stale = set(spec["manifest"]["stale_commands"])
    reported_stale = {
        registration
        for item in coverage["files"]
        if item["unsupported"]
        for registration in item["registrations"]
    }
    if stale != reported_stale:
        raise SystemExit("development stale manifest does not exactly match unsupported rules")
    if arguments.development:
        if unsupported == 0:
            print("development baseline unexpectedly reached full coverage")
        else:
            print(f"development coverage accounted for {unsupported} unsupported source files")
        return 0
    if unsupported != 0 or stale:
        raise SystemExit(
            f"Stable gate failed: unsupported_files={unsupported} stale_commands={len(stale)}"
        )
    print("Stable full-baseline coverage gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
