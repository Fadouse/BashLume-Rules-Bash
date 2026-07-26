#!/usr/bin/env python3
"""Compile the complete pinned bash-completion corpus through BashLume's shell VM frontend."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import tempfile

from common import git_commit


def source_files(upstream: pathlib.Path) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for directory in ("completions-core", "completions-fallback"):
        files.extend((upstream / directory).glob("*.bash"))
    return sorted(path.resolve() for path in files if path.is_file())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--coverage", type=pathlib.Path, default=pathlib.Path("build/coverage.json"))
    parser.add_argument("--channel", choices=("stable", "edge"), default="stable")
    parser.add_argument("--pack-version")
    arguments = parser.parse_args()

    repository = pathlib.Path(__file__).resolve().parents[1]
    lock = json.loads((repository / "rules.lock").read_text(encoding="utf-8"))
    compiler = lock["compiler"]
    compiler_commit = compiler["commit"]
    actual_compiler = os.environ.get("BASHLUME_COMPILER_COMMIT")
    if actual_compiler and actual_compiler != compiler_commit:
        raise SystemExit(
            f"compiler mismatch: expected {compiler_commit}, got {actual_compiler}"
        )

    upstream = arguments.upstream.resolve()
    files = source_files(upstream)
    if not files:
        raise SystemExit("no Bash completion modules found")
    support = upstream / "bash_completion"
    if not support.is_file():
        raise SystemExit("pinned bash_completion support library is missing")
    commit = git_commit(upstream)
    expected_commit = lock[arguments.channel]["commit"]
    if commit != expected_commit:
        raise SystemExit(
            f"pinned upstream mismatch: expected {expected_commit}, got {commit}"
        )
    pack_version = arguments.pack_version or f"0.0.0+{commit[:12]}"
    if not pack_version or "\0" in pack_version:
        raise SystemExit("pack version must be non-empty and contain no NUL")
    config = {
        "dialect": "bash",
        "source_root": str(upstream),
        "default_license": "GPL-2.0-or-later",
        "support_files": [str(support.resolve())],
        "support_roots": [
            str((upstream / "completions-core").resolve()),
            str((upstream / "completions-fallback").resolve()),
        ],
        "manifest": {
            "pack_id": "org.bashlume.rules.bash",
            "pack_version": pack_version,
            "source_kind": "bash",
            "source_repository": "https://github.com/scop/bash-completion.git",
            "source_commit": commit,
            "license_expression": "GPL-2.0-or-later",
            "channel": arguments.channel,
            "compiler_version": f"bashlume-{compiler['version']}+{compiler_commit[:12]}",
            "generated_at": "1970-01-01T00:00:00Z",
            "stale_commands": [],
            "probe_capabilities": [],
        },
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.coverage.parent.mkdir(parents=True, exist_ok=True)
    pack_tool = os.environ.get("BASHLUME_PACK", "bashlume-pack")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as config_file:
        json.dump(config, config_file, sort_keys=True)
        config_file.flush()
        subprocess.run(
            [
                pack_tool,
                "transpile-shell",
                config_file.name,
                str(arguments.output),
                str(arguments.coverage),
                *(str(path) for path in files),
            ],
            check=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
