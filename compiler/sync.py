#!/usr/bin/env python3
"""Fetch an exactly pinned completion-source checkout without executing it."""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import tempfile


def run(*arguments: str, cwd: pathlib.Path | None = None) -> str:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", choices=("stable", "edge"), required=True)
    parser.add_argument("--checkout", type=pathlib.Path, required=True)
    parser.add_argument("--lock", type=pathlib.Path, default=pathlib.Path("rules.lock"))
    parser.add_argument("--resolve-only", action="store_true")
    arguments = parser.parse_args()

    lock = json.loads(arguments.lock.read_text(encoding="utf-8"))
    source = lock["source"]
    channel = lock[arguments.channel]
    expected = channel["commit"]
    if arguments.resolve_only:
        resolved = run("git", "ls-remote", source, channel["ref"]).split()[0]
        print(resolved)
        return 0

    target = arguments.checkout.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bashlume-rules-sync-", dir=target.parent) as temporary:
        staging = pathlib.Path(temporary) / "upstream"
        run("git", "init", "--quiet", str(staging))
        run("git", "remote", "add", "origin", source, cwd=staging)
        run("git", "fetch", "--quiet", "--depth=1", "origin", expected, cwd=staging)
        run("git", "checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=staging)
        actual = run("git", "rev-parse", "HEAD", cwd=staging)
        if actual != expected:
            raise SystemExit(f"pinned commit mismatch: expected {expected}, got {actual}")
        if target.exists():
            shutil.rmtree(target)
        staging.rename(target)
    print(f"{arguments.channel}: {expected} -> {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
