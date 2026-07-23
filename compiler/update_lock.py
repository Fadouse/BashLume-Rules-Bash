#!/usr/bin/env python3
"""Resolve an upstream channel and update rules.lock for a review PR."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess


def ls_remote(source: str, pattern: str) -> list[tuple[str, str]]:
    output = subprocess.run(
        ["git", "ls-remote", source, pattern],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout
    return [(line.split()[0], line.split()[1]) for line in output.splitlines() if line]


def version_key(ref: str) -> tuple[int, ...]:
    return tuple(map(int, re.findall(r"\d+", ref)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", choices=("stable", "edge"), required=True)
    parser.add_argument("--lock", type=pathlib.Path, default=pathlib.Path("rules.lock"))
    arguments = parser.parse_args()
    data = json.loads(arguments.lock.read_text(encoding="utf-8"))
    source = data["source"]
    channel = data[arguments.channel]

    if arguments.channel == "edge":
        rows = ls_remote(source, f"refs/heads/{channel['ref']}")
        if len(rows) != 1:
            raise SystemExit("edge branch did not resolve uniquely")
        commit = rows[0][0]
        ref = channel["ref"]
    else:
        expression = re.compile(data["stable_tag_regex"])
        rows = ls_remote(source, "refs/tags/*")
        tags: dict[str, str] = {}
        for commit, full_ref in rows:
            ref = full_ref.removeprefix("refs/tags/")
            peeled = ref.endswith("^{}")
            ref = ref.removesuffix("^{}")
            if expression.fullmatch(ref) and (peeled or ref not in tags):
                tags[ref] = commit
        if not tags:
            raise SystemExit("no stable tag matched stable_tag_regex")
        ref = max(tags, key=version_key)
        commit = tags[ref]

    changed = channel["ref"] != ref or channel["commit"] != commit
    channel["ref"] = ref
    channel["commit"] = commit
    arguments.lock.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"changed": changed, "ref": ref, "commit": commit}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
