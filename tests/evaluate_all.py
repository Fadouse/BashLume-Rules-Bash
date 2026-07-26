#!/usr/bin/env python3
"""Evaluate every registration in bounded passive contexts; VM limits are fatal."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import subprocess
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=pathlib.Path, required=True)
    parser.add_argument("--pack", type=pathlib.Path, required=True)
    parser.add_argument("--pack-tool", required=True)
    arguments = parser.parse_args()
    spec = json.loads(arguments.spec.read_text(encoding="utf-8"))
    registrations = sorted(
        {registration for command in spec["commands"] for registration in command["registrations"]}
    )

    def evaluate(job: tuple[str, str]) -> str | None:
        command, query = job
        context = {
            "command": command,
            "current_word": query,
            "words": [command, query],
            "word_index": 1,
            "command_path": [command],
            "environment": {},
            "working_directory": "/tmp",
            "explicit_tab": False,
        }
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="bashlume-evaluate-", suffix=".json", delete=False
        ) as stream:
            json.dump(context, stream)
            path = stream.name
        try:
            try:
                completed = subprocess.run(
                    [arguments.pack_tool, "evaluate", str(arguments.pack), path],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=20,
                )
            except subprocess.TimeoutExpired:
                return f"{command!r} query {query!r}: evaluation exceeded 20 seconds"
        finally:
            os.unlink(path)
        if completed.returncode:
            return f"{command!r} query {query!r}: {completed.stderr.strip()}"
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            return f"{command!r} query {query!r}: invalid evaluate JSON: {error}"
        if result.get("truncated"):
            return f"{command!r} query {query!r}: candidate result was truncated"
        if result.get("denied_probe_count"):
            return (
                f"{command!r} query {query!r}: "
                f"{result['denied_probe_count']} probe requests were denied"
            )
        if result.get("probes"):
            return f"{command!r} query {query!r}: passive evaluation requested a probe"
        return None

    jobs = [(registration, query) for registration in registrations for query in ("", "--")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 1)) as pool:
        errors = [error for error in pool.map(evaluate, jobs) if error]
    if errors:
        raise SystemExit("all-registration evaluation failed:\n" + "\n".join(errors[:50]))
    print(f"{len(registrations)} registrations passed bounded passive evaluation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
