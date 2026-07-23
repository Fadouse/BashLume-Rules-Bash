#!/usr/bin/env python3
"""Exact normalized source-oracle versus Completion IR differential runner."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile


def normalize(candidates: list[dict[str, object]]) -> list[tuple[object, ...]]:
    return sorted(
        (
            item.get("value"),
            item.get("display") or item.get("value"),
            item.get("description"),
            item.get("kind"),
            item.get("append"),
        )
        for item in candidates
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--pack", type=pathlib.Path, required=True)
    parser.add_argument("--cases", type=pathlib.Path, default=pathlib.Path("tests/cases.json"))
    parser.add_argument(
        "--pack-tool",
        default=os.environ.get("BASHLUME_PACK", "bashlume-pack"),
    )
    arguments = parser.parse_args()

    if not arguments.cases.is_file():
        raise SystemExit("Stable differential corpus is missing")
    cases = json.loads(arguments.cases.read_text(encoding="utf-8"))
    if not cases:
        raise SystemExit("Stable differential corpus is empty")

    for index, case in enumerate(cases):
        oracle = subprocess.run(
            [
                sys.executable,
                "tests/oracle.py",
                "--upstream",
                str(arguments.upstream),
                "--case-json",
                json.dumps(case, separators=(",", ":")),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        expected = json.loads(oracle.stdout)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as context_file:
            json.dump(case["context"], context_file)
            context_file.flush()
            evaluated = subprocess.run(
                [arguments.pack_tool, "evaluate", str(arguments.pack), context_file.name],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        actual = json.loads(evaluated.stdout)["candidates"]
        if normalize(actual) != normalize(expected):
            raise SystemExit(
                f"case {index} ({case.get('name', case['context']['command'])}) differs:\n"
                f"expected={normalize(expected)!r}\nactual={normalize(actual)!r}"
            )
    print(f"{len(cases)} exact normalized differential cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
