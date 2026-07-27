#!/usr/bin/env python3
"""Exact pinned-Bash oracle versus Completion IR differential runner."""

from __future__ import annotations

import argparse
import glob
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile


def normalize(candidates: list[dict[str, object]], prefix: str) -> list[tuple[object, ...]]:
    normalized: list[tuple[object, ...]] = []
    for item in candidates:
        item = item.get("candidate", item)
        value = str(item.get("value", ""))
        if prefix and not value.startswith(prefix):
            continue
        normalized.append(
            (
                value,
                item.get("display") or value,
                item.get("description"),
                item.get("kind"),
                item.get("append"),
            )
        )
    return normalized


def parse_probe_output(output: bytes, parser: str) -> tuple[list[str], bool]:
    text = output.decode("utf-8", "replace")
    if parser == "lines":
        raw = text.splitlines()
    elif parser == "words":
        raw = text.split()
    elif parser == "nul":
        raw = text.split("\0")
    elif parser == "colon-first":
        raw = [line.partition(":")[0] for line in text.splitlines()]
    elif parser == "tab-first":
        raw = [line.partition("\t")[0] for line in text.splitlines()]
    else:
        raise RuntimeError(f"unknown probe parser: {parser}")
    values: list[str] = []
    for value in raw:
        value = value.removesuffix("\r")
        if not value or len(value.encode()) > 64 * 1024:
            continue
        if len(values) == 4096:
            return values, True
        values.append(value)
    return values, False


def compile_fixtures(cases: list[dict[str, object]], directory: pathlib.Path) -> None:
    fixtures: dict[str, dict[str, str]] = {}
    for case in cases:
        fixtures.update(case.get("fixture_executables", {}))
    for name, responses in fixtures.items():
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is None:
            raise RuntimeError(f"invalid fixture executable name: {name!r}")
        statements = [
            f"if (argc > 1 && strcmp(argv[1], {json.dumps(argument)}) == 0) "
            f"{{ fputs({json.dumps(output)}, stdout); return 0; }}"
            for argument, output in responses.items()
        ]
        source = directory / f"{name}.c"
        source.write_text(
            "#include <stdio.h>\n#include <string.h>\nint main(int argc, char **argv) {\n"
            + "\n".join(statements)
            + "\nreturn 1;\n}\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["cc", "-O2", "-o", str(directory / name), str(source)],
            check=True,
            stdin=subprocess.DEVNULL,
        )


def evaluate_case(
    arguments: argparse.Namespace,
    case: dict[str, object],
    process_environment: dict[str, str],
    index: int,
) -> dict[str, object]:
    context = dict(case["context"])
    probe_outcomes: dict[str, dict[str, object]] = {}
    probe_results: dict[str, list[str]] = {}
    probe_failures: set[str] = set()
    completion_results: dict[str, list[str]] = {}
    for _ in range(8):
        context["probe_outcomes"] = probe_outcomes
        context["probe_results"] = probe_results
        context["probe_failures"] = sorted(probe_failures)
        context["completion_results"] = completion_results
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as context_file:
            json.dump(context, context_file)
            context_file.flush()
            command = [arguments.pack_tool, "evaluate", str(arguments.pack), context_file.name]
            if arguments.verifying_key:
                command.append(str(arguments.verifying_key))
            evaluated = subprocess.run(
                command,
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=process_environment,
            )
        actual = json.loads(evaluated.stdout)
        progressed = False
        for request in actual.get("filesystem_requests", []):
            request_id = request["request_id"]
            if request_id in completion_results:
                continue
            path = request["path"]
            working_directory = context.get("working_directory", ".")
            resolved_path = path if os.path.isabs(path) else os.path.join(working_directory, path)
            if request["kind"] == "glob":
                values = sorted(glob.glob(resolved_path))[:4096]
                if not os.path.isabs(path):
                    values = [os.path.relpath(value, working_directory) for value in values]
            elif request["kind"] == "read":
                values = []
                try:
                    descriptor = os.open(resolved_path, os.O_RDONLY | os.O_NONBLOCK)
                    try:
                        metadata = os.fstat(descriptor)
                        if stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 1024 * 1024:
                            data = os.read(descriptor, 1024 * 1024 + 1)
                            if len(data) <= 1024 * 1024:
                                values = data.decode("utf-8", "replace").splitlines()[:4096]
                    finally:
                        os.close(descriptor)
                except OSError:
                    pass
            else:
                operator = request.get("operator")
                try:
                    matched = {
                        "-e": os.path.exists,
                        "-f": os.path.isfile,
                        "-d": os.path.isdir,
                        "-b": lambda value: stat.S_ISBLK(os.stat(value).st_mode),
                        "-c": lambda value: stat.S_ISCHR(os.stat(value).st_mode),
                        "-p": lambda value: stat.S_ISFIFO(os.stat(value).st_mode),
                        "-S": lambda value: stat.S_ISSOCK(os.stat(value).st_mode),
                        "-L": os.path.islink,
                        "-h": os.path.islink,
                        "-s": lambda value: os.path.getsize(value) > 0,
                        "-r": lambda value: os.access(value, os.R_OK),
                        "-w": lambda value: os.access(value, os.W_OK),
                        "-x": lambda value: os.access(value, os.X_OK),
                    }.get(operator, lambda _value: False)(resolved_path)
                except OSError:
                    matched = False
                values = ["true"] if matched else []
            completion_results[request_id] = values
            progressed = True
        resolved = probe_outcomes.keys() | probe_results.keys() | probe_failures
        pending = [probe for probe in actual["probes"] if probe["probe_id"] not in resolved]
        if not pending and not progressed:
            if actual["probes"]:
                raise SystemExit(f"case {index} retained already-resolved probes")
            if actual["denied_probe_count"]:
                raise SystemExit(f"case {index} denied an expected probe")
            return actual
        if pending and not case["context"].get("explicit_tab"):
            raise SystemExit(f"case {index} unexpectedly requested a passive probe")
        for probe in pending:
            if not probe.get("dynamic_authorized"):
                raise SystemExit(f"case {index} emitted an unauthorized probe")
            key = probe["key"]
            probe_environment = {
                name: process_environment[name]
                for name in ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM")
                if name in process_environment
            }
            probe_environment.update(dict(key["environment"]))
            completed_probe = subprocess.run(
                [key["executable"], *key["arguments"]],
                cwd=key["working_directory"],
                env=probe_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=(subprocess.STDOUT if key.get("include_stderr") else subprocess.DEVNULL),
                timeout=probe["timeout_ms"] / 1000,
                check=False,
            )
            if len(completed_probe.stdout) > probe["output_limit"]:
                raise SystemExit(f"case {index} probe exceeded its output limit")
            values, truncated = parse_probe_output(completed_probe.stdout, key["parser"])
            probe_outcomes[probe["probe_id"]] = {
                "status": completed_probe.returncode,
                "values": values,
                "truncated": truncated,
            }
            progressed = True
    raise SystemExit(f"case {index} did not converge after eight probe replay rounds")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--pack", type=pathlib.Path, required=True)
    parser.add_argument("--cases", type=pathlib.Path, default=pathlib.Path("tests/cases.json"))
    parser.add_argument("--pack-tool", default=os.environ.get("BASHLUME_PACK", "bashlume-pack"))
    parser.add_argument("--verifying-key", type=pathlib.Path)
    arguments = parser.parse_args()
    cases = json.loads(arguments.cases.read_text(encoding="utf-8"))
    if not cases:
        raise SystemExit("Stable differential corpus is empty")

    with tempfile.TemporaryDirectory(prefix="bashlume-bash-fixtures-") as fixture_directory:
        fixture_directory = pathlib.Path(fixture_directory)
        compile_fixtures(cases, fixture_directory)
        working_directory = pathlib.Path(".work/differential-empty").resolve()
        shutil.rmtree(working_directory, ignore_errors=True)
        working_directory.mkdir(parents=True)
        for index, original_case in enumerate(cases):
            case = dict(original_case)
            case["context"] = dict(original_case["context"])
            case["context"]["working_directory"] = str(working_directory)
            process_environment = os.environ.copy()
            if case.get("fixture_executables"):
                fixture_path = f"{fixture_directory}:{process_environment.get('PATH', '')}"
                case["path"] = fixture_path
                process_environment["PATH"] = fixture_path
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
                env=process_environment,
            )
            expected = json.loads(oracle.stdout)
            if not expected.get("available", True):
                raise SystemExit(f"case {index} has no active native Bash registration")
            actual = evaluate_case(arguments, case, process_environment, index)
            prefix = case["context"]["current_word"]
            expected_candidates = normalize(expected["candidates"], prefix)
            actual_candidates = normalize(actual["candidates"], prefix)
            if actual_candidates != expected_candidates:
                raise SystemExit(
                    f"case {index} ({case['name']}) differs:\n"
                    f"expected={expected_candidates!r}\nactual={actual_candidates!r}"
                )
            expected_status = expected.get("completion_status")
            actual_status = actual.get("completion_status")
            if actual_status != expected_status:
                raise SystemExit(
                    f"case {index} ({case['name']}) status differs: "
                    f"expected={expected_status!r} actual={actual_status!r}"
                )
            expected_path = expected.get("path_completion", "inherit")
            actual_path = actual.get("path_completion", "inherit")
            if actual_path != expected_path:
                raise SystemExit(
                    f"case {index} ({case['name']}) path policy differs: "
                    f"expected={expected_path!r} actual={actual_path!r}"
                )
            actual_quote = "filename" if actual_path in {"files", "directories"} else "literal"
            if actual_quote != expected.get("quote_behavior"):
                raise SystemExit(
                    f"case {index} ({case['name']}) quote behavior differs: "
                    f"expected={expected.get('quote_behavior')!r} actual={actual_quote!r}"
                )
    print(f"{len(cases)} exact ordered Bash differential cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
