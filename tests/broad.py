#!/usr/bin/env python3
"""Classified full-baseline differential gate for pinned native Bash."""

from __future__ import annotations

import argparse
import concurrent.futures
from collections import Counter
import glob
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any


ERROR_CATEGORIES = {"semantic_diff", "oracle_error", "vm_error", "resource_truncated"}
FIXED_USERS = ["root", "snapshot-user"]
FIXED_GROUPS = ["root", "snapshot-group"]
FIXED_HOSTS = ["localhost", "snapshot-host"]
FIXED_PROCESS_IDS = ["1", "4242"]
FIXED_PROCESS_NAMES = ["init", "snapshot-worker"]
FIXED_NETWORK_INTERFACES = ["eth0", "lo"]
FIXED_SIGNALS = [
    "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "IOT", "BUS", "FPE",
    "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT",
    "CHLD", "CLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU",
    "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "POLL", "PWR", "SYS",
    "RT<N>", "RTMIN+<N>", "RTMAX-<N>",
]
BASH_BUILTINS = {
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd",
    "command", "compgen", "complete", "compopt", "continue", "declare", "dirs",
    "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fc",
    "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let", "local",
    "logout", "mapfile", "popd", "printf", "pushd", "pwd", "read", "readarray",
    "readonly", "return", "set", "shift", "shopt", "source", "suspend", "test",
    "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias",
    "unset", "wait",
}


def fixed_available_commands() -> list[str]:
    commands = set(BASH_BUILTINS)
    for directory in (pathlib.Path("/usr/bin"), pathlib.Path("/bin")):
        try:
            for entry in directory.iterdir():
                if entry.is_file() and os.access(entry, os.X_OK):
                    commands.add(entry.name)
        except OSError:
            pass
    return sorted(commands)


def fixed_snapshots() -> tuple[list[str], list[str], list[str]]:
    return FIXED_USERS.copy(), FIXED_GROUPS.copy(), FIXED_HOSTS.copy()


def literal_registration(command: str) -> bool:
    return bool(command) and not any(
        character.isspace() or character in "*?[]()|" for character in command
    )


def jobs_from_spec(spec: pathlib.Path) -> list[tuple[str, str, str]]:
    document = json.loads(spec.read_text(encoding="utf-8"))
    jobs: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for block in document["commands"]:
        scripts = block.get("scripts", [])
        source_for_command: dict[str, str] = {}
        for script in scripts:
            source = str(script.get("source_path") or block["source_path"]).split(";", 1)[0]
            for registration in script.get("registrations", []):
                source_for_command.setdefault(str(registration.get("command", "")), source)
        default_source = str(block["source_path"]).split(";", 1)[0]
        for command in map(str, block["registrations"]):
            if not literal_registration(command):
                continue
            source = source_for_command.get(command, default_source)
            for prefix in ("", "--"):
                job = (command, prefix, source)
                if job not in seen:
                    seen.add(job)
                    jobs.append(job)
    return jobs


def normalize(candidates: list[dict[str, object]], native: bool, prefix: str) -> list[list[object]]:
    output: list[list[object]] = []
    for record in candidates:
        candidate = record if native else record.get("candidate", record)
        value = str(candidate.get("value", ""))
        if prefix and not value.startswith(prefix):
            continue
        output.append(
            [
                value,
                candidate.get("display") or value,
                candidate.get("description") or "",
                candidate.get("kind"),
                candidate.get("append"),
            ]
        )
    return output


def resolve_filesystem_request(
    request: dict[str, object], working_directory: pathlib.Path
) -> list[str]:
    path = str(request["path"])
    if request["kind"] == "test" and not path:
        return []
    resolved = pathlib.Path(path)
    if not resolved.is_absolute():
        resolved = working_directory / resolved
    if request["kind"] == "glob":
        values = glob.glob(str(resolved))[:4096]
        if not pathlib.Path(path).is_absolute():
            values = [os.path.relpath(value, working_directory) for value in values]
        return values
    if request["kind"] == "read":
        try:
            descriptor = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                    return []
                data = os.read(descriptor, 1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    return []
                return data.decode("utf-8", "replace").splitlines()[:4096]
            finally:
                os.close(descriptor)
        except OSError:
            return []
    operator = str(request.get("operator", ""))
    try:
        predicates = {
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
        }
        matched = predicates.get(operator, lambda _value: False)(resolved)
    except OSError:
        matched = False
    return ["true"] if matched else []


def run_oracle(
    arguments: argparse.Namespace, case: dict[str, object]
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(arguments.oracle),
                "--upstream",
                str(arguments.upstream),
                "--case-json",
                json.dumps({**case, "capture_providers": True}, separators=(",", ":")),
            ],
            cwd=arguments.repository,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=arguments.oracle_timeout,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if completed.returncode:
        return None, completed.stderr[-2000:] or f"status {completed.returncode}"
    try:
        return json.loads(completed.stdout), None
    except json.JSONDecodeError as error:
        return None, f"invalid oracle JSON: {error}"


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
        raise ValueError(f"unknown probe parser: {parser}")
    values = [value.removesuffix("\r") for value in raw if value][:4096]
    return values, len(raw) > 4096


def probe_request_allowed(key: dict[str, object]) -> bool:
    executable = str(key.get("executable", ""))
    arguments = list(map(str, key.get("arguments", [])))
    if not executable or "/" in executable or executable in {"sh", "bash", "dash", "zsh", "fish"}:
        return False
    forwarding = {
        "env", "busybox", "toybox", "xargs", "find", "nice", "nohup",
        "timeout", "setsid", "stdbuf", "sudo", "doas", "chroot",
    }
    return executable not in forwarding or arguments in (["--help"], ["--version"])


def run_vm(
    arguments: argparse.Namespace, context: dict[str, object]
) -> tuple[dict[str, Any] | None, str | None]:
    completion_results: dict[str, list[str]] = {}
    probe_outcomes: dict[str, dict[str, object]] = {}
    for _ in range(8):
        context["completion_results"] = completion_results
        context["probe_outcomes"] = probe_outcomes
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as context_file:
            json.dump(context, context_file)
            context_file.flush()
            command = [arguments.pack_tool, "evaluate", str(arguments.pack), context_file.name]
            if arguments.verifying_key:
                command.append(str(arguments.verifying_key))
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=arguments.vm_timeout,
                )
            except subprocess.TimeoutExpired:
                return None, "timeout"
        if completed.returncode:
            return None, completed.stderr[-2000:] or f"status {completed.returncode}"
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            return None, f"invalid VM JSON: {error}"
        progressed = False
        for request in result.get("filesystem_requests", []):
            request_id = str(request["request_id"])
            if request_id in completion_results:
                continue
            completion_results[request_id] = resolve_filesystem_request(
                request, pathlib.Path(str(context["working_directory"]))
            )
            progressed = True
        if result.get("completion_requests"):
            return None, "Bash broad evaluation requested nested shell completion"
        unresolved = [
            probe
            for probe in result.get("probes", [])
            if probe["probe_id"] not in probe_outcomes
        ]
        for probe in unresolved:
            if not probe.get("dynamic_authorized"):
                return None, "explicit broad evaluation emitted an unauthorized probe"
            key = probe["key"]
            if not probe_request_allowed(key):
                probe_outcomes[probe["probe_id"]] = {
                    "status": 126,
                    "values": [],
                    "truncated": False,
                }
                progressed = True
                continue
            executable = shutil.which(str(key["executable"]), path="/usr/bin:/bin")
            if executable is None:
                probe_outcomes[probe["probe_id"]] = {
                    "status": 127,
                    "values": [],
                    "truncated": False,
                }
                progressed = True
                continue
            environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": str(arguments.home)}
            environment.update(dict(key.get("environment", [])))
            try:
                completed_probe = subprocess.run(
                    [executable, *key["arguments"]],
                    cwd=key["working_directory"],
                    env=environment,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=(subprocess.STDOUT if key.get("include_stderr") else subprocess.DEVNULL),
                    timeout=min(float(probe["timeout_ms"]) / 1000, 2.0),
                )
            except (OSError, subprocess.TimeoutExpired):
                probe_outcomes[probe["probe_id"]] = {
                    "status": 124,
                    "values": [],
                    "truncated": True,
                }
                progressed = True
                continue
            output_limit = min(int(probe["output_limit"]), 1024 * 1024)
            output = completed_probe.stdout[: output_limit + 1]
            values, truncated = parse_probe_output(output[:output_limit], key["parser"])
            probe_outcomes[probe["probe_id"]] = {
                "status": completed_probe.returncode,
                "values": values,
                "truncated": truncated or len(output) > output_limit,
            }
            progressed = True
        if not progressed:
            return result, None
    return None, "filesystem replay did not converge"


def dimensions(expected: dict[str, Any], actual: dict[str, Any], prefix: str) -> dict[str, Any]:
    return {
        "candidates_equal": normalize(expected.get("candidates", []), True, prefix)
        == normalize(actual.get("candidates", []), False, prefix),
        "path_equal": expected.get("path_completion", "inherit")
        == actual.get("path_completion", "inherit"),
        "status_equal": expected.get("completion_status") == actual.get("completion_status"),
        "expected_candidates": normalize(expected.get("candidates", []), True, prefix),
        "actual_candidates": normalize(actual.get("candidates", []), False, prefix),
        "expected_path": expected.get("path_completion", "inherit"),
        "actual_path": actual.get("path_completion", "inherit"),
        "expected_status": expected.get("completion_status"),
        "actual_status": actual.get("completion_status"),
    }


def provider_explains(
    detail: dict[str, Any], expected: dict[str, Any], actual: dict[str, Any]
) -> bool:
    mapping = expected.get("provider_candidates", {})
    if not isinstance(mapping, dict):
        return False
    attributed = {
        str(value)
        for values in mapping.values()
        if isinstance(values, list)
        for value in values
    }
    snapshots = set(map(str, actual.get("snapshot_providers", [])))
    if "process" in snapshots:
        attributed.update(
            str(item[0]) for item in detail["expected_candidates"] if str(item[0]).isdigit()
        )
    snapshot_values: set[str] = set()
    if "process" in snapshots:
        snapshot_values.update(FIXED_PROCESS_IDS)
        snapshot_values.update(FIXED_PROCESS_NAMES)
    if "network" in snapshots:
        snapshot_values.update(FIXED_NETWORK_INTERFACES)
    if "signal" in snapshots:
        snapshot_values.update(FIXED_SIGNALS)
    if "user" in snapshots:
        snapshot_values.update(FIXED_USERS)
    if "group" in snapshots:
        snapshot_values.update(FIXED_GROUPS)
    if "host" in snapshots:
        snapshot_values.update(FIXED_HOSTS)
    if not attributed and not snapshot_values:
        return False
    common_values = (
        {item[0] for item in detail["expected_candidates"]}
        & {item[0] for item in detail["actual_candidates"]}
        & attributed
    )
    for value in common_values:
        expected_records = {tuple(item[1:]) for item in detail["expected_candidates"] if item[0] == value}
        actual_records = {tuple(item[1:]) for item in detail["actual_candidates"] if item[0] == value}
        if expected_records != actual_records:
            return False
    expected_static = [
        item for item in detail["expected_candidates"] if item[0] not in attributed
    ]
    actual_static = [
        item
        for item in detail["actual_candidates"]
        if item[0] not in attributed and item[0] not in snapshot_values
    ]
    return expected_static == actual_static


def provider_status_explains(
    detail: dict[str, Any], expected: dict[str, Any], actual: dict[str, Any]
) -> bool:
    mapping = expected.get("provider_candidates", {})
    if not isinstance(mapping, dict):
        mapping = {}
    provider_values = {
        str(value)
        for values in mapping.values()
        if isinstance(values, list)
        for value in values
    }
    snapshots = set(map(str, actual.get("snapshot_providers", [])))
    snapshot_values: set[str] = set()
    if "process" in snapshots:
        snapshot_values.update(FIXED_PROCESS_IDS)
        snapshot_values.update(FIXED_PROCESS_NAMES)
    if "network" in snapshots:
        snapshot_values.update(FIXED_NETWORK_INTERFACES)
    if "signal" in snapshots:
        snapshot_values.update(FIXED_SIGNALS)
    if "user" in snapshots:
        snapshot_values.update(FIXED_USERS)
    if "group" in snapshots:
        snapshot_values.update(FIXED_GROUPS)
    if "host" in snapshots:
        snapshot_values.update(FIXED_HOSTS)
    expected_active = any(item[0] in provider_values for item in detail["expected_candidates"])
    actual_active = any(
        item[0] in provider_values or item[0] in snapshot_values
        for item in detail["actual_candidates"]
    )
    if expected_active and not actual_active:
        return detail["expected_status"] == 0 and detail["actual_status"] != 0
    if actual_active and not expected_active:
        return detail["actual_status"] == 0 and detail["expected_status"] != 0
    return False


def classify_job(
    arguments: argparse.Namespace, job: tuple[str, str, str]
) -> dict[str, Any]:
    command, prefix, source = job
    context: dict[str, object] = {
        "command": command,
        "current_word": prefix,
        "words": [command, prefix],
        "word_index": 1,
        "command_path": [command],
        "environment": {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C.UTF-8",
            "HOME": str(arguments.home),
        },
        "available_commands": arguments.available_commands,
        "shell_functions": [],
        "shell_variables": ["HOME", "LC_ALL", "PATH"],
        "shell_variable_values": {},
        "users": arguments.users,
        "groups": arguments.groups,
        "hosts": arguments.hosts,
        "process_ids": FIXED_PROCESS_IDS,
        "process_names": FIXED_PROCESS_NAMES,
        "network_interfaces": FIXED_NETWORK_INTERFACES,
        "signals": FIXED_SIGNALS,
        "working_directory": str(arguments.working_directory),
        "explicit_tab": True,
    }
    expected, oracle_error = run_oracle(
        arguments, {"source": source, "path": "/usr/bin:/bin", "context": context}
    )
    if oracle_error == "timeout":
        return {"job": job, "category": "resource_truncated", "side": "oracle"}
    if oracle_error:
        return {"job": job, "category": "oracle_error", "error": oracle_error}
    assert expected is not None
    native_available = bool(expected.get("available", True))
    actual, vm_error = run_vm(arguments, context)
    if vm_error == "timeout":
        return {"job": job, "category": "resource_truncated", "side": "vm"}
    if vm_error:
        return {"job": job, "category": "vm_error", "error": vm_error}
    assert actual is not None
    if actual.get("truncated"):
        return {"job": job, "category": "resource_truncated", "side": "vm"}
    if actual.get("denied_probe_count") or actual.get("broad_unsafe_probes"):
        return {
            "job": job,
            "category": "vm_error",
            "error": "broad evaluation emitted a denied or unsafe probe",
        }
    detail = dimensions(expected, actual, prefix)
    if all(detail[field] for field in ("candidates_equal", "path_equal", "status_equal")):
        return {"job": job, "category": "equal" if native_available else "inactive"}
    if command not in arguments.available_command_set:
        return {
            "job": job,
            "category": "context_dependent",
            "reason": "command is absent from the fixed target snapshot",
            "detail": detail,
        }
    providers = set(map(str, expected.get("provider_categories", [])))
    providers.update(map(str, actual.get("snapshot_providers", [])))
    if actual.get("filesystem_requests"):
        providers.add("filesystem")
    if actual.get("probes") or actual.get("denied_probe_count"):
        providers.add("external-program")
    candidate_explained = detail["candidates_equal"] or provider_explains(
        detail, expected, actual
    )
    path_explained = detail["path_equal"]
    status_explained = detail["status_equal"] or provider_status_explains(
        detail, expected, actual
    )
    if providers and candidate_explained and path_explained and status_explained:
        return {
            "job": job,
            "category": "provider_dependent",
            "providers": sorted(providers),
            "detail": detail,
        }
    return {
        "job": job,
        "category": "semantic_diff",
        "providers": sorted(providers),
        "detail": detail,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--spec", type=pathlib.Path, required=True)
    parser.add_argument("--pack", type=pathlib.Path, required=True)
    parser.add_argument("--pack-tool", default=os.environ.get("BASHLUME_PACK", "bashlume-pack"))
    parser.add_argument("--verifying-key", type=pathlib.Path)
    parser.add_argument("--oracle", type=pathlib.Path, default=pathlib.Path("tests/oracle.py"))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--oracle-timeout", type=float, default=45.0)
    parser.add_argument("--vm-timeout", type=float, default=30.0)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("build/broad.json"))
    arguments = parser.parse_args()
    arguments.repository = pathlib.Path.cwd()
    arguments.upstream = arguments.upstream.resolve()
    arguments.spec = arguments.spec.resolve()
    arguments.pack = arguments.pack.resolve()
    arguments.oracle = arguments.oracle.resolve()
    arguments.available_commands = fixed_available_commands()
    arguments.available_command_set = set(arguments.available_commands)
    arguments.users, arguments.groups, arguments.hosts = fixed_snapshots()
    arguments.working_directory = pathlib.Path(".work/broad-empty").resolve()
    shutil.rmtree(arguments.working_directory, ignore_errors=True)
    arguments.working_directory.mkdir(parents=True)
    arguments.home = pathlib.Path(".work/broad-home").resolve()
    shutil.rmtree(arguments.home, ignore_errors=True)
    arguments.home.mkdir(parents=True)
    jobs = jobs_from_spec(arguments.spec)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, arguments.workers)) as executor:
        results = list(executor.map(lambda job: classify_job(arguments, job), jobs))
    counts = Counter(result["category"] for result in results)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps({"counts": dict(sorted(counts.items())), "results": results}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(f"classified {len(results)} Bash broad cases: {dict(counts)}")
    failures = [result for result in results if result["category"] in ERROR_CATEGORIES]
    for result in failures:
        print(json.dumps(result, ensure_ascii=False), file=sys.stderr)
    if failures:
        print(f"Bash broad differential has {len(failures)} unexplained failures", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
