#!/usr/bin/env python3
"""Create and verify deterministic BashLume rule-pack provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Any

MAX_JSON_BYTES = 128 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_SOURCE_FILES = 65_536


def read_json(path: pathlib.Path) -> Any:
    data = path.read_bytes()
    if len(data) > MAX_JSON_BYTES:
        raise ValueError(f"{path} exceeds the JSON size limit")
    return json.loads(data)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARTIFACT_BYTES:
                raise ValueError(f"{path} exceeds the artifact size limit")
            digest.update(chunk)
    return digest.hexdigest()


def git(checkout: pathlib.Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def require_tracked_clean(checkout: pathlib.Path, name: str) -> None:
    status = git(checkout, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ValueError(f"{name} checkout is not clean")


def git_bytes(checkout: pathlib.Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def git_tree(checkout: pathlib.Path) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for record in git_bytes(checkout, "ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        safe_relative(path)
        entries[path] = (mode, kind, object_id)
    return entries


def compiler_inputs(
    source_kind: str, entries: set[str]
) -> tuple[set[str], set[str]]:
    if source_kind == "bash":
        primary = {
            path
            for path in entries
            if len(pathlib.PurePosixPath(path).parts) == 2
            and pathlib.PurePosixPath(path).parts[0]
            in ("completions-core", "completions-fallback")
            and path.endswith(".bash")
        }
        all_inputs = {
            path
            for path in entries
            if path == "bash_completion"
            or path.startswith("completions-core/")
            or path.startswith("completions-fallback/")
        }
    elif source_kind == "fish":
        primary = {
            path
            for path in entries
            if len(pathlib.PurePosixPath(path).parts) == 3
            and path.startswith("share/completions/")
            and path.endswith(".fish")
        }
        all_inputs = primary | {
            path for path in entries if path.startswith("share/functions/")
        }
    elif source_kind == "zsh":
        primary = {
            path
            for path in entries
            if len(pathlib.PurePosixPath(path).parts) == 4
            and pathlib.PurePosixPath(path).parts[0] == "Completion"
            and pathlib.PurePosixPath(path).parts[2] == "Command"
            and pathlib.PurePosixPath(path).name.startswith("_")
        }
        all_inputs = {
            path
            for path in entries
            if path.startswith("Completion/") or path.startswith("Functions/")
        }
    else:
        raise ValueError(f"unsupported source kind: {source_kind}")
    return primary, all_inputs


def git_blob(checkout: pathlib.Path, object_id: str) -> bytes:
    data = git_bytes(checkout, "cat-file", "blob", object_id)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("Git source blob exceeds the artifact size limit")
    return data


def safe_relative(value: str) -> pathlib.PurePosixPath:
    if not value or "\\" in value or "\0" in value:
        raise ValueError(f"invalid provenance path: {value!r}")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"invalid provenance path: {value!r}")
    return path


def source_path(root: pathlib.Path, value: str) -> pathlib.Path:
    relative = safe_relative(value)
    path = root.joinpath(*relative.parts)
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"source path escapes checkout: {value}") from error
    return path


def combined_license(expressions: set[str]) -> str:
    return " AND ".join(
        f"({expression})" if " OR " in expression else expression
        for expression in sorted(expressions)
    )


def license_identifiers(expression: str) -> set[str]:
    token_pattern = re.compile(r"\s*(\(|\)|AND|OR|WITH|[A-Za-z0-9][A-Za-z0-9.+-]*)")
    tokens: list[str] = []
    position = 0
    while position < len(expression):
        match = token_pattern.match(expression, position)
        if match is None:
            raise ValueError(f"invalid SPDX expression: {expression}")
        tokens.append(match.group(1))
        position = match.end()
    if not tokens:
        raise ValueError("empty SPDX expression")
    index = 0
    identifiers: set[str] = set()

    def factor() -> None:
        nonlocal index
        if index >= len(tokens):
            raise ValueError(f"incomplete SPDX expression: {expression}")
        if tokens[index] == "(":
            index += 1
            disjunction()
            if index >= len(tokens) or tokens[index] != ")":
                raise ValueError(f"unclosed SPDX expression: {expression}")
            index += 1
        elif tokens[index] not in ("AND", "OR", "WITH", ")"):
            identifiers.add(tokens[index])
            index += 1
        else:
            raise ValueError(f"invalid SPDX expression: {expression}")
        if index < len(tokens) and tokens[index] == "WITH":
            index += 1
            if index >= len(tokens) or tokens[index] in ("AND", "OR", "WITH", "(", ")"):
                raise ValueError(f"invalid SPDX exception: {expression}")
            identifiers.add(tokens[index])
            index += 1

    def conjunction() -> None:
        nonlocal index
        factor()
        while index < len(tokens) and tokens[index] == "AND":
            index += 1
            factor()

    def disjunction() -> None:
        nonlocal index
        conjunction()
        while index < len(tokens) and tokens[index] == "OR":
            index += 1
            conjunction()

    disjunction()
    if index != len(tokens):
        raise ValueError(f"invalid SPDX expression: {expression}")
    return identifiers


def resolve_executable(value: str) -> pathlib.Path:
    candidate = pathlib.Path(value)
    if candidate.parent == pathlib.Path("."):
        found = shutil.which(value)
        if found is None:
            raise ValueError(f"executable not found: {value}")
        candidate = pathlib.Path(found)
    candidate = candidate.resolve(strict=True)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ValueError(f"not an executable file: {candidate}")
    return candidate


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def compute(arguments: argparse.Namespace) -> dict[str, Any]:
    repository = pathlib.Path(__file__).resolve().parents[1]
    upstream = arguments.upstream.resolve(strict=True)
    compiler_checkout = arguments.compiler_checkout.resolve(strict=True)
    spec_path = arguments.spec.resolve(strict=True)
    coverage_path = arguments.coverage.resolve(strict=True)
    pack_path = arguments.pack.resolve(strict=True)
    pack_tool = resolve_executable(arguments.pack_tool)
    verifying_key = (
        arguments.verifying_key.resolve(strict=True) if arguments.verifying_key else None
    )

    require_tracked_clean(repository, "rule repository")
    require_tracked_clean(upstream, "upstream")
    require_tracked_clean(compiler_checkout, "compiler")
    expected_pack_tool = (
        compiler_checkout / "target" / "release" / "bashlume-pack"
    ).resolve(strict=True)
    if pack_tool != expected_pack_tool:
        raise ValueError("pack tool is not the binary built in the pinned compiler checkout")

    lock_path = repository / "rules.lock"
    lock = read_json(lock_path)
    if lock.get("schema") != 1:
        raise ValueError("unsupported rules.lock schema")
    spec = read_json(spec_path)
    coverage = read_json(coverage_path)
    manifest = spec["manifest"]
    channel = manifest["channel"]
    if channel not in ("stable", "edge"):
        raise ValueError(f"invalid pack channel: {channel}")

    if manifest["source_repository"] != lock["source"]:
        raise ValueError("source repository does not match rules.lock")
    source_commit = git(upstream, "rev-parse", "HEAD")
    expected_source = lock[channel]["commit"]
    if source_commit != expected_source or manifest["source_commit"] != source_commit:
        raise ValueError("source checkout, lock, and pack manifest commits differ")
    if coverage.get("schema") != 3 or coverage.get("source_commit") != source_commit:
        raise ValueError("coverage schema/source commit mismatch")

    compiler_commit = git(compiler_checkout, "rev-parse", "HEAD")
    expected_compiler = lock["compiler"]["commit"]
    if compiler_commit != expected_compiler:
        raise ValueError("compiler checkout does not match rules.lock")
    expected_compiler_version = (
        f"bashlume-{lock['compiler']['version']}+{compiler_commit[:12]}"
    )
    if manifest["compiler_version"] != expected_compiler_version:
        raise ValueError("pack manifest compiler identity does not match rules.lock")

    tree_entries = git_tree(upstream)
    expected_primary, expected_inputs = compiler_inputs(
        manifest["source_kind"], set(tree_entries)
    )
    licenses_path = repository / "provenance" / "licenses.json"
    license_policy = read_json(licenses_path)
    if license_policy.get("schema") != 1:
        raise ValueError("unsupported license policy schema")
    if manifest["license_expression"] != license_policy.get("pack_expression"):
        raise ValueError("pack license expression does not match the audited policy")
    overrides = license_policy.get("overrides", {})
    if set(overrides) - expected_inputs:
        raise ValueError("license policy override references a non-input source")

    records: dict[str, dict[str, Any]] = {}
    primary_paths: set[str] = set()
    for role, entries in (("primary", coverage["files"]), ("support", coverage["support"])):
        if not isinstance(entries, list):
            raise ValueError(f"coverage {role} records are not a list")
        for entry in entries:
            path_value = entry["path"]
            if path_value in records:
                raise ValueError(f"duplicate source provenance path: {path_value}")
            path = source_path(upstream, path_value)
            resolved_value = entry.get("resolved_path")
            if path.is_symlink():
                if not resolved_value:
                    raise ValueError(f"symlink lacks resolved_path: {path_value}")
                expected_resolved = source_path(upstream, resolved_value).resolve(strict=True)
                if path.resolve(strict=True) != expected_resolved:
                    raise ValueError(f"symlink target mismatch: {path_value}")
            elif resolved_value:
                raise ValueError(f"non-symlink declares resolved_path: {path_value}")
            if sha256_file(path) != entry["sha256"]:
                raise ValueError(f"source digest mismatch: {path_value}")
            mode, kind, object_id = tree_entries.get(path_value, (None, None, None))
            if kind != "blob" or mode is None or object_id is None:
                raise ValueError(f"source is not a blob in the pinned Git tree: {path_value}")
            blob = git_blob(upstream, object_id)
            if mode == "120000":
                if not path.is_symlink() or os.readlink(path).encode() != blob:
                    raise ValueError(f"Git symlink mismatch: {path_value}")
                if not resolved_value or resolved_value not in tree_entries:
                    raise ValueError(f"Git symlink target is not tracked: {path_value}")
            elif hashlib.sha256(blob).hexdigest() != entry["sha256"]:
                raise ValueError(f"source differs from the pinned Git blob: {path_value}")
            license_expression = entry["license"]
            license_identifiers(license_expression)
            expected_license = overrides.get(path_value, license_policy["default"])
            if license_expression != expected_license:
                raise ValueError(f"source license differs from policy: {path_value}")
            dependencies = entry.get("dependencies", [])
            registrations = entry.get("registrations", [])
            if role == "primary":
                if dependencies != sorted(set(dependencies)):
                    raise ValueError(f"non-deterministic dependencies: {path_value}")
                if registrations != sorted(set(registrations)):
                    raise ValueError(f"non-deterministic registrations: {path_value}")
                primary_paths.add(path_value)
            elif dependencies or registrations:
                raise ValueError(f"support record has command metadata: {path_value}")
            records[path_value] = {
                "path": path_value,
                "resolved_path": resolved_value,
                "sha256": entry["sha256"],
                "license": license_expression,
                "role": role,
                "dependencies": dependencies,
                "registrations": registrations,
            }
    if set(records) != expected_inputs or primary_paths != expected_primary:
        raise ValueError("coverage does not exactly match the pinned compiler input inventory")
    if len(records) > MAX_SOURCE_FILES:
        raise ValueError("source provenance file limit exceeded")
    if coverage["source_files"] != len(primary_paths):
        raise ValueError("primary source count mismatch")
    if coverage["support_files"] != len(records) - len(primary_paths):
        raise ValueError("support source count mismatch")
    for record in records.values():
        for dependency in record["dependencies"]:
            safe_relative(dependency)
            if dependency not in records:
                raise ValueError(f"missing support dependency: {dependency}")

    if coverage["command_blocks"] != len(spec["commands"]):
        raise ValueError("command block count mismatch")
    source_registrations = {path: set() for path in primary_paths}
    for command in spec["commands"]:
        for module in command.get("scripts", []):
            module_path = module["source_path"]
            if module_path not in source_registrations:
                raise ValueError(f"script module has unknown source: {module_path}")
            source_registrations[module_path].update(
                registration["command"] for registration in module["registrations"]
            )
    for path_value in primary_paths:
        if sorted(source_registrations[path_value]) != records[path_value]["registrations"]:
            raise ValueError(f"source registration mapping mismatch: {path_value}")

    represented: set[str] = set()
    for command in spec["commands"]:
        if command["source_commit"] != source_commit:
            raise ValueError(f"command source commit mismatch: {command['canonical_name']}")
        paths = command["source_path"].split(";")
        expressions: set[str] = set()
        for path_value in paths:
            if path_value not in primary_paths:
                raise ValueError(f"command references unknown primary source: {path_value}")
            represented.add(path_value)
            record = records[path_value]
            expressions.add(record["license"])
            expressions.update(records[item]["license"] for item in record["dependencies"])
        if command["license"] != combined_license(expressions):
            raise ValueError(f"command license mismatch: {command['canonical_name']}")
    if represented != primary_paths:
        raise ValueError("not every primary source is represented by a command block")

    expressions = {record["license"] for record in records.values()}
    expressions.update(command["license"] for command in spec["commands"])
    expressions.add(manifest["license_expression"])
    identifiers: set[str] = set()
    for expression in expressions:
        identifiers.update(license_identifiers(expression))
    mapped = license_policy["licenses"]
    if identifiers - set(mapped):
        raise ValueError(f"unmapped licenses: {sorted(identifiers - set(mapped))}")
    license_texts = []
    for identifier in sorted(identifiers):
        relative = str(safe_relative(mapped[identifier]))
        text_path = source_path(repository, relative)
        if not text_path.is_file():
            raise ValueError(f"missing license text for {identifier}: {relative}")
        license_texts.append(
            {"id": identifier, "path": relative, "sha256": sha256_file(text_path)}
        )

    verify_command = [str(pack_tool), "verify-spec", str(spec_path), str(pack_path)]
    if verifying_key:
        verify_command.append(str(verifying_key))
    subprocess.run(verify_command, check=True, stdout=subprocess.DEVNULL)
    key = None
    if verifying_key:
        inspection = subprocess.run(
            [str(pack_tool), "inspect", str(pack_path), str(verifying_key)],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout
        if "trust: Verified" not in inspection:
            raise ValueError("pack is not signed by the declared verifying key")
        key_id = subprocess.run(
            [str(pack_tool), "key-id", str(verifying_key)],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        key = {
            "key_id": key_id,
            "sha256": sha256_file(verifying_key),
        }

    source_files = []
    dependencies: dict[str, list[str]] = {}
    for path_value in sorted(records):
        record = records[path_value]
        source_files.append(
            {
                "license": record["license"],
                "path": path_value,
                "resolved_path": record["resolved_path"],
                "role": record["role"],
                "sha256": record["sha256"],
            }
        )
        if record["dependencies"]:
            dependencies[path_value] = record["dependencies"]

    return {
        "schema": 1,
        "pack": {
            "channel": channel,
            "id": manifest["pack_id"],
            "license_expression": manifest["license_expression"],
            "sha256": sha256_file(pack_path),
            "size": pack_path.stat().st_size,
            "source_kind": manifest["source_kind"],
            "version": manifest["pack_version"],
            "verifying_key": key,
        },
        "source": {
            "commit": source_commit,
            "dependencies": dependencies,
            "files": source_files,
            "ref": lock[channel]["ref"],
            "repository": lock["source"],
            "tree": git(upstream, "rev-parse", "HEAD^{tree}"),
        },
        "compiler": {
            "commit": compiler_commit,
            "pack_tool_sha256": sha256_file(pack_tool),
            "repository": lock["compiler"]["repository"],
            "rust_toolchain": lock["compiler"]["rust_toolchain"],
            "tree": git(compiler_checkout, "rev-parse", "HEAD^{tree}"),
            "version": manifest["compiler_version"],
        },
        "rule_repository": {
            "commit": git(repository, "rev-parse", "HEAD"),
            "tree": git(repository, "rev-parse", "HEAD^{tree}"),
        },
        "inputs": {
            "coverage_sha256": sha256_file(coverage_path),
            "rules_lock_sha256": sha256_file(lock_path),
            "spec_sha256": sha256_file(spec_path),
        },
        "licenses": {
            "expressions": sorted(expressions),
            "policy_sha256": sha256_file(licenses_path),
            "texts": license_texts,
        },
        "transformation": {
            "description": "Deterministic BashLume Script IR transpilation; no upstream shell text is executed at runtime",
            "schema": 1,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("write", "verify"))
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--spec", type=pathlib.Path, required=True)
    parser.add_argument("--coverage", type=pathlib.Path, required=True)
    parser.add_argument("--pack", type=pathlib.Path, required=True)
    parser.add_argument("--pack-tool", required=True)
    parser.add_argument("--compiler-checkout", type=pathlib.Path, required=True)
    parser.add_argument("--verifying-key", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()

    provenance = compute(arguments)
    encoded = canonical_json(provenance)
    if arguments.action == "write":
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=arguments.output.parent, delete=False) as target:
            target.write(encoded)
            temporary = pathlib.Path(target.name)
        temporary.replace(arguments.output)
    else:
        existing = arguments.output.read_bytes()
        if existing != encoded:
            raise SystemExit("provenance manifest is non-canonical or does not match its inputs")
    print(f"{arguments.action} provenance for {provenance['pack']['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
