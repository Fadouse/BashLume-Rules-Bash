"""Shared deterministic Completion IR JSON helpers for rule converters."""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Iterable


def candidate(value: str, description: str | None = None) -> dict[str, object]:
    return {
        "value": value,
        "display": value,
        "description": description,
        "kind": "option" if value.startswith("-") else "value",
        "append": "no-space" if value.endswith("=") else "space",
        "preserve_order": False,
    }


def command_program(
    canonical: str,
    registrations: Iterable[str],
    source_path: str,
    source_commit: str,
    license_expression: str,
    candidates: Iterable[dict[str, object]],
) -> dict[str, object]:
    registrations = sorted(set(registrations))
    candidates = sorted(
        {str(item["value"]): item for item in candidates}.values(),
        key=lambda item: str(item["value"]),
    )
    return {
        "canonical_name": canonical,
        "registrations": registrations,
        "source_path": source_path,
        "source_commit": source_commit,
        "license": license_expression,
        "static_rules": (
            [{"when": [{"op": "true"}], "candidates": candidates}]
            if candidates
            else []
        ),
        "probes": [],
    }


def coalesce_programs(programs: list[dict[str, object]]) -> list[dict[str, object]]:
    """Merge overlapping registration groups into unique command blocks."""
    groups: list[dict[str, object]] = []
    for program in programs:
        registrations = set(map(str, program["registrations"]))
        matching = [
            group
            for group in groups
            if registrations.intersection(map(str, group["registrations"]))
        ]
        if not matching:
            groups.append(program)
            continue
        primary = matching[0]
        for group in matching[1:]:
            primary["registrations"] = sorted(
                set(map(str, primary["registrations"]))
                | set(map(str, group["registrations"]))
            )
            primary["static_rules"] = list(primary["static_rules"]) + list(group["static_rules"])
            primary["probes"] = list(primary["probes"]) + list(group["probes"])
            primary["source_path"] = ";".join(
                sorted(set(str(primary["source_path"]).split(";")) | set(str(group["source_path"]).split(";")))
            )
            groups.remove(group)
        primary["registrations"] = sorted(
            set(map(str, primary["registrations"])) | registrations
        )
        primary["static_rules"] = list(primary["static_rules"]) + list(program["static_rules"])
        primary["probes"] = list(primary["probes"]) + list(program["probes"])
        primary["source_path"] = ";".join(
            sorted(set(str(primary["source_path"]).split(";")) | {str(program["source_path"])})
        )
        primary["canonical_name"] = sorted(map(str, primary["registrations"]))[0]
    return groups


def write_spec(
    output: pathlib.Path,
    *,
    pack_id: str,
    source_kind: str,
    source_repository: str,
    source_commit: str,
    license_expression: str,
    channel: str,
    programs: list[dict[str, object]],
    probe_capabilities: list[str] | None = None,
    stale_commands: list[str] | None = None,
) -> None:
    spec = {
        "manifest": {
            "pack_id": pack_id,
            "pack_version": f"0.0.0+{source_commit[:12]}",
            "source_kind": source_kind,
            "source_repository": source_repository,
            "source_commit": source_commit,
            "license_expression": license_expression,
            "channel": channel,
            "compiler_version": "0.1.0",
            "generated_at": "1970-01-01T00:00:00Z",
            "stale_commands": stale_commands or [],
            "probe_capabilities": probe_capabilities or [],
        },
        "minimum_engine": [0, 2, 0],
        "required_opcodes": 0,
        "optional_features": 0,
        "commands": sorted(programs, key=lambda item: str(item["canonical_name"])),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def git_commit(checkout: pathlib.Path) -> str:
    head = (checkout / ".git" / "HEAD").read_text(encoding="utf-8").strip()
    if head.startswith("ref: "):
        ref = checkout / ".git" / head[5:]
        if ref.exists():
            return ref.read_text(encoding="utf-8").strip()
    if len(head) == 40:
        return head
    raise RuntimeError(f"cannot resolve detached source commit in {checkout}")


def source_digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_coverage(path: pathlib.Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
