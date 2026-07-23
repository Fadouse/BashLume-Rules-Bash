#!/usr/bin/env python3
"""Compile bash-completion sources into BashLume Completion IR.

The compiler is deliberately strict: constructs without semantic lowering are
reported and make a Stable build fail. `--allow-incomplete` is development-only
and may never be used by a release workflow.
"""

from __future__ import annotations

import argparse
import pathlib
import re

from common import candidate, coalesce_programs, command_program, git_commit, source_digest, write_coverage, write_spec

LONG_OPTION = re.compile(r"(?<![A-Za-z0-9_])(--[A-Za-z0-9][A-Za-z0-9_-]*=?)(?![A-Za-z0-9_-])")
SHORT_OPTION = re.compile(r"(?<![A-Za-z0-9_])(-[A-Za-z0-9?])(?![A-Za-z0-9_-])")
FUNCTION = re.compile(r"(?m)^\s*(?:function\s+)?[_A-Za-z][_A-Za-z0-9]*\s*(?:\(\))?\s*\{")
COMMAND_SUBSTITUTION = re.compile(r"\$\(|`[^`]*`")
COMPOPT = re.compile(r"\bcompopt\b")
COMPREPLY = re.compile(r"\bCOMPREPLY\b")
LOOP = re.compile(r"(?m)^\s*(?:for|while|until|select)\b")


def source_files(upstream: pathlib.Path) -> list[pathlib.Path]:
    result: list[pathlib.Path] = []
    for directory in ("completions-core", "completions-fallback", "completions"):
        root = upstream / directory
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if (
                not path.is_file()
                or path.name.startswith(".")
                or path.name in {"Makefile.am", "README.md", "README"}
            ):
                continue
            result.append(path)
    return sorted(result)


def registrations(path: pathlib.Path) -> set[str]:
    name = path.name
    if name.startswith("_"):
        name = name[1:]
    if name.endswith(".bash"):
        name = name[:-5]
    return {name} if name else set()


def unsupported_features(text: str) -> list[str]:
    features = []
    for name, expression in (
        ("shell-function", FUNCTION),
        ("command-substitution", COMMAND_SUBSTITUTION),
        ("compopt", COMPOPT),
        ("compreply", COMPREPLY),
        ("loop", LOOP),
    ):
        if expression.search(text):
            features.append(name)
    return features


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--coverage", type=pathlib.Path, default=pathlib.Path("build/coverage.json"))
    parser.add_argument("--channel", choices=("stable", "edge"), default="stable")
    parser.add_argument("--allow-incomplete", action="store_true")
    arguments = parser.parse_args()

    upstream = arguments.upstream.resolve()
    commit = git_commit(upstream)
    files = source_files(upstream)
    if not files:
        raise SystemExit("no bash-completion source files found")

    programs = []
    report_files = []
    all_registrations: set[str] = set()
    unsupported_count = 0
    unsupported_registrations: set[str] = set()
    for path in files:
        relative = path.relative_to(upstream).as_posix()
        text = path.read_text(encoding="utf-8", errors="surrogateescape")
        names = registrations(path)
        if not names:
            continue
        options = sorted(set(LONG_OPTION.findall(text)) | set(SHORT_OPTION.findall(text)))
        features = unsupported_features(text)
        if features:
            unsupported_count += 1
            unsupported_registrations.update(names)
        canonical = sorted(names)[0]
        programs.append(
            command_program(
                canonical,
                names,
                relative,
                commit,
                "GPL-2.0-or-later",
                [candidate(option) for option in options],
            )
        )
        all_registrations.update(names)
        report_files.append(
            {
                "path": relative,
                "sha256": source_digest(path),
                "registrations": sorted(names),
                "static_options": len(options),
                "unsupported": features,
            }
        )

    programs = coalesce_programs(programs)
    report = {
        "schema": 1,
        "source_commit": commit,
        "source_files": len(files),
        "compiled_files": len(report_files),
        "command_blocks": len(programs),
        "registrations": len(all_registrations),
        "unsupported_files": unsupported_count,
        "files": report_files,
    }
    write_coverage(arguments.coverage, report)
    if unsupported_count and not arguments.allow_incomplete:
        raise SystemExit(
            f"baseline rejected: {unsupported_count}/{len(report_files)} files still contain unsupported semantics; see {arguments.coverage}"
        )
    write_spec(
        arguments.output,
        pack_id="org.bashlume.rules.bash",
        source_kind="bash",
        source_repository="https://github.com/scop/bash-completion.git",
        source_commit=commit,
        license_expression="GPL-2.0-or-later",
        channel=arguments.channel,
        programs=programs,
        stale_commands=sorted(unsupported_registrations),
    )
    print(
        f"compiled {len(programs)} command blocks and {len(all_registrations)} registrations from {len(files)} files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
