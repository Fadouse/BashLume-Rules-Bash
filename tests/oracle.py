#!/usr/bin/env python3
"""Run one completion case against the pinned native Bash completion source."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--case-json", required=True)
    arguments = parser.parse_args()
    case = json.loads(arguments.case_json)
    context = case["context"]
    source = (arguments.upstream / case["source"]).resolve()
    if not source.is_file():
        raise SystemExit(f"oracle source is missing: {source}")

    configured_shell = os.environ.get("BASH_ORACLE")
    if not configured_shell:
        raise SystemExit("BASH_ORACLE must name the pinned Bash 5.3.9 binary")
    shell_path = pathlib.Path(configured_shell)
    if not shell_path.is_absolute() or not shell_path.is_file() or not os.access(shell_path, os.X_OK):
        raise SystemExit("BASH_ORACLE must be an absolute executable file")
    shell = str(shell_path.resolve())
    with tempfile.TemporaryDirectory(prefix="bashlume-bash-oracle-") as temporary:
        capture = pathlib.Path(temporary) / "compopt"
        provider_capture = pathlib.Path(temporary) / "providers"
        script = r'''
set +o posix
capture=$1
provider_capture=$2
upstream=$3
source_file=$4
command_name=$5
capture_providers=$6
shift 6
compopt() { printf '%s\n' "$*" >>"$capture"; return 0; }
source "$upstream/bash_completion"
source "$source_file"
exec 9>"$provider_capture"
if ((capture_providers)); then
compgen() {
    __oracle_category=
    __oracle_filter_self=
    __oracle_output_variable=
    __oracle_previous=
    __oracle_skip_first_self=
    for __oracle_argument in "$@"; do
        if [[ $__oracle_previous == -V ]]; then
            __oracle_output_variable=$__oracle_argument
            __oracle_previous=
            continue
        fi
        if [[ $__oracle_previous == -A ]]; then
            case $__oracle_argument in
                alias|builtin|keyword) __oracle_category=command ;;
                command)
                    __oracle_category=command
                    __oracle_skip_first_self=1
                    ;;
                function)
                    __oracle_category=command
                    __oracle_filter_self=1
                    ;;
                directory) __oracle_category=directory ;;
                file) __oracle_category=file ;;
                hostname) __oracle_category=host ;;
                user) __oracle_category=user ;;
                group) __oracle_category=group ;;
                variable|export) __oracle_category=variable ;;
            esac
            __oracle_previous=
            continue
        fi
        case $__oracle_argument in
            -A) __oracle_previous=-A ;;
            -V) __oracle_previous=-V ;;
            -V?*) __oracle_output_variable=${__oracle_argument:2} ;;
            -a|-b) __oracle_category=command ;;
            -c)
                __oracle_category=command
                __oracle_skip_first_self=1
                ;;
            -d) __oracle_category=directory ;;
            -f) __oracle_category=file ;;
            -u) __oracle_category=user ;;
            -g) __oracle_category=group ;;
            -v) __oracle_category=variable ;;
        esac
    done
    if [[ $__oracle_output_variable ]]; then
        builtin compgen "$@"
        __oracle_status=$?
        local -n __oracle_target=$__oracle_output_variable
        local -a __oracle_clean=()
        local __oracle_value
        for __oracle_value in "${__oracle_target[@]}"; do
            [[ $__oracle_value == __oracle_* ]] && continue
            [[ $__oracle_filter_self && $__oracle_value == compgen ]] && continue
            if [[ $__oracle_skip_first_self && $__oracle_value == compgen ]]; then
                __oracle_skip_first_self=
                continue
            fi
            __oracle_clean+=("$__oracle_value")
            if [[ $__oracle_category ]]; then
                printf '%s\t%s\0' "$__oracle_category" "$__oracle_value" >&9
            fi
        done
        __oracle_target=("${__oracle_clean[@]}")
        if (( __oracle_status == 0 )); then
            unset __oracle_category __oracle_filter_self __oracle_previous \
                __oracle_argument __oracle_output_variable __oracle_skip_first_self \
                __oracle_status
            return 0
        fi
        unset __oracle_category __oracle_filter_self __oracle_previous \
            __oracle_argument __oracle_output_variable __oracle_skip_first_self \
            __oracle_status
        return 1
    fi
    builtin compgen "$@" |
        while IFS= read -r __oracle_value; do
            [[ $__oracle_value == __oracle_* ]] && continue
            [[ $__oracle_filter_self && $__oracle_value == compgen ]] && continue
            if [[ $__oracle_skip_first_self && $__oracle_value == compgen ]]; then
                unset __oracle_skip_first_self
                continue
            fi
            if [[ $__oracle_category ]]; then
                printf '%s\t%s\0' "$__oracle_category" "$__oracle_value" >&9
            fi
            printf '%s\n' "$__oracle_value"
        done
    __oracle_status=${PIPESTATUS[0]}
    if (( __oracle_status == 0 )); then
        unset __oracle_category __oracle_filter_self __oracle_previous \
            __oracle_argument __oracle_output_variable __oracle_value \
            __oracle_skip_first_self __oracle_status
        return 0
    fi
    unset __oracle_category __oracle_filter_self __oracle_previous \
        __oracle_argument __oracle_output_variable __oracle_value \
        __oracle_skip_first_self __oracle_status
    return 1
}
fi
COMP_WORDS=("$@")
COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
COMP_LINE=$(printf '%s ' "${COMP_WORDS[@]}")
COMP_LINE=${COMP_LINE% }
[[ ${COMP_WORDS[-1]} ]] || COMP_LINE+=' '
COMP_POINT=${#COMP_LINE}
COMP_TYPE=9
COMP_KEY=9
COMPREPLY=()
spec=$(complete -p -- "$command_name") || exit 70
printf 'spec:%s\n' "$spec" >>"$capture"
if [[ $spec =~ -F[[:space:]]+([^[:space:]]+) ]]; then
    function_name=${BASH_REMATCH[1]}
    previous=
    ((COMP_CWORD > 0)) && previous=${COMP_WORDS[COMP_CWORD-1]}
    "$function_name" "$command_name" "${COMP_WORDS[COMP_CWORD]}" "$previous"
    completion_status=$?
elif [[ $spec =~ -W[[:space:]]+([^[:space:]]+) ]]; then
    COMPREPLY=( $(compgen -W "${BASH_REMATCH[1]}" -- "${COMP_WORDS[COMP_CWORD]}") )
    completion_status=$?
elif [[ $spec =~ (^|[[:space:]])-u([[:space:]]|$) ]]; then
    COMPREPLY=( $(compgen -u -- "${COMP_WORDS[COMP_CWORD]}") )
    completion_status=$?
elif [[ $spec =~ (^|[[:space:]])-g([[:space:]]|$) ]]; then
    COMPREPLY=( $(compgen -g -- "${COMP_WORDS[COMP_CWORD]}") )
    completion_status=$?
elif [[ $spec =~ (^|[[:space:]])-d([[:space:]]|$) ]]; then
    COMPREPLY=( $(compgen -d -- "${COMP_WORDS[COMP_CWORD]}") )
    completion_status=$?
elif [[ $spec =~ (^|[[:space:]])-f([[:space:]]|$) ]]; then
    COMPREPLY=( $(compgen -f -- "${COMP_WORDS[COMP_CWORD]}") )
    completion_status=$?
else
    exit 71
fi
printf 'status:%s\n' "$completion_status" >>"$capture"
printf '%s\0' "${COMPREPLY[@]}"
'''
        environment = {
            "HOME": temporary,
            "PATH": case.get(
                "path",
                "/etc/profiles/per-user/fadouse/bin:/run/current-system/sw/bin:/usr/bin:/bin",
            ),
            "TERM": "dumb",
            "LC_ALL": "C.UTF-8",
            **context.get("environment", {}),
        }
        working_directory = pathlib.Path(context.get("working_directory", temporary))
        if not working_directory.is_dir():
            raise SystemExit(f"oracle working directory is missing: {working_directory}")
        completed = subprocess.run(
            [
                shell,
                "--noprofile",
                "--norc",
                "-c",
                script,
                "bashlume-oracle",
                str(capture),
                str(provider_capture),
                str(arguments.upstream.resolve()),
                str(source),
                context["command"],
                "1" if case.get("capture_providers") else "0",
                *context["words"],
            ],
            env=environment,
            cwd=working_directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if completed.returncode == 70:
            print(
                json.dumps(
                    {
                        "available": False,
                        "candidates": [],
                        "completion_status": None,
                        "path_completion": "inherit",
                        "quote_behavior": "literal",
                    }
                )
            )
            return 0
        if completed.returncode:
            raise SystemExit(
                f"native Bash oracle failed with {completed.returncode}: "
                f"{completed.stderr.decode('utf-8', 'replace')[-1000:]}"
            )
        values = completed.stdout.rstrip(b"\0").split(b"\0") if completed.stdout else []
        options = capture.read_text(encoding="utf-8").splitlines() if capture.exists() else []
        provider_fields = (
            provider_capture.read_bytes().split(b"\0") if provider_capture.exists() else []
        )
        provider_candidates: dict[str, list[str]] = {}
        for field in provider_fields:
            if not field:
                continue
            category, separator, value = field.partition(b"\t")
            if not separator:
                continue
            name = category.decode("ascii")
            decoded = value.decode("utf-8", "surrogateescape")
            provider_candidates.setdefault(name, [])
            if decoded not in provider_candidates[name]:
                provider_candidates[name].append(decoded)
        provider_categories = sorted(provider_candidates)
    no_space = any("-o nospace" in option for option in options)
    completion_status = next(
        (int(option.removeprefix("status:")) for option in options if option.startswith("status:")),
        0,
    )
    if any("-o filenames" in option for option in options):
        path_completion = "files"
        quote_behavior = "filename"
    elif any("-o dirnames" in option for option in options):
        path_completion = "directories"
        quote_behavior = "filename"
    elif any("+o default" in option or "+o bashdefault" in option for option in options):
        path_completion = "suppress"
        quote_behavior = "literal"
    else:
        path_completion = "inherit"
        quote_behavior = "literal"
    specification = next(
        (option.removeprefix("spec:") for option in options if option.startswith("spec:")),
        "",
    )
    direct_kind = (
        "user"
        if " -u " in f" {specification} "
        else "group"
        if " -g " in f" {specification} "
        else "directory"
        if " -d " in f" {specification} "
        else "file"
        if " -f " in f" {specification} "
        else None
    )
    candidates = [
        {
            "value": value.decode("utf-8", "surrogateescape"),
            "display": value.decode("utf-8", "surrogateescape"),
            "description": None,
            "kind": direct_kind or ("option" if value.startswith(b"-") else "value"),
            "append": "no-space" if no_space else "space",
        }
        for value in values
        if value
    ]
    print(
        json.dumps(
            {
                "available": True,
                "candidates": candidates,
                "completion_status": completion_status,
                "path_completion": path_completion,
                "quote_behavior": quote_behavior,
                "provider_categories": provider_categories,
                "provider_candidates": provider_candidates,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
