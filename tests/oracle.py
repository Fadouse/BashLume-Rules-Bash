#!/usr/bin/env python3
"""Run one completion case against the pinned native Bash completion source."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--case-json", required=True)
    arguments = parser.parse_args()
    case = json.loads(arguments.case_json)
    context = case["context"]
    upstream = arguments.upstream.resolve()
    source = (upstream / case["source"]).resolve()
    try:
        source.relative_to(upstream)
    except ValueError as error:
        raise SystemExit(f"oracle source escapes the upstream checkout: {source}") from error
    if not source.is_file():
        raise SystemExit(f"oracle source is missing: {source}")

    configured_shell = os.environ.get("BASH_ORACLE")
    if not configured_shell:
        raise SystemExit("BASH_ORACLE must name the pinned Bash 5.3.9 binary")
    shell_path = pathlib.Path(configured_shell)
    if not shell_path.is_absolute() or not shell_path.is_file() or not os.access(shell_path, os.X_OK):
        raise SystemExit("BASH_ORACLE must be an absolute executable file")
    shell = str(shell_path.resolve())
    isolate_host_providers = bool(case.get("isolate_host_providers"))
    sandbox_host: pathlib.Path | None = None
    if isolate_host_providers:
        if not case.get("sandbox_host"):
            raise SystemExit("isolated Bash oracle requires sandbox_host")
        sandbox_host = pathlib.Path(str(case["sandbox_host"])).resolve(strict=True)
        if not sandbox_host.is_dir():
            raise SystemExit(f"oracle sandbox is not a directory: {sandbox_host}")
    with (
        tempfile.TemporaryDirectory(
            prefix="bashlume-bash-oracle-", dir=sandbox_host
        ) as temporary,
        tempfile.TemporaryDirectory(prefix="bashlume-bash-root-") as sandbox_root,
    ):
        capture = pathlib.Path(temporary) / "compopt"
        provider_capture = pathlib.Path(temporary) / "providers"
        (pathlib.Path(temporary) / "empty-hosts").touch()
        script = r'''
set +o posix
capture=$1
provider_capture=$2
upstream=$3
source_file=$4
command_name=$5
capture_providers=$6
isolate_host_providers=$7
shift 7
compopt() { printf '%s\n' "$*" >>"$capture"; return 0; }
source "$upstream/bash_completion"
source "$source_file"
exec 9>"$provider_capture"
if ((capture_providers)); then
__oracle_provider_sequence=0
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
                job|running|stopped) __oracle_category=process ;;
                service) __oracle_category=network ;;
                signal) __oracle_category=signal ;;
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
            -j) __oracle_category=process ;;
            -s) __oracle_category=service ;;
            -v) __oracle_category=variable ;;
        esac
    done
    [[ $__oracle_category ]] && printf '%s\t\0' "$__oracle_category" >&9
    if ((isolate_host_providers)) &&
        [[ $__oracle_category == @(directory|file|group|host|network|process|service|user) ]]; then
        if [[ $__oracle_output_variable ]]; then
            local -n __oracle_target=$__oracle_output_variable
            __oracle_target=()
        fi
        unset __oracle_category __oracle_filter_self __oracle_previous \
            __oracle_argument __oracle_output_variable __oracle_skip_first_self
        return 1
    fi
    __oracle_tag_provider=
    if ((isolate_host_providers)) &&
        [[ $__oracle_category == @(command|signal|variable) ]]; then
        __oracle_tag_provider=set
    fi
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
            __oracle_output_value=$__oracle_value
            if [[ $__oracle_tag_provider ]]; then
                ((__oracle_provider_sequence += 1))
                __oracle_output_value+=$'\x1f'"__BASHLUME_PROVIDER__${__oracle_category}__${BASHPID}_${__oracle_provider_sequence}"$'\x1f'
            fi
            __oracle_clean+=("$__oracle_output_value")
            if [[ $__oracle_category && ! $__oracle_tag_provider ]]; then
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
            __oracle_output_value=$__oracle_value
            if [[ $__oracle_tag_provider ]]; then
                ((__oracle_provider_sequence += 1))
                __oracle_output_value+=$'\x1f'"__BASHLUME_PROVIDER__${__oracle_category}__${BASHPID}_${__oracle_provider_sequence}"$'\x1f'
            elif [[ $__oracle_category ]]; then
                printf '%s\t%s\0' "$__oracle_category" "$__oracle_value" >&9
            fi
            printf '%s\n' "$__oracle_output_value"
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
if ((isolate_host_providers)); then
    # Completion helpers otherwise append system paths, enumerate NSS data, or
    # read global network/device state even when the caller supplied an empty
    # PATH. Broad parity uses an intentionally empty target snapshot instead.
    _comp_have_command() { [[ $(type -t -- "$1") == @(builtin|keyword) ]]; }
    _comp_userland() { [[ $1 == GNU ]]; }
    command_not_found_handle() {
        printf '%s\t\0' external-program >&9
        return 127
    }
    __oracle_empty_provider() {
        printf '%s\t\0' "$1" >&9
        _comp_compgen -- -W ''
    }
    _comp_expand_glob() {
        printf '%s\t\0' filesystem >&9
        local -n __oracle_glob_target=$1
        __oracle_glob_target=()
        return 1
    }
    _comp_compgen_filedir() { __oracle_empty_provider file; }
    _comp_compgen_filedir_xspec() { __oracle_empty_provider file; }
    _comp_compgen_tilde() { __oracle_empty_provider user; }
    _comp_compgen_pids() { __oracle_empty_provider process; }
    _comp_compgen_pgids() { __oracle_empty_provider process; }
    _comp_compgen_pnames() { __oracle_empty_provider process; }
    _comp_compgen_uids() { __oracle_empty_provider user; }
    _comp_compgen_allowed_users() { __oracle_empty_provider user; }
    _comp_compgen_selinux_users() { __oracle_empty_provider user; }
    _comp_compgen_gids() { __oracle_empty_provider group; }
    _comp_compgen_usergroups() { __oracle_empty_provider group; }
    _comp_compgen_allowed_groups() { __oracle_empty_provider group; }
    _comp_compgen_known_hosts() { __oracle_empty_provider host; }
    _comp_compgen_mac_addresses() { __oracle_empty_provider network; }
    _comp_compgen_configured_interfaces() { __oracle_empty_provider network; }
    _comp_compgen_ip_addresses() { __oracle_empty_provider network; }
    _comp_compgen_available_interfaces() { __oracle_empty_provider network; }
    _comp_compgen_xinetd_services() { __oracle_empty_provider network; }
    _comp_compgen_sysv_services() { __oracle_empty_provider network; }
    _comp_compgen_services() { __oracle_empty_provider network; }
    _comp_compgen_kernel_versions() { __oracle_empty_provider filesystem; }
    _comp_compgen_kernel_modules() { __oracle_empty_provider filesystem; }
    _comp_compgen_inserted_kernel_modules() { __oracle_empty_provider filesystem; }
    _comp_compgen_shells() { __oracle_empty_provider filesystem; }
    _comp_compgen_fstypes() { __oracle_empty_provider filesystem; }
    _comp_compgen_pci_ids() { __oracle_empty_provider filesystem; }
    _comp_compgen_usb_ids() { __oracle_empty_provider filesystem; }
    _comp_compgen_cd_devices() { __oracle_empty_provider filesystem; }
    _comp_compgen_dvd_devices() { __oracle_empty_provider filesystem; }
    _comp_compgen_terms() { __oracle_empty_provider filesystem; }
    GLOBIGNORE='*'
    shopt -s nullglob
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
if ((isolate_host_providers)); then
    __oracle_provider_regex=$'\x1f''__BASHLUME_PROVIDER__([a-z-]+)__([0-9]+_[0-9]+)'$'\x1f'
    for __oracle_candidate_index in "${!COMPREPLY[@]}"; do
        __oracle_final_value=${COMPREPLY[__oracle_candidate_index]}
        __oracle_final_categories=()
        while [[ $__oracle_final_value =~ $__oracle_provider_regex ]]; do
            __oracle_final_categories+=("${BASH_REMATCH[1]}")
            __oracle_final_value=${__oracle_final_value/"${BASH_REMATCH[0]}"/}
        done
        COMPREPLY[__oracle_candidate_index]=$__oracle_final_value
        for __oracle_category in "${__oracle_final_categories[@]}"; do
            printf '%s\t%s\t%s\0' "$__oracle_category" \
                "$__oracle_candidate_index" "$__oracle_final_value" >&9
        done
    done
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
        if isolate_host_providers:
            environment["HOSTFILE"] = str(pathlib.Path(temporary) / "empty-hosts")
            environment["TMPDIR"] = "/tmp"
        working_directory = pathlib.Path(context.get("working_directory", temporary))
        if not working_directory.is_dir():
            raise SystemExit(f"oracle working directory is missing: {working_directory}")
        shell_command = [
            shell,
            "--noprofile",
            "--norc",
            "-c",
            script,
            "bashlume-oracle",
            str(capture),
            str(provider_capture),
            str(upstream),
            str(source),
            context["command"],
            "1" if case.get("capture_providers") else "0",
            "1" if isolate_host_providers else "0",
            *context["words"],
        ]
        command = shell_command
        if isolate_host_providers:
            assert sandbox_host is not None
            unshare = shutil.which("unshare")
            if unshare is None:
                raise SystemExit("isolated Bash oracle requires unshare")
            helper = pathlib.Path(__file__).with_name("bash_oracle_sandbox.py").resolve()
            if not helper.is_file():
                raise SystemExit(f"Bash oracle sandbox helper is missing: {helper}")
            configuration = {
                "root": sandbox_root,
                "upstream": str(upstream),
                "sandbox": str(sandbox_host),
                "working_directory": str(working_directory.resolve(strict=True)),
                "shell": shell,
                "store_paths": case.get("oracle_store_paths", []),
                "users": context.get("users", []),
                "groups": context.get("groups", []),
                "hosts": context.get("hosts", []),
            }
            environment["BASHLUME_ORACLE_SANDBOX_CONFIG"] = json.dumps(
                configuration, separators=(",", ":")
            )
            command = [
                unshare,
                "--user",
                "--map-root-user",
                "--mount",
                "--net",
                "--uts",
                "--ipc",
                "--pid",
                "--fork",
                "--kill-child",
                "--propagation",
                "private",
                sys.executable,
                str(helper),
                *shell_command,
            ]
        completed = subprocess.run(
            command,
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
        provider_candidate_values: dict[str, list[str]] = {}
        provider_occurrence_categories: dict[int, set[str]] = {}
        provider_occurrence_values: dict[int, str] = {}
        provider_attribution_ambiguous = False
        for field in provider_fields:
            if not field:
                continue
            parts = field.split(b"\t", 2)
            if len(parts) < 2:
                continue
            name = parts[0].decode("ascii")
            provider_candidates.setdefault(name, [])
            provider_candidate_values.setdefault(name, [])
            if len(parts) == 3 and parts[1].isdigit():
                occurrence = int(parts[1])
                decoded = parts[2].decode("utf-8", "surrogateescape")
                prior = provider_occurrence_values.setdefault(occurrence, decoded)
                if prior != decoded:
                    provider_attribution_ambiguous = True
                provider_occurrence_categories.setdefault(occurrence, set()).add(name)
            else:
                decoded = parts[1].decode("utf-8", "surrogateescape")
                if decoded:
                    provider_candidate_values[name].append(decoded)
            if decoded and decoded not in provider_candidates[name]:
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
    candidates: list[dict[str, object]] = []
    candidates_by_occurrence: dict[int, dict[str, object]] = {}
    for occurrence, value in enumerate(values):
        if not value:
            continue
        decoded = value.decode("utf-8", "surrogateescape")
        candidate: dict[str, object] = {
            "value": decoded,
            "display": decoded,
            "description": None,
            "kind": direct_kind or ("option" if value.startswith(b"-") else "value"),
            "append": "no-space" if no_space else "space",
        }
        candidates.append(candidate)
        candidates_by_occurrence[occurrence] = candidate
    provider_candidate_records: dict[str, list[dict[str, object]]] = {
        provider: [] for provider in provider_candidates
    }
    provider_candidate_occurrences: list[dict[str, object]] = []
    for occurrence in sorted(provider_occurrence_categories):
        candidate = candidates_by_occurrence.get(occurrence)
        if candidate is None:
            provider_attribution_ambiguous = True
            continue
        if str(candidate["value"]) != provider_occurrence_values[occurrence]:
            provider_attribution_ambiguous = True
            continue
        provider_candidate_occurrences.append(candidate.copy())
        for provider in provider_occurrence_categories[occurrence]:
            provider_candidate_records.setdefault(provider, []).append(candidate.copy())

    provider_counts: dict[str, Counter[str]] = {}
    for provider, provider_values in provider_candidate_values.items():
        provider_counts[provider] = Counter(provider_values)
        pools: dict[str, list[dict[str, object]]] = {}
        for candidate in candidates:
            pools.setdefault(str(candidate["value"]), []).append(candidate)
        for value in provider_values:
            matches = pools.get(value, [])
            if matches:
                provider_candidate_records.setdefault(provider, []).append(
                    matches.pop(0).copy()
                )
    final_value_counts = Counter(str(candidate["value"]) for candidate in candidates)
    claimed_categories: dict[str, list[int]] = {}
    for counts in provider_counts.values():
        for value, count in counts.items():
            claimed_categories.setdefault(value, []).append(count)
    provider_attribution_ambiguous |= any(
        len(counts) != 1 or final_value_counts[value] != counts[0]
        for value, counts in claimed_categories.items()
    )
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
                "provider_candidate_records": provider_candidate_records,
                "provider_candidate_occurrences": provider_candidate_occurrences,
                "provider_attribution_ambiguous": provider_attribution_ambiguous,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
