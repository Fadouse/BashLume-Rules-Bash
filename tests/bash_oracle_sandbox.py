#!/usr/bin/env python3
"""Enter the rootless mount/network sandbox used by the broad Bash oracle."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import pathlib
import sys


MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18

PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECUREBITS = 28
SECBIT_NOROOT = 1
SECBIT_NOROOT_LOCKED = 2
SECBIT_NO_SETUID_FIXUP = 4
SECBIT_NO_SETUID_FIXUP_LOCKED = 8
LINUX_CAPABILITY_VERSION_3 = 0x20080522

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
]
libc.mount.restype = ctypes.c_int
libc.sethostname.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
libc.sethostname.restype = ctypes.c_int
libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
libc.prctl.restype = ctypes.c_int


class CapabilityHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapabilityData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


libc.capset.argtypes = [
    ctypes.POINTER(CapabilityHeader),
    ctypes.POINTER(CapabilityData),
]
libc.capset.restype = ctypes.c_int


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def checked_path(value: object, *, directory: bool = True) -> pathlib.Path:
    path = pathlib.Path(str(value))
    if not path.is_absolute():
        fail(f"sandbox path is not absolute: {path}")
    resolved = path.resolve(strict=True)
    if directory and not resolved.is_dir():
        fail(f"sandbox directory is missing: {resolved}")
    return resolved


def target_path(root: pathlib.Path, source: pathlib.Path) -> pathlib.Path:
    if not source.is_absolute():
        fail(f"bind source is not absolute: {source}")
    return root.joinpath(*source.parts[1:])


def mount(
    source: str | None,
    target: pathlib.Path,
    filesystem: str | None,
    flags: int,
) -> None:
    encoded_source = None if source is None else os.fsencode(source)
    encoded_filesystem = None if filesystem is None else os.fsencode(filesystem)
    if libc.mount(
        encoded_source,
        os.fsencode(target),
        encoded_filesystem,
        flags,
        None,
    ) != 0:
        error = ctypes.get_errno()
        fail(f"mount {source!r} on {target} failed: {os.strerror(error)}")


def bind_directory(root: pathlib.Path, source: pathlib.Path, *, readonly: bool) -> None:
    target = target_path(root, source)
    target.mkdir(parents=True, exist_ok=True)
    mount(str(source), target, None, MS_BIND | MS_REC)
    if readonly:
        mount(
            None,
            target,
            None,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
        )


def bind_file(root: pathlib.Path, source: pathlib.Path, *, readonly: bool) -> None:
    target = target_path(root, source)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch(exist_ok=True)
    mount(str(source), target, None, MS_BIND)
    if readonly:
        mount(
            None,
            target,
            None,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
        )


def safe_names(values: object, fallback: list[str]) -> list[str]:
    if not isinstance(values, list):
        return fallback
    output: list[str] = []
    for value in values:
        name = str(value)
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        if not name or any(character not in allowed for character in name):
            fail(f"invalid fixture identity: {name!r}")
        if name not in output:
            output.append(name)
    return output or fallback


def write_fixture_etc(root: pathlib.Path, config: dict[str, object]) -> None:
    etc = root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    users = safe_names(config.get("users"), ["root", "snapshot-user"])
    groups = safe_names(config.get("groups"), ["root", "snapshot-group"])
    hosts = safe_names(config.get("hosts"), ["localhost", "snapshot-host"])

    passwd_lines: list[str] = []
    for index, user in enumerate(users):
        uid = 0 if user == "root" else 4242 + index
        gid = 0 if user == "root" else 4242
        home = "/root" if user == "root" else "/nonexistent"
        passwd_lines.append(f"{user}:x:{uid}:{gid}:{user}:{home}:/bin/false")
    group_lines: list[str] = []
    for index, group in enumerate(groups):
        gid = 0 if group == "root" else 4242 + index
        group_lines.append(f"{group}:x:{gid}:")
    host_lines = ["127.0.0.1 localhost", "::1 localhost"]
    for index, host in enumerate(hosts):
        if host != "localhost":
            host_lines.append(f"192.0.2.{index + 1} {host}")

    fixtures = {
        "passwd": "\n".join(passwd_lines) + "\n",
        "group": "\n".join(group_lines) + "\n",
        "hosts": "\n".join(host_lines) + "\n",
        "nsswitch.conf": "passwd: files\ngroup: files\nhosts: files\n",
        "resolv.conf": "",
        "os-release": 'ID=bashlume-sandbox\nNAME="BashLume Sandbox"\n',
    }
    for name, content in fixtures.items():
        path = etc / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o444)


def drop_privileges() -> None:
    securebits = (
        SECBIT_NOROOT
        | SECBIT_NOROOT_LOCKED
        | SECBIT_NO_SETUID_FIXUP
        | SECBIT_NO_SETUID_FIXUP_LOCKED
    )
    if libc.prctl(PR_SET_SECUREBITS, securebits, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        fail(f"setting securebits failed: {os.strerror(error)}")
    for capability in range(64):
        if libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            if error != errno.EINVAL:
                fail(f"dropping capability {capability} failed: {os.strerror(error)}")
    header = CapabilityHeader(LINUX_CAPABILITY_VERSION_3, 0)
    data = (CapabilityData * 2)()
    if libc.capset(ctypes.byref(header), data) != 0:
        error = ctypes.get_errno()
        fail(f"clearing capabilities failed: {os.strerror(error)}")
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        fail(f"setting no_new_privs failed: {os.strerror(error)}")


def main() -> int:
    raw_config = os.environ.pop("BASHLUME_ORACLE_SANDBOX_CONFIG", None)
    if not raw_config:
        fail("sandbox configuration is missing")
    config = json.loads(raw_config)
    if not isinstance(config, dict):
        fail("sandbox configuration is not an object")
    if len(sys.argv) < 2:
        fail("sandbox command is missing")

    root = checked_path(config.get("root"))
    upstream = checked_path(config.get("upstream"))
    sandbox = checked_path(config.get("sandbox"))
    working_directory = checked_path(config.get("working_directory"))
    shell = checked_path(config.get("shell"), directory=False)
    if not shell.is_file() or not os.access(shell, os.X_OK):
        fail(f"sandbox shell is not executable: {shell}")
    nix_store = pathlib.Path("/nix/store")
    raw_store_paths = config.get("store_paths")
    if not isinstance(raw_store_paths, list) or not raw_store_paths:
        fail("sandbox Bash runtime closure is missing")
    store_paths: list[pathlib.Path] = []
    for value in raw_store_paths:
        path = checked_path(value)
        if path.parent != nix_store:
            fail(f"runtime closure item is outside /nix/store: {path}")
        if path not in store_paths:
            store_paths.append(path)
    working_directory.relative_to(sandbox)
    if not any(shell == path or path in shell.parents for path in store_paths):
        fail("sandbox Bash runtime closure does not contain the shell")

    mount(None, pathlib.Path("/"), None, MS_REC | MS_PRIVATE)
    (root / "nix/store").mkdir(parents=True, exist_ok=True)
    (root / "nix/store").chmod(0o555)
    for store_path in store_paths:
        bind_directory(root, store_path, readonly=True)
    bind_directory(root, upstream, readonly=True)
    bind_directory(root, sandbox, readonly=False)

    for relative in ("bin", "lib", "lib64", "proc", "run", "sbin", "sys", "usr"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    temporary = root / "tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    temporary.chmod(0o1777)
    device = root / "dev"
    device.mkdir(parents=True, exist_ok=True)
    bind_file(root, pathlib.Path("/dev/null"), readonly=False)
    write_fixture_etc(root, config)

    hostname = b"bashlume-sandbox"
    if libc.sethostname(hostname, len(hostname)) != 0:
        error = ctypes.get_errno()
        fail(f"setting sandbox hostname failed: {os.strerror(error)}")

    os.chroot(root)
    os.chdir(working_directory)
    drop_privileges()
    os.umask(0o077)
    try:
        maximum_fd = min(os.sysconf("SC_OPEN_MAX"), 1_048_576)
    except (OSError, ValueError):
        maximum_fd = 65_536
    os.closerange(3, maximum_fd)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "BASHLUME_ORACLE_SANDBOX_CONFIG"
    }
    os.execve(shell, sys.argv[1:], environment)
    return 127


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"bash oracle sandbox: {error}", file=sys.stderr)
        raise SystemExit(125)
