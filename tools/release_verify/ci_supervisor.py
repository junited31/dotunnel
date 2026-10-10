"""Finite, standard-library-only Linux host supervisor for release verification.

This module is trusted host code. Candidate-controlled data is limited to the
three-field specification parsed by :func:`parse_spec`; it never supplies a
command, image, mount, Docker option, or resource limit.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import fcntl
import json
import os
import platform
import pwd
import re
import selectors
import shutil
import signal
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping
from typing import Callable
from pathlib import Path
_MIB = 1024 * 1024
_GIB = 1024 * _MIB
# Trusted host headroom, independent of the candidate/container limits.
_HOST_START_MEMORY_BYTES = 8 * _GIB
_HOST_MIN_MEMORY_BYTES = 6 * _GIB
_HOST_START_DISK_BYTES = 4 * _GIB
_HOST_MIN_DISK_BYTES = 2 * _GIB
_INPUT_MAX_ENTRIES = 1024
_INPUT_MAX_DIRECTORIES = 256
_INPUT_MAX_TOTAL_BYTES = 32 * _MIB
_INPUT_MAX_FILE_BYTES = 8 * _MIB
_INPUT_MAX_DEPTH = 32
_INPUT_MAX_PATH_BYTES = 4096

_RUN_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_RE = re.compile(r"docker\.io/library/python@sha256:[0-9a-f]{64}\Z")
_DOCKER_SOCKET = "/var/run/docker.sock"
_CONTAINER_PREFIX = "dotunnel-verify-"
_LABEL_RUN = "dotunnel.verify.run"
_LABEL_KIND = "dotunnel.verify.kind"
_LABEL_VALUE_KIND = "release-pilot"
_INPUT_DESTINATION = "/candidate-input"
_USER_ID = 65532
_DEFAULT_IMAGE = (
    "docker.io/library/python@sha256:"
    "34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258"
)
# The pinned index digest and its independently observed linux/amd64 manifest.
_APPROVED_IMAGE_DIGESTS = {
    ("linux", "amd64"): frozenset({
        "34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258",
        "2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d",
    }),
}


@dataclasses.dataclass(frozen=True)
class _CoreLimits:
    memory_bytes: int = 512 * _MIB
    memory_swap_bytes: int = 512 * _MIB  # Docker's total memory+swap value.
    swap_bytes: int = 0
    cpu_percent: int = 50
    cpu_count: float = 0.5
    process_limit: int = 64
    wall_seconds: int = 180
    stdout_bytes: int = 64 * 1024
    stderr_bytes: int = 64 * 1024
    output_bytes: int = 64 * 1024
    disk_bytes: int = 256 * _MIB
    stop_seconds: int = 2


CORE_LIMITS = _CoreLimits()


@dataclasses.dataclass(frozen=True)
class Policy:
    """Trusted host policy, intentionally separate from candidate JSON."""

    image: str
    input_root: Path | None = None

@dataclasses.dataclass(frozen=True)
class _InputEntry:
    path: bytes
    kind: str
    identity: tuple[int, ...]
    sha256: str | None


@dataclasses.dataclass(frozen=True)
class _InputProof:
    root_identity: tuple[int, int, int, int, int]
    entries: tuple[_InputEntry, ...]


@dataclasses.dataclass(frozen=True)
class _Spec(Mapping[str, object]):
    schema: int
    stage: str
    run_id: str

    def __getitem__(self, key: str) -> object:
        if key == "schema":
            return self.schema
        if key == "stage":
            return self.stage
        if key == "run_id":
            return self.run_id
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(("schema", "stage", "run_id"))

    def __len__(self) -> int:
        return 3


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ValueError("value is not canonical JSON") from exc


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError("non-finite JSON number")


def _validate_image(image: object) -> str:
    if not isinstance(image, str) or _IMAGE_RE.fullmatch(image) is None:
        raise ValueError("policy image must be an immutable official Python digest")
    return image


def _effective_uid() -> int:
    try:
        return os.geteuid()
    except AttributeError as exc:  # pragma: no cover - this controller is Linux-only.
        raise ValueError("Linux effective user identity is unavailable") from exc


def _path_snapshot(path: Path, *, directory: bool = True) -> tuple[int, int, int, int]:
    """Validate every lexical component without following a symlink."""
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise ValueError("path must be absolute and contain no parent traversal")
    uid = _effective_uid()
    if uid == 0:
        raise ValueError("root is not an accepted supervisor account")
    current = Path(path.anchor)
    components = path.parts[1:]
    if not components:
        raise ValueError("filesystem root is not an accepted path")
    for index, component in enumerate(components):
        if component in ("", "."):
            raise ValueError("path contains an unsafe component")
        current = current / component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise ValueError("path component is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink path components are refused")
        is_leaf = index == len(components) - 1
        if not is_leaf and not stat.S_ISDIR(info.st_mode):
            raise ValueError("path ancestor is not a directory")
        if is_leaf:
            if directory and not stat.S_ISDIR(info.st_mode):
                raise ValueError("path is not a directory")
            if not directory and not stat.S_ISREG(info.st_mode):
                raise ValueError("path is not a regular file")
            if info.st_uid != uid:
                raise ValueError("path is not owned by the supervisor account")
        elif info.st_uid not in (0, uid):
            raise ValueError("path ancestor has an unexpected owner")
        if info.st_mode & 0o022:
            # /tmp-style root-owned sticky ancestors are safe for a private,
            # owner-controlled child; other group/world-writable ancestors are not.
            if not (not is_leaf and info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise ValueError("path has an unsafe group/world-writable component")
    leaf = os.lstat(path)
    return (leaf.st_dev, leaf.st_ino, leaf.st_uid, stat.S_IMODE(leaf.st_mode))


def _input_stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _input_root_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid,
        stat.S_IMODE(info.st_mode),
    )


def _validate_input_directory(
    info: os.stat_result, *, leaf: bool, uid: int, allow_sticky_ancestor: bool = False,
) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("reviewed input tree contains a non-directory")
    if info.st_uid not in ((uid,) if leaf else (0, uid)):
        raise ValueError("reviewed input tree has an unexpected owner")
    if info.st_mode & 0o022 and not (
        allow_sticky_ancestor and not leaf
        and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
    ):
        raise ValueError("reviewed input tree has a group/world-writable directory")


def _open_input_root(path: Path, uid: int) -> int:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise ValueError("reviewed input path must be absolute and traversal-free")
    components = path.parts[1:]
    if not components:
        raise ValueError("filesystem root is not a reviewed input tree")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for index, component in enumerate(components):
            if component in ("", ".", ".."):
                raise ValueError("reviewed input path contains an unsafe component")
            before = os.stat(component, dir_fd=fd, follow_symlinks=False)
            leaf = index == len(components) - 1
            _validate_input_directory(
                before, leaf=leaf, uid=uid, allow_sticky_ancestor=True,
            )
            next_fd = os.open(component, flags, dir_fd=fd)
            try:
                opened = os.fstat(next_fd)
                if _input_stat_identity(opened) != _input_stat_identity(before):
                    raise ValueError("reviewed input path changed during open")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _input_tree_proof(path: Path) -> _InputProof:
    """Hash a bounded regular-file tree without following path or entry symlinks."""
    uid = _effective_uid()
    if uid == 0:
        raise ValueError("root is not an accepted supervisor account")
    root_fd = _open_input_root(path, uid)
    entries: list[_InputEntry] = []
    counts = {"entries": 0, "directories": 1}
    total_bytes = 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK

    def visit(directory_fd: int, parts: tuple[bytes, ...], depth: int) -> None:
        nonlocal total_bytes
        directory_before = os.fstat(directory_fd)
        _validate_input_directory(directory_before, leaf=not parts, uid=uid)
        scan_fd = os.dup(directory_fd)
        try:
            with os.scandir(scan_fd) as iterator:
                names: list[str] = []
                for entry in iterator:
                    names.append(entry.name)
                    if counts["entries"] + len(names) > _INPUT_MAX_ENTRIES:
                        raise ValueError("reviewed input tree exceeds its entry bound")
        finally:
            try:
                os.close(scan_fd)
            except OSError:
                pass
        names.sort(key=os.fsencode)
        for name in names:
            encoded_name = os.fsencode(name)
            relative_parts = parts + (encoded_name,)
            relative_path = b"/".join(relative_parts)
            if (
                name in ("", ".", "..")
                or depth >= _INPUT_MAX_DEPTH
                or len(relative_path) > _INPUT_MAX_PATH_BYTES
            ):
                raise ValueError("reviewed input path exceeds its fixed bound")
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            counts["entries"] += 1
            if counts["entries"] > _INPUT_MAX_ENTRIES:
                raise ValueError("reviewed input tree exceeds its entry bound")
            if stat.S_ISDIR(info.st_mode):
                _validate_input_directory(info, leaf=False, uid=uid)
                counts["directories"] += 1
                if counts["directories"] > _INPUT_MAX_DIRECTORIES:
                    raise ValueError("reviewed input tree exceeds its directory bound")
                child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if _input_stat_identity(opened) != _input_stat_identity(info):
                        raise ValueError("reviewed input directory changed during open")
                    entries.append(_InputEntry(
                        relative_path, "directory", _input_stat_identity(opened), None,
                    ))
                    visit(child_fd, relative_parts, depth + 1)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if _input_stat_identity(after) != _input_stat_identity(opened):
                        raise ValueError("reviewed input directory changed during scan")
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                if (
                    info.st_uid not in (0, uid)
                    or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
                    or info.st_size < 0
                    or info.st_size > _INPUT_MAX_FILE_BYTES
                    or total_bytes + info.st_size > _INPUT_MAX_TOTAL_BYTES
                ):
                    raise ValueError("reviewed input file is unsafe or exceeds its size bound")
                file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(file_fd)
                    if _input_stat_identity(opened) != _input_stat_identity(info):
                        raise ValueError("reviewed input file changed during open")
                    digest = hashlib.sha256()
                    file_bytes = 0
                    while True:
                        chunk = os.read(file_fd, 64 * 1024)
                        if not chunk:
                            break
                        file_bytes += len(chunk)
                        total_bytes += len(chunk)
                        if (
                            file_bytes > _INPUT_MAX_FILE_BYTES
                            or total_bytes > _INPUT_MAX_TOTAL_BYTES
                        ):
                            raise ValueError("reviewed input content exceeds its size bound")
                        digest.update(chunk)
                    after_fd = os.fstat(file_fd)
                    after_name = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False,
                    )
                    if (
                        file_bytes != opened.st_size
                        or _input_stat_identity(after_fd) != _input_stat_identity(opened)
                        or _input_stat_identity(after_name) != _input_stat_identity(opened)
                    ):
                        raise ValueError("reviewed input file changed during hashing")
                    entries.append(_InputEntry(
                        relative_path, "file", _input_stat_identity(opened),
                        digest.hexdigest(),
                    ))
                finally:
                    os.close(file_fd)
            else:
                raise ValueError("reviewed input tree contains a symlink or special file")
        if _input_stat_identity(os.fstat(directory_fd)) != _input_stat_identity(directory_before):
            raise ValueError("reviewed input directory changed during scan")

    def revalidate_entry(
        entry: _InputEntry,
        directory_identities: dict[bytes, tuple[int, ...]],
    ) -> None:
        if not entry.path:
            if _input_stat_identity(os.fstat(root_fd)) != entry.identity:
                raise ValueError("reviewed input root changed during manifest validation")
            return
        components = entry.path.split(b"/")
        parent_fd = os.dup(root_fd)
        try:
            parent_path = b""
            for component in components[:-1]:
                parent_path = component if not parent_path else parent_path + b"/" + component
                expected_parent = directory_identities.get(parent_path)
                before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    expected_parent is None
                    or not stat.S_ISDIR(before.st_mode)
                    or _input_stat_identity(before) != expected_parent
                ):
                    raise ValueError("reviewed input directory changed during manifest validation")
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
                try:
                    if _input_stat_identity(os.fstat(next_fd)) != expected_parent:
                        raise ValueError("reviewed input directory changed during manifest validation")
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(parent_fd)
                parent_fd = next_fd
            leaf = components[-1]
            before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if _input_stat_identity(before) != entry.identity:
                raise ValueError("reviewed input entry changed during manifest validation")
            flags = directory_flags if entry.kind == "directory" else file_flags
            child_fd = os.open(leaf, flags, dir_fd=parent_fd)
            try:
                if (
                    _input_stat_identity(os.fstat(child_fd)) != entry.identity
                    or _input_stat_identity(os.stat(
                        leaf, dir_fd=parent_fd, follow_symlinks=False,
                    )) != entry.identity
                ):
                    raise ValueError("reviewed input entry changed during manifest validation")
            finally:
                os.close(child_fd)
        finally:
            os.close(parent_fd)

    try:
        root_info = os.fstat(root_fd)
        _validate_input_directory(root_info, leaf=True, uid=uid)
        root_identity = _input_root_identity(root_info)
        entries.append(_InputEntry(b"", "directory", _input_stat_identity(root_info), None))
        visit(root_fd, (), 0)
        directory_identities = {
            entry.path: entry.identity for entry in entries if entry.kind == "directory"
        }
        for entry in reversed(entries):
            revalidate_entry(entry, directory_identities)
        current_fd = _open_input_root(path, uid)
        try:
            if _input_stat_identity(os.fstat(current_fd)) != entries[0].identity:
                raise ValueError("reviewed input root changed during hashing")
        finally:
            os.close(current_fd)
        return _InputProof(root_identity, tuple(entries))
    finally:
        os.close(root_fd)


def _validate_policy(policy: object) -> tuple[str, _InputProof | None]:
    if type(policy) is not Policy:
        raise ValueError("trusted Policy is required")
    image = _validate_image(policy.image)
    if policy.input_root is None:
        return image, None
    if not isinstance(policy.input_root, Path):
        raise ValueError("reviewed input root must be a pathlib Path")
    if policy.input_root.name in ("", ".", "..") or "," in str(policy.input_root):
        raise ValueError("reviewed input path is not safe for Docker mount syntax")
    proof = _input_tree_proof(policy.input_root)
    return image, proof


def parse_spec(raw: bytes, policy: Policy) -> _Spec:
    """Parse canonical, restricted schema-1 capability/pilot JSON."""
    _validate_policy(policy)
    if type(raw) is not bytes or not raw or len(raw) > 4096:
        raise ValueError("specification must be a nonempty bounded byte string")
    try:
        text = raw.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("specification is not valid canonical JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "stage", "run_id"}:
        raise ValueError("specification fields must be exactly schema, stage, run_id")
    if _canonical_bytes(value) != raw:
        raise ValueError("specification JSON is not in canonical form")
    schema = value["schema"]
    if type(schema) is not int or schema != 1:
        raise ValueError("unsupported specification schema")
    stage = value["stage"]
    if not isinstance(stage, str) or stage not in {"capabilities", "hostile-pilot"}:
        raise ValueError("unsupported supervisor stage")
    run_id = value["run_id"]
    if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError("run_id must be exactly 32 lowercase UUID hex characters")
    return _Spec(schema=1, stage=stage, run_id=run_id)


def _container_driver_source() -> str:
    # This source is constant trusted host code, passed only to the pinned image.
    return r'''import errno,json,os,signal,socket,stat,sys,time
M=536870912; S=268435456; P=64; C=50000; T=100000

def emit(value):
    sys.stdout.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
    sys.stdout.flush()

def read_int(path):
    try:
        with open(path,"r",encoding="ascii") as f: return int(f.read().strip())
    except (OSError,ValueError): return None

def unescape_mount(value):
    return value.replace("\\040"," ").replace("\\011","\\t").replace("\\134","\\\\")

def mount_rows():
    rows=[]
    try:
        with open("/proc/self/mountinfo","r",encoding="ascii") as f:
            for line in f:
                left,sep,right=line.rstrip("\n").partition(" - ")
                if sep:
                    a=left.split(); b=right.split()
                    if len(a)>=6 and len(b)>=3:
                        rows.append((unescape_mount(a[4]),a[5].split(","),b[0],b[2].split(",")))
    except OSError: pass
    return rows

def cgroup_values():
    rel={}
    try:
        with open("/proc/self/cgroup","r",encoding="ascii") as f:
            for line in f:
                parts=line.rstrip("\n").split(":",2)
                if len(parts)==3: rel[parts[1]]=parts[2].lstrip("/")
    except OSError: pass
    for mount,opts,fs,superopts in mount_rows():
        if fs=="cgroup2":
            path=os.path.join(mount,rel.get("", ""))
            memory=read_int(os.path.join(path,"memory.max"))
            swap=read_int(os.path.join(path,"memory.swap.max"))
            pids=read_int(os.path.join(path,"pids.max"))
            current=read_int(os.path.join(path,"pids.current"))
            cpu=None; period=None
            try:
                with open(os.path.join(path,"cpu.max"),"r",encoding="ascii") as f:
                    q,per=f.read().split()[:2]; cpu=int(q); period=int(per)
            except (OSError,ValueError): pass
            return {"version":2,"memory_max":memory,"swap_max":swap,"cpu_quota":cpu,"cpu_period":period,"pids_max":pids,"pids_current":current}
    paths={}
    for mount,opts,fs,superopts in mount_rows():
        if fs!="cgroup": continue
        controllers=set(opts)|set(superopts)
        relpath=rel.get(",".join(sorted(controllers)),"")
        for item in rel:
            if item and set(item.split(",")) & controllers:
                relpath=rel[item]; break
        path=os.path.join(mount,relpath)
        if "memory" in controllers: paths["memory"]=path
        if "cpu" in controllers: paths["cpu"]=path
        if "pids" in controllers: paths["pids"]=path
    if {"memory","cpu","pids"} <= set(paths):
        cpu=read_int(os.path.join(paths["cpu"],"cpu.cfs_quota_us"))
        period=read_int(os.path.join(paths["cpu"],"cpu.cfs_period_us"))
        return {"version":1,"memory_max":read_int(os.path.join(paths["memory"],"memory.limit_in_bytes")),"swap_max":read_int(os.path.join(paths["memory"],"memory.memsw.limit_in_bytes")),"cpu_quota":cpu,"cpu_period":period,"pids_max":read_int(os.path.join(paths["pids"],"pids.max")),"pids_current":read_int(os.path.join(paths["pids"],"pids.current"))}
    return {"version":None,"memory_max":None,"swap_max":None,"cpu_quota":None,"cpu_period":None,"pids_max":None,"pids_current":None}

def root_is_readonly():
    for mount,opts,fs,sopts in mount_rows():
        if mount=="/": return "ro" in opts
    return False

def tmpfs_info():
    is_tmpfs=False; options=set()
    for mount,opts,fs,sopts in mount_rows():
        if mount=="/tmp" and fs=="tmpfs":
            is_tmpfs=True; options=set(opts); break
    try:
        v=os.statvfs("/tmp"); size=v.f_blocks*v.f_frsize
    except OSError: size=None
    is_tmpfs=is_tmpfs and {"rw","noexec","nosuid","nodev"}<=options
    return is_tmpfs,size

def check():
    cg=cgroup_values(); tmpfs,size=tmpfs_info()
    if cg["version"]==2:
        memory_ok=cg["memory_max"]==M and cg["swap_max"]==0
    else:
        memory_ok=cg["memory_max"]==M and cg["swap_max"]==M
    ok=(memory_ok and cg["cpu_quota"]==C and cg["cpu_period"]==T and cg["pids_max"]==P and cg["pids_current"] is not None and cg["pids_current"]<=P and tmpfs and size is not None and 0<size<=S and root_is_readonly() and os.geteuid()!=0)
    return {"ok":bool(ok),"cgroup":cg,"root_read_only":root_is_readonly(),"tmpfs":tmpfs,"tmpfs_bytes":size,"effective_uid":os.geteuid()}

def main():
    if len(sys.argv)!=3 or sys.argv[1] not in ("capabilities","hostile-pilot"): return 64
    stage=sys.argv[1]; run_id=sys.argv[2]
    result=check(); emit({"phase":"ready","run_id":run_id,**result})
    if not result["ok"]: return 70
    if sys.stdin.readline(32)!="GO\n": return 71
    if stage=="capabilities": emit({"phase":"done","run_id":run_id,"status":"PASS"}); return 0

    children=[]; failure=None
    try:
        for _ in range(P+2):
            try: pid=os.fork()
            except OSError as exc:
                failure=exc.errno; break
            if pid==0:
                time.sleep(300); os._exit(0)
            children.append(pid)
        current=cgroup_values().get("pids_current")
        limit_enforced=(failure==errno.EAGAIN and current is not None and current>=P)
        emit({"phase":"pids","attempts":len(children),"failure_errno":failure,"pids_current":current,"limit_enforced":bool(limit_enforced)})
    finally:
        for pid in children:
            try: os.kill(pid,signal.SIGKILL)
            except OSError: pass
        for pid in children:
            try: os.waitpid(pid,0)
            except OSError: pass
    if not limit_enforced: return 72

    scratch_path="/tmp/.dotunnel-scratch-probe"
    fd=os.open(scratch_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    exhausted=False; written=0
    try:
        try:
            if hasattr(os,"posix_fallocate"):
                os.posix_fallocate(fd,0,S+1); written=S+1
            else: raise OSError(errno.EOPNOTSUPP,"fallocate unavailable")
        except OSError as exc:
            if exc.errno not in (errno.ENOSPC,errno.EFBIG,errno.EOPNOTSUPP,errno.ENOSYS): raise
            if exc.errno in (errno.ENOSPC,errno.EFBIG): exhausted=True
            else:
                block=b"x"*(1024*1024)
                while written<S+1:
                    try:
                        count=os.write(fd,block[:min(len(block),S+1-written)])
                        if count<=0: break
                        written+=count
                    except OSError as write_error:
                        if write_error.errno in (errno.ENOSPC,errno.EFBIG): exhausted=True; break
                        raise
        if written<S+1 and not exhausted:
            exhausted=True
    finally:
        os.close(fd)
        os.unlink(scratch_path)
    emit({"phase":"scratch","exhausted":bool(exhausted),"attempt_bytes":S+1,"written_bytes":written})
    if not exhausted: return 73

    worker=os.fork()
    if worker==0:
        out_pid=os.fork()
        if out_pid==0:
            chunk=b"O"*4096
            time.sleep(0.5)
            for _ in range(32): os.write(1,chunk)
            while True: signal.pause()
        err_pid=os.fork()
        if err_pid==0:
            chunk=b"E"*4096
            time.sleep(0.5)
            for _ in range(32): os.write(2,chunk)
            while True: signal.pause()
        emit({"phase":"tree-ready","pids":[os.getpid(),out_pid,err_pid]})
        while True: signal.pause()
    while True: signal.pause()

if __name__=="__main__":
    try: code=main()
    except BaseException as exc:
        emit({"phase":"error","type":type(exc).__name__})
        code=74
    raise SystemExit(code)
'''


_CONTAINER_DRIVER = _container_driver_source()


def docker_arguments(spec: _Spec, policy: Policy, owned_name: str) -> list[str]:
    """Build the single fixed Docker-create argv admitted by this supervisor."""
    image, input_proof = _validate_policy(policy)
    if type(spec) is not _Spec or spec.schema != 1 or spec.stage not in {"capabilities", "hostile-pilot"}:
        raise ValueError("a validated supervisor specification is required")
    if _RUN_ID_RE.fullmatch(spec.run_id) is None or owned_name != _CONTAINER_PREFIX + spec.run_id:
        raise ValueError("container name is not the exact run-owned name")
    arguments = [
        "docker", "create", "--pull=never",
        "--name", owned_name,
        "--label", _LABEL_RUN + "=" + spec.run_id,
        "--label", _LABEL_KIND + "=" + _LABEL_VALUE_KIND,
        "--read-only",
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--user", f"{_USER_ID}:{_USER_ID}",
        "--memory", str(CORE_LIMITS.memory_bytes),
        "--memory-swap", str(CORE_LIMITS.memory_swap_bytes),
        "--cpus", "0.5",
        "--pids-limit", str(CORE_LIMITS.process_limit),
        "--stop-timeout", str(CORE_LIMITS.stop_seconds),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={CORE_LIMITS.disk_bytes},uid={_USER_ID},gid={_USER_ID},mode=1777",
        "--interactive",
        "--workdir", "/tmp",
        "--env", "HOME=/tmp",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint", "python",
    ]
    if input_proof is not None:
        if policy.input_root is None:
            raise ValueError("reviewed input proof has no bound input root")
        if _input_tree_proof(policy.input_root) != input_proof:
            raise ValueError("reviewed input tree changed during policy validation")
        arguments.extend((
            "--mount",
            f"type=bind,source={policy.input_root},target={_INPUT_DESTINATION},readonly",
        ))
    arguments.extend((image, "-I", "-c", _CONTAINER_DRIVER, spec.stage, spec.run_id))
    return arguments


def container_is_owned(
    details: object,
    run_id: str,
    owned_name: str,
    container_id: str,
) -> bool:
    """Return true only for this run's exact Docker identity and labels."""
    if not isinstance(details, dict):
        return False
    if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
        return False
    if owned_name != _CONTAINER_PREFIX + run_id:
        return False
    if not isinstance(container_id, str) or _CONTAINER_ID_RE.fullmatch(container_id) is None:
        return False
    if details.get("Id") != container_id or details.get("Name") != "/" + owned_name:
        return False
    config = details.get("Config")
    if not isinstance(config, dict):
        return False
    labels = config.get("Labels")
    return labels == {
        _LABEL_RUN: run_id,
        _LABEL_KIND: _LABEL_VALUE_KIND,
    }


@dataclasses.dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    elapsed_seconds: float


def _safe_env(home: Path | None = None) -> dict[str, str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    if home is not None:
        env["HOME"] = str(home)
    return env


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass


_EXEC_GATE_SOURCE = (
    "import os,sys,time\n"
    "deadline=int(sys.argv[1]); fd=int(sys.argv[2])\n"
    "if os.read(fd,1)!=b'G' or time.monotonic_ns()>=deadline: os._exit(125)\n"
    "os.close(fd)\n"
    "argv=sys.argv[3:]\n"
    "os.execve(argv[0],argv,os.environ)\n"
)


def _spawn_supervised(
    argv: list[str],
    *,
    on_spawn: Callable[[int, int], None] | None,
    launch_deadline_ns: int | None,
    **popen_options: object,
) -> subprocess.Popen[bytes]:
    gate_fd: int | None = None
    command = argv
    if on_spawn is not None:
        if type(launch_deadline_ns) is not int:
            raise ValueError("supervised client requires an absolute launch deadline")
        read_fd, gate_fd = os.pipe()
        command = [
            sys.executable,
            "-I",
            "-c",
            _EXEC_GATE_SOURCE,
            str(launch_deadline_ns),
            str(read_fd),
            *argv,
        ]
        try:
            process = subprocess.Popen(
                command, pass_fds=(read_fd,), **popen_options
            )
        except BaseException:
            os.close(read_fd)
            os.close(gate_fd)
            raise
        os.close(read_fd)
    else:
        process = subprocess.Popen(command, **popen_options)
    try:
        if on_spawn is not None:
            start_ticks = _current_start_ticks(process.pid)
            if start_ticks is None:
                raise OSError("supervised client process identity is unavailable")
            on_spawn(process.pid, start_ticks)
            assert gate_fd is not None
            if os.write(gate_fd, b"G") != 1:
                raise OSError("supervised client gate could not be released")
            os.close(gate_fd)
            gate_fd = None
    except BaseException:
        if gate_fd is not None:
            os.close(gate_fd)
        _kill_process_group(process)
        process.wait()
        raise
    return process

def _bounded_command(
    argv: list[str],
    *,
    timeout: float,
    stdout_limit: int = 64 * 1024,
    stderr_limit: int = 64 * 1024,
    env: dict[str, str] | None = None,
    on_spawn: Callable[[int, int], None] | None = None,
    launch_deadline_ns: int | None = None,
    resource_check: Callable[[], None] | None = None,
) -> _CommandResult:
    """Run one exact host command with selector-based output/deadline bounds."""
    started = time.monotonic()
    process = _spawn_supervised(
        argv,
        on_spawn=on_spawn,
        launch_deadline_ns=launch_deadline_ns,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        cwd="/",
        env=env if env is not None else _safe_env(),
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    output_terminated = False
    deadline = started + max(0.01, timeout)
    timed_out = False
    drain_deadline: float | None = None
    try:
        while selector.get_map():
            if resource_check is not None:
                resource_check()
            now = time.monotonic()
            if drain_deadline is not None and now >= drain_deadline:
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    stream = process.stdout if key.data == "stdout" else process.stderr
                    stream.close()
                break
            if now >= deadline and not timed_out:
                timed_out = True
                _kill_process_group(process)
                drain_deadline = now + 1.0
            effective_deadline = drain_deadline if drain_deadline is not None else deadline
            events = selector.select(max(0.0, min(0.1, effective_deadline - now)))
            if not events and process.poll() is not None:
                # EOF readiness is reported by selectors for the remaining pipes.
                continue
            for key, _mask in events:
                label = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = limits[label] - len(outputs[label])
                if room > 0:
                    outputs[label].extend(chunk[:room])
                if len(chunk) > max(0, room):
                    truncated[label] = True
                if any(truncated.values()) and not output_terminated:
                    output_terminated = True
                    _kill_process_group(process)
        if resource_check is None:
            try:
                returncode = process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                _kill_process_group(process)
                returncode = process.wait(timeout=1.0)
        else:
            wait_deadline = time.monotonic() + 1.0
            killed_for_wait = False
            while True:
                resource_check()
                returncode = process.poll()
                if returncode is not None:
                    break
                now = time.monotonic()
                remaining = wait_deadline - now
                if remaining <= 0:
                    if killed_for_wait:
                        raise subprocess.TimeoutExpired(argv, 1.0)
                    _kill_process_group(process)
                    killed_for_wait = True
                    wait_deadline = now + 1.0
                    continue
                try:
                    returncode = process.wait(timeout=min(0.1, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
    except BaseException:
        _kill_process_group(process)
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            try:
                process.wait(timeout=1.0)
            except BaseException:
                pass
        except BaseException:
            _kill_process_group(process)
        selector.close()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        raise
    assert returncode is not None
    selector.close()
    return _CommandResult(
        returncode=returncode,
        stdout=bytes(outputs["stdout"]),
        stderr=bytes(outputs["stderr"]),
        timed_out=timed_out,
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
        elapsed_seconds=max(0.0, time.monotonic() - started),
    )


def _docker_binary() -> tuple[str | None, str | None]:
    candidate = shutil.which("docker", path="/usr/bin:/bin")
    if candidate is None:
        return None, "docker-client-missing"
    try:
        resolved = Path(candidate).resolve(strict=True)
        info = os.stat(resolved, follow_symlinks=False)
        if (
            not _secure_executable(str(resolved))
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            return None, "docker-client-not-trusted"
    except (OSError, ValueError):
        return None, "docker-client-not-trusted"
    return str(resolved), None


def _docker_argv(docker: str, arguments: list[str]) -> list[str]:
    return [docker, "--host", "unix://" + _DOCKER_SOCKET, *arguments]


def _docker_command(
    docker: str,
    arguments: list[str],
    *,
    timeout: float,
    home: Path | None = None,
    stdout_limit: int = 64 * 1024,
    stderr_limit: int = 64 * 1024,
    on_spawn: Callable[[int, int], None] | None = None,
    launch_deadline_ns: int | None = None,
    resource_check: Callable[[], None] | None = None,
) -> _CommandResult:
    return _bounded_command(
        _docker_argv(docker, arguments),
        timeout=timeout,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
        env=_safe_env(home),
        on_spawn=on_spawn,
        launch_deadline_ns=launch_deadline_ns,
        resource_check=resource_check,
    )

def _parse_json_output(result: _CommandResult) -> object | None:
    if (result.returncode != 0 or result.timed_out
            or result.stdout_truncated or result.stderr_truncated):
        return None
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _proc_cgroup_metadata() -> dict[str, object]:
    result: dict[str, object] = {"version": None, "controllers": [], "memory_accounting": False}
    try:
        with open("/proc/self/mountinfo", "r", encoding="ascii") as stream:
            mounts = stream.read(256 * 1024)
    except OSError:
        return result
    controllers: set[str] = set()
    version: int | None = None
    for line in mounts.splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        right_fields = right.split()
        if len(fields) < 6 or len(right_fields) < 3:
            continue
        fs_type = right_fields[0]
        if fs_type == "cgroup2":
            version = 2
        elif fs_type == "cgroup":
            version = version or 1
            controllers.update(right_fields[2].split(","))
    if version == 2:
        try:
            with open("/sys/fs/cgroup/cgroup.controllers", "r", encoding="ascii") as stream:
                controllers.update(stream.read(4096).split())
        except OSError:
            pass
    result["version"] = version
    result["controllers"] = sorted(controllers)
    result["memory_accounting"] = "memory" in controllers
    result["cpu_accounting"] = "cpu" in controllers or "cpuacct" in controllers
    result["pids_accounting"] = "pids" in controllers
    return result


def _host_resources(
    path: Path | None = None, docker_root: Path | None = None
) -> dict[str, int | None]:
    available: int | None = None
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as stream:
            for line in stream:
                if line.startswith("MemAvailable:"):
                    available = int(line.split()[1]) * 1024
                    break
    except (OSError, ValueError, IndexError):
        pass
    free: int | None = None
    docker_free: int | None = None
    try:
        free = shutil.disk_usage(path if path is not None else "/").free
    except OSError:
        pass
    if docker_root is not None:
        try:
            docker_free = shutil.disk_usage(docker_root).free
        except OSError:
            pass
    return {
        "memory_available_bytes": available,
        "disk_free_bytes": free,
        "docker_root_disk_free_bytes": docker_free,
    }

def _host_resource_reason(
    resources: Mapping[str, int | None], *, initial: bool = False,
) -> str | None:
    keys = ("memory_available_bytes", "disk_free_bytes", "docker_root_disk_free_bytes")
    if any(type(resources.get(key)) is not int or resources[key] < 0 for key in keys):
        return "host-resource-telemetry-unavailable"
    memory_floor = _HOST_START_MEMORY_BYTES if initial else _HOST_MIN_MEMORY_BYTES
    disk_floor = _HOST_START_DISK_BYTES if initial else _HOST_MIN_DISK_BYTES
    if resources["memory_available_bytes"] < memory_floor or any(
        resources[key] < disk_floor for key in keys[1:]
    ):
        return "host-resource-headroom-insufficient" if initial else "host-resource-pressure"
    return None



def _secure_executable(path: str) -> bool:
    try:
        resolved = Path(path).resolve(strict=True)
        info = os.stat(resolved, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            return False
        if info.st_uid not in (0, _effective_uid()) or info.st_mode & 0o022:
            return False
        parent = resolved.parent
        while parent != parent.parent:
            parent_info = os.stat(parent, follow_symlinks=False)
            if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o022:
                return False
            parent = parent.parent
        return True
    except (OSError, ValueError):
        return False


def _bwrap_probe() -> dict[str, object]:
    binary = shutil.which("bwrap", path="/usr/bin:/bin")
    metadata: dict[str, object] = {"available": binary is not None, "version": None, "namespace_test": "not-run"}
    if binary is None or not _secure_executable(binary):
        metadata["available"] = False
        metadata["reason"] = "bwrap-missing-or-untrusted"
        return metadata
    version = _bounded_command([str(Path(binary).resolve()), "--version"], timeout=2, stdout_limit=4096, stderr_limit=4096)
    if version.returncode == 0 and not version.timed_out and not version.stdout_truncated:
        metadata["version"] = version.stdout.decode("utf-8", "replace").strip()[:256]
    true_path = "/usr/bin/true"
    if not _secure_executable(true_path):
        metadata["namespace_test"] = "blocked-true-executable-untrusted"
        return metadata
    command = [
        str(Path(binary).resolve()), "--die-with-parent", "--new-session",
        "--unshare-user", "--unshare-pid", "--unshare-net",
        "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
        "--", true_path,
    ]
    result = _bounded_command(command, timeout=4, stdout_limit=4096, stderr_limit=4096)
    metadata["namespace_test"] = "available" if result.returncode == 0 and not result.timed_out else "blocked"
    return metadata


def probe() -> dict[str, object]:
    """Read-only Linux/Docker/cgroup/bwrap capability probe; never claims a pilot pass."""
    uid = _effective_uid()
    reasons: list[str] = []
    if uid == 0:
        reasons.append("root-supervisor-refused")
    docker: dict[str, object] = {"available": False, "server_reachable": False}
    docker_path: str | None = None
    if uid != 0:
        docker_path, docker_reason = _docker_binary()
        if docker_reason:
            reasons.append(docker_reason)
        elif docker_path is not None:
            try:
                socket_info = os.lstat(_DOCKER_SOCKET)
                if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != 0 or socket_info.st_mode & 0o002:
                    raise OSError("unsafe Docker socket")
            except OSError:
                reasons.append("local-docker-socket-unavailable-or-unsafe")
            else:
                version = _docker_command(
                    docker_path, ["version", "--format", "{{json .}}"],
                    timeout=5, stdout_limit=16 * 1024, stderr_limit=4096,
                )
                info = _docker_command(
                    docker_path, ["info", "--format", "{{json .}}"],
                    timeout=5, stdout_limit=32 * 1024, stderr_limit=4096,
                )
                version_data = _parse_json_output(version)
                info_data = _parse_json_output(info)
                docker["available"] = True
                docker["client_path"] = docker_path
                docker["client_version"] = None
                if isinstance(version_data, dict):
                    client = version_data.get("Client")
                    server = version_data.get("Server")
                    if isinstance(client, dict):
                        docker["client_version"] = client.get("Version")
                    if isinstance(server, dict):
                        docker["server_version"] = server.get("Version")
                if isinstance(info_data, dict):
                    docker["server_reachable"] = True
                    for key in (
                        "ServerVersion", "OperatingSystem", "OSType", "Architecture",
                        "CgroupDriver", "CgroupVersion", "DockerRootDir", "SecurityOptions",
                    ):
                        value = info_data.get(key)
                        if isinstance(value, (str, int, float, bool, list)):
                            docker[key.lower()] = value
                    if str(info_data.get("OSType", "")).lower() != "linux":
                        reasons.append("docker-daemon-not-linux")
                else:
                    reasons.append("docker-daemon-unreachable")
    cgroup = _proc_cgroup_metadata()
    if cgroup.get("version") not in (1, 2):
        reasons.append("host-cgroup-accounting-unavailable")
    else:
        for controller, key in (("memory", "memory_accounting"), ("cpu", "cpu_accounting"), ("pids", "pids_accounting")):
            if not cgroup.get(key):
                reasons.append("host-cgroup-" + controller + "-accounting-unavailable")
    metadata = {
        "schema": 1,
        "status": "BLOCKED" if reasons else "AVAILABLE",
        "evidence": "host-prerequisite-probe-only",
        "platform": {"system": platform.system().lower(), "machine": platform.machine().lower()},
        "effective_uid": uid,
        "docker": docker,
        "host_cgroup": cgroup,
        "bwrap": (
            {"available": False, "namespace_test": "not-run-root-refused"}
            if uid == 0
            else _bwrap_probe()
        ),
        "host_resources": _host_resources(
            docker_root=Path(str(docker["dockerrootdir"]))
            if isinstance(docker.get("dockerrootdir"), str)
            and Path(str(docker["dockerrootdir"])).is_absolute()
            else None
        ),
        "reasons": reasons,
    }
    if metadata["platform"]["system"] != "linux":
        metadata["status"] = "BLOCKED"
        metadata["reasons"] = list(metadata["reasons"]) + ["linux-host-required"]
    return metadata


def _read_file(path: Path, *, max_bytes: int = 64 * 1024) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise ValueError("unsafe bounded metadata file")
        pieces: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            pieces.append(chunk)
            remaining -= len(chunk)
        result = b"".join(pieces)
        if len(result) > max_bytes:
            raise ValueError("metadata file exceeds bound")
        return result
    finally:
        os.close(fd)


def _load_json(data: bytes) -> object:
    return json.loads(data.decode("ascii"), object_pairs_hook=_unique_object, parse_constant=_reject_json_constant)


def _current_start_ticks(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stream:
            record = stream.read(4096)
        close = record.rfind(")")
        if close < 0:
            return None
        fields = record[close + 2 :].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def _current_process_matches(pid: int, start_ticks: int, uid: int) -> bool:
    try:
        return os.stat(f"/proc/{pid}").st_uid == uid and _current_start_ticks(pid) == start_ticks
    except OSError:
        return False
def _kill_verified_process(pid: int, start_ticks: int, uid: int) -> bool:
    """Kill only the process instance recorded in the private ledger."""
    if not _current_process_matches(pid, start_ticks, uid):
        return True
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return False
    try:
        pidfd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    try:
        if not _current_process_matches(pid, start_ticks, uid):
            return True
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if not _current_process_matches(pid, start_ticks, uid):
                return True
            time.sleep(0.02)
        return not _current_process_matches(pid, start_ticks, uid)
    finally:
        os.close(pidfd)


def _private_home() -> Path:
    uid = _effective_uid()
    if uid == 0:
        raise ValueError("root supervisor execution is refused")
    home = Path.home()
    try:
        account_home = Path(pwd.getpwuid(uid).pw_dir)
    except (KeyError, OSError) as exc:
        raise ValueError("supervisor account has no trusted home directory") from exc
    if not home.is_absolute() or home != account_home:
        raise ValueError("HOME does not match the supervisor account")
    _path_snapshot(home)
    return home


def _mkdir_private(path: Path, *, require_private: bool = True) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("private verifier directory is not a real directory")
    if info.st_uid != _effective_uid() or info.st_mode & 0o022:
        raise ValueError("verifier directory has unsafe ownership or writability")
    if require_private and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("private verifier directory has unsafe permissions")
    _path_snapshot(path)


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short private metadata write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_root_identity(root: Path) -> tuple[int, int, int, int]:
    identity = _path_snapshot(root)
    if identity[2:] != (_effective_uid(), 0o700):
        raise ValueError("private run directory ownership or mode changed")
    return identity


def _private_metadata_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != _effective_uid()
        or mode != 0o600
        or info.st_nlink != 1
    ):
        raise ValueError("private metadata file ownership, mode, or identity is unsafe")
    return (
        info.st_dev, info.st_ino, info.st_uid, mode, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _private_metadata_at(directory_fd: int, name: str) -> tuple[int, int, int, int, int, int, int, int]:
    if Path(name).name != name:
        raise ValueError("private metadata filename is not a leaf")
    return _private_metadata_identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))


def _private_metadata_snapshot(root: Path, name: str) -> tuple[int, int, int, int, int, int, int, int]:
    if Path(name).name != name:
        raise ValueError("private metadata filename is not a leaf")
    return _private_metadata_identity(os.lstat(root / name))


def _read_private_metadata(root: Path, name: str, *, max_bytes: int) -> bytes:
    root_identity = _private_root_identity(root)
    identity = _private_metadata_snapshot(root, name)
    data = _read_file(root / name, max_bytes=max_bytes)
    if (
        _private_root_identity(root) != root_identity
        or _private_metadata_snapshot(root, name) != identity
    ):
        raise ValueError("private metadata identity changed while reading")
    return data


def _open_private_root_dir(root: Path) -> tuple[int, tuple[int, int, int, int]]:
    root_identity = _private_root_identity(root)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = os.open(root, flags)
    info = os.fstat(directory_fd)
    if (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) != root_identity:
        os.close(directory_fd)
        raise ValueError("private run directory identity changed while opening")
    return directory_fd, root_identity


def _assert_open_private_root(
    root: Path, directory_fd: int, expected: tuple[int, int, int, int],
) -> None:
    info = os.fstat(directory_fd)
    if (
        (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) != expected
        or _private_root_identity(root) != expected
    ):
        raise ValueError("private run directory identity changed")


def _open_private_lock(root: Path, name: str) -> int:
    if name not in {".ledger.lock", ".go.lock"}:
        raise ValueError("unknown private lock name")
    directory_fd, root_identity = _open_private_root_dir(root)
    lock_fd: int | None = None
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            lock_fd = os.open(
                name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd,
            )
        except FileExistsError:
            lock_fd = os.open(name, flags, dir_fd=directory_fd)
        identity = _private_metadata_identity(os.fstat(lock_fd))
        if identity[5] != 0 or _private_metadata_at(directory_fd, name) != identity:
            raise ValueError("private lock file identity is unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _assert_open_private_root(root, directory_fd, root_identity)
        if _private_metadata_at(directory_fd, name) != identity:
            raise ValueError("private lock file was replaced")
        os.close(directory_fd)
        return lock_fd
    except BaseException:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(directory_fd)
        raise


def _release_private_lock(lock_fd: int) -> None:
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def _write_atomic(path: Path, data: bytes, root: Path) -> None:
    if path != root / "ledger.json" or not isinstance(data, bytes):
        raise ValueError("atomic ledger target is not the private ledger")
    lock_fd = _open_private_lock(root, ".ledger.lock")
    directory_fd: int | None = None
    temp_fd: int | None = None
    temp_name: str | None = None
    temp_dev_ino: tuple[int, int] | None = None
    try:
        directory_fd, root_identity = _open_private_root_dir(root)
        target_before: tuple[int, int, int, int, int, int, int, int] | None
        try:
            target_before = _private_metadata_at(directory_fd, "ledger.json")
        except FileNotFoundError:
            target_before = None
        temp_name = f".ledger.tmp.{os.getpid()}.{secrets.token_hex(16)}"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=directory_fd)
        created = os.fstat(temp_fd)
        _private_metadata_identity(created)
        temp_dev_ino = (created.st_dev, created.st_ino)
        view = memoryview(data)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise OSError("short private metadata write")
            view = view[written:]
        os.fsync(temp_fd)
        temp_identity = _private_metadata_identity(os.fstat(temp_fd))
        if _private_metadata_at(directory_fd, temp_name) != temp_identity:
            raise ValueError("atomic ledger temporary identity changed")
        _assert_open_private_root(root, directory_fd, root_identity)
        try:
            target_now = _private_metadata_at(directory_fd, "ledger.json")
        except FileNotFoundError:
            target_now = None
        if target_now != target_before:
            raise ValueError("ledger destination identity changed before atomic replace")
        os.replace(
            temp_name, "ledger.json",
            src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
        )
        temp_name = None
        # Rename changes ctime; the held inode's other fields must stay stable.
        committed_identity = _private_metadata_identity(os.fstat(temp_fd))
        if (committed_identity[:-1] != temp_identity[:-1]
                or _private_metadata_at(directory_fd, "ledger.json") != committed_identity):
            raise ValueError("atomic ledger destination identity changed")
        os.fsync(directory_fd)
        _assert_open_private_root(root, directory_fd, root_identity)
    except BaseException:
        if directory_fd is not None and temp_name is not None and temp_dev_ino is not None:
            try:
                _assert_open_private_root(root, directory_fd, root_identity)
                current = _private_metadata_at(directory_fd, temp_name)
                if current[:2] == temp_dev_ino:
                    os.unlink(temp_name, dir_fd=directory_fd)
            except (OSError, ValueError):
                pass
        raise
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if directory_fd is not None:
            os.close(directory_fd)
        _release_private_lock(lock_fd)


def _source_identity() -> tuple[Path, str, int, int]:
    source = Path(__file__).resolve(strict=True)
    _path_snapshot(source, directory=False)
    before = os.stat(source, follow_symlinks=False)
    if before.st_size > 2 * _MIB:
        raise ValueError("supervisor source exceeds its fixed size bound")
    digest = hashlib.sha256(_read_file(source, max_bytes=2 * _MIB)).hexdigest()
    after = os.stat(source, follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise ValueError("supervisor source changed while being identified")
    return source, digest, before.st_dev, before.st_ino


def _python_identity() -> tuple[Path, int, int]:
    executable = Path(sys.executable).resolve(strict=True)
    info = os.stat(executable, follow_symlinks=False)
    if not _secure_executable(str(executable)):
        raise ValueError("Python executable is not a trusted regular executable")
    return executable, info.st_dev, info.st_ino


def _ledger_read(root: Path) -> dict[str, object] | None:
    try:
        data = _read_private_metadata(root, "ledger.json", max_bytes=16 * 1024)
        value = _load_json(data)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    expected = {
        "schema", "run_id", "name", "state", "container_id", "attempted",
        "cleanup_confirmed", "cleanup_reason", "docker_pid", "docker_start_ticks",
        "status", "source_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != 1:
        return None
    return value


def _ledger_write(root: Path, ledger: dict[str, object]) -> None:
    _private_root_identity(root)
    _write_atomic(root / "ledger.json", _canonical_bytes(ledger), root)


def _docker_inspect(
    docker: str,
    reference: str,
    *,
    timeout: float = 5,
    home: Path | None = None,
    resource_check: Callable[[], None] | None = None,
) -> dict[str, object] | None:
    result = _docker_command(
        docker, ["container", "inspect", reference],
        timeout=timeout, home=home, resource_check=resource_check,
    )
    value = _parse_json_output(result)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return None
    return value[0]


def _docker_reference_absent(
    docker: str, reference: str, home: Path | None = None, *,
    resource_check: Callable[[], None] | None = None,
) -> bool:
    result = _docker_command(
        docker, ["container", "inspect", reference], timeout=5, home=home,
        stdout_limit=4096, stderr_limit=4096, resource_check=resource_check,
    )
    if result.returncode == 0 or result.timed_out or result.stdout_truncated or result.stderr_truncated:
        return False
    message = (result.stderr + result.stdout).decode("utf-8", "replace").lower()
    return "no such object" in message or "no such container" in message


def _state_running(details: dict[str, object]) -> bool:
    state = details.get("State")
    return isinstance(state, dict) and state.get("Running") is True


def _owned_by_run(details: object, run_id: str, name: str) -> str | None:
    if not isinstance(details, dict):
        return None
    container_id = details.get("Id")
    if isinstance(container_id, str) and container_is_owned(details, run_id, name, container_id):
        return container_id
    return None


def _inspect_expected(
    docker: str,
    run_id: str,
    name: str,
    *,
    container_id: str | None = None,
    home: Path | None = None,
    resource_check: Callable[[], None] | None = None,
) -> dict[str, object] | None:
    reference = container_id if container_id is not None else name
    details = _docker_inspect(
        docker, reference, home=home, resource_check=resource_check,
    )
    if details is None or _owned_by_run(details, run_id, name) is None:
        return None
    if container_id is not None and details.get("Id") != container_id:
        return None
    return details


def _cleanup_container(
    docker: str,
    run_id: str,
    name: str,
    container_id: str | None,
    *,
    home: Path | None = None,
    resource_check: Callable[[], None] | None = None,
) -> tuple[bool, str, str | None]:
    """Stop/remove only a repeatedly inspected exact run-owned container."""
    details = _inspect_expected(
        docker, run_id, name, container_id=container_id, home=home,
        resource_check=resource_check,
    )
    resolved_id = _owned_by_run(details, run_id, name) if details is not None else None
    if details is None and container_id is None:
        # Reconcile an interrupted create through the exact deterministic name.
        details = _inspect_expected(
            docker, run_id, name, home=home, resource_check=resource_check,
        )
        resolved_id = _owned_by_run(details, run_id, name) if details is not None else None
    if details is None:
        if container_id is not None:
            by_name = _docker_inspect(
                docker, name, home=home, resource_check=resource_check,
            )
            if by_name is not None:
                return False, "name-now-refers-to-an-unowned-container", container_id
            absent_id = _docker_reference_absent(
                docker, container_id, home, resource_check=resource_check,
            )
            absent_name = _docker_reference_absent(
                docker, name, home, resource_check=resource_check,
            )
            confirmed = absent_id and absent_name
            return confirmed, "already-absent" if confirmed else "absence-unconfirmed", container_id
        return False, "create-outcome-unresolved", None
    if resolved_id is None:
        return False, "ownership-check-failed", container_id
    if _state_running(details):
        # Recheck identity immediately before every destructive Docker request.
        current = _inspect_expected(
            docker, run_id, name, container_id=resolved_id, home=home,
            resource_check=resource_check,
        )
        if current is None:
            return False, "ownership-changed-before-stop", resolved_id
        stopped = _docker_command(
            docker, ["container", "stop", "--time", str(CORE_LIMITS.stop_seconds), resolved_id],
            timeout=CORE_LIMITS.stop_seconds + 3, home=home, resource_check=resource_check,
        )
        current = _inspect_expected(
            docker, run_id, name, container_id=resolved_id, home=home,
            resource_check=resource_check,
        )
        if current is None:
            return False, "ownership-lost-after-stop", resolved_id
        if _state_running(current):
            current = _inspect_expected(
                docker, run_id, name, container_id=resolved_id, home=home,
                resource_check=resource_check,
            )
            if current is None:
                return False, "ownership-changed-before-kill", resolved_id
            killed = _docker_command(
                docker, ["container", "kill", "--signal", "KILL", resolved_id],
                timeout=5, home=home, resource_check=resource_check,
            )
            current = _inspect_expected(
                docker, run_id, name, container_id=resolved_id, home=home,
                resource_check=resource_check,
            )
            if current is None or _state_running(current) or killed.returncode != 0:
                return False, "container-kill-unconfirmed", resolved_id
        elif stopped.returncode != 0 and _state_running(current):
            return False, "container-stop-unconfirmed", resolved_id
    current = _inspect_expected(
        docker, run_id, name, container_id=resolved_id, home=home,
        resource_check=resource_check,
    )
    if current is None:
        return False, "ownership-changed-before-remove", resolved_id
    if _state_running(current):
        return False, "container-still-running", resolved_id
    removed = _docker_command(
        docker, ["container", "rm", resolved_id], timeout=8, home=home,
        resource_check=resource_check,
    )
    if removed.returncode != 0 or removed.timed_out:
        return False, "container-remove-failed", resolved_id
    absent_id = _docker_reference_absent(
        docker, resolved_id, home, resource_check=resource_check,
    )
    by_name = _docker_inspect(docker, name, home=home, resource_check=resource_check)
    if by_name is not None:
        return False, "owned-name-reused-or-foreign-container-present", resolved_id
    absent_name = _docker_reference_absent(
        docker, name, home, resource_check=resource_check,
    )
    confirmed = absent_id and absent_name
    return confirmed, "removed" if confirmed else "removal-absence-unconfirmed", resolved_id



def _control_read(root: Path, expected_digest: str) -> dict[str, object] | None:
    try:
        root_identity = _private_root_identity(root)
        data = _read_private_metadata(root, "control.json", max_bytes=16 * 1024)
        if hashlib.sha256(data).hexdigest() != expected_digest:
            return None
        control = _load_json(data)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    keys = {
        "schema", "run_id", "name", "root", "root_dev", "root_ino", "owner_uid",
        "source_path", "source_sha256", "source_dev", "source_ino",
        "python_path", "python_dev", "python_ino",
        "docker_path", "docker_root_path", "controller_pid", "controller_start_ticks",
        "deadline_ns",
    }
    if not isinstance(control, dict) or set(control) != keys or control.get("schema") != 1:
        return None
    if control.get("root") != str(root) or control.get("owner_uid") != _effective_uid():
        return None
    try:
        docker_root_value = control.get("docker_root_path")
        if not isinstance(docker_root_value, str):
            return None
        docker_root = Path(docker_root_value)
        if (
            not docker_root.is_absolute()
            or ".." in docker_root.parts
            or str(docker_root) != docker_root_value
            or docker_root.resolve(strict=True) != docker_root
            or not stat.S_ISDIR(os.stat(docker_root, follow_symlinks=False).st_mode)
        ):
            return None
        root_info = os.stat(root, follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        return None
    try:
        current_root_identity = _private_root_identity(root)
    except (OSError, ValueError):
        return None
    if (
        current_root_identity != root_identity
        or (control.get("root_dev"), control.get("root_ino"))
        != (root_info.st_dev, root_info.st_ino)
    ):
        return None
    return control


def _source_matches(control: dict[str, object]) -> bool:
    try:
        source = Path(str(control["source_path"]))
        _path_snapshot(source, directory=False)
        info = os.stat(source, follow_symlinks=False)
        digest = hashlib.sha256(_read_file(source, max_bytes=2 * _MIB)).hexdigest()
        python = Path(str(control["python_path"]))
        python_info = os.stat(python, follow_symlinks=False)
        return (
            digest == control["source_sha256"]
            and (info.st_dev, info.st_ino) == (control["source_dev"], control["source_ino"])
            and (python_info.st_dev, python_info.st_ino) == (control["python_dev"], control["python_ino"])
            and Path(sys.executable).resolve(strict=True) == python
        )
    except (OSError, ValueError, KeyError):
        return False


def _write_private_marker(root: Path, name: str, contents: bytes) -> bool:
    if name not in {"go.closed", "go.claimed"}:
        return False
    try:
        root_identity = _private_root_identity(root)
        try:
            _write_exclusive(root / name, contents)
        except FileExistsError:
            pass
        if _read_private_metadata(root, name, max_bytes=32) != contents:
            return False
        directory_fd, opened_identity = _open_private_root_dir(root)
        try:
            if opened_identity != root_identity:
                return False
            os.fsync(directory_fd)
            _assert_open_private_root(root, directory_fd, root_identity)
        finally:
            os.close(directory_fd)
        return True
    except (OSError, ValueError):
        return False


def _go_marker_present(root: Path, name: str) -> bool:
    try:
        _private_metadata_snapshot(root, name)
        return True
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return True

def _go_ledger_ready(root: Path) -> bool:
    ledger = _ledger_read(root)
    if ledger is None:
        return False
    run_id = ledger.get("run_id")
    container_id = ledger.get("container_id")
    docker_pid = ledger.get("docker_pid")
    start_ticks = ledger.get("docker_start_ticks")
    return (
        isinstance(run_id, str)
        and _RUN_ID_RE.fullmatch(run_id) is not None
        and ledger.get("name") == _CONTAINER_PREFIX + run_id
        and ledger.get("state") == "started"
        and ledger.get("attempted") is True
        and ledger.get("cleanup_confirmed") is False
        and isinstance(container_id, str)
        and _CONTAINER_ID_RE.fullmatch(container_id) is not None
        and type(docker_pid) is int
        and docker_pid > 0
        and type(start_ticks) is int
        and start_ticks >= 0
    )


def _close_go_admission(root: Path) -> bool:
    try:
        lock_fd = _open_private_lock(root, ".go.lock")
    except (OSError, ValueError):
        return False
    try:
        return _write_private_marker(root, "go.closed", b"closed\n")
    finally:
        _release_private_lock(lock_fd)


def _remove_private_root(root: Path, expected_dev: int, expected_ino: int) -> bool:
    parent_fd: int | None = None
    directory_fd: int | None = None
    go_lock: int | None = None
    ledger_lock: int | None = None
    root_identity: tuple[int, int, int, int] | None = None
    fence_removed = False
    root_removed = False
    keep_go_lock = False
    try:
        parent_fd, _parent_identity = _open_private_root_dir(root.parent)
        root_identity = _private_root_identity(root)
        parent_entry = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (root_identity[0], root_identity[1]) != (expected_dev, expected_ino)
            or (parent_entry.st_dev, parent_entry.st_ino, parent_entry.st_uid,
                stat.S_IMODE(parent_entry.st_mode)) != root_identity
        ):
            return False
        go_lock = _open_private_lock(root, ".go.lock")
        if not _write_private_marker(root, "go.closed", b"closed\n"):
            keep_go_lock = True
            return False
        ledger_lock = _open_private_lock(root, ".ledger.lock")
        directory_fd, opened_identity = _open_private_root_dir(root)
        if opened_identity != root_identity:
            return False
        allowed = {
            "ledger.json", "control.json", ".ledger.lock", ".go.lock",
            "go.closed", "go.claimed",
        }
        entries: list[tuple[str, tuple[int, int, int, int, int, int, int, int]]] = []
        with os.scandir(directory_fd) as scan:
            for entry in scan:
                name = entry.name
                if name not in allowed and re.fullmatch(
                    r"\.ledger\.tmp\.[1-9][0-9]*\.[0-9a-f]{32}", name,
                ) is None:
                    return False
                identity = _private_metadata_at(directory_fd, name)
                if identity[5] > 16 * 1024:
                    return False
                if name in {".ledger.lock", ".go.lock"} and identity[5] != 0:
                    return False
                if name == "go.closed" and _read_private_metadata(
                    root, name, max_bytes=32,
                ) != b"closed\n":
                    return False
                if name == "go.claimed" and _read_private_metadata(
                    root, name, max_bytes=32,
                ) != b"claimed\n":
                    return False
                entries.append((name, identity))
        entries.sort(key=lambda item: item[0] == "go.closed")
        for name, identity in entries:
            if _private_metadata_at(directory_fd, name) != identity:
                return False
            os.unlink(name, dir_fd=directory_fd)
            if name == "go.closed":
                fence_removed = True
        _assert_open_private_root(root, directory_fd, root_identity)
        os.fsync(directory_fd)
        os.close(directory_fd)
        directory_fd = None
        parent_entry = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (parent_entry.st_dev, parent_entry.st_ino, parent_entry.st_uid,
             stat.S_IMODE(parent_entry.st_mode)) != root_identity
        ):
            return False
        os.rmdir(root.name, dir_fd=parent_fd)
        root_removed = True
        os.fsync(parent_fd)
        return True
    except (OSError, ValueError):
        return False
    finally:
        if fence_removed and not root_removed:
            try:
                if (
                    root_identity is None
                    or _private_root_identity(root) != root_identity
                    or not _write_private_marker(root, "go.closed", b"closed\n")
                ):
                    keep_go_lock = True
            except (OSError, ValueError):
                keep_go_lock = True
        if directory_fd is not None:
            os.close(directory_fd)
        if ledger_lock is not None:
            _release_private_lock(ledger_lock)
        if go_lock is not None and not keep_go_lock:
            _release_private_lock(go_lock)
        if parent_fd is not None:
            os.close(parent_fd)


def _private_root_absent(root: Path) -> bool:
    try:
        os.lstat(root)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _watchdog_client_quiesced(ledger: dict[str, object], owner_uid: int) -> bool:
    pid = ledger.get("docker_pid")
    start_ticks = ledger.get("docker_start_ticks")
    if type(pid) is not int or pid <= 0 or type(start_ticks) is not int or start_ticks < 0:
        return False
    try:
        killed = _kill_verified_process(pid, start_ticks, owner_uid)
        still_matches = _current_process_matches(pid, start_ticks, owner_uid)
    except (OSError, ValueError, RuntimeError):
        return False
    return killed and not still_matches


def _watchdog(root: Path, expected_control_digest: str) -> int:
    control = _control_read(root, expected_control_digest)
    if control is None or not _source_matches(control):
        return 70
    docker = str(control["docker_path"])
    docker_root = Path(str(control["docker_root_path"]))
    if not _secure_executable(docker):
        return 71
    if sys.stdout is None:
        return 71
    sys.stdout.write("READY\n")
    sys.stdout.flush()
    run_id = str(control["run_id"])
    name = str(control["name"])
    deadline_ns = int(control["deadline_ns"])
    controller_pid = int(control["controller_pid"])
    controller_ticks = int(control["controller_start_ticks"])
    owner_uid = int(control["owner_uid"])
    telemetry_failure_latched: str | None = None
    while True:
        ledger = _ledger_read(root)
        if ledger is None or ledger.get("run_id") != run_id or ledger.get("name") != name:
            return 72
        if ledger.get("state") == "complete" and ledger.get("cleanup_confirmed") is True:
            try:
                admission_lock = _open_private_lock(root, ".go.lock")
            except (OSError, ValueError):
                return 75
            if not _write_private_marker(root, "go.closed", b"closed\n"):
                # Keep the shared lock held until process exit; no controller
                # can mistake a failed fence for permission to send GO.
                return 75
            if ledger.get("attempted") is True and not _watchdog_client_quiesced(
                ledger, owner_uid,
            ):
                previous_reason = ledger.get("cleanup_reason")
                ledger["state"] = "watchdog-unresolved"
                ledger["cleanup_confirmed"] = False
                ledger["cleanup_reason"] = (
                    previous_reason + ";docker-client-quiescence-unconfirmed"
                    if isinstance(previous_reason, str) and previous_reason
                    else "docker-client-quiescence-unconfirmed"
                )
                ledger["status"] = "BLOCKED"
                try:
                    _ledger_write(root, ledger)
                except (OSError, ValueError):
                    return 73
                _release_private_lock(admission_lock)
                return 74
            _release_private_lock(admission_lock)
            removed = _remove_private_root(
                root, int(control["root_dev"]), int(control["root_ino"])
            )
            return 0 if removed or _private_root_absent(root) else 75
        now_ns = time.monotonic_ns()
        controller_alive = _current_process_matches(controller_pid, controller_ticks, owner_uid)
        if not controller_alive or now_ns >= deadline_ns:
            try:
                admission_lock = _open_private_lock(root, ".go.lock")
            except (OSError, ValueError):
                return 76
            fence_confirmed = _write_private_marker(root, "go.closed", b"closed\n")
            if fence_confirmed:
                _release_private_lock(admission_lock)
            container_id = ledger.get("container_id")
            if not isinstance(container_id, str) or _CONTAINER_ID_RE.fullmatch(container_id) is None:
                container_id = None
            if ledger.get("attempted") is not True:
                confirmed, reason, actual_id = True, "no-create-request-issued", None
                client_quiesced = True
                intermediate_write_failed = False
                telemetry_failure = telemetry_failure_latched
            else:
                home = Path(pwd.getpwuid(owner_uid).pw_dir)
                telemetry_failure = telemetry_failure_latched

                def resource_check() -> None:
                    nonlocal telemetry_failure, telemetry_failure_latched
                    try:
                        failure = _host_resource_reason(
                            _host_resources(home, docker_root),
                        )
                    except Exception:
                        failure = "host-resource-telemetry-unavailable"
                    if failure is not None and telemetry_failure_latched is None:
                        telemetry_failure_latched = failure
                    if telemetry_failure is None:
                        telemetry_failure = telemetry_failure_latched

                client_quiesced = _watchdog_client_quiesced(ledger, owner_uid)
                intermediate_write_failed = False
                if container_id is None:
                    discovered = _inspect_expected(
                        docker, run_id, name, home=home, resource_check=resource_check,
                    )
                    if discovered is not None:
                        container_id = _owned_by_run(discovered, run_id, name)
                        if container_id is not None:
                            ledger["container_id"] = container_id
                            ledger["state"] = "create-reconciled"
                            try:
                                _ledger_write(root, ledger)
                            except (OSError, ValueError):
                                intermediate_write_failed = True
                if container_id is None:
                    # Killing a client does not cancel an in-flight daemon
                    # create. NotFound cannot prove noncreation without its
                    # acknowledged CID; preserve the intent for reconciliation.
                    confirmed = False
                    reason = "create-outcome-unresolved"
                    actual_id = None
                else:
                    confirmed, reason, actual_id = _cleanup_container(
                        docker, run_id, name, container_id, home=home,
                        resource_check=resource_check,
                    )
                resource_check()
            failures: list[str] = []
            if not client_quiesced:
                failures.append("docker-client-quiescence-unconfirmed")
            if telemetry_failure is not None:
                failures.append(telemetry_failure)
            if not fence_confirmed:
                failures.append("go-admission-fence-unconfirmed")
            if intermediate_write_failed:
                failures.append("cid-reconciliation-ledger-write-failed")
            if failures:
                reason = ";".join((*failures, reason))
            confirmed = confirmed and client_quiesced and telemetry_failure is None and fence_confirmed
            ledger["state"] = "watchdog-cleaned" if confirmed else "watchdog-unresolved"
            ledger["container_id"] = actual_id
            ledger["cleanup_confirmed"] = confirmed
            ledger["cleanup_reason"] = reason
            ledger["status"] = "BLOCKED"
            try:
                _ledger_write(root, ledger)
            except (OSError, ValueError):
                return 73
            if not fence_confirmed:
                # The lock remains held through this process's exit.
                return 74
            if not controller_alive and confirmed:
                root_info = os.stat(root, follow_symlinks=False)
                removed = _remove_private_root(root, root_info.st_dev, root_info.st_ino)
                return 0 if removed else 75
            if now_ns >= deadline_ns:
                return 0 if confirmed else 74
        time.sleep(0.2)


def _watchdog_start(
    root: Path,
    control_digest: str,
    python: Path,
    source: Path,
    home: Path,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [str(python), "-I", str(source), "--_watchdog", str(root), control_digest],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        cwd="/",
        env=_safe_env(home),
    )


def _wait_watchdog_ready(
    process: subprocess.Popen[bytes], deadline_ns: int,
    *, resource_check: Callable[[], None] | None = None,
) -> None:
    stream = process.stdout
    if stream is None:
        raise RuntimeError("independent watchdog readiness channel is unavailable")
    selector = selectors.DefaultSelector()
    os.set_blocking(stream.fileno(), False)
    selector.register(stream, selectors.EVENT_READ)
    received = bytearray()
    deadline = min(time.monotonic() + 5, deadline_ns / 1_000_000_000)
    try:
        while time.monotonic() < deadline and process.poll() is None:
            if resource_check is not None:
                resource_check()
            wait_for = min(0.1, max(0.0, deadline - time.monotonic()))
            events = selector.select(wait_for)
            if resource_check is not None:
                resource_check()
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 32 - len(received))
                if not chunk:
                    break
                received.extend(chunk)
                if b"\n" in received or len(received) >= 32:
                    break
            if b"\n" in received or len(received) >= 32:
                break
        if bytes(received) != b"READY\n" or process.poll() is not None:
            raise RuntimeError("independent watchdog source/control readiness failed")
    finally:
        selector.close()
        stream.close()




def _image_preflight(
    docker: str, image: str, home: Path, *,
    resource_check: Callable[[], None] | None = None,
) -> tuple[bool, str, dict[str, object] | None]:
    if resource_check is not None:
        resource_check()
    result = _docker_command(
        docker, ["image", "inspect", image], timeout=8, home=home,
        stdout_limit=32 * 1024, resource_check=resource_check,
    )
    if resource_check is not None:
        resource_check()
    parsed = _parse_json_output(result)
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        return False, "pinned-image-not-present-or-uninspectable", None
    image_data = parsed[0]
    os_name = str(image_data.get("Os", "")).lower()
    architecture = str(image_data.get("Architecture", "")).lower()
    expected = _APPROVED_IMAGE_DIGESTS.get((os_name, architecture))
    actual_digests = image_data.get("RepoDigests")
    digest_values: set[str] = set()
    if isinstance(actual_digests, list):
        for value in actual_digests:
            if isinstance(value, str):
                match = re.fullmatch(r"(?:docker\.io/)?(?:library/)?python@sha256:([0-9a-f]{64})", value)
                if match:
                    digest_values.add(match.group(1))
    wanted = image.rsplit("sha256:", 1)[1]
    if expected is None or wanted not in expected or not (digest_values & expected):
        return False, "pinned-image-digest-or-linux-architecture-mismatch", None
    clean = {
        "id": image_data.get("Id") if isinstance(image_data.get("Id"), str) else None,
        "os": os_name,
        "architecture": architecture,
        "repo_digests": sorted(digest_values),
    }
    return True, "pinned-image-verified", clean


def _inspect_limits(
    details: dict[str, object], spec: _Spec, policy: Policy, name: str
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    config = details.get("Config")
    host = details.get("HostConfig")
    if not isinstance(config, dict) or not isinstance(host, dict):
        return False, ["docker-inspect-config-missing"]
    if not container_is_owned(details, spec.run_id, name, str(details.get("Id", ""))):
        reasons.append("docker-inspect-identity-mismatch")
    if config.get("Image") != policy.image or config.get("Entrypoint") != ["python"]:
        reasons.append("docker-image-or-entrypoint-mismatch")
    if config.get("Cmd") != ["-I", "-c", _CONTAINER_DRIVER, spec.stage, spec.run_id]:
        reasons.append("docker-command-mismatch")
    if config.get("Volumes"):
        reasons.append("image-declared-volume-present")
    if config.get("User") != f"{_USER_ID}:{_USER_ID}":
        reasons.append("docker-user-mismatch")
    if host.get("ReadonlyRootfs") is not True:
        reasons.append("docker-root-filesystem-not-readonly")
    if str(host.get("NetworkMode", "")).lower() != "none":
        reasons.append("docker-network-not-none")
    if host.get("Privileged") is not False:
        reasons.append("docker-privileged-or-unspecified")
    if set(host.get("CapDrop") or []) != {"ALL"}:
        reasons.append("docker-capabilities-not-dropped")
    if host.get("CapAdd"):
        reasons.append("docker-capability-added")
    security_options = host.get("SecurityOpt") or []
    if security_options != ["no-new-privileges:true"]:
        reasons.append("docker-no-new-privileges-missing-or-overridden")
    if host.get("Memory") != CORE_LIMITS.memory_bytes or host.get("MemorySwap") != CORE_LIMITS.memory_swap_bytes:
        reasons.append("docker-memory-or-swap-limit-mismatch")
    nano_cpus = host.get("NanoCpus")
    if (type(nano_cpus) is not int or nano_cpus != 500000000
            or host.get("CpuQuota") not in (None, 0)
            or host.get("CpuPeriod") not in (None, 0)):
        reasons.append("docker-cpu-limit-mismatch")
    if host.get("PidsLimit") != CORE_LIMITS.process_limit:
        reasons.append("docker-process-limit-mismatch")
    tmpfs = host.get("Tmpfs")
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp"}:
        reasons.append("docker-tmpfs-target-mismatch")
    else:
        values = str(tmpfs.get("/tmp", "")).lower().split(",")
        if not (f"size={CORE_LIMITS.disk_bytes}" in values and {"rw", "noexec", "nosuid", "nodev"} <= set(values)):
            reasons.append("docker-tmpfs-options-mismatch")
    if host.get("Devices") or host.get("DeviceRequests") or host.get("VolumesFrom"):
        reasons.append("docker-device-or-volume-grant-present")
    for namespace in ("PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"):
        mode = host.get(namespace)
        if mode not in (None, "", "private"):
            reasons.append("docker-shared-or-unexpected-namespace:" + namespace)
    binds = host.get("Binds") or []
    expected_source = str(policy.input_root) if policy.input_root is not None else None
    expected_bind = f"{expected_source}:{_INPUT_DESTINATION}:ro" if expected_source else None
    if expected_source is None and binds:
        reasons.append("unexpected-docker-bind-mount")
    elif expected_source is not None and binds and (
        not isinstance(binds, list) or len(binds) != 1 or binds[0] != expected_bind
    ):
        reasons.append("reviewed-input-bind-mount-mismatch")
    mounts = details.get("Mounts") or []
    bind_mounts: list[dict[str, object]] = []
    if not isinstance(mounts, list):
        reasons.append("docker-inspected-mounts-malformed")
    else:
        for mount in mounts:
            if not isinstance(mount, dict):
                reasons.append("docker-inspected-mount-malformed")
                continue
            if mount.get("Type") == "bind":
                bind_mounts.append(mount)
            elif mount.get("Type") == "tmpfs":
                if mount.get("Destination") != "/tmp":
                    reasons.append("unexpected-inspected-tmpfs-mount")
            else:
                reasons.append("unexpected-inspected-mount-type")
    if expected_source is None and bind_mounts:
        reasons.append("unexpected-inspected-bind-mount")
    elif expected_source is not None:
        if len(bind_mounts) != 1:
            reasons.append("reviewed-input-mount-not-unique")
        else:
            mount = bind_mounts[0]
            if mount.get("Source") != expected_source or mount.get("Destination") != _INPUT_DESTINATION or mount.get("RW") is not False:
                reasons.append("reviewed-input-mount-not-readonly")
    if (config.get("OpenStdin") is not True or config.get("Tty") is True):
        reasons.append("docker-interactive-stream-settings-mismatch")
    return not reasons, reasons


@dataclasses.dataclass
class _AttachedSession:
    process: subprocess.Popen[bytes]
    selector: selectors.BaseSelector
    outputs: dict[str, bytearray]
    line_buffer: bytearray
    events: list[dict[str, object]]
    truncated: dict[str, bool]
    stream_bytes: dict[str, int]
    limits: dict[str, int]

    @classmethod
    def start(
        cls,
        argv: list[str],
        home: Path,
        on_spawn: Callable[[int, int], None] | None = None,
        launch_deadline_ns: int | None = None,
    ) -> "_AttachedSession":
        process = _spawn_supervised(
            argv,
            on_spawn=on_spawn,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            launch_deadline_ns=launch_deadline_ns,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            cwd="/",
            env=_safe_env(home),
        )
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(process.stdin.fileno(), False)
        return cls(
            process, selector,
            {"stdout": bytearray(), "stderr": bytearray()}, bytearray(), [],
            {"stdout": False, "stderr": False}, {"stdout": 0, "stderr": 0},
            {"stdout": CORE_LIMITS.stdout_bytes, "stderr": CORE_LIMITS.stderr_bytes},
        )

    def _events_from_stdout(self, chunk: bytes) -> None:
        if len(self.line_buffer) < 8192:
            remaining = 8192 - len(self.line_buffer)
            self.line_buffer.extend(chunk[:remaining])
        while True:
            newline = self.line_buffer.find(b"\n")
            if newline < 0:
                if len(self.line_buffer) >= 8192:
                    self.line_buffer.clear()
                return
            line = bytes(self.line_buffer[:newline])
            del self.line_buffer[: newline + 1]
            if len(line) > 4096:
                continue
            try:
                value = json.loads(line.decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and isinstance(value.get("phase"), str):
                self.events.append(value)

    def pump(
        self, timeout: float, *, resource_check: Callable[[], None],
    ) -> bool:
        """Read available streams, checking host resources after each wait."""
        changed = False
        events = self.selector.select(max(0.0, timeout))
        resource_check()
        for key, _mask in events:
            label = key.data
            try:
                chunk = os.read(key.fileobj.fileno(), 8192)
            except BlockingIOError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            changed = True
            self.stream_bytes[label] += len(chunk)
            room = self.limits[label] - len(self.outputs[label])
            if room > 0:
                self.outputs[label].extend(chunk[:room])
            if len(chunk) > max(0, room):
                self.truncated[label] = True
            if label == "stdout":
                self._events_from_stdout(chunk)
        return changed

    def pop_event(self, phase: str) -> dict[str, object] | None:
        for index, event in enumerate(self.events):
            if event.get("phase") == phase:
                return self.events.pop(index)
        return None

    def send_go(self) -> None:
        if self.process.stdin is None:
            raise RuntimeError("container stdin is unavailable")
        os.write(self.process.stdin.fileno(), b"GO\n")
        self.process.stdin.close()

    def close(self) -> None:
        self.selector.close()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def _admit_and_send_go(
    root: Path,
    session: _AttachedSession,
    watchdog: subprocess.Popen[bytes],
    deadline_ns: int,
    *,
    final_proof: Callable[[], None] | None = None,
) -> str | None:
    try:
        admission_lock = _open_private_lock(root, ".go.lock")
    except (OSError, ValueError):
        return "go-admission-fence-unavailable"
    try:
        if _go_marker_present(root, "go.closed"):
            return "watchdog-teardown-in-progress"
        if _go_marker_present(root, "go.claimed"):
            return "go-already-claimed"
        if watchdog.poll() is not None:
            return "independent-watchdog-exited-before-go"
        if not _go_ledger_ready(root):
            return "go-ledger-not-ready"
        if time.monotonic_ns() >= deadline_ns:
            return "go-admission-deadline-exceeded"
        if final_proof is not None:
            final_proof()
        if _go_marker_present(root, "go.closed"):
            return "watchdog-teardown-in-progress"
        if _go_marker_present(root, "go.claimed"):
            return "go-already-claimed"
        if watchdog.poll() is not None:
            return "independent-watchdog-exited-before-go"
        if not _go_ledger_ready(root):
            return "go-ledger-not-ready"
        if time.monotonic_ns() >= deadline_ns:
            return "go-admission-deadline-exceeded"
        if not _write_private_marker(root, "go.claimed", b"claimed\n"):
            return "go-admission-fence-unavailable"
        if time.monotonic_ns() >= deadline_ns:
            return "go-admission-deadline-exceeded"
        if watchdog.poll() is not None:
            return "independent-watchdog-exited-before-go"
        if _go_marker_present(root, "go.closed"):
            return "watchdog-teardown-in-progress"
        if time.monotonic_ns() >= deadline_ns:
            return "go-admission-deadline-exceeded"
        session.send_go()
        return None
    finally:
        _release_private_lock(admission_lock)


def _wait_event(
    session: _AttachedSession, phase: str, deadline: float, *,
    resource_check: Callable[[], None],
) -> dict[str, object] | None:
    while time.monotonic() < deadline:
        resource_check()
        found = session.pop_event(phase)
        if found is not None:
            return found
        if session.process.poll() is not None and not session.selector.get_map():
            return None
        session.pump(
            min(0.1, max(0.0, deadline - time.monotonic())),
            resource_check=resource_check,
        )
        if any(session.truncated.values()):
            return None
    return None


def _process_identity(pid: int) -> tuple[int, int, int] | None:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stream:
            record = stream.read(4096)
        close = record.rfind(")")
        if close < 0:
            return None
        fields = record[close + 2:].split()
        start_ticks, parent_pid = int(fields[19]), int(fields[1])
        if pid <= 1 or start_ticks <= 0 or parent_pid < 0 or fields[0] in {"Z", "X"}:
            return None
        return pid, start_ticks, parent_pid
    except (OSError, ValueError, IndexError, UnicodeError):
        return None


def _docker_top(
    docker: str,
    container_id: str,
    home: Path,
    *,
    resource_check: Callable[[], None] | None = None,
) -> list[tuple[int, int, int]] | None:
    result = _docker_command(
        docker, ["container", "top", container_id, "-eo", "pid,ppid"],
        timeout=5, home=home, stdout_limit=16 * 1024,
        resource_check=resource_check,
    )
    if (result.returncode != 0 or result.timed_out
            or result.stdout_truncated or result.stderr_truncated):
        return None
    try:
        lines = result.stdout.decode("ascii").splitlines()
    except UnicodeError:
        return None
    if not lines or lines[0].split() != ["PID", "PPID"]:
        return None
    identities: list[tuple[int, int, int]] = []
    parents: dict[int, int] = {}
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 2 or not all(field.isdigit() for field in fields):
            return None
        pid, parent_pid = map(int, fields)
        if pid in parents or len(parents) >= CORE_LIMITS.process_limit:
            return None
        identity = _process_identity(pid)
        if identity is None or identity[2] != parent_pid:
            return None
        parents[pid] = parent_pid
        identities.append(identity)
    roots = [pid for pid, parent_pid in parents.items() if parent_pid not in parents]
    if len(roots) != 1:
        return None
    for pid in parents:
        seen: set[int] = set()
        while pid in parents:
            if pid in seen:
                return None
            seen.add(pid)
            parent_pid = parents[pid]
            if parent_pid not in parents and pid != roots[0]:
                return None
            pid = parent_pid
    return identities


def _processes_gone(identities: list[tuple[int, int, int]]) -> bool:
    return all(_current_start_ticks(pid) != start for pid, start, _parent in identities)


def _run_pilot(spec: _Spec, policy: Policy) -> dict[str, object]:
    uid = _effective_uid()
    if uid == 0:
        return {"schema": 1, "status": "BLOCKED", "reason": "root-supervisor-refused", "cleanup_confirmed": True}
    deadline_ns = time.monotonic_ns() + CORE_LIMITS.wall_seconds * 1_000_000_000
    root: Path | None = None
    root_info: os.stat_result | None = None
    run_root_created = False
    watchdog: subprocess.Popen[bytes] | None = None
    ledger: dict[str, object] | None = None
    home: Path | None = None
    host_probe: dict[str, object] = {}
    docker_root_path: Path | None = None
    initial_resources: dict[str, int | None] = {}
    final_resources: dict[str, int | None] = {}
    min_memory: int | None = None
    min_disk: int | None = None
    min_docker_disk: int | None = None
    resource_failure: str | None = None
    cleanup_resource_failure: str | None = None
    image_metadata: dict[str, object] | None = None
    status = "BLOCKED"
    reason = "trusted-preflight-failed"
    cleanup_failures: list[str] = []
    cleanup_confirmed = False
    watchdog_exit: int | None = None

    def sample_resources(
        *, initial: bool = False, allow_missing_docker_root: bool = False,
    ) -> str | None:
        nonlocal final_resources, min_memory, min_disk, min_docker_disk, resource_failure
        if home is None:
            return resource_failure
        try:
            current = _host_resources(home, docker_root_path)
        except Exception:
            current = {
                "memory_available_bytes": None,
                "disk_free_bytes": None,
                "docker_root_disk_free_bytes": None,
            }
        final_resources = current
        for key, previous in (
            ("memory_available_bytes", min_memory),
            ("disk_free_bytes", min_disk),
            ("docker_root_disk_free_bytes", min_docker_disk),
        ):
            value = current.get(key)
            if type(value) is int and (previous is None or value < previous):
                if key == "memory_available_bytes":
                    min_memory = value
                elif key == "disk_free_bytes":
                    min_disk = value
                else:
                    min_docker_disk = value
        if allow_missing_docker_root and docker_root_path is None:
            memory = current.get("memory_available_bytes")
            disk = current.get("disk_free_bytes")
            if type(memory) is not int or type(disk) is not int or min(memory, disk) < 0:
                failure = "host-resource-telemetry-unavailable"
            elif memory < _HOST_START_MEMORY_BYTES or disk < _HOST_START_DISK_BYTES:
                failure = "host-resource-headroom-insufficient"
            else:
                failure = None
        else:
            failure = _host_resource_reason(current, initial=initial)
        if docker_root_path is None and not allow_missing_docker_root:
            failure = failure or "host-resource-telemetry-unavailable"
        if failure is not None and resource_failure is None:
            resource_failure = failure
        return failure

    def check_resources() -> None:
        nonlocal reason, status
        sample_resources()
        failure = resource_failure
        if failure is not None:
            if status == "PASS" or reason in {"trusted-preflight-failed", "pilot-not-completed"}:
                reason = failure
            status = "FAIL" if ledger is not None and ledger.get("attempted") is True else "BLOCKED"
            raise RuntimeError("host resource accounting or headroom is unavailable")

    def cleanup_resources() -> None:
        nonlocal reason, status, resource_failure, cleanup_resource_failure
        try:
            failure = sample_resources()
        except Exception:
            if resource_failure is None:
                resource_failure = "host-resource-telemetry-unavailable"
            failure = resource_failure
        if failure is not None:
            if cleanup_resource_failure is None:
                cleanup_resource_failure = failure
            if status == "PASS":
                status = "FAIL"
                reason = failure

    def wait_with_sampling(
        process: subprocess.Popen[bytes], timeout: float, process_name: str,
    ) -> int:
        deadline = time.monotonic() + timeout
        while True:
            cleanup_resources()
            returncode = process.poll()
            if returncode is not None:
                return returncode
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process_name, timeout)
            try:
                return process.wait(timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                cleanup_resources()

    def host_telemetry() -> dict[str, object]:
        return {
            "before": initial_resources,
            "minimum_memory_available_bytes": min_memory,
            "minimum_disk_free_bytes": min_disk,
            "minimum_docker_root_disk_free_bytes": min_docker_disk,
            "after": final_resources,
        }

    try:
        home = _private_home()
        resource_reason = sample_resources(
            initial=True, allow_missing_docker_root=True,
        )
        if resource_reason is not None:
            initial_resources = final_resources.copy()
            reason = resource_reason
            return {
                "schema": 1, "status": "BLOCKED", "reason": resource_reason,
                "original_cause": resource_reason, "cleanup_failures": [],
                "probe": host_probe, "cleanup_confirmed": True,
                "host_telemetry": host_telemetry(),
            }
        image, input_proof = _validate_policy(policy)
        docker, docker_reason = _docker_binary()
        if docker is None:
            return {"schema": 1, "status": "BLOCKED", "reason": docker_reason or "docker-client-unavailable", "cleanup_confirmed": True}
        host_probe = probe()
        if host_probe.get("status") != "AVAILABLE":
            return {"schema": 1, "status": "BLOCKED", "reason": "host-prerequisite-probe-blocked", "probe": host_probe, "cleanup_confirmed": True}
        docker_root_value = (
            host_probe.get("docker", {}).get("dockerrootdir")
            if isinstance(host_probe.get("docker"), dict)
            else None
        )
        if isinstance(docker_root_value, str) and Path(docker_root_value).is_absolute():
            try:
                resolved_docker_root = Path(docker_root_value).resolve(strict=True)
                if resolved_docker_root.is_dir():
                    docker_root_path = resolved_docker_root
            except (OSError, RuntimeError):
                pass
        resource_reason = sample_resources(initial=True)
        initial_resources = final_resources.copy()
        if resource_reason is not None:
            reason = resource_reason
            return {
                "schema": 1, "status": "BLOCKED", "reason": resource_reason,
                "original_cause": resource_reason, "cleanup_failures": [],
                "probe": host_probe, "cleanup_confirmed": True,
                "host_telemetry": host_telemetry(),
            }
        image_ok, image_reason, image_metadata = _image_preflight(
            docker, image, home, resource_check=check_resources,
        )
        if not image_ok:
            return {
                "schema": 1, "status": "BLOCKED", "reason": image_reason,
                "original_cause": image_reason, "cleanup_failures": [],
                "probe": host_probe, "cleanup_confirmed": True,
                "host_telemetry": host_telemetry(),
            }
        source, source_sha, _source_dev, _source_ino = _source_identity()
        python, python_dev, python_ino = _python_identity()
        if _effective_uid() != uid:
            raise ValueError("effective UID changed during preflight")
        private_parent = home / ".cache" / "dotunnel-release-verifier"
        _mkdir_private(home / ".cache", require_private=False)
        _mkdir_private(private_parent)
        root = private_parent / spec.run_id
        os.mkdir(root, 0o700)
        run_root_created = True
        root_info = os.lstat(root)
        if root_info.st_uid != uid or stat.S_IMODE(root_info.st_mode) != 0o700:
            raise ValueError("private run directory was not created safely")
        _path_snapshot(root)
        start_ticks = _current_start_ticks(os.getpid())
        if start_ticks is None:
            raise ValueError("controller process identity is unavailable")
        name = _CONTAINER_PREFIX + spec.run_id
        control = {
            "schema": 1,
            "run_id": spec.run_id,
            "name": name,
            "root": str(root),
            "root_dev": root_info.st_dev,
            "root_ino": root_info.st_ino,
            "owner_uid": uid,
            "source_path": str(source),
            "source_sha256": source_sha,
            "source_dev": _source_dev,
            "source_ino": _source_ino,
            "python_path": str(python),
            "python_dev": python_dev,
            "python_ino": python_ino,
            "docker_path": docker,
            "docker_root_path": str(docker_root_path),
            "controller_pid": os.getpid(),
            "controller_start_ticks": start_ticks,
            "deadline_ns": deadline_ns,
        }
        control_bytes = _canonical_bytes(control)
        _write_exclusive(root / "control.json", control_bytes)
        control_digest = hashlib.sha256(control_bytes).hexdigest()
        ledger = {
            "schema": 1,
            "run_id": spec.run_id,
            "name": name,
            "state": "prepared",
            "container_id": None,
            "attempted": False,
            "cleanup_confirmed": False,
            "cleanup_reason": "not-started",
            "docker_pid": None,
            "docker_start_ticks": None,
            "status": "BLOCKED",
            "source_sha256": source_sha,
        }
        _write_exclusive(root / "ledger.json", _canonical_bytes(ledger))
        reason = "pilot-not-completed"
        watchdog = _watchdog_start(root, control_digest, python, source, home)
        _wait_watchdog_ready(watchdog, deadline_ns, resource_check=check_resources)
        cid: str | None = None
        cleanup_confirmed = False
        output_cap_proven = False
        process_tree_identities: list[tuple[int, int, int]] = []
        session: _AttachedSession | None = None
        captured: dict[str, object] = {
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_sha256": None,
            "stderr_sha256": None,
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
        effects: dict[str, object] = {}



        def input_proof_matches() -> bool:
            if input_proof is None:
                return True
            try:
                return _input_tree_proof(policy.input_root) == input_proof
            except (OSError, ValueError):
                return False

        def check_input_proof(phase: str) -> None:
            nonlocal reason, status
            if not input_proof_matches():
                reason = "reviewed-input-content-changed-" + phase
                status = "FAIL" if ledger["attempted"] else "BLOCKED"
                raise RuntimeError("reviewed input content no longer matches admission")
        try:
            if time.monotonic_ns() >= deadline_ns:
                reason = "pilot-wall-deadline-exceeded-before-create"
                raise RuntimeError("fixed pilot wall deadline elapsed before container creation")
            if watchdog.poll() is not None:
                reason = "independent-watchdog-exited-before-create"
                raise RuntimeError("independent watchdog is not alive before container creation")
            if not _docker_reference_absent(
                docker, name, home, resource_check=check_resources,
            ):
                reason = "owned-container-name-not-confirmed-absent"
                raise RuntimeError("refusing a pre-existing or unresolved Docker name")
            check_resources()
            arguments = docker_arguments(spec, policy, name)
            check_input_proof("before-create")
            ledger.update({"state": "create-starting", "attempted": True, "cleanup_reason": "create-pending"})
            _ledger_write(root, ledger)

            def record_docker_client(pid: int, start_ticks: int) -> None:
                ledger.update({"docker_pid": pid, "docker_start_ticks": start_ticks})
                _ledger_write(root, ledger)

            create = _docker_command(
                docker,
                arguments[1:],
                timeout=min(
                    15,
                    max(0.01, (deadline_ns - time.monotonic_ns()) / 1_000_000_000),
                ),
                home=home,
                on_spawn=record_docker_client,
                launch_deadline_ns=deadline_ns,
                resource_check=check_resources,
            )
            candidate_id = create.stdout.decode("ascii", "strict").strip() if not create.stdout_truncated else ""
            if create.returncode != 0 or create.timed_out or create.stdout_truncated or create.stderr_truncated or _CONTAINER_ID_RE.fullmatch(candidate_id) is None:
                reason = "docker-create-outcome-ambiguous"
                status = "BLOCKED"
                raise RuntimeError("ambiguous Docker create; automatic replay is forbidden")
            cid = candidate_id
            details = _inspect_expected(
                docker, spec.run_id, name, container_id=cid, home=home,
                resource_check=check_resources,
            )
            if details is None:
                reason = "created-container-ownership-unconfirmed"
                raise RuntimeError("created container identity did not match its owned ledger")
            ledger.update({"state": "created", "container_id": cid, "cleanup_reason": "created"})
            _ledger_write(root, ledger)
            limits_ok, limit_reasons = _inspect_limits(details, spec, policy, name)
            if not limits_ok:
                reason = "docker-effective-limit-mismatch:" + ",".join(limit_reasons)
                raise RuntimeError("Docker effective configuration is not the fixed policy")
            current_source, current_sha, current_dev, current_ino = _source_identity()
            if current_source != source or current_sha != source_sha or (current_dev, current_ino) != (_source_dev, _source_ino):
                reason = "supervisor-source-identity-changed"
                raise RuntimeError("trusted controller source changed during pilot")
            ledger.update({"state": "start-starting", "cleanup_reason": "start-pending"})
            _ledger_write(root, ledger)
            if time.monotonic_ns() >= deadline_ns:
                reason = "pilot-wall-deadline-exceeded-before-start"
                raise RuntimeError("fixed pilot wall deadline elapsed before container start")
            if watchdog.poll() is not None:
                reason = "independent-watchdog-exited-before-start"
                raise RuntimeError("independent watchdog is not alive before container start")
            check_resources()
            check_input_proof("before-start")
            def record_attach_client(pid: int, start_ticks: int) -> None:
                ledger.update({"docker_pid": pid, "docker_start_ticks": start_ticks})
                _ledger_write(root, ledger)

            session = _AttachedSession.start(
                _docker_argv(docker, ["container", "start", "--attach", "--interactive", cid]),
                home,
                on_spawn=record_attach_client,
                launch_deadline_ns=deadline_ns,
            )
            if session.process.poll() is not None:
                reason = "docker-start-command-exited-before-inspection"
                raise RuntimeError("Docker start outcome is ambiguous")
            ledger.update({"state": "started", "cleanup_reason": "started"})
            _ledger_write(root, ledger)
            deadline = min(time.monotonic() + CORE_LIMITS.wall_seconds, deadline_ns / 1_000_000_000)
            ready = _wait_event(session, "ready", deadline, resource_check=check_resources)
            if ready is None or ready.get("run_id") != spec.run_id or ready.get("ok") is not True:
                reason = "kernel-cgroup-or-tmpfs-preflight-failed"
                raise RuntimeError("kernel resource controls were not independently observed before effects")
            cgroup = ready.get("cgroup")
            if not isinstance(cgroup, dict):
                reason = "kernel-accounting-evidence-malformed"
                raise RuntimeError("container did not provide valid fixed cgroup evidence")
            tmpfs_bytes = ready.get("tmpfs_bytes")
            cgroup_version = cgroup.get("version")
            if (
                ready.get("root_read_only") is not True
                or ready.get("tmpfs") is not True
                or type(tmpfs_bytes) is not int
                or not 0 < tmpfs_bytes <= CORE_LIMITS.disk_bytes
                or ready.get("effective_uid") != _USER_ID
                or type(cgroup_version) is not int
                or cgroup_version not in (1, 2)
                or cgroup.get("memory_max") != CORE_LIMITS.memory_bytes
                or cgroup.get("pids_max") != CORE_LIMITS.process_limit
                or cgroup.get("cpu_quota") != 50000
                or cgroup.get("cpu_period") != 100000
                or (cgroup_version == 2 and cgroup.get("swap_max") != 0)
                or (cgroup_version == 1 and cgroup.get("swap_max") != CORE_LIMITS.memory_bytes)
            ):
                reason = "kernel-effective-limits-mismatch"
                raise RuntimeError("actual container cgroup values differ from the fixed policy")
            effects["kernel"] = {"cgroup": cgroup, "root_read_only": True, "tmpfs_bytes": ready.get("tmpfs_bytes")}
            current_details = _inspect_expected(
                docker, spec.run_id, name, container_id=cid, home=home,
                resource_check=check_resources,
            )
            if current_details is None:
                reason = "container-identity-changed-before-effects"
                raise RuntimeError("container identity changed before hostile effects")
            current_limits_ok, current_limit_reasons = _inspect_limits(current_details, spec, policy, name)
            if not current_limits_ok:
                reason = "docker-limits-changed-before-effects:" + ",".join(current_limit_reasons)
                raise RuntimeError("effective Docker controls changed before hostile effects")
            def final_go_proof() -> None:
                check_resources()
                check_input_proof("before-go")

            go_failure = _admit_and_send_go(
                root, session, watchdog, deadline_ns, final_proof=final_go_proof,
            )
            if go_failure is not None:
                reason = go_failure
                raise RuntimeError("final GO admission was refused")
            if spec.stage == "capabilities":
                done = _wait_event(session, "done", deadline, resource_check=check_resources)
                if done is None or done.get("status") != "PASS":
                    reason = "capabilities-driver-failed"
                    raise RuntimeError("fixed capabilities diagnostic did not complete")
                while session.process.poll() is None and time.monotonic() < deadline:
                    check_resources()
                    session.pump(
                        min(0.1, max(0.0, deadline - time.monotonic())),
                        resource_check=check_resources,
                    )
                    if any(session.truncated.values()):
                        reason = "capabilities-output-limit-exceeded"
                        raise RuntimeError("capabilities diagnostic exceeded an output bound")
                if session.process.poll() != 0:
                    reason = "capabilities-driver-failed"
                    raise RuntimeError("fixed capabilities diagnostic did not complete")
                if any(session.truncated.values()):
                    reason = "capabilities-output-limit-exceeded"
                    raise RuntimeError("capabilities diagnostic exceeded an output bound")
                effects["capabilities"] = "observed"
                status = "PASS"
                reason = "bounded-capabilities-probe-completed"
            else:
                observed: dict[str, dict[str, object]] = {}
                tree_seen = False
                while time.monotonic() < deadline:
                    check_resources()
                    for phase in ("pids", "scratch", "tree-ready"):
                        event = session.pop_event(phase)
                        if event is not None:
                            observed[phase] = event
                            if phase == "tree-ready":
                                tree_seen = True
                                identities = _docker_top(
                                    docker, cid, home, resource_check=check_resources,
                                )
                                if identities is not None:
                                    process_tree_identities = identities
                    if session.truncated["stdout"] and session.truncated["stderr"]:
                        output_cap_proven = True
                        break
                    if session.process.poll() is not None:
                        break
                    session.pump(
                        min(0.1, max(0.0, deadline - time.monotonic())),
                        resource_check=check_resources,
                    )
                captured = {
                    "stdout_bytes": len(session.outputs["stdout"]),
                    "stderr_bytes": len(session.outputs["stderr"]),
                    "stdout_sha256": hashlib.sha256(session.outputs["stdout"]).hexdigest(),
                    "stderr_sha256": hashlib.sha256(session.outputs["stderr"]).hexdigest(),
                    "stdout_truncated": session.truncated["stdout"],
                    "stderr_truncated": session.truncated["stderr"],
                }
                effects["hostile"] = observed
                if not output_cap_proven or not tree_seen:
                    reason = "hostile-output-or-descendant-probe-incomplete"
                    raise RuntimeError("hostile child did not exercise both output caps and process tree")
                pids_event = observed.get("pids", {})
                scratch_event = observed.get("scratch", {})
                if pids_event.get("limit_enforced") is not True or scratch_event.get("exhausted") is not True:
                    reason = "hostile-resource-probe-failed"
                    raise RuntimeError("actual pids or tmpfs quota evidence did not meet fixed limits")
                if len(process_tree_identities) < 4:
                    reason = "fork-tree-process-accounting-unconfirmed"
                    raise RuntimeError("container process tree was not observed through Docker")
                reason = "bounded-hostile-child-effects-completed"
                status = "PASS"
            if session is not None and spec.stage == "capabilities":
                while session.selector.get_map() and time.monotonic() < deadline:
                    check_resources()
                    session.pump(
                        min(0.1, max(0.0, deadline - time.monotonic())),
                        resource_check=check_resources,
                    )
                if session.process.poll() != 0:
                    status = "FAIL"
                    reason = "capabilities-container-exit-nonzero"
                if any(session.truncated.values()):
                    status = "FAIL"
                    reason = "capabilities-output-limit-exceeded"
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, UnicodeError) as exc:
            if reason in {"pilot-not-completed", "create-pending", "started"}:
                reason = "pilot-failed:" + type(exc).__name__
            if status == "PASS":
                status = "FAIL"
        finally:
            original_cause = reason if status != "PASS" else None
            cleanup_failures: list[str] = []
            if session is not None:
                if session.process.poll() is None and (output_cap_proven or time.monotonic() >= deadline_ns / 1_000_000_000 or status != "PASS"):
                    # Container cleanup is ownership-checked separately; terminate
                    # only the local Docker attach process group if it will not exit.
                    _kill_process_group(session.process)
                try:
                    wait_with_sampling(session.process, 2, "docker-attach")
                except subprocess.TimeoutExpired:
                    _kill_process_group(session.process)
                    try:
                        wait_with_sampling(session.process, 1, "docker-attach")
                    except subprocess.TimeoutExpired:
                        status = "BLOCKED"
                        reason = "docker-attach-process-cleanup-unconfirmed"
                        cleanup_failures.append(reason)
                session.close()
                captured.update({
                    "stdout_bytes": len(session.outputs["stdout"]),
                    "stderr_bytes": len(session.outputs["stderr"]),
                    "stdout_sha256": hashlib.sha256(session.outputs["stdout"]).hexdigest(),
                    "stderr_sha256": hashlib.sha256(session.outputs["stderr"]).hexdigest(),
                    "stdout_truncated": session.truncated["stdout"],
                    "stderr_truncated": session.truncated["stderr"],
                })
            if ledger.get("attempted") is True:
                if cid is None:
                    discovered = _inspect_expected(
                        docker, spec.run_id, name, home=home,
                        resource_check=cleanup_resources,
                    )
                    if discovered is not None:
                        cid = _owned_by_run(discovered, spec.run_id, name)
                        if cid is not None:
                            ledger.update({"container_id": cid, "state": "create-reconciled"})
                            try:
                                _ledger_write(root, ledger)
                            except (OSError, ValueError):
                                cid = None
                if cid is None:
                    # Daemon creation may outlive its killed/exited CLI client.
                    # Only an observed owned CID can anchor confirmed removal.
                    confirmed = False
                    cleanup_reason = "create-outcome-unresolved"
                    resolved_id = None
                else:
                    confirmed, cleanup_reason, resolved_id = _cleanup_container(
                        docker, spec.run_id, name, cid, home=home,
                        resource_check=cleanup_resources,
                    )
            else:
                confirmed, cleanup_reason, resolved_id = True, "no-create-request-issued", None
            if ledger.get("attempted") is True and not input_proof_matches():
                status = "FAIL"
                if original_cause is None:
                    reason = "reviewed-input-content-changed-after-runtime-cleanup"
                    original_cause = reason
            cid = resolved_id or cid
            cleanup_confirmed = confirmed
            ledger.update({
                "state": "complete" if confirmed else "cleanup-unresolved",
                "container_id": cid,
                "cleanup_confirmed": confirmed,
                "cleanup_reason": cleanup_reason,
                "status": status,
            })
            try:
                _ledger_write(root, ledger)
            except (OSError, ValueError):
                cleanup_confirmed = False
                status = "BLOCKED"
                reason = "owned-ledger-finalization-failed"
                cleanup_failures.append(reason)
            watchdog_exit: int | None = None
            try:
                watchdog_exit = wait_with_sampling(watchdog, 5, "independent watchdog")
            except subprocess.TimeoutExpired:
                status = "FAIL"
                reason = "independent-watchdog-exit-unconfirmed"
                cleanup_failures.append(reason)
            if watchdog_exit != 0:
                status = "FAIL"
                reason = "independent-watchdog-failed"
                cleanup_failures.append(reason)
            if not cleanup_confirmed:
                status = "FAIL"
                reason = "owned-container-cleanup-unconfirmed"
                cleanup_failures.append(reason)
                if cleanup_reason not in cleanup_failures:
                    cleanup_failures.append(cleanup_reason)
            if not _processes_gone(process_tree_identities):
                status = "FAIL"
                reason = "host-process-descendant-survived-container-removal"
                cleanup_failures.append(reason)
            if watchdog_exit is not None and cleanup_confirmed:
                root_removed = _remove_private_root(
                    root, root_info.st_dev, root_info.st_ino
                ) or _private_root_absent(root)
            else:
                root_removed = False
            if not root_removed:
                cleanup_failures.append("private-run-root-cleanup-unconfirmed")
                if status != "FAIL":
                    status = "FAIL"
                    reason = "private-run-root-cleanup-unconfirmed"
                ledger["status"] = status
                try:
                    _ledger_write(root, ledger)
                except (OSError, ValueError):
                    reason = "owned-ledger-finalization-failed"
                    cleanup_failures.append(reason)
            sample_resources()
            if cleanup_resource_failure is not None and cleanup_resource_failure not in cleanup_failures:
                cleanup_failures.append(cleanup_resource_failure)
            if resource_failure is not None:
                if status == "PASS":
                    status = "FAIL"
                    reason = resource_failure
            captured["host_stdout_bytes_limit"] = CORE_LIMITS.stdout_bytes
            captured["host_stderr_bytes_limit"] = CORE_LIMITS.stderr_bytes
            captured["host_output_bytes_stored"] = (
                captured["stdout_bytes"] + captured["stderr_bytes"]
            )
        return {
            "schema": 1,
            "status": status,
            "reason": reason,
            "original_cause": original_cause,
            "cleanup_failures": cleanup_failures,
            "stage": spec.stage,
            "run_id": spec.run_id,
            "image": image_metadata,
            "probe": host_probe,
            "effective_docker_limits_verified": "kernel" in effects,
            "process_accounting_evidence": effects.get("hostile", {}).get("pids") if isinstance(effects.get("hostile"), dict) else None,
            "tmpfs_quota_evidence": effects.get("hostile", {}).get("scratch") if isinstance(effects.get("hostile"), dict) else None,
            "output": captured,
            "host_telemetry": host_telemetry(),
            "cleanup_confirmed": cleanup_confirmed and root_removed and watchdog_exit == 0,
            "container_id_recorded_before_start": cid is not None,
            "process_tree_killed": bool(process_tree_identities) and _processes_gone(process_tree_identities),
            "watchdog_exit": watchdog_exit,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        cleanup_failures = []
        cleanup_confirmed = not run_root_created
        if run_root_created and root is not None and root_info is not None:
            if watchdog is None:
                cleanup_confirmed = _remove_private_root(
                    root, root_info.st_dev, root_info.st_ino
                )
                if not cleanup_confirmed:
                    cleanup_failures.append("private-run-root-cleanup-unconfirmed")
            elif ledger is not None and ledger.get("attempted") is not True:
                try:
                    ledger.update({
                        "state": "complete",
                        "cleanup_confirmed": True,
                        "cleanup_reason": "bootstrap-failed-before-create",
                        "status": "BLOCKED",
                    })
                    _ledger_write(root, ledger)
                    watchdog_exit = wait_with_sampling(
                        watchdog, 5, "independent watchdog",
                    )
                    if watchdog_exit != 0:
                        cleanup_failures.append("independent-watchdog-failed")
                    root_removed = (
                        _remove_private_root(root, root_info.st_dev, root_info.st_ino)
                        or _private_root_absent(root)
                    )
                    if not root_removed:
                        cleanup_failures.append("private-run-root-cleanup-unconfirmed")
                    cleanup_confirmed = watchdog_exit == 0 and root_removed
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    cleanup_confirmed = False
                    cleanup_failures.append("independent-watchdog-exit-unconfirmed")
            else:
                cleanup_confirmed = False
                cleanup_failures.append("preflight-cleanup-unconfirmed")
        cleanup_resources()
        if cleanup_resource_failure is not None and cleanup_resource_failure not in cleanup_failures:
            cleanup_failures.append(cleanup_resource_failure)
        failure_reason = (
            reason if reason != "trusted-preflight-failed"
            else "trusted-preflight-failed:" + type(exc).__name__
        )
        return {
            "schema": 1,
            "status": (
                "BLOCKED" if cleanup_confirmed and not cleanup_failures else "FAIL"
            ),
            "reason": failure_reason,
            "original_cause": failure_reason,
            "cleanup_failures": cleanup_failures,
            "probe": host_probe,
            "host_telemetry": host_telemetry(),
            "cleanup_confirmed": cleanup_confirmed,
            "watchdog_exit": watchdog_exit,
        }


def _spec_from_cli(stage: str, run_id: str, policy: Policy) -> _Spec:
    raw = _canonical_bytes({"schema": 1, "stage": stage, "run_id": run_id})
    return parse_spec(raw, policy)


def _format_output(value: object) -> None:
    sys.stdout.buffer.write(_canonical_bytes(value) + b"\n")
    sys.stdout.buffer.flush()


def _exit_for_status(status: object) -> int:
    if status in {"PASS", "AVAILABLE"}:
        return 0
    if status == "FAIL":
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 3 and args[0] == "--_watchdog":
        try:
            return _watchdog(Path(args[1]), args[2])
        except BaseException:
            return 70
    parser = argparse.ArgumentParser(prog="ci_supervisor.py")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("probe", help="read-only Linux/Docker/cgroup/bwrap prerequisite probe")
    pilot = commands.add_parser("pilot", help="run one fixed, finite trusted feasibility pilot")
    pilot.add_argument("--stage", choices=("capabilities", "hostile-pilot"), required=True)
    pilot.add_argument("--run-id", required=True)
    pilot.add_argument("--input-root", type=Path)
    parsed = parser.parse_args(args)
    if parsed.command == "probe":
        result = probe()
        _format_output(result)
        return _exit_for_status(result.get("status"))
    policy = Policy(image=_DEFAULT_IMAGE, input_root=parsed.input_root)
    try:
        spec = _spec_from_cli(parsed.stage, parsed.run_id, policy)
        result = _run_pilot(spec, policy)
    except (OSError, ValueError) as exc:
        result = {"schema": 1, "status": "BLOCKED", "reason": "trusted-input-refused:" + type(exc).__name__, "cleanup_confirmed": True}
    _format_output(result)
    return _exit_for_status(result.get("status"))


if __name__ == "__main__":
    raise SystemExit(main())
