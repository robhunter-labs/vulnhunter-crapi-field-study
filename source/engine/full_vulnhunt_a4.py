#!/usr/bin/env python3
"""Prepare, authorize, run, and validate one completion-grade VulnHunter scan.

This controller is intentionally thin.  It does not classify source, supply an
answer key, replace the upstream prompts, or normalize VulnHunter findings.
It only prepares pinned Git-free inputs, invokes the installed /vulnhunt skill,
captures the raw event stream, and checks for the workflow's native evidence.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable
import urllib.error
import urllib.request

import runtime_recovery as recovery


SCHEMA = "ospt.full-vulnhunter-run.v4"
RUN_ID = "VH-JS-FULL-001-A4"
OWNER_IDENTITY = "robhunter-owner"
APPROVAL_NAMESPACE = "ospt-vulnhunter-canary-v1"
TARGET_SOURCE_ID = "owasp-juice-shop-v17.1.1"
TARGET_COMMIT = "39b46860612990ae18d499a20472172839fe8c77"
TARGET_FILE_COUNT = 1141
TARGET_MANIFEST_SHA256 = "sha256:5f93bb135bb94a99c9fbdfa83fcca21e6169529b9c0b670fac13225f1b7758c6"
TOOL_SOURCE_ID = "capitalone-vulnhunter"
TOOL_COMMIT = "4042d34609ff85e0029dd55743b9c3f677cc984a"
TOOL_FILE_COUNT = 284
TOOL_MANIFEST_SHA256 = "sha256:39af5202213e1ea7f89e88f511690cf87d299724ac0af84fbffe780309b1114d"
SKILL_MANIFEST_SHA256 = "sha256:587b35ba6097f16784d84d6063671807561d58bb9e2361c4ebe4364489c5f1b0"
MAX_COST_USD = 120.0
MAX_SECONDS = 21600
NO_PROGRESS_SECONDS = 1800
TARGET_HEALTH_INTERVAL_SECONDS = 30
TARGET_HEALTH_FAILURE_LIMIT = 2
TARGET_RESTART_LIMIT = 2
PROGRESS_INTERVAL_SECONDS = 60
TARGET_START_SECONDS = 90
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 40125
TARGET_HEALTH_URL = f"http://{TARGET_HOST}:{TARGET_PORT}/"
A2_WORKSPACE_PATH = Path(
    "/private/tmp/ospt-vulnhunter-juice-shop/VH-JS-FULL-001-A2/workspace"
)
ROOT_MODEL_REQUEST = "opus"
EXPECTED_ROOT_MODEL = "claude-opus-5"
ALLOWED_FORWARDED_MODELS = (
    "claude-opus-4-8",
    "claude-sonnet-5",
)
TARGET_SANDBOX_PROFILE = (
    '(version 1)(allow default)'
    '(deny network-outbound (require-not (remote ip "localhost:*")))'
)
MAX_SCOPE_LIFETIME_SECONDS = 48 * 60 * 60
MAX_DEPENDENCY_ATTEMPTS = 4
NODE_RUNTIME_PATH = Path("/opt/homebrew/opt/node@22/bin/node")
NPM_RUNTIME_PATH = Path("/opt/homebrew/opt/node@22/bin/npm")
LIVE_WORKSPACE_PATH = Path(
    "/private/tmp/ospt-vulnhunter-juice-shop/VH-JS-FULL-001-A4/workspace"
)
LIVE_EVIDENCE_PATH = Path(
    "/path/to/local-study-workspace/OSPT/workbench/"
    "vulnhunter-juice-shop-full/VH-JS-FULL-001-A4/evidence"
)
ATTEMPT_MARKER_PATH = Path(
    "/path/to/local-study-workspace/OSPT/workbench/"
    "vulnhunter-juice-shop-full/VH-JS-FULL-001-A4/control/attempt-consumed.json"
)
CONTROLLER_DEPLOY_PATH = Path(
    "/path/to/local-study-workspace/OSPT/build/"
    "vulnhunter-juice-shop-full-run-completion-attempt-4/full_vulnhunt_a4.py"
)
STUDY_ROOT = Path("/path/to/local-study-workspace")
ALLOWED_SIGNERS_PATH = Path(
    "/path/to/local-study-workspace/OSPT/workbench/"
    "vulnhunter-real-canary/VH-REAL-CANARY-001/control/allowed_signers"
)
ALLOWED_SIGNERS_SHA256 = (
    "sha256:1c44367e7e730a9282786daf635ec01a04c65d07f513a01e3498f4ad86852c3d"
)
CLAUDE_CONFIG_PATH = Path.home() / ".claude.json"
PREPARATION_RECEIPT_NAME = "PREPARATION.json"
REQUIRED_PHASE_FILES = (
    "SKILL.md",
    "phases/phase1_recon.md",
    "phases/phase2_hunt.md",
    "phases/phase2b_verify.md",
    "phases/phase3_reproduce_test.md",
    "phases/phase3c_fixes.md",
    "phases/phase3d_sweep.md",
    "phases/phase4_report.md",
)
REQUIRED_SKILL_MARKERS = (
    "Minimum agent count = (3 × partition_count) + 1 sink-driven.",
    "${VULNHUNT_DIR}/phase1_output.md",
    "${VULNHUNT_DIR}/phase2b_output.md",
    "${VULNHUNT_DIR}/phase3_output.md",
    "${VULNHUNT_DIR}/phase3d_output.md",
    "Your role is ORCHESTRATOR",
)
REQUIRED_NATIVE_OUTPUTS = (
    "phase1_output.md",
    "phase2b_output.md",
    "phase3_output.md",
    "phase3d_output.md",
    "README.md",
)


class Refusal(RuntimeError):
    pass


class TerminationRequested(RuntimeError):
    pass


@dataclass(frozen=True)
class VerifiedBinding:
    scope_path: str
    signature_path: str
    allowed_signers_path: str
    provenance: str


def now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"cannot read JSON {path}: {exc}") from exc


def write_create_once(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise Refusal(f"create-once path already exists: {path}") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def append_jsonl(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()


def directory_manifest(root: Path, *, exclude: set[str] | None = None) -> dict[str, str]:
    excluded = exclude or set()
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise Refusal(f"symlink refused in export: {path}")
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            if rel not in excluded:
                result[rel] = sha_file(path)
    return result


def runtime_dependency_manifest(root: Path) -> dict[str, str]:
    """Measure an npm tree without following its expected executable symlinks."""
    if root.is_symlink() or not root.is_dir():
        raise Refusal("runtime dependency root is missing, not a directory, or a symlink")
    result: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        for name in list(dirnames):
            path = current / name
            if path.is_symlink():
                rel = path.relative_to(root).as_posix()
                result[rel] = "symlink:" + os.readlink(path)
                dirnames.remove(name)
        for name in filenames:
            path = current / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                result[rel] = "symlink:" + os.readlink(path)
            elif path.is_file():
                result[rel] = sha_file(path)
            else:
                raise Refusal(f"unsupported runtime dependency member: {path}")
    return result


def manifest_digest(manifest: dict[str, str]) -> str:
    return sha_bytes(canonical_bytes(manifest))


def verify_original_manifest(root: Path, expected: dict[str, str]) -> tuple[bool, list[str]]:
    """Verify pinned members and permit additions only under the runtime node_modules tree."""
    defects: list[str] = []
    if root.is_symlink() or not root.is_dir():
        return False, ["target root is missing, not a directory, or a symlink"]
    expected_dirs: set[str] = set()
    for rel in expected:
        parent = Path(rel).parent
        while parent != Path("."):
            expected_dirs.add(parent.as_posix())
            parent = parent.parent
    for rel, expected_digest in sorted(expected.items()):
        path = root / rel
        cursor = root
        symlink_component = False
        for part in Path(rel).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                symlink_component = True
                defects.append(f"original source path contains a symlink: {rel}")
                break
        if symlink_component:
            continue
        if not path.is_file():
            defects.append(f"original source member missing or not a file: {rel}")
        elif sha_file(path) != expected_digest:
            defects.append(f"original source member changed: {rel}")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        for name in list(dirnames) + list(filenames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            if rel == ".STUDY_SOURCE_EXPORT.json" or rel in expected or rel in expected_dirs:
                continue
            if rel == "node_modules" or rel.startswith("node_modules/"):
                continue
            defects.append(f"unapproved added target member: {rel}")
    return not defects, defects


def verify_pinned_members(root: Path, expected: dict[str, str]) -> tuple[bool, list[str]]:
    """Verify every pinned first-party member while measuring runtime additions separately."""
    defects: list[str] = []
    if root.is_symlink() or not root.is_dir():
        return False, ["runtime/test root is missing, not a directory, or a symlink"]
    for rel, expected_digest in sorted(expected.items()):
        path = root / rel
        cursor = root
        for part in Path(rel).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                defects.append(f"runtime/test first-party path contains a symlink: {rel}")
                break
        else:
            if not path.is_file():
                defects.append(f"runtime/test first-party member missing: {rel}")
            elif sha_file(path) != expected_digest:
                defects.append(f"runtime/test first-party member changed: {rel}")
    return not defects, defects


@contextmanager
def child_environment(workspace: Path) -> Iterable[dict[str, str]]:
    """Install the frozen child environment only for the spawn operation."""
    desired = runtime_environment(workspace)
    prior = dict(os.environ)
    os.environ.clear()
    os.environ.update(desired)
    try:
        yield desired
    finally:
        os.environ.clear()
        os.environ.update(prior)


def runtime_environment(workspace: Path) -> dict[str, str]:
    env = recovery.child_environment(dict(os.environ), workspace)
    current_path = env.get("PATH", "")
    env["PATH"] = str(NODE_RUNTIME_PATH.parent) + (os.pathsep + current_path if current_path else "")
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = env["NO_PROXY"]
    return env


def node_runtime() -> dict[str, Any]:
    for path, label in ((NODE_RUNTIME_PATH, "Node"), (NPM_RUNTIME_PATH, "npm")):
        if not path.is_file():
            raise Refusal(f"pinned {label} runtime is unavailable: {path}")
    env = runtime_environment(LIVE_WORKSPACE_PATH)
    node_version = subprocess.run(
        [str(NODE_RUNTIME_PATH), "--version"],
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
    )
    npm_version = subprocess.run(
        [str(NPM_RUNTIME_PATH), "--version"],
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
    )
    if node_version.returncode != 0 or not node_version.stdout.strip().startswith("v22."):
        raise Refusal("pinned Node runtime is not a supported Node 22 release")
    if npm_version.returncode != 0 or not npm_version.stdout.strip():
        raise Refusal("pinned npm runtime could not be resolved")
    return {
        "node_path": str(NODE_RUNTIME_PATH.resolve()),
        "node_sha256": sha_file(NODE_RUNTIME_PATH),
        "node_version": node_version.stdout.strip(),
        "npm_path": str(NPM_RUNTIME_PATH.resolve()),
        "npm_sha256": sha_file(NPM_RUNTIME_PATH),
        "npm_version": npm_version.stdout.strip(),
    }


def validate_node_runtime_plan(env: dict[str, str]) -> list[str]:
    defects: list[str] = []
    path_parts = env.get("PATH", "").split(os.pathsep)
    if not path_parts or Path(path_parts[0]).resolve() != NODE_RUNTIME_PATH.parent.resolve():
        defects.append("Node 22 bin directory is not first in child PATH")
    try:
        runtime = node_runtime()
    except Refusal as exc:
        defects.append(str(exc))
    else:
        if runtime["node_version"].split(".", 1)[0] != "v22":
            defects.append("child Node runtime is outside the target-supported major version")
    return defects


def sha_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return "sha256:" + digest.hexdigest()


@contextmanager
def pinned_allowed_signers_fd(path: Path) -> Iterable[tuple[int, str]]:
    """Yield verified signer bytes through a closed-writer, read-only pipe."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Refusal(f"cannot open pinned allowed-signers file safely: {exc}") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise Refusal("pinned allowed-signers path is not a regular file")
        data = handle.read()
    if sha_bytes(data) != ALLOWED_SIGNERS_SHA256:
        raise Refusal("pinned allowed-signers file changed")
    if len(data) > 16 * 1024:
        raise Refusal("pinned allowed-signers bytes exceed the immutable pipe bound")
    snapshot_fd, writer_fd = os.pipe()
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(writer_fd, data[offset:])
        os.close(writer_fd)
        writer_fd = -1
        yield snapshot_fd, f"/dev/fd/{snapshot_fd}"
    finally:
        os.close(snapshot_fd)
        if writer_fd >= 0:
            os.close(writer_fd)


class SuspendedProcess:
    """Small wait/poll adapter for a Darwin process spawned initially suspended."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self._resumed = False

    def resume(self) -> None:
        if self._resumed:
            raise Refusal("verified process was already resumed")
        os.kill(self.pid, signal.SIGCONT)
        self._resumed = True

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        waited, status = os.waitpid(self.pid, os.WNOHANG)
        if waited == 0:
            return None
        self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            status = self.poll()
            if status is not None:
                return status
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(["verified-child", str(self.pid)], timeout)
            time.sleep(0.05)


@dataclass
class TargetService:
    process: subprocess.Popen[bytes]
    log_handle: Any
    log_path: Path
    argv: list[str]
    started_at: str


def target_service_argv(workspace: Path) -> list[str]:
    return [
        "/usr/bin/sandbox-exec",
        "-p",
        TARGET_SANDBOX_PROFILE,
        str(NODE_RUNTIME_PATH),
        "build/app",
    ]


def claude_project_sidecar_root(workspace: Path) -> Path:
    encoded = str(workspace.resolve()).replace("/", "-")
    return Path.home() / ".claude" / "projects" / encoded


def claude_task_output_reference(
    source_root: Path,
    link_path: Path,
    project_root: Path,
) -> dict[str, Any]:
    """Validate one Claude task-output link without following it.

    Claude Code creates ``runtime/tmp/claude-*/.../tasks/<task>.output`` links
    that refer to its project-sidecar ``subagents/agent-<task>.jsonl`` file.
    With ``--no-session-persistence`` the target may be removed before final
    evidence capture, leaving a legitimate broken link.  We preserve the link
    as inert JSON metadata and continue to refuse every other symlink shape.
    """
    relative = link_path.relative_to(source_root)
    parts = relative.parts
    if len(parts) != 5 \
            or re.fullmatch(r"claude-[0-9]+", parts[0]) is None \
            or parts[3] != "tasks" \
            or re.fullmatch(r"[a-f0-9]{16,}\.output", parts[4]) is None:
        raise Refusal(f"unexpected runtime sidecar symlink refused: {link_path}")
    task_id = Path(parts[4]).stem
    link_text = os.readlink(link_path)
    lexical_target = Path(link_text)
    if not lexical_target.is_absolute() or ".." in lexical_target.parts:
        raise Refusal(f"runtime task-output link is not an absolute lexical path: {link_path}")
    try:
        project_relative = lexical_target.relative_to(project_root)
    except ValueError as exc:
        raise Refusal(f"runtime task-output link escapes the Claude project root: {link_path}") from exc
    if project_relative.parts != (
        parts[2], "subagents", f"agent-{task_id}.jsonl"
    ):
        raise Refusal(f"runtime task-output link target shape is unexpected: {link_path}")
    target_present = os.path.lexists(lexical_target)
    target_sha256 = None
    target_size = None
    if target_present:
        observed = lexical_target.lstat()
        if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
            raise Refusal(f"runtime task-output target is not a regular file: {lexical_target}")
        target_sha256 = sha_file(lexical_target)
        target_size = observed.st_size
    return {
        "schema": "ospt.claude-task-output-reference.v1",
        "kind": "symlink-reference",
        "source_relative_path": relative.as_posix(),
        "link_text": link_text,
        "project_relative_target": project_relative.as_posix(),
        "target_present_at_capture": target_present,
        "target_sha256": target_sha256,
        "target_size": target_size,
        "dereferenced": False,
    }


def copy_regular_tree(
    source: Path,
    destination: Path,
    *,
    claude_project_root: Path | None = None,
) -> dict[str, Any]:
    if destination.exists():
        raise Refusal(f"sidecar evidence destination already exists: {destination}")
    destination.mkdir(parents=True)
    copied = 0
    symlink_references = 0
    if source.exists():
        for path in sorted(source.rglob("*")):
            rel = path.relative_to(source)
            target = destination / rel
            if path.is_symlink():
                if claude_project_root is None:
                    raise Refusal(f"runtime sidecar symlink refused: {path}")
                reference = claude_task_output_reference(source, path, claude_project_root)
                reference_target = target.with_name(target.name + ".symlink-reference.json")
                reference_target.parent.mkdir(parents=True, exist_ok=True)
                write_create_once(reference_target, canonical_bytes(reference))
                copied += 1
                symlink_references += 1
                continue
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
                copied += 1
            else:
                raise Refusal(f"unsupported runtime sidecar member: {path}")
    manifest = directory_manifest(destination)
    return {
        "source": str(source),
        "evidence": str(destination),
        "file_count": copied,
        "symlink_reference_count": symlink_references,
        "manifest_sha256": manifest_digest(manifest),
    }


def capture_runtime_sidecars(workspace: Path, evidence_root: Path) -> dict[str, Any]:
    project_root = claude_project_sidecar_root(workspace)
    runtime_tmp = recovery.runtime_paths(workspace)["tmp"]
    sidecar_root = evidence_root / "runtime-sidecars"
    sidecar_root.mkdir(parents=True, exist_ok=False)
    return {
        "claude_project": copy_regular_tree(project_root, sidecar_root / "claude-project"),
        "runtime_tmp": copy_regular_tree(
            runtime_tmp,
            sidecar_root / "tmp",
            claude_project_root=project_root,
        ),
        "allowed_roots": [str(project_root), str(runtime_tmp)],
        "claim_ceiling": "This binds known Claude project and configured temporary sidecars, preserving approved task-output links as inert non-dereferenced metadata; it does not claim kernel-complete file-write tracing.",
    }


def target_service_environment(workspace: Path) -> dict[str, str]:
    env = runtime_environment(workspace)
    env.update(
        {
            "NODE_ENV": "production",
            "PORT": str(TARGET_PORT),
            "HOST": TARGET_HOST,
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        }
    )
    return env


def target_health(timeout: float = 3.0) -> tuple[bool, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(TARGET_HEALTH_URL, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            response.read(256)
        return status == 200, f"HTTP {status}"
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def start_target_service(workspace: Path) -> TargetService:
    runtime_target = workspace / "runtime-target"
    if not (runtime_target / "build/app.js").is_file():
        raise Refusal("controller-owned target cannot start: build/app.js is absent")
    log_path = recovery.runtime_paths(workspace)["root"] / "target-service-controller.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("wb")
    argv = target_service_argv(workspace)
    process = subprocess.Popen(
        argv,
        cwd=runtime_target,
        env=target_service_environment(workspace),
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    service = TargetService(process, log_handle, log_path, argv, now_z())
    deadline = time.monotonic() + TARGET_START_SECONDS
    last_detail = "not checked"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log_handle.flush()
            log_handle.close()
            raise Refusal(
                f"controller-owned target exited before health: {process.returncode}; "
                f"log={log_path}"
            )
        healthy, last_detail = target_health()
        if healthy:
            return service
        time.sleep(1)
    stop_target_service(service)
    raise Refusal(f"controller-owned target did not become healthy: {last_detail}")


def stop_target_service(service: TargetService) -> dict[str, Any]:
    escalation = "none"
    if service.process.poll() is None:
        try:
            os.killpg(service.process.pid, signal.SIGTERM)
            service.process.wait(timeout=15)
            escalation = "SIGTERM"
        except subprocess.TimeoutExpired:
            os.killpg(service.process.pid, signal.SIGKILL)
            service.process.wait(timeout=10)
            escalation = "SIGKILL"
        except ProcessLookupError:
            pass
    try:
        service.log_handle.flush()
    finally:
        service.log_handle.close()
    return {
        "exit_code": service.process.returncode,
        "termination": escalation,
        "log_path": str(service.log_path),
        "log_sha256": sha_file(service.log_path) if service.log_path.is_file() else None,
    }


def recover_target_service(
    workspace: Path,
    service: TargetService,
    evidence_root: Path,
    episode: int,
    reason: str,
) -> dict[str, Any]:
    """Preserve one failed target episode and restart from the pinned runtime copy."""
    stopped = stop_target_service(service)
    episode_log = evidence_root / f"target-service-crash-{episode:02d}.log"
    if episode_log.exists():
        raise Refusal(f"target crash evidence already exists: {episode_log}")
    source_log = Path(stopped["log_path"])
    if not source_log.is_file() or source_log.is_symlink():
        raise Refusal("target crash log is absent or unsafe")
    shutil.copy2(source_log, episode_log)
    stopped["evidence_path"] = str(episode_log)
    stopped["evidence_sha256"] = sha_file(episode_log)
    stopped["episode"] = episode
    stopped["reason"] = reason

    replacement = start_target_service(workspace)
    service.process = replacement.process
    service.log_handle = replacement.log_handle
    service.log_path = replacement.log_path
    service.argv = replacement.argv
    service.started_at = replacement.started_at
    stopped["replacement_pid"] = service.process.pid
    stopped["replacement_started_at"] = service.started_at
    return stopped


def progress_state(raw_log: Path, results: Path) -> dict[str, Any]:
    files = [path for path in results.rglob("*") if path.is_file()] if results.is_dir() else []
    phase_files = {
        rel: (results / rel).stat().st_size
        for rel in REQUIRED_NATIVE_OUTPUTS
        if (results / rel).is_file()
    }
    return {
        "raw_bytes": raw_log.stat().st_size if raw_log.is_file() else 0,
        "result_file_count": len(files),
        "result_bytes": sum(path.stat().st_size for path in files),
        "phase_files": phase_files,
    }


def monitor_provider(
    process: SuspendedProcess,
    service: TargetService,
    raw_log: Path,
    results: Path,
    operational: Path,
    budgets: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    started = time.monotonic()
    last_progress = started
    last_health = 0.0
    last_emit = 0.0
    state = progress_state(raw_log, results)
    stop_reason = "provider process exited"
    forced = False
    consecutive_health_failures = 0
    restart_count = 0
    crash_episodes: list[dict[str, Any]] = []
    while process.poll() is None:
        current_time = time.monotonic()
        current = progress_state(raw_log, results)
        if current != state:
            state = current
            last_progress = current_time
        if current_time - last_health >= TARGET_HEALTH_INTERVAL_SECONDS:
            healthy, detail = target_health()
            last_health = current_time
            if not healthy or service.process.poll() is not None:
                consecutive_health_failures += 1
                append_jsonl(
                    operational,
                    {
                        "event": "TARGET_HEALTH_FAILED",
                        "event_time": now_z(),
                        "run_id": RUN_ID,
                        "detail": detail,
                        "target_exit_code": service.process.poll(),
                        "consecutive_failures": consecutive_health_failures,
                        "failure_limit": TARGET_HEALTH_FAILURE_LIMIT,
                    },
                )
                definite_exit = service.process.poll() is not None
                if definite_exit or consecutive_health_failures >= TARGET_HEALTH_FAILURE_LIMIT:
                    stop_reason = f"controller-owned target unhealthy: {detail}"
                    if restart_count < TARGET_RESTART_LIMIT:
                        episode = restart_count + 1
                        append_jsonl(
                            operational.with_name("ENFORCEMENT.jsonl"),
                            {
                                "event": "TARGET_RESTART_ALLOWED",
                                "event_time": now_z(),
                                "run_id": RUN_ID,
                                "reason": stop_reason,
                                "episode": episode,
                                "restart_budget": TARGET_RESTART_LIMIT,
                                "policy": "controller-owned recovery from pinned runtime copy",
                            },
                        )
                        try:
                            crash = recover_target_service(
                                results.parent,
                                service,
                                operational.parent,
                                episode,
                                stop_reason,
                            )
                        except (Refusal, OSError, subprocess.SubprocessError) as exc:
                            stop_reason = f"target recovery failed: {type(exc).__name__}: {exc}"
                            forced = True
                            terminate_process_group(process, operational, stop_reason)
                            break
                        crash_episodes.append(crash)
                        restart_count += 1
                        consecutive_health_failures = 0
                        last_progress = current_time
                        append_jsonl(
                            operational,
                            {
                                "event": "TARGET_RESTARTED",
                                "event_time": now_z(),
                                "run_id": RUN_ID,
                                "episode": episode,
                                "restart_count": restart_count,
                                "restart_budget": TARGET_RESTART_LIMIT,
                                "target_service": crash,
                            },
                        )
                        continue
                    forced = True
                    terminate_process_group(process, operational, stop_reason)
                    break
            else:
                consecutive_health_failures = 0
        if current_time - last_emit >= PROGRESS_INTERVAL_SECONDS:
            runtime = raw_runtime_summary(raw_log) if raw_log.is_file() else {}
            append_jsonl(
                operational,
                {
                    "event": "RUN_PROGRESS",
                    "event_time": now_z(),
                    "run_id": RUN_ID,
                    "elapsed_seconds": current_time - started,
                    "seconds_since_progress": current_time - last_progress,
                    "progress": state,
                    "provider_runtime": runtime,
                    "trace_profile": "high-stakes-scaled",
                },
            )
            last_emit = current_time
        if current_time - last_progress >= NO_PROGRESS_SECONDS:
            stop_reason = f"no observable progress for {NO_PROGRESS_SECONDS} seconds"
            forced = True
            terminate_process_group(process, operational, stop_reason)
            break
        if current_time - started >= int(budgets["max_seconds"]):
            stop_reason = "absolute emergency watchdog reached"
            forced = True
            terminate_process_group(process, operational, stop_reason)
            break
        time.sleep(5)
    exit_code = int(process.returncode if process.returncode is not None else process.wait())
    return exit_code, {
        "forced_stop": forced,
        "stop_reason": stop_reason,
        "elapsed_seconds": time.monotonic() - started,
        "final_progress": progress_state(raw_log, results),
        "target_restart_count": restart_count,
        "target_restart_budget": TARGET_RESTART_LIMIT,
        "target_crash_episodes": crash_episodes,
        "target_health_failure_limit": TARGET_HEALTH_FAILURE_LIMIT,
    }


def _darwin_spawn_suspended(
    executable: Path,
    argv: list[str],
    cwd: Path,
    stdout_fd: int,
    stderr_fd: int,
) -> SuspendedProcess:
    if sys.platform != "darwin":
        raise Refusal("atomic executable-consumption proof is implemented only for Darwin")
    libc = ctypes.CDLL(None, use_errno=True)
    attr = ctypes.c_void_p()
    actions = ctypes.c_void_p()
    pid = ctypes.c_int()

    def bind(name: str, argument_types: list[Any]) -> Any:
        function = getattr(libc, name)
        function.argtypes = argument_types
        function.restype = ctypes.c_int
        return function

    attr_init = bind("posix_spawnattr_init", [ctypes.POINTER(ctypes.c_void_p)])
    attr_setflags = bind(
        "posix_spawnattr_setflags", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_short]
    )
    attr_destroy = bind("posix_spawnattr_destroy", [ctypes.POINTER(ctypes.c_void_p)])
    actions_init = bind("posix_spawn_file_actions_init", [ctypes.POINTER(ctypes.c_void_p)])
    actions_dup2 = bind(
        "posix_spawn_file_actions_adddup2",
        [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_int],
    )
    actions_chdir = bind(
        "posix_spawn_file_actions_addchdir",
        [ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p],
    )
    actions_destroy = bind(
        "posix_spawn_file_actions_destroy", [ctypes.POINTER(ctypes.c_void_p)]
    )
    spawn = bind(
        "posix_spawn",
        [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p),
        ],
    )
    try:
        for rc, label in (
            (attr_init(ctypes.byref(attr)), "initialize spawn attributes"),
            (actions_init(ctypes.byref(actions)), "initialize spawn file actions"),
        ):
            if rc:
                raise Refusal(f"cannot {label}: {os.strerror(rc)}")
        # Darwin guarantees the child is stopped before executing any instruction.
        flags = 0x0080 | 0x0400  # POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSID
        for rc, label in (
            (attr_setflags(ctypes.byref(attr), flags), "set suspended/session spawn flags"),
            (actions_dup2(ctypes.byref(actions), stdout_fd, 1), "bind child stdout"),
            (actions_dup2(ctypes.byref(actions), stderr_fd, 2), "bind child stderr"),
            (
                actions_chdir(ctypes.byref(actions), os.fsencode(cwd)),
                "bind child working directory",
            ),
        ):
            if rc:
                raise Refusal(f"cannot {label}: {os.strerror(rc)}")
        argv_bytes = [os.fsencode(item) for item in argv]
        env_bytes = [os.fsencode(f"{key}={value}") for key, value in os.environ.items()]
        argv_array = (ctypes.c_char_p * (len(argv_bytes) + 1))(*argv_bytes, None)
        env_array = (ctypes.c_char_p * (len(env_bytes) + 1))(*env_bytes, None)
        rc = spawn(
            ctypes.byref(pid),
            os.fsencode(executable),
            ctypes.byref(actions),
            ctypes.byref(attr),
            argv_array,
            env_array,
        )
        if rc:
            raise Refusal(f"cannot spawn signed executable: {os.strerror(rc)}")
        return SuspendedProcess(pid.value)
    finally:
        if actions.value:
            actions_destroy(ctypes.byref(actions))
        if attr.value:
            attr_destroy(ctypes.byref(attr))


def _darwin_text_vnodes(pid: int) -> set[tuple[int, int]]:
    """Read kernel-reported text-vnode identities for a suspended process."""
    read_fd, write_fd = os.pipe()
    try:
        child = os.posix_spawn(
            "/usr/sbin/lsof",
            ["lsof", "-a", "-p", str(pid), "-d", "txt", "-F", "pDino"],
            os.environ,
            file_actions=[
                (os.POSIX_SPAWN_DUP2, write_fd, 1),
                (os.POSIX_SPAWN_DUP2, write_fd, 2),
                (os.POSIX_SPAWN_CLOSE, read_fd),
            ],
        )
        os.close(write_fd)
        write_fd = -1
        chunks: list[bytes] = []
        while True:
            chunk = os.read(read_fd, 8192)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 1024 * 1024:
                raise Refusal("text-vnode identity output exceeded its bound")
        _, status = os.waitpid(child, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise Refusal("kernel text-vnode identity inspection failed")
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
    identities: set[tuple[int, int]] = set()
    device: int | None = None
    inode: int | None = None
    for line in b"".join(chunks).decode(errors="replace").splitlines():
        if line.startswith("f"):
            if device is not None and inode is not None:
                identities.add((device, inode))
            device = None
            inode = None
        elif line.startswith("D"):
            device = int(line[1:], 0)
        elif line.startswith("i"):
            inode = int(line[1:])
    if device is not None and inode is not None:
        identities.add((device, inode))
    if not identities:
        raise Refusal("kernel text-vnode identity inspection returned no executable mapping")
    return identities


def darwin_code_identity(subject: str) -> dict[str, str]:
    """Return the code directory identity for a path or a suspended +PID guest."""
    if sys.platform != "darwin":
        raise Refusal("code-signing identity proof is implemented only for Darwin")
    completed = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", subject],
        text=True,
        capture_output=True,
        timeout=15,
    )
    output = "\n".join((completed.stdout, completed.stderr))
    if completed.returncode != 0:
        raise Refusal("code-signing identity inspection failed")
    values: dict[str, str] = {}
    for line in output.splitlines():
        if line.startswith("Identifier="):
            values["identifier"] = line.split("=", 1)[1]
        elif line.startswith("CandidateCDHashFull sha256="):
            values["cdhash_full_sha256"] = line.split("=", 1)[1]
        elif line.startswith("TeamIdentifier="):
            values["team_identifier"] = line.split("=", 1)[1]
    if not values.get("identifier") or len(values.get("cdhash_full_sha256", "")) != 64:
        raise Refusal("complete SHA-256 code-signing identity is unavailable")
    return values


def spawn_verified_executable(
    executable: Path,
    argv: list[str],
    cwd: Path,
    stdout_fd: int,
    stderr_fd: int,
    expected_sha256: str,
    expected_code_identity: dict[str, str],
) -> tuple[SuspendedProcess, dict[str, Any]]:
    """Spawn stopped, prove the consumed vnode, and return without releasing it."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(executable, flags)
    process: SuspendedProcess | None = None
    service: TargetService | None = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Refusal("signed runtime executable is not a regular file")
        if sha_fd(fd) != expected_sha256:
            raise Refusal("signed runtime executable digest changed before spawn")
        process = _darwin_spawn_suspended(executable, argv, cwd, stdout_fd, stderr_fd)
        consumed = _darwin_text_vnodes(process.pid)
        expected_identity = (before.st_dev, before.st_ino)
        if expected_identity not in consumed:
            raise Refusal("spawned executable vnode differs from the verified signed runtime")
        consumed_code_identity = darwin_code_identity(f"+{process.pid}")
        if consumed_code_identity != expected_code_identity:
            raise Refusal("spawned executable code identity differs from the signed runtime")
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ) or sha_fd(fd) != expected_sha256:
            raise Refusal("signed runtime executable changed during suspended consumption")
        return process, {
            "sha256": expected_sha256,
            "device": before.st_dev,
            "inode": before.st_ino,
            "size": before.st_size,
            "code_identity": consumed_code_identity,
            "verified_while_suspended": True,
        }
    except BaseException:
        if process is not None and process.poll() is None:
            os.kill(process.pid, signal.SIGKILL)
            process.wait()
        raise
    finally:
        os.close(fd)


def run_json(argv: list[str], *, cwd: Path) -> dict[str, Any]:
    completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True)
    if completed.returncode != 0:
        raise Refusal(f"command failed ({completed.returncode}): {' '.join(argv)}\n{completed.stderr}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal(f"command returned non-JSON: {' '.join(argv)}") from exc


def sourcectl_base(study_root: Path) -> list[str]:
    control = study_root / "local-source-control"
    return [
        sys.executable,
        str(control / "tools/sourcectl.py"),
        "--root",
        str(study_root),
        "--registry",
        str(control / "CODE_SOURCES.json"),
    ]


def export_source(study_root: Path, source_id: str, destination: Path) -> dict[str, Any]:
    if destination.exists():
        raise Refusal(f"export destination must not exist: {destination}")
    audit = run_json(sourcectl_base(study_root) + ["audit", "--source-id", source_id], cwd=study_root)
    if audit.get("status") != "PASS" or audit.get("finding_count") != 0:
        raise Refusal(f"source audit is not clean for {source_id}")
    return run_json(
        sourcectl_base(study_root)
        + ["export", "--source-id", source_id, "--destination", str(destination)],
        cwd=study_root,
    )


def verify_export(root: Path, source_id: str, commit: str, file_count: int) -> dict[str, Any]:
    receipt_path = root / ".STUDY_SOURCE_EXPORT.json"
    receipt = load_json(receipt_path)
    expected = {
        "schema": "study.code-source-export.v1",
        "source_id": source_id,
        "source_commit": commit,
        "file_count": file_count,
        "git_metadata_included": False,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise Refusal(f"export receipt mismatch for {source_id}: {key}")
    if list(root.rglob(".git")):
        raise Refusal(f"Git metadata present in {source_id} export")
    manifest = directory_manifest(root, exclude={".STUDY_SOURCE_EXPORT.json"})
    if len(manifest) != file_count:
        raise Refusal(f"{source_id} export denominator is {len(manifest)}, expected {file_count}")
    return {
        "receipt_sha256": sha_file(receipt_path),
        "manifest_sha256": manifest_digest(manifest),
        "file_count": len(manifest),
        "manifest": manifest,
    }


def install_skill(tool_export: Path, workspace: Path) -> dict[str, Any]:
    source = tool_export / "vulnhunt"
    installed = workspace / ".claude/skills/vulnhunt"
    if installed.exists():
        raise Refusal(f"skill destination already exists: {installed}")
    installed.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, installed)
    source_manifest = directory_manifest(source)
    installed_manifest = directory_manifest(installed)
    if source_manifest != installed_manifest:
        raise Refusal("project-local VulnHunter skill differs from pinned export")
    for rel in REQUIRED_PHASE_FILES:
        if rel not in installed_manifest:
            raise Refusal(f"required upstream skill file missing: {rel}")
    skill_text = (installed / "SKILL.md").read_text()
    for marker in REQUIRED_SKILL_MARKERS:
        if marker not in skill_text:
            raise Refusal(f"upstream workflow marker missing: {marker}")
    return {
        "file_count": len(installed_manifest),
        "manifest_sha256": manifest_digest(installed_manifest),
        "skill_sha256": sha_file(installed / "SKILL.md"),
        "manifest": installed_manifest,
    }


def project_settings(workspace: Path = LIVE_WORKSPACE_PATH) -> dict[str, Any]:
    target = workspace / "target"
    runtime_target = workspace / "runtime-target"
    results = workspace / "results"
    skill = workspace / ".claude/skills/vulnhunt"
    runtime = recovery.runtime_paths(workspace)
    return {
        "permissions": {
            "defaultMode": "dontAsk",
            "allow": [
                f"Read({target}/**)",
                f"Read({runtime_target}/**)",
                f"Read({results}/**)",
                f"Read({skill}/**)",
                f"Edit({results}/**)",
                "Glob",
                "Grep",
                "Agent",
                "Bash",
            ],
            "deny": [
                "WebFetch",
                "WebSearch",
                "Read(/path/to/local-home/**)",
                "Edit(/path/to/local-home/**)",
                f"Edit({target}/**)",
                f"Edit({runtime_target}/**)",
                f"Edit({skill}/**)",
                f"Edit({workspace}/.claude/**)",
                "Bash(git push*)",
                "Bash(ssh *)",
                "Bash(scp *)",
            ],
        },
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "filesystem": {
                "denyRead": ["/path/to/local-home"],
                "denyWrite": ["/path/to/local-home"],
                "allowWrite": [
                    str(runtime_target),
                    str(results),
                    str(runtime["npm_cache"]),
                    str(runtime["tmp"]),
                ],
            },
            "network": {
                "allowedDomains": ["localhost", "127.0.0.1"],
                "allowLocalBinding": True,
            },
        },
    }


def prompt_for(target: Path, runtime_target: Path, results: Path) -> str:
    return f"""/vulnhunt

Pre-resolved scan metadata
VULNHUNT_DIR: {results}
VULNHUNT_BRANCH: v17.1.1 [{TARGET_COMMIT[:7]}]
Repository URL: https://github.com/juice-shop/juice-shop.git
Bash: AVAILABLE
Controller-owned target service: {TARGET_HEALTH_URL}

Immutable source directory: {target}
Writable runtime/test copy: {runtime_target}

Run the complete unchanged upstream VulnHunter workflow against the full immutable source repository. Follow every documented phase, use the required subagents, write native phase outputs, PoCs, exploit tests, sweep, and final report into VULNHUNT_DIR. Dependencies have already been prepared in the writable runtime/test copy. The target service is already running at the controller-owned URL above; use it for dynamic tests but do not start, stop, rebuild, or replace it. Read and analyze first-party source from the immutable source directory. Run Bash, tests, builds, PoCs, and local loopback requests only inside the writable runtime/test copy. Never write to the immutable source directory. Do not use benchmark labels, an answer key, prior findings, or earlier run output. Do not access external targets or install/download anything. Stop if the installed /vulnhunt skill or any phase file differs from the pinned project-local copy.
"""


def claude_argv(scope: dict[str, Any], prompt: str) -> list[str]:
    return [
        scope["runtime"]["executable"],
        "--print",
        "--verbose",
        "--output-format",
        "stream-json",
        "--forward-subagent-text",
        "--model",
        scope["model"],
        "--effort",
        "high",
        "--permission-mode",
        "dontAsk",
        "--setting-sources",
        "project",
        "--settings",
        str(recovery.runtime_paths(Path(scope["target"]["workspace_root"]))["settings"]),
        "--tools",
        "Read,Write,Glob,Grep,Agent,Bash",
        "--disallowedTools",
        "Edit,WebFetch,WebSearch",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--no-chrome",
        "--no-session-persistence",
        "--max-budget-usd",
        str(scope["budgets"]["max_cost_usd"]),
        prompt,
    ]


def auth_status() -> dict[str, Any]:
    try:
        completed = subprocess.run(["claude", "auth", "status"], text=True, capture_output=True, timeout=10)
        value = json.loads(completed.stdout) if completed.stdout.strip() else {}
        return {"exit_code": completed.returncode, **value}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {"exit_code": 127, "error": str(exc), "loggedIn": False}


def claude_runtime() -> dict[str, Any]:
    executable = shutil.which("claude")
    if not executable:
        raise Refusal("Claude Code executable is unavailable")
    resolved = Path(executable).resolve()
    completed = subprocess.run([str(resolved), "--version"], text=True, capture_output=True, timeout=10)
    if completed.returncode != 0 or not completed.stdout.strip():
        raise Refusal("Claude Code version could not be resolved")
    return {
        "executable": str(resolved),
        "executable_sha256": sha_file(resolved),
        "version": completed.stdout.strip(),
        "code_identity": darwin_code_identity(str(resolved)),
    }


def prepare_workspace(study_root: Path, workspace: Path) -> dict[str, Any]:
    if study_root.resolve() != STUDY_ROOT.resolve():
        raise Refusal("Study source-control root differs from the frozen controller contract")
    workspace.mkdir(parents=True, exist_ok=False)
    target_export = export_source(study_root, TARGET_SOURCE_ID, workspace / "target")
    tool_export = export_source(study_root, TOOL_SOURCE_ID, workspace / "tool")
    target = verify_export(workspace / "target", TARGET_SOURCE_ID, TARGET_COMMIT, TARGET_FILE_COUNT)
    tool = verify_export(workspace / "tool", TOOL_SOURCE_ID, TOOL_COMMIT, TOOL_FILE_COUNT)
    if target["manifest_sha256"] != TARGET_MANIFEST_SHA256:
        raise Refusal("full target manifest differs from the pinned denominator")
    if tool["manifest_sha256"] != TOOL_MANIFEST_SHA256:
        raise Refusal("full tool manifest differs from the pinned source")
    installed = install_skill(workspace / "tool", workspace)
    if installed["manifest_sha256"] != SKILL_MANIFEST_SHA256:
        raise Refusal("installed VulnHunter skill differs from the pinned manifest")
    runtime_target = workspace / "runtime-target"
    shutil.copytree(workspace / "target", runtime_target)
    runtime_target_manifest = directory_manifest(
        runtime_target, exclude={".STUDY_SOURCE_EXPORT.json"}
    )
    if runtime_target_manifest != target["manifest"]:
        raise Refusal("writable runtime/test copy differs from the pinned source preimage")
    results = workspace / "results"
    results.mkdir()
    paths = recovery.runtime_paths(workspace)
    for directory in (paths["root"], paths["npm_cache"], paths["tmp"]):
        directory.mkdir(parents=True, exist_ok=True)
    paths["git_config"].write_text(recovery.git_config_text())
    settings_bytes = canonical_bytes(project_settings(workspace))
    settings_path = workspace / ".claude/settings.json"
    settings_path.write_bytes(settings_bytes)
    paths["settings"].write_bytes(settings_bytes)
    prepared = {
        "schema": "ospt.full-vulnhunter-preparation.v2",
        "prepared_at": now_z(),
        "provider_invoked": False,
        "target": target,
        "tool": tool,
        "installed_skill": installed,
        "export_receipts": {"target": target_export, "tool": tool_export},
        "settings_sha256": sha_file(settings_path),
        "explicit_settings_sha256": sha_file(paths["settings"]),
        "git_config_sha256": sha_file(paths["git_config"]),
        "runtime_target_preimage_sha256": manifest_digest(runtime_target_manifest),
        "auth": auth_status(),
    }
    receipt = paths["root"] / PREPARATION_RECEIPT_NAME
    write_create_once(receipt, canonical_bytes(prepared))
    return prepared


def inspect_prepared_workspace(
    workspace: Path, *, allow_settings_mismatch: bool = False
) -> dict[str, Any]:
    if workspace.resolve() != LIVE_WORKSPACE_PATH.resolve():
        raise Refusal("workspace differs from the frozen A4 location")
    paths = recovery.runtime_paths(workspace)
    receipt = load_json(paths["root"] / PREPARATION_RECEIPT_NAME)
    if receipt.get("schema") != "ospt.full-vulnhunter-preparation.v2":
        raise Refusal("workspace preparation receipt is missing or invalid")
    target = verify_export(workspace / "target", TARGET_SOURCE_ID, TARGET_COMMIT, TARGET_FILE_COUNT)
    tool = verify_export(workspace / "tool", TOOL_SOURCE_ID, TOOL_COMMIT, TOOL_FILE_COUNT)
    if target["manifest_sha256"] != TARGET_MANIFEST_SHA256:
        raise Refusal("prepared immutable target differs from the pinned denominator")
    if tool["manifest_sha256"] != TOOL_MANIFEST_SHA256:
        raise Refusal("prepared tool differs from the pinned source")
    installed_manifest = directory_manifest(workspace / ".claude/skills/vulnhunt")
    if manifest_digest(installed_manifest) != SKILL_MANIFEST_SHA256:
        raise Refusal("prepared project-local skill differs from the pinned manifest")
    settings_digest = sha_bytes(canonical_bytes(project_settings(workspace)))
    for path in (workspace / ".claude/settings.json", paths["settings"]):
        if not path.is_file() or sha_file(path) != settings_digest:
            if not allow_settings_mismatch:
                raise Refusal("prepared safety settings differ from the controller contract")
    if not paths["git_config"].is_file() or paths["git_config"].read_text() != recovery.git_config_text():
        raise Refusal("prepared Git transport rewrite differs from the controller contract")
    source_unchanged, source_defects = recovery.verify_source_postimage(
        workspace / "target", target["manifest"]
    )
    if not source_unchanged:
        raise Refusal("immutable source postimage changed: " + "; ".join(source_defects))
    runtime_source_unchanged, runtime_source_defects = verify_pinned_members(
        workspace / "runtime-target", target["manifest"]
    )
    if not runtime_source_unchanged:
        raise Refusal("runtime/test copy changed first-party source: " + "; ".join(runtime_source_defects))
    return {
        "receipt": receipt,
        "target": target,
        "tool": tool,
        "installed_skill": {
            "manifest": installed_manifest,
            "manifest_sha256": manifest_digest(installed_manifest),
        },
        "settings_sha256": settings_digest,
        "auth": auth_status(),
        "runtime_target_first_party_unchanged": True,
    }


def command_refresh_settings(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    inspect_prepared_workspace(workspace, allow_settings_mismatch=True)
    paths = recovery.runtime_paths(workspace)
    receipt_path = paths["root"] / "SETTINGS_REFRESH.json"
    if receipt_path.exists():
        raise Refusal("settings refresh receipt already exists")
    project_path = workspace / ".claude/settings.json"
    explicit_path = paths["settings"]
    old_project = project_path.read_bytes()
    old_explicit = explicit_path.read_bytes()
    expected = canonical_bytes(project_settings(workspace))
    if old_project == expected and old_explicit == expected:
        raise Refusal("workspace settings already match the controller contract")
    write_create_once(paths["root"] / "project-settings.before-refresh.json", old_project)
    write_create_once(paths["root"] / "explicit-settings.before-refresh.json", old_explicit)
    for path in (project_path, explicit_path):
        temporary = path.with_name(path.name + ".refresh")
        write_create_once(temporary, expected)
        os.replace(temporary, path)
    expected_digest = sha_bytes(expected)
    if sha_file(project_path) != expected_digest or sha_file(explicit_path) != expected_digest:
        raise Refusal("settings refresh postimage differs from the controller contract")
    receipt = {
        "schema": "ospt.vulnhunter-settings-refresh.v1",
        "status": "PASS",
        "refreshed_at": now_z(),
        "provider_invoked": False,
        "old_project_settings_sha256": sha_bytes(old_project),
        "old_explicit_settings_sha256": sha_bytes(old_explicit),
        "new_settings_sha256": expected_digest,
        "reason": "Claude 2.1.228 requires Edit(path) rules for all path-scoped file-editing tools; ignored Write(path) rules were replaced before trust or provider use.",
        "claim_ceiling": "Local settings syntax refresh only; no trust, provider, scan, finding, or runtime-containment claim.",
    }
    write_create_once(receipt_path, canonical_bytes(receipt))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def build_scope(
    workspace_root: str,
    expires: str,
    max_cost: float,
    max_seconds: int,
    *,
    require_empty_results: bool = True,
) -> dict[str, Any]:
    if float(max_cost) != MAX_COST_USD or int(max_seconds) != MAX_SECONDS:
        raise Refusal(
            f"budget differs from frozen controller contract: ${MAX_COST_USD:.2f}/{MAX_SECONDS}s"
        )
    root = Path(workspace_root).resolve()
    if root != LIVE_WORKSPACE_PATH.resolve():
        raise Refusal("workspace differs from the frozen one-attempt location")
    try:
        expires_at = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise Refusal("scope expiry is not a valid timestamp") from exc
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now or (expires_at - now).total_seconds() > MAX_SCOPE_LIFETIME_SECONDS:
        raise Refusal("scope expiry must be current and no more than 48 hours in the future")
    prepared = inspect_prepared_workspace(root)
    if require_empty_results and any(path.is_file() for path in (root / "results").rglob("*")):
        raise Refusal("results directory is not empty before scope creation")
    project_sidecar_root = claude_project_sidecar_root(root)
    if require_empty_results and project_sidecar_root.exists() and any(project_sidecar_root.rglob("*")):
        raise Refusal("A4 Claude project sidecar root is not empty before scope creation")
    prompt = prompt_for(root / "target", root / "runtime-target", root / "results")
    scope = {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "purpose": "Complete the unchanged upstream VulnHunter workflow against the full pinned OWASP Juice Shop v17.1.1 source repository with a controller-owned contained target service.",
        "owner": {
            "identity": OWNER_IDENTITY,
            "namespace": APPROVAL_NAMESPACE,
            "allowed_signers_path": str(ALLOWED_SIGNERS_PATH),
            "allowed_signers_sha256": ALLOWED_SIGNERS_SHA256,
        },
        "controller": {
            "path": str(CONTROLLER_DEPLOY_PATH),
            "sha256": sha_file(Path(__file__).resolve()),
        },
        "runtime": claude_runtime(),
        "actual_consumer": {
            "command": "/vulnhunt",
            "tool_source_id": TOOL_SOURCE_ID,
            "tool_commit": TOOL_COMMIT,
            "required_native_outputs": list(REQUIRED_NATIVE_OUTPUTS),
            "required_agent_formula": "3 * partition_count + 5 total minimum, including recon, verify, reproduce/test/fix, and sweep",
        },
        "target": {
            "source_id": TARGET_SOURCE_ID,
            "commit": TARGET_COMMIT,
            "tracked_file_count": TARGET_FILE_COUNT,
            "manifest_sha256": TARGET_MANIFEST_SHA256,
            "workspace_root": str(LIVE_WORKSPACE_PATH),
            "evidence_root": str(LIVE_EVIDENCE_PATH),
            "attempt_marker": str(ATTEMPT_MARKER_PATH),
            "immutable_source": str(root / "target"),
            "runtime_test_copy": str(root / "runtime-target"),
        },
        "source_control": {
            "study_root": str(STUDY_ROOT),
            "tool_export_manifest_sha256": TOOL_MANIFEST_SHA256,
            "installed_skill_manifest_sha256": SKILL_MANIFEST_SHA256,
        },
        "safety_settings_sha256": sha_bytes(canonical_bytes(project_settings(root))),
        "mode": "immutable source plus a separate writable runtime/test copy; provider Bash is sandboxed to runtime/test, results, isolated caches and loopback only; the controller owns the target PID, health, log, egress policy and teardown",
        "model": ROOT_MODEL_REQUEST,
        "model_resolution_contract": {
            "root": EXPECTED_ROOT_MODEL,
            "forwarded_allowed": list(ALLOWED_FORWARDED_MODELS),
            "unexpected_model_action": "refuse completion",
        },
        "tools": ["Read", "Write", "Glob", "Grep", "Agent", "Bash"],
        "disallowed_tools": ["Edit", "WebFetch", "WebSearch"],
        "budgets": {
            "attempts": 1,
            "max_cost_usd": max_cost,
            "max_seconds": max_seconds,
            "no_progress_seconds": NO_PROGRESS_SECONDS,
            "primary_stop": "provider-enforced max cost or normal workflow completion",
            "time_role": "absolute emergency watchdog only",
            "widening": False,
        },
        "target_service": {
            "owner": "controller",
            "health_url": TARGET_HEALTH_URL,
            "port": TARGET_PORT,
            "command_argv": target_service_argv(root),
            "sandbox_profile_sha256": sha_bytes(TARGET_SANDBOX_PROFILE.encode()),
            "outbound_policy": "deny non-loopback network from target process",
            "health_interval_seconds": TARGET_HEALTH_INTERVAL_SECONDS,
            "health_failure_limit": TARGET_HEALTH_FAILURE_LIMIT,
            "restart_budget": TARGET_RESTART_LIMIT,
            "restart_source": "pinned writable runtime/test copy",
            "crash_evidence_required": True,
            "teardown_required": True,
        },
        "runtime_sidecars": {
            "allowed_roots": [
                str(project_sidecar_root),
                str(recovery.runtime_paths(root)["tmp"]),
            ],
            "capture_required": True,
            "approved_symlink_references": "Claude runtime tmp tasks/<task>.output -> project subagents/agent-<task>.jsonl only; captured as inert JSON without dereference",
            "unexpected_path_action": "refuse completion",
        },
        "logging": {
            "planes": ["ENFORCEMENT.jsonl", "OPERATIONAL.jsonl", "EVIDENCE_DECISION.jsonl"],
            "raw": "raw-event-log.jsonl",
            "trace_profile": "high-stakes-scaled",
            "first_class_outcomes": ["allow", "deny", "refuse", "abstain", "failed-evidence", "no-action", "kill", "complete"],
        },
        "prompt": prompt,
        "expires": expires,
        "claim_ceiling": "One completion-grade full-repository VulnHunter experiment. Native outputs remain model claims until independent human disposition. No finding activation, production accuracy, adoption, recurrence, CI, deployment, publication, or external-presentation authority.",
    }
    scope["command_argv"] = claude_argv(scope, prompt)
    runtime_env = runtime_environment(root)
    readiness = recovery.readiness_report(
        workspace=root,
        claude_config=CLAUDE_CONFIG_PATH,
        argv=scope["command_argv"],
        env=runtime_env,
        dependency_receipt=recovery.runtime_paths(root)["dependency_receipt"],
    )
    if readiness["status"] != "PASS":
        raise Refusal("pre-provider readiness is not GREEN: " + "; ".join(readiness["defects"]))
    node_defects = validate_node_runtime_plan(runtime_env)
    if node_defects:
        raise Refusal("pinned Node runtime is not GREEN: " + "; ".join(node_defects))
    dependency = readiness["dependency"]["receipt"]
    node_modules = root / "runtime-target/node_modules"
    if not node_modules.is_dir():
        raise Refusal("prepared runtime dependencies are absent")
    node_modules_digest = manifest_digest(runtime_dependency_manifest(node_modules))
    if dependency.get("node_modules_manifest_sha256") != node_modules_digest:
        raise Refusal("dependency receipt does not match the runtime dependency postimage")
    scope["preprovider"] = {
        "preparation_receipt_sha256": sha_file(
            recovery.runtime_paths(root)["root"] / PREPARATION_RECEIPT_NAME
        ),
        "dependency_receipt_sha256": sha_file(recovery.runtime_paths(root)["dependency_receipt"]),
        "node_modules_manifest_sha256": node_modules_digest,
        "exact_workspace_trust": readiness["trust"],
        "runtime_environment": {
            key: runtime_env[key]
            for key in (
                recovery.BACKGROUND_WAIT_ENV,
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM",
                "GIT_TERMINAL_PROMPT",
                "NPM_CONFIG_CACHE",
                "TMPDIR",
                "CLAUDE_TMPDIR",
                "CLAUDE_CODE_TMPDIR",
                "BUN_TMPDIR",
            )
        },
        "runtime_target_first_party_unchanged": prepared[
            "runtime_target_first_party_unchanged"
        ],
        "node_runtime": node_runtime(),
        "target_service_plan": scope["target_service"],
    }
    return scope


def verify_scope(scope_path: Path, signature_path: Path, allowed_signers: Path) -> dict[str, Any]:
    scope_bytes = scope_path.read_bytes()
    if canonical_bytes(json.loads(scope_bytes)) != scope_bytes:
        raise Refusal("scope is not canonical JSON bytes")
    scope = json.loads(scope_bytes)
    if scope.get("schema") != SCHEMA or scope.get("run_id") != RUN_ID:
        raise Refusal("scope identity mismatch")
    if scope.get("actual_consumer", {}).get("command") != "/vulnhunt":
        raise Refusal("scope does not authorize the upstream /vulnhunt consumer")
    if scope.get("target", {}).get("tracked_file_count") != TARGET_FILE_COUNT:
        raise Refusal("scope does not bind the full target denominator")
    if scope.get("target", {}).get("manifest_sha256") != TARGET_MANIFEST_SHA256:
        raise Refusal("scope does not bind the pinned full-target manifest")
    if scope.get("source_control", {}).get("study_root") != str(STUDY_ROOT):
        raise Refusal("scope does not bind the Study source-control root")
    if scope.get("source_control", {}).get("tool_export_manifest_sha256") != TOOL_MANIFEST_SHA256:
        raise Refusal("scope does not bind the pinned full-tool manifest")
    if scope.get("source_control", {}).get("installed_skill_manifest_sha256") != SKILL_MANIFEST_SHA256:
        raise Refusal("scope does not bind the pinned installed-skill manifest")
    if scope.get("target", {}).get("workspace_root") != str(LIVE_WORKSPACE_PATH):
        raise Refusal("scope does not bind the fixed isolated workspace")
    if scope.get("target", {}).get("evidence_root") != str(LIVE_EVIDENCE_PATH):
        raise Refusal("scope does not bind the fixed evidence destination")
    if scope.get("target", {}).get("attempt_marker") != str(ATTEMPT_MARKER_PATH):
        raise Refusal("scope does not bind the global one-attempt marker")
    if scope.get("target", {}).get("immutable_source") != str(
        (LIVE_WORKSPACE_PATH / "target").resolve()
    ):
        raise Refusal("scope does not bind the immutable source directory")
    if scope.get("target", {}).get("runtime_test_copy") != str(
        (LIVE_WORKSPACE_PATH / "runtime-target").resolve()
    ):
        raise Refusal("scope does not bind the writable runtime/test copy")
    if Path(__file__).resolve() != CONTROLLER_DEPLOY_PATH.resolve():
        raise Refusal("live execution is permitted only from the canonical controller path")
    controller = scope.get("controller", {})
    if controller.get("path") != str(CONTROLLER_DEPLOY_PATH):
        raise Refusal("scope does not bind the canonical controller path")
    if controller.get("sha256") != sha_file(Path(__file__).resolve()):
        raise Refusal("running controller differs from the signed controller digest")
    if scope.get("budgets", {}).get("attempts") != 1 or scope.get("budgets", {}).get("widening") is not False:
        raise Refusal("scope is not one-attempt/no-widening")
    if float(scope.get("budgets", {}).get("max_cost_usd", -1)) != MAX_COST_USD:
        raise Refusal("scope cost ceiling differs from frozen controller contract")
    if int(scope.get("budgets", {}).get("max_seconds", -1)) != MAX_SECONDS:
        raise Refusal("scope time ceiling differs from frozen controller contract")
    owner = scope.get("owner", {})
    expected_signers = ALLOWED_SIGNERS_PATH.resolve()
    if allowed_signers.resolve() != expected_signers:
        raise Refusal("caller-supplied allowed-signers file is not the pinned owner trust root")
    if owner.get("allowed_signers_path") != str(ALLOWED_SIGNERS_PATH):
        raise Refusal("scope does not bind the pinned allowed-signers path")
    if owner.get("allowed_signers_sha256") != ALLOWED_SIGNERS_SHA256:
        raise Refusal("scope does not bind the pinned allowed-signers digest")
    expires = dt.datetime.fromisoformat(scope["expires"].replace("Z", "+00:00"))
    if dt.datetime.now(dt.timezone.utc) >= expires:
        raise Refusal("scope expired")
    with pinned_allowed_signers_fd(allowed_signers) as (signers_fd, verified_signers):
        completed = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(verified_signers),
                "-I",
                OWNER_IDENTITY,
                "-n",
                APPROVAL_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=scope_bytes,
            capture_output=True,
            pass_fds=(signers_fd,),
        )
    if completed.returncode != 0:
        raise Refusal("owner signature verification failed")
    expected = build_scope(
        scope["target"]["workspace_root"],
        scope["expires"],
        float(scope["budgets"]["max_cost_usd"]),
        int(scope["budgets"]["max_seconds"]),
        require_empty_results=False,
    )
    if scope != expected:
        raise Refusal("scope contains values outside the frozen controller contract")
    return scope


def reconstruct_replay_binding(
    scope_path: Path,
    signature_path: Path,
    allowed_signers: Path,
    results: Path,
    raw_log: Path,
) -> VerifiedBinding:
    scope = verify_scope(scope_path, signature_path, allowed_signers)
    workspace = Path(scope["target"]["workspace_root"]).resolve()
    if results.resolve() != (workspace / "results").resolve():
        raise Refusal("replay results path differs from the signed workspace")
    expected_raw = Path(scope["target"]["evidence_root"]) / "raw-event-log.jsonl"
    if raw_log.resolve() != expected_raw.resolve():
        raise Refusal("replay raw-event path differs from the signed evidence destination")
    with tempfile.TemporaryDirectory(prefix="ospt-vh-replay-source-") as name:
        fresh_target = Path(name) / "target"
        export_source(STUDY_ROOT, TARGET_SOURCE_ID, fresh_target)
        expected_target = verify_export(
            fresh_target, TARGET_SOURCE_ID, TARGET_COMMIT, TARGET_FILE_COUNT
        )
        if expected_target["manifest_sha256"] != TARGET_MANIFEST_SHA256:
            raise Refusal("fresh replay source differs from the pinned target manifest")
        unchanged, defects = verify_original_manifest(
            workspace / "target", expected_target["manifest"]
        )
        if not unchanged or defects:
            raise Refusal("replay target source or added-member boundary cannot be verified")
        runtime_unchanged, runtime_defects = verify_pinned_members(
            workspace / "runtime-target", expected_target["manifest"]
        )
        if not runtime_unchanged or runtime_defects:
            raise Refusal("replay runtime/test copy changed first-party source")
    skill_manifest = directory_manifest(workspace / ".claude/skills/vulnhunt")
    if manifest_digest(skill_manifest) != SKILL_MANIFEST_SHA256:
        raise Refusal("replay skill differs from the pinned manifest")
    settings_path = workspace / ".claude/settings.json"
    if sha_file(settings_path) != scope["safety_settings_sha256"]:
        raise Refusal("replay safety settings differ from the signed scope")
    explicit_settings = recovery.runtime_paths(workspace)["settings"]
    if sha_file(explicit_settings) != scope["safety_settings_sha256"]:
        raise Refusal("replay explicit runtime settings differ from the signed scope")
    return VerifiedBinding(
        scope_path=str(scope_path.resolve()),
        signature_path=str(signature_path.resolve()),
        allowed_signers_path=str(allowed_signers.resolve()),
        provenance="signed-replay",
    )


def iter_json_lines(path: Path) -> Iterable[Any]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def collect_tool_records(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if value.get("type") == "tool_use" and isinstance(value.get("name"), str):
            found.append(value)
        for child in value.values():
            found.extend(collect_tool_records(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(collect_tool_records(child))
    return found


def collect_tool_result_ids(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        if value.get("type") == "tool_result" and isinstance(value.get("tool_use_id"), str):
            found.append(value["tool_use_id"])
        for child in value.values():
            found.extend(collect_tool_result_ids(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(collect_tool_result_ids(child))
    return found


def validate_init_events(
    init_events: list[dict[str, Any]], binding_map: dict[str, Any] | None
) -> list[str]:
    defects: list[str] = []
    if not init_events:
        return ["no Claude root init event observed"]
    init = init_events[0]
    if binding_map:
        if Path(str(init.get("cwd", ""))).resolve() != Path(
            binding_map["expected_cwd"]
        ).resolve():
            defects.append("Claude init cwd differs from signed workspace")
        if init.get("model") != binding_map["expected_root_model"]:
            defects.append("Claude init model differs from signed model")
    init_tools = set(init.get("tools", []))
    if not {"Read", "Write", "Glob", "Grep", "Bash"}.issubset(init_tools):
        defects.append("Claude init tool set is missing required tools")
    if not ({"Agent", "Task"} & init_tools):
        defects.append("Claude init did not expose Agent/Task")
    if init.get("mcp_servers") not in ([], None):
        defects.append("Claude init exposed an MCP server")
    discovered = json.dumps(
        {"skills": init.get("skills", []), "slash_commands": init.get("slash_commands", [])},
        sort_keys=True,
    ).lower()
    if "vulnhunt" not in discovered:
        defects.append("Claude init did not discover the project-local vulnhunt skill")
    for index, forwarded in enumerate(init_events[1:], start=1):
        if binding_map and Path(str(forwarded.get("cwd", ""))).resolve() != Path(
            binding_map["expected_cwd"]
        ).resolve():
            defects.append(f"forwarded init {index} cwd differs from signed workspace")
        if binding_map and forwarded.get("model") not in set(
            binding_map["allowed_forwarded_models"]
        ):
            defects.append(
                f"forwarded init {index} model is outside the signed model set"
            )
        if forwarded.get("mcp_servers") not in ([], None):
            defects.append(f"forwarded init {index} exposed an MCP server")
    return defects


def phase_finding_denominator(results: Path) -> tuple[list[str], list[str]]:
    expected: list[str] = []
    phase2b_path = results / "phase2b_output.md"
    if phase2b_path.is_file():
        in_confirmed = False
        for line in phase2b_path.read_text(errors="replace").splitlines():
            if line.startswith("## 4.") and "Confirmed" in line:
                in_confirmed = True
                continue
            if in_confirmed and line.startswith("## "):
                in_confirmed = False
            if not in_confirmed:
                continue
            match = re.match(
                r"^- \*\*(VULN-\d{3,})\*\*.*\*\*(High\+?|Medium|Low/Medium)\*\*",
                line,
            )
            if match:
                expected.append(match.group(1))
    assigned: list[str] = []
    phase3_path = results / "phase3_output.md"
    if phase3_path.is_file():
        assigned = sorted(
            set(
                re.findall(
                    r"^\|\s*(VULN-\d{3,})\s*\|",
                    phase3_path.read_text(errors="replace"),
                    re.MULTILINE,
                )
            )
        )
    return expected, assigned


def validate_native_results(
    results: Path,
    raw_log: Path,
    binding: VerifiedBinding | None = None,
    *,
    synthetic_fixture: bool = False,
    stderr_path: Path | None = None,
) -> dict[str, Any]:
    defects: list[str] = []
    if binding is not None and not isinstance(binding, VerifiedBinding):
        raise Refusal("consumer binding must be reconstructed by the signed controller")
    binding_map: dict[str, Any] | None = None
    if binding:
        signed_scope = verify_scope(
            Path(binding.scope_path),
            Path(binding.signature_path),
            Path(binding.allowed_signers_path),
        )
        signed_workspace = Path(signed_scope["target"]["workspace_root"]).resolve()
        signed_raw = Path(signed_scope["target"]["evidence_root"]) / "raw-event-log.jsonl"
        if results.resolve() != (signed_workspace / "results").resolve():
            raise Refusal("validation results differ from the signed workspace")
        if raw_log.resolve() != signed_raw.resolve():
            raise Refusal("validation raw log differs from the signed evidence path")
        signed_prompt = signed_scope["prompt"]
        signed_argv = claude_argv(signed_scope, signed_prompt)
        binding_map = {
            "scope_sha256": sha_file(Path(binding.scope_path)),
            "prompt_sha256": sha_bytes(signed_prompt.encode()),
            "command_argv_sha256": sha_bytes(canonical_bytes(signed_argv)),
            "target_manifest_sha256": TARGET_MANIFEST_SHA256,
            "skill_manifest_sha256": SKILL_MANIFEST_SHA256,
            "settings_sha256": signed_scope["safety_settings_sha256"],
            "expected_cwd": str(signed_workspace),
            "expected_root_model": signed_scope["model_resolution_contract"]["root"],
            "allowed_forwarded_models": signed_scope["model_resolution_contract"]["forwarded_allowed"],
            "provenance": binding.provenance,
        }
    if binding is None and not synthetic_fixture:
        defects.append("missing signed controller/consumer binding")
    for rel in REQUIRED_NATIVE_OUTPUTS:
        path = results / rel
        if not path.is_file() or path.stat().st_size == 0:
            defects.append(f"missing native output: {rel}")
    partitions = sorted((results / "partitions").glob("sg-*_data.md")) if (results / "partitions").is_dir() else []
    if not partitions:
        defects.append("no native partition data files")
    hunt_results = sorted((results / "results").glob("*")) if (results / "results").is_dir() else []
    hunt_files = [path for path in hunt_results if path.is_file() and path.stat().st_size > 0]
    if partitions and len(hunt_files) < 3 * len(partitions) + 1:
        defects.append(
            f"hunt result denominator {len(hunt_files)} is below 3*{len(partitions)}+1"
        )
    for dirname in ("poc", "exploit_tests"):
        directory = results / dirname
        populated = directory.is_dir() and any(path.is_file() and path.stat().st_size > 0 for path in directory.rglob("*"))
        if not populated:
            defects.append(f"native {dirname} directory is absent or empty")
    tool_records: list[dict[str, Any]] = []
    tool_result_ids: list[str] = []
    init_events: list[dict[str, Any]] = []
    event_count = 0
    for event in iter_json_lines(raw_log):
        event_count += 1
        if isinstance(event, dict) and event.get("type") == "system" and event.get("subtype") == "init":
            init_events.append(event)
        tool_records.extend(collect_tool_records(event))
        tool_result_ids.extend(collect_tool_result_ids(event))
    tool_uses = [record["name"] for record in tool_records]
    agent_records = [record for record in tool_records if record["name"] in {"Agent", "Task"}]
    agent_count = len(agent_records)
    required_agents = 3 * len(partitions) + 5 if partitions else 5
    if agent_count < required_agents:
        defects.append(f"agent activity {agent_count} is below required minimum {required_agents}")
    agent_ids = [record.get("id") for record in agent_records]
    if any(not isinstance(tool_id, str) for tool_id in agent_ids):
        defects.append("one or more Agent/Task dispatches lack a tool-use ID")
    else:
        dispatch_counts = Counter(agent_ids)
        result_counts = Counter(tool_result_ids)
        duplicate_dispatches = [tool_id for tool_id, count in dispatch_counts.items() if count != 1]
        if duplicate_dispatches:
            defects.append(
                f"{len(duplicate_dispatches)} Agent/Task tool-use IDs are not unique"
            )
        missing_results = [tool_id for tool_id in agent_ids if result_counts[tool_id] != 1]
        if missing_results:
            defects.append(
                f"{len(missing_results)} Agent/Task dispatches do not have exactly one matching tool result"
            )
    if "Bash" not in tool_uses:
        defects.append("no Bash activity observed for dependency installation or exploit testing")
    defects.extend(validate_init_events(init_events, binding_map))
    agent_inputs = [json.dumps(record.get("input", {}), sort_keys=True) for record in agent_records]
    for marker in (
        "phase1_recon.md",
        "phase2b_verify.md",
        "phase3_reproduce_test.md",
        "phase3c_fixes.md",
        "phase3d_sweep.md",
    ):
        if not any(marker in value for value in agent_inputs):
            defects.append(f"no phase-specific Agent/Task dispatch for {marker}")
    if not any("sink-driven" in value.lower() for value in agent_inputs):
        defects.append("no sink-driven Agent/Task dispatch observed")
    for partition in partitions:
        references = sum(partition.name in value for value in agent_inputs)
        if references < 3:
            defects.append(
                f"partition {partition.name} appears in {references} Agent/Task dispatches; expected at least 3"
            )
    terminal = recovery.terminal_state(raw_log, stderr_path)
    cost = recovery.cost_accounting(raw_log)
    if not synthetic_fixture and not terminal["complete"]:
        defects.append("Claude terminal state is incomplete or background work was cut off")
    if (
        not synthetic_fixture
        and isinstance(cost["conservative_cost_usd"], (int, float))
        and cost["conservative_cost_usd"] > MAX_COST_USD
    ):
        defects.append("conservative runtime cost view exceeds the signed ceiling")
    try:
        results_manifest = directory_manifest(results) if results.exists() else {}
    except Refusal as exc:
        defects.append(f"results evidence manifest refused: {exc}")
        results_manifest = {}
    phase2b_expected_ids, phase3_assignment_ids = phase_finding_denominator(results)
    if not phase2b_expected_ids:
        defects.append("Phase 2b has no machine-countable High/Medium confirmed-finding denominator")
    expected_set = set(phase2b_expected_ids)
    assigned_set = set(phase3_assignment_ids)
    if expected_set and assigned_set != expected_set:
        defects.append(
            f"Phase 3 assignment denominator differs from Phase 2b High/Medium set: expected {len(expected_set)}, observed {len(assigned_set)}"
        )
    poc_names = [path.name for path in (results / "poc").glob("*") if path.is_file()] if (results / "poc").is_dir() else []
    test_names = [path.name.lower() for path in (results / "exploit_tests").glob("*") if path.is_file()] if (results / "exploit_tests").is_dir() else []
    for finding_id in sorted(expected_set):
        numeric = finding_id.split("-", 1)[1]
        if not any(name.startswith(finding_id) for name in poc_names):
            defects.append(f"missing PoC for Phase 2b High/Medium finding {finding_id}")
        if not any(f"vuln_{numeric}" in name for name in test_names):
            defects.append(f"missing exploit test for Phase 2b High/Medium finding {finding_id}")
    report = {
        "schema": "ospt.full-vulnhunter-native-validation.v1",
        "validated_at": now_z(),
        "status": "PASS" if not defects else "KICKBACK",
        "actual_consumer_observed": bool(binding) and not defects,
        "synthetic_fixture": synthetic_fixture,
        "partition_count": len(partitions),
        "hunt_result_file_count": len(hunt_files),
        "agent_tool_use_count": agent_count,
        "required_agent_tool_use_count": required_agents,
        "root_init_count": 1 if init_events else 0,
        "forwarded_init_count": max(0, len(init_events) - 1),
        "phase2b_high_medium_count": len(expected_set),
        "phase3_assignment_count": len(assigned_set),
        "event_count": event_count,
        "tool_use_counts": {name: tool_uses.count(name) for name in sorted(set(tool_uses))},
        "terminal_state": terminal,
        "cost_accounting": cost,
        "controller_binding": binding_map,
        "results_path": str(results),
        "results_manifest_sha256": manifest_digest(results_manifest),
        "raw_log_path": str(raw_log),
        "raw_log_sha256": sha_file(raw_log),
        "defects": defects,
        "claim_ceiling": (
            "Synthetic PASS proves only that the validator accepts a structural fixture; it never proves the actual consumer."
            if synthetic_fixture
            else "PASS proves only that the signed documented upstream workflow and native evidence contract were observed; all security findings remain PENDING_HUMAN."
        ),
    }
    return report


def raw_runtime_summary(raw_log: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "event_count": 0,
        "result_event_count": 0,
        "rate_limit_event_count": 0,
        "reported_cost_usd": None,
        "reported_duration_ms": None,
        "reported_num_turns": None,
        "result_subtype": None,
        "result_is_error": None,
    }
    for event in iter_json_lines(raw_log):
        summary["event_count"] += 1
        if not isinstance(event, dict):
            continue
        if event.get("type") == "rate_limit_event":
            summary["rate_limit_event_count"] += 1
        if event.get("type") == "result":
            summary["result_event_count"] += 1
            summary["reported_cost_usd"] = event.get("total_cost_usd")
            summary["reported_duration_ms"] = event.get("duration_ms")
            summary["reported_num_turns"] = event.get("num_turns")
            summary["result_subtype"] = event.get("subtype")
            summary["result_is_error"] = event.get("is_error")
    summary["cost_accounting"] = recovery.cost_accounting(raw_log)
    return summary


def record_terminal_failure(
    enforcement: Path,
    operational: Path,
    evidence_log: Path,
    *,
    error: str,
    scope_consumed: bool,
) -> None:
    timestamp = now_z()
    append_jsonl(
        enforcement,
        {
            "event": "ACTION_FAILED",
            "event_time": timestamp,
            "run_id": RUN_ID,
            "scope_consumed": scope_consumed,
            "reason": error,
        },
    )
    append_jsonl(
        operational,
        {
            "event": "RUN_FAILED",
            "event_time": timestamp,
            "run_id": RUN_ID,
            "scope_consumed": scope_consumed,
            "error": error,
        },
    )
    append_jsonl(
        evidence_log,
        {
            "event": "ACTIVATION_NOT_AUTHORIZED",
            "event_time": timestamp,
            "transaction_time": timestamp,
            "effective_time": None,
            "run_id": RUN_ID,
            "decision": "PENDING_HUMAN",
            "scope_consumed": scope_consumed,
            "reason": error,
        },
    )


def terminate_process_group(process: SuspendedProcess, operational: Path, reason: str) -> None:
    if process.poll() is not None:
        return
    append_jsonl(
        operational,
        {
            "event": "TERMINATION_SIGNAL_SENT",
            "event_time": now_z(),
            "run_id": RUN_ID,
            "signal": "SIGTERM",
            "reason": reason,
        },
    )
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        append_jsonl(
            operational,
            {
                "event": "KILL_SIGNAL_SENT",
                "event_time": now_z(),
                "run_id": RUN_ID,
                "signal": "SIGKILL",
                "reason": "child did not stop after SIGTERM",
            },
        )
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def command_prepare(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    if workspace != LIVE_WORKSPACE_PATH.resolve():
        raise Refusal("prepare destination differs from the frozen A4 workspace")
    if workspace.exists():
        raise Refusal("A4 workspace already exists")
    prepared = prepare_workspace(args.study_root.resolve(), workspace)
    report = {
        "schema": "ospt.full-vulnhunter-prepare-command.v2",
        "status": "PASS",
        "provider_invoked": False,
        "workspace": str(workspace),
        "target_file_count": prepared["target"]["file_count"],
        "target_manifest_sha256": prepared["target"]["manifest_sha256"],
        "runtime_target_preimage_sha256": prepared["runtime_target_preimage_sha256"],
        "skill_manifest_sha256": prepared["installed_skill"]["manifest_sha256"],
        "settings_sha256": prepared["settings_sha256"],
        "next": "Prepare dependencies without a provider call, then accept exact workspace trust interactively.",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def command_dependencies(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    prepared = inspect_prepared_workspace(workspace)
    paths = recovery.runtime_paths(workspace)
    receipt_path = paths["dependency_receipt"]
    node_modules = workspace / "runtime-target/node_modules"
    attempt_index = 1
    if receipt_path.exists():
        prior = load_json(receipt_path)
        if not args.retry_after_kickback:
            raise Refusal("dependency preparation receipt already exists")
        if prior.get("status") != "KICKBACK" or prior.get("provider_invoked") is not False:
            raise Refusal("only a provider-free dependency KICKBACK may be retried")
        if node_modules.exists():
            raise Refusal("failed dependency attempt left an unmeasured node_modules tree")
        archived = sorted(paths["root"].glob("DEPENDENCY_PREP_ATTEMPT_*.json"))
        if len(archived) >= MAX_DEPENDENCY_ATTEMPTS - 1:
            raise Refusal("dependency preparation retry budget is exhausted")
        attempt_index = len(archived) + 2
        prior_receipt = paths["root"] / f"DEPENDENCY_PREP_ATTEMPT_{attempt_index - 1}.json"
        receipt_path.rename(prior_receipt)
        for old_name, suffix in (
            ("npm-ci.stdout.log", "stdout.log"),
            ("npm-ci.stderr.log", "stderr.log"),
            ("npm-prep.stdout.log", "stdout.log"),
            ("npm-prep.stderr.log", "stderr.log"),
        ):
            old = paths["root"] / old_name
            if old.exists():
                destination = paths["root"] / f"npm-prep-attempt-{attempt_index - 1}.{suffix}"
                if destination.exists():
                    raise Refusal("dependency retry log archive already exists")
                old.rename(destination)
    elif args.retry_after_kickback:
        raise Refusal("dependency retry requested without a prior KICKBACK receipt")
    if node_modules.exists():
        raise Refusal("runtime dependencies exist without a PASS controller receipt")
    runtime = node_runtime()
    npm_path = NPM_RUNTIME_PATH
    env = runtime_environment(workspace)
    node_defects = validate_node_runtime_plan(env)
    if node_defects:
        raise Refusal("dependency runtime plan is not GREEN: " + "; ".join(node_defects))
    version = subprocess.run(
        [str(npm_path), "--version"],
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
    )
    if version.returncode != 0 or not version.stdout.strip():
        raise Refusal("npm version could not be resolved")
    package_lock = workspace / "runtime-target/package-lock.json"
    if package_lock.is_file():
        strategy = "npm-ci-from-lock"
        argv = [str(npm_path), "ci", "--no-audit", "--no-fund"]
    else:
        strategy = "npm-install-without-lockfile-write"
        argv = [
            str(npm_path),
            "install",
            "--no-package-lock",
            "--no-audit",
            "--no-fund",
        ]
    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            argv,
            cwd=workspace / "runtime-target",
            env=env,
            text=True,
            capture_output=True,
            timeout=args.max_seconds,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
    stdout_path = paths["root"] / "npm-prep.stdout.log"
    stderr_path = paths["root"] / "npm-prep.stderr.log"
    write_create_once(stdout_path, stdout.encode())
    write_create_once(stderr_path, stderr.encode())
    source_unchanged, source_defects = recovery.verify_source_postimage(
        workspace / "target", prepared["target"]["manifest"]
    )
    runtime_unchanged, runtime_defects = verify_pinned_members(
        workspace / "runtime-target", prepared["target"]["manifest"]
    )
    node_manifest = runtime_dependency_manifest(node_modules) if node_modules.is_dir() else {}
    status = (
        "PASS"
        if exit_code == 0 and source_unchanged and runtime_unchanged and node_manifest
        else "KICKBACK"
    )
    receipt = {
        "schema": "ospt.vulnhunter-dependency-prep.v1",
        "status": status,
        "prepared_at": now_z(),
        "provider_invoked": False,
        "attempt_index": attempt_index,
        "target_root": str((workspace / "runtime-target").resolve()),
        "npm": {
            "path": str(npm_path),
            "sha256": sha_file(npm_path),
            "version": version.stdout.strip(),
            "argv": argv,
            "strategy": strategy,
        },
        "node": runtime,
        "npm_exit_code": exit_code,
        "timed_out": timed_out,
        "elapsed_seconds": time.monotonic() - started,
        "node_modules_file_count": len(node_manifest),
        "node_modules_manifest_sha256": manifest_digest(node_manifest) if node_manifest else None,
        "git_config_sha256": sha_file(paths["git_config"]),
        "stdout_sha256": sha_file(stdout_path),
        "stderr_sha256": sha_file(stderr_path),
        "immutable_source_unchanged": source_unchanged,
        "runtime_target_first_party_unchanged": runtime_unchanged,
        "defects": source_defects + runtime_defects,
        "claim_ceiling": "Provider-free dependency preparation only; no scan, finding, or runtime safety claim.",
    }
    write_create_once(receipt_path, canonical_bytes(receipt))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 2


def command_reuse_dependencies(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    if workspace != LIVE_WORKSPACE_PATH.resolve():
        raise Refusal("dependency reuse destination differs from the frozen A4 workspace")
    prepared = inspect_prepared_workspace(workspace)
    source_workspace = args.from_workspace.resolve()
    if source_workspace != A2_WORKSPACE_PATH.resolve():
        raise Refusal("dependency reuse source differs from the immutable A2 runtime")
    source_runtime = source_workspace / "runtime-target"
    source_receipt_path = recovery.runtime_paths(source_workspace)["dependency_receipt"]
    source_status = recovery.dependency_receipt_status(source_receipt_path, source_workspace)
    if not source_status["accepted"]:
        raise Refusal("A2 dependency receipt is not accepted")
    source_receipt = source_status["receipt"]
    source_node_modules = source_runtime / "node_modules"
    source_manifest = runtime_dependency_manifest(source_node_modules)
    if manifest_digest(source_manifest) != source_receipt["node_modules_manifest_sha256"]:
        raise Refusal("A2 node_modules postimage differs from its receipt")
    source_ok, source_defects = verify_pinned_members(
        source_runtime, prepared["target"]["manifest"]
    )
    if not source_ok:
        raise Refusal("A2 runtime first-party source drift: " + "; ".join(source_defects))
    source_runtime_manifest = runtime_dependency_manifest(source_runtime)
    shutil.copytree(source_runtime, workspace / "runtime-target", dirs_exist_ok=True, symlinks=True)
    destination_ok, destination_defects = verify_pinned_members(
        workspace / "runtime-target", prepared["target"]["manifest"]
    )
    destination_manifest = runtime_dependency_manifest(workspace / "runtime-target/node_modules")
    if manifest_digest(destination_manifest) != source_receipt["node_modules_manifest_sha256"]:
        raise Refusal("copied A4 node_modules differs from the A2 dependency postimage")
    if not (workspace / "runtime-target/build/app.js").is_file():
        raise Refusal("copied dependency/build postimage lacks build/app.js")
    destination_runtime_manifest = runtime_dependency_manifest(workspace / "runtime-target")
    if destination_runtime_manifest != source_runtime_manifest:
        raise Refusal("A4 runtime/test postimage differs from the bound A2 source postimage")
    paths = recovery.runtime_paths(workspace)
    receipt = {
        "schema": "ospt.vulnhunter-dependency-prep.v1",
        "status": "PASS" if destination_ok else "KICKBACK",
        "prepared_at": now_z(),
        "provider_invoked": False,
        "attempt_index": 1,
        "target_root": str((workspace / "runtime-target").resolve()),
        "npm": {
            "path": str(NPM_RUNTIME_PATH),
            "sha256": sha_file(NPM_RUNTIME_PATH),
            "version": node_runtime()["npm_version"],
            "argv": [],
            "strategy": "verified-local-postimage-reuse",
            "verification_exit_code": 0,
        },
        "node": node_runtime(),
        "npm_exit_code": 0,
        "node_modules_file_count": len(destination_manifest),
        "node_modules_manifest_sha256": manifest_digest(destination_manifest),
        "git_config_sha256": sha_file(paths["git_config"]),
        "source_run": "VH-JS-FULL-001-A2",
        "source_dependency_receipt_sha256": sha_file(source_receipt_path),
        "source_runtime_manifest_sha256": manifest_digest(source_runtime_manifest),
        "destination_runtime_manifest_sha256": manifest_digest(destination_runtime_manifest),
        "immutable_source_unchanged": True,
        "runtime_target_first_party_unchanged": destination_ok,
        "defects": destination_defects,
        "claim_ceiling": "Provider-free reuse of a hash-bound local dependency/build postimage; no provider, scan, finding or runtime-containment claim.",
    }
    write_create_once(paths["dependency_receipt"], canonical_bytes(receipt))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 2


def command_recover_dependencies(args: argparse.Namespace) -> int:
    """Finish receipt creation after a proven install and controller-only hash refusal."""
    workspace = args.workspace.resolve()
    prepared = inspect_prepared_workspace(workspace)
    paths = recovery.runtime_paths(workspace)
    receipt_path = paths["dependency_receipt"]
    node_modules = workspace / "runtime-target/node_modules"
    if receipt_path.exists():
        raise Refusal("dependency receipt already exists; recovery is not applicable")
    archived = sorted(paths["root"].glob("DEPENDENCY_PREP_ATTEMPT_*.json"))
    if len(archived) != MAX_DEPENDENCY_ATTEMPTS - 1:
        raise Refusal("recovery requires the exact exhausted provider-free retry history")
    if not node_modules.is_dir():
        raise Refusal("completed dependency tree is absent")
    stdout_path = paths["root"] / "npm-prep.stdout.log"
    stderr_path = paths["root"] / "npm-prep.stderr.log"
    if not stdout_path.is_file() or not stderr_path.is_file():
        raise Refusal("completed install logs are absent")
    debug_logs = sorted((paths["npm_cache"] / "_logs").glob("*-debug-0.log"))
    debug_evidence = []
    successful_node22_log = False
    for path in debug_logs:
        text = path.read_text(errors="replace")
        exit_zero = "verbose exit 0" in text and "info ok" in text
        node22 = "verbose node v22." in text
        successful_node22_log = successful_node22_log or (exit_zero and node22)
        debug_evidence.append(
            {
                "path": str(path),
                "sha256": sha_file(path),
                "exit_zero": exit_zero,
                "node22": node22,
            }
        )
    if not successful_node22_log:
        raise Refusal("npm debug evidence does not prove a successful Node 22 install")
    env = runtime_environment(workspace)
    runtime = node_runtime()
    verify_argv = [str(NPM_RUNTIME_PATH), "ls", "--depth=0", "--json"]
    verified = subprocess.run(
        verify_argv,
        cwd=workspace / "runtime-target",
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
    )
    verify_stdout = paths["root"] / "npm-ls.stdout.json"
    verify_stderr = paths["root"] / "npm-ls.stderr.log"
    write_create_once(verify_stdout, verified.stdout.encode())
    write_create_once(verify_stderr, verified.stderr.encode())
    if verified.returncode != 0:
        raise Refusal("npm ls rejected the recovered dependency tree")
    try:
        npm_ls = json.loads(verified.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal("npm ls recovery evidence is not JSON") from exc
    if npm_ls.get("name") != "juice-shop" or npm_ls.get("version") != "17.1.1":
        raise Refusal("npm ls recovery evidence does not identify pinned Juice Shop")
    source_unchanged, source_defects = recovery.verify_source_postimage(
        workspace / "target", prepared["target"]["manifest"]
    )
    runtime_unchanged, runtime_defects = verify_pinned_members(
        workspace / "runtime-target", prepared["target"]["manifest"]
    )
    if not source_unchanged or not runtime_unchanged:
        raise Refusal("dependency recovery found first-party source drift")
    node_manifest = runtime_dependency_manifest(node_modules)
    if not node_manifest:
        raise Refusal("recovered dependency manifest is empty")
    receipt = {
        "schema": "ospt.vulnhunter-dependency-prep.v1",
        "status": "PASS",
        "prepared_at": now_z(),
        "provider_invoked": False,
        "attempt_index": MAX_DEPENDENCY_ATTEMPTS,
        "recovered_controller_postprocessing": True,
        "target_root": str((workspace / "runtime-target").resolve()),
        "npm": {
            "path": str(NPM_RUNTIME_PATH),
            "sha256": sha_file(NPM_RUNTIME_PATH),
            "version": runtime["npm_version"],
            "argv": [
                str(NPM_RUNTIME_PATH),
                "install",
                "--no-package-lock",
                "--no-audit",
                "--no-fund",
            ],
            "strategy": "npm-install-without-lockfile-write",
            "verification_argv": verify_argv,
            "verification_exit_code": verified.returncode,
        },
        "node": runtime,
        "npm_exit_code": 0,
        "node_modules_file_count": len(node_manifest),
        "node_modules_manifest_sha256": manifest_digest(node_manifest),
        "git_config_sha256": sha_file(paths["git_config"]),
        "stdout_sha256": sha_file(stdout_path),
        "stderr_sha256": sha_file(stderr_path),
        "npm_ls_stdout_sha256": sha_file(verify_stdout),
        "npm_ls_stderr_sha256": sha_file(verify_stderr),
        "npm_debug_evidence": debug_evidence,
        "immutable_source_unchanged": source_unchanged,
        "runtime_target_first_party_unchanged": runtime_unchanged,
        "defects": source_defects + runtime_defects,
        "claim_ceiling": "Provider-free recovery of a completed dependency postimage only; no scan, finding, or runtime safety claim.",
    }
    write_create_once(receipt_path, canonical_bytes(receipt))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def command_rehearse(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    evidence = prepare_workspace(args.study_root.resolve(), workspace)
    plan = {
        "schema": "ospt.full-vulnhunter-rehearsal.v1",
        "rehearsed_at": now_z(),
        "status": "PASS" if evidence["auth"].get("loggedIn") else "READY_EXCEPT_AUTH",
        "provider_invoked": False,
        "source_transferred_outside_host": False,
        "spend_usd": 0.0,
        "full_target_file_count": evidence["target"]["file_count"],
        "target_commit": TARGET_COMMIT,
        "tool_commit": TOOL_COMMIT,
        "installed_skill": evidence["installed_skill"],
        "sandbox_settings_sha256": evidence["settings_sha256"],
        "auth": evidence["auth"],
        "next": "Prepare dependencies, accept exact workspace trust, then render and sign a fresh exact scope.",
        "claim_ceiling": "Spend-free launch-path rehearsal only; no model, scan, finding, value, or deployment claim.",
    }
    write_create_once(args.receipt.resolve(), canonical_bytes(plan))
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


def command_target_preflight(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    prepared = inspect_prepared_workspace(workspace)
    service: TargetService | None = None
    try:
        service = start_target_service(workspace)
        sandbox_prefix = target_service_argv(workspace)[:-2]
        local_probe = subprocess.run(
            sandbox_prefix
            + [
                str(NODE_RUNTIME_PATH),
                "-e",
                f"fetch('{TARGET_HEALTH_URL}').then(r=>process.exit(r.status===200?0:8)).catch(()=>process.exit(9))",
            ],
            cwd=workspace / "runtime-target",
            env=target_service_environment(workspace),
            capture_output=True,
            timeout=15,
        )
        external_probe = subprocess.run(
            sandbox_prefix
            + [
                str(NODE_RUNTIME_PATH),
                "-e",
                "fetch('https://www.alchemy.com/').then(()=>process.exit(9)).catch(()=>process.exit(0))",
            ],
            cwd=workspace / "runtime-target",
            env=target_service_environment(workspace),
            capture_output=True,
            timeout=15,
        )
        if local_probe.returncode != 0:
            raise Refusal("target sandbox did not permit the signed loopback consumer")
        if external_probe.returncode != 0:
            raise Refusal("target sandbox did not bite on a non-loopback outbound attempt")
        healthy, health_detail = target_health()
        if not healthy:
            raise Refusal(f"target lost health during preflight: {health_detail}")
        service_result = stop_target_service(service)
        service = None
        source_unchanged, source_defects = recovery.verify_source_postimage(
            workspace / "target", prepared["target"]["manifest"]
        )
        runtime_unchanged, runtime_defects = verify_pinned_members(
            workspace / "runtime-target", prepared["target"]["manifest"]
        )
        receipt = {
            "schema": "ospt.vulnhunter-target-preflight.v1",
            "status": "PASS" if source_unchanged and runtime_unchanged else "KICKBACK",
            "tested_at": now_z(),
            "provider_invoked": False,
            "spend_usd": 0.0,
            "target_service": {
                "health_url": TARGET_HEALTH_URL,
                "command_argv": target_service_argv(workspace),
                "sandbox_profile_sha256": sha_bytes(TARGET_SANDBOX_PROFILE.encode()),
                "local_probe_exit": local_probe.returncode,
                "external_denied_probe_exit": external_probe.returncode,
                "teardown": service_result,
            },
            "source_unchanged": source_unchanged,
            "runtime_first_party_unchanged": runtime_unchanged,
            "defects": source_defects + runtime_defects,
            "claim_ceiling": "Provider-free target start, loopback health, non-loopback denial and teardown only; no model, scan, finding or full-run claim.",
        }
        write_create_once(args.out.resolve(), canonical_bytes(receipt))
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0 if receipt["status"] == "PASS" else 2
    finally:
        if service is not None:
            stop_target_service(service)


def command_scope(args: argparse.Namespace) -> int:
    scope = build_scope(str(args.workspace.resolve()), args.expires, args.max_cost, args.max_seconds)
    write_create_once(args.out.resolve(), canonical_bytes(scope))
    print(json.dumps({"scope": str(args.out.resolve()), "sha256": sha_file(args.out.resolve())}, indent=2))
    return 0


def command_run(args: argparse.Namespace) -> int:
    scope = verify_scope(args.scope.resolve(), args.signature.resolve(), args.allowed_signers.resolve())
    workspace = Path(scope["target"]["workspace_root"]).resolve()
    if args.run_dir.resolve() != Path(scope["target"]["evidence_root"]).resolve():
        raise Refusal("run evidence directory differs from signed scope")
    attempt_marker = Path(scope["target"]["attempt_marker"]).resolve()
    if attempt_marker != ATTEMPT_MARKER_PATH.resolve():
        raise Refusal("attempt marker differs from the fixed global marker")
    current_auth = auth_status()
    if not current_auth.get("loggedIn"):
        raise Refusal("Claude Code is not authenticated; scope remains unconsumed")
    if attempt_marker.exists():
        raise Refusal("the global one-attempt marker already exists")
    if not workspace.is_dir():
        raise Refusal("signed prepared workspace is absent; scope remains unconsumed")
    if args.run_dir.resolve().exists():
        raise Refusal("signed evidence destination already exists; scope remains unconsumed")
    enforcement = args.run_dir.resolve() / "ENFORCEMENT.jsonl"
    operational = args.run_dir.resolve() / "OPERATIONAL.jsonl"
    evidence_log = args.run_dir.resolve() / "EVIDENCE_DECISION.jsonl"
    preparation_started_at = now_z()
    process: SuspendedProcess | None = None
    service: TargetService | None = None
    prior_signal_handlers = {
        signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGHUP)
    }

    def controlled_termination(signum: int, _frame: Any) -> None:
        raise TerminationRequested(f"received signal {signum}")

    for signum in prior_signal_handlers:
        signal.signal(signum, controlled_termination)
    try:
        if args.study_root.resolve() != STUDY_ROOT.resolve():
            raise Refusal("Study source-control root differs from the frozen controller contract")
        prepared = inspect_prepared_workspace(workspace)
        raw_log = args.run_dir.resolve() / "raw-event-log.jsonl"
        stderr_path = args.run_dir.resolve() / "claude-stderr.log"
        prompt = scope["prompt"]
        argv = claude_argv(scope, prompt)
        prompt_sha256 = sha_bytes(prompt.encode())
        command_argv_sha256 = sha_bytes(canonical_bytes(argv))
        binding = VerifiedBinding(
            scope_path=str(args.scope.resolve()),
            signature_path=str(args.signature.resolve()),
            allowed_signers_path=str(args.allowed_signers.resolve()),
            provenance="signed-live-controller",
        )
        preconsume_env = runtime_environment(workspace)
        preconsume_defects = recovery.validate_runtime_plan(workspace, preconsume_env, argv)
        preconsume_defects.extend(validate_node_runtime_plan(preconsume_env))
        if preconsume_defects:
            raise Refusal(
                "pre-consumption runtime plan differs from signed scope: "
                + "; ".join(preconsume_defects)
            )
        service = start_target_service(workspace)
        args.run_dir.resolve().mkdir(parents=True, exist_ok=False)
        append_jsonl(
            enforcement,
            {
                "event": "ACTION_PROPOSED",
                "event_time": preparation_started_at,
                "run_id": RUN_ID,
                "scope_sha256": sha_file(args.scope.resolve()),
                "action": "complete upstream /vulnhunt against full pinned Juice Shop",
            },
        )
        append_jsonl(
            operational,
            {
                "event": "PREPARATION_STARTED",
                "event_time": preparation_started_at,
                "run_id": RUN_ID,
                "provider_invoked": False,
            },
        )
        append_jsonl(
            evidence_log,
            {
                "event": "SCOPE_VERIFIED_PENDING_CONSUMPTION",
                "event_time": preparation_started_at,
                "transaction_time": now_z(),
                "effective_time": None,
                "run_id": RUN_ID,
                "decision": "PENDING_HUMAN",
            },
        )
        append_jsonl(
            operational,
            {
                "event": "PREPARATION_COMPLETED",
                "event_time": now_z(),
                "run_id": RUN_ID,
                "provider_invoked": False,
                "target_file_count": prepared["target"]["file_count"],
                "target_manifest_sha256": prepared["target"]["manifest_sha256"],
                "skill_manifest_sha256": prepared["installed_skill"]["manifest_sha256"],
                "settings_sha256": prepared["settings_sha256"],
            },
        )
        append_jsonl(
            enforcement,
            {
                "event": "TARGET_START_PROPOSED",
                "event_time": preparation_started_at,
                "run_id": RUN_ID,
                "action": "start controller-owned pinned Juice Shop service",
                "policy": scope["target_service"],
            },
        )
        append_jsonl(
            enforcement,
            {
                "event": "TARGET_START_ALLOWED",
                "event_time": now_z(),
                "run_id": RUN_ID,
                "reason": "pinned command, loopback health and non-loopback deny profile matched the signed scope",
                "pid": service.process.pid,
            },
        )
        append_jsonl(
            operational,
            {
                "event": "TARGET_HEALTHY",
                "event_time": now_z(),
                "run_id": RUN_ID,
                "health_url": TARGET_HEALTH_URL,
                "pid": service.process.pid,
                "provider_invoked": False,
            },
        )
        write_create_once(
            attempt_marker,
            canonical_bytes(
                {
                    "run_id": RUN_ID,
                    "scope_sha256": sha_file(args.scope.resolve()),
                    "consumed_at": now_z(),
                    "workspace": str(workspace),
                }
            ),
        )
        append_jsonl(
            enforcement,
            {
                "event": "ACTION_ALLOWED",
                "event_time": now_z(),
                "run_id": RUN_ID,
                "identity": OWNER_IDENTITY,
                "namespace": APPROVAL_NAMESPACE,
                "reason": "detached signature and fixed trust root verified; exact one-attempt scope consumed",
            },
        )
        started = time.monotonic()
        timed_out = False
        monitor: dict[str, Any] = {}
        with raw_log.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            with child_environment(workspace) as runtime_env:
                runtime_plan_defects = recovery.validate_runtime_plan(
                    workspace, runtime_env, argv
                )
                runtime_plan_defects.extend(validate_node_runtime_plan(runtime_env))
                if runtime_plan_defects:
                    raise Refusal(
                        "runtime environment differs from signed plan: "
                        + "; ".join(runtime_plan_defects)
                    )
                process, executable_identity = spawn_verified_executable(
                    Path(scope["runtime"]["executable"]),
                    argv,
                    workspace,
                    stdout_handle.fileno(),
                    stderr_handle.fileno(),
                    scope["runtime"]["executable_sha256"],
                    scope["runtime"]["code_identity"],
                )
            append_jsonl(
                enforcement,
                {
                    "event": "EXECUTION_IDENTITY_VERIFIED",
                    "event_time": now_z(),
                    "run_id": RUN_ID,
                    "runtime": executable_identity,
                    "reason": "child held suspended until its kernel text-vnode and code-directory identity matched the signed executable",
                },
            )
            append_jsonl(
                operational,
                {
                    "event": "RUN_STARTED",
                    "event_time": now_z(),
                    "run_id": RUN_ID,
                    "budgets": scope["budgets"],
                    "auth_method": prepared["auth"].get("authMethod"),
                },
            )
            process.resume()
            append_jsonl(
                enforcement,
                {
                    "event": "ACTION_EXECUTED",
                    "event_time": now_z(),
                    "run_id": RUN_ID,
                    "argv": argv[:-1] + ["<scope-bound-prompt>"],
                    "prompt_sha256": prompt_sha256,
                    "command_argv_sha256": command_argv_sha256,
                    "runtime": executable_identity,
                },
            )
            exit_code, monitor = monitor_provider(
                process,
                service,
                raw_log,
                workspace / "results",
                operational,
                scope["budgets"],
            )
            timed_out = monitor.get("stop_reason") == "absolute emergency watchdog reached"
        elapsed = time.monotonic() - started
        service_result = stop_target_service(service)
        service = None
        service_evidence = args.run_dir.resolve() / "target-service.log"
        shutil.copy2(Path(service_result["log_path"]), service_evidence)
        service_result["evidence_path"] = str(service_evidence)
        service_result["evidence_sha256"] = sha_file(service_evidence)
        sidecar_evidence = capture_runtime_sidecars(workspace, args.run_dir.resolve())
        append_jsonl(
            operational,
            {
                "event": "TARGET_STOPPED",
                "event_time": now_z(),
                "run_id": RUN_ID,
                "target_service": service_result,
                "runtime_sidecars": sidecar_evidence,
            },
        )
        runtime = raw_runtime_summary(raw_log)
        append_jsonl(
            operational,
            {
                "event": "RUN_STOPPED",
                "event_time": now_z(),
                "run_id": RUN_ID,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "elapsed_seconds": elapsed,
                "monitor": monitor,
                "raw_event_log_bytes": raw_log.stat().st_size,
                "provider_runtime": runtime,
            },
        )
        source_unchanged, source_defects = recovery.verify_source_postimage(
            workspace / "target", prepared["target"]["manifest"]
        )
        runtime_source_unchanged, runtime_source_defects = verify_pinned_members(
            workspace / "runtime-target", prepared["target"]["manifest"]
        )
        try:
            installed_after = directory_manifest(workspace / ".claude/skills/vulnhunt")
            skill_unchanged = prepared["installed_skill"]["manifest"] == installed_after
        except Refusal:
            skill_unchanged = False
        settings_unchanged = (
            sha_file(workspace / ".claude/settings.json") == prepared["settings_sha256"]
        )
        explicit_settings_unchanged = (
            sha_file(recovery.runtime_paths(workspace)["settings"])
            == prepared["settings_sha256"]
        )
        validation = validate_native_results(
            workspace / "results", raw_log, binding, stderr_path=stderr_path
        )
        validation["source_manifest_unchanged"] = source_unchanged
        validation["runtime_target_first_party_unchanged"] = runtime_source_unchanged
        validation["installed_skill_unchanged"] = skill_unchanged
        validation["settings_unchanged"] = settings_unchanged
        validation["explicit_settings_unchanged"] = explicit_settings_unchanged
        validation["runtime_summary"] = runtime
        validation["target_service"] = service_result
        validation["runtime_sidecars"] = sidecar_evidence
        validation["sandbox_claim"] = (
            "The provider Bash sandbox was restricted to bound workspace paths and loopback. "
            "The controller separately owned the target PID, health checks, non-loopback deny "
            "profile, log and teardown; settings and source postimages were checked."
        )
        for defect in source_defects:
            validation["defects"].append(defect)
        for defect in runtime_source_defects:
            validation["defects"].append(defect)
        if exit_code != 0:
            validation["defects"].append(f"Claude process exited nonzero: {exit_code}")
        if not source_unchanged:
            validation["defects"].append("original full-source manifest changed during run")
        if not runtime_source_unchanged:
            validation["defects"].append("runtime/test copy changed a pinned first-party source member")
        if not skill_unchanged:
            validation["defects"].append("project-local upstream skill changed during run")
        if not settings_unchanged:
            validation["defects"].append("project-local safety settings changed during run")
        if not explicit_settings_unchanged:
            validation["defects"].append("explicit runtime safety settings changed during run")
        if validation["defects"]:
            validation["status"] = "KICKBACK"
            validation["actual_consumer_observed"] = False
        write_create_once(args.run_dir.resolve() / "native-validation.json", canonical_bytes(validation))
        append_jsonl(
            evidence_log,
            {
                "event": "RAW_OUTPUT_PRESERVED",
                "event_time": now_z(),
                "run_id": RUN_ID,
                "raw_event_log_sha256": sha_file(raw_log),
                "results_path": str(workspace / "results"),
                "results_manifest_sha256": validation["results_manifest_sha256"],
            },
        )
        append_jsonl(
            evidence_log,
            {
                "event": "ACTIVATION_NOT_AUTHORIZED",
                "event_time": now_z(),
                "transaction_time": now_z(),
                "effective_time": None,
                "run_id": RUN_ID,
                "decision": "PENDING_HUMAN",
                "validation_status": validation["status"],
            },
        )
        return 0 if exit_code == 0 and validation["status"] == "PASS" else 2
    except BaseException as exc:
        if process is not None and process.poll() is None:
            try:
                terminate_process_group(process, operational, "controller exception or interruption")
            except Exception as termination_exc:
                append_jsonl(
                    operational,
                    {
                        "event": "TERMINATION_FAILED",
                        "event_time": now_z(),
                        "run_id": RUN_ID,
                        "error": str(termination_exc),
                    },
                )
        if args.run_dir.resolve().is_dir():
            record_terminal_failure(
                enforcement,
                operational,
                evidence_log,
                error=f"{type(exc).__name__}: {exc}",
                scope_consumed=attempt_marker.exists(),
            )
        raise
    finally:
        if service is not None:
            try:
                service_result = stop_target_service(service)
                if args.run_dir.resolve().is_dir() and Path(service_result["log_path"]).is_file():
                    destination = args.run_dir.resolve() / "target-service-aborted.log"
                    if not destination.exists():
                        shutil.copy2(Path(service_result["log_path"]), destination)
            except Exception:
                pass
        for signum, handler in prior_signal_handlers.items():
            signal.signal(signum, handler)


def command_validate(args: argparse.Namespace) -> int:
    authority = (args.scope, args.signature, args.allowed_signers)
    if any(authority) and not all(authority):
        raise Refusal("signed replay requires scope, signature, and allowed-signers together")
    binding = None
    if all(authority):
        binding = reconstruct_replay_binding(
            args.scope.resolve(),
            args.signature.resolve(),
            args.allowed_signers.resolve(),
            args.results.resolve(),
            args.raw_log.resolve(),
        )
    report = validate_native_results(
        args.results.resolve(),
        args.raw_log.resolve(),
        binding,
        stderr_path=args.stderr.resolve() if args.stderr else None,
    )
    if args.out:
        write_create_once(args.out.resolve(), canonical_bytes(report))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--study-root", type=Path, required=True)
    prepare.add_argument("--workspace", type=Path, required=True)
    prepare.set_defaults(func=command_prepare)
    refresh_settings = sub.add_parser("refresh-settings")
    refresh_settings.add_argument("--workspace", type=Path, required=True)
    refresh_settings.set_defaults(func=command_refresh_settings)
    dependencies = sub.add_parser("dependencies")
    dependencies.add_argument("--workspace", type=Path, required=True)
    dependencies.add_argument("--max-seconds", type=int, default=1800)
    dependencies.add_argument("--retry-after-kickback", action="store_true")
    dependencies.set_defaults(func=command_dependencies)
    reuse_dependencies = sub.add_parser("reuse-dependencies")
    reuse_dependencies.add_argument("--workspace", type=Path, required=True)
    reuse_dependencies.add_argument("--from-workspace", type=Path, required=True)
    reuse_dependencies.set_defaults(func=command_reuse_dependencies)
    recover_dependencies = sub.add_parser("recover-dependencies")
    recover_dependencies.add_argument("--workspace", type=Path, required=True)
    recover_dependencies.set_defaults(func=command_recover_dependencies)
    rehearse = sub.add_parser("rehearse")
    rehearse.add_argument("--study-root", type=Path, required=True)
    rehearse.add_argument("--workspace", type=Path, required=True)
    rehearse.add_argument("--live-workspace", type=Path, required=True)
    rehearse.add_argument("--receipt", type=Path, required=True)
    rehearse.add_argument("--expires", required=True)
    rehearse.add_argument("--max-cost", type=float, default=120.0)
    rehearse.add_argument("--max-seconds", type=int, default=21600)
    rehearse.set_defaults(func=command_rehearse)
    target_preflight = sub.add_parser("target-preflight")
    target_preflight.add_argument("--workspace", type=Path, required=True)
    target_preflight.add_argument("--out", type=Path, required=True)
    target_preflight.set_defaults(func=command_target_preflight)
    scope = sub.add_parser("scope")
    scope.add_argument("--workspace", type=Path, required=True)
    scope.add_argument("--out", type=Path, required=True)
    scope.add_argument("--expires", required=True)
    scope.add_argument("--max-cost", type=float, default=120.0)
    scope.add_argument("--max-seconds", type=int, default=21600)
    scope.set_defaults(func=command_scope)
    run = sub.add_parser("run")
    run.add_argument("--study-root", type=Path, required=True)
    run.add_argument("--scope", type=Path, required=True)
    run.add_argument("--signature", type=Path, required=True)
    run.add_argument("--allowed-signers", type=Path, required=True)
    run.add_argument("--run-dir", type=Path, required=True)
    run.set_defaults(func=command_run)
    validate = sub.add_parser("validate")
    validate.add_argument("--results", type=Path, required=True)
    validate.add_argument("--raw-log", type=Path, required=True)
    validate.add_argument("--stderr", type=Path)
    validate.add_argument("--scope", type=Path)
    validate.add_argument("--signature", type=Path)
    validate.add_argument("--allowed-signers", type=Path)
    validate.add_argument("--out", type=Path)
    validate.set_defaults(func=command_validate)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.func(args))
    except Refusal as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
