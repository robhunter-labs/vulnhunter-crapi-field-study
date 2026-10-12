#!/usr/bin/env python3
"""Run one signed completion-grade VulnHunter canary against pinned OWASP crAPI.

This is a target adapter over the repaired A4 execution engine.  It keeps
the engine's owner signature, one-attempt, model identity, raw capture,
three-plane logging, monitor, postimage, and native-output gates.  This file
owns only the crAPI source contract, sealed Docker lifecycle, hidden evaluator,
prompt, readiness, and scope.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from typing import Any


STUDY_ROOT = Path("/path/to/local-study-workspace")
OSPT_ROOT = STUDY_ROOT / "OSPT"
A4_ROOT = OSPT_ROOT / "build/vulnhunter-juice-shop-full-run-completion-attempt-4"
A4_CONTROLLER = A4_ROOT / "full_vulnhunt_a4.py"
A4_CONTROLLER_SHA256 = "sha256:4befbd4897dbd4e157d7b6ace048e01b5c0e92de62e0b9b662efcf4b97f3fadc"
QUALIFICATION_ROOT = OSPT_ROOT / "build/vulnhunter-crapi-challenger-attempt-1/runtime-qualification"
sys.path.insert(0, str(A4_ROOT))
sys.path.insert(0, str(QUALIFICATION_ROOT))

import full_vulnhunt_a4 as engine  # noqa: E402
import crapi_runtime_qualifier as qualifier  # noqa: E402


SCHEMA = "ospt.full-vulnhunter-crapi-run.v2"
RUN_ID = "VH-CRAPI-FULL-001-A2"
TARGET_SOURCE_ID = "owasp-crapi-v1.1.6"
TARGET_COMMIT = "700f03d12a392d9e408260b4beae72ed02a4a1a4"
TARGET_TREE = "2792786e48320f7923de56a1024b19537091ff34"
TARGET_EXPORT_FILE_COUNT = 1022
TARGET_SOURCE_TRACKED_FILE_COUNT = 1041
TARGET_MANIFEST_SHA256 = "sha256:55938846701d70989098980cd548be59f9a64c20a0d7acbbb6b7b9ad82ac8a5f"
TARGET_SOURCE_TRACKED_MANIFEST_SHA256 = "sha256:3eaaa608e275e4c71341c8a8be5beafd5919a3b9b05c48cb15b508cf89454ad7"
MAX_COST_USD = 180.0
MAX_SECONDS = 8 * 60 * 60
NO_PROGRESS_SECONDS = 30 * 60
MAX_SCOPE_LIFETIME_SECONDS = 48 * 60 * 60
TARGET_HEALTH_URL = "http://127.0.0.1:8888/health"
TARGET_WEB_URL = "http://127.0.0.1:8888/"
LIVE_WORKSPACE_PATH = Path("/private/tmp/ospt-vulnhunter-crapi/VH-CRAPI-FULL-001-A2/workspace")
LIVE_EVIDENCE_PATH = OSPT_ROOT / "workbench/vulnhunter-crapi-full/VH-CRAPI-FULL-001-A2/evidence"
TARGET_CONTROL_EVIDENCE = OSPT_ROOT / "workbench/vulnhunter-crapi-full/VH-CRAPI-FULL-001-A2/control/target-runtime"
ATTEMPT_MARKER_PATH = OSPT_ROOT / "workbench/vulnhunter-crapi-full/VH-CRAPI-FULL-001-A2/control/attempt-consumed.json"
CONTROLLER_DEPLOY_PATH = OSPT_ROOT / "build/vulnhunter-crapi-challenger-attempt-2/full_vulnhunt_crapi_a2.py"
SCOPE_PATH = OSPT_ROOT / "build/vulnhunter-crapi-challenger-attempt-2/FULL_WORKFLOW_OWNER_SCOPE_CRAPI_A2.json"
HIDDEN_EVALUATOR_ROOT = Path("/private/tmp/ospt-crapi-hidden-evaluator")
HIDDEN_EVALUATOR_ALIASES = (HIDDEN_EVALUATOR_ROOT, Path("/tmp/ospt-crapi-hidden-evaluator"))
PREPARATION_RECEIPT_NAME = "PREPARATION_CRAPI.json"
OWNER_IDENTITY = engine.OWNER_IDENTITY
APPROVAL_NAMESPACE = engine.APPROVAL_NAMESPACE
ALLOWED_SIGNERS_PATH = engine.ALLOWED_SIGNERS_PATH
ALLOWED_SIGNERS_SHA256 = engine.ALLOWED_SIGNERS_SHA256
CLAUDE_CONFIG_PATH = engine.CLAUDE_CONFIG_PATH
CLAUDE_TASK_OUTPUT_LINK_CONTRACT = (
    "Claude runtime tmp tasks/<task>.output -> project "
    "subagents/agent-<task>.jsonl only; captured as inert JSON without dereference"
)


Refusal = engine.Refusal
ORIGINAL_APPEND_JSONL = engine.append_jsonl
ORIGINAL_WRITE_CREATE_ONCE = engine.write_create_once


def replace_stale_labels(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: replace_stale_labels(item) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_stale_labels(item) for item in value]
    if isinstance(value, str):
        return (
            value.replace("full pinned Juice Shop", "full pinned crAPI")
            .replace("pinned Juice Shop service", "pinned crAPI service set")
            .replace("target PID, health checks, non-loopback deny profile", "target runtime, tunnel health checks, internal network and zero-published-port boundary")
        )
    return value


def append_jsonl(path: Path, event: dict[str, Any]) -> None:
    ORIGINAL_APPEND_JSONL(path, replace_stale_labels(event))


def write_create_once(path: Path, data: bytes) -> None:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        ORIGINAL_WRITE_CREATE_ONCE(path, data)
        return
    ORIGINAL_WRITE_CREATE_ONCE(path, engine.canonical_bytes(replace_stale_labels(value)))


def qualification_bindings() -> dict[str, Any]:
    files = {
        "runtime_qualifier": "crapi_runtime_qualifier.py",
        "image_lock": "IMAGE_LOCK.json",
        "runtime_override": "COMPOSE_IMPORTED.override.yml",
        "registry_override": "COMPOSE_PINNED.override.yml",
        "safe_environment": "SAFE_RUNTIME.env",
        "public_evaluator_contract": "EVALUATOR_PUBLIC_CONTRACT.json",
        "oci_import_receipt": "evidence/oci-import/OCI_IMPORT_ALL.json",
        "provider_free_qualification": "evidence/runtime/attempt-4/QUALIFICATION_RECEIPT.json",
        "provider_free_runtime": "evidence/runtime/attempt-4/RUNTIME_INSPECTION.json",
        "provider_free_teardown": "evidence/runtime/attempt-4/TEARDOWN_RECEIPT.json",
        "buildworks_done": "DOD_RECEIPT.json",
    }
    result: dict[str, Any] = {}
    for name, relative in files.items():
        path = QUALIFICATION_ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise Refusal(f"qualification binding missing: {relative}")
        result[name] = {"path": str(path), "sha256": engine.sha_file(path)}
    receipt = engine.load_json(QUALIFICATION_ROOT / "evidence/runtime/attempt-4/QUALIFICATION_RECEIPT.json")
    done = engine.load_json(QUALIFICATION_ROOT / "DOD_RECEIPT.json")
    if receipt.get("status") != "PASS" or receipt.get("provider_invoked") is not False:
        raise Refusal("provider-free qualification receipt is not GREEN")
    if done.get("loop", {}).get("disposition") != "PASS" or done.get("authority", {}).get("deployment_authorized") is not False:
        raise Refusal("BuildWorks runtime close receipt is not bounded PASS")
    return result


def project_settings(workspace: Path = LIVE_WORKSPACE_PATH) -> dict[str, Any]:
    target = workspace / "target"
    runtime_target = workspace / "runtime-target"
    results = workspace / "results"
    skill = workspace / ".claude/skills/vulnhunt"
    runtime = engine.recovery.runtime_paths(workspace)
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
                *[f"Read({path}/**)" for path in HIDDEN_EVALUATOR_ALIASES],
                "Edit(/path/to/local-home/**)",
                *[f"Edit({path}/**)" for path in HIDDEN_EVALUATOR_ALIASES],
                f"Edit({target}/**)",
                f"Edit({runtime_target}/**)",
                f"Edit({skill}/**)",
                f"Edit({workspace}/.claude/**)",
                "Bash(git push*)",
                "Bash(docker *)",
                "Bash(docker-compose *)",
                "Bash(colima *)",
                "Bash(ssh *)",
                "Bash(scp *)",
                "Bash(*8025*)",
            ],
        },
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "filesystem": {
                "denyRead": ["/path/to/local-home", *[str(path) for path in HIDDEN_EVALUATOR_ALIASES]],
                "denyWrite": ["/path/to/local-home", *[str(path) for path in HIDDEN_EVALUATOR_ALIASES]],
                "allowWrite": [
                    str(runtime_target),
                    str(results),
                    str(runtime["npm_cache"]),
                    str(runtime["tmp"]),
                ],
            },
            "network": {"allowedDomains": ["localhost", "127.0.0.1"], "allowLocalBinding": True},
        },
    }


def prompt_for(target: Path, runtime_target: Path, results: Path) -> str:
    return f"""/vulnhunt

Pre-resolved scan metadata
VULNHUNT_DIR: {results}
VULNHUNT_BRANCH: v1.1.6 [{TARGET_COMMIT[:7]}]
Repository URL: https://github.com/OWASP/crAPI.git
Bash: AVAILABLE
Controller-owned target service: {TARGET_WEB_URL}

Immutable source directory: {target}
Writable runtime/test copy: {runtime_target}

Run the complete unchanged upstream VulnHunter workflow against the full immutable source export. Follow every documented phase, use the required subagents, and write native phase outputs, PoCs, exploit tests, sweep, and final report into VULNHUNT_DIR. The exact multi-service target is already running behind the controller-owned loopback URL; use only that URL for dynamic tests and do not start, stop, rebuild, inspect, or replace its containers or tunnel. Read and analyze first-party source from the immutable source directory. Run Bash, PoCs, local scripts, and local loopback requests only inside the writable runtime/test copy. Never write to the immutable source directory. Do not use benchmark labels, an answer key, prior findings, seeded identities, or earlier run output. Do not enumerate unrelated localhost services. Do not access external targets or install/download anything. Stop if the installed /vulnhunt skill or any phase file differs from the pinned project-local copy.
"""


def prepare_workspace(study_root: Path, workspace: Path) -> dict[str, Any]:
    if study_root.resolve() != STUDY_ROOT.resolve():
        raise Refusal("Study root differs from the frozen controller contract")
    workspace.mkdir(parents=True, exist_ok=False)
    target_export = engine.export_source(study_root, TARGET_SOURCE_ID, workspace / "target")
    tool_export = engine.export_source(study_root, engine.TOOL_SOURCE_ID, workspace / "tool")
    target = engine.verify_export(workspace / "target", TARGET_SOURCE_ID, TARGET_COMMIT, TARGET_EXPORT_FILE_COUNT)
    tool = engine.verify_export(workspace / "tool", engine.TOOL_SOURCE_ID, engine.TOOL_COMMIT, engine.TOOL_FILE_COUNT)
    if target["manifest_sha256"] != TARGET_MANIFEST_SHA256:
        raise Refusal("target export differs from the pinned crAPI denominator")
    if tool["manifest_sha256"] != engine.TOOL_MANIFEST_SHA256:
        raise Refusal("tool export differs from the pinned VulnHunter denominator")
    installed = engine.install_skill(workspace / "tool", workspace)
    if installed["manifest_sha256"] != engine.SKILL_MANIFEST_SHA256:
        raise Refusal("installed VulnHunter skill differs from its pin")
    runtime_target = workspace / "runtime-target"
    shutil.copytree(workspace / "target", runtime_target)
    runtime_manifest = engine.directory_manifest(runtime_target, exclude={".STUDY_SOURCE_EXPORT.json"})
    if runtime_manifest != target["manifest"]:
        raise Refusal("runtime/test copy differs from the target preimage")
    (workspace / "results").mkdir()
    paths = engine.recovery.runtime_paths(workspace)
    for directory in (paths["root"], paths["npm_cache"], paths["tmp"]):
        directory.mkdir(parents=True, exist_ok=True)
    paths["git_config"].write_text(engine.recovery.git_config_text(), encoding="utf-8")
    settings_bytes = engine.canonical_bytes(project_settings(workspace))
    settings_path = workspace / ".claude/settings.json"
    settings_path.write_bytes(settings_bytes)
    paths["settings"].write_bytes(settings_bytes)
    prepared = {
        "schema": "ospt.full-vulnhunter-crapi-preparation.v1",
        "prepared_at": engine.now_z(),
        "provider_invoked": False,
        "target": target,
        "tool": tool,
        "installed_skill": installed,
        "export_receipts": {"target": target_export, "tool": tool_export},
        "settings_sha256": engine.sha_file(settings_path),
        "explicit_settings_sha256": engine.sha_file(paths["settings"]),
        "git_config_sha256": engine.sha_file(paths["git_config"]),
        "runtime_target_preimage_sha256": engine.manifest_digest(runtime_manifest),
        "qualification_bindings": qualification_bindings(),
        "auth": engine.auth_status(),
    }
    write_create_once(paths["root"] / PREPARATION_RECEIPT_NAME, engine.canonical_bytes(prepared))
    return prepared


def inspect_prepared_workspace(workspace: Path, *, allow_settings_mismatch: bool = False) -> dict[str, Any]:
    if workspace.resolve() != LIVE_WORKSPACE_PATH.resolve():
        raise Refusal("workspace differs from the frozen crAPI A2 location")
    paths = engine.recovery.runtime_paths(workspace)
    receipt = engine.load_json(paths["root"] / PREPARATION_RECEIPT_NAME)
    if receipt.get("schema") != "ospt.full-vulnhunter-crapi-preparation.v1" or receipt.get("provider_invoked") is not False:
        raise Refusal("crAPI preparation receipt is missing or invalid")
    target = engine.verify_export(workspace / "target", TARGET_SOURCE_ID, TARGET_COMMIT, TARGET_EXPORT_FILE_COUNT)
    tool = engine.verify_export(workspace / "tool", engine.TOOL_SOURCE_ID, engine.TOOL_COMMIT, engine.TOOL_FILE_COUNT)
    if target["manifest_sha256"] != TARGET_MANIFEST_SHA256 or tool["manifest_sha256"] != engine.TOOL_MANIFEST_SHA256:
        raise Refusal("prepared source or tool moved")
    installed_manifest = engine.directory_manifest(workspace / ".claude/skills/vulnhunt")
    if engine.manifest_digest(installed_manifest) != engine.SKILL_MANIFEST_SHA256:
        raise Refusal("prepared project-local VulnHunter skill moved")
    expected_settings = engine.sha_bytes(engine.canonical_bytes(project_settings(workspace)))
    for path in (workspace / ".claude/settings.json", paths["settings"]):
        if not path.is_file() or engine.sha_file(path) != expected_settings:
            if not allow_settings_mismatch:
                raise Refusal("prepared safety settings moved")
    if paths["git_config"].read_text(encoding="utf-8") != engine.recovery.git_config_text():
        raise Refusal("prepared Git transport rewrite moved")
    runtime_ok, runtime_defects = engine.verify_pinned_members(workspace / "runtime-target", target["manifest"])
    if not runtime_ok:
        raise Refusal("runtime/test first-party source moved: " + "; ".join(runtime_defects))
    if receipt.get("qualification_bindings") != qualification_bindings():
        raise Refusal("provider-free qualification bindings moved")
    if HIDDEN_EVALUATOR_ROOT.resolve() == workspace.resolve() or workspace.resolve() in HIDDEN_EVALUATOR_ROOT.resolve().parents:
        raise Refusal("hidden evaluator overlaps the model workspace")
    return {
        **receipt,
        "target": target,
        "tool": tool,
        "installed_skill": {"manifest": installed_manifest, "manifest_sha256": engine.manifest_digest(installed_manifest)},
        "settings_sha256": expected_settings,
        "runtime_target_first_party_unchanged": True,
        "auth": engine.auth_status(),
    }


def configure_qualifier() -> None:
    qualifier.PROJECT = "ospt-crapi-vh-full-001-a2"
    qualifier.RUN_ID = RUN_ID
    qualifier.EVIDENCE = TARGET_CONTROL_EVIDENCE
    qualifier.HIDDEN_ROOT = HIDDEN_EVALUATOR_ROOT


@dataclass
class CrAPIService:
    process: subprocess.Popen[str]
    log_path: Path
    argv: list[str]
    started_at: str
    seed_receipt: dict[str, Any]


def start_web_only_tunnel() -> tuple[subprocess.Popen[str], dict[str, Any]]:
    web_ip = qualifier.container_ip("crapi-web")
    argv = [
        "ssh", "-F", str(qualifier.COLIMA_SSH_CONFIG), "-o", "ControlMaster=no",
        "-o", "ControlPath=none", "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", "-N",
        "-L", f"127.0.0.1:8888:{web_ip}:80", "lima-colima",
    ]
    log_path = TARGET_CONTROL_EVIDENCE / "web-only-tunnel.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(argv, text=True, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise Refusal("web-only tunnel exited before health")
        healthy, _ = target_health()
        if healthy and not qualifier.port_open(8025):
            receipt = {
                "schema": "ospt.crapi-web-only-tunnel.v1",
                "status": "PASS",
                "pid": process.pid,
                "argv_sha256": qualifier.sha_bytes("\0".join(argv).encode()),
                "host_listener": ["127.0.0.1", 8888],
                "mailhog_listener_present": False,
                "destination": f"{web_ip}:80",
                "container_network": qualifier.PROJECT + "_default",
                "container_network_internal": True,
            }
            qualifier.write_json(TARGET_CONTROL_EVIDENCE / "WEB_ONLY_TUNNEL_RECEIPT.json", receipt)
            return process, receipt
        time.sleep(1)
    process.terminate()
    process.wait(timeout=10)
    raise Refusal("web-only tunnel did not become healthy")


def target_health(timeout: float = 3.0) -> tuple[bool, str]:
    try:
        status, _, _ = qualifier.http_json("GET", TARGET_HEALTH_URL, timeout=max(1, int(timeout)))
        return status == 200, f"HTTP {status}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def target_service_argv(_workspace: Path) -> list[str]:
    return [
        "controller:crapi-sealed-runtime-v1",
        "docker-compose-up:pull-never",
        "seed:hidden-two-principal-evaluator",
        "tunnel:127.0.0.1:8888-only",
    ]


def start_target_service(_workspace: Path) -> CrAPIService:
    configure_qualifier()
    if TARGET_CONTROL_EVIDENCE.exists():
        raise Refusal("target-control evidence already exists")
    if (HIDDEN_EVALUATOR_ROOT / RUN_ID).exists():
        raise Refusal("hidden evaluator already exists for this one-attempt run")
    TARGET_CONTROL_EVIDENCE.mkdir(parents=True, exist_ok=False)
    dual_tunnel: subprocess.Popen[str] | None = None
    web_tunnel: subprocess.Popen[str] | None = None
    try:
        qualifier.static_preflight(retain=True)
        qualifier.docker_available()
        if qualifier.existing_containers():
            raise Refusal("controlled crAPI container names already exist")
        if qualifier.port_open(8888) or qualifier.port_open(8025):
            raise Refusal("controlled loopback port already occupied")
        lock = qualifier.validate_lock()
        imports = qualifier.import_rows()
        for name, imported in imports.items():
            image = json.loads(qualifier.run(["docker", "image", "inspect", imported["local_image_id"]], timeout=20).stdout)[0]
            if image.get("Id") != imported["local_image_id"]:
                raise Refusal(f"imported image absent for {name}")
        up = qualifier.run(qualifier.compose_argv("up", "-d", "--pull", "never", "--wait", "--wait-timeout", "420"), timeout=480)
        (TARGET_CONTROL_EVIDENCE / "up.log").write_text(up.stdout + up.stderr, encoding="utf-8")
        health = qualifier.wait_for_health()
        runtime = qualifier.inspect_runtime(lock, imports)
        runtime["health"] = health
        qualifier.write_json(TARGET_CONTROL_EVIDENCE / "RUNTIME_INSPECTION.json", runtime)
        dual_tunnel, _ = qualifier.start_loopback_tunnel()
        seed = qualifier.seed_and_evaluate()
        qualifier.stop_loopback_tunnel(dual_tunnel)
        dual_tunnel = None
        web_tunnel, web_receipt = start_web_only_tunnel()
        seed["model_visible_listener"] = web_receipt["host_listener"]
        seed["mailhog_listener_present_for_model"] = False
        qualifier.write_json(TARGET_CONTROL_EVIDENCE / "LIVE_SEED_PUBLIC_RECEIPT.json", seed)
        return CrAPIService(web_tunnel, TARGET_CONTROL_EVIDENCE / "compose.log", target_service_argv(_workspace), engine.now_z(), seed)
    except Exception:
        if web_tunnel is not None and web_tunnel.poll() is None:
            web_tunnel.terminate()
            web_tunnel.wait(timeout=10)
        try:
            qualifier.teardown(retain_logs=True, tunnel=dual_tunnel)
        except Exception:
            pass
        raise


def stop_target_service(service: CrAPIService) -> dict[str, Any]:
    configure_qualifier()
    termination = "none"
    if service.process.poll() is None:
        os.killpg(service.process.pid, signal.SIGTERM)
        try:
            service.process.wait(timeout=10)
            termination = "SIGTERM"
        except subprocess.TimeoutExpired:
            os.killpg(service.process.pid, signal.SIGKILL)
            service.process.wait(timeout=10)
            termination = "SIGKILL"
    teardown = qualifier.teardown(retain_logs=True, tunnel=None)
    pointers = {}
    for name in ("STATIC_PREFLIGHT.json", "RUNTIME_INSPECTION.json", "LIVE_SEED_PUBLIC_RECEIPT.json", "WEB_ONLY_TUNNEL_RECEIPT.json", "TEARDOWN_RECEIPT.json"):
        path = TARGET_CONTROL_EVIDENCE / name
        if path.is_file():
            pointers[name] = {"path": str(path), "sha256": engine.sha_file(path)}
    return {
        "exit_code": service.process.returncode,
        "termination": termination,
        "log_path": str(TARGET_CONTROL_EVIDENCE / "compose.log"),
        "teardown": teardown,
        "evidence": pointers,
        "hidden_evaluator_sha256": service.seed_receipt["hidden_evaluator_sha256"],
        "claim_ceiling": "Controller-owned crAPI lifecycle and evaluator evidence only; model findings remain pending human disposition.",
    }


def build_scope(workspace_root: str, expires: str, max_cost: float, max_seconds: int, *, require_empty_results: bool = True) -> dict[str, Any]:
    if float(max_cost) != MAX_COST_USD or int(max_seconds) != MAX_SECONDS:
        raise Refusal(f"budget differs from frozen controller contract: ${MAX_COST_USD:.2f}/{MAX_SECONDS}s")
    root = Path(workspace_root).resolve()
    if root != LIVE_WORKSPACE_PATH.resolve():
        raise Refusal("workspace differs from the frozen crAPI one-attempt location")
    try:
        expires_at = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise Refusal("scope expiry is invalid") from exc
    now = dt.datetime.now(dt.timezone.utc)
    if expires_at <= now or (expires_at - now).total_seconds() > MAX_SCOPE_LIFETIME_SECONDS:
        raise Refusal("scope expiry must be current and no more than 48 hours ahead")
    prepared = inspect_prepared_workspace(root)
    if require_empty_results and any(path.is_file() for path in (root / "results").rglob("*")):
        raise Refusal("results directory is not empty")
    sidecar_root = engine.claude_project_sidecar_root(root)
    if require_empty_results and sidecar_root.exists() and any(sidecar_root.rglob("*")):
        raise Refusal("Claude project sidecar root is not empty")
    prompt = prompt_for(root / "target", root / "runtime-target", root / "results")
    runtime = engine.claude_runtime()
    bindings = qualification_bindings()
    scope = {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "purpose": "Complete the unchanged upstream VulnHunter workflow against the full pinned OWASP crAPI v1.1.6 Git-free source export with a sealed controller-owned target.",
        "owner": {"identity": OWNER_IDENTITY, "namespace": APPROVAL_NAMESPACE, "allowed_signers_path": str(ALLOWED_SIGNERS_PATH), "allowed_signers_sha256": ALLOWED_SIGNERS_SHA256},
        "controller": {"path": str(CONTROLLER_DEPLOY_PATH), "sha256": engine.sha_file(Path(__file__).resolve())},
        "runtime": runtime,
        "actual_consumer": {
            "command": "/vulnhunt",
            "tool_source_id": engine.TOOL_SOURCE_ID,
            "tool_commit": engine.TOOL_COMMIT,
            "required_native_outputs": list(engine.REQUIRED_NATIVE_OUTPUTS),
            "required_agent_formula": "3 * partition_count + 5 total minimum, including recon, verify, reproduce/test/fix, and sweep",
        },
        "target": {
            "source_id": TARGET_SOURCE_ID,
            "commit": TARGET_COMMIT,
            "tree": TARGET_TREE,
            "tracked_file_count": TARGET_EXPORT_FILE_COUNT,
            "source_custody_tracked_file_count": TARGET_SOURCE_TRACKED_FILE_COUNT,
            "manifest_sha256": TARGET_MANIFEST_SHA256,
            "source_custody_manifest_sha256": TARGET_SOURCE_TRACKED_MANIFEST_SHA256,
            "workspace_root": str(LIVE_WORKSPACE_PATH),
            "evidence_root": str(LIVE_EVIDENCE_PATH),
            "target_control_evidence": str(TARGET_CONTROL_EVIDENCE),
            "attempt_marker": str(ATTEMPT_MARKER_PATH),
            "immutable_source": str(root / "target"),
            "runtime_test_copy": str(root / "runtime-target"),
        },
        "source_control": {
            "study_root": str(STUDY_ROOT),
            "tool_export_manifest_sha256": engine.TOOL_MANIFEST_SHA256,
            "installed_skill_manifest_sha256": engine.SKILL_MANIFEST_SHA256,
        },
        "qualification_bindings": bindings,
        "execution_engine": {"path": str(A4_CONTROLLER), "sha256": A4_CONTROLLER_SHA256},
        "safety_settings_sha256": engine.sha_bytes(engine.canonical_bytes(project_settings(root))),
        "mode": "immutable Git-free source plus writable test copy; sealed digest-pinned internal Docker target; web-only controller tunnel on 127.0.0.1:8888; hidden evaluator and MailHog outside model reach; provider Bash limited to workspace and loopback",
        "model": engine.ROOT_MODEL_REQUEST,
        "model_resolution_contract": {"root": engine.EXPECTED_ROOT_MODEL, "forwarded_allowed": list(engine.ALLOWED_FORWARDED_MODELS), "unexpected_model_action": "refuse completion"},
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
            "model_visible_url": TARGET_WEB_URL,
            "command_plan": target_service_argv(root),
            "docker_published_ports": [],
            "container_network_internal": True,
            "model_visible_listener": ["127.0.0.1", 8888],
            "mailhog_listener_for_model": None,
            "health_interval_seconds": engine.TARGET_HEALTH_INTERVAL_SECONDS,
            "health_failure_limit": 2,
            "restart_budget": 0,
            "recovery_policy": "fail closed; the sealed crAPI evaluator lifecycle is not safe for generic engine restart",
            "teardown_required": True,
            "control_evidence": str(TARGET_CONTROL_EVIDENCE),
        },
        "runtime_sidecars": {
            "allowed_roots": [str(sidecar_root), str(engine.recovery.runtime_paths(root)["tmp"])],
            "capture_required": True,
            "claude_task_output_link_contract": CLAUDE_TASK_OUTPUT_LINK_CONTRACT,
            "unexpected_path_action": "refuse completion",
        },
        "logging": {
            "planes": ["ENFORCEMENT.jsonl", "OPERATIONAL.jsonl", "EVIDENCE_DECISION.jsonl"],
            "raw": "raw-event-log.jsonl",
            "target_control": str(TARGET_CONTROL_EVIDENCE),
            "trace_profile": "high-stakes-scaled",
            "first_class_outcomes": ["allow", "deny", "refuse", "abstain", "failed-evidence", "no-action", "kill", "complete"],
        },
        "prompt": prompt,
        "expires": expires,
        "claim_ceiling": "One completion-grade crAPI VulnHunter experiment. Native outputs and hidden-evaluator comparisons remain pending human disposition. No finding activation, production accuracy, adoption, recurrence, CI, deployment, publication, or presentation authority.",
    }
    scope["command_argv"] = engine.claude_argv(scope, prompt)
    runtime_env = engine.runtime_environment(root)
    defects = engine.recovery.validate_runtime_plan(root, runtime_env, scope["command_argv"])
    defects.extend(engine.validate_node_runtime_plan(runtime_env))
    trust = engine.recovery.exact_project_trust(CLAUDE_CONFIG_PATH, root)
    if not trust["accepted"]:
        defects.append(trust["reason"])
    if defects:
        raise Refusal("pre-provider readiness is not GREEN: " + "; ".join(defects))
    scope["preprovider"] = {
        "preparation_receipt_sha256": engine.sha_file(engine.recovery.runtime_paths(root)["root"] / PREPARATION_RECEIPT_NAME),
        "exact_workspace_trust": trust,
        "runtime_environment": {key: runtime_env[key] for key in (engine.recovery.BACKGROUND_WAIT_ENV, "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_TERMINAL_PROMPT", "NPM_CONFIG_CACHE", "TMPDIR", "CLAUDE_TMPDIR", "CLAUDE_CODE_TMPDIR", "BUN_TMPDIR")},
        "runtime_target_first_party_unchanged": prepared["runtime_target_first_party_unchanged"],
        "node_runtime": engine.node_runtime(),
        "target_service_plan": scope["target_service"],
        "dependency_installation": "NOT_REQUIRED_FOR_SOURCE_ANALYSIS_OR_CONTROLLER_OWNED_PREBUILT_TARGET",
    }
    return scope


def verify_scope(scope_path: Path, signature_path: Path, allowed_signers: Path) -> dict[str, Any]:
    scope_bytes = scope_path.read_bytes()
    if engine.canonical_bytes(json.loads(scope_bytes)) != scope_bytes:
        raise Refusal("scope is not canonical JSON")
    scope = json.loads(scope_bytes)
    required = {
        "schema": SCHEMA,
        "run_id": RUN_ID,
    }
    for key, value in required.items():
        if scope.get(key) != value:
            raise Refusal(f"scope identity mismatch: {key}")
    if scope.get("target", {}).get("source_id") != TARGET_SOURCE_ID or scope.get("target", {}).get("manifest_sha256") != TARGET_MANIFEST_SHA256:
        raise Refusal("scope target binding mismatch")
    if scope.get("controller") != {"path": str(CONTROLLER_DEPLOY_PATH), "sha256": engine.sha_file(Path(__file__).resolve())}:
        raise Refusal("scope controller binding mismatch")
    if scope.get("execution_engine") != {"path": str(A4_CONTROLLER), "sha256": A4_CONTROLLER_SHA256}:
        raise Refusal("scope execution-engine binding mismatch")
    if not A4_CONTROLLER.is_file() or engine.sha_file(A4_CONTROLLER) != A4_CONTROLLER_SHA256:
        raise Refusal("pinned A4 execution engine moved")
    if Path(__file__).resolve() != CONTROLLER_DEPLOY_PATH.resolve():
        raise Refusal("live execution requires the canonical crAPI controller path")
    if scope.get("budgets", {}).get("attempts") != 1 or scope.get("budgets", {}).get("widening") is not False:
        raise Refusal("scope is not one-attempt/no-widening")
    if float(scope.get("budgets", {}).get("max_cost_usd", -1)) != MAX_COST_USD or int(scope.get("budgets", {}).get("max_seconds", -1)) != MAX_SECONDS:
        raise Refusal("scope budget mismatch")
    if allowed_signers.resolve() != ALLOWED_SIGNERS_PATH.resolve() or scope.get("owner", {}).get("allowed_signers_sha256") != ALLOWED_SIGNERS_SHA256:
        raise Refusal("owner trust root mismatch")
    expires_at = dt.datetime.fromisoformat(scope["expires"].replace("Z", "+00:00"))
    if dt.datetime.now(dt.timezone.utc) >= expires_at:
        raise Refusal("scope expired")
    with engine.pinned_allowed_signers_fd(allowed_signers) as (signers_fd, verified_signers):
        completed = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(verified_signers), "-I", OWNER_IDENTITY, "-n", APPROVAL_NAMESPACE, "-s", str(signature_path)],
            input=scope_bytes,
            capture_output=True,
            pass_fds=(signers_fd,),
        )
    if completed.returncode != 0:
        raise Refusal("owner signature verification failed")
    expected = build_scope(scope["target"]["workspace_root"], scope["expires"], float(scope["budgets"]["max_cost_usd"]), int(scope["budgets"]["max_seconds"]), require_empty_results=False)
    if scope != expected:
        raise Refusal("scope contains values outside the frozen controller contract")
    return scope


def command_prepare(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    if workspace != LIVE_WORKSPACE_PATH.resolve() or workspace.exists():
        raise Refusal("prepare requires the absent frozen crAPI A2 workspace")
    prepared = prepare_workspace(args.study_root.resolve(), workspace)
    report = {
        "schema": "ospt.full-vulnhunter-crapi-prepare-command.v1",
        "status": "PASS",
        "provider_invoked": False,
        "workspace": str(workspace),
        "target_file_count": prepared["target"]["file_count"],
        "target_manifest_sha256": prepared["target"]["manifest_sha256"],
        "runtime_target_preimage_sha256": prepared["runtime_target_preimage_sha256"],
        "skill_manifest_sha256": prepared["installed_skill"]["manifest_sha256"],
        "settings_sha256": prepared["settings_sha256"],
        "next": "Accept trusted access for this exact disposable workspace, then freeze the owner scope.",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def command_preflight(args: argparse.Namespace) -> int:
    prepared = inspect_prepared_workspace(args.workspace.resolve())
    runtime_env = engine.runtime_environment(args.workspace.resolve())
    trust = engine.recovery.exact_project_trust(CLAUDE_CONFIG_PATH, args.workspace.resolve())
    report = {
        "schema": "ospt.full-vulnhunter-crapi-preflight.v1",
        "status": "PASS" if trust["accepted"] else "HOLD_TRUST",
        "provider_invoked": False,
        "trust": trust,
        "runtime_plan_defects": engine.validate_node_runtime_plan(runtime_env),
        "target_manifest_sha256": prepared["target"]["manifest_sha256"],
        "qualification_bindings": qualification_bindings(),
        "target_started": False,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 3


def install_engine_contract() -> None:
    engine.SCHEMA = SCHEMA
    engine.RUN_ID = RUN_ID
    engine.TARGET_SOURCE_ID = TARGET_SOURCE_ID
    engine.TARGET_COMMIT = TARGET_COMMIT
    engine.TARGET_FILE_COUNT = TARGET_EXPORT_FILE_COUNT
    engine.TARGET_MANIFEST_SHA256 = TARGET_MANIFEST_SHA256
    engine.MAX_COST_USD = MAX_COST_USD
    engine.MAX_SECONDS = MAX_SECONDS
    engine.NO_PROGRESS_SECONDS = NO_PROGRESS_SECONDS
    engine.TARGET_HEALTH_FAILURE_LIMIT = 2
    engine.TARGET_RESTART_LIMIT = 0
    engine.TARGET_HEALTH_URL = TARGET_HEALTH_URL
    engine.LIVE_WORKSPACE_PATH = LIVE_WORKSPACE_PATH
    engine.LIVE_EVIDENCE_PATH = LIVE_EVIDENCE_PATH
    engine.ATTEMPT_MARKER_PATH = ATTEMPT_MARKER_PATH
    engine.CONTROLLER_DEPLOY_PATH = CONTROLLER_DEPLOY_PATH
    engine.PREPARATION_RECEIPT_NAME = PREPARATION_RECEIPT_NAME
    engine.project_settings = project_settings
    engine.prompt_for = prompt_for
    engine.prepare_workspace = prepare_workspace
    engine.inspect_prepared_workspace = inspect_prepared_workspace
    engine.target_service_argv = target_service_argv
    engine.start_target_service = start_target_service
    engine.stop_target_service = stop_target_service
    engine.target_health = target_health
    engine.build_scope = build_scope
    engine.verify_scope = verify_scope
    engine.append_jsonl = append_jsonl
    engine.write_create_once = write_create_once


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--study-root", type=Path, required=True)
    prepare.add_argument("--workspace", type=Path, required=True)
    prepare.set_defaults(func=command_prepare)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--workspace", type=Path, required=True)
    preflight.set_defaults(func=command_preflight)
    scope = sub.add_parser("scope")
    scope.add_argument("--workspace", type=Path, required=True)
    scope.add_argument("--out", type=Path, required=True)
    scope.add_argument("--expires", required=True)
    scope.add_argument("--max-cost", type=float, default=MAX_COST_USD)
    scope.add_argument("--max-seconds", type=int, default=MAX_SECONDS)
    scope.set_defaults(func=engine.command_scope)
    run = sub.add_parser("run")
    run.add_argument("--study-root", type=Path, required=True)
    run.add_argument("--scope", type=Path, required=True)
    run.add_argument("--signature", type=Path, required=True)
    run.add_argument("--allowed-signers", type=Path, required=True)
    run.add_argument("--run-dir", type=Path, required=True)
    run.set_defaults(func=engine.command_run)
    validate = sub.add_parser("validate")
    validate.add_argument("--results", type=Path, required=True)
    validate.add_argument("--raw-log", type=Path, required=True)
    validate.add_argument("--stderr", type=Path)
    validate.add_argument("--scope", type=Path)
    validate.add_argument("--signature", type=Path)
    validate.add_argument("--allowed-signers", type=Path)
    validate.add_argument("--out", type=Path)
    validate.set_defaults(func=engine.command_validate)
    return result


def main() -> int:
    install_engine_contract()
    args = parser().parse_args()
    try:
        return int(args.func(args))
    except (Refusal, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "REFUSED", "provider_invoked": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
