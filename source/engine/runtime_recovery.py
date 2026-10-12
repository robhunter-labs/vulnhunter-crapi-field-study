#!/usr/bin/env python3
"""Zero-spend recovery gate for the next VulnHunter Juice Shop attempt.

This module does not invoke Claude, npm, Git, or a network. It converts the
observed A1 failures into a pre-provider contract that a later signed controller
must satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA = "ospt.vulnhunter-runtime-recovery.v1"
BACKGROUND_WAIT_ENV = "CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS"
EXPECTED_BACKGROUND_WAIT = "0"
ALLOWED_SOURCE_RUNTIME_DIRECTORIES = frozenset({".claude", ".claude/.cc-writes"})


class Refusal(RuntimeError):
    """A pre-provider safety condition is not satisfied."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def iter_json_lines(path: Path) -> Iterable[Any]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def collect_records(value: Any, record_type: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if value.get("type") == record_type:
            found.append(value)
        for child in value.values():
            found.extend(collect_records(child, record_type))
    elif isinstance(value, list):
        for child in value:
            found.extend(collect_records(child, record_type))
    return found


def exact_project_trust(config_path: Path, workspace: Path) -> dict[str, Any]:
    """Inspect Claude's exact-project trust entry without changing user state."""
    try:
        config = json.loads(config_path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"accepted": False, "reason": f"Claude project config is unreadable: {exc}"}
    project = config.get("projects", {}).get(str(workspace.resolve()))
    accepted = isinstance(project, dict) and project.get("hasTrustDialogAccepted") is True
    return {
        "accepted": accepted,
        "workspace": str(workspace.resolve()),
        "config_path": str(config_path.resolve()),
        "reason": (
            "exact workspace trust is recorded"
            if accepted
            else "exact workspace trust has not been accepted"
        ),
    }


def runtime_paths(workspace: Path) -> dict[str, Path]:
    root = workspace.resolve() / "runtime"
    return {
        "root": root,
        "git_config": root / "gitconfig",
        "npm_cache": root / "npm-cache",
        "tmp": root / "tmp",
        "settings": root / "settings.json",
        "dependency_receipt": root / "DEPENDENCY_PREP.json",
    }


def child_environment(base: Mapping[str, str], workspace: Path) -> dict[str, str]:
    """Return the future Claude child environment without breaking OAuth HOME."""
    paths = runtime_paths(workspace)
    env = dict(base)
    env.update(
        {
            BACKGROUND_WAIT_ENV: EXPECTED_BACKGROUND_WAIT,
            "GIT_CONFIG_GLOBAL": str(paths["git_config"]),
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "NPM_CONFIG_CACHE": str(paths["npm_cache"]),
            "TMPDIR": str(paths["tmp"]),
            "CLAUDE_TMPDIR": str(paths["tmp"]),
            "CLAUDE_CODE_TMPDIR": str(paths["tmp"]),
            "BUN_TMPDIR": str(paths["tmp"]),
        }
    )
    return env


def git_config_text() -> str:
    return (
        '[url "https://github.com/"]\n'
        "\tinsteadOf = ssh://git@github.com/\n"
        "\tinsteadOf = git@github.com:\n"
    )


def validate_runtime_plan(workspace: Path, env: Mapping[str, str], argv: list[str]) -> list[str]:
    defects: list[str] = []
    paths = runtime_paths(workspace)
    if env.get(BACKGROUND_WAIT_ENV) != EXPECTED_BACKGROUND_WAIT:
        defects.append("print-mode background wait is not unlimited")
    if env.get("HOME") != os.environ.get("HOME"):
        defects.append("Claude HOME changed and may detach authenticated state")
    for key, expected in (
        ("GIT_CONFIG_GLOBAL", paths["git_config"]),
        ("NPM_CONFIG_CACHE", paths["npm_cache"]),
        ("TMPDIR", paths["tmp"]),
        ("CLAUDE_TMPDIR", paths["tmp"]),
        ("CLAUDE_CODE_TMPDIR", paths["tmp"]),
        ("BUN_TMPDIR", paths["tmp"]),
    ):
        if Path(env.get(key, "")).resolve() != expected.resolve():
            defects.append(f"{key} is not bound to the runtime workspace")
    if env.get("GIT_CONFIG_SYSTEM") != os.devnull:
        defects.append("system Git configuration is not disabled")
    if env.get("GIT_TERMINAL_PROMPT") != "0":
        defects.append("interactive Git credential prompting is not disabled")
    def option_value(name: str) -> str | None:
        if name not in argv:
            return None
        index = argv.index(name)
        return argv[index + 1] if index + 1 < len(argv) else None

    if option_value("--permission-mode") != "dontAsk":
        defects.append("Claude permission mode is not dontAsk")
    if option_value("--setting-sources") != "project":
        defects.append("project settings source is not explicit")
    settings_value = option_value("--settings")
    if settings_value is None:
        defects.append("signed runtime settings path is not explicit")
    elif Path(settings_value).resolve() != paths["settings"].resolve():
        defects.append("runtime settings path differs from the prepared path")
    if option_value("--max-budget-usd") is None:
        defects.append("provider cost ceiling is absent")
    return defects


def dependency_receipt_status(path: Path, workspace: Path) -> dict[str, Any]:
    """Require a prepared dependency postimage before provider authorization."""
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"accepted": False, "reason": f"dependency receipt is unreadable: {exc}"}
    expected_root = str((workspace.resolve() / "runtime-target").resolve())
    git_config = runtime_paths(workspace)["git_config"]
    git_digest = sha_file(git_config) if git_config.is_file() else None
    accepted = (
        value.get("schema") == "ospt.vulnhunter-dependency-prep.v1"
        and value.get("status") == "PASS"
        and value.get("provider_invoked") is False
        and value.get("target_root") == expected_root
        and value.get("npm_exit_code") == 0
        and isinstance(value.get("node_modules_manifest_sha256"), str)
        and value["node_modules_manifest_sha256"].startswith("sha256:")
        and value.get("git_config_sha256") == git_digest
    )
    return {
        "accepted": accepted,
        "reason": "dependency preparation is bound" if accepted else "dependency preparation is not bound",
        "receipt": value,
    }


def verify_source_postimage(root: Path, expected: Mapping[str, str]) -> tuple[bool, list[str]]:
    """Verify first-party files while measuring exact empty runtime sidecar dirs separately."""
    defects: list[str] = []
    if root.is_symlink() or not root.is_dir():
        return False, ["target root is missing, not a directory, or a symlink"]
    expected_dirs: set[str] = set()
    for rel in expected:
        parent = Path(rel).parent
        while parent != Path("."):
            expected_dirs.add(parent.as_posix())
            parent = parent.parent
    for rel, digest in sorted(expected.items()):
        path = root / rel
        cursor = root
        for part in Path(rel).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                defects.append(f"first-party source path contains a symlink: {rel}")
                break
        else:
            if not path.is_file():
                defects.append(f"first-party source member is missing: {rel}")
            elif sha_file(path) != digest:
                defects.append(f"first-party source member changed: {rel}")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        for name in list(dirnames) + list(filenames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() and not (rel == "node_modules" or rel.startswith("node_modules/")):
                defects.append(f"unexpected symlink in target postimage: {rel}")
                continue
            if rel == ".STUDY_SOURCE_EXPORT.json" or rel in expected or rel in expected_dirs:
                continue
            if rel == "node_modules" or rel.startswith("node_modules/"):
                continue
            if rel in ALLOWED_SOURCE_RUNTIME_DIRECTORIES and path.is_dir():
                continue
            defects.append(f"unexpected target postimage member: {rel}")
    return not defects, defects


def terminal_state(raw_log: Path, stderr_path: Path | None = None) -> dict[str, Any]:
    tool_uses: set[str] = set()
    tool_results: set[str] = set()
    started_tasks: set[str] = set()
    stopped_tasks: set[str] = set()
    result_events = 0
    last_result: dict[str, Any] | None = None
    for event in iter_json_lines(raw_log):
        if not isinstance(event, dict):
            continue
        for record in collect_records(event, "tool_use"):
            if isinstance(record.get("id"), str):
                tool_uses.add(record["id"])
        for record in collect_records(event, "tool_result"):
            if isinstance(record.get("tool_use_id"), str):
                tool_results.add(record["tool_use_id"])
        if event.get("type") == "system" and event.get("subtype") == "task_started":
            if isinstance(event.get("task_id"), str):
                started_tasks.add(event["task_id"])
        if event.get("type") == "system" and event.get("subtype") == "task_notification":
            if event.get("status") in {"completed", "failed", "stopped", "cancelled"} and isinstance(event.get("task_id"), str):
                stopped_tasks.add(event["task_id"])
        if event.get("type") == "result":
            result_events += 1
            last_result = event
    stderr = stderr_path.read_text(errors="replace") if stderr_path and stderr_path.exists() else ""
    pending_tools = sorted(tool_uses - tool_results)
    pending_tasks = sorted(started_tasks - stopped_tasks)
    background_cutoff = "Background tasks still running" in stderr
    complete = result_events == 1 and not pending_tools and not pending_tasks and not background_cutoff
    return {
        "complete": complete,
        "result_event_count": result_events,
        "result_subtype": last_result.get("subtype") if last_result else None,
        "result_is_error": last_result.get("is_error") if last_result else None,
        "pending_tool_use_ids": pending_tools,
        "pending_task_ids": pending_tasks,
        "background_cutoff_observed": background_cutoff,
    }


def cost_accounting(raw_log: Path) -> dict[str, Any]:
    last_result: dict[str, Any] | None = None
    for event in iter_json_lines(raw_log):
        if isinstance(event, dict) and event.get("type") == "result":
            last_result = event
    if last_result is None:
        return {
            "reported_total_cost_usd": None,
            "model_usage_cost_usd": None,
            "conservative_cost_usd": None,
            "cost_disagreement": False,
        }
    reported = last_result.get("total_cost_usd")
    model_values = []
    usage = last_result.get("modelUsage")
    if isinstance(usage, dict):
        for value in usage.values():
            if isinstance(value, dict) and isinstance(value.get("costUSD"), (int, float)):
                model_values.append(float(value["costUSD"]))
    model_sum = math.fsum(model_values) if model_values else None
    candidates = [float(value) for value in (reported, model_sum) if isinstance(value, (int, float))]
    conservative = max(candidates) if candidates else None
    disagreement = (
        isinstance(reported, (int, float))
        and model_sum is not None
        and not math.isclose(float(reported), model_sum, rel_tol=1e-6, abs_tol=0.01)
    )
    return {
        "reported_total_cost_usd": float(reported) if isinstance(reported, (int, float)) else None,
        "model_usage_cost_usd": model_sum,
        "conservative_cost_usd": conservative,
        "cost_disagreement": disagreement,
        "billing_claim_authorized": False,
    }


def readiness_report(
    *,
    workspace: Path,
    claude_config: Path,
    argv: list[str],
    env: Mapping[str, str],
    dependency_receipt: Path,
) -> dict[str, Any]:
    trust = exact_project_trust(claude_config, workspace)
    dependency = dependency_receipt_status(dependency_receipt, workspace)
    defects = validate_runtime_plan(workspace, env, argv)
    if not trust["accepted"]:
        defects.append(trust["reason"])
    if not dependency["accepted"]:
        defects.append(dependency["reason"])
    return {
        "schema": SCHEMA,
        "status": "PASS" if not defects else "KICKBACK",
        "provider_invoked": False,
        "trust": trust,
        "dependency": dependency,
        "defects": defects,
        "claim_ceiling": (
            "PASS proves only the local pre-provider runtime contract; it does not prove a scan, finding, sandbox containment, dependency correctness, or spend."
        ),
    }
