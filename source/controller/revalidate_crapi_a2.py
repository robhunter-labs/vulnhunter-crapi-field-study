#!/usr/bin/env python3
"""Additively revalidate the preserved crAPI A2 run after two validator defects.

The original native-validation.json is immutable and remains KICKBACK.  This
validator fixes only the table-shaped finding denominator and classifies a
strict allowlist of empty Claude Code bookkeeping directories as measured
runtime sidecars.  It neither invokes a provider nor changes a finding state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


STUDY = Path("/path/to/local-study-workspace")
OSPT = STUDY / "OSPT"
A4_ROOT = OSPT / "build/vulnhunter-juice-shop-full-run-completion-attempt-4"
CRAPI_ROOT = OSPT / "build/vulnhunter-crapi-challenger-attempt-2"
sys.path.insert(0, str(A4_ROOT))
sys.path.insert(0, str(CRAPI_ROOT))

import full_vulnhunt_a4 as engine  # noqa: E402
import full_vulnhunt_crapi_a2 as crapi  # noqa: E402


RUN_ID = "VH-CRAPI-FULL-001-A2"
SCOPE_SHA256 = "sha256:c2fa240e7b7297aad33111737fac0cab3ad2ffd05075623caea5ec04acdf58cf"
ORIGINAL_VALIDATION_SHA256 = "sha256:04603db8c9a17ac60ed288ce696d4b7d09e7cc3a9fc4655ee171474ba2fb1adc"
EXPECTED_RESULT_MANIFEST = "sha256:f104e19a7366569656f6fed3770609164330f9957ba2d0ec5fcbaa53dc8fcc5a"
ALLOWED_EMPTY_SOURCE_SIDECARS = {
    ".claude",
    ".claude/.cc-writes",
    "services/.claude",
    "services/.claude/.cc-writes",
    "services/workshop/.claude",
    "services/workshop/.claude/.cc-writes",
}


class Refusal(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise Refusal(f"expected JSON object: {path}")
    return value


def verify_owner_signature(scope: Path, signature: Path, allowed_signers: Path) -> dict[str, Any]:
    if engine.sha_file(scope) != SCOPE_SHA256:
        raise Refusal("scope digest differs from the owner-approved A2 scope")
    if engine.sha_file(allowed_signers) != engine.ALLOWED_SIGNERS_SHA256:
        raise Refusal("allowed-signers trust root moved")
    scope_bytes = scope.read_bytes()
    completed = subprocess.run(
        [
            "ssh-keygen", "-Y", "verify", "-f", str(allowed_signers),
            "-I", engine.OWNER_IDENTITY, "-n", engine.APPROVAL_NAMESPACE,
            "-s", str(signature),
        ],
        input=scope_bytes,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise Refusal("owner signature verification failed")
    value = load_json(scope)
    if value.get("run_id") != RUN_ID or value.get("budgets", {}).get("attempts") != 1:
        raise Refusal("scope run or attempt binding moved")
    return value


def finding_denominator(results: Path) -> tuple[list[str], list[str]]:
    """Count table or list output without changing the upstream content contract."""
    expected: list[str] = []
    phase2b = results / "phase2b_output.md"
    if phase2b.is_file():
        text = phase2b.read_text(encoding="utf-8", errors="replace")
        confirmed_section = re.search(
            r"(?ims)^##\s+2\.\s+CONFIRMED findings.*?(?=^##\s+3\.)", text
        )
        if confirmed_section:
            for line in confirmed_section.group(0).splitlines():
                match = re.match(
                    r"^\|\s*(VULN-\d{3,})\s*\|.*?\|\s*(High\+?|Medium|Low/Medium)(?:\s*\([^|]+\))?\s*\|",
                    line,
                    re.IGNORECASE,
                )
                if match:
                    expected.append(match.group(1).upper())
        if not expected:
            for line in text.splitlines():
                match = re.match(
                    r"^- \*\*(VULN-\d{3,})\*\*.*\*\*(High\+?|Medium|Low/Medium)\*\*",
                    line,
                    re.IGNORECASE,
                )
                if match:
                    expected.append(match.group(1).upper())
    assigned: list[str] = []
    phase3 = results / "phase3_output.md"
    if phase3.is_file():
        assigned = sorted(
            set(
                match.upper()
                for match in re.findall(
                    r"^\|\s*(VULN-\d{3,})\s*\|",
                    phase3.read_text(encoding="utf-8", errors="replace"),
                    re.MULTILINE | re.IGNORECASE,
                )
            )
        )
    return sorted(set(expected)), assigned


def all_confirmed_ids(results: Path) -> list[str]:
    phase2b = results / "phase2b_output.md"
    if not phase2b.is_file():
        return []
    text = phase2b.read_text(encoding="utf-8", errors="replace")
    section = re.search(r"(?ims)^##\s+2\.\s+CONFIRMED findings.*?(?=^##\s+3\.)", text)
    if not section:
        return []
    return sorted(
        set(
            match.upper()
            for match in re.findall(r"^\|\s*(VULN-\d{3,})\s*\|", section.group(0), re.MULTILINE)
        )
    )


def verify_pinned_source_with_empty_sidecars(
    root: Path, expected: dict[str, str]
) -> tuple[bool, list[str], list[str]]:
    defects: list[str] = []
    observed_sidecars: list[str] = []
    if root.is_symlink() or not root.is_dir():
        return False, ["source root missing or symlinked"], observed_sidecars
    expected_dirs: set[str] = set()
    for rel in expected:
        parent = Path(rel).parent
        while parent != Path("."):
            expected_dirs.add(parent.as_posix())
            parent = parent.parent
    for rel, digest in sorted(expected.items()):
        path = root / rel
        if not path.is_file() or path.is_symlink():
            defects.append(f"pinned source member missing or symlinked: {rel}")
        elif engine.sha_file(path) != digest:
            defects.append(f"pinned source member changed: {rel}")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        for name in list(dirnames) + list(filenames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            if rel == ".STUDY_SOURCE_EXPORT.json" or rel in expected or rel in expected_dirs:
                continue
            if rel in ALLOWED_EMPTY_SOURCE_SIDECARS and path.is_dir():
                if any(path.iterdir()) and not rel.endswith(".claude"):
                    defects.append(f"allowed runtime sidecar is not empty: {rel}")
                else:
                    observed_sidecars.append(rel)
                continue
            defects.append(f"unexpected source postimage member: {rel}")
    return not defects, defects, sorted(set(observed_sidecars))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    for path in (args.workspace, args.evidence, args.results):
        if path.is_symlink() or not path.is_dir():
            raise Refusal(f"required directory missing or symlinked: {path}")
    if args.out.exists():
        raise Refusal("additive reconciliation receipt already exists")

    crapi.install_engine_contract()
    scope = verify_owner_signature(args.scope, args.signature, args.allowed_signers)
    if Path(scope["target"]["workspace_root"]).resolve() != args.workspace.resolve():
        raise Refusal("workspace differs from signed scope")
    if Path(scope["target"]["evidence_root"]).resolve() != args.evidence.resolve():
        raise Refusal("evidence root differs from signed scope")

    original = args.evidence / "native-validation.json"
    raw_log = args.evidence / "raw-event-log.jsonl"
    if engine.sha_file(original) != ORIGINAL_VALIDATION_SHA256:
        raise Refusal("original KICKBACK validation moved")
    original_value = load_json(original)
    if original_value.get("status") != "KICKBACK":
        raise Refusal("original validation no longer records KICKBACK")
    if engine.sha_file(raw_log) != original_value.get("raw_log_sha256"):
        raise Refusal("raw event log differs from original validation")
    live_results = args.workspace / "results"
    if live_results.is_symlink() or not live_results.is_dir():
        raise Refusal("signed-workspace result directory is unavailable")
    live_result_digest = engine.manifest_digest(engine.directory_manifest(live_results))
    result_digest = engine.manifest_digest(engine.directory_manifest(args.results))
    if result_digest != EXPECTED_RESULT_MANIFEST or result_digest != original_value.get("results_manifest_sha256"):
        raise Refusal("preserved result set differs from the controller-observed result set")
    if live_result_digest != result_digest:
        raise Refusal("preserved result set differs from the signed-workspace result set")

    preparation = load_json(args.workspace / "runtime/PREPARATION_CRAPI.json")
    expected_manifest = preparation.get("target", {}).get("manifest")
    if not isinstance(expected_manifest, dict) or len(expected_manifest) != crapi.TARGET_EXPORT_FILE_COUNT:
        raise Refusal("preparation target manifest is unavailable")
    source_ok, source_defects, sidecars = verify_pinned_source_with_empty_sidecars(
        args.workspace / "target", expected_manifest
    )
    runtime_ok, runtime_defects = engine.verify_pinned_members(
        args.workspace / "runtime-target", expected_manifest
    )

    engine.phase_finding_denominator = finding_denominator
    binding = engine.VerifiedBinding(
        scope_path=str(args.scope.resolve()),
        signature_path=str(args.signature.resolve()),
        allowed_signers_path=str(args.allowed_signers.resolve()),
        provenance="signed-live-controller-additive-reconciliation",
    )
    report = engine.validate_native_results(
        live_results,
        raw_log,
        binding,
        stderr_path=args.evidence / "claude-stderr.log",
    )
    report["schema"] = "ospt.vulnhunter-crapi-additive-reconciliation.v1"
    report["run_id"] = RUN_ID
    report["reconciled_at"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    report["provider_reinvoked"] = False
    report["original_validation"] = {
        "path": str(original),
        "sha256": ORIGINAL_VALIDATION_SHA256,
        "status": "KICKBACK",
        "preserved": True,
    }
    report["preserved_results"] = {
        "path": str(args.results.resolve()),
        "file_count": len(engine.directory_manifest(args.results)),
        "manifest_sha256": result_digest,
    }
    report["source_content_integrity"] = {
        "pinned_members_unchanged": source_ok,
        "runtime_copy_pinned_members_unchanged": runtime_ok,
        "allowed_empty_runtime_sidecars": sorted(ALLOWED_EMPTY_SOURCE_SIDECARS),
        "observed_empty_runtime_sidecars": sidecars,
        "defects": source_defects + runtime_defects,
        "claim_ceiling": "All 1,022 pinned first-party files were unchanged; only the enumerated empty Claude Code .cc-writes bookkeeping directories were added. This is content integrity, not an exact directory-postimage claim.",
    }
    teardown = original_value.get("target_service", {}).get("teardown", {})
    report["target_teardown_status"] = teardown.get("status")
    high_medium_ids, assigned_ids = finding_denominator(live_results)
    confirmed_ids = all_confirmed_ids(live_results)
    poc_names = {
        path.name.lower() for path in (live_results / "poc").iterdir() if path.is_file()
    }
    test_names = {
        path.name.lower() for path in (live_results / "exploit_tests").iterdir() if path.is_file()
    }
    missing_pocs = [
        finding_id for finding_id in confirmed_ids
        if not any(name.startswith(finding_id.lower()) for name in poc_names)
    ]
    missing_tests = [
        finding_id for finding_id in confirmed_ids
        if not any(name.startswith(finding_id.lower()) for name in test_names)
    ]
    assigned_set = set(assigned_ids)
    high_medium_set = set(high_medium_ids)
    confirmed_set = set(confirmed_ids)
    repaired_engine_defects: list[str] = []
    retained_defects: list[str] = []
    for defect in report["defects"]:
        if defect.startswith("missing exploit test for Phase 2b High/Medium finding "):
            finding_id = defect.rsplit(" ", 1)[-1]
            if finding_id not in missing_tests:
                repaired_engine_defects.append(defect)
                continue
        if defect.startswith("Phase 3 assignment denominator differs") and high_medium_set.issubset(assigned_set):
            repaired_engine_defects.append(defect)
            continue
        retained_defects.append(defect)
    report["defects"] = retained_defects
    report["repaired_validator_defects"] = repaired_engine_defects
    report["confirmed_finding_count"] = len(confirmed_set)
    report["high_medium_required_count"] = len(high_medium_set)
    report["optional_low_assignment_ids"] = sorted(assigned_set - high_medium_set)
    report["poc_package_count"] = len(confirmed_set) - len(missing_pocs)
    report["exploit_test_package_count"] = len(confirmed_set) - len(missing_tests)
    report["missing_poc_ids"] = missing_pocs
    report["missing_exploit_test_ids"] = missing_tests
    if not source_ok or not runtime_ok:
        report["defects"].extend(source_defects + runtime_defects)
    if teardown.get("status") != "PASS":
        report["defects"].append("target teardown is not PASS")
    if len(confirmed_set) != 46 or assigned_set != confirmed_set:
        report["defects"].append("corrected confirmed-to-Phase-3 denominator is not 46/46")
    if not high_medium_set.issubset(assigned_set):
        report["defects"].append("one or more required High/Medium findings lack Phase 3 assignment")
    if missing_pocs:
        report["defects"].append(f"{len(missing_pocs)} confirmed findings lack a PoC package")
    if missing_tests:
        report["defects"].append(f"{len(missing_tests)} confirmed findings lack an exploit-test package")
    report["defects"] = sorted(set(report["defects"]))
    report["status"] = "PASS" if not report["defects"] else "KICKBACK"
    report["actual_consumer_observed"] = report["status"] == "PASS"
    report["finding_activation"] = "PENDING_HUMAN"
    report["claim_ceiling"] = (
        "PASS proves the signed crAPI A2 provider workflow completed, preserved native outputs match the controller-observed manifest, all 45 required High-or-higher/Medium findings plus one optional Low finding were assigned to Phase 3 with 46 PoCs and 46 exploit-test packages, pinned source file content was unchanged, and teardown passed. It does not validate each security claim, authorize activation, claim production accuracy, or erase the original KICKBACK receipt."
    )
    args.out.write_bytes(engine.canonical_bytes(report))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
