#!/usr/bin/env python3
"""Prepare a hash-bound, PENDING_HUMAN review packet from a completed VulnHunter run."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


SCHEMA = "ospt.vulnhunter-human-review-packet.v2"
DECISION_SCHEMA = "ospt.vulnhunter-human-decisions.v2"
RECONCILIATION_SCHEMAS = {
    "ospt.vulnhunter-a7-terminal-reconciliation.v1",
    "ospt.vulnhunter-crapi-additive-reconciliation.v1",
}


class Refusal(RuntimeError):
    pass


def now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Refusal(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(), object_pairs_hook=strict_object)
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(f"cannot load strict JSON from {path}") from exc


def create_once(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise Refusal(f"output already exists: {path}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_bytes(value))


def regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise Refusal(f"{label} must be one regular file: {path}")
    return path.resolve()


def directory_manifest(root: Path) -> tuple[list[dict[str, Any]], str]:
    if root.is_symlink() or not root.is_dir():
        raise Refusal("results must be one real directory")
    resolved = root.resolve()
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise Refusal(f"results contain a symlink: {path.relative_to(root)}")
        if not path.is_file():
            continue
        current = path.resolve()
        try:
            relative = current.relative_to(resolved).as_posix()
        except ValueError as exc:
            raise Refusal(f"result path escapes the root: {path}") from exc
        entries.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha_file(path)})
    return entries, sha_bytes(canonical_bytes(entries))


def controller_manifest_sha(root: Path) -> str:
    """Reproduce the VulnHunter controllers' path-to-digest manifest contract."""
    if root.is_symlink() or not root.is_dir():
        raise Refusal("results must be one real directory")
    resolved = root.resolve()
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise Refusal(f"results contain a symlink: {path.relative_to(root)}")
        if not path.is_file():
            continue
        current = path.resolve()
        try:
            relative = current.relative_to(resolved).as_posix()
        except ValueError as exc:
            raise Refusal(f"result path escapes the root: {path}") from exc
        manifest[relative] = sha_file(path)
    return sha_bytes(canonical_bytes(manifest))


def validation_chain(
    results: Path,
    validation_path: Path,
    raw_path: Path,
    reconciliation_path: Path | None,
) -> dict[str, Any]:
    validation = load_json(validation_path)
    if not isinstance(validation, dict):
        raise Refusal("native validation must be an object")
    native_sha = sha_file(validation_path)
    raw_sha = sha_file(raw_path)
    results_sha = controller_manifest_sha(results)

    if reconciliation_path is None:
        if validation.get("status") != "PASS" or validation.get("actual_consumer_observed") is not True:
            raise Refusal("native validation has not proved the actual consumer; an additive reconciliation is required")
        declared_results = validation.get("results_path")
        if declared_results and Path(str(declared_results)).resolve() != results:
            raise Refusal("native validation names a different results directory")
        declared_manifest = validation.get("results_manifest_sha256")
        if declared_manifest and declared_manifest != results_sha:
            raise Refusal("native validation results manifest differs from the supplied results")
        declared_raw = validation.get("raw_log_sha256")
        if declared_raw and declared_raw != raw_sha:
            raise Refusal("native validation raw-log digest differs from the supplied log")
        return {
            "mode": "DIRECT_NATIVE_PASS",
            "native_validation": {
                "path": str(validation_path),
                "sha256": native_sha,
                "status": "PASS",
                "actual_consumer_observed": True,
            },
            "reconciliation": None,
            "controller_results_manifest_sha256": results_sha,
        }

    reconciliation_path = regular_file(reconciliation_path, "additive reconciliation")
    reconciliation = load_json(reconciliation_path)
    if not isinstance(reconciliation, dict) or reconciliation.get("schema") not in RECONCILIATION_SCHEMAS:
        raise Refusal("unsupported additive reconciliation schema")
    schema = reconciliation["schema"]
    if schema == "ospt.vulnhunter-a7-terminal-reconciliation.v1":
        original = reconciliation.get("original_native_validation", {})
        corrected = reconciliation.get("corrected_validation", {})
        expected_results = reconciliation.get("frozen_inputs", {}).get(
            "preserved_results_manifest_sha256"
        )
        accepted = (
            reconciliation.get("status") == "RECONCILED_PASS"
            and corrected.get("status") == "PASS"
            and corrected.get("actual_consumer_observed") is True
        )
        expected_raw = corrected.get("raw_log_sha256")
    else:
        original = reconciliation.get("original_validation", {})
        corrected = reconciliation
        expected_results = reconciliation.get("preserved_results", {}).get(
            "manifest_sha256"
        ) or reconciliation.get("results_manifest_sha256")
        accepted = (
            reconciliation.get("status") == "PASS"
            and reconciliation.get("actual_consumer_observed") is True
        )
        expected_raw = reconciliation.get("raw_log_sha256")

    if not accepted:
        raise Refusal("additive reconciliation has not proved the actual consumer")
    if original.get("sha256") != native_sha:
        raise Refusal("additive reconciliation does not bind the exact original validation")
    if original.get("status") != validation.get("status"):
        raise Refusal("additive reconciliation and original validation status differ")
    if expected_raw != raw_sha:
        raise Refusal("additive reconciliation raw-log digest differs from the supplied log")
    if expected_results != results_sha:
        raise Refusal("additive reconciliation results manifest differs from the supplied results")
    return {
        "mode": "ADDITIVE_RECONCILIATION_PASS",
        "native_validation": {
            "path": str(validation_path),
            "sha256": native_sha,
            "status": validation.get("status"),
            "actual_consumer_observed": validation.get("actual_consumer_observed"),
            "preserved_not_rewritten": True,
        },
        "reconciliation": {
            "path": str(reconciliation_path),
            "sha256": sha_file(reconciliation_path),
            "schema": schema,
            "status": reconciliation.get("status"),
            "corrected_status": corrected.get("status"),
            "actual_consumer_observed": True,
        },
        "controller_results_manifest_sha256": results_sha,
    }


def clean_cell(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("**", "").replace(r"\|", "|").strip())


def split_table_row(value: str) -> list[str]:
    return [clean_cell(cell) for cell in re.split(r"(?<!\\)\|", value.strip().strip("|"))]


def extract_candidates(readme: Path) -> list[dict[str, str]]:
    lines = readme.read_text(errors="strict").splitlines()
    tables: list[list[dict[str, str]]] = []
    index = 0
    while index + 1 < len(lines):
        header_line, divider = lines[index], lines[index + 1]
        if not header_line.lstrip().startswith("|") or not re.match(
            r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*$", divider
        ):
            index += 1
            continue
        headers = [cell.lower() for cell in split_table_row(header_line)]
        rows: list[dict[str, str]] = []
        index += 2
        while index < len(lines) and lines[index].lstrip().startswith("|"):
            cells = split_table_row(lines[index])
            if len(cells) == len(headers):
                rows.append(dict(zip(headers, cells)))
            index += 1
        tables.append(rows)

    found: dict[str, dict[str, str]] = {}
    for rows in tables:
        for row in rows:
            raw_id = row.get("id", "")
            match = re.search(r"VULN-\d{3,}", raw_id, re.IGNORECASE)
            if not match:
                continue
            candidate_id = match.group(0).upper()
            exploit_test = row.get("exploit test", "")
            machine_status = row.get("status", "")
            if not machine_status and exploit_test.upper().startswith("CONDITIONAL"):
                machine_status = "CONDITIONAL"
            normalized = {
                "candidate_id": candidate_id,
                "title": row.get("title", ""),
                "cwe": row.get("cwe", ""),
                "severity": row.get("severity", ""),
                "machine_status": machine_status,
                "machine_row": " | ".join(row.values()),
            }
            if candidate_id in found and found[candidate_id] != normalized:
                previous = found[candidate_id]
                previous_quality = sum(bool(previous[key]) for key in ("title", "cwe", "severity", "machine_status"))
                current_quality = sum(bool(normalized[key]) for key in ("title", "cwe", "severity", "machine_status"))
                if previous_quality == current_quality:
                    raise Refusal(f"conflicting final-report rows for {candidate_id}")
                if current_quality > previous_quality:
                    found[candidate_id] = normalized
            else:
                found[candidate_id] = normalized
    return [found[key] for key in sorted(found)]


def artifacts_for(results: Path, candidate_id: str) -> dict[str, list[dict[str, Any]]]:
    number = candidate_id.split("-", 1)[1]
    poc_dir = results / "poc"
    test_dir = results / "exploit_tests"
    pocs = sorted(path for path in poc_dir.glob(f"{candidate_id}*") if path.is_file()) if poc_dir.is_dir() else []
    tests = (
        sorted(
            path
            for path in test_dir.iterdir()
            if path.is_file() and re.search(rf"vuln[_-]?0*{int(number)}(?:\D|$)", path.name, re.I)
        )
        if test_dir.is_dir()
        else []
    )
    if not pocs or not tests:
        raise Refusal(f"{candidate_id} lacks a matching PoC or exploit test")

    def records(paths: list[Path]) -> list[dict[str, Any]]:
        return [
            {
                "path": path.relative_to(results).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha_file(path),
            }
            for path in paths
        ]

    return {"poc": records(pocs), "exploit_test": records(tests)}


def build_packet(
    run_id: str,
    results: Path,
    native_validation: Path,
    raw_log: Path,
    reconciliation: Path | None = None,
    candidate_ids: list[str] | None = None,
    created_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not run_id.strip():
        raise Refusal("run ID is required")
    results = results.resolve()
    validation_path = regular_file(native_validation, "native validation")
    raw_path = regular_file(raw_log, "raw event log")
    chain = validation_chain(results, validation_path, raw_path, reconciliation)
    entries, manifest_sha = directory_manifest(results)
    readme = regular_file(results / "README.md", "final report")
    candidates = extract_candidates(readme)
    population_count = len(candidates)
    if candidate_ids is not None:
        requested = [item.strip().upper() for item in candidate_ids if item.strip()]
        if not requested or len(requested) != len(set(requested)):
            raise Refusal("candidate selection must be nonempty and unique")
        by_id = {item["candidate_id"]: item for item in candidates}
        missing = sorted(set(requested) - set(by_id))
        if missing:
            raise Refusal("requested candidate IDs are absent from the final report: " + ", ".join(missing))
        candidates = [by_id[item] for item in requested]
    prepared_candidates: list[dict[str, Any]] = []
    for candidate in candidates:
        prepared_candidates.append(
            {
                **candidate,
                "machine_state": "PENDING_HUMAN",
                "artifacts": artifacts_for(results, candidate["candidate_id"]),
            }
        )
    subject = {
        "run_id": run_id,
        "results_manifest_sha256": manifest_sha,
        "native_validation_sha256": sha_file(validation_path),
        "validation_chain_sha256": sha_bytes(canonical_bytes(chain)),
        "raw_event_log_sha256": sha_file(raw_path),
        "population_candidate_count": population_count,
        "selection": [item["candidate_id"] for item in prepared_candidates],
        "candidates": prepared_candidates,
    }
    subject_sha = sha_bytes(canonical_bytes(subject))
    packet = {
        "schema": SCHEMA,
        "created_at": created_at or now_z(),
        "run_id": run_id,
        "review_state": "PENDING_HUMAN",
        "review_subject_sha256": subject_sha,
        "validation_chain": chain,
        "raw_event_log": {"path": str(raw_path), "sha256": subject["raw_event_log_sha256"]},
        "results": {
            "path": str(results),
            "file_count": len(entries),
            "manifest_sha256": manifest_sha,
            "manifest": entries,
        },
        "population_candidate_count": population_count,
        "review_candidate_count": len(prepared_candidates),
        "selection_basis": "Explicit bounded candidate IDs" if candidate_ids is not None else "All final-report candidates",
        "candidate_count": len(prepared_candidates),
        "candidates": prepared_candidates,
        "claim_ceiling": "A direct or additively reconciled validation chain was transformed into a hash-bound human review surface. Every selected candidate remains PENDING_HUMAN; the selection does not estimate population accuracy and no finding, presentation, deployment, recurrence, CI, publication, or adoption authority exists.",
    }
    template = {
        "schema": DECISION_SCHEMA,
        "packet_sha256": None,
        "review_subject_sha256": subject_sha,
        "run_id": run_id,
        "reviewer": {"role": "human_owner", "identity": None},
        "reviewed_at": None,
        "review_duration_minutes": None,
        "presentation_use_authorized": False,
        "presentation_limits": "Private technical presentation only; training-target claims must remain labeled and source-bound.",
        "decisions": [
            {
                "candidate_id": candidate["candidate_id"],
                "disposition": None,
                "rationale": None,
                "source_trace_verified": False,
                "poc_reviewed": False,
                "exploit_test_observed": False,
                "correction": None,
            }
            for candidate in prepared_candidates
        ],
    }
    return packet, template


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--run-id", required=True)
    result.add_argument("--results", type=Path, required=True)
    result.add_argument("--native-validation", type=Path, required=True)
    result.add_argument("--raw-log", type=Path, required=True)
    result.add_argument("--reconciliation", type=Path)
    result.add_argument(
        "--candidate-ids",
        help="Comma-separated exact candidate IDs for a bounded review sample; omission selects all.",
    )
    result.add_argument("--out", type=Path, required=True)
    result.add_argument("--template-out", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    packet, template = build_packet(
        args.run_id,
        args.results,
        args.native_validation,
        args.raw_log,
        reconciliation=args.reconciliation,
        candidate_ids=args.candidate_ids.split(",") if args.candidate_ids else None,
    )
    create_once(args.out.resolve(), packet)
    template["packet_sha256"] = sha_file(args.out.resolve())
    create_once(args.template_out.resolve(), template)
    print(json.dumps({"status": "PENDING_HUMAN", "packet": str(args.out), "candidate_count": packet["candidate_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as exc:
        print(f"REFUSED: {exc}")
        raise SystemExit(2)
