#!/usr/bin/env python3
"""Finalize a complete human decision set without promoting production findings."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

import prepare_review as common


SCHEMA = "ospt.vulnhunter-human-review-receipt.v2"
DISPOSITIONS = {
    "CONFIRMED_TRAINING_TARGET",
    "REJECTED",
    "NEEDS_MORE_EVIDENCE",
    "DUPLICATE",
    "OUT_OF_SCOPE",
}


def aware_time(value: Any) -> str:
    if not isinstance(value, str):
        raise common.Refusal("reviewed_at must be a timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise common.Refusal("reviewed_at is invalid") from exc
    if parsed.tzinfo is None:
        raise common.Refusal("reviewed_at must include a timezone")
    return parsed.isoformat().replace("+00:00", "Z")


def finalize(packet_path: Path, decisions_path: Path, transaction_time: str | None = None) -> dict[str, Any]:
    packet_path = common.regular_file(packet_path, "review packet")
    decisions_path = common.regular_file(decisions_path, "human decisions")
    packet = common.load_json(packet_path)
    decisions = common.load_json(decisions_path)
    if not isinstance(packet, dict) or packet.get("schema") != common.SCHEMA:
        raise common.Refusal("review packet schema differs")
    if not isinstance(decisions, dict) or decisions.get("schema") != common.DECISION_SCHEMA:
        raise common.Refusal("human decisions schema differs")
    if decisions.get("packet_sha256") != common.sha_file(packet_path):
        raise common.Refusal("human decisions do not bind the exact packet bytes")
    if decisions.get("review_subject_sha256") != packet.get("review_subject_sha256"):
        raise common.Refusal("human decisions bind a different review subject")
    if decisions.get("run_id") != packet.get("run_id"):
        raise common.Refusal("human decisions name a different run")
    reviewer = decisions.get("reviewer")
    if not isinstance(reviewer, dict) or reviewer.get("role") not in {"human_owner", "human_delegate"}:
        raise common.Refusal("reviewer must be a human owner or named human delegate")
    if not isinstance(reviewer.get("identity"), str) or not reviewer["identity"].strip():
        raise common.Refusal("human reviewer identity is required")
    effective_time = aware_time(decisions.get("reviewed_at"))
    duration = decisions.get("review_duration_minutes")
    if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration <= 0:
        raise common.Refusal("review_duration_minutes must be a positive number")

    candidate_ids = [item.get("candidate_id") for item in packet.get("candidates", [])]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise common.Refusal("packet candidate IDs are not unique")
    decision_items = decisions.get("decisions")
    if not isinstance(decision_items, list):
        raise common.Refusal("decisions must be a list")
    by_id: dict[str, dict[str, Any]] = {}
    for item in decision_items:
        if not isinstance(item, dict) or not isinstance(item.get("candidate_id"), str):
            raise common.Refusal("every decision needs a candidate ID")
        candidate_id = item["candidate_id"]
        if candidate_id in by_id:
            raise common.Refusal(f"duplicate decision for {candidate_id}")
        by_id[candidate_id] = item
    if set(by_id) != set(candidate_ids):
        raise common.Refusal("human decisions do not cover the exact candidate set")

    completed: list[dict[str, Any]] = []
    for candidate_id in candidate_ids:
        item = by_id[candidate_id]
        disposition = item.get("disposition")
        if disposition not in DISPOSITIONS:
            raise common.Refusal(f"{candidate_id} has no valid human disposition")
        if not isinstance(item.get("rationale"), str) or not item["rationale"].strip():
            raise common.Refusal(f"{candidate_id} needs a human rationale")
        checks = {
            "source_trace_verified": item.get("source_trace_verified") is True,
            "poc_reviewed": item.get("poc_reviewed") is True,
            "exploit_test_observed": item.get("exploit_test_observed") is True,
        }
        if disposition == "CONFIRMED_TRAINING_TARGET" and not all(checks.values()):
            raise common.Refusal(
                f"{candidate_id} cannot be confirmed without source, PoC, and observed exploit-test checks"
            )
        completed.append(
            {
                "candidate_id": candidate_id,
                "disposition": disposition,
                "rationale": item["rationale"].strip(),
                "checks": checks,
                "correction": item.get("correction"),
            }
        )

    return {
        "schema": SCHEMA,
        "run_id": packet["run_id"],
        "packet_path": str(packet_path),
        "packet_sha256": common.sha_file(packet_path),
        "decisions_path": str(decisions_path),
        "decisions_sha256": common.sha_file(decisions_path),
        "review_subject_sha256": packet["review_subject_sha256"],
        "reviewer": reviewer,
        "event_time": effective_time,
        "effective_time": effective_time,
        "transaction_time": transaction_time or common.now_z(),
        "review_state": "HUMAN_REVIEW_COMPLETE",
        "candidate_count": len(candidate_ids),
        "review_duration_minutes": duration,
        "minutes_per_candidate": round(duration / len(candidate_ids), 3),
        "disposition_counts": {
            key: sum(item["disposition"] == key for item in completed)
            for key in sorted(DISPOSITIONS)
        },
        "decisions": completed,
        "presentation_use_authorized": decisions.get("presentation_use_authorized") is True,
        "presentation_limits": decisions.get("presentation_limits"),
        "finding_activation_authorized": False,
        "deployment_authorized": False,
        "recurrence_authorized": False,
        "ci_enforcement_authorized": False,
        "publication_authorized": False,
        "claim_ceiling": "A named human reviewed every machine candidate against the hash-bound evidence for one pinned training-target run. No production finding, deployment, recurrence, CI, publication, provider-comparison, or population-accuracy claim is activated.",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--packet", type=Path, required=True)
    result.add_argument("--decisions", type=Path, required=True)
    result.add_argument("--out", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    receipt = finalize(args.packet, args.decisions)
    common.create_once(args.out.resolve(), receipt)
    print(json.dumps({"status": receipt["review_state"], "receipt": str(args.out), "candidate_count": receipt["candidate_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except common.Refusal as exc:
        print(f"REFUSED: {exc}")
        raise SystemExit(2)
