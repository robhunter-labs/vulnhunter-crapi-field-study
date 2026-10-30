#!/usr/bin/env python3
"""Create a synthetic review exercise, never a validated run or human receipt."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import prepare_review as review


DEMO_SCHEMA = "vulnhunter.synthetic-review-exercise.v1"
REPORT = (
    "# Synthetic candidate report\n\n"
    "| ID | Title | CWE | Severity | Status |\n"
    "|---|---|---|---|---|\n"
    "| VULN-001 | Example search injection | CWE-89 | High | Candidate |\n"
)


def build_demo(out_dir: Path) -> tuple[Path, Path]:
    # A new directory is intentional: no existing review material is replaced.
    try:
        out_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise review.Refusal(f"demo output already exists: {out_dir}") from exc
    results = out_dir / "results"
    (results / "poc").mkdir(parents=True)
    (results / "exploit_tests").mkdir()
    (results / "README.md").write_text(REPORT, encoding="utf-8")
    (results / "poc" / "VULN-001_example.md").write_text(
        "Synthetic illustration only. No target was tested.\n", encoding="utf-8"
    )
    (results / "exploit_tests" / "test_vuln_001_example.txt").write_text(
        "NOT RUN — synthetic illustration.\n", encoding="utf-8"
    )

    candidate = review.extract_candidates(results / "README.md")[0]
    entries, manifest_sha = review.directory_manifest(results)
    packet = {
        "schema": DEMO_SCHEMA,
        "demo_only": True,
        "run_id": "SYNTHETIC-EXERCISE",
        "review_state": "DEMO_ONLY",
        "results_manifest_sha256": manifest_sha,
        "results": entries,
        "candidates": [
            {
                **candidate,
                "machine_state": "PENDING_HUMAN",
                "artifacts": review.artifacts_for(results, candidate["candidate_id"]),
            }
        ],
        "claim_ceiling": "Synthetic reader exercise only. No native validation, live target, human review, finding, or publication authority.",
    }
    packet_path = out_dir / "packet.demo.json"
    review.create_once(packet_path, packet)
    decision = {
        "schema": DEMO_SCHEMA,
        "demo_only": True,
        "packet_sha256": review.sha_file(packet_path),
        "candidate_id": candidate["candidate_id"],
        "example_disposition": "NEEDS_MORE_EVIDENCE",
        "why": "A report row and illustrative files cannot establish that the weakness exists.",
        "claim_ceiling": "This is an example of a question a reviewer might ask, not a human decision receipt.",
    }
    decision_path = out_dir / "decision.demo.json"
    review.create_once(decision_path, decision)
    return packet_path, decision_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True, help="New directory for disposable demo files")
    args = parser.parse_args()
    packet, decision = build_demo(args.out_dir)
    print(json.dumps({"status": "DEMO_ONLY", "packet": str(packet), "example_decision": str(decision)}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except review.Refusal as exc:
        print(f"REFUSED: {exc}")
        raise SystemExit(2)
