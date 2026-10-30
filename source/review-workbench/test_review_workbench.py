#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import finalize_review  # noqa: E402
import prepare_review  # noqa: E402
import demo_first_use  # noqa: E402


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def write_json(path: Path, value: object) -> None:
    path.write_bytes(prepare_review.canonical_bytes(value))


def fixture(root: Path, *, validation_pass: bool = True) -> tuple[Path, Path, Path]:
    results = root / "results"
    (results / "poc").mkdir(parents=True)
    (results / "exploit_tests").mkdir()
    (results / "README.md").write_text(
        "# Report\n\n| ID | Title | CWE | Severity | Status |\n"
        "|---|---|---|---|---|\n"
        "| VULN-001 | Search injection | CWE-89 | High | Confirmed |\n"
    )
    (results / "phase1_output.md").write_text("complete\n")
    (results / "poc" / "VULN-001_search.md").write_text("proof\n")
    (results / "exploit_tests" / "test_vuln_001_search.py").write_text("PASS\n")
    raw = root / "raw.jsonl"
    raw.write_text('{"type":"result"}\n')
    validation = root / "validation.json"
    write_json(
        validation,
        {
            "schema": "field-study.full-vulnhunter-native-validation.v1",
            "status": "PASS" if validation_pass else "KICKBACK",
            "actual_consumer_observed": validation_pass,
            "synthetic_fixture": False,
            "defects": [],
            "controller_binding": {"scope_sha256": "fixture-scope"},
            "results_path": str(results.resolve()),
            "results_manifest_sha256": prepare_review.controller_manifest_sha(results),
            "raw_log_sha256": prepare_review.sha_file(raw),
        },
    )
    return results, validation, raw


def prepared(root: Path) -> tuple[Path, Path, dict, dict]:
    results, validation, raw = fixture(root)
    packet, template = prepare_review.build_packet(
        "TEST-RUN", results, validation, raw, created_at="2026-08-26T00:00:00Z"
    )
    packet_path = root / "packet.json"
    write_json(packet_path, packet)
    template["packet_sha256"] = prepare_review.sha_file(packet_path)
    decisions_path = root / "decisions.json"
    return packet_path, decisions_path, packet, template


def reconciled_fixture(root: Path) -> tuple[Path, Path, Path, Path]:
    results, validation, raw = fixture(root, validation_pass=False)
    reconciliation = root / "reconciliation.json"
    write_json(
        reconciliation,
        {
            "schema": "field-study.vulnhunter-a7-terminal-reconciliation.v1",
            "status": "RECONCILED_PASS",
            "original_native_validation": {
                "sha256": prepare_review.sha_file(validation),
                "status": "KICKBACK",
            },
            "corrected_validation": {
                "status": "PASS",
                "actual_consumer_observed": True,
                "raw_log_sha256": prepare_review.sha_file(raw),
            },
            "frozen_inputs": {
                "preserved_results_manifest_sha256": prepare_review.controller_manifest_sha(results)
            },
        },
    )
    return results, validation, raw, reconciliation


def test_prepare_binds_candidate_and_artifacts() -> None:
    with tempfile.TemporaryDirectory() as name:
        results, validation, raw = fixture(Path(name))
        packet, template = prepare_review.build_packet("TEST-RUN", results, validation, raw)
        check(packet["candidate_count"] == 1, "one candidate extracted")
        check(packet["candidates"][0]["machine_state"] == "PENDING_HUMAN", "machine cannot decide")
        check(len(packet["candidates"][0]["artifacts"]["poc"]) == 1, "PoC bound")
        check(template["decisions"][0]["disposition"] is None, "human blank preserved")


def test_extract_prefers_richer_row_with_escaped_table_pipe() -> None:
    with tempfile.TemporaryDirectory() as name:
        report = Path(name) / "README.md"
        report.write_text(
            "| ID | Title | CWE | Severity | Exploit Test | Status |\n"
            "|---|---|---|---|---|---|\n"
            "| VULN-001 | Rich title | CWE-89 | High | PASS — PoC \\| Test | Confirmed |\n\n"
            "| ID | PoC | Test |\n|---|---|---|\n| VULN-001 | poc | test |\n"
        )
        candidates = prepare_review.extract_candidates(report)
        check(candidates[0]["title"] == "Rich title", "richer report row retained")
        check(candidates[0]["machine_status"] == "Confirmed", "escaped pipe parsed")


def test_prepare_refuses_unproved_consumer() -> None:
    with tempfile.TemporaryDirectory() as name:
        results, validation, raw = fixture(Path(name), validation_pass=False)
        try:
            prepare_review.build_packet("TEST-RUN", results, validation, raw)
        except prepare_review.Refusal as exc:
            check("actual consumer" in str(exc), "consumer refusal explains gate")
        else:
            raise AssertionError("KICKBACK validation was accepted")


def test_prepare_direct_pass_requires_exact_evidence_bindings() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        results, validation, raw = fixture(root)
        original = prepare_review.load_json(validation)
        for field in ("results_path", "results_manifest_sha256", "raw_log_sha256"):
            for broken in (None, "", "wrong"):
                value = dict(original)
                if broken is None:
                    del value[field]
                else:
                    value[field] = broken
                write_json(validation, value)
                try:
                    prepare_review.build_packet("TEST-RUN", results, validation, raw)
                except prepare_review.Refusal:
                    pass
                else:
                    raise AssertionError(f"direct PASS accepted {field}={broken!r}")
        write_json(validation, original)
        packet, _ = prepare_review.build_packet("TEST-RUN", results, validation, raw)
        check(packet["validation_chain"]["mode"] == "DIRECT_NATIVE_PASS", "bound native PASS remains usable")


def test_prepare_direct_pass_refuses_synthetic_or_defect_bearing_record() -> None:
    with tempfile.TemporaryDirectory() as name:
        results, validation, raw = fixture(Path(name))
        original = prepare_review.load_json(validation)
        for field, replacement in (("synthetic_fixture", True), ("defects", ["unresolved"]),
                                   ("controller_binding", None), ("schema", "other")):
            changed = dict(original)
            changed[field] = replacement
            write_json(validation, changed)
            try:
                prepare_review.build_packet("TEST-RUN", results, validation, raw)
            except prepare_review.Refusal:
                pass
            else:
                raise AssertionError(f"direct PASS accepted {field}={replacement!r}")


def test_prepare_refuses_results_changed_after_validation_chain() -> None:
    with tempfile.TemporaryDirectory() as name:
        results, validation, raw = fixture(Path(name))
        original_chain = prepare_review.validation_chain

        def changed_chain(*args: object) -> dict:
            chain = original_chain(*args)
            (results / "README.md").write_text("changed after validation\n")
            return chain

        prepare_review.validation_chain = changed_chain
        try:
            try:
                prepare_review.build_packet("TEST-RUN", results, validation, raw)
            except prepare_review.Refusal as exc:
                check("results changed" in str(exc), "snapshot drift refused")
            else:
                raise AssertionError("changed results were accepted")
        finally:
            prepare_review.validation_chain = original_chain


def test_prepare_accepts_additive_reconciliation_without_rewriting_failure() -> None:
    with tempfile.TemporaryDirectory() as name:
        results, validation, raw, reconciliation = reconciled_fixture(Path(name))
        packet, _template = prepare_review.build_packet(
            "TEST-RUN", results, validation, raw, reconciliation=reconciliation
        )
        chain = packet["validation_chain"]
        check(chain["mode"] == "ADDITIVE_RECONCILIATION_PASS", "additive chain retained")
        check(chain["native_validation"]["status"] == "KICKBACK", "original failure retained")
        check(chain["reconciliation"]["actual_consumer_observed"] is True, "correction observed")


def test_prepare_refuses_wrong_original_or_results_binding() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        results, validation, raw, reconciliation = reconciled_fixture(root)
        value = prepare_review.load_json(reconciliation)
        value["original_native_validation"]["sha256"] = "sha256:" + "0" * 64
        bad_original = root / "bad-original.json"
        write_json(bad_original, value)
        try:
            prepare_review.build_packet(
                "TEST-RUN", results, validation, raw, reconciliation=bad_original
            )
        except prepare_review.Refusal as exc:
            check("exact original" in str(exc), "wrong original digest refused")
        else:
            raise AssertionError("wrong original validation digest was accepted")
        value = prepare_review.load_json(reconciliation)
        value["frozen_inputs"]["preserved_results_manifest_sha256"] = "sha256:" + "1" * 64
        bad_results = root / "bad-results.json"
        write_json(bad_results, value)
        try:
            prepare_review.build_packet(
                "TEST-RUN", results, validation, raw, reconciliation=bad_results
            )
        except prepare_review.Refusal as exc:
            check("results manifest" in str(exc), "wrong results digest refused")
        else:
            raise AssertionError("wrong results manifest was accepted")


def test_prepare_exact_subset_and_missing_id_refusal() -> None:
    with tempfile.TemporaryDirectory() as name:
        results, validation, raw = fixture(Path(name))
        packet, _template = prepare_review.build_packet(
            "TEST-RUN", results, validation, raw, candidate_ids=["VULN-001"]
        )
        check(packet["review_candidate_count"] == 1, "bounded sample retained")
        check(packet["population_candidate_count"] == 1, "population denominator retained")
        try:
            prepare_review.build_packet(
                "TEST-RUN", results, validation, raw, candidate_ids=["VULN-999"]
            )
        except prepare_review.Refusal as exc:
            check("absent" in str(exc), "missing sample member refused")
        else:
            raise AssertionError("missing candidate ID was accepted")


def test_prepare_refuses_result_symlink() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        results, validation, raw = fixture(root)
        (results / "escape").symlink_to(root / "raw.jsonl")
        try:
            prepare_review.build_packet("TEST-RUN", results, validation, raw)
        except prepare_review.Refusal as exc:
            check("symlink" in str(exc), "symlink refusal explains defect")
        else:
            raise AssertionError("result symlink was accepted")


def test_create_once_refuses_overwrite() -> None:
    with tempfile.TemporaryDirectory() as name:
        output = Path(name) / "output.json"
        prepare_review.create_once(output, {"first": True})
        try:
            prepare_review.create_once(output, {"second": True})
        except prepare_review.Refusal as exc:
            check("already exists" in str(exc), "overwrite refusal explains defect")
        else:
            raise AssertionError("create-once output was overwritten")


def test_finalize_refuses_fake_reviewer_and_digest_drift() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        packet_path, decisions_path, _packet, template = prepared(root)
        template["reviewer"] = {"role": "model", "identity": "agent"}
        template["reviewed_at"] = "2026-08-26T01:00:00Z"
        template["review_duration_minutes"] = 1
        write_json(decisions_path, template)
        try:
            finalize_review.finalize(packet_path, decisions_path)
        except prepare_review.Refusal as exc:
            check("human" in str(exc), "fake reviewer refused")
        else:
            raise AssertionError("model reviewer was accepted")
        template["reviewer"] = {"role": "human_owner", "identity": "owner"}
        template["packet_sha256"] = "sha256:" + "0" * 64
        write_json(root / "drift.json", template)
        try:
            finalize_review.finalize(packet_path, root / "drift.json")
        except prepare_review.Refusal as exc:
            check("exact packet" in str(exc), "packet drift refused")
        else:
            raise AssertionError("digest drift was accepted")


def test_confirmed_requires_three_human_checks() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        packet_path, decisions_path, _packet, template = prepared(root)
        template["reviewer"]["identity"] = "owner"
        template["reviewed_at"] = "2026-08-26T01:00:00Z"
        template["review_duration_minutes"] = 1
        template["decisions"][0].update(
            {"disposition": "CONFIRMED_TRAINING_TARGET", "rationale": "Trace supports it."}
        )
        write_json(decisions_path, template)
        try:
            finalize_review.finalize(packet_path, decisions_path)
        except prepare_review.Refusal as exc:
            check("source, PoC" in str(exc), "missing checks refused")
        else:
            raise AssertionError("unchecked confirmation was accepted")


def test_finalize_complete_review_keeps_authority_bounded() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        packet_path, decisions_path, _packet, template = prepared(root)
        template["reviewer"]["identity"] = "owner"
        template["reviewed_at"] = "2026-08-26T01:00:00Z"
        template["review_duration_minutes"] = 2.5
        template["presentation_use_authorized"] = True
        template["decisions"][0].update(
            {
                "disposition": "CONFIRMED_TRAINING_TARGET",
                "rationale": "Independent source trace and retained proof agree.",
                "source_trace_verified": True,
                "poc_reviewed": True,
                "exploit_test_observed": True,
            }
        )
        write_json(decisions_path, template)
        receipt = finalize_review.finalize(
            packet_path, decisions_path, "2026-08-26T01:01:00Z"
        )
        check(receipt["review_state"] == "HUMAN_REVIEW_COMPLETE", "review completed")
        check(receipt["presentation_use_authorized"] is True, "presentation decision retained")
        check(receipt["finding_activation_authorized"] is False, "finding activation remains false")
        check(receipt["publication_authorized"] is False, "publication remains false")
        check(receipt["minutes_per_candidate"] == 2.5, "review burden measured")


def test_finalize_refuses_missing_review_duration() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        packet_path, decisions_path, _packet, template = prepared(root)
        template["reviewer"]["identity"] = "owner"
        template["reviewed_at"] = "2026-08-26T01:00:00Z"
        template["decisions"][0].update(
            {"disposition": "REJECTED", "rationale": "The retained evidence does not support it."}
        )
        write_json(decisions_path, template)
        try:
            finalize_review.finalize(packet_path, decisions_path)
        except prepare_review.Refusal as exc:
            check("review_duration_minutes" in str(exc), "missing duration refused")
        else:
            raise AssertionError("missing review duration was accepted")


def test_synthetic_first_use_cannot_be_finalized_as_a_real_review() -> None:
    with tempfile.TemporaryDirectory() as name:
        packet_path, decision_path = demo_first_use.build_demo(Path(name) / "walkthrough")
        packet = prepare_review.load_json(packet_path)
        decision = prepare_review.load_json(decision_path)
        check(packet["schema"] == demo_first_use.DEMO_SCHEMA, "demo has a distinct schema")
        check(packet["demo_only"] is True and packet["review_state"] == "DEMO_ONLY", "demo status is visible")
        check(packet["candidates"][0]["candidate_id"] == "VULN-001", "one candidate is readable")
        check(decision["example_disposition"] == "NEEDS_MORE_EVIDENCE", "example avoids a finding claim")
        try:
            finalize_review.finalize(packet_path, decision_path)
        except prepare_review.Refusal as exc:
            check("schema differs" in str(exc), "real finalizer refuses demo packet")
        else:
            raise AssertionError("synthetic demo became a real review receipt")
        try:
            demo_first_use.build_demo(Path(name) / "walkthrough")
        except prepare_review.Refusal as exc:
            check("already exists" in str(exc), "repeat demo refuses without replacing output")
        else:
            raise AssertionError("repeat demo replaced earlier output")


def main() -> None:
    tests = [
        test_prepare_binds_candidate_and_artifacts,
        test_extract_prefers_richer_row_with_escaped_table_pipe,
        test_prepare_refuses_unproved_consumer,
        test_prepare_direct_pass_requires_exact_evidence_bindings,
        test_prepare_direct_pass_refuses_synthetic_or_defect_bearing_record,
        test_prepare_refuses_results_changed_after_validation_chain,
        test_prepare_accepts_additive_reconciliation_without_rewriting_failure,
        test_prepare_refuses_wrong_original_or_results_binding,
        test_prepare_exact_subset_and_missing_id_refusal,
        test_prepare_refuses_result_symlink,
        test_create_once_refuses_overwrite,
        test_finalize_refuses_fake_reviewer_and_digest_drift,
        test_confirmed_requires_three_human_checks,
        test_finalize_complete_review_keeps_authority_bounded,
        test_finalize_refuses_missing_review_duration,
        test_synthetic_first_use_cannot_be_finalized_as_a_real_review,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS {len(tests)}/{len(tests)}")


if __name__ == "__main__":
    main()
