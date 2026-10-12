from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


PATH = Path(__file__).resolve().parents[1] / "full_vulnhunt_crapi_a2.py"
SPEC = importlib.util.spec_from_file_location("crapi_live", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
import sys
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CrAPIControllerTests(unittest.TestCase):
    def test_target_identity_is_exact(self):
        self.assertEqual(MODULE.TARGET_SOURCE_ID, "owasp-crapi-v1.1.6")
        self.assertEqual(MODULE.TARGET_COMMIT, "700f03d12a392d9e408260b4beae72ed02a4a1a4")
        self.assertEqual(MODULE.TARGET_EXPORT_FILE_COUNT, 1022)

    def test_budget_uses_completion_primary_and_eight_hour_watchdog(self):
        self.assertEqual(MODULE.MAX_COST_USD, 180.0)
        self.assertEqual(MODULE.MAX_SECONDS, 28800)
        self.assertEqual(MODULE.NO_PROGRESS_SECONDS, 1800)

    def test_crapi_fails_closed_instead_of_generic_target_restart(self):
        MODULE.install_engine_contract()
        self.assertEqual(MODULE.engine.TARGET_RESTART_LIMIT, 0)
        self.assertEqual(MODULE.engine.TARGET_HEALTH_FAILURE_LIMIT, 2)

    def test_execution_engine_is_exact_a4(self):
        self.assertEqual(MODULE.engine.sha_file(MODULE.A4_CONTROLLER), MODULE.A4_CONTROLLER_SHA256)

    def test_sidecar_scope_contract_is_local_and_non_dereferencing(self):
        self.assertIn("captured as inert JSON", MODULE.CLAUDE_TASK_OUTPUT_LINK_CONTRACT)
        self.assertIn("without dereference", MODULE.CLAUDE_TASK_OUTPUT_LINK_CONTRACT)
        source = PATH.read_text(encoding="utf-8")
        self.assertNotIn("engine.CLAUDE_TASK_OUTPUT_LINK_CONTRACT", source)

    def test_prompt_names_crapi_not_juice_shop(self):
        text = MODULE.prompt_for(Path("/x/target"), Path("/x/runtime"), Path("/x/results"))
        self.assertIn("OWASP/crAPI", text)
        self.assertIn("127.0.0.1:8888", text)
        self.assertNotIn("Juice Shop", text)
        self.assertIn("do not start, stop, rebuild, inspect, or replace", text)

    def test_settings_hide_answer_key_and_host_controls(self):
        settings = MODULE.project_settings(Path("/private/tmp/unit-workspace"))
        sandbox = settings["sandbox"]["filesystem"]
        self.assertIn(str(MODULE.HIDDEN_EVALUATOR_ROOT), sandbox["denyRead"])
        denied = settings["permissions"]["deny"]
        self.assertIn("Bash(docker *)", denied)
        self.assertIn("Bash(*8025*)", denied)

    def test_target_plan_has_no_docker_published_port(self):
        self.assertIn("tunnel:127.0.0.1:8888-only", MODULE.target_service_argv(Path("/x")))

    def test_label_rewrite_removes_stale_target(self):
        value = MODULE.replace_stale_labels({"x": "complete full pinned Juice Shop"})
        self.assertEqual(value["x"], "complete full pinned crAPI")

    def test_qualification_bindings_are_green(self):
        bindings = MODULE.qualification_bindings()
        self.assertEqual(len(bindings), 11)
        self.assertTrue(all(row["sha256"].startswith("sha256:") for row in bindings.values()))

    def test_scope_rejects_budget_change_before_workspace_read(self):
        with self.assertRaises(MODULE.Refusal):
            MODULE.build_scope(str(MODULE.LIVE_WORKSPACE_PATH), "2026-08-27T23:00:00Z", 181.0, MODULE.MAX_SECONDS)

    def test_scope_rejects_workspace_change_before_workspace_read(self):
        with self.assertRaises(MODULE.Refusal):
            MODULE.build_scope("/private/tmp/wrong", "2026-08-27T23:00:00Z", MODULE.MAX_COST_USD, MODULE.MAX_SECONDS)

    def test_prepared_workspace_requires_exact_location(self):
        with self.assertRaises(MODULE.Refusal):
            MODULE.inspect_prepared_workspace(Path("/private/tmp/wrong"))

    def test_target_start_refuses_reused_control_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            original = MODULE.TARGET_CONTROL_EVIDENCE
            MODULE.TARGET_CONTROL_EVIDENCE = Path(raw)
            try:
                with self.assertRaises(MODULE.Refusal):
                    MODULE.start_target_service(Path("/unused"))
            finally:
                MODULE.TARGET_CONTROL_EVIDENCE = original

    def test_web_health_is_failure_closed(self):
        with mock.patch.object(MODULE.qualifier, "http_json", side_effect=OSError("closed")):
            self.assertEqual(MODULE.target_health(), (False, "OSError: closed"))

    def test_engine_contract_replaces_core_functions(self):
        MODULE.install_engine_contract()
        self.assertIs(MODULE.engine.build_scope, MODULE.build_scope)
        self.assertIs(MODULE.engine.start_target_service, MODULE.start_target_service)
        self.assertEqual(MODULE.engine.RUN_ID, MODULE.RUN_ID)

    def test_parser_has_no_dependency_install_command(self):
        choices = MODULE.parser()._subparsers._group_actions[0].choices
        self.assertEqual(set(choices), {"prepare", "preflight", "scope", "run", "validate"})

    def test_scope_schema_is_distinct_from_juice_shop(self):
        self.assertEqual(MODULE.SCHEMA, "ospt.full-vulnhunter-crapi-run.v2")


if __name__ == "__main__":
    unittest.main()
