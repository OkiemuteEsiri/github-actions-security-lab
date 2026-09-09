import importlib.util
import pathlib
import sys
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "src" / "action_security_audit.py"
spec = importlib.util.spec_from_file_location("action_security_audit", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class ActionSecurityAuditTests(unittest.TestCase):
    def test_safe_workflow_has_no_findings(self):
        workflow = {
            "name": "safe",
            "trigger": "pull_request",
            "permissions": ["contents:read"],
            "actions": [{"source": "actions/checkout", "ref": "a" * 40}],
        }
        self.assertEqual(module.audit_workflow(workflow), [])

    def test_mutable_action_reference_is_high(self):
        workflow = {
            "name": "mutable",
            "actions": [{"source": "actions/checkout", "ref": "v4"}],
        }
        findings = module.audit_workflow(workflow)
        self.assertEqual(findings[0].control, "immutable-action-reference")
        self.assertEqual(findings[0].severity, "high")

    def test_privileged_pr_target_is_critical(self):
        workflow = {
            "name": "danger",
            "trigger": "pull_request_target",
            "permissions": ["contents:write"],
            "checks_out_pr_head": True,
        }
        severities = [f.severity for f in module.audit_workflow(workflow)]
        self.assertIn("critical", severities)

    def test_deployment_without_environment_is_medium(self):
        workflow = {"name": "deploy", "deploys": True, "protected_environment": False}
        findings = module.audit_workflow(workflow)
        self.assertTrue(any(f.control == "deployment-protection" for f in findings))

    def test_assessment_aggregates_counts(self):
        inventory = [
            {"name": "one", "actions": [{"source": "vendor/x", "ref": "main"}]},
            {"name": "two", "uses_long_lived_secret": True},
        ]
        report = module.assess(inventory)
        self.assertEqual(report["workflow_count"], 2)
        self.assertEqual(report["finding_count"], 2)
        self.assertEqual(report["severity_counts"]["high"], 2)


if __name__ == "__main__":
    unittest.main()
