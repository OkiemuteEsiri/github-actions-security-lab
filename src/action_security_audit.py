from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

SEVERITY_SCORE = {"low": 10, "medium": 35, "high": 70, "critical": 95}

@dataclass
class Finding:
    workflow: str
    control: str
    severity: str
    evidence: str
    remediation: str

    @property
    def score(self) -> int:
        return SEVERITY_SCORE[self.severity]


def _is_immutable_ref(ref: str) -> bool:
    return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())


def audit_workflow(workflow: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    name = workflow["name"]
    trigger = workflow.get("trigger", "push")
    permissions = set(workflow.get("permissions", []))

    if {"contents:write", "actions:write", "packages:write"} & permissions:
        sev = "critical" if trigger == "pull_request_target" else "high"
        findings.append(Finding(name, "least-privilege-token", sev,
            f"Broad token permissions: {sorted(permissions)}",
            "Reduce GITHUB_TOKEN permissions to job-level minimums."))

    if trigger == "pull_request_target" and workflow.get("checks_out_pr_head", False):
        findings.append(Finding(name, "untrusted-pr-execution", "critical",
            "pull_request_target checks out contributor-controlled head content",
            "Do not execute untrusted PR code in privileged pull_request_target context."))

    for action in workflow.get("actions", []):
        ref = action.get("ref", "")
        source = action.get("source", "")
        if source != "local" and not _is_immutable_ref(ref):
            findings.append(Finding(name, "immutable-action-reference", "high",
                f"{source}@{ref} is mutable",
                "Pin third-party actions to a reviewed full commit SHA."))

    if workflow.get("uses_long_lived_secret", False):
        findings.append(Finding(name, "credential-lifetime", "high",
            "Long-lived deployment credential configured",
            "Prefer short-lived OIDC federation and narrowly scoped trust policies."))

    if workflow.get("deploys", False) and not workflow.get("protected_environment", False):
        findings.append(Finding(name, "deployment-protection", "medium",
            "Deployment job has no protected environment",
            "Use protected environments with reviewers and scoped environment secrets."))

    for expression in workflow.get("shell_expressions", []):
        if "github.event" in expression and "${{" in expression:
            findings.append(Finding(name, "script-injection", "high",
                f"Untrusted context interpolated into shell: {expression}",
                "Move untrusted context into an environment variable and validate it before use."))

    return findings


def assess(inventory: list[dict[str, Any]]) -> dict[str, Any]:
    findings = [f for workflow in inventory for f in audit_workflow(workflow)]
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_SCORE}
    risk_score = max((f.score for f in findings), default=0)
    return {
        "workflow_count": len(inventory),
        "finding_count": len(findings),
        "severity_counts": counts,
        "highest_risk_score": risk_score,
        "findings": [asdict(f) | {"score": f.score} for f in findings],
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python action_security_audit.py <workflow-inventory.json>")
        return 2
    inventory = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    report = assess(inventory)
    print(json.dumps(report, indent=2))
    return 1 if report["severity_counts"]["critical"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
