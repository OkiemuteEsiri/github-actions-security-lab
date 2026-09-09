# GitHub Actions Security Lab

A defensive DevSecOps engineering project for reviewing GitHub Actions workflows against common CI/CD security risks. The lab analyzes synthetic workflow metadata, identifies risky configuration patterns, scores findings, and produces remediation-oriented output.

## Problem statement
CI/CD pipelines often hold powerful repository permissions, consume third-party actions, handle deployment credentials, and execute code from pull requests. Weak workflow design can turn a repository automation feature into a supply-chain risk.

This project demonstrates how to convert workflow-security requirements into deterministic, testable controls.

## What this project checks
- excessive `GITHUB_TOKEN` permissions
- unpinned third-party actions
- mutable action references such as branches and tags
- unsafe use of `pull_request_target`
- long-lived or broadly scoped credentials
- missing environment protection for deployment jobs
- untrusted fork execution paths
- script injection exposure through untrusted context values
- missing dependency/provenance controls

## Architecture
`data/workflows.json` -> `src/action_security_audit.py` -> normalized findings -> severity/risk score -> remediation report.

The implementation is intentionally defensive. It does not exploit workflows, steal tokens, execute payloads, or target real repositories.

## Repository structure
```text
.github/workflows/ci.yml       Security-focused CI
src/action_security_audit.py   Audit and scoring engine
data/workflows.json            Synthetic workflow inventory
tests/test_action_security_audit.py
                               Unit tests
docs/architecture.md           Technical design
docs/methodology.md            Assessment methodology
docs/remediation-validation.md Remediation and re-test workflow
reports/example-assessment.md  Example recruiter-facing output
```

## Usage
```bash
python src/action_security_audit.py data/workflows.json
python -m unittest discover -s tests -v
```

## Risk model
Each finding is assigned a severity and an explainable score. Critical risks include privileged execution of untrusted code or broad token permissions in dangerous trigger contexts. High risks include mutable action references, unmanaged deployment credentials, and missing protected environments.

## Security engineering principles demonstrated
- least privilege
- immutable dependencies
- protected deployment boundaries
- untrusted input handling
- supply-chain integrity
- policy-as-code
- test-driven security controls
- remediation verification

## MITRE ATT&CK context
The project is defensive and maps relevant scenarios to techniques such as:
- **T1195 – Supply Chain Compromise**
- **T1552 – Unsecured Credentials**
- **T1078 – Valid Accounts**

These mappings describe risk context, not offensive implementation.

## Limitations
The analyzer operates on normalized synthetic workflow metadata rather than parsing arbitrary production YAML. It is designed to demonstrate security-control engineering, not replace GitHub Advanced Security, CodeQL, OIDC design review, or manual threat modeling.

## Roadmap
- native YAML parsing
- reusable organization policy packs
- SARIF output
- repository ruleset correlation
- OIDC trust-policy review
- SBOM/provenance validation

## Safety
All examples are synthetic. No credentials, proprietary workflows, employer/client information, or production repositories are included.