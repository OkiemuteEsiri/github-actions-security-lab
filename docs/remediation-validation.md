# Remediation and Revalidation Playbook

## Critical: privileged untrusted execution
**Remediation:** separate untrusted PR validation from privileged release workflows. Do not checkout contributor-controlled head content inside `pull_request_target` jobs with write permissions or secrets.

**Validation:** confirm the privileged workflow no longer executes contributor code, verify token permissions, and re-run the analyzer.

## High: broad token permissions
**Remediation:** set workflow permissions to read-only by default and grant narrower job-level permissions only where required.

**Validation:** inspect generated workflow token scopes and ensure write permissions exist only in intended trusted jobs.

## High: mutable third-party actions
**Remediation:** replace tags/branches with reviewed full commit SHAs and implement dependency update governance.

**Validation:** confirm each external action resolves to the approved SHA and review update diffs before changing pins.

## High: long-lived credentials
**Remediation:** migrate to short-lived OIDC federation where supported and restrict trust conditions.

**Validation:** verify no static deployment secret remains, inspect trust-policy subject/audience conditions, and test intended deployment access.

## High: script injection
**Remediation:** avoid directly interpolating event-controlled values in shell code. Pass them via environment variables and validate expected formats.

**Validation:** use synthetic hostile-looking strings as test data and confirm they are treated as data rather than executable shell syntax.

## Medium: missing deployment protection
**Remediation:** configure protected environments, appropriate reviewers, branch restrictions, and environment-scoped credentials.

**Validation:** confirm deployments from unauthorized refs or actors are blocked while approved release paths remain functional.

## Closure evidence
A finding is closed only when configuration evidence, successful security-control re-evaluation, and intended-function validation are available.