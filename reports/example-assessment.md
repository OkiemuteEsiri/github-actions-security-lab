# Example GitHub Actions Security Assessment

> All workflows and observations in this report are synthetic.

## Executive summary
The sample inventory contains three workflows. One intentionally unsafe release example demonstrates how multiple individually risky choices can combine into a critical CI/CD trust-boundary failure.

## Key observations
| Workflow | Risk | Observation |
|---|---|---|
| build-and-test | Low | Read-only token and immutable action references |
| unsafe-release-example | Critical | Privileged `pull_request_target` context executes contributor head content |
| protected-deploy | Low | OIDC-style permission model and protected deployment boundary |

## Priority remediation
1. Remove contributor-head execution from the privileged release context.
2. Reduce write permissions to the minimum required trusted release job.
3. Pin external actions to reviewed full commit SHAs.
4. Replace persistent deployment credentials with short-lived federation.
5. Protect deployment environments and scope approvals.
6. Remove direct interpolation of event-controlled values into shell expressions.

## Validation criteria
The critical release path is considered remediated when privileged workflows no longer execute untrusted PR content, external actions are immutable, persistent deployment secrets are removed, and deployment controls are enforced.

## Strategic outcome
The exercise demonstrates CI/CD security as an engineering discipline: identify trust boundaries, encode controls, measure risk, remediate configuration, and validate that risk has actually been reduced.