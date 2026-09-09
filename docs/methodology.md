# Assessment Methodology

## 1. Inventory
Collect workflow trigger, token permission, action dependency, deployment, credential, and shell-expression metadata. This lab uses synthetic data only.

## 2. Evaluate trust context
Determine whether contributor-controlled content can execute in a privileged context. `pull_request_target` combined with contributor head checkout is treated as critical because repository secrets or write permissions may become reachable.

## 3. Review permissions
Evaluate `GITHUB_TOKEN` scope against least privilege. Write access is not automatically a defect, but broad write access materially increases impact when the workflow trigger is untrusted.

## 4. Validate dependency integrity
Third-party actions should be pinned to immutable reviewed commit SHAs. Branches and tags are treated as mutable references.

## 5. Review credential architecture
Prefer short-lived identity federation such as OIDC over persistent cloud credentials. Scope trust policies to repository, branch/environment, and intended audience.

## 6. Review deployment boundary
Production-like deployments should use protected environments, reviewers where appropriate, and environment-scoped credentials.

## 7. Review input handling
Event properties may be attacker-controlled. Avoid direct interpolation into shell commands; pass data through environment variables and validate before use.

## 8. Prioritize and validate
Critical findings are addressed first, followed by high-risk dependency, credential, and privilege findings. Re-run the analyzer and unit tests after remediation and retain evidence of the corrected configuration.

## ATT&CK context
- T1195 Supply Chain Compromise
- T1552 Unsecured Credentials
- T1078 Valid Accounts

ATT&CK references provide defensive threat context only.