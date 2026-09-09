# Architecture

## Objective
The lab separates workflow inventory, control evaluation, scoring, reporting, and validation so each layer can be reviewed independently.

## Components
1. **Synthetic workflow inventory** – normalized metadata representing triggers, permissions, action references, deployment properties, and trust boundaries.
2. **Control engine** – evaluates deterministic security controls in `src/action_security_audit.py`.
3. **Risk model** – maps findings to low/medium/high/critical scores while retaining evidence and remediation.
4. **Validation layer** – unit tests protect control behavior and regression cases.
5. **CI layer** – executes tests and the analyzer against the synthetic dataset.

## Trust boundaries
The highest-risk boundary is execution of contributor-controlled content with privileged workflow context. Other important boundaries include third-party action integrity, deployment credentials, protected environments, and shell interpolation of event data.

## Design choices
- normalized JSON keeps the lab deterministic and safe
- evidence is stored with every finding to support analyst review
- remediation text is generated with findings rather than added later
- exit status distinguishes critical posture from ordinary reporting

## Extensibility
Future adapters can parse YAML, organization policy exports, or repository APIs into the same normalized model without changing core control logic.