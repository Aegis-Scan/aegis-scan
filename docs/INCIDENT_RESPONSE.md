# Incident Response Runbook

## Purpose

This runbook defines how Aegis incidents are detected, triaged, contained, and closed.

## Severity Levels

- `SEV-1`: Active compromise, critical data exposure, or systemic outage.
- `SEV-2`: High-risk issue with limited blast radius.
- `SEV-3`: Security defect with workaround and low immediate impact.
- `SEV-4`: Informational or low-risk finding.

## Response Roles

- `Incident Commander (IC)`: Owns decisions and coordination.
- `Operations Lead`: Runs containment/recovery actions.
- `Comms Lead`: Handles internal and external updates.
- `Scribe`: Maintains timeline, actions, and evidence.

## Detection and Triage

1. Open incident ticket with timestamp, reporter, and suspected impact.
2. Assign severity and owner within 15 minutes.
3. Start incident timeline and preserve relevant logs/artifacts.

## Containment

1. Revoke affected trust artifacts and lockfiles when needed.
2. Disable affected integrations or execution pathways.
3. Isolate impacted environments or workflows.

## Eradication and Recovery

1. Patch root cause and validate with tests/scans.
2. Restore service with staged rollout.
3. Confirm no residual indicators of compromise.

## Communication Cadence

- `SEV-1`: Update every 30 minutes.
- `SEV-2`: Update every 2 hours.
- `SEV-3/4`: Daily or on meaningful changes.

## Post-Incident Review

Within 5 business days, publish:

- Timeline and root cause.
- Control failures and successful mitigations.
- Action items with owner and due date.

## Evidence Retention

Retain incident records, affected reports, and remediation evidence for at least 12 months.
