# Business Continuity and Disaster Recovery

## Scope

This document covers continuity and recovery expectations for:

- Aegis scanner workflows
- Lockfile verification processes
- Batch scanning and reporting artifacts

## Recovery Objectives

- `RTO` (restore service): 24 hours
- `RPO` (acceptable data loss): 4 hours for generated reports and audit artifacts

## Critical Assets

- Source repository and release artifacts
- `aegis.lock` and scan reports
- Rule bundles and policy files

## Backup Strategy

1. Daily backups for scan outputs and policy artifacts.
2. Weekly snapshot retention for 90 days.
3. Offsite copy for backup sets.

## Disaster Scenarios

- Repository corruption or accidental deletion
- CI/CD outage
- Local environment compromise
- Third-party service disruption

## Recovery Procedure

1. Declare DR event and assign incident commander.
2. Restore source and artifacts from latest valid backup.
3. Re-run verification and regression/security tests.
4. Resume operations in staged mode.
5. Confirm integrity of restored outputs.

## Validation Cadence

- Quarterly tabletop DR exercise.
- Biannual backup restore test.

## Ownership

- `Primary`: Security/Operations owner
- `Backup`: Engineering lead
