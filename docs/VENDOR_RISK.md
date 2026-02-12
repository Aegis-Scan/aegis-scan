# Vendor Risk Management

## Purpose

Define a lightweight process for assessing security risk from third-party services, dependencies, and skill sources.

## Vendor Tiers

- `Tier 1` (Critical): Can affect integrity, credentials, or production security decisions.
- `Tier 2` (Important): Supports development/security workflows but not critical control plane.
- `Tier 3` (Low): Limited impact tooling.

## Minimum Due Diligence

For Tier 1 and Tier 2 vendors:

1. Verify security contact and incident notification path.
2. Confirm vulnerability disclosure process.
3. Review data handling and retention posture.
4. Review authentication and access control model.
5. Document dependency and outage risk.

## Ongoing Review

- Tier 1: every 6 months
- Tier 2: annually
- Tier 3: as needed

## Triggered Reassessment

Reassess immediately when:

- A major security incident is reported.
- Service ownership materially changes.
- New sensitive data or privileged access is introduced.

## Decision Log Template

| Vendor | Tier | Use Case | Key Risks | Compensating Controls | Approval | Next Review |
|---|---|---|---|---|---|---|
| Example Vendor | Tier 2 | Dependency distribution | Supply-chain tampering | Pinning, integrity checks, monitoring | Approved | 2027-01-01 |
