# Security Risk Register

## How to Use

Track material risks with owner, treatment, and due date. Update this register at least monthly and after incidents.

## Risk Scale

- `Likelihood`: Low / Medium / High
- `Impact`: Low / Medium / High
- `Priority`: Low / Medium / High / Critical

## Open Risks

| ID | Risk | Domain | Likelihood | Impact | Priority | Current Controls | Treatment Plan | Owner | Due Date | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| R-001 | No automated core CI security gate for `aegis-core` | DevSecOps | Medium | High | High | Local test execution | Add CI workflow with tests, scan, and dependency audit | Engineering | 2026-03-15 | In Progress |
| R-002 | Path traversal risk in lockfile leaf path handling | AppSec | Medium | High | High | Static rules and manual review | Enforce canonical path containment checks | Engineering | 2026-03-01 | In Progress |
| R-003 | Subprocess invocation with shell evaluation in batch script | AppSec | Medium | Medium | Medium | Static detection in scanner | Move to arg-list subprocess calls, validate slugs | Engineering | 2026-03-01 | In Progress |
| R-004 | No formal incident response runbook | Operations | Medium | High | High | Ad-hoc handling | Adopt incident runbook and severity matrix | Security | 2026-03-20 | Open |
| R-005 | No BCP/DR procedure or recovery test cadence | Resilience | Medium | High | High | None | Establish RTO/RPO and run restore drills | Operations | 2026-03-31 | Open |
| R-006 | No formal vendor risk process | Governance | Medium | Medium | Medium | Informal evaluation | Add tiered vendor review checklist and annual reassessment | Security | 2026-04-15 | Open |

## Closed Risks

Add closed items below with closure date and evidence link.
