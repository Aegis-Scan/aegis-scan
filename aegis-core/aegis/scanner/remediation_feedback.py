# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Build one-pass machine-readable remediation feedback payloads."""

from __future__ import annotations

from typing import Any

from aegis.models.capabilities import CombinationRisk, Finding, FindingSeverity


def _severity_rank(f: Finding) -> int:
    if f.severity == FindingSeverity.PROHIBITED:
        return 0
    return 1


def build_one_pass_feedback(
    prohibited_findings: list[Finding],
    restricted_findings: list[Finding],
    combination_risks: list[CombinationRisk],
    *,
    max_items: int = 12,
) -> dict[str, Any]:
    """Create deterministic feedback for one auto-remediation iteration."""
    findings = list(prohibited_findings) + list(restricted_findings)
    findings_sorted = sorted(
        findings,
        key=lambda f: (_severity_rank(f), f.file, f.line, f.col, f.pattern),
    )

    tasks: list[dict[str, Any]] = []
    for f in findings_sorted[:max_items]:
        tasks.append(
            {
                "kind": "finding",
                "file": f.file,
                "line": f.line,
                "end_line": f.end_line,
                "col": f.col,
                "end_col": f.end_col,
                "severity": f.severity.value,
                "pattern": f.pattern,
                "message": f.message,
                "suggested_fix": f.suggested_fix or "",
                "risk_note": f.risk_note,
                "cwe_ids": list(f.cwe_ids),
                "owasp_ids": list(f.owasp_ids),
                "tags": list(f.tags),
            }
        )

    combo_budget = max(0, max_items - len(tasks))
    for risk in combination_risks[:combo_budget]:
        tasks.append(
            {
                "kind": "combination_risk",
                "rule_id": risk.rule_id,
                "severity": risk.severity,
                "message": risk.message,
                "suggested_fix": risk.suggested_fix or "",
                "matched_capabilities": list(risk.matched_capabilities),
            }
        )

    return {
        "schema_version": "1.0",
        "mode": "one_pass",
        "max_iterations": 1,
        "objective": "Apply the highest-priority deterministic fixes while preserving behavior.",
        "constraints": [
            "Prefer local, minimal code edits.",
            "Do not introduce new capabilities.",
            "If uncertain, fail closed and request human review.",
        ],
        "tasks": tasks,
    }
