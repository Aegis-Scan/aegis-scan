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

"""Trifecta combination risk detection.

Takes Set[ScopedCapability] as input (NOT a ScanResult), making it
reusable at both scan time (single repo) and proxy time (session envelope).

The cross-repo trifecta (Skill A has browser, Skill B has secrets) is
detected ONLY at proxy time against the Session Capability Envelope.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from aegis.models.capabilities import (
    CombinationRisk,
    ScopedCapability,
)
from aegis.models.rules import CombinationRule

logger = logging.getLogger(__name__)


def _load_trifecta_rules() -> list[CombinationRule]:
    """Load combination rules from YAML config."""
    rules_path = Path(__file__).parent.parent / "rules" / "trifecta_rules.yaml"

    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("Trifecta rules not found at %s", rules_path)
        return []

    rules = []
    for rule_data in data.get("combination_rules", []):
        rules.append(CombinationRule(**rule_data))
    return rules


# Module-level cache
_trifecta_rules: list[CombinationRule] | None = None


def _get_rules() -> list[CombinationRule]:
    """Get cached trifecta rules."""
    global _trifecta_rules
    if _trifecta_rules is None:
        _trifecta_rules = _load_trifecta_rules()
    return _trifecta_rules


def _capability_keys(capabilities: set[ScopedCapability] | list[ScopedCapability]) -> set[str]:
    """Extract the set of capability keys (e.g., 'fs:write', 'network:connect')."""
    return {cap.capability_key for cap in capabilities}


def analyze_combinations(
    capabilities: set[ScopedCapability] | list[ScopedCapability],
    has_unrecognized_binary: bool = False,
    custom_rules: list[CombinationRule] | None = None,
) -> list[CombinationRisk]:
    """Analyze capability combinations for trifecta risks.

    Args:
        capabilities: Set of scoped capabilities to check.
        has_unrecognized_binary: Whether unrecognized binaries were detected.
        custom_rules: Optional custom rules (overrides default loaded rules).

    Returns:
        List of triggered CombinationRisk objects.
    """
    rules = custom_rules if custom_rules is not None else _get_rules()
    cap_keys = _capability_keys(capabilities)
    triggered: list[CombinationRisk] = []

    for rule in rules:
        required = set(rule.match_all)

        # Check if all required capabilities are present
        if not required.issubset(cap_keys):
            continue

        # Check additional conditions
        if rule.conditions:
            if rule.conditions.get("has_unrecognized_binary") and not has_unrecognized_binary:
                continue

        triggered.append(
            CombinationRisk(
                rule_id=rule.id,
                severity=rule.severity,
                matched_capabilities=sorted(required & cap_keys),
                risk_override=rule.risk_override,
                message=rule.message.strip(),
            )
        )

    return triggered


def get_max_risk_override(combination_risks: list[CombinationRisk]) -> int | None:
    """Get the highest risk override from triggered combinations.

    Returns None if no combinations were triggered.
    """
    if not combination_risks:
        return None
    return max(r.risk_override for r in combination_risks)


def has_critical_combination(combination_risks: list[CombinationRisk]) -> bool:
    """Check if any triggered combination is CRITICAL severity."""
    return any(r.severity == "critical" for r in combination_risks)
