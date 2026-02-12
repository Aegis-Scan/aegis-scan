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

"""Unified rule evaluation engine.

Evaluates (capability, scope_value) against policy rules.
Priority-ordered: deny rules first, then allow, then default action.

Used at:
- Scan time: check extracted scopes against default deny paths
- Proxy time: check runtime args against enterprise policies
"""

from __future__ import annotations

import fnmatch
import logging
import os
from pathlib import Path
from typing import Any, Optional

import yaml

from aegis.models.rules import (
    CombinationRule,
    Policy,
    PolicyDefaults,
    PolicyRule,
    RuleAction,
)

logger = logging.getLogger(__name__)


class RuleMatch:
    """Result of rule evaluation."""

    def __init__(
        self,
        action: RuleAction,
        rule_id: Optional[str] = None,
        message: Optional[str] = None,
        is_default: bool = False,
    ) -> None:
        self.action = action
        self.rule_id = rule_id
        self.message = message
        self.is_default = is_default

    def __repr__(self) -> str:
        return f"RuleMatch(action={self.action}, rule_id={self.rule_id}, is_default={self.is_default})"


def _load_deny_paths() -> list[str]:
    """Load default deny paths from YAML config."""
    rules_path = Path(__file__).parent.parent / "rules" / "default_deny_paths.yaml"
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("deny_paths", [])
    except FileNotFoundError:
        logger.warning("Default deny paths not found at %s", rules_path)
        return []


def _expand_tilde(path: str) -> str:
    """Expand ~ to home directory for matching."""
    if path.startswith("~"):
        return os.path.expanduser(path)
    return path


def _scope_matches(scope_pattern: str, scope_value: str) -> bool:
    """Check if a scope value matches a pattern.

    Supports glob-style patterns (fnmatch).
    Handles ~ expansion for filesystem paths.
    """
    pattern = _expand_tilde(scope_pattern)
    value = _expand_tilde(scope_value)

    # Normalize separators
    pattern = pattern.replace("\\", "/")
    value = value.replace("\\", "/")

    return fnmatch.fnmatch(value, pattern)


def load_policy(policy_path: str | Path) -> Policy:
    """Load a unified policy from a YAML file."""
    path = Path(policy_path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = []
    for rule_data in data.get("rules", []):
        # Handle combination rules separately
        if rule_data.get("type") == "combination":
            continue
        rules.append(PolicyRule(**rule_data))

    combo_rules = []
    for rule_data in data.get("rules", []):
        if rule_data.get("type") == "combination":
            combo_rules.append(
                CombinationRule(
                    id=rule_data["id"],
                    severity=rule_data.get("severity", "high"),
                    match_all=rule_data["match_all"],
                    risk_override=rule_data.get("risk_override", 0),
                    message=rule_data.get("message", ""),
                )
            )

    defaults_data = data.get("defaults", {})
    defaults = PolicyDefaults(**defaults_data)

    return Policy(rules=rules, combination_rules=combo_rules, defaults=defaults)


def evaluate_rule(
    capability: str,
    scope_value: str,
    policy: Policy,
) -> RuleMatch:
    """Evaluate a single (capability, scope_value) against policy rules.

    Evaluation order:
    1. Explicit deny rules (highest priority first)
    2. Explicit allow rules (highest priority first)
    3. defaults.unmatched_action

    Args:
        capability: e.g., "fs:write", "network:connect"
        scope_value: e.g., "/tmp/output.txt", "api.weather.com"
        policy: The policy to evaluate against.

    Returns:
        RuleMatch with action, matched rule ID, and message.
    """
    # Separate deny and allow rules
    deny_rules = sorted(
        [r for r in policy.rules if r.action == RuleAction.DENY and r.capability == capability],
        key=lambda r: r.priority,
        reverse=True,
    )
    allow_rules = sorted(
        [r for r in policy.rules if r.action == RuleAction.ALLOW and r.capability == capability],
        key=lambda r: r.priority,
        reverse=True,
    )

    # Check deny rules first
    for rule in deny_rules:
        for pattern in rule.scope:
            if _scope_matches(pattern, scope_value):
                return RuleMatch(
                    action=RuleAction.DENY,
                    rule_id=rule.id,
                    message=rule.message or f"Denied by rule {rule.id}",
                )

    # Then check allow rules
    for rule in allow_rules:
        for pattern in rule.scope:
            if _scope_matches(pattern, scope_value):
                return RuleMatch(
                    action=RuleAction.ALLOW,
                    rule_id=rule.id,
                    message=rule.message or f"Allowed by rule {rule.id}",
                )

    # Default action
    return RuleMatch(
        action=policy.defaults.unmatched_action,
        is_default=True,
        message=f"No matching rule — default action: {policy.defaults.unmatched_action.value}",
    )


def check_path_violations(
    scoped_capabilities: list[Any],
    custom_deny_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Check capabilities against default deny paths.

    Used at scan time to flag path violations.

    Args:
        scoped_capabilities: List of ScopedCapability objects.
        custom_deny_paths: Optional custom deny paths (overrides default).

    Returns:
        List of violation dicts with file, path, and rule info.
    """
    deny_paths = custom_deny_paths if custom_deny_paths is not None else _load_deny_paths()
    violations = []

    for cap in scoped_capabilities:
        # Only check filesystem write capabilities
        if cap.capability_key not in ("fs:write", "fs:delete"):
            continue

        for scope_val in cap.scope:
            if scope_val == "*":
                # Wildcard — can't check specific paths, but flag as unrestricted
                continue

            for deny_pattern in deny_paths:
                if _scope_matches(deny_pattern, scope_val):
                    violations.append(
                        {
                            "capability": cap.capability_key,
                            "scope": scope_val,
                            "deny_pattern": deny_pattern,
                            "message": f"Path violation: {scope_val} matches deny pattern {deny_pattern}",
                        }
                    )

    return violations
