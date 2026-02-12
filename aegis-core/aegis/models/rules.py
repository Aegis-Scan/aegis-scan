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

"""Pydantic models for policy rules and trifecta combination rules."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RuleAction(str, Enum):
    """Action to take when a rule matches."""

    ALLOW = "allow"
    DENY = "deny"
    FLAG = "flag"


class PolicyRule(BaseModel):
    """A single unified policy rule.

    Covers filesystem, network, subprocess, and all other capability types
    using a single schema.
    """

    id: str
    capability: str  # e.g., "fs:write", "network:connect"
    scope: list[str] = Field(default_factory=list)
    action: RuleAction
    priority: int = 0
    severity: Optional[str] = None
    message: Optional[str] = None


class CombinationRule(BaseModel):
    """A trifecta/combination rule that matches on multiple capabilities."""

    id: str
    severity: str  # "critical", "high"
    match_all: list[str]  # e.g., ["browser:control", "secret:access", "network:connect"]
    risk_override: int
    message: str
    conditions: Optional[dict] = None  # e.g., {"has_unrecognized_binary": true}


class PolicyDefaults(BaseModel):
    """Default policy settings."""

    unmatched_action: RuleAction = RuleAction.FLAG
    max_stale_ttl: str = "24h"
    staleness_yellow: str = "1h"
    trust_mode: str = "registry_only"


class Policy(BaseModel):
    """A complete unified policy."""

    rules: list[PolicyRule] = Field(default_factory=list)
    combination_rules: list[CombinationRule] = Field(default_factory=list)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
