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

"""External binary spawn detection.

Detects binary names invoked via subprocess.run(), Popen(), os.system(), etc.
Compares against deny/allow lists from default_deny_binaries.yaml.
"""

from __future__ import annotations

import logging
from importlib import resources
from pathlib import Path

import yaml

from aegis.models.capabilities import ScopedCapability, CapabilityCategory, CapabilityAction

logger = logging.getLogger(__name__)


def _load_binary_lists() -> tuple[set[str], set[str]]:
    """Load deny and allow binary lists from YAML config.

    Returns:
        (deny_set, allow_set)
    """
    rules_path = Path(__file__).parent.parent / "rules" / "default_deny_binaries.yaml"

    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("Binary deny list not found at %s", rules_path)
        return set(), set()

    deny = set(data.get("deny_binaries", []))
    allow = set(data.get("allow_binaries", []))
    return deny, allow


# Module-level cache
_deny_binaries: set[str] | None = None
_allow_binaries: set[str] | None = None


def _get_lists() -> tuple[set[str], set[str]]:
    """Get cached binary lists."""
    global _deny_binaries, _allow_binaries
    if _deny_binaries is None:
        _deny_binaries, _allow_binaries = _load_binary_lists()
    return _deny_binaries, _allow_binaries


def extract_binaries_from_capabilities(
    capabilities: list[ScopedCapability],
) -> list[str]:
    """Extract binary names from subprocess capabilities.

    Looks at scope values of subprocess:exec capabilities.
    """
    binaries = set()
    for cap in capabilities:
        if cap.category == CapabilityCategory.SUBPROCESS and cap.action == CapabilityAction.EXEC:
            for scope_val in cap.scope:
                if scope_val != "*":
                    # The first element of the scope is the binary name
                    binary = scope_val.split("/")[-1]  # handle paths like /usr/bin/git
                    binaries.add(binary)
    return sorted(binaries)


def classify_binaries(
    binary_names: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Classify binary names into denied, allowed, and unrecognized.

    Returns:
        (denied, allowed, unrecognized)
    """
    deny_set, allow_set = _get_lists()

    denied = []
    allowed = []
    unrecognized = []

    for name in binary_names:
        if name in deny_set:
            denied.append(name)
        elif name in allow_set:
            allowed.append(name)
        else:
            unrecognized.append(name)

    return denied, allowed, unrecognized


def has_unrecognized_binaries(binary_names: list[str]) -> bool:
    """Check if any binary is not in the allow list."""
    _, allow_set = _get_lists()
    for name in binary_names:
        if name not in allow_set:
            return True
    return False


def get_all_external_binaries(capabilities: list[ScopedCapability]) -> list[str]:
    """Get all external binary names from capabilities.

    Returns sorted unique list of all binary names found.
    """
    return extract_binaries_from_capabilities(capabilities)
