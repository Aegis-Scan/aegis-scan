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

"""Canonical JSON output for scan reports and lockfiles.

Produces deterministic JSON output:
- Sorted keys
- 2-space indentation
- LF line endings
- Trailing newline
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from aegis.models.report import ScanReport

logger = logging.getLogger(__name__)


def to_canonical_json(data: dict[str, Any] | Any) -> str:
    """Convert data to canonical JSON string.

    Canonical JSON: sorted keys, 2-space indent, ensure LF, trailing newline.
    """
    if hasattr(data, "model_dump"):
        data = data.model_dump()

    result = json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)
    # Ensure LF line endings
    result = result.replace("\r\n", "\n").replace("\r", "\n")
    # Ensure trailing newline
    if not result.endswith("\n"):
        result += "\n"
    return result


def write_report(report: ScanReport, output_path: Path) -> None:
    """Write scan report as canonical JSON to file."""
    data = report.model_dump()
    content = to_canonical_json(data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8", newline="\n")
    logger.info("Wrote report to %s", output_path)


def write_lockfile(lockfile_data: dict[str, Any], output_path: Path) -> None:
    """Write lockfile as canonical JSON to file."""
    content = to_canonical_json(lockfile_data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8", newline="\n")
    logger.info("Wrote lockfile to %s", output_path)
