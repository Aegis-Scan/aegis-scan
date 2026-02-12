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

"""Social engineering pattern matcher — flags persuasion tactics in code.

AI-generated skill code may contain strings designed to trick users
into running dangerous commands. This scanner detects:

- "sudo" combined with urgency ("urgent", "fix", "immediately")
- "paste this" combined with "terminal"
- curl-pipe-bash one-liners embedded in print/log strings
- Fake error messages designed to prompt dangerous user actions
- Authority impersonation ("admin", "system requires", "security update")
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from aegis.models.capabilities import (
    Finding,
    FindingSeverity,
)

logger = logging.getLogger(__name__)

# Binary / non-text file extensions to skip
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".avi",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".whl", ".egg", ".pyc", ".pyo", ".so", ".dll", ".dylib",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".lock", ".lockb",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
})


# Each rule is: (compiled regex for the FULL line, message)
# These match inside string literals, print/log calls, comments, etc.
_SOCIAL_ENGINEERING_RULES: list[tuple[re.Pattern, str]] = [
    # ── sudo + urgency ──
    (
        re.compile(
            r"""(?=.*\bsudo\b)(?=.*\b(urgent|urgently|immediately|right\s+now|fix\s+this|quick\s+fix|asap)\b)""",
            re.IGNORECASE,
        ),
        "Social engineering: 'sudo' combined with urgency language — "
        "may trick users into running privileged commands",
    ),
    # ── paste into terminal ──
    (
        re.compile(
            r"""(?=.*\bpaste\s+(this|it|the\s+following)\b)(?=.*\b(terminal|console|shell|command\s+line|cmd)\b)""",
            re.IGNORECASE,
        ),
        "Social engineering: instruction to paste into terminal — "
        "classic social engineering vector",
    ),
    # ── curl|bash / curl|sh embedded in strings ──
    (
        re.compile(
            r"""curl\s+\S+\s*\|\s*(ba)?sh""",
            re.IGNORECASE,
        ),
        "Social engineering: curl-pipe-bash pattern — "
        "remote code execution disguised as an install command",
    ),
    # ── wget|bash / wget|sh embedded in strings ──
    (
        re.compile(
            r"""wget\s+\S+\s*\|\s*(ba)?sh""",
            re.IGNORECASE,
        ),
        "Social engineering: wget-pipe-bash pattern — "
        "remote code execution disguised as an install command",
    ),
    # ── "run this as root" / "run as administrator" ──
    (
        re.compile(
            r"""\brun\s+(this\s+)?(as\s+)?(root|administrator|admin)\b""",
            re.IGNORECASE,
        ),
        "Social engineering: instruction to run as root/administrator — "
        "privilege escalation prompt",
    ),
    # ── Fake security warnings ──
    (
        re.compile(
            r"""(?=.*\b(security\s+update|critical\s+update|emergency\s+patch)\b)(?=.*\b(run|execute|install)\b)""",
            re.IGNORECASE,
        ),
        "Social engineering: fake security update with execution instruction — "
        "authority impersonation tactic",
    ),
    # ── "disable antivirus" / "disable firewall" ──
    (
        re.compile(
            r"""\b(disable|turn\s+off|deactivate)\s+(your\s+)?(antivirus|firewall|defender|protection|security)\b""",
            re.IGNORECASE,
        ),
        "Social engineering: instruction to disable security software",
    ),
    # ── chmod 777 instructions ──
    (
        re.compile(
            r"""\bchmod\s+777\b""",
        ),
        "Social engineering: chmod 777 — removes all file permission restrictions",
    ),
]


def scan_file_social_engineering(
    file_path: Path,
    relative_name: str,
) -> list[Finding]:
    """Scan a single file for social engineering patterns in string content.

    Returns a list of RESTRICTED findings.
    """
    # Skip binary files
    if file_path.suffix.lower() in _BINARY_EXTENSIONS:
        return []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Could not read %s: %s", file_path, e)
        return []

    if not content:
        return []

    findings: list[Finding] = []
    seen_rules: set[str] = set()  # Deduplicate by rule message prefix

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for pattern, message in _SOCIAL_ENGINEERING_RULES:
            if pattern.search(stripped):
                # Deduplicate: only one finding per rule type per file
                rule_key = message[:40]
                if rule_key in seen_rules:
                    continue
                seen_rules.add(rule_key)

                findings.append(
                    Finding(
                        file=relative_name,
                        line=line_num,
                        col=0,
                        pattern="social_engineering",
                        severity=FindingSeverity.RESTRICTED,
                        message=message,
                    )
                )
                break  # One match per line

    return findings
