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

"""Stdlib module shadowing detector.

Detects when local files or packages shadow Python standard library modules.
A local file named `email.py` or `code.py` will silently override the stdlib
module, potentially breaking functionality or introducing vulnerabilities.

Reference: Section 6.4 of "Deep Static Analysis of Python Standard Library
Vulnerabilities: An AST-Centric Taxonomy for Legacy Monolith Audits".
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from aegis.models.capabilities import (
    Finding,
    FindingSeverity,
)

logger = logging.getLogger(__name__)

# High-risk stdlib modules that should never be shadowed.
# This is a curated subset — shadowing these has security implications.
_SECURITY_SENSITIVE_STDLIB = frozenset({
    # Execution / subprocess
    "os", "sys", "subprocess", "signal", "shutil",
    "platform", "posix", "pty", "commands", "runpy",
    # Networking
    "socket", "http", "urllib", "ftplib", "smtplib",
    "telnetlib", "xmlrpc", "socketserver", "ssl",
    "imaplib", "poplib",
    # Serialization / data
    "pickle", "marshal", "shelve", "json", "xml",
    "plistlib", "csv", "configparser", "sqlite3",
    # Crypto / random
    "hashlib", "hmac", "secrets", "random",
    # Introspection
    "inspect", "code", "codeop", "gc", "dis",
    "ast", "compile", "compileall",
    # Concurrency
    "threading", "multiprocessing", "concurrent",
    "asyncio",
    # Filesystem / io
    "io", "tempfile", "glob", "zipfile", "tarfile",
    "pathlib",
    # Other
    "ctypes", "importlib", "builtins", "abc",
    "email", "logging", "re", "string", "base64",
    "binascii", "struct", "collections", "functools",
    "operator", "itertools", "copy", "types",
    "traceback", "warnings", "atexit",
})

# The full set of stdlib top-level module names (Python 3.11+).
# We use sys.stdlib_module_names if available, otherwise fall back to the curated list.
def _get_stdlib_modules() -> frozenset[str]:
    """Get the set of standard library module names."""
    if hasattr(sys, "stdlib_module_names"):
        return frozenset(sys.stdlib_module_names)
    # Fallback for Python < 3.10
    return _SECURITY_SENSITIVE_STDLIB


def detect_shadow_modules(
    all_files: list[Path],
    target_dir: Path,
) -> list[Finding]:
    """Detect local files/packages that shadow Python stdlib modules.

    Args:
        all_files: List of relative paths discovered in the project.
        target_dir: The root directory of the project.

    Returns:
        List of findings for each shadowed module.
    """
    stdlib_names = _get_stdlib_modules()
    findings: list[Finding] = []
    seen: set[str] = set()

    for rel_path in all_files:
        # Check top-level .py files (e.g., email.py, code.py)
        if rel_path.suffix == ".py" and len(rel_path.parts) == 1:
            stem = rel_path.stem
            if stem in stdlib_names and stem not in seen:
                seen.add(stem)
                severity = FindingSeverity.PROHIBITED if stem in _SECURITY_SENSITIVE_STDLIB else FindingSeverity.RESTRICTED
                findings.append(
                    Finding(
                        file=str(rel_path),
                        line=0,
                        col=0,
                        pattern=f"shadow_module:{stem}",
                        severity=severity,
                        message=(
                            f"Local file '{rel_path}' shadows the Python stdlib module '{stem}'. "
                            f"This will override the standard library when any code runs "
                            f"'import {stem}', potentially breaking functionality or "
                            f"introducing vulnerabilities."
                        ),
                    )
                )

        # Check top-level packages (directories with __init__.py)
        if rel_path.name == "__init__.py" and len(rel_path.parts) == 2:
            pkg_name = rel_path.parts[0]
            if pkg_name in stdlib_names and pkg_name not in seen:
                seen.add(pkg_name)
                severity = FindingSeverity.PROHIBITED if pkg_name in _SECURITY_SENSITIVE_STDLIB else FindingSeverity.RESTRICTED
                findings.append(
                    Finding(
                        file=str(rel_path),
                        line=0,
                        col=0,
                        pattern=f"shadow_module:{pkg_name}",
                        severity=severity,
                        message=(
                            f"Local package '{pkg_name}/' shadows the Python stdlib module "
                            f"'{pkg_name}'. This will override the standard library when "
                            f"any code runs 'import {pkg_name}', potentially breaking "
                            f"functionality or introducing vulnerabilities."
                        ),
                    )
                )

    return findings
