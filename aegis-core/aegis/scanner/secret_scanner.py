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

"""Hardcoded secret detection in Python source code.

Detects:
- Variable assignments where names match secret-like patterns AND
  values are non-trivial string literals
- High-entropy string constants that look like real API keys
  (AWS AKIA..., GitHub PATs ghp_..., Stripe sk_live_..., JWTs eyJ..., etc.)
- Connection strings with embedded credentials (postgres://user:pass@host/db)
"""

from __future__ import annotations

import ast
import logging
import math
import re
from pathlib import Path

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    Finding,
    FindingSeverity,
    ScopedCapability,
)

logger = logging.getLogger(__name__)


# ── Secret-like variable name patterns ──

SECRET_NAME_PATTERNS = re.compile(
    r"""(?i)^_*"""
    r"""(password|passwd|pwd|secret|api_?key|apikey|auth_?token|"""
    r"""access_?key|access_?token|private_?key|secret_?key|"""
    r"""token|credential|auth|signing_?key|encryption_?key|"""
    r"""master_?key|client_?secret|app_?secret|"""
    r"""db_?password|database_?password|"""
    r"""jwt_?secret|session_?secret|cookie_?secret)"""
    r"""_*$"""
)

# Placeholders that should NOT be flagged
PLACEHOLDER_VALUES = {
    "", "todo", "changeme", "change_me", "change-me",
    "replace_me", "replace-me", "your_key_here", "your-key-here",
    "xxx", "xxxx", "xxxxx", "xxxxxxxx",
    "none", "null", "undefined", "n/a", "na",
    "placeholder", "example", "test", "testing",
    "dummy", "fake", "mock", "sample",
    "insert_here", "insert-here", "fill_in", "fill-in",
    "redacted", "removed", "hidden",
    "<your_key>", "<your-key>", "<api_key>", "<token>",
    "${api_key}", "${token}", "${secret}", "${password}",
    "sk_test_xxx", "pk_test_xxx",
}


# ── High-entropy / known API key patterns ──

KNOWN_KEY_PATTERNS: list[tuple[re.Pattern, str]] = [
    # AWS Access Key ID
    (re.compile(r"""^AKIA[0-9A-Z]{16}$"""), "AWS Access Key ID"),
    # AWS Secret Access Key (40 chars base64-like)
    (re.compile(r"""^[A-Za-z0-9/+=]{40}$"""), "AWS Secret Access Key (possible)"),
    # GitHub PAT (classic)
    (re.compile(r"""^ghp_[A-Za-z0-9]{36,}$"""), "GitHub Personal Access Token"),
    # GitHub fine-grained PAT
    (re.compile(r"""^github_pat_[A-Za-z0-9_]{22,}$"""), "GitHub Fine-Grained PAT"),
    # GitHub OAuth/App tokens
    (re.compile(r"""^gho_[A-Za-z0-9]{36,}$"""), "GitHub OAuth Token"),
    (re.compile(r"""^ghu_[A-Za-z0-9]{36,}$"""), "GitHub User-to-Server Token"),
    (re.compile(r"""^ghs_[A-Za-z0-9]{36,}$"""), "GitHub Server-to-Server Token"),
    # Stripe keys
    (re.compile(r"""^sk_live_[A-Za-z0-9]{20,}$"""), "Stripe Live Secret Key"),
    (re.compile(r"""^rk_live_[A-Za-z0-9]{20,}$"""), "Stripe Restricted Key"),
    # Slack tokens
    (re.compile(r"""^xox[bpras]-[A-Za-z0-9\-]+$"""), "Slack Token"),
    # SendGrid
    (re.compile(r"""^SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}$"""), "SendGrid API Key"),
    # Twilio
    (re.compile(r"""^SK[0-9a-f]{32}$"""), "Twilio API Key"),
    # npm token
    (re.compile(r"""^npm_[A-Za-z0-9]{36,}$"""), "npm Token"),
    # PyPI token
    (re.compile(r"""^pypi-[A-Za-z0-9\-_]{50,}$"""), "PyPI API Token"),
    # JWT
    (re.compile(r"""^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$"""), "JSON Web Token"),
    # Base64-encoded long secrets (generic, 20+ chars, high entropy)
    # Handled by entropy check instead
]


# ── Connection string patterns ──

CONNECTION_STRING_PATTERN = re.compile(
    r"""^(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|"""
    r"""mssql|mariadb|oracle)://"""
    r"""([^:]+):([^@]+)@"""  # user:password@
    r"""[^/\s]+"""  # host
)


def _shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0.0
    length = len(s)
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_placeholder(value: str) -> bool:
    """Check if a string value is a known placeholder."""
    lower = value.lower().strip()
    if lower in PLACEHOLDER_VALUES:
        return True
    # Check for common placeholder patterns
    if re.match(r"""^<[^>]+>$""", value):
        return True
    if re.match(r"""^\$\{[^}]+\}$""", value):
        return True
    if re.match(r"""^\{\{[^}]+\}\}$""", value):
        return True
    # All-same-char strings like "aaaaaa"
    if len(set(value)) <= 1:
        return True
    return False


def _check_known_key_pattern(value: str) -> str | None:
    """Check if a value matches a known API key pattern.

    Returns the key type name if matched, None otherwise.
    """
    for pattern, key_type in KNOWN_KEY_PATTERNS:
        if pattern.match(value):
            return key_type
    return None


def _is_high_entropy_secret(value: str) -> bool:
    """Check if a string has high enough entropy to be a real secret.

    Requires: 20+ chars, Shannon entropy > 3.5 bits/char,
    and a mix of character types.
    """
    if len(value) < 20:
        return False

    entropy = _shannon_entropy(value)
    if entropy < 3.5:
        return False

    # Must have at least 2 of: uppercase, lowercase, digits, symbols
    char_types = 0
    if any(c.isupper() for c in value):
        char_types += 1
    if any(c.islower() for c in value):
        char_types += 1
    if any(c.isdigit() for c in value):
        char_types += 1
    if any(not c.isalnum() for c in value):
        char_types += 1

    return char_types >= 2


def _check_connection_string(value: str) -> str | None:
    """Check if a value is a connection string with embedded credentials.

    Returns the database type if matched, None otherwise.
    """
    match = CONNECTION_STRING_PATTERN.match(value)
    if match:
        db_type = match.group(1)
        password = match.group(3)
        # Only flag if password isn't a placeholder
        if password and not _is_placeholder(password):
            return db_type
    return None


def scan_python_secrets(
    file_path: Path, relative_name: str
) -> tuple[list[Finding], list[ScopedCapability]]:
    """Scan a Python file for hardcoded secrets.

    Returns:
        (findings, capabilities) — all findings have severity=RESTRICTED
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Could not read %s: %s", file_path, e)
        return [], []

    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError:
        logger.debug("Syntax error in %s, skipping secret scan", file_path)
        return [], []

    findings: list[Finding] = []
    capabilities: list[ScopedCapability] = []
    seen_lines: set[int] = set()

    for node in ast.walk(tree):
        # ── Check variable assignments ──
        if isinstance(node, ast.Assign):
            for target in node.targets:
                var_name = None
                if isinstance(target, ast.Name):
                    var_name = target.id
                elif isinstance(target, ast.Attribute):
                    var_name = target.attr

                if var_name and SECRET_NAME_PATTERNS.match(var_name):
                    value_str = _extract_string_value(node.value)
                    if value_str and not _is_placeholder(value_str) and len(value_str) >= 3:
                        _add_finding(
                            findings, capabilities, seen_lines,
                            relative_name, node.lineno, node.col_offset,
                            f"hardcoded_secret:{var_name}",
                            f"Hardcoded secret in variable '{var_name}'",
                        )

        # ── Check keyword arguments in function calls ──
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and SECRET_NAME_PATTERNS.match(kw.arg):
                    value_str = _extract_string_value(kw.value)
                    if value_str and not _is_placeholder(value_str) and len(value_str) >= 3:
                        _add_finding(
                            findings, capabilities, seen_lines,
                            relative_name, node.lineno, node.col_offset,
                            f"hardcoded_secret:{kw.arg}",
                            f"Hardcoded secret in keyword argument '{kw.arg}'",
                        )

        # ── Check all string constants for known patterns and high entropy ──
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            line = getattr(node, "lineno", 0)

            if line in seen_lines:
                continue

            # Check known API key patterns
            key_type = _check_known_key_pattern(value)
            if key_type:
                _add_finding(
                    findings, capabilities, seen_lines,
                    relative_name, line, getattr(node, "col_offset", 0),
                    f"hardcoded_key:{key_type}",
                    f"Possible {key_type} detected in string literal",
                )
                continue

            # Check connection strings with embedded credentials
            db_type = _check_connection_string(value)
            if db_type:
                _add_finding(
                    findings, capabilities, seen_lines,
                    relative_name, line, getattr(node, "col_offset", 0),
                    f"connection_string:{db_type}",
                    f"Connection string with embedded credentials ({db_type})",
                )
                continue

            # Check for high-entropy strings (generic secret detection)
            if _is_high_entropy_secret(value) and not _looks_like_code(value):
                _add_finding(
                    findings, capabilities, seen_lines,
                    relative_name, line, getattr(node, "col_offset", 0),
                    "high_entropy_string",
                    "High-entropy string constant — possible hardcoded secret",
                )

    return findings, capabilities


def _extract_string_value(node: ast.expr) -> str | None:
    """Extract the string value from an AST node, if it's a string constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _looks_like_code(value: str) -> bool:
    """Heuristic: does this string look like code/data rather than a secret?

    Real secrets (API keys, tokens, passwords) almost never contain spaces,
    almost never read like English prose, and almost never look like log
    messages or docstrings.  This function filters those out.
    """
    # Very long strings are probably not secrets
    if len(value) > 500:
        return True
    # Strings with lots of whitespace/newlines are probably code
    if value.count("\n") > 2:
        return True
    # Strings with ANY spaces are almost certainly natural language, log
    # messages, docstrings, or format strings — not secrets.  Real API
    # keys and tokens do not contain spaces.
    if " " in value:
        return True
    # Common code patterns
    if any(marker in value for marker in ("def ", "class ", "import ", "SELECT ", "INSERT ", "CREATE ")):
        return True
    # Regex patterns
    if value.startswith("^") or value.startswith("(?"):
        return True
    # URL paths without credentials
    if value.startswith("/") and ":" not in value:
        return True
    # URLs (http/https/ftp) — not secrets unless they have embedded credentials
    if re.match(r"""^https?://""", value) or re.match(r"""^ftp://""", value):
        # Only flag if there are embedded credentials (user:pass@)
        if not re.search(r"""://[^/]+:[^/]+@""", value):
            return True
    # File paths
    if value.startswith("./") or value.startswith("../"):
        return True
    # Common data format strings
    if re.match(r"""^[a-z]+://""", value):  # Protocol URIs
        return True
    # Strings that look like format templates
    if "{" in value and "}" in value:
        return True
    # Simple human-readable text (contains common words)
    lower = value.lower()
    if any(word in lower for word in ("error", "warning", "info", "debug", "version", "description")):
        return True
    # Strings that look like dotted module paths or Python identifiers
    if re.match(r"""^[a-zA-Z_][a-zA-Z0-9_.]+$""", value) and "." in value:
        return True
    # Strings ending with common file extensions are not secrets
    if re.search(r"""\.(py|js|ts|json|yaml|yml|md|txt|csv|log|xml|html|sql)$""", value, re.IGNORECASE):
        return True
    return False


def _add_finding(
    findings: list[Finding],
    capabilities: list[ScopedCapability],
    seen_lines: set[int],
    file: str,
    line: int,
    col: int,
    pattern: str,
    message: str,
) -> None:
    """Add a secret finding + capability, deduplicating by line."""
    if line in seen_lines:
        return
    seen_lines.add(line)

    cap = ScopedCapability(
        category=CapabilityCategory.SECRET,
        action=CapabilityAction.ACCESS,
        scope=["hardcoded"],
        scope_resolved=True,
    )
    findings.append(
        Finding(
            file=file,
            line=line,
            col=col,
            pattern=pattern,
            severity=FindingSeverity.RESTRICTED,
            capability=cap,
            message=message,
        )
    )
    capabilities.append(cap)
