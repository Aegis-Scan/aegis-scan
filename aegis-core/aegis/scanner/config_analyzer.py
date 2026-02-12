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

"""Config file analyzer — pattern-based capability extraction for JSON/YAML/TOML.

Detects:
- Sensitive keys (api_key, secret, token, password, credential)
- URL/endpoint values (network capability)
- Sensitive filesystem paths (/etc/, ~/.ssh/, etc.)
- Command execution values (subprocess references)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    Finding,
    FindingSeverity,
    ScopedCapability,
)

logger = logging.getLogger(__name__)


# ── Sensitive key patterns ──

SENSITIVE_KEY_PATTERN = re.compile(
    r"""(api[_-]?key|secret|token|password|credential|auth[_-]?token|"""
    r"""private[_-]?key|access[_-]?key|client[_-]?secret|"""
    r"""db[_-]?password|database[_-]?password|redis[_-]?password|"""
    r"""encryption[_-]?key|signing[_-]?key|webhook[_-]?secret|"""
    r"""master[_-]?key|session[_-]?secret|cookie[_-]?secret|"""
    r"""jwt[_-]?secret|ssh[_-]?key|passphrase|"""
    r"""bearer[_-]?token|refresh[_-]?token|"""
    r"""oauth[_-]?secret|oauth[_-]?token|"""
    r"""stripe[_-]?key|sendgrid[_-]?key|twilio[_-]?token|"""
    r"""slack[_-]?token|github[_-]?token|"""
    r"""openai[_-]?key|anthropic[_-]?key)""",
    re.IGNORECASE,
)

# ── URL pattern ──

URL_PATTERN = re.compile(
    r"""https?://[^\s"'\]},]+""", re.IGNORECASE
)

# ── Connection string patterns (database/message broker URIs) ──

CONNECTION_STRING_PATTERN = re.compile(
    r"""(postgres(ql)?://|mysql://|mongodb(\+srv)?://|"""
    r"""redis(s)?://|amqp(s)?://|sqlite:///|"""
    r"""mssql(\+pyodbc)?://|oracle://|"""
    r"""elasticsearch://|memcached://)""",
    re.IGNORECASE,
)

# ── Base64-encoded value detection (likely embedded secrets) ──

BASE64_PATTERN = re.compile(
    r"""^[A-Za-z0-9+/]{40,}={0,2}$"""
)

# ── JWT token pattern ──

JWT_PATTERN = re.compile(
    r"""eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"""
)

# ── Sensitive path patterns ──

SENSITIVE_PATH_PATTERN = re.compile(
    r"""(/etc/|/root/|~/.ssh/|~/.gnupg/|~/.aws/|"""
    r"""~/.kube/|~/.azure/|~/.docker/|"""
    r"""~/.config/|~/.local/|~/.netrc|~/.npmrc|~/.pypirc|"""
    r"""~/.gitconfig|~/.bashrc|~/.zshrc|~/.profile|"""
    r"""/var/log/|/proc/|/sys/|/dev/|"""
    r"""C:\\Windows\\|C:\\Users\\.*\\AppData|"""
    r"""%USERPROFILE%|%APPDATA%|%LOCALAPPDATA%|"""
    r"""%PROGRAMDATA%|%SYSTEMROOT%)""",
    re.IGNORECASE,
)

# ── Command patterns in values ──

COMMAND_PATTERN = re.compile(
    r"""\b(curl|wget|ssh|docker|kubectl|aws|gcloud|az|"""
    r"""python|python3|node|npm|npx|pip|pip3|"""
    r"""bash|sh|zsh|powershell|pwsh|cmd|"""
    r"""terraform|ansible|helm|make|"""
    r"""sudo|crontab|systemctl|"""
    r"""apt|apt-get|yum|brew)\b""",
    re.IGNORECASE,
)


def _parse_file_content(file_path: Path) -> dict | list | None:
    """Parse a config file into a Python structure. Returns None on failure."""
    suffix = file_path.suffix.lower()

    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Could not read %s: %s", file_path, e)
        return None

    if not text.strip():
        return None

    try:
        if suffix == ".json":
            return json.loads(text)
        elif suffix in (".yaml", ".yml"):
            import yaml
            return yaml.safe_load(text)
        elif suffix == ".toml":
            # Python 3.11+ has tomllib
            import tomllib
            return tomllib.loads(text)
    except Exception as e:
        logger.debug("Could not parse %s: %s", file_path, e)
        return None

    return None


def _walk_structure(
    data: Any,
    path_prefix: str = "",
) -> list[tuple[str, str, Any]]:
    """Walk a nested dict/list and yield (key_path, key, value) tuples."""
    results: list[tuple[str, str, Any]] = []

    if isinstance(data, dict):
        for key, value in data.items():
            key_path = f"{path_prefix}.{key}" if path_prefix else key
            results.append((key_path, str(key), value))
            results.extend(_walk_structure(value, key_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            key_path = f"{path_prefix}[{i}]"
            results.extend(_walk_structure(item, key_path))

    return results


def parse_config_file(
    file_path: Path, relative_name: str
) -> tuple[list[Finding], list[Finding], list[ScopedCapability]]:
    """Parse a config file and extract findings + capabilities.

    Returns:
        (prohibited_findings, restricted_findings, capabilities)
    """
    prohibited: list[Finding] = []
    restricted: list[Finding] = []
    capabilities: list[ScopedCapability] = []
    seen_caps: set[tuple[str, str]] = set()

    data = _parse_file_content(file_path)
    if data is None:
        return [], [], []

    entries = _walk_structure(data)

    for key_path, key, value in entries:
        str_value = str(value) if value is not None else ""

        # ── Sensitive key detection → secret:access ──
        if SENSITIVE_KEY_PATTERN.search(key):
            # Only flag if the value is non-empty and not a placeholder
            if str_value and str_value not in ("", "null", "None", "TODO", "CHANGEME"):
                cap_key = ("secret", "access")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.SECRET,
                        action=CapabilityAction.ACCESS,
                        scope=[key_path],
                        scope_resolved=True,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=0,
                            col=0,
                            pattern=key,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Sensitive key in config: {key_path}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)

        # ── URL detection → network:connect ──
        if isinstance(value, str) and URL_PATTERN.search(value):
            url_match = URL_PATTERN.search(value)
            if url_match:
                url = url_match.group(0)
                cap = ScopedCapability(
                    category=CapabilityCategory.NETWORK,
                    action=CapabilityAction.CONNECT,
                    scope=[url],
                    scope_resolved=True,
                )
                cap_key = ("network", url)
                if cap_key not in seen_caps:
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=0,
                            col=0,
                            pattern="url",
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Network endpoint in config: {key_path} → {url}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)

        # ── Sensitive path detection → fs:read ──
        if isinstance(value, str) and SENSITIVE_PATH_PATTERN.search(value):
            path_match = SENSITIVE_PATH_PATTERN.search(value)
            if path_match:
                cap_key = ("fs", "sensitive_path")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.FS,
                        action=CapabilityAction.READ,
                        scope=[value],
                        scope_resolved=True,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=0,
                            col=0,
                            pattern="sensitive_path",
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Sensitive filesystem path in config: {key_path} → {value}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)

        # ── Connection string detection → network:connect ──
        if isinstance(value, str) and CONNECTION_STRING_PATTERN.search(value):
            conn_match = CONNECTION_STRING_PATTERN.search(value)
            if conn_match:
                cap_key = ("network", "connstring")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.NETWORK,
                        action=CapabilityAction.CONNECT,
                        scope=[value],
                        scope_resolved=True,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=0,
                            col=0,
                            pattern="connection_string",
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Database/service connection string in config: {key_path}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)

        # ── Base64-encoded value detection → secret:access ──
        if isinstance(value, str) and len(value) >= 40 and BASE64_PATTERN.match(value):
            cap_key = ("secret", "base64")
            if cap_key not in seen_caps:
                cap = ScopedCapability(
                    category=CapabilityCategory.SECRET,
                    action=CapabilityAction.ACCESS,
                    scope=[key_path],
                    scope_resolved=True,
                )
                restricted.append(
                    Finding(
                        file=relative_name,
                        line=0,
                        col=0,
                        pattern="base64_value",
                        severity=FindingSeverity.RESTRICTED,
                        capability=cap,
                        message=f"Base64-encoded value in config (possible embedded secret): {key_path}",
                    )
                )
                capabilities.append(cap)
                seen_caps.add(cap_key)

        # ── JWT token detection → secret:access ──
        if isinstance(value, str) and JWT_PATTERN.search(value):
            cap_key = ("secret", "jwt")
            if cap_key not in seen_caps:
                cap = ScopedCapability(
                    category=CapabilityCategory.SECRET,
                    action=CapabilityAction.ACCESS,
                    scope=[key_path],
                    scope_resolved=True,
                )
                restricted.append(
                    Finding(
                        file=relative_name,
                        line=0,
                        col=0,
                        pattern="jwt_token",
                        severity=FindingSeverity.RESTRICTED,
                        capability=cap,
                        message=f"JWT token embedded in config: {key_path}",
                    )
                )
                capabilities.append(cap)
                seen_caps.add(cap_key)

        # ── Command patterns in values → subprocess:exec ──
        if isinstance(value, str) and COMMAND_PATTERN.search(value):
            cmd_match = COMMAND_PATTERN.search(value)
            if cmd_match:
                cmd = cmd_match.group(1).lower()
                cap_key = ("subprocess", cmd)
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.SUBPROCESS,
                        action=CapabilityAction.EXEC,
                        scope=[cmd],
                        scope_resolved=True,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=0,
                            col=0,
                            pattern=cmd,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Command reference in config: {key_path} → {cmd}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)

    return prohibited, restricted, capabilities
