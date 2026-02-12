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

"""Dockerfile Analyzer — flags privilege escalation patterns in Dockerfiles.

AI Agents frequently generate Dockerfiles to deploy their work.  A Dockerfile
is a massive vector for privilege escalation, data exfiltration, and supply-
chain attacks.  This module performs regex-based analysis of Dockerfile
instructions to flag dangerous patterns.

Patterns detected:
    - USER root (running container as root)
    - EXPOSE 22 / 23 / privileged ports
    - Package manager installs (apk add, apt-get install) of risky tools
    - ADD from remote URLs (supply-chain risk)
    - --privileged hints in RUN commands
    - Curl-pipe-bash anti-patterns
    - Sensitive volume mounts
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    Finding,
    FindingSeverity,
    ScopedCapability,
)

logger = logging.getLogger(__name__)


# ── Dockerfile extension detection ──

DOCKERFILE_NAMES = {
    "dockerfile",
    "dockerfile.dev",
    "dockerfile.prod",
    "dockerfile.staging",
    "dockerfile.test",
    "containerfile",
}

DOCKERFILE_EXTENSIONS = {".dockerfile"}


def is_dockerfile(path: Path) -> bool:
    """Check if a path is a Dockerfile."""
    name_lower = path.name.lower()
    if name_lower in DOCKERFILE_NAMES:
        return True
    if name_lower.startswith("dockerfile."):
        return True
    if path.suffix.lower() in DOCKERFILE_EXTENSIONS:
        return True
    return False


# ── Patterns ──

# USER root — running container as root
_RE_USER_ROOT = re.compile(
    r"^\s*USER\s+root\b", re.IGNORECASE | re.MULTILINE
)

# EXPOSE privileged ports (< 1024) or specifically dangerous ones
_DANGEROUS_PORTS = {22, 23, 25, 2375, 2376, 5900, 6379}
_RE_EXPOSE = re.compile(
    r"^\s*EXPOSE\s+(.+)", re.IGNORECASE | re.MULTILINE
)

# ADD from remote URL (supply-chain risk — should use COPY or verified downloads)
_RE_ADD_REMOTE = re.compile(
    r"^\s*ADD\s+(https?://\S+)", re.IGNORECASE | re.MULTILINE
)

# Curl-pipe-bash pattern in RUN
_RE_CURL_PIPE_BASH = re.compile(
    r"curl\s+.*\|\s*(bash|sh|zsh)\b", re.IGNORECASE
)
_RE_WGET_PIPE_BASH = re.compile(
    r"wget\s+.*\|\s*(bash|sh|zsh)\b", re.IGNORECASE
)

# Package manager installs of risky tools
_RISKY_PACKAGES = {
    "nmap", "netcat", "nc", "ncat", "socat", "tcpdump", "wireshark",
    "openssh-server", "sshd", "telnet", "telnetd", "rsh", "rlogin",
    "john", "hashcat", "hydra", "metasploit", "sqlmap",
    "gcc", "g++", "make", "build-essential",  # compilers in prod
}
_RE_PKG_INSTALL = re.compile(
    r"(apt-get\s+install|apk\s+add|yum\s+install|dnf\s+install|pacman\s+-S)"
    r"\s+(.+)",
    re.IGNORECASE,
)

# Sensitive volume mounts
_SENSITIVE_MOUNT_PATTERNS = [
    r"/etc/shadow", r"/etc/passwd", r"/root/\.ssh",
    r"/var/run/docker\.sock", r"docker\.sock",
    r"/proc", r"/sys",
]
_RE_SENSITIVE_VOLUME = re.compile(
    r"^\s*VOLUME\s+(.+)", re.IGNORECASE | re.MULTILINE
)

# --privileged or --cap-add in RUN
_RE_PRIVILEGED = re.compile(
    r"--privileged|--cap-add\s*=?\s*(SYS_ADMIN|SYS_PTRACE|NET_ADMIN|ALL)",
    re.IGNORECASE,
)

# No USER instruction at all (implicit root)
_RE_USER_ANY = re.compile(
    r"^\s*USER\s+\S+", re.IGNORECASE | re.MULTILINE
)

# FROM with :latest (unpinned base image)
_RE_FROM_LATEST = re.compile(
    r"^\s*FROM\s+\S+:latest\b", re.IGNORECASE | re.MULTILINE
)

# ENV/ARG with secret-like values
_SECRET_KEY_NAMES = re.compile(
    r"(PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|TOKEN|PRIVATE_KEY|"
    r"ACCESS_KEY|AUTH_TOKEN|CREDENTIAL|DB_PASS|MASTER_KEY|"
    r"ENCRYPTION_KEY|SIGNING_KEY|SSH_KEY)",
    re.IGNORECASE,
)
_RE_ENV_SECRET = re.compile(
    r"^\s*ENV\s+(\S+?)[\s=](.+)", re.IGNORECASE | re.MULTILINE
)
_RE_ARG_SECRET = re.compile(
    r"^\s*ARG\s+(\S+?)[\s=](.+)", re.IGNORECASE | re.MULTILINE
)


def parse_dockerfile(
    file_path: Path,
    relative_name: str,
) -> tuple[list[Finding], list[Finding], list[ScopedCapability]]:
    """Analyze a Dockerfile for privilege escalation and security patterns.

    Returns:
        (prohibited_findings, restricted_findings, capabilities)
    """
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning("Cannot read %s: %s", file_path, e)
        return [], [], []

    lines = content.splitlines()
    prohibited: list[Finding] = []
    restricted: list[Finding] = []
    capabilities: list[ScopedCapability] = []

    # --- USER root ---
    for match in _RE_USER_ROOT.finditer(content):
        line_no = content[:match.start()].count("\n") + 1
        restricted.append(Finding(
            file=relative_name,
            line=line_no,
            pattern="dockerfile:user_root",
            severity=FindingSeverity.RESTRICTED,
            message="Container runs as root. Use a non-root USER for production.",
            suggested_fix="Add 'USER nonroot' or 'USER 1000' after installing dependencies.",
        ))
        capabilities.append(ScopedCapability(
            category=CapabilityCategory.SYSTEM,
            action=CapabilityAction.EXEC,
            scope=["root"],
            scope_resolved=True,
            source_file=relative_name,
            source_line=line_no,
        ))

    # --- No USER instruction at all (implicit root) ---
    if not _RE_USER_ANY.search(content):
        restricted.append(Finding(
            file=relative_name,
            line=1,
            pattern="dockerfile:implicit_root",
            severity=FindingSeverity.RESTRICTED,
            message="No USER instruction — container runs as root by default.",
            suggested_fix="Add 'USER nonroot' or 'USER 1000' before CMD/ENTRYPOINT.",
        ))
        capabilities.append(ScopedCapability(
            category=CapabilityCategory.SYSTEM,
            action=CapabilityAction.EXEC,
            scope=["root"],
            scope_resolved=True,
            source_file=relative_name,
            source_line=1,
        ))

    # --- Dangerous EXPOSE ports ---
    for match in _RE_EXPOSE.finditer(content):
        line_no = content[:match.start()].count("\n") + 1
        port_str = match.group(1)
        for token in port_str.split():
            token = token.strip().split("/")[0]  # strip protocol
            try:
                port = int(token)
            except ValueError:
                continue
            if port in _DANGEROUS_PORTS:
                restricted.append(Finding(
                    file=relative_name,
                    line=line_no,
                    pattern=f"dockerfile:expose_dangerous_port:{port}",
                    severity=FindingSeverity.RESTRICTED,
                    message=f"Exposing port {port} is a security risk.",
                    suggested_fix=f"Remove EXPOSE {port} unless explicitly needed.",
                ))
                capabilities.append(ScopedCapability(
                    category=CapabilityCategory.NETWORK,
                    action=CapabilityAction.LISTEN,
                    scope=[str(port)],
                    scope_resolved=True,
                    source_file=relative_name,
                    source_line=line_no,
                ))

    # --- ADD from remote URL ---
    for match in _RE_ADD_REMOTE.finditer(content):
        line_no = content[:match.start()].count("\n") + 1
        url = match.group(1)
        restricted.append(Finding(
            file=relative_name,
            line=line_no,
            pattern="dockerfile:add_remote_url",
            severity=FindingSeverity.RESTRICTED,
            message=f"ADD from remote URL ({url}). Prefer COPY + verified download.",
            suggested_fix="Use 'RUN curl -fsSL <url> -o /tmp/file && sha256sum --check' instead of ADD.",
        ))
        capabilities.append(ScopedCapability(
            category=CapabilityCategory.NETWORK,
            action=CapabilityAction.CONNECT,
            scope=[url],
            scope_resolved=True,
            source_file=relative_name,
            source_line=line_no,
        ))

    # --- Curl-pipe-bash in RUN ---
    for i, line in enumerate(lines, 1):
        if _RE_CURL_PIPE_BASH.search(line) or _RE_WGET_PIPE_BASH.search(line):
            prohibited.append(Finding(
                file=relative_name,
                line=i,
                pattern="dockerfile:curl_pipe_bash",
                severity=FindingSeverity.PROHIBITED,
                message="Curl-pipe-bash: untrusted remote code execution in container build.",
                suggested_fix="Download the script first, verify its checksum, then execute.",
            ))
            capabilities.append(ScopedCapability(
                category=CapabilityCategory.SUBPROCESS,
                action=CapabilityAction.EXEC,
                scope=["*"],
                scope_resolved=False,
                source_file=relative_name,
                source_line=i,
            ))

    # --- Risky package installs ---
    for i, line in enumerate(lines, 1):
        pkg_match = _RE_PKG_INSTALL.search(line)
        if pkg_match:
            pkg_list = pkg_match.group(2).lower()
            for pkg in _RISKY_PACKAGES:
                if re.search(rf"\b{re.escape(pkg)}\b", pkg_list):
                    restricted.append(Finding(
                        file=relative_name,
                        line=i,
                        pattern=f"dockerfile:risky_package:{pkg}",
                        severity=FindingSeverity.RESTRICTED,
                        message=f"Installing '{pkg}' in container — potential attack tool.",
                        suggested_fix=f"Remove '{pkg}' from production image. Use multi-stage build if needed for build only.",
                    ))

    # --- Sensitive volume mounts ---
    for match in _RE_SENSITIVE_VOLUME.finditer(content):
        line_no = content[:match.start()].count("\n") + 1
        vol_str = match.group(1)
        for pattern in _SENSITIVE_MOUNT_PATTERNS:
            if re.search(pattern, vol_str, re.IGNORECASE):
                restricted.append(Finding(
                    file=relative_name,
                    line=line_no,
                    pattern="dockerfile:sensitive_volume",
                    severity=FindingSeverity.RESTRICTED,
                    message=f"Sensitive path in VOLUME: {vol_str.strip()}",
                    suggested_fix="Remove sensitive volume mounts from the Dockerfile.",
                ))
                capabilities.append(ScopedCapability(
                    category=CapabilityCategory.FS,
                    action=CapabilityAction.READ,
                    scope=[vol_str.strip()],
                    scope_resolved=True,
                    source_file=relative_name,
                    source_line=line_no,
                ))
                break  # one finding per VOLUME line

    # --- --privileged / --cap-add ---
    for i, line in enumerate(lines, 1):
        priv_match = _RE_PRIVILEGED.search(line)
        if priv_match:
            restricted.append(Finding(
                file=relative_name,
                line=i,
                pattern="dockerfile:privileged_flag",
                severity=FindingSeverity.RESTRICTED,
                message=f"Privileged capability escalation: {priv_match.group(0)}",
                suggested_fix="Remove --privileged or limit --cap-add to only needed capabilities.",
            ))
            capabilities.append(ScopedCapability(
                category=CapabilityCategory.SYSTEM,
                action=CapabilityAction.EXEC,
                scope=["privileged"],
                scope_resolved=True,
                source_file=relative_name,
                source_line=i,
            ))

    # --- FROM :latest (unpinned) ---
    for match in _RE_FROM_LATEST.finditer(content):
        line_no = content[:match.start()].count("\n") + 1
        restricted.append(Finding(
            file=relative_name,
            line=line_no,
            pattern="dockerfile:unpinned_base",
            severity=FindingSeverity.RESTRICTED,
            message="Base image uses :latest tag — unpinned and non-reproducible.",
            suggested_fix="Pin the base image to a specific digest or version tag.",
        ))

    # --- ENV with secret-like key names ---
    for match in _RE_ENV_SECRET.finditer(content):
        key_name = match.group(1)
        value = match.group(2).strip()
        if _SECRET_KEY_NAMES.search(key_name) and value and value not in ("", '""', "''"):
            line_no = content[:match.start()].count("\n") + 1
            restricted.append(Finding(
                file=relative_name,
                line=line_no,
                pattern="dockerfile:env_secret",
                severity=FindingSeverity.RESTRICTED,
                message=f"ENV instruction with secret-like key '{key_name}'. Secrets baked into images are visible in image history.",
                suggested_fix="Use --secret or --mount=type=secret at build time, or inject secrets at runtime via environment variables.",
            ))
            capabilities.append(ScopedCapability(
                category=CapabilityCategory.SECRET,
                action=CapabilityAction.ACCESS,
                scope=[key_name],
                scope_resolved=True,
                source_file=relative_name,
                source_line=line_no,
            ))

    # --- ARG with secret-like key names ---
    for match in _RE_ARG_SECRET.finditer(content):
        key_name = match.group(1)
        value = match.group(2).strip()
        if _SECRET_KEY_NAMES.search(key_name) and value and value not in ("", '""', "''"):
            line_no = content[:match.start()].count("\n") + 1
            restricted.append(Finding(
                file=relative_name,
                line=line_no,
                pattern="dockerfile:arg_secret",
                severity=FindingSeverity.RESTRICTED,
                message=f"ARG instruction with secret-like key '{key_name}'. Build args are visible in image metadata and build logs.",
                suggested_fix="Use --secret or --mount=type=secret for build-time secrets instead of ARG.",
            ))
            capabilities.append(ScopedCapability(
                category=CapabilityCategory.SECRET,
                action=CapabilityAction.ACCESS,
                scope=[key_name],
                scope_resolved=True,
                source_file=relative_name,
                source_line=line_no,
            ))

    return prohibited, restricted, capabilities
