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

"""Shell script analyzer — regex-based capability extraction for .sh/.bat/.ps1.

Implements pattern-based detection for:
- Network commands (curl, wget, ssh, scp, rsync)
- Filesystem commands (rm, mv, cp, chmod, chown, mkdir)
- Cloud CLIs (aws, gcloud, az, kubectl, docker)
- Secret/env variable access ($API_KEY, $SECRET, $TOKEN, etc.)
- Dangerous patterns (eval, curl|sh pipe-to-shell)
- Environment-dumping / system-inspection commands (printenv, docker inspect, etc.)
"""

from __future__ import annotations

import logging
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


# ── Prohibited patterns in shell scripts ──

PROHIBITED_SHELL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"""curl\s+.*\|\s*(ba)?sh""", re.IGNORECASE),
        "Pipe-to-shell: curl output piped into sh/bash — remote code execution",
    ),
    (
        re.compile(r"""wget\s+.*\|\s*(ba)?sh""", re.IGNORECASE),
        "Pipe-to-shell: wget output piped into sh/bash — remote code execution",
    ),
    (
        re.compile(r"""\beval\s+["'\$]"""),
        "Dynamic code execution via eval in shell script",
    ),
    (
        re.compile(r"""\beval\s+\("""),
        "Dynamic code execution via eval in shell script",
    ),
    # Backtick command substitution piped to shell
    (
        re.compile(r"""`[^`]+`\s*\|\s*(ba)?sh""", re.IGNORECASE),
        "Command substitution piped into sh/bash — remote code execution",
    ),
    # PowerShell: Invoke-Expression (iex) is the PS equivalent of eval
    (
        re.compile(r"""\bInvoke-Expression\b""", re.IGNORECASE),
        "Dynamic code execution via Invoke-Expression in PowerShell",
    ),
    (
        re.compile(r"""\biex\s+""", re.IGNORECASE),
        "Dynamic code execution via iex alias in PowerShell",
    ),
    # PowerShell: downloading and executing in one pipeline
    (
        re.compile(r"""Invoke-WebRequest\b.*\|\s*Invoke-Expression""", re.IGNORECASE),
        "Pipe-to-exec: Invoke-WebRequest piped into Invoke-Expression — remote code execution",
    ),
    (
        re.compile(r"""iwr\b.*\|\s*iex""", re.IGNORECASE),
        "Pipe-to-exec: iwr piped into iex — remote code execution",
    ),
    # PowerShell: DownloadString piped to iex
    (
        re.compile(r"""DownloadString\s*\(.*\)\s*\|\s*(iex|Invoke-Expression)""", re.IGNORECASE),
        "Pipe-to-exec: DownloadString piped into Invoke-Expression — remote code execution",
    ),
    # Bash: source/dot-source of remote or dynamic content
    (
        re.compile(r"""\bsource\s+/dev/stdin"""),
        "Source from stdin — potential remote code execution",
    ),
    # Base64-encoded payload execution
    (
        re.compile(r"""base64\s+(-d|--decode)\b.*\|\s*(ba)?sh""", re.IGNORECASE),
        "Encoded payload execution: base64 decode piped to shell — obfuscated remote code execution",
    ),
    (
        re.compile(r"""base64\s+(-d|--decode)\b.*\|\s*(python|perl|ruby|node)""", re.IGNORECASE),
        "Encoded payload execution: base64 decode piped to interpreter — obfuscated code execution",
    ),
    # Inline code execution via interpreters
    (
        re.compile(r"""\bpython[23]?\s+-c\s+['"]"""),
        "Inline Python code execution via python -c — embedded script execution",
    ),
    (
        re.compile(r"""\bperl\s+-e\s+['"]"""),
        "Inline Perl code execution via perl -e — embedded script execution",
    ),
    (
        re.compile(r"""\bruby\s+-e\s+['"]"""),
        "Inline Ruby code execution via ruby -e — embedded script execution",
    ),
    (
        re.compile(r"""\bnode\s+-e\s+['"]"""),
        "Inline Node.js code execution via node -e — embedded script execution",
    ),
    # Netcat reverse shell patterns
    (
        re.compile(r"""\b(nc|ncat|netcat)\b.*-[elp]""", re.IGNORECASE),
        "Netcat with listener/exec flag — potential reverse shell",
    ),
    (
        re.compile(r"""/dev/tcp/"""),
        "Bash /dev/tcp — raw TCP connection, common in reverse shells",
    ),
    # Overly permissive file permissions
    (
        re.compile(r"""\bchmod\s+(777|666|a\+rwx)\b"""),
        "Overly permissive file permissions (chmod 777/666) — world-writable files",
    ),
    # Multi-stage download and execute
    (
        re.compile(r"""curl\s+.*-o\s+\S+\s*&&\s*(ba)?sh\s""", re.IGNORECASE),
        "Download-and-execute: curl download followed by shell execution",
    ),
    (
        re.compile(r"""wget\s+.*-O\s+\S+\s*&&\s*(ba)?sh\s""", re.IGNORECASE),
        "Download-and-execute: wget download followed by shell execution",
    ),
]


# ── Network commands ──

NETWORK_COMMANDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"""\bcurl\b"""), "curl"),
    (re.compile(r"""\bwget\b"""), "wget"),
    (re.compile(r"""\bssh\b"""), "ssh"),
    (re.compile(r"""\bscp\b"""), "scp"),
    (re.compile(r"""\brsync\b"""), "rsync"),
    (re.compile(r"""\bnc\b"""), "nc"),
    (re.compile(r"""\bnetcat\b"""), "netcat"),
    (re.compile(r"""\bsocat\b"""), "socat"),
    (re.compile(r"""\bftp\b"""), "ftp"),
    (re.compile(r"""\bsftp\b"""), "sftp"),
    (re.compile(r"""\btelnet\b"""), "telnet"),
    (re.compile(r"""\bnslookup\b"""), "nslookup"),
    (re.compile(r"""\bdig\b"""), "dig"),
    (re.compile(r"""\bping\b"""), "ping"),
    (re.compile(r"""\btcpdump\b"""), "tcpdump"),
    (re.compile(r"""\bnmap\b"""), "nmap"),
    (re.compile(r"""\biptables\b"""), "iptables"),
    (re.compile(r"""\bnetstat\b"""), "netstat"),
    (re.compile(r"""\bss\b"""), "ss"),
    # PowerShell network commands
    (re.compile(r"""\bInvoke-WebRequest\b""", re.IGNORECASE), "Invoke-WebRequest"),
    (re.compile(r"""\biwr\b""", re.IGNORECASE), "iwr"),
    (re.compile(r"""\bInvoke-RestMethod\b""", re.IGNORECASE), "Invoke-RestMethod"),
    (re.compile(r"""\birm\b""", re.IGNORECASE), "irm"),
    (re.compile(r"""\bNew-Object\s+System\.Net""", re.IGNORECASE), "System.Net"),
    (re.compile(r"""\bTest-Connection\b""", re.IGNORECASE), "Test-Connection"),
    (re.compile(r"""\bTest-NetConnection\b""", re.IGNORECASE), "Test-NetConnection"),
]


# ── Filesystem commands ──

FS_WRITE_COMMANDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"""\brm\b"""), "rm"),
    (re.compile(r"""\bmv\b"""), "mv"),
    (re.compile(r"""\bcp\b"""), "cp"),
    (re.compile(r"""\bmkdir\b"""), "mkdir"),
    (re.compile(r"""\bchmod\b"""), "chmod"),
    (re.compile(r"""\bchown\b"""), "chown"),
    (re.compile(r"""\btouch\b"""), "touch"),
    (re.compile(r"""\bln\b"""), "ln"),
    (re.compile(r"""\btar\b"""), "tar"),
    (re.compile(r"""\bunzip\b"""), "unzip"),
    (re.compile(r"""\bzip\b"""), "zip"),
    (re.compile(r"""\bsed\b"""), "sed"),
    (re.compile(r"""\bawk\b"""), "awk"),
    (re.compile(r"""\bdd\b"""), "dd"),
    (re.compile(r"""\btee\b"""), "tee"),
    (re.compile(r"""\bshred\b"""), "shred"),
    (re.compile(r"""\btruncate\b"""), "truncate"),
    (re.compile(r"""\bmkfifo\b"""), "mkfifo"),
    (re.compile(r"""\binstall\b"""), "install"),
    # Redirect to file (>>file or >file)
    (re.compile(r""">+\s*\S"""), ">"),
    # PowerShell filesystem write commands
    (re.compile(r"""\bSet-Content\b""", re.IGNORECASE), "Set-Content"),
    (re.compile(r"""\bAdd-Content\b""", re.IGNORECASE), "Add-Content"),
    (re.compile(r"""\bOut-File\b""", re.IGNORECASE), "Out-File"),
    (re.compile(r"""\bNew-Item\b""", re.IGNORECASE), "New-Item"),
    (re.compile(r"""\bRemove-Item\b""", re.IGNORECASE), "Remove-Item"),
    (re.compile(r"""\bCopy-Item\b""", re.IGNORECASE), "Copy-Item"),
    (re.compile(r"""\bMove-Item\b""", re.IGNORECASE), "Move-Item"),
    (re.compile(r"""\bRename-Item\b""", re.IGNORECASE), "Rename-Item"),
]

FS_READ_COMMANDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"""\bcat\b"""), "cat"),
    (re.compile(r"""\bhead\b"""), "head"),
    (re.compile(r"""\btail\b"""), "tail"),
    (re.compile(r"""\bless\b"""), "less"),
    (re.compile(r"""\bmore\b"""), "more"),
    (re.compile(r"""\bfind\b"""), "find"),
    (re.compile(r"""\bls\b"""), "ls"),
    (re.compile(r"""\bwc\b"""), "wc"),
    (re.compile(r"""\bstat\b"""), "stat"),
    (re.compile(r"""\bfile\b"""), "file"),
    (re.compile(r"""\bdu\b"""), "du"),
    (re.compile(r"""\bdf\b"""), "df"),
    (re.compile(r"""\breadlink\b"""), "readlink"),
    (re.compile(r"""\brealpath\b"""), "realpath"),
    (re.compile(r"""\bmd5sum\b"""), "md5sum"),
    (re.compile(r"""\bsha256sum\b"""), "sha256sum"),
    # PowerShell read commands
    (re.compile(r"""\bGet-Content\b""", re.IGNORECASE), "Get-Content"),
    (re.compile(r"""\bGet-ChildItem\b""", re.IGNORECASE), "Get-ChildItem"),
    (re.compile(r"""\bGet-Item\b""", re.IGNORECASE), "Get-Item"),
    (re.compile(r"""\bTest-Path\b""", re.IGNORECASE), "Test-Path"),
    (re.compile(r"""\bSelect-String\b""", re.IGNORECASE), "Select-String"),
]


# ── Subprocess / binary execution ──

EXEC_COMMANDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"""\bsudo\b"""), "sudo"),
    (re.compile(r"""\bdocker\b"""), "docker"),
    (re.compile(r"""\bkubectl\b"""), "kubectl"),
    (re.compile(r"""\baws\b"""), "aws"),
    (re.compile(r"""\bgcloud\b"""), "gcloud"),
    (re.compile(r"""\baz\b"""), "az"),
    (re.compile(r"""\bterraform\b"""), "terraform"),
    (re.compile(r"""\bansible\b"""), "ansible"),
    (re.compile(r"""\bhelm\b"""), "helm"),
    (re.compile(r"""\bnpm\b"""), "npm"),
    (re.compile(r"""\bnpx\b"""), "npx"),
    (re.compile(r"""\byarn\b"""), "yarn"),
    (re.compile(r"""\bpnpm\b"""), "pnpm"),
    (re.compile(r"""\bpip\b"""), "pip"),
    (re.compile(r"""\bpip3\b"""), "pip3"),
    (re.compile(r"""\bgem\b"""), "gem"),
    (re.compile(r"""\bcargo\b"""), "cargo"),
    (re.compile(r"""\bbrew\b"""), "brew"),
    (re.compile(r"""\bapt\b"""), "apt"),
    (re.compile(r"""\bapt-get\b"""), "apt-get"),
    (re.compile(r"""\byum\b"""), "yum"),
    (re.compile(r"""\bdnf\b"""), "dnf"),
    (re.compile(r"""\bpacman\b"""), "pacman"),
    (re.compile(r"""\bsnap\b"""), "snap"),
    (re.compile(r"""\bgit\b"""), "git"),
    (re.compile(r"""\bpython\b"""), "python"),
    (re.compile(r"""\bpython3\b"""), "python3"),
    (re.compile(r"""\bnode\b"""), "node"),
    (re.compile(r"""\bbash\b"""), "bash"),
    (re.compile(r"""\bsh\b"""), "sh"),
    (re.compile(r"""\bzsh\b"""), "zsh"),
    (re.compile(r"""\bcrontab\b"""), "crontab"),
    (re.compile(r"""\bsystemctl\b"""), "systemctl"),
    (re.compile(r"""\bservice\b"""), "service"),
    (re.compile(r"""\bmake\b"""), "make"),
    (re.compile(r"""\bcmake\b"""), "cmake"),
    (re.compile(r"""\bgcc\b"""), "gcc"),
    # PowerShell execution commands
    (re.compile(r"""\bStart-Process\b""", re.IGNORECASE), "Start-Process"),
    (re.compile(r"""\bSet-ExecutionPolicy\b""", re.IGNORECASE), "Set-ExecutionPolicy"),
    (re.compile(r"""\bRegister-ScheduledTask\b""", re.IGNORECASE), "Register-ScheduledTask"),
    (re.compile(r"""\bInstall-Module\b""", re.IGNORECASE), "Install-Module"),
    (re.compile(r"""\bInstall-Package\b""", re.IGNORECASE), "Install-Package"),
    (re.compile(r"""\bpowershell\b""", re.IGNORECASE), "powershell"),
    (re.compile(r"""\bpwsh\b""", re.IGNORECASE), "pwsh"),
    (re.compile(r"""\bcmd\b"""), "cmd"),
]


# ── Secret / env var access patterns ──

SECRET_ENV_PATTERN = re.compile(
    r"""\$\{?"""
    r"""(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE_KEY|"""
    r"""AWS_SECRET|AWS_ACCESS|AWS_SESSION_TOKEN|"""
    r"""GITHUB_TOKEN|GITHUB_SECRET|GH_TOKEN|"""
    r"""NPM_TOKEN|NPM_AUTH|DOCKER_PASSWORD|DOCKER_TOKEN|"""
    r"""DB_PASSWORD|DATABASE_URL|DATABASE_PASSWORD|"""
    r"""REDIS_URL|REDIS_PASSWORD|MONGO_URI|MONGO_PASSWORD|"""
    r"""OPENAI_API_KEY|ANTHROPIC_API_KEY|"""
    r"""STRIPE_KEY|STRIPE_SECRET|"""
    r"""SLACK_TOKEN|SLACK_WEBHOOK|SLACK_SECRET|"""
    r"""TWILIO_TOKEN|TWILIO_AUTH|TWILIO_SID|"""
    r"""SENDGRID_API_KEY|SENDGRID_KEY|"""
    r"""JWT_SECRET|SESSION_SECRET|COOKIE_SECRET|"""
    r"""SSH_KEY|SSH_PRIVATE_KEY|SSH_PASSPHRASE|"""
    r"""ENCRYPTION_KEY|SIGNING_KEY|MASTER_KEY|"""
    r"""AZURE_SECRET|AZURE_KEY|AZURE_TENANT|"""
    r"""GCP_KEY|GOOGLE_APPLICATION_CREDENTIALS|"""
    r"""HEROKU_API_KEY|VERCEL_TOKEN|NETLIFY_TOKEN|"""
    r"""PYPI_TOKEN|PYPI_PASSWORD|"""
    r"""SONAR_TOKEN|CODECOV_TOKEN|"""
    r"""CI_TOKEN|DEPLOY_KEY|DEPLOY_TOKEN)"""
    r"""\}?""",
    re.IGNORECASE,
)

# ── Environment / source patterns ──

ENV_SOURCE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"""\bsource\s+.*\.env\b"""),
        "Sourcing .env file — loading secrets into environment",
    ),
    (
        re.compile(r"""\.\s+.*\.env\b"""),
        "Dot-sourcing .env file — loading secrets into environment",
    ),
    (
        re.compile(r"""\bexport\s+\w*(SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL)\w*\s*=""", re.IGNORECASE),
        "Exporting secret/credential to environment variable",
    ),
]


# ── Environment-dumping / system-inspection commands ──
# These commands dump secrets, credentials, or infrastructure state to stdout.
# A tool that looks "safe" but runs these is the classic Snake pattern.

ENV_DUMP_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"""\bdocker\s+compose\s+config\b""", re.IGNORECASE),
        "docker compose config — resolves .env vars and dumps them to stdout",
    ),
    (
        re.compile(r"""\bdocker\s+inspect\b""", re.IGNORECASE),
        "docker inspect — dumps container JSON including environment variables",
    ),
    (
        re.compile(r"""\bprintenv\b"""),
        "printenv — dumps all environment variables to stdout",
    ),
    (
        re.compile(r"""^\s*\benv\b\s*$"""),
        "env — dumps all environment variables to stdout",
    ),
    (
        re.compile(r"""\benv\b\s*\|"""),
        "env piped to another command — environment variable exfiltration",
    ),
    (
        re.compile(r"""\bkubectl\s+get\s+secrets?\b""", re.IGNORECASE),
        "kubectl get secret — dumps Kubernetes secrets",
    ),
    (
        re.compile(r"""\bgit\s+config\s+--list\b""", re.IGNORECASE),
        "git config --list — dumps git configuration including credentials",
    ),
    (
        re.compile(r"""\bset\b\s*$"""),
        "set — dumps all shell variables including secrets",
    ),
    (
        re.compile(r"""\bcompgen\s+-v\b"""),
        "compgen -v — lists all shell variable names",
    ),
    # PowerShell equivalents
    (
        re.compile(r"""\bGet-ChildItem\s+Env:\b""", re.IGNORECASE),
        "Get-ChildItem Env: — dumps all environment variables (PowerShell)",
    ),
    (
        re.compile(r"""\b\$env:\b""", re.IGNORECASE),
        "Direct environment variable access via $env: (PowerShell)",
    ),
    (
        re.compile(r"""\bGet-AzKeyVaultSecret\b""", re.IGNORECASE),
        "Get-AzKeyVaultSecret — dumps Azure Key Vault secrets (PowerShell)",
    ),
]


def _strip_comments(line: str) -> str:
    """Strip shell comments from a line (preserving strings is best-effort)."""
    # Simple approach: if # appears outside of quotes, strip from there
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i]
    return line


def parse_shell_file(
    file_path: Path, relative_name: str
) -> tuple[list[Finding], list[Finding], list[ScopedCapability]]:
    """Parse a shell script and extract findings + capabilities.

    Returns:
        (prohibited_findings, restricted_findings, capabilities)
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Could not read %s: %s", file_path, e)
        return [], [], []

    prohibited: list[Finding] = []
    restricted: list[Finding] = []
    capabilities: list[ScopedCapability] = []

    # Track already-seen capabilities to avoid duplicates
    seen_caps: set[tuple[str, str]] = set()

    lines = content.splitlines()

    for line_num, raw_line in enumerate(lines, start=1):
        line = _strip_comments(raw_line).strip()
        if not line:
            continue

        # ── Prohibited patterns (full-line matching) ──
        for pattern, message in PROHIBITED_SHELL_PATTERNS:
            if pattern.search(line):
                prohibited.append(
                    Finding(
                        file=relative_name,
                        line=line_num,
                        col=0,
                        pattern=pattern.pattern.strip(),
                        severity=FindingSeverity.PROHIBITED,
                        message=message,
                    )
                )

        # ── Network commands ──
        for pattern, cmd_name in NETWORK_COMMANDS:
            if pattern.search(line):
                cap_key = ("network", "connect")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.NETWORK,
                        action=CapabilityAction.CONNECT,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Network command: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break  # One match per line for this category

        # ── Filesystem write commands ──
        for pattern, cmd_name in FS_WRITE_COMMANDS:
            if pattern.search(line):
                cap_key = ("fs", "write")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.FS,
                        action=CapabilityAction.WRITE,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Filesystem write command: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Filesystem read commands ──
        for pattern, cmd_name in FS_READ_COMMANDS:
            if pattern.search(line):
                cap_key = ("fs", "read")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.FS,
                        action=CapabilityAction.READ,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Filesystem read command: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Subprocess / binary execution ──
        for pattern, cmd_name in EXEC_COMMANDS:
            if pattern.search(line):
                cap = ScopedCapability(
                    category=CapabilityCategory.SUBPROCESS,
                    action=CapabilityAction.EXEC,
                    scope=[cmd_name],
                    scope_resolved=True,
                )
                cap_key = ("subprocess", cmd_name)
                if cap_key not in seen_caps:
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"External binary execution: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Secret / env variable access ──
        secret_match = SECRET_ENV_PATTERN.search(line)
        if secret_match:
            var_name = secret_match.group(1)
            cap_key = ("secret", "access")
            if cap_key not in seen_caps:
                cap = ScopedCapability(
                    category=CapabilityCategory.SECRET,
                    action=CapabilityAction.ACCESS,
                    scope=["*"],
                    scope_resolved=False,
                )
                restricted.append(
                    Finding(
                        file=relative_name,
                        line=line_num,
                        col=0,
                        pattern=f"${var_name}",
                        severity=FindingSeverity.RESTRICTED,
                        capability=cap,
                        message=f"Secret/credential access via environment variable: ${var_name}",
                    )
                )
                capabilities.append(cap)
                seen_caps.add(cap_key)

        # ── Environment sourcing / exporting secrets ──
        for pattern, message in ENV_SOURCE_PATTERNS:
            if pattern.search(line):
                cap_key = ("env", "source")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.ENV,
                        action=CapabilityAction.READ,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern="env_source",
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=message,
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Environment-dumping / system-inspection commands ──
        for pattern, message in ENV_DUMP_PATTERNS:
            if pattern.search(line):
                cap_key = ("secret", "env_dump")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.SECRET,
                        action=CapabilityAction.ACCESS,
                        scope=["env_dump"],
                        scope_resolved=True,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern="env_dump",
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"System inspection: {message}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

    return prohibited, restricted, capabilities
