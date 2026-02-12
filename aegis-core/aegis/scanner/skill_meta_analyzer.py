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

"""SKILL.md and manifest meta-analyzer — the claim-vs-reality bridge.

This module fills the gap between documentation analysis (what OpenClaw does)
and code analysis (what Aegis's AST scanner does). It reads the SKILL.md file,
extracts what the skill *claims* about itself, and cross-references those
claims against:

1. The actual file manifest (do referenced files exist?)
2. The code-level capabilities Aegis found (does the code match the claims?)
3. Credential declarations vs. actual credential access
4. Install mechanism and execution model
5. Persistence and privilege metadata

The result is a set of MetaInsight findings that highlight discrepancies —
places where what the skill says and what the skill does don't match.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from aegis.models.capabilities import (
    MetaInsight,
    MetaInsightCategory,
    MetaInsightSeverity,
    ScopedCapability,
)

logger = logging.getLogger(__name__)


# ── Technology / integration keyword detection ─────────────────────
# We look for these in the SKILL.md description to understand what the
# skill *claims* it integrates with.

TECHNOLOGY_KEYWORDS: dict[str, list[str]] = {
    "cloud_providers": [
        "aws", "amazon web services", "gcloud", "google cloud", "gcp",
        "azure", "microsoft azure", "digitalocean", "heroku", "vercel",
        "cloudflare", "linode",
    ],
    "containers": [
        "docker", "kubernetes", "k8s", "helm", "container", "pod",
        "deployment", "docker-compose", "dockerfile",
    ],
    "databases": [
        "postgres", "postgresql", "mysql", "mongodb", "redis",
        "elasticsearch", "dynamodb", "sqlite", "database", "sql server",
        "cassandra", "neo4j", "influxdb",
    ],
    "ci_cd": [
        "github actions", "gitlab ci", "jenkins", "circleci", "travis",
        "terraform", "ansible", "puppet", "chef",
    ],
    "monitoring": [
        "prometheus", "grafana", "datadog", "new relic", "sentry",
        "splunk", "elk", "kibana", "cloudwatch", "monitoring",
    ],
    "data_science": [
        "spark", "hadoop", "kafka", "airflow", "mlflow",
        "tensorflow", "pytorch", "pandas", "numpy", "scikit",
        "jupyter", "notebook", "training", "model",
    ],
    "messaging": [
        "rabbitmq", "kafka", "sqs", "sns", "pubsub", "nats",
        "celery", "redis queue", "message queue",
    ],
    "auth": [
        "oauth", "jwt", "saml", "ldap", "sso", "authentication",
        "authorization", "keycloak", "auth0",
    ],
}

# Flatten for quick lookup
ALL_TECH_KEYWORDS: dict[str, str] = {}
for category, keywords in TECHNOLOGY_KEYWORDS.items():
    for kw in keywords:
        ALL_TECH_KEYWORDS[kw] = category


# ── File/path reference patterns in SKILL.md ──────────────────────

FILE_REFERENCE_PATTERN = re.compile(
    r"""(?:^|\s|["'`(])"""                # preceded by whitespace, quote, or backtick
    r"""([\w./\-]+\.(?:py|sh|yaml|yml|json|toml|cfg|ini|txt|md|csv|sql|js|ts|go|rs|rb))"""
    r"""(?:\s|["'`),.]|$)""",             # followed by whitespace, quote, or punctuation
    re.IGNORECASE | re.MULTILINE,
)

DIR_REFERENCE_PATTERN = re.compile(
    r"""(?:^|\s|["'`(])"""
    r"""([\w./\-]+/)"""                   # path ending in /
    r"""(?:\s|["'`),.]|$)""",
    re.IGNORECASE | re.MULTILINE,
)

# ── Command reference patterns ────────────────────────────────────

COMMAND_REFERENCE_PATTERN = re.compile(
    r"""(?:^|\s|[`])"""
    r"""((?:pip|npm|docker|kubectl|helm|terraform|ansible|gcloud|aws|az|"""
    r"""pytest|python|node|bash|sh|make|cargo|go|ruby|java|mvn|gradle)"""
    r"""\s+[\w\-./]+)""",
    re.IGNORECASE | re.MULTILINE,
)

BINARY_REFERENCE_PATTERN = re.compile(
    r"""\b(pip|npm|yarn|docker|kubectl|helm|terraform|ansible|"""
    r"""gcloud|aws|az|pytest|python|python3|node|bash|sh|make|"""
    r"""cargo|go|ruby|java|mvn|gradle|cmake|gcc|g\+\+|"""
    r"""curl|wget|ssh|scp|rsync|git)\b""",
    re.IGNORECASE,
)

# ── MCP/OpenClaw tool name patterns (for extraction from SKILL.md) ──
# Backticked or quoted tool names: `web_fetch`, "sessions_spawn", etc.
TOOL_NAME_PATTERN = re.compile(
    r"""`([a-z][a-z0-9_]*(?:_[a-z0-9_]+)*)`""",  # `tool_name`
    re.IGNORECASE,
)
# Known tool names for validation (subset — we accept any snake_case tool-like token)
KNOWN_TOOL_NAMES = frozenset({
    "read", "write", "edit", "apply_patch", "exec", "process",
    "web_fetch", "web_search", "browser", "image", "canvas",
    "lobster", "llm_task", "memory_search", "memory_get",
    "sessions_spawn", "sessions_list", "sessions_history",
    "session_status", "sessions_send", "agents_list",
    "message", "nodes", "cron", "gateway", "secret",
})

# ── Credential / env var declaration patterns ─────────────────────

ENV_VAR_DECLARATION = re.compile(
    r"""(?:set|export|requires?|needs?|expects?|configure|provide)\s+"""
    r"""[`"']?(\w+(?:_(?:KEY|TOKEN|SECRET|PASSWORD|URL|URI|CREDENTIAL|AUTH))\w*)[`"']?""",
    re.IGNORECASE,
)

ENV_VAR_REFERENCE = re.compile(
    r"""[`"']?([A-Z][A-Z0-9_]*(?:_(?:KEY|TOKEN|SECRET|PASSWORD|URL|URI|CREDENTIAL|AUTH))[A-Z0-9_]*)[`"']?""",
)

# ── Install mechanism files ───────────────────────────────────────

INSTALL_FILES = {
    "setup.py", "setup.cfg", "pyproject.toml",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "Makefile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Cargo.toml", "go.mod", "Gemfile",
}

# ── Persistence / privilege metadata keys ─────────────────────────
# Fields in Cursor skill config that affect how/when the skill runs.

PERSISTENCE_KEYS = {
    "always",           # always: true means it runs on every invocation
    "model_invocable",  # can the AI invoke it without user asking
    "force_install",    # installed system-wide without opt-in
    "auto_run",         # runs automatically on certain triggers
    "startup",          # runs at IDE startup
}


def _read_skill_md(target_dir: Path) -> str | None:
    """Find and read the SKILL.md file. Returns None if not found."""
    # Try common locations
    candidates = [
        target_dir / "SKILL.md",
        target_dir / "skill.md",
        target_dir / "README.md",
        target_dir / "readme.md",
    ]
    for candidate in candidates:
        if candidate.exists():
            try:
                return candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    return None


def _read_skill_config(target_dir: Path) -> dict[str, Any] | None:
    """Read skill configuration (JSON/YAML metadata) if present."""
    candidates = [
        target_dir / "skill.json",
        target_dir / "skill.yaml",
        target_dir / "skill.yml",
        target_dir / ".skill.json",
        target_dir / "manifest.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
                if candidate.suffix == ".json":
                    return json.loads(text)
                elif candidate.suffix in (".yaml", ".yml"):
                    import yaml
                    return yaml.safe_load(text)
            except Exception:
                continue
    return None


def extract_declared_tools(
    target_dir: Path,
    skill_md: str | None,
) -> list[str]:
    """Extract declared/requested MCP/OpenClaw tool names from skill config and SKILL.md.

    Sources:
      - skill.json / skill.yaml: tools, requires.tools
      - SKILL.md: backticked tool names like `web_fetch`, `sessions_spawn`

    Returns deduplicated list of tool names (lowercase).
    """
    tools: set[str] = set()

    # From config
    config = _read_skill_config(target_dir)
    if config:
        # Direct tools list
        if isinstance(config.get("tools"), list):
            for t in config["tools"]:
                if isinstance(t, str) and t.strip():
                    tools.add(t.strip().lower())
        # Nested under requires
        requires = config.get("requires") or {}
        if isinstance(requires, dict):
            req_tools = requires.get("tools")
            if isinstance(req_tools, list):
                for t in req_tools:
                    if isinstance(t, str) and t.strip():
                        tools.add(t.strip().lower())
        # OpenClaw-style
        openclaw = config.get("openclaw") or config.get("clawdbot") or {}
        if isinstance(openclaw, dict):
            oc_tools = openclaw.get("tools")
            if isinstance(oc_tools, list):
                for t in oc_tools:
                    if isinstance(t, str) and t.strip():
                        tools.add(t.strip().lower())

    # From SKILL.md — backticked tool names
    if skill_md:
        for match in TOOL_NAME_PATTERN.finditer(skill_md):
            name = match.group(1).lower()
            # Accept known tools or snake_case identifiers that look like tools
            if name in KNOWN_TOOL_NAMES or (
                "_" in name and name.replace("_", "").isalnum()
            ):
                tools.add(name)

    return sorted(tools)


def _extract_claimed_technologies(text: str) -> dict[str, list[str]]:
    """Extract technology keywords mentioned in the SKILL.md text.

    Returns a dict mapping category → list of matched keywords.
    """
    text_lower = text.lower()
    found: dict[str, list[str]] = {}
    for keyword, category in ALL_TECH_KEYWORDS.items():
        if keyword in text_lower:
            if category not in found:
                found[category] = []
            if keyword not in found[category]:
                found[category].append(keyword)
    return found


def _extract_referenced_files(text: str) -> list[str]:
    """Extract file paths referenced in the SKILL.md text."""
    files = set()
    for match in FILE_REFERENCE_PATTERN.finditer(text):
        path = match.group(1)
        # Filter out common false positives
        if not path.startswith("http") and "/" not in path[:1]:
            files.add(path)
    for match in DIR_REFERENCE_PATTERN.finditer(text):
        files.add(match.group(1))
    return sorted(files)


def _extract_referenced_binaries(text: str) -> list[str]:
    """Extract binary/command names referenced in the SKILL.md."""
    return sorted({m.group(1).lower() for m in BINARY_REFERENCE_PATTERN.finditer(text)})


def _extract_declared_env_vars(text: str) -> list[str]:
    """Extract environment variable names declared/referenced in SKILL.md."""
    env_vars = set()
    for match in ENV_VAR_DECLARATION.finditer(text):
        env_vars.add(match.group(1))
    for match in ENV_VAR_REFERENCE.finditer(text):
        env_vars.add(match.group(1))
    return sorted(env_vars)


def _parse_skill_md_frontmatter(skill_md: str | None) -> dict[str, Any] | None:
    """Parse YAML frontmatter from SKILL.md (content between --- delimiters)."""
    if not skill_md or not skill_md.strip().startswith("---"):
        return None
    try:
        import yaml

        parts = skill_md.strip().split("---", 2)
        if len(parts) < 2:
            return None
        front = parts[1].strip()
        if not front:
            return None
        data = yaml.safe_load(front)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _extract_bins_from_nested(config: dict[str, Any], *paths: str) -> list[str]:
    """Extract bin names from nested dict paths like ('openclaw', 'requires', 'bins')."""
    bins: list[str] = []
    for path in paths:
        d = config
        keys = path.split(".")
        for k in keys:
            d = d.get(k) if isinstance(d, dict) else None
            if d is None:
                break
        if isinstance(d, list):
            for item in d:
                if isinstance(item, str) and item.strip():
                    bins.append(item.strip().lower())
    return bins


def _extract_declared_binaries(
    target_dir: Path,
    skill_md: str | None,
    skill_config: dict[str, Any] | None,
) -> tuple[list[str], bool]:
    """Extract declared binary names from skill config and SKILL.md.

    Returns:
        (declared_bin_names, has_any_declaration)
        has_any_declaration is True if we found explicit bins or allowed-tools.
    """
    bins: list[str] = []
    has_any_declaration = False

    # From skill.json / skill config
    if skill_config:
        extracted = _extract_bins_from_nested(
            skill_config,
            "openclaw.requires.bins",
            "clawdbot.requires.bins",
            "requires.bins",
        )
        bins.extend(extracted)
        if extracted:
            has_any_declaration = True

    # From SKILL.md frontmatter
    front = _parse_skill_md_frontmatter(skill_md)
    if front:
        # metadata can be inline JSON: metadata: { "openclaw": { "requires": { "bins": [...] } } }
        meta = front.get("metadata")
        if isinstance(meta, dict):
            extracted = _extract_bins_from_nested(
                meta,
                "openclaw.requires.bins",
                "clawdbot.requires.bins",
                "requires.bins",
            )
            bins.extend(extracted)
            if extracted:
                has_any_declaration = True
        elif isinstance(meta, str):
            try:
                meta_dict = json.loads(meta)
                if isinstance(meta_dict, dict):
                    extracted = _extract_bins_from_nested(
                        meta_dict,
                        "openclaw.requires.bins",
                        "clawdbot.requires.bins",
                        "requires.bins",
                    )
                    bins.extend(extracted)
                    if extracted:
                        has_any_declaration = True
            except json.JSONDecodeError:
                pass

        # allowed-tools: abstract, but counts as "has declaration"
        if front.get("allowed-tools") or front.get("allowed_tools"):
            has_any_declaration = True

    declared = sorted(set(b.strip().lower() for b in bins if b.strip()))
    return declared, has_any_declaration


# ── Main analysis functions ────────────────────────────────────────


def analyze_purpose_and_capability(
    skill_md: str,
    manifest_files: list[Path],
    code_capabilities: dict[str, dict[str, list[str]]],
    external_binaries: list[str],
) -> MetaInsight:
    """Analyze PURPOSE & CAPABILITY — do the claims match reality?

    Compares what the SKILL.md description says the skill does against
    what the code analysis actually found.
    """
    claimed_tech = _extract_claimed_technologies(skill_md)
    claimed_binaries = _extract_referenced_binaries(skill_md)
    manifest_extensions = {f.suffix.lower() for f in manifest_files}
    manifest_names = {f.name.lower() for f in manifest_files}

    evidence: list[str] = []
    issues: list[str] = []

    # Check: claims cloud providers but has no cloud CLI usage
    cloud_claims = claimed_tech.get("cloud_providers", [])
    has_cloud_in_code = any(
        b in external_binaries for b in ("aws", "gcloud", "az", "kubectl")
    )
    if cloud_claims and not has_cloud_in_code:
        issues.append(
            f"The description mentions cloud services ({', '.join(cloud_claims)}) "
            f"but no cloud CLI usage was found in the actual code."
        )
        evidence.append(f"Claimed cloud: {', '.join(cloud_claims)}")
        evidence.append("Cloud CLIs in code: none")

    # Check: claims containers but has no Dockerfile or docker usage
    container_claims = claimed_tech.get("containers", [])
    has_docker_file = any(
        n in manifest_names for n in ("dockerfile", "docker-compose.yml", "docker-compose.yaml")
    )
    has_docker_in_code = "docker" in external_binaries or "kubectl" in external_binaries
    if container_claims and not has_docker_file and not has_docker_in_code:
        issues.append(
            f"The description mentions containers ({', '.join(container_claims)}) "
            f"but no Dockerfile, docker-compose, or container commands were found."
        )
        evidence.append(f"Claimed containers: {', '.join(container_claims)}")
        evidence.append("Container files in manifest: none")

    # Check: claims databases but no database drivers or connection strings
    db_claims = claimed_tech.get("databases", [])
    has_db_in_code = "network" in code_capabilities  # rough proxy
    if db_claims and not has_db_in_code:
        issues.append(
            f"The description mentions databases ({', '.join(db_claims)}) "
            f"but no network connections or database drivers were found in code."
        )

    # Check: claims data science but no relevant libraries
    ds_claims = claimed_tech.get("data_science", [])
    has_ds_files = any(ext in manifest_extensions for ext in (".ipynb", ".csv", ".parquet"))
    if ds_claims and not has_ds_files and "subprocess" not in code_capabilities:
        issues.append(
            f"The description mentions data science tools ({', '.join(ds_claims)}) "
            f"but no notebooks, data files, or relevant subprocess calls were found."
        )

    # Check: claims many binaries but declares none
    if len(claimed_binaries) > 3 and not external_binaries:
        issues.append(
            f"The description references {len(claimed_binaries)} command-line tools "
            f"({', '.join(claimed_binaries[:5])}) but the code doesn't invoke any of them."
        )
        evidence.append(f"Claimed binaries: {', '.join(claimed_binaries)}")
        evidence.append("Binaries in code: none")

    # Build the insight
    if not claimed_tech and not claimed_binaries:
        return MetaInsight(
            category=MetaInsightCategory.PURPOSE,
            severity=MetaInsightSeverity.INFO,
            title="PURPOSE & CAPABILITY",
            summary="The SKILL.md does not make specific technology claims to verify.",
            detail=(
                "The description doesn't reference specific integrations, cloud "
                "providers, or external tools. There's nothing to cross-reference "
                "against the code."
            ),
            evidence=["No specific technology claims found in SKILL.md"],
        )

    if not issues:
        tech_list = [kw for kws in claimed_tech.values() for kw in kws]
        return MetaInsight(
            category=MetaInsightCategory.PURPOSE,
            severity=MetaInsightSeverity.PASS,
            title="PURPOSE & CAPABILITY",
            summary=(
                "The skill's claimed capabilities are consistent with what the code provides."
            ),
            detail=(
                f"The description mentions {', '.join(tech_list[:5])} and the code "
                f"analysis confirms matching capabilities. The skill appears to deliver "
                f"what it advertises."
            ),
            evidence=evidence or [f"Claimed technologies: {', '.join(tech_list[:5])}"],
        )

    severity = (
        MetaInsightSeverity.DANGER if len(issues) >= 3
        else MetaInsightSeverity.WARNING
    )

    return MetaInsight(
        category=MetaInsightCategory.PURPOSE,
        severity=severity,
        title="PURPOSE & CAPABILITY",
        summary=(
            f"The description claims capabilities that don't match what the code "
            f"provides — {len(issues)} mismatch(es) found."
        ),
        detail=(
            " ".join(issues) + "\n\n"
            "This mismatch suggests the skill either won't work as advertised "
            "without extra setup that isn't included, or the description is "
            "overstating what the skill actually does. Either way, the skill's "
            "documentation is not trustworthy as-is."
        ),
        evidence=evidence,
    )


def analyze_instruction_scope(
    skill_md: str,
    manifest_files: list[Path],
) -> MetaInsight:
    """Analyze INSTRUCTION SCOPE — do referenced files/commands actually exist?

    Checks if the SKILL.md references files, scripts, or paths that aren't
    present in the file manifest. Ghost references mean the instructions will
    cause the agent to look for things that don't exist — or worse, to reach
    outside the skill directory for them.
    """
    referenced_files = _extract_referenced_files(skill_md)
    referenced_binaries = _extract_referenced_binaries(skill_md)
    manifest_names = {str(f).replace("\\", "/") for f in manifest_files}
    manifest_basenames = {f.name for f in manifest_files}

    ghost_files: list[str] = []
    found_files: list[str] = []

    for ref in referenced_files:
        # Check if the referenced file exists in the manifest
        ref_normalized = ref.replace("\\", "/").lstrip("./")
        if ref_normalized in manifest_names or ref.split("/")[-1] in manifest_basenames:
            found_files.append(ref)
        else:
            ghost_files.append(ref)

    evidence: list[str] = []

    if ghost_files:
        evidence.append(f"Files referenced but missing: {', '.join(ghost_files[:10])}")
    if found_files:
        evidence.append(f"Files referenced and present: {', '.join(found_files[:5])}")
    if referenced_binaries:
        evidence.append(f"Commands referenced: {', '.join(referenced_binaries[:10])}")

    if not referenced_files and not referenced_binaries:
        return MetaInsight(
            category=MetaInsightCategory.INSTRUCTION_SCOPE,
            severity=MetaInsightSeverity.INFO,
            title="INSTRUCTION SCOPE",
            summary="The SKILL.md does not reference specific files or commands.",
            detail=(
                "The instructions are general and don't point to specific scripts, "
                "config files, or command invocations. This is neither good nor bad — "
                "it just means there's nothing to cross-reference against the manifest."
            ),
            evidence=evidence,
        )

    if not ghost_files:
        return MetaInsight(
            category=MetaInsightCategory.INSTRUCTION_SCOPE,
            severity=MetaInsightSeverity.PASS,
            title="INSTRUCTION SCOPE",
            summary="All files and paths referenced in the SKILL.md exist in the package.",
            detail=(
                f"The instructions reference {len(found_files)} file(s) and all of them "
                f"are present in the manifest. The instructions are well-scoped to what "
                f"the package actually contains."
            ),
            evidence=evidence,
        )

    # Ghost files found
    severity = (
        MetaInsightSeverity.DANGER if len(ghost_files) > 5
        else MetaInsightSeverity.WARNING
    )

    ghost_list = ", ".join(ghost_files[:8])
    remainder = f" and {len(ghost_files) - 8} more" if len(ghost_files) > 8 else ""

    return MetaInsight(
        category=MetaInsightCategory.INSTRUCTION_SCOPE,
        severity=severity,
        title="INSTRUCTION SCOPE",
        summary=(
            f"The SKILL.md references {len(ghost_files)} file(s) or path(s) that "
            f"don't exist in the package."
        ),
        detail=(
            f"The instructions reference: {ghost_list}{remainder} — but these "
            f"files are not present in the package manifest.\n\n"
            "This means the instructions will cause the AI agent to look for "
            "files that aren't there. The agent may then try to find them "
            "elsewhere on your system, download them, or create them — all of "
            "which happen outside the skill's controlled scope. This is how "
            "skills can trick an agent into accessing files or running commands "
            "that the skill itself doesn't contain."
        ),
        evidence=evidence,
    )


def analyze_install_mechanism(
    manifest_files: list[Path],
) -> MetaInsight:
    """Analyze INSTALL MECHANISM — what runs when you install this?

    Checks for setup scripts, install hooks, and executable files to
    understand what code executes during installation vs. runtime.
    """
    manifest_names = {f.name for f in manifest_files}
    manifest_basenames_lower = {f.name.lower() for f in manifest_files}

    found_install_files: list[str] = []
    for install_file in INSTALL_FILES:
        if install_file.lower() in manifest_basenames_lower:
            found_install_files.append(install_file)

    # Count executable Python scripts (files at the top level with shebangs)
    py_files = [f for f in manifest_files if f.suffix == ".py"]
    sh_files = [f for f in manifest_files if f.suffix in (".sh", ".bat", ".ps1")]
    executable_scripts = py_files + sh_files

    evidence: list[str] = []
    if found_install_files:
        evidence.append(f"Install files found: {', '.join(found_install_files)}")
    evidence.append(f"Python scripts: {len(py_files)}")
    evidence.append(f"Shell scripts: {len(sh_files)}")

    # Determine severity
    has_setup = any(
        f in manifest_basenames_lower for f in ("setup.py", "setup.cfg", "pyproject.toml")
    )
    has_dockerfile = "dockerfile" in manifest_basenames_lower
    has_makefile = "makefile" in manifest_basenames_lower

    if not found_install_files and not executable_scripts:
        return MetaInsight(
            category=MetaInsightCategory.INSTALL_MECHANISM,
            severity=MetaInsightSeverity.PASS,
            title="INSTALL MECHANISM",
            summary="No install scripts or executable files detected.",
            detail=(
                "The package contains no setup scripts, Dockerfiles, Makefiles, or "
                "executable shell scripts. Installation risk is minimal — there's "
                "no code that runs automatically during setup."
            ),
            evidence=evidence,
        )

    if not found_install_files and executable_scripts:
        return MetaInsight(
            category=MetaInsightCategory.INSTALL_MECHANISM,
            severity=MetaInsightSeverity.INFO,
            title="INSTALL MECHANISM",
            summary=(
                f"No formal install spec, but the package includes "
                f"{len(executable_scripts)} executable script(s)."
            ),
            detail=(
                f"There's no setup.py, pyproject.toml, or package manager config, "
                f"but the package contains {len(py_files)} Python script(s) and "
                f"{len(sh_files)} shell script(s). Because there's no controlled "
                f"install process, using this skill means executing these scripts "
                f"directly with your environment's Python or shell.\n\n"
                f"Review the script contents before running them — without a formal "
                f"install process, there are no dependency declarations to verify "
                f"and no sandboxing guarantees."
            ),
            evidence=evidence,
        )

    # Has install files
    install_risks: list[str] = []
    if has_setup:
        install_risks.append(
            "setup.py can execute arbitrary Python code during pip install — "
            "including network requests, file writes, and subprocess calls"
        )
    if has_dockerfile:
        install_risks.append(
            "a Dockerfile defines a build process that runs commands as root "
            "inside a container — review the RUN instructions"
        )
    if has_makefile:
        install_risks.append(
            "a Makefile runs shell commands — review the targets before running make"
        )

    severity = MetaInsightSeverity.WARNING if has_setup else MetaInsightSeverity.INFO

    return MetaInsight(
        category=MetaInsightCategory.INSTALL_MECHANISM,
        severity=severity,
        title="INSTALL MECHANISM",
        summary=(
            f"Found {len(found_install_files)} install-related file(s) that "
            f"execute code during setup."
        ),
        detail=(
            f"The package includes: {', '.join(found_install_files)}.\n\n"
            + (" ".join(install_risks) + "\n\n" if install_risks else "")
            + "Install-time code execution is the highest-risk moment because it "
            "runs before you've had a chance to audit the skill's behavior. Always "
            "inspect install scripts before running pip install or make."
        ),
        evidence=evidence,
    )


def analyze_credentials(
    skill_md: str,
    code_capabilities: dict[str, dict[str, list[str]]],
    claimed_tech: dict[str, list[str]],
) -> MetaInsight:
    """Analyze CREDENTIALS — does the skill declare what it actually accesses?

    Compares:
    - What integrations the description advertises (implies needing credentials)
    - What env vars / credentials the SKILL.md declares as required
    - What the code actually accesses (from Aegis code analysis)
    """
    declared_env_vars = _extract_declared_env_vars(skill_md)

    # What does the code actually access?
    code_reads_secrets = "secret" in code_capabilities
    code_reads_env = "env" in code_capabilities
    code_uses_network = "network" in code_capabilities

    # What integrations typically require credentials?
    needs_creds_categories = {"cloud_providers", "databases", "auth", "monitoring", "messaging"}
    claimed_needing_creds = {
        cat: kws for cat, kws in claimed_tech.items() if cat in needs_creds_categories
    }

    evidence: list[str] = []
    if declared_env_vars:
        evidence.append(f"Declared env vars: {', '.join(declared_env_vars[:8])}")
    if claimed_needing_creds:
        all_kws = [kw for kws in claimed_needing_creds.values() for kw in kws]
        evidence.append(f"Integrations needing credentials: {', '.join(all_kws[:8])}")
    evidence.append(f"Code reads secrets: {'yes' if code_reads_secrets else 'no'}")
    evidence.append(f"Code reads env vars: {'yes' if code_reads_env else 'no'}")

    # Case 1: Claims credential-heavy integrations but declares none
    if claimed_needing_creds and not declared_env_vars:
        integration_list = [kw for kws in claimed_needing_creds.values() for kw in kws]

        if code_reads_secrets or code_reads_env:
            severity = MetaInsightSeverity.DANGER
            detail = (
                f"The description advertises integrations that normally require "
                f"credentials ({', '.join(integration_list[:5])}) and the code "
                f"{'reads credentials' if code_reads_secrets else 'reads environment variables'} — "
                f"but the SKILL.md declares no required environment variables or "
                f"credentials.\n\n"
                f"This is a significant red flag. The skill accesses secrets in "
                f"its code but doesn't tell you which ones it needs or why. It "
                f"may be reading credentials you didn't intend to share, or it "
                f"may be accessing environment secrets opportunistically."
            )
        else:
            severity = MetaInsightSeverity.WARNING
            detail = (
                f"The description advertises integrations that normally require "
                f"credentials ({', '.join(integration_list[:5])}) but declares "
                f"no required environment variables or credentials.\n\n"
                f"This is disproportionate: either the skill is incomplete or "
                f"misdocumented, or its scripts may try to access environment "
                f"secrets or endpoints without declaring them. The code analysis "
                f"didn't find explicit credential access, but the mismatch "
                f"between claims and declarations deserves scrutiny."
            )

        return MetaInsight(
            category=MetaInsightCategory.CREDENTIALS,
            severity=severity,
            title="CREDENTIALS",
            summary=(
                f"The skill advertises credential-heavy integrations but declares "
                f"no required credentials."
            ),
            detail=detail,
            evidence=evidence,
        )

    # Case 2: Code accesses secrets but SKILL.md doesn't mention it
    if (code_reads_secrets or code_reads_env) and not declared_env_vars:
        return MetaInsight(
            category=MetaInsightCategory.CREDENTIALS,
            severity=MetaInsightSeverity.WARNING,
            title="CREDENTIALS",
            summary=(
                "The code accesses credentials or environment variables, but the "
                "SKILL.md doesn't declare which ones are needed."
            ),
            detail=(
                "Aegis's code analysis found that this skill reads "
                + ("stored credentials" if code_reads_secrets else "environment variables")
                + ", but the SKILL.md documentation doesn't list any required "
                "environment variables or credential configuration.\n\n"
                "A well-documented skill should explicitly declare every credential "
                "it needs so you can provide only what's required and nothing more. "
                "Undeclared credential access means the skill might be reading "
                "secrets you didn't intend to share."
            ),
            evidence=evidence,
        )

    # Case 3: Declares credentials and code matches
    if declared_env_vars and (code_reads_secrets or code_reads_env):
        return MetaInsight(
            category=MetaInsightCategory.CREDENTIALS,
            severity=MetaInsightSeverity.PASS,
            title="CREDENTIALS",
            summary=(
                "The skill declares its credential requirements, and the code "
                "accesses them as expected."
            ),
            detail=(
                f"The SKILL.md declares {len(declared_env_vars)} environment "
                f"variable(s) and the code analysis confirms credential access. "
                f"The declarations match the behavior — this is the expected "
                f"pattern for a well-documented skill.\n\n"
                f"Still verify that the declared credentials are appropriate for "
                f"the skill's stated purpose."
            ),
            evidence=evidence,
        )

    # Case 4: No credentials needed, none declared
    return MetaInsight(
        category=MetaInsightCategory.CREDENTIALS,
        severity=MetaInsightSeverity.PASS,
        title="CREDENTIALS",
        summary="No credential access detected, and none declared.",
        detail=(
            "The code does not access stored credentials or environment variables, "
            "and the SKILL.md doesn't declare any. This is consistent."
        ),
        evidence=evidence,
    )


def analyze_persistence_and_privilege(
    skill_md: str,
    skill_config: dict[str, Any] | None,
    code_capabilities: dict[str, dict[str, list[str]]],
) -> MetaInsight:
    """Analyze PERSISTENCE & PRIVILEGE — does the skill run when you don't expect it?

    Checks metadata flags that control when and how the skill executes:
    - always: true → runs on every agent invocation
    - model-invocable → AI can run it without user explicitly asking
    - force-install → installed system-wide without opt-in
    """
    evidence: list[str] = []
    issues: list[str] = []

    always_on = False
    model_invocable = False
    force_install = False

    if skill_config:
        always_on = skill_config.get("always", False) is True
        model_invocable = skill_config.get("model_invocable", True)  # default is usually True
        force_install = skill_config.get("force_install", False) is True

        if always_on:
            evidence.append("always: true — runs on every agent invocation")
            issues.append(
                "The skill sets 'always: true', meaning it runs on every single "
                "agent invocation — not just when you ask for it. This gives it "
                "persistent access to your agent sessions."
            )

        if force_install:
            evidence.append("force_install: true — installed system-wide")
            issues.append(
                "The skill is configured for force-install, meaning it installs "
                "system-wide rather than per-workspace. This extends its reach "
                "beyond any single project."
            )

        if model_invocable:
            evidence.append("model-invocable: the AI agent can run this autonomously")
        else:
            evidence.append("not model-invocable: requires explicit user request")
    else:
        evidence.append("No skill config file found (skill.json/skill.yaml)")

    # Check SKILL.md for persistence-related keywords
    md_lower = skill_md.lower() if skill_md else ""
    if "always: true" in md_lower or "always_on" in md_lower:
        evidence.append("SKILL.md mentions 'always' execution mode")
        if not always_on:
            issues.append(
                "The SKILL.md mentions always-on execution but the config "
                "doesn't set it. The documentation may be outdated."
            )

    # System-level access in code raises the stakes
    has_system_access = "system" in code_capabilities
    has_subprocess = "subprocess" in code_capabilities

    if always_on and (has_system_access or has_subprocess):
        issues.append(
            "Critically, this always-on skill also has system access or subprocess "
            "execution capability. A persistent skill with these powers runs "
            "unattended with broad access to your machine."
        )

    if not issues:
        detail_parts = []
        if skill_config:
            if not always_on:
                detail_parts.append(
                    "The skill does not set 'always: true' — it only runs when invoked."
                )
            if model_invocable:
                detail_parts.append(
                    "It is model-invocable, meaning the AI agent can run it "
                    "autonomously when it determines the skill is applicable. "
                    "This is the default configuration."
                )
            if not force_install:
                detail_parts.append(
                    "It is not force-installed system-wide — it's a per-workspace "
                    "or per-user installation."
                )
        else:
            detail_parts.append(
                "No skill configuration metadata was found. Default Cursor skill "
                "settings apply: model-invocable (the AI can run it when applicable) "
                "but not always-on."
            )

        return MetaInsight(
            category=MetaInsightCategory.PERSISTENCE,
            severity=MetaInsightSeverity.PASS,
            title="PERSISTENCE & PRIVILEGE",
            summary="Typical configuration — not always-on, not force-installed.",
            detail=" ".join(detail_parts),
            evidence=evidence,
        )

    severity = (
        MetaInsightSeverity.DANGER
        if (always_on and (has_system_access or has_subprocess))
        else MetaInsightSeverity.WARNING
    )

    return MetaInsight(
        category=MetaInsightCategory.PERSISTENCE,
        severity=severity,
        title="PERSISTENCE & PRIVILEGE",
        summary=(
            f"This skill has elevated persistence or privilege settings — "
            f"{len(issues)} concern(s) found."
        ),
        detail=" ".join(issues),
        evidence=evidence,
    )


def analyze_tool_declarations(
    target_dir: Path,
    skill_md: str | None,
    skill_config: dict[str, Any] | None,
    external_binaries: list[str],
) -> MetaInsight:
    """Analyze TOOLS — do declared binaries match what the code uses?

    Compares explicitly declared binaries (from skill.json, SKILL.md metadata)
    against Aegis-detected external_binaries. Surfaces undeclared use and
    over-declaration as worth-reviewing findings.
    """
    declared_bins, has_declaration = _extract_declared_binaries(
        target_dir, skill_md, skill_config
    )
    detected_set = {b.lower() for b in external_binaries}
    declared_set = {b.lower() for b in declared_bins}

    undeclared = detected_set - declared_set
    over_declared = declared_set - detected_set

    evidence: list[str] = []
    if declared_bins:
        evidence.append(f"Declared: {', '.join(sorted(declared_set))}")
    if external_binaries:
        evidence.append(f"Detected in code: {', '.join(sorted(detected_set))}")

    # Undeclared use: code uses binaries not in the declaration
    if undeclared and has_declaration and declared_bins:
        undeclared_list = sorted(undeclared)
        return MetaInsight(
            category=MetaInsightCategory.TOOLS,
            severity=MetaInsightSeverity.WARNING,
            title="TOOL DECLARATIONS",
            summary=(
                f"Code uses {', '.join(undeclared_list)} but the skill only "
                "declares other binaries. Worth double-checking."
            ),
            detail=(
                f"The skill declares it needs: {', '.join(sorted(declared_set))}. "
                f"However, the code analysis also found uses of: "
                f"{', '.join(undeclared_list)}. These may be used indirectly "
                "or via shell scripts Aegis can't fully trace. Consider updating "
                "the skill's declared tool list to match what it actually uses."
            ),
            evidence=evidence,
        )

    # Over-declaration: declared but not detected
    if over_declared and declared_bins:
        over_list = sorted(over_declared)
        return MetaInsight(
            category=MetaInsightCategory.TOOLS,
            severity=MetaInsightSeverity.INFO,
            title="TOOL DECLARATIONS",
            summary=(
                f"Skill declares {', '.join(over_list)} but the code doesn't "
                "appear to use them. May be optional or used indirectly."
            ),
            detail=(
                f"The skill declares it needs: {', '.join(sorted(declared_set))}. "
                f"Code analysis didn't find direct use of: {', '.join(over_list)}. "
                "These might be optional dependencies, used at install time, or "
                "invoked in ways Aegis doesn't detect (e.g. via shell scripts)."
            ),
            evidence=evidence,
        )

    # No declaration but has external binaries
    if not has_declaration and external_binaries:
        return MetaInsight(
            category=MetaInsightCategory.TOOLS,
            severity=MetaInsightSeverity.INFO,
            title="TOOL DECLARATIONS",
            summary=(
                "The skill doesn't declare which binaries it needs; "
                f"code uses {', '.join(sorted(detected_set))}."
            ),
            detail=(
                "The code invokes external programs, but the skill doesn't "
                "explicitly declare its tool requirements (e.g. via requires.bins "
                "in skill.json or SKILL.md metadata). Declaring them helps users "
                "and runtimes know what to expect."
            ),
            evidence=evidence,
        )

    # Match or nothing to compare
    if declared_bins and not undeclared and not over_declared:
        return MetaInsight(
            category=MetaInsightCategory.TOOLS,
            severity=MetaInsightSeverity.PASS,
            title="TOOL DECLARATIONS",
            summary="Declared binaries match what the code uses.",
            detail=(
                f"The skill declares {', '.join(sorted(declared_set))} and "
                "the code analysis confirms their use. Consistent."
            ),
            evidence=evidence,
        )

    # No declaration and no binaries
    return MetaInsight(
        category=MetaInsightCategory.TOOLS,
        severity=MetaInsightSeverity.INFO,
        title="TOOL DECLARATIONS",
        summary="No tool declarations to verify; code doesn't invoke external binaries.",
        detail=(
            "The skill doesn't declare external tool requirements, and the "
            "code doesn't invoke subprocess binaries. Nothing to compare."
        ),
        evidence=evidence if evidence else ["No declared or detected binaries"],
    )


# ── Main entry point ───────────────────────────────────────────────


def analyze_skill_meta(
    target_dir: Path,
    manifest_files: list[Path],
    code_capabilities: dict[str, dict[str, list[str]]],
    external_binaries: list[str],
) -> list[MetaInsight]:
    """Run the full meta-analysis suite.

    Cross-references the SKILL.md documentation, skill config metadata,
    and file manifest against Aegis's code analysis to find discrepancies.

    Args:
        target_dir: Path to the skill directory
        manifest_files: All files in the skill package
        code_capabilities: Capability map from Aegis code analysis
        external_binaries: Binaries detected by code analysis

    Returns:
        List of MetaInsight findings, one per analysis category.
    """
    insights: list[MetaInsight] = []

    # Read SKILL.md and config
    skill_md = _read_skill_md(target_dir)
    skill_config = _read_skill_config(target_dir)

    if skill_md is None:
        # No SKILL.md — we can still analyze install mechanism and config
        insights.append(
            MetaInsight(
                category=MetaInsightCategory.PURPOSE,
                severity=MetaInsightSeverity.WARNING,
                title="PURPOSE & CAPABILITY",
                summary="No SKILL.md or README.md found — the skill doesn't describe itself.",
                detail=(
                    "There is no SKILL.md or README.md in the package. Without "
                    "documentation, there's no way to verify whether the skill's "
                    "code matches its intended purpose. A skill that doesn't describe "
                    "itself is asking you to trust it blindly."
                ),
                evidence=["No SKILL.md, skill.md, README.md, or readme.md found"],
            )
        )
        insights.append(
            MetaInsight(
                category=MetaInsightCategory.INSTRUCTION_SCOPE,
                severity=MetaInsightSeverity.INFO,
                title="INSTRUCTION SCOPE",
                summary="No SKILL.md to analyze for instruction scope.",
                detail="Without a SKILL.md, there are no instructions to cross-reference.",
                evidence=["No SKILL.md found"],
            )
        )
    else:
        # Run SKILL.md-based analyses
        claimed_tech = _extract_claimed_technologies(skill_md)

        insights.append(
            analyze_purpose_and_capability(
                skill_md, manifest_files, code_capabilities, external_binaries
            )
        )
        insights.append(
            analyze_instruction_scope(skill_md, manifest_files)
        )
        insights.append(
            analyze_credentials(
                skill_md, code_capabilities, claimed_tech
            )
        )
        insights.append(
            analyze_persistence_and_privilege(
                skill_md, skill_config, code_capabilities
            )
        )

    # Always analyze install mechanism (doesn't need SKILL.md)
    insights.append(analyze_install_mechanism(manifest_files))

    # Tool declarations: run even when skill_md is None (skill_config may have requires.bins)
    insights.append(
        analyze_tool_declarations(
            target_dir, skill_md, skill_config, external_binaries
        )
    )

    return insights
