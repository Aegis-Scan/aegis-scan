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

"""Semgrep Rule Ingestion — loads Semgrep-format YAML rules and
converts them into Aegis findings.

Supports:
- pattern-regex rules (regex applied to source lines)
- Simple pattern rules converted to regex where feasible
- Severity mapping: ERROR → PROHIBITED, WARNING/INFO → RESTRICTED
- CWE/OWASP from metadata
- Optional aegis_capability mapping for combination analysis
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    Finding,
    FindingSeverity,
    ScopedCapability,
)

logger = logging.getLogger(__name__)

# ── Language to file extension mapping ──

_LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "js": {".js", ".jsx", ".mjs", ".cjs"},
    "ts": {".ts", ".tsx"},
    "generic": set(),  # matches all files
    "regex": set(),     # matches all files
}

# ── Severity mapping ──

_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "ERROR": FindingSeverity.PROHIBITED,
    "WARNING": FindingSeverity.RESTRICTED,
    "INFO": FindingSeverity.RESTRICTED,
}

# Features we cannot support — skip rules requiring these
_UNSUPPORTED_FEATURES = frozenset({
    "pattern-sources",
    "pattern-sinks",
    "pattern-propagators",
    "taint",
    "join",
    "metavariable-comparison",
    "metavariable-pattern",
    "pattern-not-inside",
    "pattern-inside",
    "pattern-not",
})


@dataclass
class SemgrepRule:
    """Parsed Semgrep rule ready for evaluation."""

    id: str
    regex_patterns: list[re.Pattern]
    message: str
    severity: FindingSeverity
    languages: list[str]
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    aegis_capability: Optional[str] = None  # e.g., "network:connect"
    source_file: str = ""


def _pattern_to_regex(pattern: str) -> Optional[str]:
    """Convert a simple Semgrep pattern to regex where feasible.

    Handles simple cases like:
    - eval(...) → \\beval\\s*\\(
    - os.system(...) → \\bos\\.system\\s*\\(
    - $X.innerHTML = ... → \\.innerHTML\\s*=

    Returns None if the pattern is too complex to convert.
    """
    # Skip patterns with advanced Semgrep features
    if any(marker in pattern for marker in ("...", "$", ":", "=~")):
        # But allow simple $X patterns — just strip the variable part
        pass

    stripped = pattern.strip()

    # Pattern: func(...) → \bfunc\s*\(
    m = re.match(r'^([\w.]+)\s*\(\s*\.\.\.\s*\)\s*$', stripped)
    if m:
        func_name = re.escape(m.group(1))
        return rf'\b{func_name}\s*\('

    # Pattern: func($X) → \bfunc\s*\(
    m = re.match(r'^([\w.]+)\s*\(\s*\$\w+.*\)\s*$', stripped)
    if m:
        func_name = re.escape(m.group(1))
        return rf'\b{func_name}\s*\('

    # Pattern: $X.method(...) → \.method\s*\(
    m = re.match(r'^\$\w+\.([\w]+)\s*\(.*\)\s*$', stripped)
    if m:
        method = re.escape(m.group(1))
        return rf'\.{method}\s*\('

    # Pattern: $X.property = ... → \.property\s*=
    m = re.match(r'^\$\w+\.([\w]+)\s*=\s*.*$', stripped)
    if m:
        prop = re.escape(m.group(1))
        return rf'\.{prop}\s*='

    return None


def _has_unsupported_features(rule_dict: dict) -> bool:
    """Check if a rule uses features we can't support."""
    for key in _UNSUPPORTED_FEATURES:
        if key in rule_dict:
            return True
    # Check nested patterns
    if "patterns" in rule_dict:
        for p in rule_dict["patterns"]:
            if isinstance(p, dict):
                for key in _UNSUPPORTED_FEATURES:
                    if key in p:
                        return True
    return False


def load_semgrep_rules(rules_dir: Path) -> list[SemgrepRule]:
    """Load all Semgrep-format YAML rules from a directory.

    Skips rules requiring unsupported features (taint mode, etc.).
    Logs count of skipped rules.

    Returns list of parsed SemgrepRule objects.
    """
    if not rules_dir.exists() or not rules_dir.is_dir():
        logger.debug("Semgrep rules directory not found: %s", rules_dir)
        return []

    rules: list[SemgrepRule] = []
    skipped = 0
    errors = 0

    for yaml_file in sorted(rules_dir.glob("*.y*ml")):
        try:
            content = yaml_file.read_text(encoding="utf-8")
            docs = list(yaml.safe_load_all(content))
        except Exception as e:
            logger.warning("Failed to parse Semgrep YAML %s: %s", yaml_file.name, e)
            errors += 1
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            rule_list = doc.get("rules", [doc] if "id" in doc else [])
            for rule_dict in rule_list:
                if not isinstance(rule_dict, dict):
                    continue

                rule_id = rule_dict.get("id", "")
                if not rule_id:
                    continue

                # Skip unsupported features
                if _has_unsupported_features(rule_dict):
                    skipped += 1
                    continue

                # Extract regex patterns
                regex_patterns: list[re.Pattern] = []

                # pattern-regex (direct regex)
                if "pattern-regex" in rule_dict:
                    try:
                        regex_patterns.append(
                            re.compile(rule_dict["pattern-regex"])
                        )
                    except re.error as e:
                        logger.warning(
                            "Invalid regex in rule %s: %s", rule_id, e
                        )
                        errors += 1
                        continue

                # pattern (simple pattern → try to convert to regex)
                if "pattern" in rule_dict and not regex_patterns:
                    regex_str = _pattern_to_regex(rule_dict["pattern"])
                    if regex_str:
                        try:
                            regex_patterns.append(re.compile(regex_str))
                        except re.error:
                            pass

                # pattern-either (list of patterns/regexes)
                if "pattern-either" in rule_dict and not regex_patterns:
                    for item in rule_dict["pattern-either"]:
                        if isinstance(item, dict):
                            if "pattern-regex" in item:
                                try:
                                    regex_patterns.append(
                                        re.compile(item["pattern-regex"])
                                    )
                                except re.error:
                                    pass
                            elif "pattern" in item:
                                regex_str = _pattern_to_regex(item["pattern"])
                                if regex_str:
                                    try:
                                        regex_patterns.append(
                                            re.compile(regex_str)
                                        )
                                    except re.error:
                                        pass

                # patterns (list of pattern dicts)
                if "patterns" in rule_dict and not regex_patterns:
                    for item in rule_dict["patterns"]:
                        if isinstance(item, dict):
                            if "pattern-regex" in item:
                                try:
                                    regex_patterns.append(
                                        re.compile(item["pattern-regex"])
                                    )
                                except re.error:
                                    pass
                            elif "pattern" in item:
                                regex_str = _pattern_to_regex(item["pattern"])
                                if regex_str:
                                    try:
                                        regex_patterns.append(
                                            re.compile(regex_str)
                                        )
                                    except re.error:
                                        pass

                if not regex_patterns:
                    skipped += 1
                    continue

                # Map severity
                raw_severity = rule_dict.get("severity", "WARNING").upper()
                severity = _SEVERITY_MAP.get(raw_severity, FindingSeverity.RESTRICTED)

                # Extract metadata
                metadata = rule_dict.get("metadata", {}) or {}
                cwe = metadata.get("cwe", [])
                if isinstance(cwe, str):
                    cwe = [cwe]
                owasp = metadata.get("owasp", [])
                if isinstance(owasp, str):
                    owasp = [owasp]
                aegis_cap = metadata.get("aegis_capability")

                languages = rule_dict.get("languages", ["generic"])
                if isinstance(languages, str):
                    languages = [languages]

                rules.append(SemgrepRule(
                    id=rule_id,
                    regex_patterns=regex_patterns,
                    message=rule_dict.get("message", ""),
                    severity=severity,
                    languages=languages,
                    cwe=cwe,
                    owasp=owasp,
                    aegis_capability=aegis_cap,
                    source_file=yaml_file.name,
                ))

    if skipped:
        logger.info("Semgrep: skipped %d unsupported rules", skipped)
    if errors:
        logger.info("Semgrep: %d rules had errors", errors)
    logger.info("Semgrep: loaded %d rules from %s", len(rules), rules_dir)

    return rules


def _file_matches_language(file_path: Path, languages: list[str]) -> bool:
    """Check if a file matches the rule's language filter."""
    suffix = file_path.suffix.lower()
    for lang in languages:
        lang_lower = lang.lower()
        if lang_lower in ("generic", "regex", "none"):
            return True
        exts = _LANGUAGE_EXTENSIONS.get(lang_lower, set())
        if suffix in exts:
            return True
    return False


def _parse_aegis_capability(cap_str: str) -> Optional[ScopedCapability]:
    """Parse an aegis_capability string like 'network:connect' into a ScopedCapability."""
    parts = cap_str.split(":", 1)
    if len(parts) != 2:
        return None

    try:
        category = CapabilityCategory(parts[0])
    except ValueError:
        return None

    try:
        action = CapabilityAction(parts[1])
    except ValueError:
        return None

    return ScopedCapability(
        category=category,
        action=action,
        scope=["*"],
        scope_resolved=False,
    )


def evaluate_semgrep_rules(
    file_path: Path,
    relative_name: str,
    content: str,
    language: str,
    rules: list[SemgrepRule],
) -> tuple[list[Finding], list[Finding], list[ScopedCapability]]:
    """Apply Semgrep regex rules line-by-line against file content.

    Returns:
        (prohibited_findings, restricted_findings, capabilities)
    """
    prohibited: list[Finding] = []
    restricted: list[Finding] = []
    capabilities: list[ScopedCapability] = []

    lines = content.splitlines()

    for rule in rules:
        # Check language match
        if not _file_matches_language(file_path, rule.languages):
            continue

        for lineno, line in enumerate(lines, start=1):
            for pattern in rule.regex_patterns:
                if pattern.search(line):
                    # Build CWE/OWASP suffix
                    refs = []
                    if rule.cwe:
                        refs.append(f"CWE: {', '.join(rule.cwe)}")
                    if rule.owasp:
                        refs.append(f"OWASP: {', '.join(rule.owasp)}")
                    ref_str = f" [{'; '.join(refs)}]" if refs else ""

                    # Build suggested fix from message
                    suggested_fix = rule.message if rule.message else None

                    # Parse capability if present
                    cap = None
                    if rule.aegis_capability:
                        cap = _parse_aegis_capability(rule.aegis_capability)
                        if cap:
                            capabilities.append(cap)

                    finding = Finding(
                        file=relative_name,
                        line=lineno,
                        col=0,
                        pattern=f"semgrep:{rule.id}",
                        severity=rule.severity,
                        capability=cap,
                        message=f"{rule.message}{ref_str}",
                        suggested_fix=suggested_fix,
                    )

                    if rule.severity == FindingSeverity.PROHIBITED:
                        prohibited.append(finding)
                    else:
                        restricted.append(finding)

                    # Only match each rule once per line
                    break

    return prohibited, restricted, capabilities


def deduplicate_findings(
    aegis_findings: list[Finding],
    semgrep_findings: list[Finding],
) -> list[Finding]:
    """Deduplicate: if both Aegis and Semgrep flag the same line, prefer Aegis.

    Returns the list of Semgrep findings that should be added
    (i.e., those NOT already covered by an Aegis finding on the same line).
    """
    # Build a set of (file, line) from Aegis findings
    aegis_lines = {(f.file, f.line) for f in aegis_findings}

    unique = []
    for f in semgrep_findings:
        if (f.file, f.line) not in aegis_lines:
            unique.append(f)

    return unique
