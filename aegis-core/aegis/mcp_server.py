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

"""Aegis MCP Server — Model Context Protocol integration.

Exposes Aegis scanning capabilities as MCP tools for use with
Cursor, Claude Desktop, and other MCP-compatible clients.

Tools:
  scan_skill        — Full Aegis scan: capabilities, findings, risk score
  verify_lockfile   — Verify an existing aegis.lock against current code
  list_capabilities — Extract capabilities (lightweight scan)
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from aegis import __version__

logger = logging.getLogger("aegis.mcp")

mcp = FastMCP(
    name="aegis",
    instructions=(
        "Aegis is a behavioral security scanner for AI agent skills. "
        "Use scan_skill to audit a directory for capabilities, risks, and secrets. "
        "Use verify_lockfile to check if code has been tampered with. "
        "Use list_capabilities for a lightweight capability extraction."
    ),
)

_MAX_PATH_LEN = 4096


def _error_response(code: str, message: str, details: dict[str, Any] | None = None) -> str:
    payload: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details:
        payload["error"]["details"] = details
    return json.dumps(payload)


def _validate_directory_input(directory: Any) -> tuple[bool, str]:
    if not isinstance(directory, str):
        return False, _error_response(
            "schema_validation_failed",
            "Field 'directory' must be a string.",
            {"field": "directory", "expected": "string", "received_type": type(directory).__name__},
        )

    if not directory.strip():
        return False, _error_response(
            "schema_validation_failed",
            "Field 'directory' must be a non-empty path string.",
            {"field": "directory", "constraint": "non_empty"},
        )

    if len(directory) > _MAX_PATH_LEN:
        return False, _error_response(
            "schema_validation_failed",
            "Field 'directory' is too long.",
            {"field": "directory", "max_length": _MAX_PATH_LEN},
        )

    if "\x00" in directory:
        return False, _error_response(
            "schema_validation_failed",
            "Field 'directory' contains an invalid null byte.",
            {"field": "directory", "constraint": "no_null_byte"},
        )

    return True, ""


def _run_scan(target_dir: Path) -> dict[str, Any]:
    """Run the Aegis scan pipeline on a directory.

    Returns the full report as a dict.
    """
    from aegis.crypto.hasher import build_merkle_tree, compute_file_hashes
    from aegis.models.capabilities import ScopedCapability
    from aegis.policy.rule_engine import check_path_violations
    from aegis.scanner.ast_parser import parse_file
    from aegis.scanner.binary_detector import (
        classify_binaries,
        get_all_external_binaries,
        has_unrecognized_binaries,
    )
    from aegis.scanner.combo_analyzer import (
        analyze_combinations,
        get_max_risk_override,
    )
    from aegis.scanner.config_analyzer import parse_config_file
    from aegis.scanner.coordinator import (
        discover_files,
        get_config_files,
        get_js_files,
        get_python_files,
        get_shell_files,
    )
    from aegis.scanner.fix_suggestions import populate_fix_suggestions
    from aegis.scanner.js_analyzer import parse_js_file
    from aegis.scanner.remediation_feedback import build_one_pass_feedback
    from aegis.scanner.secret_scanner import scan_python_secrets
    from aegis.scanner.shell_analyzer import parse_shell_file

    target_dir = target_dir.resolve()

    # Discover files
    all_files, manifest_source = discover_files(target_dir)
    python_files = get_python_files(all_files)
    shell_files = get_shell_files(all_files)
    js_files = get_js_files(all_files)
    config_files = get_config_files(all_files)

    # AST analysis (Python)
    all_prohibited = []
    all_restricted = []
    all_capabilities: list[ScopedCapability] = []

    for rel_path in python_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps, _context = parse_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    # Secret detection (Python)
    for rel_path in python_files:
        full_path = target_dir / rel_path
        secret_findings, secret_caps = scan_python_secrets(full_path, str(rel_path))
        all_restricted.extend(secret_findings)
        all_capabilities.extend(secret_caps)

    # Shell analysis
    for rel_path in shell_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps = parse_shell_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    # JS/TS analysis
    for rel_path in js_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps = parse_js_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    # Config analysis
    for rel_path in config_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps = parse_config_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    # Binary detection
    external_binaries = get_all_external_binaries(all_capabilities)
    denied_bins, allowed_bins, unrecognized_bins = classify_binaries(external_binaries)

    # Combination analysis
    has_unrec_bins = has_unrecognized_binaries(external_binaries)
    combination_risks = analyze_combinations(
        set(all_capabilities), has_unrecognized_binary=has_unrec_bins
    )

    # Path violations
    path_violations = check_path_violations(all_capabilities)

    # Fix suggestions
    populate_fix_suggestions(all_prohibited + all_restricted, combination_risks)
    remediation_feedback = build_one_pass_feedback(
        all_prohibited,
        all_restricted,
        combination_risks,
    )

    # Compute static risk score
    score = 0
    from aegis.models.capabilities import CapabilityCategory
    for cap in all_capabilities:
        if cap.category in (CapabilityCategory.SUBPROCESS, CapabilityCategory.BROWSER, CapabilityCategory.SECRET):
            score += 15
        elif cap.category in (CapabilityCategory.NETWORK, CapabilityCategory.FS):
            score += 10
        elif cap.category == CapabilityCategory.SERIAL:
            score += 12
        else:
            score += 5
        if "*" in cap.scope:
            score += 5

    max_override = get_max_risk_override(combination_risks)
    if max_override is not None:
        score = max(score, max_override)
    score += len(path_violations) * 10
    score += len(denied_bins) * 10
    score += len(unrecognized_bins) * 5
    static_risk = min(100, max(0, score))

    # Build capability map
    cap_map: dict[str, dict[str, list[str]]] = {}
    for cap in all_capabilities:
        cat = cap.category.value
        act = cap.action.value
        if cat not in cap_map:
            cap_map[cat] = {}
        if act not in cap_map[cat]:
            cap_map[cat][act] = []
        for s in cap.scope:
            if s not in cap_map[cat][act]:
                cap_map[cat][act].append(s)

    # Hashes
    file_hashes = compute_file_hashes(target_dir, all_files)
    merkle_tree = build_merkle_tree(file_hashes)

    return {
        "aegis_version": __version__,
        "scan_target": str(target_dir),
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "file_count": len(all_files),
        "manifest_source": manifest_source,
        "capabilities": cap_map,
        "external_binaries": external_binaries,
        "prohibited_findings": [f.model_dump() for f in all_prohibited],
        "restricted_findings": [f.model_dump() for f in all_restricted],
        "combination_risks": [r.model_dump() for r in combination_risks],
        "path_violations": path_violations,
        "remediation_feedback": remediation_feedback,
        "risk_score": static_risk,
        "merkle_root": merkle_tree.root,
        "file_types": {
            "python": len(python_files),
            "shell": len(shell_files),
            "js_ts": len(js_files),
            "config": len(config_files),
        },
    }


@mcp.tool()
def scan_skill(directory: str) -> str:
    """Run a full Aegis security scan on a skill directory.

    Analyzes all Python, JavaScript/TypeScript, shell, and config files
    to extract capabilities, detect prohibited patterns, find hardcoded
    secrets, evaluate combination risks, and compute a risk score.

    Args:
        directory: Path to the skill directory to scan.

    Returns:
        JSON report with capabilities, findings, combination risks, and risk score.
    """
    try:
        ok, error_json = _validate_directory_input(directory)
        if not ok:
            return error_json

        target = Path(directory).resolve()
        if not target.exists():
            return _error_response("not_found", "Directory not found.", {"directory": directory})
        if not target.is_dir():
            return _error_response("invalid_target", "Path is not a directory.", {"directory": directory})

        report = _run_scan(target)
        return json.dumps(report, indent=2, default=str)
    except Exception:
        logger.exception("scan_skill failed")
        return _error_response("internal_error", "scan_skill failed unexpectedly.")


@mcp.tool()
def verify_lockfile(directory: str) -> str:
    """Verify an existing aegis.lock against the current code.

    Checks that file hashes in the signed lockfile match the current
    files on disk. Returns pass/fail with details.

    Args:
        directory: Path to the skill directory containing aegis.lock.

    Returns:
        JSON with 'passed' (bool) and 'messages' (list of strings).
    """
    try:
        from aegis.verify.standalone import verify as standalone_verify

        ok, error_json = _validate_directory_input(directory)
        if not ok:
            return error_json

        target = Path(directory).resolve()
        if not target.exists():
            return json.dumps({"passed": False, "messages": ["Directory not found."]})
        if not target.is_dir():
            return json.dumps({"passed": False, "messages": ["Path is not a directory."]})

        passed, messages = standalone_verify(target, None, False)
        if not passed:
            messages = list(messages) + [
                "If this change is unexpected, follow docs/INCIDENT_RESPONSE.md and record it in docs/RISK_REGISTER.md."
            ]
        return json.dumps({"passed": passed, "messages": messages}, indent=2)
    except Exception:
        logger.exception("verify_lockfile failed")
        return json.dumps({"passed": False, "messages": ["verify_lockfile failed unexpectedly."]})


@mcp.tool()
def list_capabilities(directory: str) -> str:
    """Extract capabilities from a skill directory (lightweight scan).

    Runs only the capability extraction phase without risk scoring,
    combination analysis, or hash computation.

    Args:
        directory: Path to the skill directory to analyze.

    Returns:
        JSON with the capability map and file counts.
    """
    try:
        from aegis.models.capabilities import ScopedCapability
        from aegis.scanner.ast_parser import parse_file
        from aegis.scanner.coordinator import (
            discover_files,
            get_config_files,
            get_js_files,
            get_python_files,
            get_shell_files,
        )
        from aegis.scanner.config_analyzer import parse_config_file
        from aegis.scanner.js_analyzer import parse_js_file
        from aegis.scanner.shell_analyzer import parse_shell_file

        ok, error_json = _validate_directory_input(directory)
        if not ok:
            return error_json

        target = Path(directory).resolve()
        if not target.exists():
            return _error_response("not_found", "Directory not found.", {"directory": directory})
        if not target.is_dir():
            return _error_response("invalid_target", "Path is not a directory.", {"directory": directory})

        all_files, manifest_source = discover_files(target)
        python_files = get_python_files(all_files)
        shell_files = get_shell_files(all_files)
        js_files = get_js_files(all_files)
        config_files = get_config_files(all_files)

        all_capabilities: list[ScopedCapability] = []

        for rel_path in python_files:
            _, _, caps, _ = parse_file(target / rel_path, str(rel_path))
            all_capabilities.extend(caps)

        for rel_path in shell_files:
            _, _, caps = parse_shell_file(target / rel_path, str(rel_path))
            all_capabilities.extend(caps)

        for rel_path in js_files:
            _, _, caps = parse_js_file(target / rel_path, str(rel_path))
            all_capabilities.extend(caps)

        for rel_path in config_files:
            _, _, caps = parse_config_file(target / rel_path, str(rel_path))
            all_capabilities.extend(caps)

        # Build capability map
        cap_map: dict[str, dict[str, list[str]]] = {}
        for cap in all_capabilities:
            cat = cap.category.value
            act = cap.action.value
            if cat not in cap_map:
                cap_map[cat] = {}
            if act not in cap_map[cat]:
                cap_map[cat][act] = []
            for s in cap.scope:
                if s not in cap_map[cat][act]:
                    cap_map[cat][act].append(s)

        return json.dumps({
            "directory": str(target),
            "file_count": len(all_files),
            "capabilities": cap_map,
            "file_types": {
                "python": len(python_files),
                "shell": len(shell_files),
                "js_ts": len(js_files),
                "config": len(config_files),
            },
        }, indent=2)
    except Exception:
        logger.exception("list_capabilities failed")
        return _error_response("internal_error", "list_capabilities failed unexpectedly.")


def run_server() -> None:
    """Start the Aegis MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run_server()
