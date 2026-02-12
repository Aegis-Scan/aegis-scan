# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# Licensed under the AGPL-3.0. See LICENSE for details.

"""Tests for extract_declared_tools from skill config and SKILL.md."""

import json
import pytest
from pathlib import Path

from aegis.scanner.skill_meta_analyzer import extract_declared_tools


def test_extract_from_skill_json_tools(tmp_path: Path) -> None:
    """Extract tools from skill.json tools array."""
    (tmp_path / "skill.json").write_text(
        json.dumps({"name": "test-skill", "tools": ["web_fetch", "read", "sessions_spawn"]}),
        encoding="utf-8",
    )
    tools = extract_declared_tools(tmp_path, None)
    assert set(tools) == {"read", "sessions_spawn", "web_fetch"}


def test_extract_from_skill_json_requires_tools(tmp_path: Path) -> None:
    """Extract tools from skill.json requires.tools."""
    (tmp_path / "skill.json").write_text(
        json.dumps({"requires": {"tools": ["browser", "web_fetch"]}}),
        encoding="utf-8",
    )
    tools = extract_declared_tools(tmp_path, None)
    assert set(tools) == {"browser", "web_fetch"}


def test_extract_from_skill_md_backticks(tmp_path: Path) -> None:
    """Extract backticked tool names from SKILL.md."""
    md = """
    This skill uses `web_fetch` and `sessions_spawn` to do things.
    Also mentions `read` and `write`.
    """
    tools = extract_declared_tools(tmp_path, md)
    assert "web_fetch" in tools
    assert "sessions_spawn" in tools
    assert "read" in tools
    assert "write" in tools


def test_extract_empty_when_no_config_or_md(tmp_path: Path) -> None:
    """Returns empty list when no config and no SKILL.md."""
    tools = extract_declared_tools(tmp_path, None)
    assert tools == []
