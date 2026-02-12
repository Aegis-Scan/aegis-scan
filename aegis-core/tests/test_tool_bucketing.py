# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# Licensed under the AGPL-3.0. See LICENSE for details.

"""Tests for tool bucketing taxonomy."""

import pytest

from aegis.scanner.tool_bucketing import (
    TOOL_BUCKET_TAXONOMY,
    DEFAULT_TOOL_PROFILE,
    compute_tool_overreach,
    get_tool_profile,
)


class TestToolBucketTaxonomy:
    def test_all_skill_types_have_profiles(self):
        expected_keys = {
            "data-science", "browser-automation", "api-integration",
            "devtools", "document-processing", "system-ops", "communication",
            "crypto-web3", "security", "finance", "database",
            "ai-agents", "research", "infrastructure",
        }
        assert set(TOOL_BUCKET_TAXONOMY.keys()) == expected_keys

    def test_data_science_core_tools(self):
        profile = TOOL_BUCKET_TAXONOMY["data-science"]
        assert "read" in profile.core_tools
        assert "web_fetch" in profile.core_tools
        assert "sessions_spawn" not in profile.core_tools

    def test_data_science_high_risk_tools(self):
        profile = TOOL_BUCKET_TAXONOMY["data-science"]
        assert "sessions_send" in profile.high_risk_tools
        assert "gateway" in profile.high_risk_tools

    def test_ai_agents_core_tools(self):
        profile = TOOL_BUCKET_TAXONOMY["ai-agents"]
        assert "sessions_spawn" in profile.core_tools
        assert "agents_list" in profile.core_tools


class TestComputeToolOverreach:
    def test_empty_tools_no_overreach(self):
        msgs = compute_tool_overreach(
            declared_tools=[],
            skill_category="data-science",
        )
        assert msgs == []

    def test_core_tools_no_overreach(self):
        msgs = compute_tool_overreach(
            declared_tools=["read", "write", "web_fetch"],
            skill_category="data-science",
        )
        assert msgs == []

    def test_high_risk_tool_triggers_overreach(self):
        msgs = compute_tool_overreach(
            declared_tools=["read", "sessions_send", "web_fetch"],
            skill_category="data-science",
        )
        assert len(msgs) == 1
        assert "sessions_send" in msgs[0]
        assert "worth double-checking" in msgs[0]

    def test_contextual_tools_no_overreach(self):
        msgs = compute_tool_overreach(
            declared_tools=["memory_search", "memory_get"],
            skill_category="data-science",
        )
        assert msgs == []

    def test_general_profile_flags_high_risk(self):
        msgs = compute_tool_overreach(
            declared_tools=["browser", "sessions_spawn"],
            skill_category="general",
        )
        assert len(msgs) >= 1

    def test_browser_automation_exec_is_high_risk(self):
        msgs = compute_tool_overreach(
            declared_tools=["browser", "exec", "web_fetch"],
            skill_category="browser-automation",
        )
        assert len(msgs) == 1
        assert "exec" in msgs[0]


class TestGetToolProfile:
    def test_returns_profile_for_known_category(self):
        profile = get_tool_profile("data-science")
        assert profile.name == "Data Science / ML"

    def test_returns_default_for_unknown(self):
        profile = get_tool_profile("unknown-category")
        assert profile is DEFAULT_TOOL_PROFILE
