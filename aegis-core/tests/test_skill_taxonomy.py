# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# Licensed under the AGPL-3.0. See LICENSE for details.

"""Tests for skill taxonomy and permission overreach."""

import pytest

from aegis.scanner.skill_taxonomy import (
    SKILL_TAXONOMY,
    DEFAULT_PROFILE,
    classify_skill_type,
    compute_permission_overreach,
    compute_documentation_integrity,
)


class TestClassifySkillType:
    def test_returns_three_values(self):
        key, profile, confidence = classify_skill_type("")
        assert key == "general"
        assert profile is DEFAULT_PROFILE
        assert confidence == "none"

    def test_data_science_classification(self):
        md = """
        This skill does machine learning and data science.
        Uses pandas, scikit-learn, and pytorch for model training.
        Supports regression and classification.
        """
        key, profile, confidence = classify_skill_type(md)
        assert key == "data-science"
        assert profile.name == "Data Science / ML"
        assert confidence in ("high", "low")

    def test_general_for_weak_signal(self):
        md = "A skill that does stuff."
        key, _, confidence = classify_skill_type(md)
        assert key == "general"
        assert confidence == "none"

    def test_browser_automation(self):
        md = "Web scraping with Selenium and Playwright. Headless browser automation."
        key, profile, _ = classify_skill_type(md)
        assert key == "browser-automation"
        assert "browser" in profile.expected_capabilities

    def test_new_categories_exist(self):
        assert "database" in SKILL_TAXONOMY
        assert "ai-agents" in SKILL_TAXONOMY
        assert "research" in SKILL_TAXONOMY
        assert "infrastructure" in SKILL_TAXONOMY


class TestComputePermissionOverreach:
    def test_empty_caps_no_overreach(self):
        msgs = compute_permission_overreach(
            skill_category="data-science",
            skill_profile=SKILL_TAXONOMY["data-science"],
            code_capabilities={},
        )
        assert msgs == []

    def test_expected_caps_no_overreach(self):
        msgs = compute_permission_overreach(
            skill_category="data-science",
            skill_profile=SKILL_TAXONOMY["data-science"],
            code_capabilities={"fs": {"read": ["/tmp"]}, "subprocess": {"exec": ["python"]}},
        )
        assert msgs == []

    def test_unusual_cap_triggers_overreach(self):
        msgs = compute_permission_overreach(
            skill_category="data-science",
            skill_profile=SKILL_TAXONOMY["data-science"],
            code_capabilities={"browser": {"control": ["*"]}},
        )
        assert len(msgs) == 1
        assert "browser" in msgs[0]
        assert "worth double-checking" in msgs[0]

    def test_network_not_unusual_for_data_science(self):
        # Network moved to sometimes_expected (Hugging Face, datasets) — no overreach
        msgs = compute_permission_overreach(
            skill_category="data-science",
            skill_profile=SKILL_TAXONOMY["data-science"],
            code_capabilities={"network": {"connect": ["https://api.example.com"]}},
        )
        assert len(msgs) == 0

    def test_general_profile_flags_all_high_risk(self):
        msgs = compute_permission_overreach(
            skill_category="general",
            skill_profile=DEFAULT_PROFILE,
            code_capabilities={"network": {"connect": []}, "secret": {"access": []}},
        )
        assert len(msgs) == 2
        assert all("worth double-checking" in m for m in msgs)


class TestDefaultProfile:
    def test_general_has_conservative_unusual_set(self):
        assert len(DEFAULT_PROFILE.expected_capabilities) == 0
        assert len(DEFAULT_PROFILE.suspicious_capabilities) > 0
        assert "network" in DEFAULT_PROFILE.suspicious_capabilities
        assert "secret" in DEFAULT_PROFILE.suspicious_capabilities
        assert "browser" in DEFAULT_PROFILE.suspicious_capabilities


class TestIntegrityReport:
    def test_compute_documentation_integrity_populates_overreach(self):
        md = """
        Machine learning skill using pandas and scikit-learn.
        Trains regression models and runs inference.
        """
        # browser is unusual for data-science; network is sometimes_expected (no overreach)
        report = compute_documentation_integrity(
            skill_md=md,
            code_capabilities={"browser": {"control": []}},
            meta_insights=[],
            restricted_finding_count=2,
            python_file_count=1,
            total_file_count=1,
        )
        assert report.skill_category == "data-science"
        assert len(report.permission_overreach) >= 1
        assert report.classification_confidence in ("high", "low", "none")

    def test_compute_documentation_integrity_tool_overreach(self):
        md = """
        Machine learning skill using pandas and scikit-learn.
        """
        report = compute_documentation_integrity(
            skill_md=md,
            code_capabilities={"fs": {"read": ["/tmp"]}},
            meta_insights=[],
            restricted_finding_count=0,
            python_file_count=1,
            total_file_count=1,
            declared_tools=["read", "sessions_send"],
        )
        assert report.skill_category == "data-science"
        assert len(report.tool_overreach) >= 1
        assert any("sessions_send" in m for m in report.tool_overreach)
