# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# Licensed under the AGPL-3.0. See LICENSE for details.

"""Tests for the SKILL.md / manifest meta-analyzer."""

from pathlib import Path

import pytest

from aegis.models.capabilities import MetaInsightCategory, MetaInsightSeverity
from aegis.scanner.skill_meta_analyzer import (
    _extract_claimed_technologies,
    _extract_declared_binaries,
    _extract_referenced_binaries,
    _extract_referenced_files,
    _extract_declared_env_vars,
    analyze_install_mechanism,
    analyze_instruction_scope,
    analyze_purpose_and_capability,
    analyze_credentials,
    analyze_persistence_and_privilege,
    analyze_skill_meta,
    analyze_tool_declarations,
)


FIXTURES = Path(__file__).parent / "fixtures"


# ── Extraction helpers ──


class TestExtractClaimedTechnologies:
    def test_detects_cloud_providers(self):
        text = "Deploy to AWS and Google Cloud with Kubernetes"
        result = _extract_claimed_technologies(text)
        assert "cloud_providers" in result
        assert "aws" in result["cloud_providers"]

    def test_detects_databases(self):
        text = "Connects to PostgreSQL and Redis for caching"
        result = _extract_claimed_technologies(text)
        assert "databases" in result
        assert "postgresql" in result["databases"]
        assert "redis" in result["databases"]

    def test_detects_containers(self):
        text = "Builds and pushes Docker images to Kubernetes clusters"
        result = _extract_claimed_technologies(text)
        assert "containers" in result
        assert "docker" in result["containers"]
        assert "kubernetes" in result["containers"]

    def test_empty_text_returns_empty(self):
        result = _extract_claimed_technologies("")
        assert result == {}


class TestExtractReferencedFiles:
    def test_finds_python_files(self):
        text = "Run `scripts/train.py` and `scripts/evaluate.py`"
        result = _extract_referenced_files(text)
        assert "scripts/train.py" in result
        assert "scripts/evaluate.py" in result

    def test_finds_config_files(self):
        text = "Edit config.yaml to set your options"
        result = _extract_referenced_files(text)
        assert "config.yaml" in result


class TestExtractReferencedBinaries:
    def test_finds_binaries(self):
        text = "Run kubectl apply and helm install"
        result = _extract_referenced_binaries(text)
        assert "kubectl" in result
        assert "helm" in result

    def test_finds_python_and_pip(self):
        text = "Install with pip install and run python main.py"
        result = _extract_referenced_binaries(text)
        assert "pip" in result
        assert "python" in result


class TestExtractDeclaredEnvVars:
    def test_finds_declared_vars(self):
        text = "Set your `AWS_ACCESS_KEY` and `DATABASE_URL` environment variables"
        result = _extract_declared_env_vars(text)
        assert "AWS_ACCESS_KEY" in result
        assert "DATABASE_URL" in result

    def test_no_vars_returns_empty(self):
        result = _extract_declared_env_vars("No special config needed")
        assert result == []


class TestExtractDeclaredBinaries:
    def test_extracts_from_skill_config_openclaw_bins(self, tmp_path):
        config = {"openclaw": {"requires": {"bins": ["curl", "jq"]}}}
        bins, has_decl = _extract_declared_binaries(tmp_path, None, config)
        assert set(b.lower() for b in bins) == {"curl", "jq"}
        assert has_decl is True

    def test_extracts_from_skill_md_frontmatter_metadata(self, tmp_path):
        skill_md = """---
metadata: { "openclaw": { "requires": { "bins": ["ffmpeg"] } } }
---
# Skill
"""
        skill_md_file = tmp_path / "SKILL.md"
        skill_md_file.write_text(skill_md)
        md_content = skill_md_file.read_text()
        bins, has_decl = _extract_declared_binaries(tmp_path, md_content, None)
        assert "ffmpeg" in [b.lower() for b in bins]
        assert has_decl is True

    def test_no_declaration_returns_empty(self, tmp_path):
        bins, has_decl = _extract_declared_binaries(tmp_path, None, None)
        assert bins == []
        assert has_decl is False


class TestAnalyzeToolDeclarations:
    def test_undeclared_use_returns_warning(self, tmp_path):
        """Detect wget, declare curl -> WARNING (undeclared use)."""
        config = {"openclaw": {"requires": {"bins": ["curl"]}}}
        insight = analyze_tool_declarations(
            target_dir=tmp_path,
            skill_md=None,
            skill_config=config,
            external_binaries=["wget"],
        )
        assert insight.category == MetaInsightCategory.TOOLS
        assert insight.severity == MetaInsightSeverity.WARNING
        assert "wget" in insight.summary or "double-checking" in insight.summary.lower()

    def test_over_declared_returns_info(self, tmp_path):
        """Declare curl, no detection -> INFO (over-declaration)."""
        config = {"openclaw": {"requires": {"bins": ["curl"]}}}
        insight = analyze_tool_declarations(
            target_dir=tmp_path,
            skill_md=None,
            skill_config=config,
            external_binaries=[],
        )
        assert insight.category == MetaInsightCategory.TOOLS
        assert insight.severity == MetaInsightSeverity.INFO
        assert "curl" in insight.summary or "declares" in insight.summary.lower()

    def test_match_returns_pass(self, tmp_path):
        """Declare curl+jq, detect curl+jq -> PASS."""
        config = {"openclaw": {"requires": {"bins": ["curl", "jq"]}}}
        insight = analyze_tool_declarations(
            target_dir=tmp_path,
            skill_md=None,
            skill_config=config,
            external_binaries=["curl", "jq"],
        )
        assert insight.category == MetaInsightCategory.TOOLS
        assert insight.severity == MetaInsightSeverity.PASS
        assert "match" in insight.summary.lower()


# ── Individual analyzers ──


class TestAnalyzePurposeAndCapability:
    def test_flags_cloud_claims_without_code(self):
        skill_md = "Deploy to AWS and Kubernetes with monitoring via Prometheus"
        insight = analyze_purpose_and_capability(
            skill_md=skill_md,
            manifest_files=[Path("main.py")],
            code_capabilities={"fs": {"read": ["/tmp"]}},
            external_binaries=[],
        )
        assert insight.severity in (MetaInsightSeverity.WARNING, MetaInsightSeverity.DANGER)
        assert "mismatch" in insight.summary.lower() or "don't match" in insight.summary.lower()

    def test_passes_when_claims_match_code(self):
        skill_md = "Makes HTTP requests to fetch data"
        insight = analyze_purpose_and_capability(
            skill_md=skill_md,
            manifest_files=[Path("main.py")],
            code_capabilities={"network": {"connect": ["https://api.example.com"]}},
            external_binaries=[],
        )
        # No cloud/container claims to mismatch — should not flag
        assert insight.severity in (MetaInsightSeverity.PASS, MetaInsightSeverity.INFO)


class TestAnalyzeInstructionScope:
    def test_flags_ghost_files(self):
        skill_md = "Run scripts/train.py and scripts/evaluate.py"
        manifest = [Path("main.py"), Path("README.md")]
        insight = analyze_instruction_scope(skill_md, manifest)
        assert insight.severity in (MetaInsightSeverity.WARNING, MetaInsightSeverity.DANGER)
        assert "don't exist" in insight.summary.lower() or "not present" in insight.detail.lower()

    def test_passes_when_files_exist(self):
        skill_md = "Run main.py"
        manifest = [Path("main.py"), Path("README.md")]
        insight = analyze_instruction_scope(skill_md, manifest)
        assert insight.severity in (MetaInsightSeverity.PASS, MetaInsightSeverity.INFO)


class TestAnalyzeInstallMechanism:
    def test_flags_setup_py(self):
        manifest = [Path("setup.py"), Path("main.py")]
        insight = analyze_install_mechanism(manifest)
        assert insight.severity == MetaInsightSeverity.WARNING
        assert "install" in insight.summary.lower()

    def test_passes_with_no_install_files(self):
        manifest = [Path("main.py")]
        insight = analyze_install_mechanism(manifest)
        assert insight.severity in (MetaInsightSeverity.PASS, MetaInsightSeverity.INFO)


class TestAnalyzeCredentials:
    def test_flags_undeclared_credential_access(self):
        skill_md = "Connects to AWS and PostgreSQL"
        code_caps = {"secret": {"access": ["*"]}, "network": {"connect": ["*"]}}
        claimed_tech = _extract_claimed_technologies(skill_md)
        insight = analyze_credentials(skill_md, code_caps, claimed_tech)
        assert insight.severity in (MetaInsightSeverity.WARNING, MetaInsightSeverity.DANGER)

    def test_passes_when_no_creds_needed(self):
        skill_md = "A simple text processing tool"
        code_caps = {"fs": {"read": ["/tmp"]}}
        claimed_tech = _extract_claimed_technologies(skill_md)
        insight = analyze_credentials(skill_md, code_caps, claimed_tech)
        assert insight.severity == MetaInsightSeverity.PASS


class TestAnalyzePersistenceAndPrivilege:
    def test_flags_always_on_with_subprocess(self):
        skill_md = "Runs continuously"
        config = {"always": True, "model_invocable": True}
        code_caps = {"subprocess": {"exec": ["*"]}}
        insight = analyze_persistence_and_privilege(skill_md, config, code_caps)
        assert insight.severity == MetaInsightSeverity.DANGER

    def test_passes_with_default_config(self):
        skill_md = "A normal skill"
        config = {"always": False, "model_invocable": True}
        code_caps = {"fs": {"read": ["/tmp"]}}
        insight = analyze_persistence_and_privilege(skill_md, config, code_caps)
        assert insight.severity == MetaInsightSeverity.PASS

    def test_handles_no_config(self):
        skill_md = "A skill with no config"
        insight = analyze_persistence_and_privilege(skill_md, None, {})
        assert insight.severity == MetaInsightSeverity.PASS


# ── Integration test with fixture ──


class TestAnalyzeSkillMeta:
    def test_meta_skill_fixture(self):
        """The meta_skill fixture claims Docker/K8s/databases but only has a
        simple script — should flag multiple mismatches."""
        target = FIXTURES / "meta_skill"
        manifest = [Path("SKILL.md"), Path("main.py")]

        # Simulate what Aegis code analysis would find
        code_caps = {
            "env": {"read": ["*"]},
            "network": {"connect": ["https://api.example.com"]},
            "fs": {"write": ["/tmp/output.txt"]},
        }

        insights = analyze_skill_meta(
            target_dir=target,
            manifest_files=manifest,
            code_capabilities=code_caps,
            external_binaries=[],
        )

        # Should have insights for all categories
        categories = {i.category for i in insights}
        assert MetaInsightCategory.PURPOSE in categories
        assert MetaInsightCategory.INSTRUCTION_SCOPE in categories
        assert MetaInsightCategory.INSTALL_MECHANISM in categories
        assert MetaInsightCategory.CREDENTIALS in categories
        assert MetaInsightCategory.PERSISTENCE in categories
        assert MetaInsightCategory.TOOLS in categories

        # Purpose should flag mismatches (claims Docker/K8s/databases)
        purpose = next(i for i in insights if i.category == MetaInsightCategory.PURPOSE)
        assert purpose.severity in (MetaInsightSeverity.WARNING, MetaInsightSeverity.DANGER)

        # Instruction scope should flag ghost files (scripts/train.py doesn't exist)
        scope = next(i for i in insights if i.category == MetaInsightCategory.INSTRUCTION_SCOPE)
        assert scope.severity in (MetaInsightSeverity.WARNING, MetaInsightSeverity.DANGER)

    def test_no_skill_md(self):
        """A directory with no SKILL.md should still return insights."""
        target = FIXTURES / "safe_skill"  # has no SKILL.md
        manifest = [Path("weather.py"), Path("config.yaml")]

        insights = analyze_skill_meta(
            target_dir=target,
            manifest_files=manifest,
            code_capabilities={},
            external_binaries=[],
        )

        # Should have at least a warning about missing SKILL.md
        purpose = next(i for i in insights if i.category == MetaInsightCategory.PURPOSE)
        assert purpose.severity == MetaInsightSeverity.WARNING
        assert "no SKILL.md" in purpose.summary.lower() or "doesn't describe" in purpose.summary.lower()

        # TOOLS analysis runs even without SKILL.md (skill_config may have requires.bins)
        assert MetaInsightCategory.TOOLS in {i.category for i in insights}
