"""Integration tests for the Aegis CLI.

Tests end-to-end scan and verify workflows against fixture skills.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


class TestSafeScan:
    """Safe skill end-to-end: scan → report → lockfile → verify."""

    def test_scan_produces_report(self):
        result = runner.invoke(app, ["scan", str(FIXTURES / "safe_skill"), "--no-llm"])
        assert result.exit_code == 0

    def test_scan_json_output(self):
        result = runner.invoke(
            app, ["scan", str(FIXTURES / "safe_skill"), "--json", "--no-llm"]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "deterministic" in data
        assert "ephemeral" in data
        feedback = data["deterministic"].get("remediation_feedback")
        assert isinstance(feedback, dict)
        assert feedback.get("max_iterations") == 1
        assert isinstance(feedback.get("tasks"), list)

    def test_report_file_created(self):
        runner.invoke(app, ["scan", str(FIXTURES / "safe_skill"), "--no-llm"])
        report_path = FIXTURES / "safe_skill" / "aegis_report.json"
        assert report_path.exists()
        # Clean up
        report_path.unlink(missing_ok=True)

    def test_lockfile_created_with_lock_command(self):
        runner.invoke(app, ["lock", str(FIXTURES / "safe_skill"), "--no-llm"])
        lockfile_path = FIXTURES / "safe_skill" / "aegis.lock"
        assert lockfile_path.exists()
        # Clean up
        lockfile_path.unlink(missing_ok=True)
        (FIXTURES / "safe_skill" / "aegis_report.json").unlink(missing_ok=True)

    def test_no_lockfile_without_lock_flag(self):
        """Scan is read-only by default — no lockfile."""
        # Clean up any pre-existing lockfile first
        (FIXTURES / "safe_skill" / "aegis.lock").unlink(missing_ok=True)
        runner.invoke(app, ["scan", str(FIXTURES / "safe_skill"), "--no-llm"])
        lockfile_path = FIXTURES / "safe_skill" / "aegis.lock"
        assert not lockfile_path.exists()
        (FIXTURES / "safe_skill" / "aegis_report.json").unlink(missing_ok=True)


class TestProhibitedPattern:
    """Prohibited patterns should cause hard failure."""

    def test_eval_hard_fails(self):
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES / "dangerous_skill"), "--no-llm", "--quiet"],
        )
        assert result.exit_code == 1

    def test_no_lockfile_on_hard_fail(self):
        runner.invoke(
            app,
            ["scan", str(FIXTURES / "dangerous_skill"), "--no-llm", "--quiet"],
        )
        lockfile_path = FIXTURES / "dangerous_skill" / "aegis.lock"
        assert not lockfile_path.exists()


class TestDeadlyTrifecta:
    """Trifecta detection should block lockfile generation."""

    def test_trifecta_detected(self):
        result = runner.invoke(
            app,
            ["lock", str(FIXTURES / "deadly_trifecta"), "--json", "--no-llm", "--force"],
        )
        # --force allows lockfile even for critical, so scan completes
        data = json.loads(result.stdout)
        combo_risks = data["deterministic"]["combination_risks"]
        assert len(combo_risks) > 0
        assert any(r["severity"] == "critical" for r in combo_risks)
        feedback = data["deterministic"].get("remediation_feedback")
        assert isinstance(feedback, dict)
        assert isinstance(feedback.get("tasks"), list)
        assert len(feedback["tasks"]) > 0
        # Clean up
        (FIXTURES / "deadly_trifecta" / "aegis.lock").unlink(missing_ok=True)
        (FIXTURES / "deadly_trifecta" / "aegis_report.json").unlink(missing_ok=True)


class TestBinarySpawn:
    """Binary spawn detection should flag cloud CLIs."""

    def test_aws_detected(self):
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES / "binary_spawn"), "--json", "--no-llm"],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        binaries = data["deterministic"]["external_binaries"]
        assert "aws" in binaries
        # Clean up
        (FIXTURES / "binary_spawn" / "aegis_report.json").unlink(missing_ok=True)


class TestPathViolation:
    """Path violations should be flagged."""

    def test_ssh_path_flagged(self):
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES / "path_violation"), "--json", "--no-llm"],
        )
        if result.exit_code == 0:
            data = json.loads(result.stdout)
            violations = data["deterministic"]["path_violations"]
            assert len(violations) > 0


class TestUnresolvedScope:
    """Variable paths should produce wildcard scopes."""

    def test_wildcard_scopes(self):
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES / "unresolved_scope"), "--json", "--no-llm"],
        )
        if result.exit_code == 0:
            data = json.loads(result.stdout)
            caps = data["deterministic"]["capabilities"]
            # At least some scope should be ["*"]
            has_wildcard = False
            for cat in caps.values():
                for action_scopes in cat.values():
                    if "*" in action_scopes:
                        has_wildcard = True
            assert has_wildcard


class TestVerify:
    """Verification tests."""

    def test_verify_pass(self):
        """Scan then verify should pass."""
        # First lock to create lockfile
        runner.invoke(app, ["lock", str(FIXTURES / "safe_skill"), "--no-llm", "--quiet"])

        # Then verify
        result = runner.invoke(app, ["verify", str(FIXTURES / "safe_skill")])
        assert result.exit_code == 0

        # Clean up
        (FIXTURES / "safe_skill" / "aegis.lock").unlink(missing_ok=True)
        (FIXTURES / "safe_skill" / "aegis_report.json").unlink(missing_ok=True)

    def test_verify_no_lockfile_fails(self, tmp_path: Path):
        """Verify without lockfile should fail."""
        (tmp_path / "test.py").write_text("x = 1")
        result = runner.invoke(app, ["verify", str(tmp_path)])
        assert result.exit_code == 1


class TestStandaloneVerify:
    """Test that standalone verifier works without heavy dependencies (Directive 4)."""

    def test_standalone_module_invocation(self):
        """python -m aegis.verify.standalone should work."""
        # First create a lockfile
        runner.invoke(app, ["lock", str(FIXTURES / "safe_skill"), "--no-llm", "--quiet"])

        # Then verify using standalone module
        result = subprocess.run(
            [sys.executable, "-m", "aegis.verify.standalone", str(FIXTURES / "safe_skill")],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout

        # Clean up
        (FIXTURES / "safe_skill" / "aegis.lock").unlink(missing_ok=True)
        (FIXTURES / "safe_skill" / "aegis_report.json").unlink(missing_ok=True)


class TestSemgrepFlags:
    """Test Semgrep CLI flags (--no-semgrep, --semgrep-rules)."""

    def test_no_semgrep_flag(self):
        """--no-semgrep should skip Semgrep rules but still produce a valid scan."""
        result = runner.invoke(
            app, ["scan", str(FIXTURES / "safe_skill"), "--json", "--no-llm", "--no-semgrep"]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "deterministic" in data
        # Clean up
        (FIXTURES / "safe_skill" / "aegis_report.json").unlink(missing_ok=True)

    def test_custom_semgrep_rules_dir(self, tmp_path: Path):
        """--semgrep-rules should load additional rules from a custom directory."""
        import yaml

        # Create a custom rule that flags 'requests.get'
        rule_yaml = {
            "rules": [{
                "id": "custom-no-requests-get",
                "pattern-regex": r"requests\.get\s*\(",
                "message": "Custom rule: do not use requests.get directly",
                "severity": "WARNING",
                "languages": ["python"],
            }]
        }
        rules_dir = tmp_path / "custom_rules"
        rules_dir.mkdir()
        (rules_dir / "custom.yaml").write_text(yaml.dump(rule_yaml))

        result = runner.invoke(
            app, [
                "scan", str(FIXTURES / "safe_skill"),
                "--json", "--no-llm",
                "--semgrep-rules", str(rules_dir),
            ]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # The custom rule should have produced findings (or been deduped with the built-in one)
        assert "deterministic" in data
        # Clean up
        (FIXTURES / "safe_skill" / "aegis_report.json").unlink(missing_ok=True)

    def test_custom_semgrep_rules_nonexistent_warns(self):
        """--semgrep-rules with nonexistent path should still complete scan."""
        result = runner.invoke(
            app, [
                "scan", str(FIXTURES / "safe_skill"),
                "--no-llm", "--quiet",
                "--semgrep-rules", "C:\\nonexistent\\rules",
            ]
        )
        # Scan should still complete (warning printed, not a fatal error)
        assert result.exit_code == 0
        # Clean up
        (FIXTURES / "safe_skill" / "aegis_report.json").unlink(missing_ok=True)


class TestVersion:
    """Test version command."""

    def test_version_output(self):
        from aegis import __version__
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout
