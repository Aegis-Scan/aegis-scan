"""Tests for the auto-fix suggestions module."""

import pytest

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    CombinationRisk,
    Finding,
    FindingSeverity,
    ScopedCapability,
)
from aegis.scanner.fix_suggestions import (
    get_fix_for_combination,
    get_fix_for_finding,
    populate_fix_suggestions,
)


def _make_finding(
    pattern: str,
    message: str = "",
    category: CapabilityCategory | None = None,
    action: CapabilityAction | None = None,
) -> Finding:
    """Helper to create a Finding for testing."""
    cap = None
    if category and action:
        cap = ScopedCapability(category=category, action=action)
    return Finding(
        file="test.py",
        line=1,
        pattern=pattern,
        severity=FindingSeverity.RESTRICTED,
        capability=cap,
        message=message,
    )


class TestGetFixForFinding:
    """Test fix suggestion lookup for findings."""

    def test_eval_fix(self):
        f = _make_finding("eval", "Dynamic code execution via eval()")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "literal_eval" in fix or "Remove" in fix

    def test_exec_fix(self):
        f = _make_finding("exec", "Dynamic code execution via exec()")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "Remove" in fix or "exec" in fix

    def test_subprocess_run_fix(self):
        f = _make_finding("subprocess.run", "Subprocess execution")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "shell=False" in fix or "list" in fix

    def test_pickle_fix(self):
        f = _make_finding("pickle.load", "Pickle deserialization")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "json" in fix.lower() or "safe" in fix.lower()

    def test_yaml_load_fix(self):
        f = _make_finding("yaml.load", "Unsafe YAML loading")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "safe_load" in fix

    def test_verify_false_fix(self):
        f = _make_finding("verify=False", "SSL verification disabled")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "verify" in fix.lower()

    def test_hardcoded_secret_fix(self):
        f = _make_finding("hardcoded_secret:password", "Hardcoded secret")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "environment" in fix.lower() or "secrets manager" in fix.lower()

    def test_hardcoded_key_fix(self):
        f = _make_finding("hardcoded_key:AWS", "AWS key detected")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "environment" in fix.lower() or "rotate" in fix.lower()

    def test_connection_string_fix(self):
        f = _make_finding("connection_string:postgres", "Connection string")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "environment" in fix.lower()

    def test_child_process_fix(self):
        f = _make_finding("child_process.exec", "Subprocess execution")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "execFile" in fix or "spawn" in fix

    def test_process_env_fix(self):
        f = _make_finding("process.env", "Env access")
        fix = get_fix_for_finding(f)
        assert fix is not None

    def test_puppeteer_fix(self):
        f = _make_finding("puppeteer", "Browser automation")
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "headless" in fix.lower() or "url" in fix.lower()

    def test_fs_write_fallback(self):
        """Capability-based fallback for patterns with no specific match."""
        f = _make_finding(
            "custom_fs_write",
            "Custom write",
            category=CapabilityCategory.FS,
            action=CapabilityAction.WRITE,
        )
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "temp" in fix.lower() or "project" in fix.lower()

    def test_network_fallback(self):
        f = _make_finding(
            "custom_network",
            "Custom network",
            category=CapabilityCategory.NETWORK,
            action=CapabilityAction.CONNECT,
        )
        fix = get_fix_for_finding(f)
        assert fix is not None
        assert "endpoint" in fix.lower() or "SSL" in fix

    def test_no_match_returns_none(self):
        f = _make_finding("totally_unknown_pattern_xyz", "Unknown")
        fix = get_fix_for_finding(f)
        # No specific match and no capability fallback
        assert fix is None


class TestGetFixForCombination:
    """Test fix suggestion lookup for combination risks."""

    def test_automated_purchasing(self):
        risk = CombinationRisk(
            rule_id="automated-purchasing",
            severity="critical",
            matched_capabilities=["browser:control", "secret:access", "network:connect"],
            risk_override=95,
            message="Test",
        )
        fix = get_fix_for_combination(risk)
        assert fix is not None
        assert "browser" in fix.lower() or "credential" in fix.lower()

    def test_rce_pipeline(self):
        risk = CombinationRisk(
            rule_id="rce-pipeline",
            severity="high",
            matched_capabilities=["fs:write", "subprocess:exec", "network:connect"],
            risk_override=85,
            message="Test",
        )
        fix = get_fix_for_combination(risk)
        assert fix is not None
        assert "download" in fix.lower() or "execute" in fix.lower()

    def test_secret_exfiltration(self):
        risk = CombinationRisk(
            rule_id="secret-exfiltration",
            severity="high",
            matched_capabilities=["secret:access", "network:connect"],
            risk_override=80,
            message="Test",
        )
        fix = get_fix_for_combination(risk)
        assert fix is not None

    def test_supply_chain(self):
        risk = CombinationRisk(
            rule_id="supply-chain-autoload",
            severity="high",
            matched_capabilities=["subprocess:exec"],
            risk_override=75,
            message="Test",
        )
        fix = get_fix_for_combination(risk)
        assert fix is not None
        assert "version" in fix.lower() or "checksum" in fix.lower()

    def test_crypto_ransomware(self):
        fix = get_fix_for_combination(
            CombinationRisk(
                rule_id="crypto-ransomware",
                severity="critical",
                matched_capabilities=["fs:write", "fs:read", "crypto:encrypt"],
                risk_override=90,
                message="Test",
            )
        )
        assert fix is not None
        assert "encrypt" in fix.lower()

    def test_unknown_rule_returns_none(self):
        risk = CombinationRisk(
            rule_id="unknown-rule-xyz",
            severity="high",
            matched_capabilities=["fs:read"],
            risk_override=50,
            message="Test",
        )
        fix = get_fix_for_combination(risk)
        assert fix is None


class TestPopulateFixSuggestions:
    """Test the bulk population function."""

    def test_populates_findings(self):
        findings = [
            _make_finding("eval", "eval usage"),
            _make_finding("pickle.load", "pickle deserialization"),
        ]
        populate_fix_suggestions(findings, [])
        assert findings[0].suggested_fix is not None
        assert findings[1].suggested_fix is not None

    def test_populates_combination_risks(self):
        risks = [
            CombinationRisk(
                rule_id="rce-pipeline",
                severity="high",
                matched_capabilities=["fs:write", "subprocess:exec", "network:connect"],
                risk_override=85,
                message="Test",
            ),
        ]
        populate_fix_suggestions([], risks)
        assert risks[0].suggested_fix is not None

    def test_does_not_overwrite_existing(self):
        findings = [
            Finding(
                file="test.py",
                line=1,
                pattern="eval",
                severity=FindingSeverity.RESTRICTED,
                message="eval",
                suggested_fix="Custom fix",
            ),
        ]
        populate_fix_suggestions(findings, [])
        assert findings[0].suggested_fix == "Custom fix"

    def test_handles_empty_inputs(self):
        # Should not raise
        populate_fix_suggestions([], [])

    def test_all_combination_rules_covered(self):
        """Every known trifecta rule should have a fix suggestion."""
        known_rules = [
            "automated-purchasing", "rce-pipeline", "data-exfiltration",
            "secret-exfiltration", "credential-harvesting", "crypto-ransomware",
            "persistence-mechanism", "browser-credential-theft",
            "deserialization-rce", "supply-chain-autoload", "network-listen-exec",
        ]
        for rule_id in known_rules:
            risk = CombinationRisk(
                rule_id=rule_id,
                severity="high",
                matched_capabilities=["test:test"],
                risk_override=75,
                message="Test",
            )
            fix = get_fix_for_combination(risk)
            assert fix is not None, f"No fix for rule: {rule_id}"
