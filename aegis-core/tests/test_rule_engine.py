"""Tests for the unified rule evaluation engine."""

import pytest

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    ScopedCapability,
)
from aegis.models.rules import Policy, PolicyDefaults, PolicyRule, RuleAction
from aegis.policy.rule_engine import (
    RuleMatch,
    check_path_violations,
    evaluate_rule,
)


@pytest.fixture
def sample_policy() -> Policy:
    """Create a sample policy for testing."""
    return Policy(
        rules=[
            PolicyRule(
                id="allow-tmp-writes",
                capability="fs:write",
                scope=["/tmp/*", "./workspace/*"],
                action=RuleAction.ALLOW,
            ),
            PolicyRule(
                id="deny-sensitive-paths",
                capability="fs:write",
                scope=["~/.ssh/*", "~/.aws/*", "~/.bashrc"],
                action=RuleAction.DENY,
                priority=100,
            ),
            PolicyRule(
                id="allow-weather-api",
                capability="network:connect",
                scope=["api.weather.com", "*.openweathermap.org"],
                action=RuleAction.ALLOW,
            ),
            PolicyRule(
                id="deny-internal",
                capability="network:connect",
                scope=["10.*", "192.168.*"],
                action=RuleAction.DENY,
                priority=100,
            ),
            PolicyRule(
                id="allow-git",
                capability="subprocess:exec",
                scope=["git", "python3"],
                action=RuleAction.ALLOW,
            ),
            PolicyRule(
                id="deny-cloud-clis",
                capability="subprocess:exec",
                scope=["aws", "gcloud", "kubectl"],
                action=RuleAction.DENY,
                priority=90,
            ),
        ],
        defaults=PolicyDefaults(unmatched_action=RuleAction.FLAG),
    )


class TestEvaluateRule:
    """Test priority-ordered rule evaluation."""

    def test_allow_tmp_write(self, sample_policy: Policy):
        result = evaluate_rule("fs:write", "/tmp/output.txt", sample_policy)
        assert result.action == RuleAction.ALLOW
        assert result.rule_id == "allow-tmp-writes"

    def test_deny_ssh_path(self, sample_policy: Policy):
        result = evaluate_rule("fs:write", "~/.ssh/authorized_keys", sample_policy)
        assert result.action == RuleAction.DENY
        assert result.rule_id == "deny-sensitive-paths"

    def test_deny_overrides_allow_by_priority(self, sample_policy: Policy):
        """Deny rules with higher priority should override allow rules."""
        result = evaluate_rule("network:connect", "10.0.0.1", sample_policy)
        assert result.action == RuleAction.DENY

    def test_allow_weather_api(self, sample_policy: Policy):
        result = evaluate_rule("network:connect", "api.weather.com", sample_policy)
        assert result.action == RuleAction.ALLOW

    def test_deny_cloud_cli(self, sample_policy: Policy):
        result = evaluate_rule("subprocess:exec", "aws", sample_policy)
        assert result.action == RuleAction.DENY

    def test_allow_git(self, sample_policy: Policy):
        result = evaluate_rule("subprocess:exec", "git", sample_policy)
        assert result.action == RuleAction.ALLOW

    def test_default_action_for_unmatched(self, sample_policy: Policy):
        result = evaluate_rule("fs:write", "/some/random/path.txt", sample_policy)
        assert result.action == RuleAction.FLAG
        assert result.is_default is True


class TestPathViolations:
    """Test default deny path checking at scan time."""

    def test_ssh_path_violation(self):
        caps = [
            ScopedCapability(
                category=CapabilityCategory.FS,
                action=CapabilityAction.WRITE,
                scope=["~/.ssh/authorized_keys"],
                scope_resolved=True,
            ),
        ]
        violations = check_path_violations(caps)
        assert len(violations) > 0
        assert any("~/.ssh" in v["deny_pattern"] for v in violations)

    def test_bashrc_violation(self):
        caps = [
            ScopedCapability(
                category=CapabilityCategory.FS,
                action=CapabilityAction.WRITE,
                scope=["~/.bashrc"],
                scope_resolved=True,
            ),
        ]
        violations = check_path_violations(caps)
        assert len(violations) > 0

    def test_safe_path_no_violation(self):
        caps = [
            ScopedCapability(
                category=CapabilityCategory.FS,
                action=CapabilityAction.WRITE,
                scope=["/tmp/output.txt"],
                scope_resolved=True,
            ),
        ]
        violations = check_path_violations(caps)
        assert len(violations) == 0

    def test_read_not_checked(self):
        """Read capabilities should not trigger path violations."""
        caps = [
            ScopedCapability(
                category=CapabilityCategory.FS,
                action=CapabilityAction.READ,
                scope=["~/.ssh/known_hosts"],
                scope_resolved=True,
            ),
        ]
        violations = check_path_violations(caps)
        assert len(violations) == 0
