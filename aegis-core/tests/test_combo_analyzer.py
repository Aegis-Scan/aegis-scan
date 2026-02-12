"""Tests for the combination risk analyzer."""

import pytest

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    ScopedCapability,
)
from aegis.scanner.combo_analyzer import (
    analyze_combinations,
    get_max_risk_override,
    has_critical_combination,
)


def _cap(category: str, action: str) -> ScopedCapability:
    """Helper to create a capability."""
    return ScopedCapability(
        category=CapabilityCategory(category),
        action=CapabilityAction(action),
        scope=["*"],
        scope_resolved=False,
    )


class TestAnalyzeCombinations:
    """Test trifecta combination risk detection.

    Verifies that input is Set[ScopedCapability] (not a scan result),
    making it reusable at both scan time and proxy time.
    """

    def test_automated_purchasing_trifecta(self):
        caps = {
            _cap("browser", "control"),
            _cap("secret", "access"),
            _cap("network", "connect"),
        }
        risks = analyze_combinations(caps)
        assert any(r.rule_id == "automated-purchasing" for r in risks)
        assert any(r.severity == "critical" for r in risks)

    def test_rce_pipeline(self):
        caps = {
            _cap("fs", "write"),
            _cap("subprocess", "exec"),
            _cap("network", "connect"),
        }
        risks = analyze_combinations(caps)
        assert any(r.rule_id == "rce-pipeline" for r in risks)

    def test_secret_exfiltration(self):
        caps = {
            _cap("secret", "access"),
            _cap("network", "connect"),
        }
        risks = analyze_combinations(caps)
        assert any(r.rule_id == "secret-exfiltration" for r in risks)

    def test_supply_chain_autoload(self):
        caps = {
            _cap("subprocess", "exec"),
        }
        risks = analyze_combinations(caps, has_unrecognized_binary=True)
        assert any(r.rule_id == "supply-chain-autoload" for r in risks)

    def test_supply_chain_no_unrecognized(self):
        """Should NOT trigger without unrecognized binaries."""
        caps = {
            _cap("subprocess", "exec"),
        }
        risks = analyze_combinations(caps, has_unrecognized_binary=False)
        assert not any(r.rule_id == "supply-chain-autoload" for r in risks)

    def test_no_risk_for_safe_caps(self):
        caps = {
            _cap("fs", "read"),
            _cap("env", "read"),
        }
        risks = analyze_combinations(caps)
        assert len(risks) == 0

    def test_set_input_not_tied_to_scan(self):
        """Verify the analyzer accepts Set[ScopedCapability] directly."""
        # This is critical for proxy-time reuse
        cap_set = set()
        cap_set.add(_cap("browser", "control"))
        cap_set.add(_cap("secret", "access"))
        cap_set.add(_cap("network", "connect"))
        risks = analyze_combinations(cap_set)
        assert len(risks) > 0

    def test_list_input_also_works(self):
        """Also accepts list (for convenience)."""
        caps = [
            _cap("browser", "control"),
            _cap("secret", "access"),
            _cap("network", "connect"),
        ]
        risks = analyze_combinations(caps)
        assert len(risks) > 0


class TestRiskOverride:
    """Test risk override calculation."""

    def test_max_override(self):
        caps = {
            _cap("browser", "control"),
            _cap("secret", "access"),
            _cap("network", "connect"),
        }
        risks = analyze_combinations(caps)
        assert get_max_risk_override(risks) == 95

    def test_no_override(self):
        assert get_max_risk_override([]) is None

    def test_has_critical(self):
        caps = {
            _cap("browser", "control"),
            _cap("secret", "access"),
            _cap("network", "connect"),
        }
        risks = analyze_combinations(caps)
        assert has_critical_combination(risks) is True

    def test_no_critical(self):
        caps = {
            _cap("fs", "write"),
            _cap("subprocess", "exec"),
            _cap("network", "connect"),
        }
        risks = analyze_combinations(caps)
        assert has_critical_combination(risks) is False
