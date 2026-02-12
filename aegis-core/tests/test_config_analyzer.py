"""Tests for the config file analyzer."""

from pathlib import Path

import pytest

from aegis.models.capabilities import CapabilityCategory, FindingSeverity
from aegis.scanner.config_analyzer import parse_config_file

FIXTURES = Path(__file__).parent / "fixtures"


class TestJsonConfig:
    """Test capability extraction from JSON config files."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.prohibited, self.restricted, self.caps = parse_config_file(
            FIXTURES / "config_skill" / "settings.json", "settings.json"
        )

    def test_no_prohibited(self):
        """Config files should not produce prohibited findings."""
        assert len(self.prohibited) == 0

    def test_detects_secret_keys(self):
        """Should detect api_key and db_password as secret:access."""
        secret_caps = [c for c in self.caps if c.category == CapabilityCategory.SECRET]
        assert len(secret_caps) >= 1

    def test_detects_network_endpoints(self):
        """Should detect URLs as network:connect."""
        net_caps = [c for c in self.caps if c.category == CapabilityCategory.NETWORK]
        assert len(net_caps) >= 1
        # Should resolve the actual URL
        all_scopes = []
        for c in net_caps:
            all_scopes.extend(c.scope)
        assert any("weather.com" in s for s in all_scopes)

    def test_detects_sensitive_path(self):
        """Should detect ~/.ssh/ path as fs:read."""
        fs_caps = [c for c in self.caps if c.category == CapabilityCategory.FS]
        assert len(fs_caps) >= 1

    def test_detects_command_reference(self):
        """Should detect docker command reference as subprocess:exec."""
        sub_caps = [c for c in self.caps if c.category == CapabilityCategory.SUBPROCESS]
        assert len(sub_caps) >= 1


class TestYamlConfig:
    """Test capability extraction from YAML config files."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.prohibited, self.restricted, self.caps = parse_config_file(
            FIXTURES / "config_skill" / "config.yaml", "config.yaml"
        )

    def test_detects_secret_keys(self):
        """Should detect api_key as secret:access."""
        secret_caps = [c for c in self.caps if c.category == CapabilityCategory.SECRET]
        assert len(secret_caps) >= 1

    def test_detects_endpoints(self):
        """Should detect endpoint URLs as network:connect."""
        net_caps = [c for c in self.caps if c.category == CapabilityCategory.NETWORK]
        assert len(net_caps) >= 1

    def test_detects_kubectl_command(self):
        """Should detect kubectl in deploy command."""
        sub_caps = [c for c in self.caps if c.category == CapabilityCategory.SUBPROCESS]
        assert len(sub_caps) >= 1


class TestEdgeCases:
    """Test edge cases in config analysis."""

    def test_empty_json(self, tmp_path: Path):
        """Empty JSON produces no findings."""
        config = tmp_path / "empty.json"
        config.write_text("{}")
        prohibited, restricted, caps = parse_config_file(config, "empty.json")
        assert len(prohibited) == 0
        assert len(restricted) == 0
        assert len(caps) == 0

    def test_invalid_json(self, tmp_path: Path):
        """Invalid JSON is gracefully handled."""
        config = tmp_path / "broken.json"
        config.write_text("{ not valid json }")
        prohibited, restricted, caps = parse_config_file(config, "broken.json")
        assert len(prohibited) == 0
        assert len(restricted) == 0
        assert len(caps) == 0

    def test_placeholder_values_ignored(self, tmp_path: Path):
        """Keys with placeholder values should not be flagged."""
        config = tmp_path / "placeholder.json"
        config.write_text('{"api_key": "TODO", "secret": "CHANGEME"}')
        prohibited, restricted, caps = parse_config_file(config, "placeholder.json")
        secret_caps = [c for c in caps if c.category == CapabilityCategory.SECRET]
        assert len(secret_caps) == 0

    def test_safe_config(self, tmp_path: Path):
        """Config with no sensitive data produces no findings."""
        config = tmp_path / "safe.json"
        config.write_text('{"name": "my-app", "version": "1.0.0", "debug": true}')
        prohibited, restricted, caps = parse_config_file(config, "safe.json")
        assert len(caps) == 0
