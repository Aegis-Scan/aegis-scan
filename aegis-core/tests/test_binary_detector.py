"""Tests for the binary detector."""

import pytest

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    ScopedCapability,
)
from aegis.scanner.binary_detector import (
    classify_binaries,
    extract_binaries_from_capabilities,
    has_unrecognized_binaries,
)


class TestExtractBinaries:
    """Test binary name extraction from capabilities."""

    def test_extracts_from_subprocess_scope(self):
        caps = [
            ScopedCapability(
                category=CapabilityCategory.SUBPROCESS,
                action=CapabilityAction.EXEC,
                scope=["aws", "s3", "cp"],
                scope_resolved=True,
            ),
        ]
        binaries = extract_binaries_from_capabilities(caps)
        assert "aws" in binaries

    def test_ignores_non_subprocess(self):
        caps = [
            ScopedCapability(
                category=CapabilityCategory.NETWORK,
                action=CapabilityAction.CONNECT,
                scope=["api.example.com"],
                scope_resolved=True,
            ),
        ]
        binaries = extract_binaries_from_capabilities(caps)
        assert len(binaries) == 0

    def test_ignores_wildcard_scope(self):
        caps = [
            ScopedCapability(
                category=CapabilityCategory.SUBPROCESS,
                action=CapabilityAction.EXEC,
                scope=["*"],
                scope_resolved=False,
            ),
        ]
        binaries = extract_binaries_from_capabilities(caps)
        assert len(binaries) == 0

    def test_handles_path_binary(self):
        caps = [
            ScopedCapability(
                category=CapabilityCategory.SUBPROCESS,
                action=CapabilityAction.EXEC,
                scope=["/usr/bin/git"],
                scope_resolved=True,
            ),
        ]
        binaries = extract_binaries_from_capabilities(caps)
        assert "git" in binaries


class TestClassifyBinaries:
    """Test binary classification against deny/allow lists."""

    def test_denied_binary(self):
        denied, allowed, unrec = classify_binaries(["aws", "kubectl"])
        assert "aws" in denied
        assert "kubectl" in denied

    def test_allowed_binary(self):
        denied, allowed, unrec = classify_binaries(["git", "python"])
        assert "git" in allowed
        assert "python" in allowed

    def test_unrecognized_binary(self):
        denied, allowed, unrec = classify_binaries(["my_custom_tool"])
        assert "my_custom_tool" in unrec

    def test_has_unrecognized(self):
        assert has_unrecognized_binaries(["git", "my_custom_tool"]) is True

    def test_no_unrecognized(self):
        assert has_unrecognized_binaries(["git", "python"]) is False
