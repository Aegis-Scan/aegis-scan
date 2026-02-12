"""Tests for the Aegis MCP server tool handlers."""

import json
from pathlib import Path

import pytest

from aegis.mcp_server import (
    list_capabilities,
    scan_skill,
    verify_lockfile,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestScanSkill:
    """Test the scan_skill MCP tool."""

    def test_scan_safe_skill(self):
        result = scan_skill(str(FIXTURES / "safe_skill"))
        data = json.loads(result)
        assert "error" not in data
        assert "capabilities" in data
        assert "risk_score" in data
        assert "file_count" in data
        assert "remediation_feedback" in data
        assert data["remediation_feedback"]["max_iterations"] == 1
        assert data["file_count"] > 0

    def test_scan_returns_capabilities(self):
        result = scan_skill(str(FIXTURES / "safe_skill"))
        data = json.loads(result)
        caps = data["capabilities"]
        assert "network" in caps
        assert "connect" in caps["network"]

    def test_scan_returns_risk_score(self):
        result = scan_skill(str(FIXTURES / "safe_skill"))
        data = json.loads(result)
        assert isinstance(data["risk_score"], int)
        assert 0 <= data["risk_score"] <= 100

    def test_scan_returns_file_types(self):
        result = scan_skill(str(FIXTURES / "safe_skill"))
        data = json.loads(result)
        assert "file_types" in data
        assert "python" in data["file_types"]

    def test_scan_nonexistent_directory(self):
        result = scan_skill("/nonexistent/path/xyz")
        data = json.loads(result)
        assert "error" in data

    def test_scan_schema_invalid_directory_type(self):
        result = scan_skill(123)  # type: ignore[arg-type]
        data = json.loads(result)
        assert "error" in data
        assert data["error"]["code"] == "schema_validation_failed"

    def test_scan_dangerous_skill_has_prohibited(self):
        result = scan_skill(str(FIXTURES / "dangerous_skill"))
        data = json.loads(result)
        assert len(data.get("prohibited_findings", [])) > 0

    def test_scan_detects_combination_risks(self):
        result = scan_skill(str(FIXTURES / "deadly_trifecta"))
        data = json.loads(result)
        assert len(data.get("combination_risks", [])) > 0

    def test_scan_returns_fix_suggestions(self):
        result = scan_skill(str(FIXTURES / "dangerous_skill"))
        data = json.loads(result)
        # At least some findings should have fix suggestions
        findings = data.get("prohibited_findings", []) + data.get("restricted_findings", [])
        fixes = [f for f in findings if f.get("suggested_fix")]
        assert len(fixes) > 0

    def test_scan_returns_merkle_root(self):
        result = scan_skill(str(FIXTURES / "safe_skill"))
        data = json.loads(result)
        assert "merkle_root" in data
        assert data["merkle_root"].startswith("sha256:")


class TestVerifyLockfile:
    """Test the verify_lockfile MCP tool."""

    def test_verify_no_lockfile(self, tmp_path: Path):
        (tmp_path / "test.py").write_text("x = 1\n")
        result = verify_lockfile(str(tmp_path))
        data = json.loads(result)
        assert data["passed"] is False
        assert len(data["messages"]) > 0

    def test_verify_nonexistent_dir(self):
        result = verify_lockfile("/nonexistent/path/xyz")
        data = json.loads(result)
        assert data["passed"] is False

    def test_verify_schema_invalid_directory_type(self):
        result = verify_lockfile(None)  # type: ignore[arg-type]
        data = json.loads(result)
        assert "error" in data
        assert data["error"]["code"] == "schema_validation_failed"

    def test_verify_returns_structure(self, tmp_path: Path):
        (tmp_path / "test.py").write_text("x = 1\n")
        result = verify_lockfile(str(tmp_path))
        data = json.loads(result)
        assert "passed" in data
        assert "messages" in data
        assert isinstance(data["passed"], bool)
        assert isinstance(data["messages"], list)


class TestListCapabilities:
    """Test the list_capabilities MCP tool."""

    def test_list_safe_skill(self):
        result = list_capabilities(str(FIXTURES / "safe_skill"))
        data = json.loads(result)
        assert "error" not in data
        assert "capabilities" in data
        assert "file_count" in data

    def test_list_returns_file_types(self):
        result = list_capabilities(str(FIXTURES / "safe_skill"))
        data = json.loads(result)
        assert "file_types" in data
        assert data["file_types"]["python"] > 0

    def test_list_nonexistent_directory(self):
        result = list_capabilities("/nonexistent/path/xyz")
        data = json.loads(result)
        assert "error" in data

    def test_list_schema_invalid_directory_type(self):
        result = list_capabilities({})  # type: ignore[arg-type]
        data = json.loads(result)
        assert "error" in data
        assert data["error"]["code"] == "schema_validation_failed"

    def test_list_detects_network(self):
        result = list_capabilities(str(FIXTURES / "safe_skill"))
        data = json.loads(result)
        caps = data["capabilities"]
        assert "network" in caps

    def test_list_empty_dir(self, tmp_path: Path):
        result = list_capabilities(str(tmp_path))
        data = json.loads(result)
        assert data["file_count"] == 0
        assert data["capabilities"] == {}


class TestMCPToolSignatures:
    """Test that MCP tools have proper return types (always JSON strings)."""

    def test_scan_returns_string(self):
        result = scan_skill(str(FIXTURES / "safe_skill"))
        assert isinstance(result, str)
        json.loads(result)  # Should be valid JSON

    def test_verify_returns_string(self, tmp_path: Path):
        (tmp_path / "x.py").write_text("x = 1\n")
        result = verify_lockfile(str(tmp_path))
        assert isinstance(result, str)
        json.loads(result)

    def test_list_returns_string(self):
        result = list_capabilities(str(FIXTURES / "safe_skill"))
        assert isinstance(result, str)
        json.loads(result)
