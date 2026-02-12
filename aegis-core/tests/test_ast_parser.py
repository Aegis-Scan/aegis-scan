"""Tests for the AST parser — prohibited/restricted detection + pessimistic scope."""

from pathlib import Path

import pytest

from aegis.scanner.ast_parser import (
    AegisASTVisitor,
    parse_file,
    try_extract_literal,
)
from aegis.models.capabilities import FindingSeverity

FIXTURES = Path(__file__).parent / "fixtures"


class TestTryExtractLiteral:
    """Test pessimistic scope extraction (Directive 3)."""

    def test_string_literal(self):
        import ast
        node = ast.Constant(value="hello.txt")
        val, resolved = try_extract_literal(node)
        assert val == "hello.txt"
        assert resolved is True

    def test_string_concatenation(self):
        import ast
        node = ast.BinOp(
            left=ast.Constant(value="/data/"),
            op=ast.Add(),
            right=ast.Constant(value="output.txt"),
        )
        val, resolved = try_extract_literal(node)
        assert val == "/data/output.txt"
        assert resolved is True

    def test_variable_returns_wildcard(self):
        import ast
        node = ast.Name(id="some_var")
        val, resolved = try_extract_literal(node)
        assert val == "*"
        assert resolved is False

    def test_fstring_returns_wildcard(self):
        import ast
        node = ast.JoinedStr(values=[
            ast.Constant(value="prefix_"),
            ast.FormattedValue(value=ast.Name(id="x"), conversion=-1),
        ])
        val, resolved = try_extract_literal(node)
        assert val == "*"
        assert resolved is False

    def test_function_call_returns_wildcard(self):
        import ast
        node = ast.Call(func=ast.Name(id="get_path"), args=[], keywords=[])
        val, resolved = try_extract_literal(node)
        assert val == "*"
        assert resolved is False

    def test_attribute_access_returns_wildcard(self):
        import ast
        node = ast.Attribute(value=ast.Name(id="config"), attr="path")
        val, resolved = try_extract_literal(node)
        assert val == "*"
        assert resolved is False

    def test_subscript_returns_wildcard(self):
        import ast
        node = ast.Subscript(
            value=ast.Name(id="config"),
            slice=ast.Constant(value="key"),
        )
        val, resolved = try_extract_literal(node)
        assert val == "*"
        assert resolved is False

    def test_ternary_returns_wildcard(self):
        import ast
        node = ast.IfExp(
            test=ast.Constant(value=True),
            body=ast.Constant(value="a"),
            orelse=ast.Constant(value="b"),
        )
        val, resolved = try_extract_literal(node)
        assert val == "*"
        assert resolved is False

    def test_numeric_constant_returns_wildcard(self):
        import ast
        node = ast.Constant(value=42)
        val, resolved = try_extract_literal(node)
        assert val == "*"
        assert resolved is False


class TestSafeSkill:
    """Test scanning a safe weather skill."""

    def test_no_prohibited_findings(self):
        prohibited, _, _, _ = parse_file(
            FIXTURES / "safe_skill" / "weather.py", "weather.py"
        )
        assert len(prohibited) == 0

    def test_detects_network_capability(self):
        _, restricted, caps, _ = parse_file(
            FIXTURES / "safe_skill" / "weather.py", "weather.py"
        )
        cap_keys = {c.capability_key for c in caps}
        assert "network:connect" in cap_keys

    def test_literal_url_resolved(self):
        _, restricted, caps, _ = parse_file(
            FIXTURES / "safe_skill" / "weather.py", "weather.py"
        )
        network_caps = [c for c in caps if c.capability_key == "network:connect"]
        assert any(
            "https://api.weather.com/v1/current" in c.scope and c.scope_resolved
            for c in network_caps
        )


class TestDangerousSkill:
    """Test scanning a dangerous skill with prohibited patterns."""

    def test_detects_eval(self):
        prohibited, _, _, _ = parse_file(
            FIXTURES / "dangerous_skill" / "malicious.py", "malicious.py"
        )
        patterns = {f.pattern for f in prohibited}
        assert "eval" in patterns

    def test_detects_exec(self):
        prohibited, _, _, _ = parse_file(
            FIXTURES / "dangerous_skill" / "malicious.py", "malicious.py"
        )
        patterns = {f.pattern for f in prohibited}
        assert "exec" in patterns

    def test_detects_importlib(self):
        prohibited, _, _, _ = parse_file(
            FIXTURES / "dangerous_skill" / "malicious.py", "malicious.py"
        )
        patterns = {f.pattern for f in prohibited}
        assert "importlib.import_module" in patterns

    def test_all_prohibited_severity(self):
        prohibited, _, _, _ = parse_file(
            FIXTURES / "dangerous_skill" / "malicious.py", "malicious.py"
        )
        assert all(f.severity == FindingSeverity.PROHIBITED for f in prohibited)


class TestDeadlyTrifecta:
    """Test scanning a skill with browser + secrets + network."""

    def test_detects_browser_control(self):
        _, _, caps, _ = parse_file(
            FIXTURES / "deadly_trifecta" / "trifecta.py", "trifecta.py"
        )
        cap_keys = {c.capability_key for c in caps}
        assert "browser:control" in cap_keys

    def test_detects_secret_access(self):
        _, _, caps, _ = parse_file(
            FIXTURES / "deadly_trifecta" / "trifecta.py", "trifecta.py"
        )
        cap_keys = {c.capability_key for c in caps}
        assert "secret:access" in cap_keys

    def test_detects_network_connect(self):
        _, _, caps, _ = parse_file(
            FIXTURES / "deadly_trifecta" / "trifecta.py", "trifecta.py"
        )
        cap_keys = {c.capability_key for c in caps}
        assert "network:connect" in cap_keys


class TestBinarySpawn:
    """Test scanning a skill that invokes cloud CLIs."""

    def test_detects_subprocess_exec(self):
        _, _, caps, _ = parse_file(
            FIXTURES / "binary_spawn" / "spawner.py", "spawner.py"
        )
        cap_keys = {c.capability_key for c in caps}
        assert "subprocess:exec" in cap_keys

    def test_extracts_aws_binary(self):
        _, _, caps, _ = parse_file(
            FIXTURES / "binary_spawn" / "spawner.py", "spawner.py"
        )
        subprocess_caps = [c for c in caps if c.capability_key == "subprocess:exec"]
        all_scopes = []
        for c in subprocess_caps:
            all_scopes.extend(c.scope)
        assert "aws" in all_scopes

    def test_extracts_git_binary(self):
        _, _, caps, _ = parse_file(
            FIXTURES / "binary_spawn" / "spawner.py", "spawner.py"
        )
        subprocess_caps = [c for c in caps if c.capability_key == "subprocess:exec"]
        all_scopes = []
        for c in subprocess_caps:
            all_scopes.extend(c.scope)
        assert "git" in all_scopes


class TestUnresolvedScope:
    """Test that variable paths produce wildcard scopes."""

    def test_variable_path_unresolved(self):
        _, restricted, caps, _ = parse_file(
            FIXTURES / "unresolved_scope" / "dynamic.py", "dynamic.py"
        )
        # At least one capability should have unresolved scope
        unresolved = [c for c in caps if not c.scope_resolved]
        assert len(unresolved) > 0

    def test_wildcard_in_scope(self):
        _, _, caps, _ = parse_file(
            FIXTURES / "unresolved_scope" / "dynamic.py", "dynamic.py"
        )
        wildcard_caps = [c for c in caps if "*" in c.scope]
        assert len(wildcard_caps) > 0
