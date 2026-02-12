"""Tests for the JavaScript/TypeScript analyzer."""

from pathlib import Path

import pytest

from aegis.models.capabilities import CapabilityCategory, CapabilityAction, FindingSeverity
from aegis.scanner.js_analyzer import parse_js_file


class TestProhibitedPatterns:
    """Test prohibited pattern detection in JS/TS."""

    def test_detects_eval(self, tmp_path: Path):
        script = tmp_path / "evil.js"
        script.write_text('const result = eval("1+1");\n')
        prohibited, _, _ = parse_js_file(script, "evil.js")
        assert len(prohibited) >= 1
        assert any("eval" in f.message.lower() for f in prohibited)

    def test_detects_new_function(self, tmp_path: Path):
        script = tmp_path / "evil.js"
        script.write_text('const fn = new Function("return 42");\n')
        prohibited, _, _ = parse_js_file(script, "evil.js")
        assert len(prohibited) >= 1
        assert any("Function" in f.message for f in prohibited)

    def test_detects_vm_run_in_context(self, tmp_path: Path):
        script = tmp_path / "sandbox.js"
        script.write_text('vm.runInNewContext("code", sandbox);\n')
        prohibited, _, _ = parse_js_file(script, "sandbox.js")
        assert len(prohibited) >= 1

    def test_all_prohibited_severity(self, tmp_path: Path):
        script = tmp_path / "evil.js"
        script.write_text('eval("code");\nnew Function("body");\n')
        prohibited, _, _ = parse_js_file(script, "evil.js")
        assert all(f.severity == FindingSeverity.PROHIBITED for f in prohibited)


class TestNetworkPatterns:
    """Test network capability detection."""

    def test_detects_fetch(self, tmp_path: Path):
        script = tmp_path / "api.js"
        script.write_text('const resp = await fetch("https://api.example.com/data");\n')
        _, restricted, caps = parse_js_file(script, "api.js")
        assert any(c.category == CapabilityCategory.NETWORK for c in caps)

    def test_detects_axios(self, tmp_path: Path):
        script = tmp_path / "api.js"
        script.write_text('const resp = await axios.get("https://api.example.com");\n')
        _, restricted, caps = parse_js_file(script, "api.js")
        assert any(c.category == CapabilityCategory.NETWORK for c in caps)

    def test_detects_http_request(self, tmp_path: Path):
        script = tmp_path / "server.js"
        script.write_text('const req = https.request("https://api.example.com");\n')
        _, restricted, caps = parse_js_file(script, "server.js")
        assert any(c.category == CapabilityCategory.NETWORK for c in caps)

    def test_detects_websocket(self, tmp_path: Path):
        script = tmp_path / "ws.js"
        script.write_text('const ws = new WebSocket("wss://example.com");\n')
        _, restricted, caps = parse_js_file(script, "ws.js")
        assert any(c.category == CapabilityCategory.NETWORK for c in caps)

    def test_detects_database_client(self, tmp_path: Path):
        script = tmp_path / "db.js"
        script.write_text('const pg = require("pg");\n')
        _, restricted, caps = parse_js_file(script, "db.js")
        assert any(c.category == CapabilityCategory.NETWORK for c in caps)

    def test_extracts_url_scope(self, tmp_path: Path):
        script = tmp_path / "api.js"
        script.write_text('fetch("https://api.example.com/v1/data");\n')
        _, restricted, caps = parse_js_file(script, "api.js")
        net_caps = [c for c in caps if c.category == CapabilityCategory.NETWORK]
        assert len(net_caps) >= 1
        assert net_caps[0].scope == ["https://api.example.com/v1/data"]
        assert net_caps[0].scope_resolved is True

    def test_detects_mongoose(self, tmp_path: Path):
        script = tmp_path / "db.ts"
        script.write_text('const mongoose = require("mongoose");\n')
        _, _, caps = parse_js_file(script, "db.ts")
        assert any(c.category == CapabilityCategory.NETWORK for c in caps)

    def test_detects_prisma(self, tmp_path: Path):
        script = tmp_path / "db.ts"
        script.write_text('import { PrismaClient } from "@prisma/client";\n')
        _, _, caps = parse_js_file(script, "db.ts")
        assert any(c.category == CapabilityCategory.NETWORK for c in caps)


class TestFilesystemPatterns:
    """Test filesystem capability detection."""

    def test_detects_fs_read(self, tmp_path: Path):
        script = tmp_path / "reader.js"
        script.write_text('const data = fs.readFileSync("config.json");\n')
        _, _, caps = parse_js_file(script, "reader.js")
        fs_caps = [c for c in caps if c.category == CapabilityCategory.FS]
        assert any(c.action == CapabilityAction.READ for c in fs_caps)

    def test_detects_fs_write(self, tmp_path: Path):
        script = tmp_path / "writer.js"
        script.write_text('fs.writeFileSync("output.txt", data);\n')
        _, _, caps = parse_js_file(script, "writer.js")
        fs_caps = [c for c in caps if c.category == CapabilityCategory.FS]
        assert any(c.action == CapabilityAction.WRITE for c in fs_caps)

    def test_detects_fs_delete(self, tmp_path: Path):
        script = tmp_path / "cleaner.js"
        script.write_text('fs.unlinkSync("temp.txt");\n')
        _, _, caps = parse_js_file(script, "cleaner.js")
        fs_caps = [c for c in caps if c.category == CapabilityCategory.FS]
        assert any(c.action == CapabilityAction.DELETE for c in fs_caps)

    def test_detects_fs_promises(self, tmp_path: Path):
        script = tmp_path / "async.js"
        script.write_text('import fs from "fs/promises";\n')
        _, _, caps = parse_js_file(script, "async.js")
        assert any(c.category == CapabilityCategory.FS for c in caps)


class TestSubprocessPatterns:
    """Test subprocess detection."""

    def test_detects_child_process_exec(self, tmp_path: Path):
        script = tmp_path / "runner.js"
        script.write_text('const { exec } = require("child_process");\nexec("ls");\n')
        _, _, caps = parse_js_file(script, "runner.js")
        assert any(c.category == CapabilityCategory.SUBPROCESS for c in caps)

    def test_detects_spawn(self, tmp_path: Path):
        script = tmp_path / "runner.js"
        script.write_text('child_process.spawn("node", ["script.js"]);\n')
        _, _, caps = parse_js_file(script, "runner.js")
        assert any(c.category == CapabilityCategory.SUBPROCESS for c in caps)

    def test_detects_shelljs(self, tmp_path: Path):
        script = tmp_path / "shell.js"
        script.write_text('const shell = require("shelljs");\n')
        _, _, caps = parse_js_file(script, "shell.js")
        assert any(c.category == CapabilityCategory.SUBPROCESS for c in caps)


class TestBrowserPatterns:
    """Test browser automation detection."""

    def test_detects_puppeteer(self, tmp_path: Path):
        script = tmp_path / "scraper.js"
        script.write_text('const puppeteer = require("puppeteer");\n')
        _, _, caps = parse_js_file(script, "scraper.js")
        assert any(c.category == CapabilityCategory.BROWSER for c in caps)

    def test_detects_playwright(self, tmp_path: Path):
        script = tmp_path / "e2e.ts"
        script.write_text('import { chromium } from "playwright";\n')
        _, _, caps = parse_js_file(script, "e2e.ts")
        assert any(c.category == CapabilityCategory.BROWSER for c in caps)

    def test_detects_jsdom(self, tmp_path: Path):
        script = tmp_path / "dom.js"
        script.write_text('const jsdom = require("jsdom");\n')
        _, _, caps = parse_js_file(script, "dom.js")
        assert any(c.category == CapabilityCategory.BROWSER for c in caps)


class TestSecretPatterns:
    """Test secret/env access detection."""

    def test_detects_process_env(self, tmp_path: Path):
        script = tmp_path / "config.js"
        script.write_text('const key = process.env.API_KEY;\n')
        _, _, caps = parse_js_file(script, "config.js")
        assert any(c.category == CapabilityCategory.SECRET for c in caps)

    def test_detects_dotenv(self, tmp_path: Path):
        script = tmp_path / "env.js"
        script.write_text('require("dotenv").config();\n')
        _, _, caps = parse_js_file(script, "env.js")
        assert any(c.category == CapabilityCategory.SECRET for c in caps)

    def test_detects_aws_sdk(self, tmp_path: Path):
        script = tmp_path / "aws.js"
        script.write_text('const AWS = require("aws-sdk");\n')
        _, _, caps = parse_js_file(script, "aws.js")
        assert any(c.category == CapabilityCategory.SECRET for c in caps)


class TestCryptoPatterns:
    """Test crypto capability detection."""

    def test_detects_crypto_hash(self, tmp_path: Path):
        script = tmp_path / "hash.js"
        script.write_text('const hash = crypto.createHash("sha256");\n')
        _, _, caps = parse_js_file(script, "hash.js")
        assert any(c.category == CapabilityCategory.CRYPTO for c in caps)

    def test_detects_bcrypt(self, tmp_path: Path):
        script = tmp_path / "auth.js"
        script.write_text('const bcrypt = require("bcrypt");\n')
        _, _, caps = parse_js_file(script, "auth.js")
        assert any(c.category == CapabilityCategory.CRYPTO for c in caps)

    def test_detects_jsonwebtoken(self, tmp_path: Path):
        script = tmp_path / "jwt.js"
        script.write_text('const jwt = require("jsonwebtoken");\n')
        _, _, caps = parse_js_file(script, "jwt.js")
        crypto_caps = [c for c in caps if c.category == CapabilityCategory.CRYPTO]
        assert any(c.action == CapabilityAction.SIGN for c in crypto_caps)


class TestHardcodedSecrets:
    """Test hardcoded secret detection in JS/TS."""

    def test_detects_password_const(self, tmp_path: Path):
        script = tmp_path / "creds.js"
        script.write_text('const password = "hunter2rocks";\n')
        _, restricted, _ = parse_js_file(script, "creds.js")
        assert any("hardcoded_secret" in f.pattern for f in restricted)

    def test_detects_api_key_let(self, tmp_path: Path):
        script = tmp_path / "config.ts"
        script.write_text('let apiKey = "sk_live_abc123def456ghi789jkl";\n')
        _, restricted, _ = parse_js_file(script, "config.ts")
        assert any("hardcoded" in f.pattern for f in restricted)

    def test_detects_aws_key_in_string(self, tmp_path: Path):
        script = tmp_path / "aws.js"
        script.write_text('const id = "AKIAIOSFODNN7EXAMPLE";\n')
        _, restricted, _ = parse_js_file(script, "aws.js")
        assert any("AWS" in f.message for f in restricted)

    def test_detects_connection_string(self, tmp_path: Path):
        script = tmp_path / "db.js"
        script.write_text(
            'const url = "postgres://admin:s3cur3p@ss@db.example.com/mydb";\n'
        )
        _, restricted, _ = parse_js_file(script, "db.js")
        assert any("connection_string" in f.pattern for f in restricted)

    def test_ignores_placeholder(self, tmp_path: Path):
        script = tmp_path / "placeholder.js"
        script.write_text('const password = "changeme";\n')
        _, restricted, _ = parse_js_file(script, "placeholder.js")
        assert not any("hardcoded_secret" in f.pattern for f in restricted)


class TestCommentHandling:
    """Test that comments are properly handled."""

    def test_single_line_comment_ignored(self, tmp_path: Path):
        script = tmp_path / "commented.js"
        script.write_text('// eval("dangerous");\nconst x = 1;\n')
        prohibited, _, _ = parse_js_file(script, "commented.js")
        assert len(prohibited) == 0

    def test_block_comment_ignored(self, tmp_path: Path):
        script = tmp_path / "commented.js"
        script.write_text('/* eval("dangerous"); */\nconst x = 1;\n')
        prohibited, _, _ = parse_js_file(script, "commented.js")
        assert len(prohibited) == 0

    def test_multiline_block_comment(self, tmp_path: Path):
        script = tmp_path / "commented.js"
        script.write_text('/*\neval("dangerous");\n*/\nconst x = 1;\n')
        prohibited, _, _ = parse_js_file(script, "commented.js")
        assert len(prohibited) == 0


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_file(self, tmp_path: Path):
        script = tmp_path / "empty.js"
        script.write_text("")
        prohibited, restricted, caps = parse_js_file(script, "empty.js")
        assert len(prohibited) == 0
        assert len(restricted) == 0
        assert len(caps) == 0

    def test_nonexistent_file(self, tmp_path: Path):
        prohibited, restricted, caps = parse_js_file(
            tmp_path / "missing.js", "missing.js"
        )
        assert len(prohibited) == 0
        assert len(restricted) == 0

    def test_typescript_file(self, tmp_path: Path):
        script = tmp_path / "app.tsx"
        script.write_text(
            'import axios from "axios";\n'
            'const data = await axios.get("https://api.example.com");\n'
        )
        _, _, caps = parse_js_file(script, "app.tsx")
        assert any(c.category == CapabilityCategory.NETWORK for c in caps)

    def test_combined_capabilities(self, tmp_path: Path):
        """A file with multiple capability types."""
        script = tmp_path / "complex.js"
        script.write_text(
            'const fs = require("fs");\n'
            'const { exec } = require("child_process");\n'
            'fetch("https://api.example.com");\n'
            'const key = process.env.SECRET_KEY;\n'
        )
        _, restricted, caps = parse_js_file(script, "complex.js")
        categories = {c.category for c in caps}
        assert CapabilityCategory.FS in categories
        assert CapabilityCategory.SUBPROCESS in categories
        assert CapabilityCategory.NETWORK in categories
        assert CapabilityCategory.SECRET in categories
