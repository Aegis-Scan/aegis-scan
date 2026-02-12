"""Tests for enhancements derived from PDF research:

"Deep Static Analysis of Python Standard Library Vulnerabilities:
 An AST-Centric Taxonomy for Legacy Monolith Audits"

Covers:
- shell=True detection (prohibited when dynamic, restricted when static)
- Legacy execution sinks (platform.popen, pty, posix, commands)
- Metaprogramming / introspection (runpy, code/codeop, sys._getframe, etc.)
- sqlite3.enable_load_extension(True)
- Weak randomness in security contexts
- tempfile.mktemp TOCTOU
- Archive bomb detection (zipfile, tarfile, shutil.unpack_archive)
- SSRF detection (non-literal URLs)
- Module shadowing detection
- Cyclomatic complexity detection
"""

import tempfile
from pathlib import Path

import pytest

from aegis.models.capabilities import FindingSeverity
from aegis.scanner.ast_parser import parse_file
from aegis.scanner.shadow_detector import detect_shadow_modules
from aegis.scanner.complexity_analyzer import analyze_complexity


def _parse_code(code: str, filename: str = "test.py"):
    """Helper: write code to a temp file and parse it.

    Returns (prohibited, restricted, caps, context) — 4-tuple.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        f.flush()
        return parse_file(Path(f.name), filename)


# ════════════════════════════════════════════════════════════════════
# 1. shell=True Detection
# ════════════════════════════════════════════════════════════════════


class TestShellTrueDetection:
    """Section 2.2.1 — shell=True anti-pattern."""

    def test_dynamic_command_shell_true_prohibited(self):
        """shell=True with variable command → PROHIBITED."""
        code = """\
import subprocess
cmd = input("enter command: ")
subprocess.run(cmd, shell=True)
"""
        prohibited, restricted, caps, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "subprocess.run(shell=True)" in patterns

    def test_static_command_shell_true_restricted(self):
        """shell=True with literal command → RESTRICTED (not prohibited)."""
        code = """\
import subprocess
subprocess.run("echo hello", shell=True)
"""
        prohibited, restricted, caps, _ = _parse_code(code)
        # Should NOT be prohibited
        shell_prohibited = [f for f in prohibited if "shell=True" in f.pattern]
        assert len(shell_prohibited) == 0
        # Should be restricted
        shell_restricted = [f for f in restricted if "shell=True" in f.pattern]
        assert len(shell_restricted) > 0

    def test_popen_shell_true_dynamic(self):
        """Popen with shell=True and dynamic command → PROHIBITED."""
        code = """\
import subprocess
cmd = get_cmd()
subprocess.Popen(cmd, shell=True)
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "subprocess.Popen(shell=True)" in patterns

    def test_shell_false_no_flag(self):
        """shell=False should not be flagged."""
        code = """\
import subprocess
subprocess.run(["echo", "hello"], shell=False)
"""
        prohibited, _, _, _ = _parse_code(code)
        shell_findings = [f for f in prohibited if "shell" in f.pattern.lower()]
        assert len(shell_findings) == 0


# ════════════════════════════════════════════════════════════════════
# 2. Legacy / Low-Level Execution Sinks
# ════════════════════════════════════════════════════════════════════


class TestLegacyExecutionSinks:
    """Sections 2.3–2.6 — platform.popen, pty, posix, commands."""

    def test_pty_import_prohibited(self):
        """import pty → PROHIBITED (common in reverse shells)."""
        code = "import pty\n"
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "import pty" in patterns

    def test_commands_import_prohibited(self):
        """import commands → PROHIBITED (Python 2 shell exec)."""
        code = "import commands\n"
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "import commands" in patterns

    def test_pty_spawn_detected(self):
        """pty.spawn() → detected as subprocess:exec."""
        code = """\
import pty
pty.spawn("/bin/bash")
"""
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "subprocess:exec" in cap_keys

    def test_platform_popen_detected(self):
        """platform.popen() → detected as subprocess:exec."""
        code = """\
import platform
platform.popen("ls")
"""
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "subprocess:exec" in cap_keys

    def test_posix_system_detected(self):
        """posix.system() → detected as subprocess:exec."""
        code = """\
import posix
posix.system("ls")
"""
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "subprocess:exec" in cap_keys

    def test_from_commands_import_prohibited(self):
        """from commands import getoutput → PROHIBITED."""
        code = "from commands import getoutput\n"
        prohibited, _, _, _ = _parse_code(code)
        prohibited_patterns = {f.pattern for f in prohibited}
        assert any("commands" in p for p in prohibited_patterns)


# ════════════════════════════════════════════════════════════════════
# 3. Metaprogramming / Introspection
# ════════════════════════════════════════════════════════════════════


class TestMetaprogramming:
    """Sections 4.2–4.5 — runpy, code/codeop, sys._getframe, gc."""

    def test_runpy_run_path_dynamic_prohibited(self):
        """runpy.run_path with dynamic arg → PROHIBITED."""
        code = """\
import runpy
path = get_path()
runpy.run_path(path)
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "runpy.run_path" in patterns

    def test_runpy_run_module_dynamic_prohibited(self):
        """runpy.run_module with dynamic arg → PROHIBITED."""
        code = """\
import runpy
mod = get_module()
runpy.run_module(mod)
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "runpy.run_module" in patterns

    def test_code_interactive_interpreter_prohibited(self):
        """code.InteractiveInterpreter → PROHIBITED (embedded REPL)."""
        code = """\
import code
interp = code.InteractiveInterpreter()
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "code.InteractiveInterpreter" in patterns

    def test_code_interactive_console_prohibited(self):
        """code.InteractiveConsole → PROHIBITED (embedded REPL)."""
        code = """\
import code
console = code.InteractiveConsole()
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "code.InteractiveConsole" in patterns

    def test_sys_getframe_detected(self):
        """sys._getframe → RESTRICTED (introspection)."""
        code = """\
import sys
frame = sys._getframe(0)
"""
        _, restricted, _, _ = _parse_code(code)
        messages = {f.message for f in restricted}
        assert any("introspection" in m.lower() for m in messages)

    def test_sys_settrace_detected(self):
        """sys.settrace → RESTRICTED (introspection)."""
        code = """\
import sys
sys.settrace(my_tracer)
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "sys.settrace" in patterns

    def test_inspect_stack_detected(self):
        """inspect.stack() → RESTRICTED."""
        code = """\
import inspect
frames = inspect.stack()
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "inspect.stack" in patterns

    def test_gc_get_objects_detected(self):
        """gc.get_objects() → RESTRICTED (sandbox escape)."""
        code = """\
import gc
all_objects = gc.get_objects()
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "gc.get_objects" in patterns


# ════════════════════════════════════════════════════════════════════
# 4. sqlite3 Special Sinks
# ════════════════════════════════════════════════════════════════════


class TestSQLiteSinks:
    """Section 3.6 — sqlite3.enable_load_extension."""

    def test_enable_load_extension_true_prohibited(self):
        """enable_load_extension(True) → PROHIBITED."""
        code = """\
import sqlite3
conn = sqlite3.connect("db.sqlite3")
conn.enable_load_extension(True)
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "sqlite3.enable_load_extension(True)" in patterns

    def test_enable_load_extension_false_not_flagged(self):
        """enable_load_extension(False) → not flagged as prohibited."""
        code = """\
import sqlite3
conn = sqlite3.connect("db.sqlite3")
conn.enable_load_extension(False)
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "sqlite3.enable_load_extension(True)" not in patterns


# ════════════════════════════════════════════════════════════════════
# 5. Weak Randomness
# ════════════════════════════════════════════════════════════════════


class TestWeakRandomness:
    """Section 6.1 — random module in security contexts."""

    def test_random_in_security_variable_prohibited(self):
        """random.randint assigned to token/key/secret → PROHIBITED."""
        code = """\
import random
session_token = random.randint(0, 999999)
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert any("weak_random_secret" in p for p in patterns)

    def test_random_generic_use_restricted(self):
        """random.random() in non-security context → RESTRICTED."""
        code = """\
import random
x = random.random()
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert any("weak_random" in p for p in patterns)

    def test_random_choice_for_password_prohibited(self):
        """random.choice used for password generation → PROHIBITED."""
        code = """\
import random
import string
password = random.choice(string.ascii_letters)
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert any("weak_random_secret" in p for p in patterns)


# ════════════════════════════════════════════════════════════════════
# 6. tempfile.mktemp TOCTOU
# ════════════════════════════════════════════════════════════════════


class TestTempfileMktemp:
    """Section 5.3 — tempfile.mktemp race condition."""

    def test_mktemp_flagged(self):
        """tempfile.mktemp() → RESTRICTED with TOCTOU warning."""
        code = """\
import tempfile
path = tempfile.mktemp()
"""
        _, restricted, _, _ = _parse_code(code)
        messages = [f.message for f in restricted if "mktemp" in f.pattern]
        assert len(messages) > 0
        assert any("TOCTOU" in m for m in messages)

    def test_mkstemp_not_flagged_as_toctou(self):
        """tempfile.mkstemp() → no TOCTOU warning (safe alternative)."""
        code = """\
import tempfile
fd, path = tempfile.mkstemp()
"""
        _, restricted, _, _ = _parse_code(code)
        toctou_findings = [f for f in restricted if "TOCTOU" in f.message]
        assert len(toctou_findings) == 0


# ════════════════════════════════════════════════════════════════════
# 7. Archive Bomb Detection
# ════════════════════════════════════════════════════════════════════


class TestArchiveBombs:
    """Section 5.4 — zipfile, tarfile, shutil.unpack_archive."""

    def test_zipfile_detected(self):
        """zipfile.ZipFile → RESTRICTED with bomb warning."""
        code = """\
import zipfile
zf = zipfile.ZipFile("archive.zip")
"""
        _, restricted, _, _ = _parse_code(code)
        messages = [f.message for f in restricted if "zipfile" in f.pattern.lower()]
        assert any("bomb" in m.lower() for m in messages)

    def test_tarfile_detected(self):
        """tarfile.open → RESTRICTED with bomb warning."""
        code = """\
import tarfile
tf = tarfile.open("archive.tar.gz")
"""
        _, restricted, _, _ = _parse_code(code)
        messages = [f.message for f in restricted if "tarfile" in f.pattern.lower()]
        assert any("bomb" in m.lower() for m in messages)

    def test_shutil_unpack_archive_detected(self):
        """shutil.unpack_archive → RESTRICTED with bomb warning."""
        code = """\
import shutil
shutil.unpack_archive("archive.zip", "/tmp/output")
"""
        _, restricted, _, _ = _parse_code(code)
        messages = [f.message for f in restricted if "unpack_archive" in f.pattern.lower()]
        assert any("bomb" in m.lower() or "archive" in m.lower() for m in messages)


# ════════════════════════════════════════════════════════════════════
# 8. SSRF Detection
# ════════════════════════════════════════════════════════════════════


class TestSSRF:
    """Section 5.2 — SSRF via urllib with non-literal URL."""

    def test_urlopen_dynamic_url_ssrf(self):
        """urllib.request.urlopen with variable URL → SSRF finding."""
        code = """\
import urllib.request
url = get_user_input()
urllib.request.urlopen(url)
"""
        _, restricted, _, _ = _parse_code(code)
        ssrf_findings = [f for f in restricted if "ssrf" in f.pattern.lower()]
        assert len(ssrf_findings) > 0

    def test_urlopen_static_url_no_ssrf(self):
        """urllib.request.urlopen with literal URL → no SSRF finding."""
        code = """\
import urllib.request
urllib.request.urlopen("https://api.example.com/data")
"""
        _, restricted, _, _ = _parse_code(code)
        ssrf_findings = [f for f in restricted if "ssrf" in f.pattern.lower()]
        assert len(ssrf_findings) == 0


# ════════════════════════════════════════════════════════════════════
# 9. Module Shadowing Detection
# ════════════════════════════════════════════════════════════════════


class TestShadowDetection:
    """Section 6.4 — local files shadowing stdlib modules."""

    def test_email_py_shadows_stdlib(self):
        """A top-level email.py should be flagged as shadowing."""
        files = [Path("email.py"), Path("main.py")]
        findings = detect_shadow_modules(files, Path("/fake/project"))
        assert len(findings) > 0
        assert any("email" in f.message for f in findings)

    def test_code_py_shadows_stdlib(self):
        """A top-level code.py should be flagged as shadowing."""
        files = [Path("code.py"), Path("app.py")]
        findings = detect_shadow_modules(files, Path("/fake/project"))
        assert len(findings) > 0
        assert any("code" in f.message for f in findings)

    def test_os_package_shadows_stdlib(self):
        """A top-level os/ package should be flagged."""
        files = [Path("os/__init__.py"), Path("main.py")]
        findings = detect_shadow_modules(files, Path("/fake/project"))
        assert len(findings) > 0
        assert any("os" in f.message for f in findings)

    def test_nested_file_not_flagged(self):
        """A file nested in a package (pkg/email.py) should NOT be flagged."""
        files = [Path("mypackage/email.py"), Path("main.py")]
        findings = detect_shadow_modules(files, Path("/fake/project"))
        shadow_findings = [f for f in findings if "email" in f.message]
        assert len(shadow_findings) == 0

    def test_non_stdlib_name_not_flagged(self):
        """A file named 'myapp.py' should not be flagged."""
        files = [Path("myapp.py"), Path("utils.py")]
        findings = detect_shadow_modules(files, Path("/fake/project"))
        assert len(findings) == 0

    def test_security_sensitive_shadows_are_prohibited(self):
        """Shadowing security-sensitive modules → PROHIBITED severity."""
        files = [Path("os.py")]
        findings = detect_shadow_modules(files, Path("/fake/project"))
        assert len(findings) > 0
        assert findings[0].severity == FindingSeverity.PROHIBITED


# ════════════════════════════════════════════════════════════════════
# 10. Cyclomatic Complexity
# ════════════════════════════════════════════════════════════════════


class TestCyclomaticComplexity:
    """Section 7.3 — complexity-based risk flagging."""

    def test_simple_function_not_flagged(self):
        """A simple function (CC=1) should not be flagged."""
        code = """\
def simple():
    return 42
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            f.flush()
            findings = analyze_complexity(Path(f.name), "test.py", threshold=15)
        assert len(findings) == 0

    def test_complex_function_flagged(self):
        """A function with high CC should be flagged."""
        # Build a function with many branches (CC > 15)
        branches = "\n".join(
            f"    if x == {i}:\n        return {i}" for i in range(20)
        )
        code = f"def complex_func(x):\n{branches}\n    return -1\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            f.flush()
            findings = analyze_complexity(Path(f.name), "test.py", threshold=15)
        assert len(findings) > 0
        assert any("complex_func" in f.message for f in findings)
        assert any("complexity" in f.message.lower() for f in findings)

    def test_custom_threshold(self):
        """Custom threshold should be respected."""
        code = """\
def moderate(x):
    if x > 0:
        if x > 10:
            return "big"
        return "small"
    return "negative"
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            f.flush()
            # CC=3, threshold=2 → should flag
            findings = analyze_complexity(Path(f.name), "test.py", threshold=2)
        assert len(findings) > 0

    def test_async_functions_analyzed(self):
        """Async functions should also have complexity computed."""
        branches = "\n".join(
            f"    if x == {i}:\n        return {i}" for i in range(20)
        )
        code = f"async def complex_async(x):\n{branches}\n    return -1\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            f.flush()
            findings = analyze_complexity(Path(f.name), "test.py", threshold=15)
        assert len(findings) > 0

    def test_syntax_error_handled(self):
        """Files with syntax errors should not crash."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("def broken(\n")
            f.flush()
            findings = analyze_complexity(Path(f.name), "test.py")
        assert len(findings) == 0


# ════════════════════════════════════════════════════════════════════
# 11. New Import-Level Detections
# ════════════════════════════════════════════════════════════════════


class TestNewImportPatterns:
    """Verify new import-level patterns are detected."""

    def test_import_runpy_restricted(self):
        code = "import runpy\n"
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "subprocess:exec" in cap_keys

    def test_import_inspect_restricted(self):
        code = "import inspect\n"
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "system:sysinfo" in cap_keys

    def test_import_gc_restricted(self):
        code = "import gc\n"
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "system:sysinfo" in cap_keys

    def test_import_random_restricted(self):
        code = "import random\n"
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "crypto:hash" in cap_keys

    def test_import_zipfile_restricted(self):
        code = "import zipfile\n"
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "fs:read" in cap_keys

    def test_import_plistlib_restricted(self):
        code = "import plistlib\n"
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys


# ════════════════════════════════════════════════════════════════════
# 12. XML / Deserialization Extended Sinks
# ════════════════════════════════════════════════════════════════════


class TestExtendedDeserializationSinks:
    """Extended XML / deserialization sinks from PDF."""

    def test_plistlib_load_detected(self):
        code = """\
import plistlib
data = plistlib.load(open("info.plist", "rb"))
"""
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys

    def test_xml_pulldom_detected(self):
        code = """\
from xml.dom import pulldom
doc = pulldom.parse("data.xml")
"""
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys

    def test_xmlrpc_server_detected(self):
        code = """\
from xmlrpc.server import SimpleXMLRPCServer
server = SimpleXMLRPCServer(("localhost", 8000))
"""
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "network:listen" in cap_keys

    def test_yaml_load_with_safeloader_not_flagged(self):
        code = """\
import yaml
data = yaml.load(payload, Loader=yaml.SafeLoader)
"""
        _, restricted, caps, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "yaml.load" not in patterns
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys

    def test_yaml_load_without_loader_flagged(self):
        code = """\
import yaml
data = yaml.load(payload)
"""
        _, restricted, caps, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "yaml.load" in patterns
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys

    def test_yaml_load_all_without_loader_flagged(self):
        code = """\
import yaml
for doc in yaml.load_all(payload):
    pass
"""
        _, restricted, caps, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "yaml.load_all" in patterns
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys

    def test_xml_c_elementtree_parse_detected(self):
        code = """\
import xml.etree.cElementTree
doc = xml.etree.cElementTree.parse("data.xml")
"""
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys

    def test_shelve_dbfilename_shelf_detected(self):
        code = """\
import shelve
db = shelve.DbfilenameShelf("cache.db")
"""
        _, restricted, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys


# ════════════════════════════════════════════════════════════════════
# 13. Alias / Symbol Resolution Hardening
# ════════════════════════════════════════════════════════════════════


class TestAliasResolution:
    """Aliased imports should still resolve to canonical dangerous sinks."""

    def test_alias_os_system_detected(self):
        code = """\
import os as sys_ops
sys_ops.system("id")
"""
        _, restricted, caps, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "os.system" in patterns
        cap_keys = {c.capability_key for c in caps}
        assert "subprocess:exec" in cap_keys

    def test_alias_subprocess_run_shell_true_prohibited(self):
        code = """\
from subprocess import run as runner
cmd = input("cmd: ")
runner(cmd, shell=True)
"""
        prohibited, _, _, _ = _parse_code(code)
        patterns = {f.pattern for f in prohibited}
        assert "subprocess.run(shell=True)" in patterns

    def test_alias_yaml_load_detected(self):
        code = """\
import yaml as y
obj = y.load(payload)
"""
        _, restricted, caps, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "yaml.load" in patterns
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys

    def test_alias_elementtree_parse_detected(self):
        code = """\
import xml.etree.ElementTree as ET
tree = ET.parse("data.xml")
"""
        _, _, caps, _ = _parse_code(code)
        cap_keys = {c.capability_key for c in caps}
        assert "serial:deserialize" in cap_keys


# ════════════════════════════════════════════════════════════════════
# 14. Lightweight Source-to-Sink Taint Flows
# ════════════════════════════════════════════════════════════════════


class TestLightweightTaintFlows:
    """Deterministic source->sink checks for common high-risk paths."""

    def test_taint_to_command_sink_detected(self):
        code = """\
import subprocess
cmd = input("cmd: ")
subprocess.run(cmd)
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "taint:subprocess.run" in patterns

    def test_taint_to_url_sink_detected(self):
        code = """\
import requests
u = input("url: ")
requests.get(u)
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "taint:requests.get" in patterns

    def test_taint_to_sql_sink_detected(self):
        code = """\
query = input("q: ")
cursor.execute(query)
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "taint:sql.execute" in patterns

    def test_taint_to_open_path_detected(self):
        code = """\
p = input("path: ")
with open(p, "r") as f:
    data = f.read()
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "taint:open" in patterns

    def test_taint_from_sys_argv_attribute_detected(self):
        code = """\
import sys
import subprocess
argv = sys.argv
subprocess.run(argv[1])
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "taint:subprocess.run" in patterns

    def test_taint_url_keyword_argument_detected(self):
        code = """\
import requests
u = input("url: ")
requests.get(url=u)
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "taint:requests.get" in patterns

    def test_taint_path_second_argument_detected(self):
        code = """\
import os
dst = input("dst: ")
os.rename("a.txt", dst)
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "taint:os.rename" in patterns

    def test_interprocedural_tainted_return_detected(self):
        code = """\
import os
def read_cmd():
    return input("cmd: ")
cmd = read_cmd()
os.system(cmd)
"""
        _, restricted, _, _ = _parse_code(code)
        patterns = {f.pattern for f in restricted}
        assert "taint:os.system" in patterns
