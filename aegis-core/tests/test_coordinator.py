"""Tests for the file walker / coordinator."""

from pathlib import Path

import pytest

from aegis.scanner.coordinator import (
    discover_files,
    get_config_files,
    get_files_directory,
    get_manifest_files,
    get_python_files,
    get_shell_files,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestDiscoverFiles:
    """Test file discovery in skill directories."""

    def test_safe_skill_finds_files(self):
        files, source = discover_files(FIXTURES / "safe_skill")
        assert len(files) > 0
        assert source == "directory"  # No .git in fixtures

    def test_nonexistent_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            discover_files(Path("/nonexistent/path"))

    def test_not_a_dir_raises(self):
        with pytest.raises(NotADirectoryError):
            discover_files(FIXTURES / "safe_skill" / "weather.py")


class TestDirectoryWalk:
    """Test directory walk fallback."""

    def test_finds_python_files(self):
        files = get_files_directory(FIXTURES / "safe_skill")
        py_files = [f for f in files if f.suffix == ".py"]
        assert len(py_files) >= 1

    def test_finds_yaml_files(self):
        files = get_files_directory(FIXTURES / "safe_skill")
        yaml_files = [f for f in files if f.suffix in (".yaml", ".yml")]
        assert len(yaml_files) >= 1

    def test_ignores_pycache(self, tmp_path: Path):
        """__pycache__ should be ignored."""
        (tmp_path / "main.py").write_text("x = 1")
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "main.cpython-311.pyc").write_bytes(b"\x00")

        files = get_files_directory(tmp_path)
        file_names = [str(f) for f in files]
        assert not any("__pycache__" in f for f in file_names)


class TestFileFilters:
    """Test file type filters."""

    def test_python_filter(self):
        all_files = [Path("a.py"), Path("b.txt"), Path("c.py"), Path("d.yaml")]
        py_files = get_python_files(all_files)
        assert len(py_files) == 2
        assert all(f.suffix == ".py" for f in py_files)

    def test_manifest_includes_all_files(self):
        """Manifest now includes ALL discovered files for full integrity."""
        all_files = [Path("a.py"), Path("b.txt"), Path("c.so"), Path("d.yaml")]
        manifest_files = get_manifest_files(all_files)
        assert len(manifest_files) == 4
        assert Path("c.so") in manifest_files
        assert Path("a.py") in manifest_files
        assert Path("d.yaml") in manifest_files

    def test_shell_filter(self):
        all_files = [Path("a.py"), Path("b.sh"), Path("c.bat"), Path("d.yaml")]
        shell_files = get_shell_files(all_files)
        assert len(shell_files) == 2
        assert all(f.suffix in (".sh", ".bat") for f in shell_files)

    def test_config_filter(self):
        all_files = [Path("a.py"), Path("b.json"), Path("c.yaml"), Path("d.toml")]
        config_files = get_config_files(all_files)
        assert len(config_files) == 3
        assert all(f.suffix in (".json", ".yaml", ".toml") for f in config_files)
