"""Security-focused tests for standalone lockfile verification."""

from pathlib import Path

from aegis.verify.standalone import verify_merkle_tree


def test_verify_merkle_tree_rejects_path_escape(tmp_path: Path):
    outside_file = tmp_path.parent / "outside.py"
    outside_file.write_text("print('outside')\n", encoding="utf-8")

    lockfile_data = {
        "merkle_tree": {
            "root": "sha256:" + "0" * 64,
            "leaves": [
                {
                    "path": "../outside.py",
                    "hash": "sha256:" + "1" * 64,
                }
            ],
        }
    }

    passed, errors = verify_merkle_tree(tmp_path, lockfile_data)

    assert not passed
    assert any("Path escapes target directory" in err for err in errors)
