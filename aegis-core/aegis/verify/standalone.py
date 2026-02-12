# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""DEPENDENCY-FREE standalone verifier for aegis.lock files.

This module MUST import ONLY:
- json, hashlib, os, pathlib, sys, typing (stdlib)
- cryptography (single external dependency)

It MUST NOT import Typer, Rich, Pydantic, httpx, PyYAML, or any LLM library.

Invocable as: python -m aegis.verify.standalone ./path
Produces plain-text output with exit code 0 (pass) or 1 (fail).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional


def resolve_under_root(root: Path, relative_path: str) -> tuple[Optional[Path], Optional[str]]:
    """Resolve a relative path safely under root.

    Returns:
        (resolved_path, error_message)
    """
    root = root.resolve()
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None, f"Path escapes target directory: {relative_path}"

    normalized_rel = Path(os.path.normpath(relative_path))
    if normalized_rel.is_absolute() or normalized_rel.parts[:1] == ("..",):
        return None, f"Path escapes target directory: {relative_path}"

    try:
        resolved = (root / normalized_rel).resolve()
        resolved.relative_to(root)
    except Exception:
        return None, f"Path escapes target directory: {relative_path}"

    return resolved, None


def normalize_content(content: bytes) -> bytes:
    """Normalize file content to LF line endings before hashing."""
    return content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def hash_content(content: bytes) -> str:
    """SHA-256 hash of normalized content. Returns 'sha256:hex...'."""
    normalized = normalize_content(content)
    digest = hashlib.sha256(normalized).hexdigest()
    return f"sha256:{digest}"


def hash_file(file_path: Path) -> str:
    """Hash a single file with content normalization."""
    content = file_path.read_bytes()
    return hash_content(content)


def hash_pair(left: str, right: str) -> str:
    """Hash two node values to create a parent node."""
    left_hex = left.removeprefix("sha256:")
    right_hex = right.removeprefix("sha256:")
    combined = (left_hex + right_hex).encode("ascii")
    digest = hashlib.sha256(combined).hexdigest()
    return f"sha256:{digest}"


def build_merkle_root(leaf_hashes: list[str]) -> str:
    """Rebuild the Merkle root from leaf hashes."""
    if not leaf_hashes:
        return "sha256:" + "0" * 64

    if len(leaf_hashes) == 1:
        return leaf_hashes[0]

    current_level = list(leaf_hashes)

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
            next_level.append(hash_pair(left, right))
        current_level = next_level

    return current_level[0]


def verify_leaf_proof(
    leaf_hash: str,
    proof_path: list[tuple[str, str]],
    expected_root: str,
) -> bool:
    """Verify a single file against the Merkle root using its proof path.

    O(log n) — does not read or hash any other file.
    """
    current = leaf_hash

    for sibling_hash, side in proof_path:
        if side == "left":
            current = hash_pair(sibling_hash, current)
        else:
            current = hash_pair(current, sibling_hash)

    return current == expected_root


def load_lockfile(lockfile_path: Path) -> dict[str, Any]:
    """Load and parse aegis.lock using only json (stdlib)."""
    content = lockfile_path.read_text(encoding="utf-8")
    return json.loads(content)


def verify_merkle_tree(
    target_dir: Path,
    lockfile_data: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Verify the full Merkle tree against files on disk.

    Recomputes all leaf hashes, rebuilds the tree, compares root.

    Returns:
        (passed, list_of_error_messages)
    """
    merkle = lockfile_data.get("merkle_tree", {})
    expected_root = merkle.get("root", "")
    leaves = merkle.get("leaves", [])
    errors = []

    if not leaves:
        errors.append("No leaves in Merkle tree")
        return False, errors

    # Recompute leaf hashes from files on disk
    computed_hashes = []
    for leaf in leaves:
        file_path, path_error = resolve_under_root(target_dir, str(leaf["path"]))
        if path_error:
            errors.append(path_error)
            computed_hashes.append("sha256:" + "0" * 64)
            continue

        if not file_path.exists():
            errors.append(f"Missing file: {leaf['path']}")
            computed_hashes.append("sha256:" + "0" * 64)  # placeholder
            continue

        computed_hash = hash_file(file_path)
        if computed_hash != leaf["hash"]:
            errors.append(
                f"Hash mismatch: {leaf['path']} "
                f"(expected {leaf['hash']}, got {computed_hash})"
            )
        computed_hashes.append(computed_hash)

    # Rebuild Merkle root
    computed_root = build_merkle_root(computed_hashes)

    if computed_root != expected_root:
        errors.append(
            f"Merkle root mismatch (expected {expected_root}, got {computed_root})"
        )

    return len(errors) == 0, errors


def verify_signature(
    lockfile_data: dict[str, Any],
    slot_name: str = "developer",
) -> tuple[bool, str]:
    """Verify an Ed25519 signature slot.

    Uses only the `cryptography` library.

    Returns:
        (passed, message)
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, "cryptography library not installed"

    signatures = lockfile_data.get("signatures", {})
    slot = signatures.get(slot_name)

    if not slot:
        return False, f"No {slot_name} signature found"

    key_id = slot["key_id"]
    sig_b64 = slot["value"]

    # Parse public key from key_id
    if not key_id.startswith("ed25519:"):
        return False, f"Unknown key type: {key_id}"

    try:
        pub_bytes = base64.b64decode(key_id.removeprefix("ed25519:"))
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as e:
        return False, f"Invalid public key in key_id: {e}"

    # Reconstruct signable payload
    signed_fields = lockfile_data.get("signed_fields", [])
    payload_data: dict[str, Any] = {}

    for field_path in signed_fields:
        if "." in field_path:
            parts = field_path.split(".")
            value: Any = lockfile_data
            for part in parts:
                value = value[part]
            payload_data[field_path] = value
        else:
            payload_data[field_path] = lockfile_data[field_path]

    payload = json.dumps(payload_data, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    payload_bytes = payload.encode("utf-8")

    # Verify signature
    try:
        sig_bytes = base64.b64decode(sig_b64)
        public_key.verify(sig_bytes, payload_bytes)
        return True, "Signature valid"
    except Exception as e:
        return False, f"Signature verification failed: {e}"


def verify_single_file(
    target_dir: Path,
    lockfile_data: dict[str, Any],
    file_path: str,
) -> tuple[bool, str]:
    """Verify a single file against the Merkle root using proof path.

    This is O(log n) — no need to re-hash the entire codebase.
    """
    merkle = lockfile_data.get("merkle_tree", {})
    leaves = merkle.get("leaves", [])
    expected_root = merkle.get("root", "")

    # Find the leaf
    leaf_idx = None
    for i, leaf in enumerate(leaves):
        if leaf["path"] == file_path:
            leaf_idx = i
            break

    if leaf_idx is None:
        return False, f"File not found in lockfile: {file_path}"

    # Compute current hash
    full_path, path_error = resolve_under_root(target_dir, file_path)
    if path_error:
        return False, path_error

    if not full_path.exists():
        return False, f"File not found on disk: {file_path}"

    current_hash = hash_file(full_path)
    expected_hash = leaves[leaf_idx]["hash"]

    if current_hash != expected_hash:
        return False, f"File hash mismatch: {file_path}"

    # Build proof path and verify
    # We need to rebuild the proof from the full tree
    leaf_hashes = [leaf["hash"] for leaf in leaves]
    current_level_hashes = list(leaf_hashes)
    idx = leaf_idx
    proof: list[tuple[str, str]] = []

    while len(current_level_hashes) > 1:
        if idx % 2 == 0:
            sibling_idx = idx + 1
            if sibling_idx < len(current_level_hashes):
                proof.append((current_level_hashes[sibling_idx], "right"))
            else:
                proof.append((current_level_hashes[idx], "right"))
        else:
            proof.append((current_level_hashes[idx - 1], "left"))

        next_level = []
        for i in range(0, len(current_level_hashes), 2):
            left = current_level_hashes[i]
            right = (
                current_level_hashes[i + 1]
                if i + 1 < len(current_level_hashes)
                else current_level_hashes[i]
            )
            next_level.append(hash_pair(left, right))
        current_level_hashes = next_level
        idx = idx // 2

    if verify_leaf_proof(current_hash, proof, expected_root):
        return True, f"File verified: {file_path}"
    else:
        return False, f"Merkle proof failed for: {file_path}"


def verify(
    target_dir: Path,
    lockfile_path: Optional[Path] = None,
    strict: bool = False,
) -> tuple[bool, list[str]]:
    """Full verification of aegis.lock against code on disk.

    Steps:
    1. Load and parse aegis.lock
    2. Verify Merkle tree (all file hashes match)
    3. Verify developer signature

    Args:
        target_dir: Path to the skill directory.
        lockfile_path: Path to aegis.lock (default: target_dir/aegis.lock).
        strict: If True, fail on any file change.

    Returns:
        (passed, list_of_messages)
    """
    if lockfile_path is None:
        lockfile_path = target_dir / "aegis.lock"

    messages = []

    # Step 1: Load lockfile
    if not lockfile_path.exists():
        return False, [f"Lockfile not found: {lockfile_path}"]

    try:
        lockfile_data = load_lockfile(lockfile_path)
    except (json.JSONDecodeError, OSError) as e:
        return False, [f"Failed to parse lockfile: {e}"]

    messages.append(f"Loaded lockfile: {lockfile_path}")
    messages.append(f"Aegis version: {lockfile_data.get('aegis_version', 'unknown')}")
    messages.append(f"Cert ID: {lockfile_data.get('cert_id', 'unknown')}")

    # Step 2: Verify Merkle tree
    merkle_passed, merkle_errors = verify_merkle_tree(target_dir, lockfile_data)
    if merkle_passed:
        leaf_count = len(lockfile_data.get("merkle_tree", {}).get("leaves", []))
        messages.append(f"Merkle tree: PASS ({leaf_count} files verified)")
    else:
        messages.append("Merkle tree: FAIL")
        messages.extend(f"  - {e}" for e in merkle_errors)
        return False, messages

    # Step 3: Verify signature
    sig_passed, sig_msg = verify_signature(lockfile_data, slot_name="developer")
    if sig_passed:
        messages.append(f"Signature (developer): PASS")
    else:
        messages.append(f"Signature (developer): FAIL — {sig_msg}")
        return False, messages

    messages.append("VERIFICATION PASSED")
    return True, messages


def main() -> None:
    """CLI entry point for standalone verification.

    Usage: python -m aegis.verify.standalone <path> [--lockfile <path>] [--strict]
    """
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("Usage: python -m aegis.verify.standalone <path> [--lockfile <path>] [--strict]")
        print()
        print("Verify an aegis.lock file against the code on disk.")
        print("Dependency-free: requires only Python stdlib + cryptography.")
        sys.exit(0)

    target_dir = Path(args[0]).resolve()
    lockfile_path = None
    strict = False

    i = 1
    while i < len(args):
        if args[i] == "--lockfile" and i + 1 < len(args):
            lockfile_path = Path(args[i + 1]).resolve()
            i += 2
        elif args[i] == "--strict":
            strict = True
            i += 1
        else:
            print(f"Unknown argument: {args[i]}", file=sys.stderr)
            sys.exit(2)

    if lockfile_path:
        passed, messages = verify(target_dir, lockfile_path, strict)
    else:
        passed, messages = verify(target_dir, strict=strict)

    for msg in messages:
        print(msg)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
