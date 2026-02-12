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

"""Lazy Merkle tree — content-aware normalization and per-file hashing.

Every file is a leaf. The tree structure (leaf hashes + intermediate nodes)
is stored in the lockfile so the proxy can verify any individual file's
integrity against the root hash WITHOUT re-hashing the entire tree.

Implements:
- LF normalization before hashing
- SHA-256 per-file hashing
- Binary Merkle tree construction (bottom-up)
- Single-file proof verification via sibling hash path (O(log n))
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path

from aegis.models.report import MerkleLeaf, MerkleTree


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


def _hash_pair(left: str, right: str) -> str:
    """Hash two node values together to create a parent node.

    Strips the 'sha256:' prefix, concatenates the hex strings,
    and re-hashes.
    """
    left_hex = left.removeprefix("sha256:")
    right_hex = right.removeprefix("sha256:")
    combined = (left_hex + right_hex).encode("ascii")
    digest = hashlib.sha256(combined).hexdigest()
    return f"sha256:{digest}"


def build_merkle_tree(
    file_hashes: list[tuple[str, str]],
) -> MerkleTree:
    """Build a binary Merkle tree from sorted file hashes.

    Args:
        file_hashes: List of (relative_path, hash_string) tuples,
                     sorted lexicographically by path.

    Returns:
        MerkleTree with root, leaves, and all intermediate nodes.
    """
    if not file_hashes:
        return MerkleTree(
            root="sha256:" + "0" * 64,
            algorithm="sha256",
            leaves=[],
            nodes=[],
        )

    # Create leaves (sorted by path — caller must ensure this)
    leaves = [MerkleLeaf(path=path, hash=h) for path, h in file_hashes]

    if len(leaves) == 1:
        return MerkleTree(
            root=leaves[0].hash,
            algorithm="sha256",
            leaves=leaves,
            nodes=[],
        )

    # Build tree bottom-up
    # Current level starts with leaf hashes
    current_level = [leaf.hash for leaf in leaves]
    all_intermediate_nodes: list[str] = []

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # If odd number of nodes, duplicate the last one
            right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
            parent = _hash_pair(left, right)
            next_level.append(parent)
            all_intermediate_nodes.append(parent)

        current_level = next_level

    root = current_level[0]

    return MerkleTree(
        root=root,
        algorithm="sha256",
        leaves=leaves,
        nodes=all_intermediate_nodes,
    )


def get_proof_path(tree: MerkleTree, target_path: str) -> list[tuple[str, str]] | None:
    """Get the sibling hash proof path for a single file.

    Args:
        tree: The full Merkle tree.
        target_path: The file path to get the proof for.

    Returns:
        List of (sibling_hash, side) tuples where side is "left" or "right",
        or None if the path is not found. The proof can be used with
        verify_leaf() to confirm the file's integrity.
    """
    # Find the leaf index
    leaf_idx = None
    for i, leaf in enumerate(tree.leaves):
        if leaf.path == target_path:
            leaf_idx = i
            break

    if leaf_idx is None:
        return None

    if len(tree.leaves) <= 1:
        return []  # Single leaf — no proof needed

    proof: list[tuple[str, str]] = []
    current_level_hashes = [leaf.hash for leaf in tree.leaves]
    idx = leaf_idx

    while len(current_level_hashes) > 1:
        # Find sibling
        if idx % 2 == 0:
            # Current is left, sibling is right
            sibling_idx = idx + 1
            if sibling_idx < len(current_level_hashes):
                proof.append((current_level_hashes[sibling_idx], "right"))
            else:
                # Odd count, duplicate self
                proof.append((current_level_hashes[idx], "right"))
        else:
            # Current is right, sibling is left
            proof.append((current_level_hashes[idx - 1], "left"))

        # Move up: compute next level
        next_level = []
        for i in range(0, len(current_level_hashes), 2):
            left = current_level_hashes[i]
            right = (
                current_level_hashes[i + 1]
                if i + 1 < len(current_level_hashes)
                else current_level_hashes[i]
            )
            next_level.append(_hash_pair(left, right))

        current_level_hashes = next_level
        idx = idx // 2

    return proof


def verify_leaf(
    leaf_hash: str,
    proof_path: list[tuple[str, str]],
    expected_root: str,
) -> bool:
    """Verify a single file against the Merkle root using its proof path.

    This is O(log n) — it does NOT need to read or hash any other file.

    Args:
        leaf_hash: The SHA-256 hash of the file being verified.
        proof_path: List of (sibling_hash, side) from get_proof_path().
        expected_root: The expected Merkle root hash.

    Returns:
        True if the leaf hash is consistent with the root.
    """
    current = leaf_hash

    for sibling_hash, side in proof_path:
        if side == "left":
            current = _hash_pair(sibling_hash, current)
        else:
            current = _hash_pair(current, sibling_hash)

    return current == expected_root


def compute_file_hashes(
    target_dir: Path, file_list: list[Path]
) -> list[tuple[str, str]]:
    """Hash all files and return sorted (path, hash) tuples.

    Files are sorted lexicographically by relative path.
    """
    hashes = []
    for rel_path in sorted(file_list):
        full_path = target_dir / rel_path
        if full_path.exists() and full_path.is_file():
            h = hash_file(full_path)
            hashes.append((str(rel_path).replace("\\", "/"), h))

    return hashes
