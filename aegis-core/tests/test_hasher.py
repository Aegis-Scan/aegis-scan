"""Tests for the Merkle tree hasher.

Tests LF normalization, tree determinism, lexicographic ordering,
single-file proof verification, and proof isolation (Directive 2).
"""

import pytest

from aegis.crypto.hasher import (
    build_merkle_tree,
    get_proof_path,
    hash_content,
    normalize_content,
    verify_leaf,
)


class TestNormalization:
    """Test content normalization."""

    def test_crlf_to_lf(self):
        content = b"line1\r\nline2\r\nline3"
        assert normalize_content(content) == b"line1\nline2\nline3"

    def test_cr_to_lf(self):
        content = b"line1\rline2\rline3"
        assert normalize_content(content) == b"line1\nline2\nline3"

    def test_lf_unchanged(self):
        content = b"line1\nline2\nline3"
        assert normalize_content(content) == b"line1\nline2\nline3"

    def test_mixed_line_endings(self):
        content = b"line1\r\nline2\rline3\nline4"
        result = normalize_content(content)
        assert b"\r" not in result


class TestHashing:
    """Test SHA-256 hashing."""

    def test_hash_format(self):
        h = hash_content(b"hello world")
        assert h.startswith("sha256:")
        assert len(h) == len("sha256:") + 64

    def test_deterministic(self):
        h1 = hash_content(b"hello world")
        h2 = hash_content(b"hello world")
        assert h1 == h2

    def test_different_content_different_hash(self):
        h1 = hash_content(b"hello")
        h2 = hash_content(b"world")
        assert h1 != h2

    def test_normalization_applied(self):
        """Same content with different line endings should produce same hash."""
        h1 = hash_content(b"line1\nline2")
        h2 = hash_content(b"line1\r\nline2")
        assert h1 == h2


class TestMerkleTree:
    """Test Merkle tree construction and verification."""

    def test_empty_tree(self):
        tree = build_merkle_tree([])
        assert tree.root == "sha256:" + "0" * 64
        assert tree.leaves == []
        assert tree.nodes == []

    def test_single_leaf(self):
        tree = build_merkle_tree([("file.py", "sha256:aaa")])
        assert tree.root == "sha256:aaa"
        assert len(tree.leaves) == 1
        assert tree.nodes == []

    def test_two_leaves(self):
        tree = build_merkle_tree([
            ("a.py", "sha256:aaa"),
            ("b.py", "sha256:bbb"),
        ])
        assert len(tree.leaves) == 2
        assert len(tree.nodes) == 1
        assert tree.root == tree.nodes[0]

    def test_deterministic_ordering(self):
        """Same files in same order should produce same tree."""
        hashes = [
            ("a.py", "sha256:111"),
            ("b.py", "sha256:222"),
            ("c.py", "sha256:333"),
        ]
        tree1 = build_merkle_tree(hashes)
        tree2 = build_merkle_tree(hashes)
        assert tree1.root == tree2.root

    def test_different_order_different_root(self):
        """Different ordering should produce different root."""
        tree1 = build_merkle_tree([
            ("a.py", "sha256:111"),
            ("b.py", "sha256:222"),
        ])
        tree2 = build_merkle_tree([
            ("b.py", "sha256:222"),
            ("a.py", "sha256:111"),
        ])
        assert tree1.root != tree2.root

    def test_odd_number_of_leaves(self):
        """Odd leaf count should still build a valid tree."""
        tree = build_merkle_tree([
            ("a.py", "sha256:111"),
            ("b.py", "sha256:222"),
            ("c.py", "sha256:333"),
        ])
        assert tree.root is not None
        assert len(tree.leaves) == 3


class TestProofVerification:
    """Test single-file proof verification (Directive 2).

    verify_leaf() MUST confirm a single file's integrity against
    the root using O(log n) sibling hashes, WITHOUT reading any other file.
    """

    def test_valid_proof(self):
        hashes = [
            ("a.py", "sha256:111"),
            ("b.py", "sha256:222"),
            ("c.py", "sha256:333"),
            ("d.py", "sha256:444"),
        ]
        tree = build_merkle_tree(hashes)

        # Get proof for file "b.py"
        proof = get_proof_path(tree, "b.py")
        assert proof is not None

        # Verify using only the proof path — no other file hashes needed
        result = verify_leaf("sha256:222", proof, tree.root)
        assert result is True

    def test_invalid_hash_fails(self):
        hashes = [
            ("a.py", "sha256:111"),
            ("b.py", "sha256:222"),
        ]
        tree = build_merkle_tree(hashes)
        proof = get_proof_path(tree, "b.py")
        assert proof is not None

        # Tampered hash should fail
        result = verify_leaf("sha256:TAMPERED", proof, tree.root)
        assert result is False

    def test_proof_for_each_leaf(self):
        """Every leaf should have a valid proof."""
        hashes = [
            ("a.py", "sha256:111"),
            ("b.py", "sha256:222"),
            ("c.py", "sha256:333"),
        ]
        tree = build_merkle_tree(hashes)

        for path, hash_val in hashes:
            proof = get_proof_path(tree, path)
            assert proof is not None
            assert verify_leaf(hash_val, proof, tree.root) is True

    def test_nonexistent_file_returns_none(self):
        tree = build_merkle_tree([("a.py", "sha256:111")])
        proof = get_proof_path(tree, "nonexistent.py")
        assert proof is None

    def test_single_leaf_proof(self):
        tree = build_merkle_tree([("a.py", "sha256:111")])
        proof = get_proof_path(tree, "a.py")
        assert proof is not None
        assert len(proof) == 0  # No siblings for single leaf
        assert verify_leaf("sha256:111", proof, tree.root) is True
