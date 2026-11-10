"""Canonical JSON (RFC 8785, JCS) hashing and an RFC 6962-style Merkle tree.

Leaves and nodes are domain-separated (0x00 / 0x01 prefixes) so a leaf can never be passed off as a node.
Database-free: the offline verifier imports this module.
"""

import hashlib
from typing import Any

import rfc8785


def canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(value: Any) -> str:
    return sha256_hex(b"\x00" + canonical(value))


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaf_hashes: list[str]) -> str:
    """RFC 6962 tree hash: split at the largest power of two below n, recursively."""
    if not leaf_hashes:
        return sha256_hex(b"")
    nodes = [bytes.fromhex(h) for h in leaf_hashes]

    def tree(items: list[bytes]) -> bytes:
        if len(items) == 1:
            return items[0]
        split = 1 << ((len(items) - 1).bit_length() - 1)
        return _node(tree(items[:split]), tree(items[split:]))

    return tree(nodes).hex()
