"""Checking a W3C Data Integrity proof, cryptosuite `eddsa-jcs-2022`, issued by a `did:web` (Ed25519).

The proof signs SHA-256(JCS(proof options)) ‖ SHA-256(JCS(document without proof)); `proofValue` is multibase
base58btc. Lookup Luke signs with the other half of this code; this package only verifies.
"""

import hashlib
from typing import Any
from urllib.parse import quote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from lookupluke_verify.canonical import canonical

CRYPTOSUITE = "eddsa-jcs-2022"
ED25519_MULTICODEC = b"\xed\x01"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + _B58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def public_key_multibase(key: Ed25519PublicKey) -> str:
    return "z" + b58encode(ED25519_MULTICODEC + key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def public_key_from_multibase(value: str) -> Ed25519PublicKey:
    if not value.startswith("z"):
        raise ValueError("publicKeyMultibase must be base58btc (z…)")
    raw = b58decode(value[1:])
    if not raw.startswith(ED25519_MULTICODEC) or len(raw) != 34:
        raise ValueError("not an Ed25519 multikey")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def did_web(public_url: str) -> str:
    """did:web for the public origin (a port is percent-encoded, per the did:web method)."""
    return "did:web:" + quote(urlsplit(public_url).netloc, safe="")


# ---- Data Integrity proof -------------------------------------------------------------------------------------


def _signing_input(document: dict[str, Any], options: dict[str, Any]) -> bytes:
    unsecured = {key: value for key, value in document.items() if key != "proof"}
    return hashlib.sha256(canonical(options)).digest() + hashlib.sha256(canonical(unsecured)).digest()


def verify(document: dict[str, Any], key: Ed25519PublicKey) -> bool:
    proof = document.get("proof")
    if not isinstance(proof, dict) or proof.get("cryptosuite") != CRYPTOSUITE or not str(proof.get("proofValue", "")).startswith("z"):
        return False
    options = {key_: value for key_, value in proof.items() if key_ != "proofValue"}
    options["@context"] = document.get("@context")
    try:
        key.verify(b58decode(proof["proofValue"][1:]), _signing_input(document, options))
    except (InvalidSignature, ValueError):
        return False
    return True
