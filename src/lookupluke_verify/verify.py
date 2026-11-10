"""Verify an evidence package: hashes and Merkle root, issuer signature, RFC 3161 timestamp, OpenTimestamps.

`key_for(verification_method)` supplies the issuer's public key: Lookup Luke's server passes its own DID documents;
the command line resolves `did:web` over HTTPS or reads a saved did.json. Lookup Luke's API uses this exact code,
so the API and this package always give the same answer.
"""

import base64
import binascii
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lookupluke_verify import ots
from lookupluke_verify import signing_verify as signing
from lookupluke_verify.canonical import leaf_hash, merkle_root
from lookupluke_verify.timestamping import verify_rfc3161


def leaves(subject: dict[str, Any]) -> list[str]:
    """Leaf order: observations by their evidence number, then the case (verdict, authorization, links, summary)."""
    observations = sorted(subject["observations"], key=lambda o: o["n"])
    return [leaf_hash({"kind": "observation", **o}) for o in observations] + [leaf_hash({"kind": "case", **subject["case"]})]


def key_from_did_document(document: dict[str, Any]) -> Callable[[str], Ed25519PublicKey]:
    methods = {m["id"]: m for m in document.get("verificationMethod", [])}
    allowed = set(document.get("assertionMethod", []))

    def key_for(method_id: str) -> Ed25519PublicKey:
        if method_id not in methods or method_id not in allowed:
            raise ValueError(f"{method_id} is not an assertion key of {document.get('id')}")
        return signing.public_key_from_multibase(methods[method_id]["publicKeyMultibase"])

    return key_for


def key_from_did_documents(documents: list[dict[str, Any]]) -> Callable[[str], Ed25519PublicKey]:
    """Key lookup over several DID documents (one issuer known under several hosts): the method's DID picks one."""
    by_did = {document.get("id"): key_from_did_document(document) for document in documents}

    def key_for(method_id: str) -> Ed25519PublicKey:
        lookup = by_did.get(method_id.split("#")[0])
        if lookup is None:
            raise ValueError(f"{method_id.split('#')[0]} is not a known issuer")
        return lookup(method_id)

    return key_for


def verify_package(package: dict[str, Any], key_for: Callable[[str], Ed25519PublicKey]) -> dict[str, Any]:
    problems: list[str] = []
    try:
        credential = package["credential"]
        subject = credential["credentialSubject"]
        claimed_root = subject["integrity"]["merkleRoot"]
        root = merkle_root(leaves(subject))
    except (KeyError, TypeError, ValueError) as exc:
        return {"verified": False, "problems": [f"not an evidence package: {type(exc).__name__}: {exc}"]}

    hashes_ok = root == claimed_root
    if not hashes_ok:
        problems.append("the evidence does not match its Merkle root (something was changed)")

    try:
        method = credential["proof"]["verificationMethod"]
        signature_ok = signing.verify(credential, key_for(method))
    except (KeyError, TypeError, ValueError) as exc:
        signature_ok, method = False, None
        problems.append(f"issuer key unavailable: {exc}")
    if not signature_ok and method is not None:
        problems.append("issuer signature is invalid")

    timestamp: dict[str, Any] | None = None
    if token := (subject.get("timestamp") or {}).get("token"):
        check = verify_rfc3161(base64.b64decode(token), bytes.fromhex(claimed_root))
        timestamp = check.as_dict()
        problems.extend(f"timestamp: {p}" for p in check.problems)
    else:
        problems.append("no RFC 3161 timestamp")

    anchor: dict[str, Any] | None = None
    if proof := ((package.get("anchors") or {}).get("openTimestamps") or {}).get("proof"):
        try:
            anchor = ots.inspect(base64.b64decode(proof), bytes.fromhex(claimed_root)).as_dict()
        except binascii.Error:
            anchor = {"valid": False, "status": "invalid", "problems": ["proof is not base64"]}
        problems.extend(f"OpenTimestamps: {p}" for p in anchor["problems"])

    verified = hashes_ok and signature_ok and bool(timestamp and timestamp["valid"])
    return {
        "verified": verified,
        "merkle_root": claimed_root,
        "observations": len(subject.get("observations", [])),
        "issuer": credential.get("issuer"),
        "verification_method": method,
        "signed": signature_ok,
        "hashes": hashes_ok,
        "timestamp": timestamp,
        "open_timestamps": anchor,
        "problems": problems,
    }
