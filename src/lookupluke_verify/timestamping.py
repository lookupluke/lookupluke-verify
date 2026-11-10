"""RFC 3161 trusted timestamps, verified offline: token signature, message imprint and the TSA's certificate chain.

Trust roots are the standard ones (certifi), plus a PEM file named by TSA_TRUSTED_ROOTS (for example FreeTSA's root).
"""

import hashlib
import os
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import certifi
from asn1crypto import cms, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

_HASHES: dict[str, type[hashes.HashAlgorithm]] = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


@dataclass
class TimestampCheck:
    valid: bool  # imprint matches and the token's signature verifies
    gen_time: datetime | None = None
    tsa: str | None = None
    chain: str = "not checked"  # "trusted", "untrusted", "not checked"
    problems: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "time": self.gen_time.isoformat() if self.gen_time else None, "tsa": self.tsa,
                "chain": self.chain, "problems": self.problems}


def trusted_roots() -> list[x509.Certificate]:
    """Standard roots (certifi) plus TSA_TRUSTED_ROOTS (a PEM file), e.g. for FreeTSA's own root."""
    pem = Path(certifi.where()).read_bytes()
    if extra := os.getenv("TSA_TRUSTED_ROOTS"):
        pem += b"\n" + Path(extra).read_bytes()
    # One at a time: a single malformed root (some bundles carry one) must not take down every chain check.
    roots = []
    end = b"-----END CERTIFICATE-----"
    for block in pem.split(end)[:-1]:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                roots.append(x509.load_pem_x509_certificate(block + end))
        except ValueError:
            continue
    return roots


def _verify_signed_by(cert: x509.Certificate, signature: bytes, data: bytes, digest: str, algorithm: str) -> None:
    key = cert.public_key()
    hash_algorithm = _HASHES[digest]()
    if isinstance(key, rsa.RSAPublicKey):
        if algorithm == "rsassa_pss":
            key.verify(signature, data, padding.PSS(padding.MGF1(hash_algorithm), padding.PSS.AUTO), hash_algorithm)
        else:
            key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, data, ec.ECDSA(hash_algorithm))
    else:
        raise InvalidSignature("unsupported TSA key type")


def verify_rfc3161(token_der: bytes, digest: bytes, roots: list[x509.Certificate] | None = None) -> TimestampCheck:
    try:
        token = cms.ContentInfo.load(token_der)
        signed = token["content"]
        content = signed["encap_content_info"]["content"]
        info = content.parsed
    except (ValueError, KeyError, TypeError) as exc:
        return TimestampCheck(False, problems=[f"unreadable token: {exc}"])

    check = TimestampCheck(False, gen_time=info["gen_time"].native)
    if info["message_imprint"]["hashed_message"].native != digest:
        check.problems.append("timestamp is for a different hash")
        return check

    signer = signed["signer_infos"][0]
    digest_name = signer["digest_algorithm"]["algorithm"].native
    if digest_name not in _HASHES:
        check.problems.append(f"unsupported digest {digest_name}")
        return check
    attrs = {attr["type"].native: attr["values"][0] for attr in signer["signed_attrs"]}
    if attrs.get("message_digest") is None or attrs["message_digest"].native != hashlib.new(digest_name, content.contents).digest():
        check.problems.append("signed attributes don't match the timestamp content")
        return check

    certificates = [x509.load_der_x509_certificate(c.chosen.dump()) for c in (signed["certificates"] or [])]
    sid = signer["sid"]
    if sid.name == "issuer_and_serial_number":
        serial = sid.chosen["serial_number"].native
        candidates = [c for c in certificates if c.serial_number == serial]
    else:
        key_id = sid.chosen.native
        candidates = [c for c in certificates if _ski(c) == key_id]
    if not candidates:
        check.problems.append("TSA certificate not included in the token")
        return check
    tsa_cert = candidates[0]
    check.tsa = tsa_cert.subject.rfc4514_string()
    signed_attrs = b"\x31" + signer["signed_attrs"].dump()[1:]  # signature covers the attributes as a SET
    try:
        _verify_signed_by(tsa_cert, signer["signature"].native, signed_attrs, digest_name,
                          signer["signature_algorithm"].signature_algo)
    except (InvalidSignature, ValueError) as exc:
        check.problems.append(f"TSA signature invalid: {exc or type(exc).__name__}")
        return check
    check.valid = True
    check.chain = _chain(tsa_cert, certificates, roots if roots is not None else trusted_roots())
    if check.chain != "trusted":
        check.problems.append("TSA certificate does not chain to a trusted root (add it via TSA_TRUSTED_ROOTS)")
    return check


def _ski(cert: x509.Certificate) -> bytes | None:
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        return None


def _chain(leaf: x509.Certificate, intermediates: list[x509.Certificate], roots: list[x509.Certificate]) -> str:
    # Roots first: tokens often carry a cross-signed copy of a root (same subject, different issuer).
    current, pool = leaf, roots + intermediates
    root_fingerprints = {r.fingerprint(hashes.SHA256()) for r in roots}
    for _ in range(6):
        if current.fingerprint(hashes.SHA256()) in root_fingerprints:
            return "trusted"
        issuer = next((c for c in pool if c.subject == current.issuer and c is not current and _issued(current, c)), None)
        if issuer is None:
            return "untrusted"
        current = issuer
    return "untrusted"


def _issued(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
