"""OpenTimestamps proofs: parse and inspect a detached `.ots` proof, and (online, on request) check its Bitcoin
attestations against block headers. Stamping and upgrading live in Lookup Luke itself, not in this package."""

import hashlib
from dataclasses import dataclass, field
from typing import Any

import httpx

HEADER = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
SHA256_OP = 0x08
PENDING = bytes.fromhex("83dfe30d2ef90c8e")
BITCOIN = bytes.fromhex("0588960d73d71901")


def _varuint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


class _Reader:
    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data, self.pos = data, pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("truncated proof")
        self.pos += 1
        return self.data[self.pos - 1]

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated proof")
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def varuint(self) -> int:
        value, shift = 0, 0
        while True:
            byte = self.byte()
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7

    def varbytes(self) -> bytes:
        return self.take(self.varuint())


@dataclass
class Attestation:
    kind: str  # "pending" | "bitcoin" | "unknown"
    commitment: bytes  # the message the attestation commits to
    detail: str  # calendar URL, or Bitcoin block height
    start: int  # byte span of this attestation item in the proof (for upgrades)
    end: int
    last_item: bool  # whether the item can be replaced by a multi-branch timestamp


@dataclass
class OtsCheck:
    valid: bool
    digest: str | None = None
    status: str = "invalid"  # "bitcoin", "pending", "invalid"
    bitcoin_blocks: list[int] = field(default_factory=list)
    calendars: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "bitcoin_blocks": self.bitcoin_blocks,
                "calendars": self.calendars, "problems": self.problems}


def _apply(tag: int, reader: _Reader, msg: bytes) -> bytes:
    if tag == 0xF0:
        return msg + reader.varbytes()
    if tag == 0xF1:
        return reader.varbytes() + msg
    if tag == 0x08:
        return hashlib.sha256(msg).digest()
    if tag == 0x02:
        return hashlib.sha1(msg).digest()  # noqa: S324 (part of the OTS format, not our choice)
    if tag == 0x03:
        return hashlib.new("ripemd160", msg).digest()
    if tag == 0xF2:
        return msg[::-1]
    raise ValueError(f"unsupported OTS operation 0x{tag:02x}")


def _walk(reader: _Reader, msg: bytes, found: list[Attestation], depth: int = 0) -> None:
    """Timestamp = items; every item but the last is prefixed with 0xff. Item = attestation | op + timestamp."""
    if depth > 256:
        raise ValueError("proof too deep")
    while True:
        start = reader.pos
        tag = reader.byte()
        forked = tag == 0xFF
        if forked:
            start = reader.pos
            tag = reader.byte()
        if tag == 0x00:
            kind_tag, payload = reader.take(8), reader.varbytes()
            if kind_tag == PENDING:
                found.append(Attestation("pending", msg, _Reader(payload).varbytes().decode(), start, reader.pos, not forked))
            elif kind_tag == BITCOIN:
                found.append(Attestation("bitcoin", msg, str(_Reader(payload).varuint()), start, reader.pos, not forked))
            else:
                found.append(Attestation("unknown", msg, kind_tag.hex(), start, reader.pos, not forked))
        else:
            _walk(reader, _apply(tag, reader, msg), found, depth + 1)
        if not forked:
            return


def _parse(proof: bytes) -> tuple[bytes, list[Attestation]]:
    reader = _Reader(proof)
    if reader.take(len(HEADER)) != HEADER or reader.varuint() != 1:
        raise ValueError("not an OpenTimestamps v1 proof")
    if reader.byte() != SHA256_OP:
        raise ValueError("only SHA-256 file hashes are supported")
    digest = reader.take(32)
    found: list[Attestation] = []
    _walk(reader, digest, found)
    if reader.pos != len(proof):
        raise ValueError("trailing bytes after the proof")
    return digest, found


def inspect(proof: bytes, expected_digest: bytes) -> OtsCheck:
    """Replay the proof's operations from the digest. A Bitcoin attestation names the block whose Merkle root the
    final commitment must equal; check that block with `ots verify` or any block explorer."""
    try:
        digest, attestations = _parse(proof)
    except ValueError as exc:
        return OtsCheck(False, problems=[str(exc)])
    check = OtsCheck(digest == expected_digest, digest=digest.hex())
    if not check.valid:
        check.problems.append("proof is for a different hash")
        return check
    check.bitcoin_blocks = sorted(int(a.detail) for a in attestations if a.kind == "bitcoin")
    check.calendars = sorted({a.detail for a in attestations if a.kind == "pending"})
    check.status = "bitcoin" if check.bitcoin_blocks else "pending" if check.calendars else "invalid"
    if check.status == "invalid":
        check.valid = False
        check.problems.append("proof has no attestations")
    return check


async def bitcoin_confirmations(proof: bytes, esplora: str = "https://blockstream.info/api") -> dict[int, bool]:
    """Online check: does each attested block's Merkle root equal the proof's commitment? {height: matches}."""
    _, attestations = _parse(proof)
    results: dict[int, bool] = {}
    async with httpx.AsyncClient(timeout=15.0) as client:
        for attestation in (a for a in attestations if a.kind == "bitcoin"):
            height = int(attestation.detail)
            block_hash = (await client.get(f"{esplora}/block-height/{height}")).text.strip()
            merkle_root = (await client.get(f"{esplora}/block/{block_hash}")).json()["merkle_root"]
            results[height] = merkle_root == attestation.commitment[::-1].hex()  # block explorers show it reversed
    return results
