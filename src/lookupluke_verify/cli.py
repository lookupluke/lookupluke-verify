"""lookupluke-verify: check a Lookup Luke evidence bundle without trusting Lookup Luke.

    lookupluke-verify bundle.json                 resolve the issuer key via did:web (HTTPS)
    lookupluke-verify bundle.json --did did.json  fully offline, with a saved DID document
    lookupluke-verify bundle.json --bitcoin       also check the OpenTimestamps anchor against Bitcoin blocks
    lookupluke-verify bundle.json --json          print the full result object

Exit codes: 0 verified · 1 not verified (a check failed) · 2 the bundle or DID document couldn't be read.
"""

import argparse
import asyncio
import base64
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx

from lookupluke_verify import BUNDLE_FORMAT, __version__, ots
from lookupluke_verify.verify import key_from_did_document, verify_package

VERIFIED, NOT_VERIFIED, INPUT_ERROR = 0, 1, 2


def resolve_did_web(did: str) -> dict[str, Any]:
    """Fetch https://<host>/.well-known/did.json and check it describes this DID."""
    host = unquote(did.removeprefix("did:web:").split("#")[0].split(":")[0])
    scheme = "http" if host.startswith(("localhost", "127.0.0.1")) else "https"
    response = httpx.get(f"{scheme}://{host}/.well-known/did.json", timeout=15)
    response.raise_for_status()
    document: dict[str, Any] = response.json()
    if document.get("id") != did.split("#")[0]:
        raise ValueError(f"DID document at {host} is for {document.get('id')}, not {did}")
    return document


def _print(result: dict[str, Any], name: str) -> None:
    def mark(ok: bool) -> str:
        return "✓" if ok else "✗"

    timestamp, anchor = result.get("timestamp") or {}, result.get("open_timestamps") or {}
    print(f"{mark(result['verified'])} {'VERIFIED' if result['verified'] else 'NOT VERIFIED'}  {name}")
    root = str(result.get("merkle_root") or "")
    print(f"  {mark(bool(result.get('hashes')))} {result.get('observations')} observations + case hash to Merkle root {root[:16]}…")
    print(f"  {mark(bool(result.get('signed')))} signed by {result.get('issuer')} ({result.get('verification_method')})")
    print(f"  {mark(bool(timestamp.get('valid')))} RFC 3161 time {timestamp.get('time')} · TSA chain {timestamp.get('chain')}")
    if anchor:
        print(f"  {mark(bool(anchor.get('valid')))} OpenTimestamps: {anchor.get('status')} "
              f"{anchor.get('bitcoin_blocks') or anchor.get('calendars')}")
    for height, ok in (result.get("bitcoin") or {}).items():
        print(f"  {mark(ok)} Bitcoin block {height} Merkle root matches the proof")
    for problem in result.get("problems", []):
        print(f"  ! {problem}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lookupluke-verify", description=(__doc__ or "").splitlines()[0])
    parser.add_argument("bundle", type=Path, help="the evidence bundle (.json) as downloaded from Lookup Luke")
    parser.add_argument("--did", type=Path, help="a saved did.json (offline); default: resolve did:web over HTTPS")
    parser.add_argument("--bitcoin", action="store_true", help="check OpenTimestamps attestations against Bitcoin blocks")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--version", action="version",
                        version=f"lookupluke-verify {__version__} (evidence bundle format {BUNDLE_FORMAT})")
    args = parser.parse_args(argv)

    try:
        package = json.loads(args.bundle.read_text())
        issuer = package["credential"]["issuer"]
        document = json.loads(args.did.read_text()) if args.did else resolve_did_web(issuer)
    except (OSError, ValueError, KeyError, TypeError, httpx.HTTPError) as exc:
        print(f"lookupluke-verify: can't read the input: {type(exc).__name__}: {exc}", file=sys.stderr)
        return INPUT_ERROR

    result = verify_package(package, key_from_did_document(document))
    proof = ((package.get("anchors") or {}).get("openTimestamps") or {}).get("proof")
    if args.bitcoin and proof:
        result["bitcoin"] = asyncio.run(ots.bitcoin_confirmations(base64.b64decode(proof)))

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print(result, args.bundle.name)
    return VERIFIED if result["verified"] else NOT_VERIFIED


if __name__ == "__main__":
    raise SystemExit(main())
