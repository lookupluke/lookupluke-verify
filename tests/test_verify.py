"""lookupluke-verify against saved fixtures: no network, no Lookup Luke, no database.

The fixtures come from a real bundle issued by Lookup Luke's code (api/tests/test_verify_package.py writes them),
signed with a published fixture key and timestamped by a throwaway TSA whose root is `tsa-root.pem`.
"""

import base64
import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from lookupluke_verify import BUNDLE_FORMAT, __version__, key_from_did_document, verify_package
from lookupluke_verify.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / name).read_text())
    return data


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Trust the fixture TSA, and fail loudly if anything reaches for the network."""
    monkeypatch.setenv("TSA_TRUSTED_ROOTS", str(FIXTURES / "tsa-root.pem"))

    def no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("lookupluke-verify used the network in an offline test")

    monkeypatch.setattr(httpx, "get", no_network)
    monkeypatch.setattr(httpx.AsyncClient, "send", no_network)
    yield


def check(bundle: dict[str, Any], did: str = "did.json") -> dict[str, Any]:
    return verify_package(bundle, key_from_did_document(load(did)))


def test_a_genuine_bundle_verifies() -> None:
    result = check(load("bundle.json"))
    assert result["verified"] and result["hashes"] and result["signed"] and not result["problems"]
    assert result["timestamp"]["valid"] and result["timestamp"]["chain"] == "trusted"
    assert result["issuer"] == "did:web:fixtures.lookupluke.test"


def test_one_changed_observation_breaks_the_merkle_root() -> None:
    result = check(load("tampered.json"))
    assert not result["verified"] and not result["hashes"]
    assert any("Merkle root" in problem for problem in result["problems"])


def test_another_key_does_not_verify_the_signature() -> None:
    result = check(load("bundle.json"), did="wrong-did.json")
    assert not result["verified"] and not result["signed"] and result["hashes"]


def test_a_broken_timestamp_fails_on_its_own_and_hides_nothing() -> None:
    bundle = load("bundle.json")
    token = bytearray(base64.b64decode(bundle["credential"]["credentialSubject"]["timestamp"]["token"]))
    token[-40] ^= 0xFF  # inside the TSA's signature
    bundle["credential"]["credentialSubject"]["timestamp"]["token"] = base64.b64encode(bytes(token)).decode()
    result = check(bundle)
    assert not result["verified"] and not result["timestamp"]["valid"]
    assert result["hashes"]  # the evidence itself is still reported intact
    assert any(problem.startswith("timestamp:") for problem in result["problems"])


def test_a_broken_open_timestamps_proof_is_reported_separately() -> None:
    bundle = copy.deepcopy(load("bundle.json"))
    bundle["anchors"]["openTimestamps"]["proof"] = base64.b64encode(b"not an ots proof").decode()
    result = check(bundle)
    assert result["hashes"] and result["signed"] and result["timestamp"]["valid"]
    assert not result["open_timestamps"]["valid"]
    assert any("OpenTimestamps" in problem or "opentimestamps" in problem.lower() for problem in result["problems"])


def test_cli_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    did = str(FIXTURES / "did.json")
    assert main([str(FIXTURES / "bundle.json"), "--did", did]) == 0
    assert "✓ VERIFIED" in capsys.readouterr().out
    assert main([str(FIXTURES / "tampered.json"), "--did", did]) == 1
    assert "NOT VERIFIED" in capsys.readouterr().out
    assert main([str(FIXTURES / "missing.json"), "--did", did]) == 2
    assert main([str(FIXTURES / "tsa-root.pem"), "--did", did]) == 2  # not JSON
    assert "can't read the input" in capsys.readouterr().err


def test_cli_json_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(FIXTURES / "bundle.json"), "--did", str(FIXTURES / "did.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True
    with pytest.raises(SystemExit) as version:
        main(["--version"])
    assert version.value.code == 0
    assert f"{__version__} (evidence bundle format {BUNDLE_FORMAT})" in capsys.readouterr().out
