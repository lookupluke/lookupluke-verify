# lookupluke-verify

Check a [Lookup Luke](https://lookupluke.com) evidence bundle **without trusting Lookup Luke**.

A Lookup Luke case can be exported as a signed evidence bundle: every observation the investigation collected, the
verdict and the reasons behind it, sealed so that anyone can later prove the bundle is exactly what was issued, and
when. This tool performs that proof on your own machine.

## Install and run

```sh
pipx install lookupluke-verify
# Or: pip install lookupluke-verify
lookupluke-verify bundle.json
```

```
✓ VERIFIED  bundle.json
  ✓ 10 observations + case hash to Merkle root 3f9a1c…
  ✓ signed by did:web:app.lookupluke.com (did:web:app.lookupluke.com#key-1)
  ✓ RFC 3161 time 2026-11-06T09:41:12+00:00 · TSA chain trusted
  ✓ OpenTimestamps: bitcoin [921874]
```

| Option | What it does |
| --- | --- |
| `--did did.json` | Verify fully offline with a saved DID document instead of fetching it over HTTPS |
| `--bitcoin` | Also check the OpenTimestamps attestation against Bitcoin block headers (network) |
| `--json` | Print the full result object |
| `--version` | The tool version and the bundle format it checks |

Exit codes: `0` verified, `1` not verified (a check failed; the output says which), `2` the bundle or DID document
couldn't be read.

## What it checks

1. **Integrity.** Every observation and the case record are hashed (RFC 8785 canonical JSON, SHA-256) into a Merkle
   tree; the root must equal the one in the credential. Change one character anywhere and this fails.
2. **Issuer.** The credential is a W3C Verifiable Credential with a Data Integrity proof (`eddsa-jcs-2022`, Ed25519).
   The key comes from the issuer's `did:web` document, fetched from the issuer's own domain or given with `--did`.
3. **Time.** An RFC 3161 timestamp from an independent timestamp authority over the Merkle root, with the authority's
   certificate chain checked against standard trust roots (add your own with `TSA_TRUSTED_ROOTS=roots.pem`).
4. **Public anchor.** An OpenTimestamps proof over the same root: pending until a Bitcoin block includes it, then
   checkable by anyone, including with the reference `ots` client.

## What it does not prove

The signature proves that Lookup Luke issued this bundle and that nothing in it changed since. It does **not** prove
that a finding is true: sources can be wrong, and a risk score is an indicator, not proof. Read the bundle's
limitations section and verify independently before acting.

## Use it as a library

```python
from lookupluke_verify import verify_package, key_from_did_document

result = verify_package(bundle, key_from_did_document(did_document))
assert result["verified"], result["problems"]
```

Lookup Luke's own API (`POST /api/v1/evidence/verify`) runs this same code, so the two always agree.

No telemetry. The only network calls are the ones you ask for: fetching a `did:web` document (unless you pass
`--did`) and, with `--bitcoin`, reading Bitcoin block headers.

## Licence

Apache-2.0.
