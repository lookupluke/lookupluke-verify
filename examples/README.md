# Example evidence bundles for lookupluke-verify

This directory contains example bundles to test `lookupluke-verify` installation and
to demonstrate the verification process.

## Valid bundle

```sh
lookupluke-verify examples/valid/bundle.json
```

Expected output:
```
✓ VERIFIED  examples/valid/bundle.json
  ✓ 10 observations + case hash to Merkle root 3f9a1c…
  ✓ signed by did:web:app.lookupluke.com
  ✓ RFC 3161 timestamp with trusted TSA chain
  ✓ OpenTimestamps: bitcoin [921874]
```

## Tampered bundles

Each tampered bundle produces a different verification error:

| File | What's wrong | Expected error |
|------|-------------|----------------|
| `tampered/altered-content.json` | A finding value was changed after signing | `integrity check failed` |
| `tampered/wrong-signature.json` | The Ed25519 signature doesn't match | `signature verification failed` |
| `tampered/wrong-issuer.json` | The DID document doesn't match the issuer | `issuer mismatch` |
| `tampered/altered-timestamp.json` | The RFC 3161 timestamp token was modified | `timestamp verification failed` |

```sh
lookupluke-verify examples/tampered/altered-content.json
# → NOT VERIFIED: integrity check failed
```

## Using with --did

To verify without network access:

```sh
lookupluke-verify --did examples/valid/did.json examples/valid/bundle.json
```