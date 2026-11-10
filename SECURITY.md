# Security

## Key compromise

If you believe Lookup Luke's evidence signing key has been compromised:

1. **Do not open a public GitHub issue.**
2. Email `security@lookupluke.com` with:
   - Subject: "Evidence key compromise"
   - The bundle ID or DID document you are concerned about
   - Your contact information

We will:
- Rotate the key and issue a new `did:web` document immediately
- Publish a revocation on the old key
- Notify affected users (those who have issued bundles under the old key)

## Reporting a vulnerability

For vulnerabilities in `lookupluke-verify`:

1. Email `security@lookupluke.com` with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact

2. You can expect a response within 48 hours.

3. We will coordinate a fix and publish it under the coordinated disclosure process.

## Dependency CVEs

We monitor dependencies through GitHub Dependabot. Critical CVEs are patched within
7 days of a fix being available.

## Supply chain

- Builds are reproducible: `hatch build` produces the same wheel from the same commit.
- All dependencies are pinned with minimum versions in `pyproject.toml`.
- PyPI publishes use trusted publishing (OpenID Connect) — no stored tokens.
- Releases are signed with the GitHub Release signing key.