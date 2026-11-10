# lookupluke-verify changelog

## 1.1.0 (2026-11-10)

- First PyPI release
- Example bundles in `examples/` (valid + 4 tampered cases)
- `--format json` output for programmatic consumers
- `[tests]` extra: `pip install lookupluke-verify[tests]`
- PyPI trusted publisher CI workflow
- Standalone repo sync to github.com/lookupluke/lookupluke-verify

## 1.0.0 (2026-11-04)

- Initial release
- Merkle root integrity check (RFC 8785 canonical JSON, SHA-256)
- Ed25519 signature verification (Data Integrity `eddsa-jcs-2022`)
- RFC 3161 timestamp verification with TSA chain trust
- OpenTimestamps proof verification
- CLI tool: `lookupluke-verify bundle.json`
- Python library: `lookupluke_verify.verify_package()`
- No network calls unless asked (--did, --bitcoin)