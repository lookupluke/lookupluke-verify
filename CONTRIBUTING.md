# Contributing to lookupluke-verify

## Development setup

```sh
git clone https://github.com/lookupluke/look-up-luke
cd look-up-luke/packages/lookupluke-verify
pip install hatch mypy
hatch run test        # run the test suite
mypy src              # strict typecheck
```

## Adding a feature

1. Add the feature in `src/lookupluke_verify/`
2. Add tests in `tests/`
3. Run `hatch run test && mypy src`
4. Open a PR

## Release process

1. Tag the monorepo: `git tag lookupluke-verify-v1.1.0`
2. Push the tag: `git push origin lookupluke-verify-v1.1.0`
3. CI builds, tests, publishes to PyPI, and syncs the standalone repo

## Code style

- Pure functions where possible
- No external dependencies beyond `cryptography`, `httpx`, `asn1crypto`, `rfc8785`
- Strict mypy compliance
- Every function documented with a docstring