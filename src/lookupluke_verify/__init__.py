"""Verify Lookup Luke evidence bundles without trusting Lookup Luke.

    from lookupluke_verify import verify_package, key_from_did_document
    result = verify_package(bundle, key_from_did_document(did_document))
    result["verified"]  # True only if every check passed
"""

__version__ = "1.0.0"
BUNDLE_FORMAT = "1"  # the evidence bundle format this release checks

from lookupluke_verify.verify import key_from_did_document, key_from_did_documents, verify_package  # noqa: E402

__all__ = ["BUNDLE_FORMAT", "__version__", "key_from_did_document", "key_from_did_documents", "verify_package"]
