"""Registry-check tests: read-only PyPI JSON API calls only, no installs.
Per the project's safety rule, this is the one place tests may talk to the
real PyPI, since looking up a known, real, benign package's metadata
(`requests`) is a safe read, not an install.

Skipped, not failed, if the real PyPI API is unreachable from this
environment -- that's an environment limitation, not an escrow defect.
"""

import pytest

from escrow.registry import RegistryInfo, check_registry


def _info_or_skip(package: str) -> RegistryInfo:
    info = check_registry(package, timeout=5)
    if info.error is not None:
        pytest.skip(f"PyPI JSON API unreachable: {info.error}")
    return info


def test_known_benign_package_exists():
    info = _info_or_skip("requests")
    assert info.exists is True
    assert info.created is not None
    # PyPI's `downloads` field is a permanently deprecated placeholder --
    # escrow never reports a fabricated number.
    assert info.download_estimate is None


def test_nonexistent_package_does_not_exist():
    info = _info_or_skip("this-package-definitely-does-not-exist-escrow-test-xyz-987654321")
    assert info.exists is False
    assert info.error is None
