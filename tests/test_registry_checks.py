"""Registry-check tests: read-only PyPI JSON API calls only, no installs.
Per the project's safety rule, this is the one place tests may talk to the
real PyPI, since looking up a known, real, benign package's metadata
(`requests`) is a safe read, not an install.

Skipped, not failed, if the real PyPI API is unreachable from this
environment -- that's an environment limitation, not an escrow defect.
"""

import urllib.error
from unittest.mock import patch

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
    """A real 404 from PyPI is a confident negative: `exists=False`,
    `error=None`. Contrast with the mocked-failure tests below, where the
    check itself couldn't be completed -- that must never collapse to the
    same `exists=False` this test asserts."""
    info = _info_or_skip("this-package-definitely-does-not-exist-escrow-test-xyz-987654321")
    assert info.exists is False
    assert info.error is None


# The tests below mock the HTTP layer rather than relying on the real API
# actually being down, so they're deterministic -- and they exist
# precisely to prove that an unreachable/erroring registry produces a
# state distinct from `test_nonexistent_package_does_not_exist` above. A
# transient network failure must never be reported as though it were a
# confident "this package does not exist"; that ambiguity would defeat
# the one signal this tool exists to give cleanly.


def test_unreachable_registry_is_not_reported_as_nonexistent():
    with patch(
        "escrow.registry.urllib.request.urlopen",
        side_effect=urllib.error.URLError("mocked: network unreachable"),
    ):
        info = check_registry("whatever-package", timeout=5)

    assert info.exists is None
    assert info.error is not None
    assert "unreachable" in info.error.lower()
    assert info.created is None
    assert info.download_estimate is None


def test_timeout_is_not_reported_as_nonexistent():
    with patch("escrow.registry.urllib.request.urlopen", side_effect=TimeoutError("mocked timeout")):
        info = check_registry("whatever-package", timeout=5)

    assert info.exists is None
    assert info.error is not None


def test_pypi_5xx_is_not_reported_as_nonexistent():
    with patch(
        "escrow.registry.urllib.request.urlopen",
        side_effect=urllib.error.HTTPError("https://pypi.org/pypi/x/json", 503, "Service Unavailable", {}, None),
    ):
        info = check_registry("whatever-package", timeout=5)

    assert info.exists is None
    assert info.error is not None
    assert "503" in info.error


def test_unparseable_response_is_not_reported_as_nonexistent():
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def read(self):
            return b"not valid json"

    with patch("escrow.registry.urllib.request.urlopen", return_value=_FakeResponse()):
        info = check_registry("whatever-package", timeout=5)

    assert info.exists is None
    assert info.error is not None
