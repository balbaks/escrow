"""Phase 1 detection: prove the malicious_install_hook fixture's setup.py
file-write-outside-/tmp is observed as an event during install, and that a
benign fixture produces a clean report. Every install in this file uses a
local fixture directory via `local_source` -- never the live PyPI -- per
the project's own safety rule.

Requires local Docker socket access. If Docker isn't available, these
tests are skipped rather than failed, since that's an environment
limitation, not an escrow defect.
"""

from pathlib import Path

import pytest

from escrow import install_phase
from escrow._container import DockerUnavailableError

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def sandbox_image():
    try:
        install_phase.ensure_image_built()
    except DockerUnavailableError as exc:
        pytest.skip(f"Docker not available: {exc}")


def test_benign_install_is_clean():
    result = install_phase.run_install(
        "benign-package", local_source=FIXTURES_DIR / "benign_package", timeout=120,
    )

    assert not result.timed_out
    assert result.exit_code == 0
    assert result.artifact is not None
    assert result.import_name == "benign_package"

    # The driver's own act of invoking pip is expected and must not be
    # mistaken for something the package did -- see Dockerfile.install's
    # `-S` flag and escrow/sandbox_hook.py for why it isn't observed.
    # Nothing the package itself did should be observed either.
    suspicious = [e for e in result.events if e["type"] in ("fs_write", "network", "opaque_escape_hatch")]
    assert suspicious == [], f"benign fixture produced unexpected events: {suspicious}"


def test_malicious_install_hook_fs_write_is_observed():
    result = install_phase.run_install(
        "malicious-install-hook", local_source=FIXTURES_DIR / "malicious_install_hook", timeout=120,
    )

    fs_events = [e for e in result.events if e["type"] == "fs_write"]
    assert fs_events, f"expected at least one fs_write event, got: {result.events}"
    assert any("escrow_test_pwned" in e["detail"] for e in fs_events)

    # Phase 1 keeps read-only rootfs (only network differs from husk's
    # default) -- a write outside /tmp is still expected to be blocked by
    # that, even though network was open.
    assert any(e["blocked"] for e in fs_events)
