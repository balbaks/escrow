"""Phase 2 detection: prove the malicious_import_hook fixture's network
attempt on import is observed, and that it shows as *blocked* -- unlike
how a network event would look in Phase 1, where network is open. Also
proves a benign fixture's import is clean.

Each test installs its fixture via Phase 1 first (local source, never the
live PyPI) to get a real installed-files artifact, then hands that
artifact to Phase 2 -- exercising the exact handoff `core.vet()` performs.

Requires local Docker socket access. If Docker isn't available, these
tests are skipped rather than failed, since that's an environment
limitation, not an escrow defect.
"""

from pathlib import Path

import pytest

from escrow import install_phase, runtime_phase
from escrow._container import DockerUnavailableError

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def sandbox_images():
    try:
        install_phase.ensure_image_built()
        runtime_phase.ensure_image_built()
    except DockerUnavailableError as exc:
        pytest.skip(f"Docker not available: {exc}")


def _install(fixture_name: str, package_name: str):
    result = install_phase.run_install(
        package_name, local_source=FIXTURES_DIR / fixture_name, timeout=120,
    )
    assert result.exit_code == 0, f"fixture install failed: {result.events}"
    assert result.artifact is not None
    return result


def test_benign_import_is_clean():
    installed = _install("benign_package", "benign-package")

    result = runtime_phase.run_import(installed.artifact, installed.import_name, timeout=20)

    assert not result.timed_out
    assert result.import_succeeded
    assert result.events == []


def test_malicious_import_hook_network_attempt_is_observed_and_blocked():
    installed = _install("malicious_import_hook", "malicious-import-hook")
    assert installed.import_name == "malicious_import_hook"

    result = runtime_phase.run_import(installed.artifact, installed.import_name, timeout=20)

    assert not result.timed_out
    # The fixture catches the connection failure itself, so the import
    # completes either way -- what matters is that the attempt was seen.
    assert result.import_succeeded

    network_events = [e for e in result.events if e["type"] == "network"]
    assert network_events, f"expected at least one network event, got: {result.events}"
    assert any("203.0.113.10" in e["detail"] for e in network_events)

    # Phase 2 has network off entirely -- contrast with Phase 1, where the
    # same kind of event would show blocked=False because network is open
    # there. This is the distinction the two-phase report exists to draw.
    assert all(e["blocked"] for e in network_events)


def test_pth_triggered_action_is_observed_in_phase_2():
    """Regression test for the .pth blind spot MALWARE_EVALUATION.md
    documented against the real litellm compromise: a package that ships a
    top-level `.pth` file (outside the package directory entirely, e.g.
    via `data_files=[("", [...])]`) whose `import`-prefixed line Python's
    own site module auto-executes at interpreter startup -- independent of
    whether the package next to it is ever imported.

    `pth_trigger` models that *mechanism* with a harmless marker action (a
    connection attempt to the same RFC 5737 TEST-NET-3 address
    `malicious_import_hook` already uses), not any real payload. Before
    the fix (runtime_phase.py's `sys.path.insert()` -> `site.addsitedir()`
    change), this reported zero events for this fixture -- confirmed by
    temporarily reverting the fix and re-running this exact check.
    """
    installed = _install("pth_trigger", "pth-trigger")
    assert installed.import_name == "pth_trigger"

    result = runtime_phase.run_import(installed.artifact, installed.import_name, timeout=20)

    assert not result.timed_out
    assert result.import_succeeded

    network_events = [e for e in result.events if e["type"] == "network"]
    assert network_events, (
        "expected the .pth file's network attempt to be observed, got: "
        f"{result.events}"
    )
    assert any("203.0.113.10" in e["detail"] for e in network_events)
    assert all(e["blocked"] for e in network_events)
