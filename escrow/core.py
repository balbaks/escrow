"""The one public entrypoint: `vet()`.

Runs the registry check, then Phase 1 (install, network allowed, fully
observed), then Phase 2 (fresh container, import only, network off),
combining all three into one `VettingReport` with the two phases' event
lists kept distinct. See install_phase.py and runtime_phase.py for why
that separation matters, and the README for the wall this whole approach
runs into: Phase 1 needs network to install for real, so anything
malicious that completes fast enough during that window can be detected
here but not prevented.
"""

from __future__ import annotations

from pathlib import Path

from . import install_phase, registry, runtime_phase
from .result import VettingReport


def vet(
    package: str,
    version: str | None = None,
    *,
    local_source: Path | None = None,
    install_timeout: int = install_phase.DEFAULT_TIMEOUT_S,
    runtime_timeout: int = runtime_phase.DEFAULT_TIMEOUT_S,
) -> VettingReport:
    """Vet `package` (optionally pinned to `version`) before it's ever
    installed for real: check its PyPI registry footprint, then actually
    install it (network allowed, Phase 1) and import it (network off,
    fresh container, Phase 2) inside a sandbox, reporting what happened.

    `local_source` is for tests only -- a local directory pip can install
    from directly, bypassing the real PyPI entirely (see
    `install_phase.run_install`). Real callers never need it.

    Never raises on account of what the vetted package itself did. Can
    raise if Docker itself is unavailable or a sandbox image fails to
    build (`escrow._container.DockerUnavailableError`, `ImageBuildError`).
    """
    reg = registry.check_registry(package)

    install_result = install_phase.run_install(
        package, version, local_source=local_source, timeout=install_timeout,
    )

    runtime_events: list[dict] = []
    runtime_exit_code: int | None = None
    if (
        install_result.exit_code == 0
        and install_result.artifact is not None
        and install_result.import_name is not None
    ):
        runtime_result = runtime_phase.run_import(
            install_result.artifact, install_result.import_name, timeout=runtime_timeout,
        )
        runtime_events = runtime_result.events
        runtime_exit_code = runtime_result.exit_code

    return VettingReport(
        package=package,
        version=version,
        registry_exists=reg.exists,
        registry_created=reg.created,
        registry_download_estimate=reg.download_estimate,
        registry_error=reg.error,
        install_events=install_result.events,
        runtime_events=runtime_events,
        install_exit_code=install_result.exit_code,
        runtime_exit_code=runtime_exit_code,
    )
