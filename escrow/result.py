"""The structured report every vetting run returns."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VettingReport:
    """`install_events` and `runtime_events` are kept as two separate
    lists deliberately, never merged: `install_events` is what actually
    happened during Phase 1, where network was allowed; `runtime_events`
    is what was attempted and blocked during Phase 2, where it wasn't.
    Collapsing them into one list would misrepresent which is proof of
    action and which is proof of intent -- see install_phase.py /
    runtime_phase.py and the README for why that distinction matters.

    `registry_error` is set (and `registry_exists` /
    `registry_created` / `registry_download_estimate` are meaningless
    placeholders) when the PyPI JSON API itself could not be reached --
    see `registry.py`.

    `runtime_exit_code` and `runtime_events` are left at their defaults
    (`None` / `[]`) when Phase 2 never ran -- i.e. Phase 1 itself failed
    (`install_exit_code != 0`), so there was nothing installed to import.
    """

    package: str
    version: str | None
    registry_exists: bool
    registry_created: str | None
    registry_download_estimate: int | None
    registry_error: str | None
    install_events: list[dict]
    runtime_events: list[dict]
    install_exit_code: int | None
    runtime_exit_code: int | None = None
