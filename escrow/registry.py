"""Registry check: cheap, first, no sandbox needed. Queries PyPI's JSON
API read-only -- existence, creation date, rough download volume -- as an
early signal, not a verdict. No fuzzy name-similarity-to-popular-package
heuristics here; that's a real future direction, explicitly deferred out
of v0.1.0.

On download volume: PyPI's JSON API has returned a permanently
deprecated placeholder (`-1`) in its `downloads` field for every package
for years -- it was never a live count and isn't wired up here. Rather
than fabricate a number from a second, unrelated service (e.g.
pypistats.org) and its own availability/rate-limit failure modes, this
module always reports `download_estimate=None`. Wiring up a real download
source is future work, not something to fake here.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
DEFAULT_TIMEOUT_S = 10


@dataclass
class RegistryInfo:
    """Result of one registry check.

    When `error` is set, the API could not be reached or returned
    something unparseable -- `exists`/`created`/`download_estimate` are
    meaningless placeholders in that case, not a real signal. Callers must
    check `error` first, precisely so an unreachable API is never silently
    reported as "package does not exist".
    """

    exists: bool
    created: str | None
    download_estimate: int | None
    error: str | None


def check_registry(package: str, timeout: int = DEFAULT_TIMEOUT_S) -> RegistryInfo:
    """Look up `package` on PyPI's JSON API. Never raises: unreachability
    or a malformed response is reported via `RegistryInfo.error` instead."""
    url = PYPI_JSON_URL.format(package=package)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return RegistryInfo(exists=False, created=None, download_estimate=None, error=None)
        return RegistryInfo(
            exists=False, created=None, download_estimate=None,
            error=f"PyPI returned HTTP {exc.code}",
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return RegistryInfo(
            exists=False, created=None, download_estimate=None,
            error=f"PyPI JSON API unreachable: {exc}",
        )

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return RegistryInfo(
            exists=False, created=None, download_estimate=None,
            error=f"PyPI returned unparseable JSON: {exc}",
        )

    releases = data.get("releases", {})
    upload_times = [
        entry.get("upload_time_iso_8601")
        for files in releases.values()
        for entry in files
        if entry.get("upload_time_iso_8601")
    ]
    created = min(upload_times) if upload_times else None

    return RegistryInfo(exists=True, created=created, download_estimate=None, error=None)
