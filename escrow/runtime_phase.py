"""Phase 2: fresh container, import only, full husk hardening (network
off).

After Phase 1 installs a package (with network open), this phase spins up
a completely new container -- husk's normal fully-hardened profile, no
network at all (`Dockerfile.runtime`, via `escrow._container`) -- and
merely `import`s the installed package (no calling into it beyond that).
The same audit-hook watcher observes the same event categories.

Anything the package tries here that needs network will visibly fail,
which is itself informative: it shows the package *wants* network access
post-install, distinct from what it already did during Phase 1 when
network was open. That's why `runtime_events` and `install_events` are
kept separate rather than merged -- Phase 1's log is proof of action
(network was allowed), Phase 2's is proof of intent (network was
blocked).

No host path is ever bind-mounted in here either: the installed files
Phase 1 produced arrive as a base64 tarball embedded directly in this
phase's driver script, decoded and extracted inside the container.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

from . import _container, watcher

_REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = _REPO_ROOT / "Dockerfile.runtime"
DEFAULT_IMAGE = "escrow-runtime:latest"
DEFAULT_TIMEOUT_S = 30


@dataclass
class RuntimePhaseResult:
    exit_code: int | None
    timed_out: bool
    events: list[dict]
    import_succeeded: bool


def ensure_image_built(force: bool = False) -> None:
    _container.ensure_image_built(DEFAULT_IMAGE, DOCKERFILE, DOCKERFILE.parent, force=force)


def _build_driver_script(marker: str, import_name: str, artifact_b64: str) -> str:
    return f'''import base64, io, os, site, sys, tarfile

_MARKER = {marker!r}
_EVENTS_PATH = os.environ.get("ESCROW_EVENTS_PATH", "/tmp/escrow_events.jsonl")
_TARGET_DIR = "/tmp/escrow_import_target"
os.makedirs(_TARGET_DIR, exist_ok=True)

with tarfile.open(fileobj=io.BytesIO(base64.b64decode({artifact_b64!r})), mode="r:gz") as _tf:
    _tf.extractall(_TARGET_DIR, filter="data")

# site.addsitedir(), not a plain sys.path.insert(): pip installed this
# artifact with --target, the same shape as a real site-packages
# directory, and a package can ship a top-level *.pth file whose
# `import ...` lines Python's own site module executes automatically at
# real interpreter startup (the mechanism the real litellm compromise
# used). sys.path.insert() alone makes the package importable but never
# triggers that .pth processing -- only site.addsitedir() (or a directory
# site itself scans at startup) does. addsitedir() also adds _TARGET_DIR
# to sys.path itself, so this replaces the old sys.path.insert() call
# rather than needing both.
site.addsitedir(_TARGET_DIR)

_import_ok = True
try:
    __import__({import_name!r})
except BaseException as _exc:
    _import_ok = False
    print("escrow: import failed: " + repr(_exc), file=sys.stderr)

if os.path.exists(_EVENTS_PATH):
    with open(_EVENTS_PATH) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line:
                print(_MARKER + "EVENT:" + _line, file=sys.stderr, flush=True)

sys.exit(0 if _import_ok else 1)
'''


def run_import(
    artifact: bytes,
    import_name: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> RuntimePhaseResult:
    """Import `import_name` from the installed files in `artifact` (the
    tar.gz `install_phase.run_install` produced) inside a fresh, fully
    network-off, fully hardened container."""
    marker = watcher.generate_marker()
    artifact_b64 = base64.b64encode(artifact).decode("ascii")
    script = _build_driver_script(marker, import_name, artifact_b64)

    raw = _container.run_driver(
        script, image=DEFAULT_IMAGE, dockerfile=DOCKERFILE, timeout=timeout, network=False,
        name_prefix="escrow-runtime",
    )

    real_stderr, event_lines = watcher.split_marked(raw.stderr, marker, "EVENT")
    events = watcher.parse_events(event_lines, real_stderr)

    return RuntimePhaseResult(
        exit_code=raw.exit_code,
        timed_out=raw.timed_out,
        events=events,
        import_succeeded=(not raw.timed_out and raw.exit_code == 0),
    )
