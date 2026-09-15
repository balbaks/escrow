"""Phase 1: install, network allowed, fully observed.

Real `pip install` can execute arbitrary code at install time via
`setup.py` / PEP 517 build hooks -- a common real attack vector, arguably
more common than import-time payloads. Installing requires network
access, which conflicts with husk's default no-network hardening. So this
phase uses its own sandbox variant (`Dockerfile.install`, via
`escrow._container`): husk's other hardening flags stay on (non-root,
dropped caps, read-only rootfs with only /tmp writable, resource limits,
`--rm`) but network is allowed, specifically so the install can complete.

**The wall**: because network is open here, anything malicious that
completes fast enough during the install window -- e.g. exfiltrating
environment variables before this function even returns -- cannot be
prevented in real time. This function can only detect and report it after
the fact, never guarantee it never happened. See the README for why this
is a fundamental limit of vetting something that requires network access
to install at all, not a bug to engineer around in v0.1.0.

Test fixtures are installed via `local_source` -- a local directory pip
can build from a path, `--no-index`, so no network is touched. Real
installs pass `package`/`version` and no `local_source`, hitting the real
index the way an actual `pip install` would.
"""

from __future__ import annotations

import base64
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path

from . import _container, watcher

_REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = _REPO_ROOT / "Dockerfile.install"
DEFAULT_IMAGE = "escrow-install:latest"
DEFAULT_TIMEOUT_S = 180


@dataclass
class InstallPhaseResult:
    exit_code: int | None
    timed_out: bool
    events: list[dict]
    artifact: bytes | None  # tar.gz of the installed files, for Phase 2
    import_name: str | None  # inferred top-level module name to import


def ensure_image_built(force: bool = False) -> None:
    _container.ensure_image_built(DEFAULT_IMAGE, DOCKERFILE, DOCKERFILE.parent, force=force)


def _tar_directory_b64(path: Path) -> str:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(path, arcname=".")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _infer_import_name(artifact: bytes, fallback: str) -> str:
    """Read `top_level.txt` out of the installed distribution's
    dist-info/egg-info, rather than guessing the import name from the
    pip/PyPI package name -- the two often differ (e.g. `scikit-learn` /
    `sklearn`). Falls back to a normalized version of `fallback` if that
    metadata isn't present."""
    try:
        with tarfile.open(fileobj=io.BytesIO(artifact), mode="r:gz") as tf:
            for member in tf.getmembers():
                if member.name.endswith((".dist-info/top_level.txt", ".egg-info/top_level.txt")):
                    extracted = tf.extractfile(member)
                    if extracted is not None:
                        names = extracted.read().decode().split()
                        if names:
                            return names[0]
    except Exception:
        pass
    return fallback.replace("-", "_")


def _build_driver_script(
    marker: str,
    *,
    package: str,
    version: str | None,
    local_source_b64: str | None,
) -> str:
    if local_source_b64 is not None:
        setup_lines = f'''_fixture_dir = "/tmp/escrow_fixture_src"
os.makedirs(_fixture_dir, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(base64.b64decode({local_source_b64!r})), mode="r:gz") as _tf_in:
    _tf_in.extractall(_fixture_dir, filter="data")
_pip_args = ["--no-index", _fixture_dir]'''
    else:
        spec = package if not version else f"{package}=={version}"
        setup_lines = f"_pip_args = [{spec!r}]"

    return f'''import base64, io, os, subprocess, sys, tarfile

_MARKER = {marker!r}
_EVENTS_PATH = os.environ.get("ESCROW_EVENTS_PATH", "/tmp/escrow_events.jsonl")
_TARGET_DIR = "/tmp/escrow_install_target"
os.makedirs(_TARGET_DIR, exist_ok=True)

{setup_lines}

# --verbose: pip normally captures each build step's own subprocess
# output internally and only surfaces it on failure -- so a write that a
# malicious setup.py itself catches and ignores (its own build step still
# "succeeds") would otherwise never reach real stderr, and escrow's
# blocked-attribution (which greps real stderr for the sandbox's own
# rejection message) would silently miss it.
_cmd = [sys.executable, "-m", "pip", "install", "--verbose", "--no-build-isolation",
        "--target", _TARGET_DIR] + _pip_args
_proc = subprocess.run(_cmd)
_exit_code = _proc.returncode

if os.path.exists(_EVENTS_PATH):
    with open(_EVENTS_PATH) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line:
                print(_MARKER + "EVENT:" + _line, file=sys.stderr, flush=True)

_buf = io.BytesIO()
with tarfile.open(fileobj=_buf, mode="w:gz") as _tf_out:
    _tf_out.add(_TARGET_DIR, arcname=".")
_artifact_b64 = base64.b64encode(_buf.getvalue()).decode("ascii")
print(_MARKER + "ARTIFACT:" + _artifact_b64, flush=True)

sys.exit(_exit_code)
'''


def run_install(
    package: str,
    version: str | None = None,
    *,
    local_source: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
    docker_network: str | None = None,
    docker_dns: str | None = None,
) -> InstallPhaseResult:
    """Install `package` (or, for tests, the local fixture directory at
    `local_source`) inside Phase 1's sandbox, and report exit code, every
    observed behavior event, the tar.gz'd installed files, and the
    inferred import name -- all needed to hand off to `runtime_phase.run_import`.

    `docker_network`/`docker_dns` default to `None` and leave normal
    behavior (real internet, Docker's default bridge) untouched -- see
    `_container.run_driver` for what they're for.
    """
    marker = watcher.generate_marker()
    local_source_b64 = _tar_directory_b64(local_source) if local_source is not None else None
    script = _build_driver_script(
        marker, package=package, version=version, local_source_b64=local_source_b64,
    )

    raw = _container.run_driver(
        script, image=DEFAULT_IMAGE, dockerfile=DOCKERFILE, timeout=timeout, network=True,
        docker_network=docker_network, docker_dns=docker_dns,
        name_prefix="escrow-install",
    )

    real_stdout, artifact_lines = watcher.split_marked(raw.stdout, marker, "ARTIFACT")
    real_stderr, event_lines = watcher.split_marked(raw.stderr, marker, "EVENT")
    events = watcher.parse_events(event_lines, real_stderr)

    artifact = base64.b64decode(artifact_lines[0]) if artifact_lines else None
    import_name = _infer_import_name(artifact, package) if artifact else None

    return InstallPhaseResult(
        exit_code=raw.exit_code,
        timed_out=raw.timed_out,
        events=events,
        artifact=artifact,
        import_name=import_name,
    )
