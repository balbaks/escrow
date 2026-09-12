"""Shared container orchestration for escrow's two sandbox phases.

Copied from husk/witness's docker_runner.py pattern -- build-the-image-if-
needed, run one script over stdin in an ephemeral container, enforce a
host-side wall-clock timeout, always remove the container -- and
generalized so install_phase.py and runtime_phase.py (which differ only in
which image/Dockerfile they use and whether network is allowed) don't each
re-derive it. Nothing here changes husk's hardening; the only new
parameter is `network`, since Phase 1 needs it allowed and Phase 2 needs
it off, unlike husk which is always off.

The script is streamed to the container over stdin (`python3 -`), never
bind-mounted in as a file -- no host path is ever made visible inside the
container, same as husk/witness.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MEMORY = "256m"
DEFAULT_CPUS = "1.0"
DEFAULT_PIDS_LIMIT = 64
# Larger than husk/witness's 64m default: this tmpfs also has to hold
# whatever an actual `pip install` unpacks and builds, not just a small
# script's own scratch space.
DEFAULT_TMPFS_SIZE = "256m"

_KILL_GRACE_S = 10


class DockerUnavailableError(RuntimeError):
    """Raised when the `docker` CLI or daemon isn't usable."""


class ImageBuildError(RuntimeError):
    """Raised when building a sandbox image fails."""


@dataclass
class RawRunResult:
    """The unprocessed outcome of one container run, before either phase
    module splits marker-prefixed lines out of stdout/stderr."""

    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    duration_s: float


def require_docker() -> None:
    if shutil.which("docker") is None:
        raise DockerUnavailableError(
            "the `docker` CLI was not found on PATH -- escrow requires local Docker socket access"
        )
    check = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if check.returncode != 0:
        raise DockerUnavailableError(
            "`docker info` failed -- is the Docker daemon running and is this "
            "user allowed to talk to it?\n" + check.stderr.strip()
        )


def _image_exists(image: str) -> bool:
    result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    return result.returncode == 0


def ensure_image_built(image: str, dockerfile: Path, repo_root: Path, force: bool = False) -> None:
    """Build `image` from `dockerfile` (with `repo_root` as build context)
    if it isn't already present, or unconditionally if `force=True`."""
    require_docker()

    if not force and _image_exists(image):
        return

    if not dockerfile.exists():
        raise ImageBuildError(f"Dockerfile not found at {dockerfile}")

    build = subprocess.run(
        ["docker", "build", "-t", image, "-f", str(dockerfile), str(repo_root)],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        raise ImageBuildError(f"failed to build image {image}:\n{build.stderr}")


def run_driver(
    script: str,
    *,
    image: str,
    dockerfile: Path,
    timeout: int,
    network: bool,
    name_prefix: str = "escrow",
    memory: str = DEFAULT_MEMORY,
    cpus: str = DEFAULT_CPUS,
    pids_limit: int = DEFAULT_PIDS_LIMIT,
    tmpfs_size: str = DEFAULT_TMPFS_SIZE,
) -> RawRunResult:
    """Run `script` inside a single hardened, ephemeral container built
    from `dockerfile`. `network=True` omits `--network none` (Phase 1);
    `network=False` passes it (Phase 2). Always removes the container
    afterward, whether the run succeeded, failed, or timed out.
    """
    repo_root = dockerfile.resolve().parent
    require_docker()
    ensure_image_built(image, dockerfile, repo_root)

    container_name = f"{name_prefix}-{uuid.uuid4().hex[:12]}"

    cmd = ["docker", "run", "--rm", "--name", container_name, "-i"]
    if not network:
        cmd += ["--network", "none"]
    cmd += [
        "--read-only",
        "--tmpfs",
        f"/tmp:rw,size={tmpfs_size},mode=1777",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--cpus={cpus}",
        f"--memory={memory}",
        f"--pids-limit={pids_limit}",
        image,
        "-",  # ENTRYPOINT is python3 (-S for Phase 1); "-" reads the script from stdin
    ]

    start = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    timed_out = False
    try:
        stdout, stderr = proc.communicate(input=script, timeout=timeout)
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        # `docker run` doesn't own the container the way a normal child
        # process would -- killing it wouldn't stop the container running
        # under dockerd. Kill the container explicitly.
        subprocess.run(["docker", "kill", container_name], capture_output=True)
        try:
            stdout, stderr = proc.communicate(timeout=_KILL_GRACE_S)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            exit_code = proc.returncode
    finally:
        # Belt and braces: --rm should have removed the container already,
        # but if `docker run` itself was killed before that happened, force
        # removal so nothing orphaned is left behind.
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    duration_s = time.monotonic() - start

    return RawRunResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        timed_out=timed_out,
        duration_s=duration_s,
    )
